# resilience.py
# Retry, Rate-limit, Circuit Breaker, DNS fallback — Trio-friendly, zero hard deps.
# Integrazione consigliata: decorare la funzione HTTP async con @with_retry_http.
# - Timeout "di profilo": get_profile_timeouts(profile) → dict con suggerimenti.
# - Retry con jitter: solo su transient (timeout/reset/429/5xx noti), hard stop su 4xx (eccetto 408/425/429).
# - Circuit breaker per host: OPEN→HALF_OPEN→CLOSED con reset automatico.
# - Rate limit per host + cooldown da Retry-After (429).
# - DNS fallback: prima socket.getaddrinfo; se fallisce e c’è dnspython, prova risolutori pubblici (1.1.1.1, 8.8.8.8).
# - Semafori: per-host e globale per controllare la concorrenza lato chiamante.

from __future__ import annotations

import math
import socket
import time
import logging
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple
from functools import wraps
from urllib.parse import urlsplit
from email.utils import parsedate_to_datetime

import trio  # sleep/backoff/semafori

# ─────────────────────────────────────────────────────────────────────────────
# BLOCCO 4 — WAF-Aware pacing + Circuit Breaker (stateless API + state interno)
# ─────────────────────────────────────────────────────────────────────────────
import threading, random

# Stato interno per pacing / retry-after / breaker per host
_PACE_LOCK = threading.RLock()
_PACE_STATE: Dict[str, Dict[str, Any]] = {}   # {host: {"next_at": float, "retry_until": float}}
_CB_STATE:   Dict[str, Dict[str, Any]] = {}   # {host: {"fail_count", "first_fail_at", "opened_until", "backoff_s", ...}}

# mapping vendor → profilo di prudenza (delay base + jitter + burst)
_WAF_PROFILES = {
    "cloudflare":   {"base_ms": 300, "jitter_ms": 400, "max_burst": 2, "backoff": 1.8, "max_backoff_s": 60},
    "akamai":       {"base_ms": 250, "jitter_ms": 300, "max_burst": 2, "backoff": 1.6, "max_backoff_s": 45},
    "imperva":      {"base_ms": 280, "jitter_ms": 350, "max_burst": 2, "backoff": 1.7, "max_backoff_s": 60},
    "f5":           {"base_ms": 220, "jitter_ms": 260, "max_burst": 3, "backoff": 1.6, "max_backoff_s": 45},
    "aws":          {"base_ms": 260, "jitter_ms": 300, "max_burst": 3, "backoff": 1.5, "max_backoff_s": 45},
    "_default":     {"base_ms": 120, "jitter_ms": 180, "max_burst": 4, "backoff": 1.4, "max_backoff_s": 30},
}

def _pick_waf_profile(vendors: Optional[list]) -> Dict[str, Any]:
    v = [str(x).strip().lower() for x in (vendors or []) if x]
    for name in ("cloudflare", "akamai", "imperva", "f5", "aws"):
        if any(name in w for w in v):
            return dict(_WAF_PROFILES[name])
    return dict(_WAF_PROFILES["_default"])

def host_pacing_policy(host: str, waf_vendors: Optional[list] = None) -> Dict[str, Any]:
    """
    Calcola quanto **aspettare prima** della prossima richiesta a 'host', considerando:
      - Retry-After (se presente) → priorità massima
      - profilo WAF (base + jitter)
    NON dorme: ritorna solo i numeri.
    """
    host_key = (host or "").strip().lower()
    prof = _pick_waf_profile(waf_vendors)
    now = time.monotonic()

    with _PACE_LOCK:
        st = _PACE_STATE.setdefault(host_key, {"next_at": 0.0, "retry_until": 0.0, "burst": 0})
        # Retry-After attivo?
        retry_until = float(st.get("retry_until") or 0.0)
        if retry_until > now:
            return {
                "sleep_s": max(0.0, retry_until - now),
                "base_ms": int(prof["base_ms"]),
                "jitter_ms": int(prof["jitter_ms"]),
                "max_burst": int(prof["max_burst"]),
                "retry_until": retry_until,
            }

        sleep_s = max(0.0, float(st.get("next_at") or 0.0) - now)
        return {
            "sleep_s": sleep_s,
            "base_ms": int(prof["base_ms"]),
            "jitter_ms": int(prof["jitter_ms"]),
            "max_burst": int(prof["max_burst"]),
            "retry_until": 0.0,
        }

def _update_pacing_after_send(host: str, base_ms: int, jitter_ms: int) -> None:
    """
    Da chiamare **subito dopo** l’invio della richiesta per spostare il prossimo slot 'next_at'.
    """
    with _PACE_LOCK:
        st = _PACE_STATE.setdefault(host.lower(), {"next_at": 0.0, "retry_until": 0.0, "burst": 0})
        delay = (int(base_ms) + random.randint(0, max(0, int(jitter_ms)))) / 1000.0
        nxt = time.monotonic() + delay
        st["next_at"] = max(nxt, float(st.get("next_at") or 0.0))

def _parse_retry_after(headers: Dict[str, Any]) -> Optional[float]:
    """
    Interpreta Retry-After come delta (secondi) o HTTP-date; ritorna i secondi o None.
    """
    if not headers:
        return None
    ra = headers.get("retry-after") or headers.get("Retry-After")
    if not ra:
        return None
    s = str(ra).strip()
    # delta
    if s.isdigit():
        return float(int(s))
    # data HTTP
    try:
        dt = parsedate_to_datetime(s)
        if dt is None:
            return None
        return max(0.0, dt.timestamp() - time.time())
    except Exception:
        return None

def circuit_breaker_for_host(host: str):
    """
    Piccolo breaker per hos con API:
      - allow() -> bool
      - on_success() -> None
      - on_error(status: int|None = None, headers: dict|None = None, exc: Exception|None = None) -> None
      - cooldown_remaining() -> float
    Regole: 5 errori in 60s → APRI; backoff esponenziale; Retry-After valorizza anche il pacing.
    """
    host_key = (host or "").strip().lower()
    with _PACE_LOCK:
        _CB_STATE.setdefault(host_key, {
            "fail_count": 0,
            "first_fail_at": 0.0,
            "opened_until": 0.0,
            "backoff_s": 2.0,
            "last_retry_set": 0.0,
        })

    class _Handle:
        __slots__ = ("_h",)

        def __init__(self, h: str):
            self._h = h

        def allow(self) -> bool:
            with _PACE_LOCK:
                opened_until = float(_CB_STATE[self._h].get("opened_until", 0.0))
            return time.monotonic() >= opened_until

        def on_success(self) -> None:
            with _PACE_LOCK:
                s = _CB_STATE[self._h]
                s["fail_count"] = max(0, int(s.get("fail_count", 0)) // 2)
                s["first_fail_at"] = 0.0 if s["fail_count"] == 0 else s["first_fail_at"]
                s["backoff_s"] = max(1.5, float(s.get("backoff_s", 2.0)) / 1.5)

        def on_error(self, status: Optional[int] = None, headers: Optional[dict] = None, exc: Optional[Exception] = None) -> None:
            now = time.monotonic()
            ra_s = _parse_retry_after(headers or {}) or 0.0
            with _PACE_LOCK:
                s = _CB_STATE[self._h]
                # finestra 60s
                if (now - float(s.get("first_fail_at") or 0.0)) > 60.0:
                    s["first_fail_at"] = now
                    s["fail_count"] = 0
                s["fail_count"] = int(s.get("fail_count", 0)) + 1

                bad = (
                    status in (401, 403, 404, 408, 409, 413, 418, 421, 429, 499, 500, 501, 502, 503, 504, 508)
                    or exc is not None
                )
                if bad and s["fail_count"] >= 5:
                    s["backoff_s"] = min(float(s.get("backoff_s", 2.0)) * 1.8, 120.0)
                    _CB_STATE[self._h]["opened_until"] = now + s["backoff_s"]

                # Pacing: se c'è Retry-After, spingi retry_until
                if ra_s > 0.0:
                    ps = _PACE_STATE.setdefault(self._h, {"next_at": 0.0, "retry_until": 0.0, "burst": 0})
                    ps["retry_until"] = max(ps.get("retry_until", 0.0), time.monotonic() + ra_s)
                    s["last_retry_set"] = now

        def cooldown_remaining(self) -> float:
            with _PACE_LOCK:
                ou = float(_CB_STATE[self._h].get("opened_until", 0.0))
            return max(0.0, ou - time.monotonic())

    return _Handle(host_key)

def pacing_snapshot(host: str) -> Dict[str, Any]:
    """
    Ritorna lo stato di pacing per 'host':
      {"next_at": float, "retry_until": float, "burst": int, "now": float, "sleep_s": float}
    Utile per capire perché stiamo dormendo.
    """
    h = (host or "").strip().lower()
    now = time.monotonic()
    with _PACE_LOCK:
        st = dict(_PACE_STATE.get(h, {"next_at": 0.0, "retry_until": 0.0, "burst": 0}))
    return {
        **st,
        "now": now,
        "sleep_s": max(0.0, max(st.get("next_at", 0.0), st.get("retry_until", 0.0)) - now),
    }


def circuit_snapshot(host: str) -> Dict[str, Any]:
    """
    Snapshot leggero del breaker per 'host'. Se non esiste ancora, crea entry vuota.
    """
    h = (host or "").strip().lower()
    with _PACE_LOCK:
        s = _CB_STATE.get(h) or {
            "fail_count": 0, "first_fail_at": 0.0, "opened_until": 0.0, "backoff_s": 2.0
        }
        out = dict(s)
    out["cooldown_remaining"] = max(0.0, float(out.get("opened_until", 0.0)) - time.monotonic())
    out["host"] = h
    return out


def set_retry_after_for_host(host: str, seconds: float) -> None:
    """
    Forza un 'Retry-After' sul pacing dell'host (utile nei test o se lo vuoi impostare manualmente).
    """
    h = (host or "").strip().lower()
    sec = max(0.0, float(seconds or 0.0))
    if sec <= 0.0:
        return
    with _PACE_LOCK:
        st = _PACE_STATE.setdefault(h, {"next_at": 0.0, "retry_until": 0.0, "burst": 0})
        st["retry_until"] = max(float(st.get("retry_until") or 0.0), time.monotonic() + sec)


def reset_pacing(host: Optional[str] = None) -> None:
    """
    Resetta lo stato di pacing (Retry-After/next_at) per un host o per tutti.
    """
    with _PACE_LOCK:
        if host:
            _PACE_STATE.pop(host.strip().lower(), None)
        else:
            _PACE_STATE.clear()
    logger.info("Resilience: pacing reset (%s).", host or "ALL")


def reset_resilience() -> None:
    """
    Reset completo: pacing + circuit breaker (non tocca rate limits configurati altrove).
    """
    with _PACE_LOCK:
        _PACE_STATE.clear()
        _CB_STATE.clear()
    logger.info("Resilience: pacing + CB state cleared.")


def budget_guard(
    profile: str | None = "standard",
    *,
    base_timeout_s: float | None = None,
    base_retries: int | None = None,
    env_prefix: str = "SCAN",           # SCAN_TIMEOUT, SCAN_RETRIES
) -> dict:
    """
    Definisce timeouts/retries coerenti col profilo, con override da ENV.
    Obiettivo: profilo 'light' molto prudente (no impatto SLA), 'standard' bilanciato,
    'deep' un po' più insistente. NON apre connessioni: è solo policy locale.

    Ritorna un dict con chiavi (subset usabili dalla sonda):
      - timeout:  float (secondi)
      - retries:  int   (tentativi aggiuntivi sul singolo endpoint)

    Env override (se presenti):
      {env_prefix}_TIMEOUT, {env_prefix}_RETRIES
    """
    prof = (profile or "standard").strip().lower()
    if base_timeout_s is None:
        base_timeout_s = {"light": 5.0, "standard": 8.0, "deep": 12.0}.get(prof, 8.0)
    if base_retries is None:
        base_retries = {"light": 0,   "standard": 1,  "deep": 2}.get(prof, 1)

    # Clamp conservativi
    timeout = float(max(2.0, min(30.0, base_timeout_s)))
    retries = int(max(0, min(4, base_retries)))

    # Override ENV (se definiti)
    import os
    t_env = os.getenv(f"{env_prefix}_TIMEOUT") or os.getenv(f"{env_prefix}_TIMEOUT_S")
    r_env = os.getenv(f"{env_prefix}_RETRIES")
    try:
        if t_env is not None:
            timeout = float(max(2.0, min(30.0, float(t_env))))
    except Exception:
        pass
    try:
        if r_env is not None:
            retries = int(max(0, min(4, int(r_env))))
    except Exception:
        pass

    # Profilo 'light': fail-fast e nessun tentativo aggressivo
    if prof == "light":
        timeout = min(timeout, 6.0)
        retries = min(retries, 1)

    return {"timeout": timeout, "retries": retries}


logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

__all__ = [
    # Profili / budget
    "get_profile_timeouts",
    "budget_guard",

    # DNS
    "ensure_dns",

    # Rate-limit (token bucket)
    "TokenBucket",
    "configure_rate_limit",
    "set_global_rate_limit_defaults",

    # Concorrenza
    "get_host_semaphore",
    "set_global_semaphore",

    # Circuiti / osservazioni
    "Circuit",
    "circuit_for_domain",
    "record_observed_latency",
    "reset_circuits",
    "reset_rate_limits",

    # Decoratore retry/backoff Trio-friendly
    "with_retry_http",

    # --- BLOCCO 4: WAF-aware pacing + circuit breaker ---
    "host_pacing_policy",
    "circuit_breaker_for_host",
    "_update_pacing_after_send",

    # --- Nuove utilità (debug/telemetria) ---
    "pacing_snapshot",              # leggi stato pacing per host
    "circuit_snapshot",             # leggi snapshot del CB per host
    "set_retry_after_for_host",     # forza un Retry-After sul pacing
    "reset_pacing",                 # reset pacing (uno o tutti gli host)
    "reset_resilience",             # reset totale pacing+CB
]


# --------------------------------------------------------------------------------------
# Profili di timeout (helper da usare nel client HTTP)
# --------------------------------------------------------------------------------------

def get_profile_timeouts(profile: str) -> Dict[str, float]:
    """
    Ritorna suggerimenti timeout per profilo (in secondi).
    light:   connect=3, read=5, write=5, total=8
    deep:    connect=5, read=8, write=8, total=12
    default: connect=3, read=5, write=5, total=10
    """
    p = (profile or "").lower()
    if p == "light":
        return {"connect": 3.0, "read": 5.0, "write": 5.0, "total": 8.0}
    if p == "deep":
        return {"connect": 5.0, "read": 8.0, "write": 8.0, "total": 12.0}
    return {"connect": 3.0, "read": 5.0, "write": 5.0, "total": 10.0}

# --------------------------------------------------------------------------------------
# Stato globale
# --------------------------------------------------------------------------------------

_LAT_MS: Dict[str, list] = {}                       # storici latenza (ms) per tuning leggero
_CIRCUITS: Dict[str, "Circuit"] = {}                # circuit breakers per dominio
_COOLDOWNS_UNTIL: Dict[str, float] = {}             # cooldown epoch (da Retry-After)
_HOST_SEMAPHORES: Dict[str, Tuple[trio.Semaphore, int]] = {}  # {host: (sem, limit)}
_GLOBAL_SEM: Optional[trio.Semaphore] = None        # semaforo globale (opzionale)

# Rate limit (token bucket) per host
_RATE_LIMITS: Dict[str, "TokenBucket"] = {}
_GLOBAL_RL_DEFAULT: Dict[str, Any] = {"rps": None, "burst": 2, "min_interval_s": None}

# Classificazioni HTTP
_TRANSIENT_STATUS = {408, 425, 429, 500, 502, 503, 504}
_HARDSTOP_4XX = set(range(400, 500)) - {408, 425, 429}

def _now() -> float:
    return time.monotonic()

def _host_of(url: str) -> str:
    try:
        return urlsplit(url).netloc.lower()
    except Exception:
        return ""

# --------------------------------------------------------------------------------------
# DNS fallback (opzionale, usa dnspython se disponibile)
# --------------------------------------------------------------------------------------

async def ensure_dns(host: str, timeout_s: float = 2.0) -> None:
    """
    Assicura che il nome sia risolvibile: tenta getaddrinfo; se fallisce,
    prova con resolver pubblici (1.1.1.1, 8.8.8.8) via dnspython (se installato).
    Non solleva se anche il fallback fallisce: logga soltanto.
    """
    host = (host or "").strip()
    if not host:
        return

    # Primo tentativo: getaddrinfo in thread (non ha timeout nativo; in genere rapido)
    try:
        await trio.to_thread.run_sync(lambda: socket.getaddrinfo(host, 80, proto=socket.IPPROTO_TCP))
        return
    except Exception as e:
        logger.debug("getaddrinfo fallita per %s: %s (provo fallback DNS)", host, e)

    # Fallback con dnspython (se presente)
    try:
        import dns.resolver  # type: ignore
    except Exception:
        logger.info("DNS fallback non disponibile (dnspython non installato) per %s", host)
        return

    async def _dns_query(resolver_ip: str) -> bool:
        try:
            def _mk_resolver():
                r = dns.resolver.Resolver(configure=False)
                r.nameservers = [resolver_ip]
                r.timeout = timeout_s
                r.lifetime = timeout_s
                return r

            r = await trio.to_thread.run_sync(_mk_resolver)
            # prova A e AAAA
            for rrtype in ("A", "AAAA"):
                try:
                    await trio.to_thread.run_sync(lambda: r.resolve(host, rrtype))
                    return True
                except Exception:
                    pass
        except Exception:
            return False
        return False

    for ip in ("1.1.1.1", "8.8.8.8"):
        ok = await _dns_query(ip)
        if ok:
            logger.info("DNS fallback riuscito per %s tramite %s", host, ip)
            return
    logger.info("DNS fallback fallito per %s (resolver pubblici)", host)

# --------------------------------------------------------------------------------------
# Token Bucket (rate limit dolce)
# --------------------------------------------------------------------------------------

class TokenBucket:
    def __init__(self, rps: Optional[float], burst: int = 2, min_interval_s: Optional[float] = None):
        self.rps = float(rps) if rps else None
        self.burst = max(1, int(burst or 1))
        self.tokens = float(self.burst)
        self.last = _now()
        self.min_interval_s = float(min_interval_s) if min_interval_s else None
        self.last_consume_ts: Optional[float] = None

    async def acquire(self) -> None:
        # Intervallo minimo tra chiamate (se richiesto)
        if self.min_interval_s is not None and self.last_consume_ts is not None:
            elapsed = _now() - self.last_consume_ts
            remain = self.min_interval_s - elapsed
            if remain > 0:
                await trio.sleep(min(remain, 5.0))

        # Nessun limite: passa
        if self.rps is None:
            self.last_consume_ts = _now()
            return

        # Ricarica e consuma token
        now = _now()
        elapsed = now - self.last
        self.last = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rps)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            self.last_consume_ts = now
            return

        need = 1.0 - self.tokens
        delay = need / max(self.rps, 1e-6)
        await trio.sleep(min(delay, 10.0))
        self.tokens = max(0.0, self.tokens + delay * self.rps - 1.0)
        self.last_consume_ts = _now()

def configure_rate_limit(host: str,
                         rps: Optional[float] = None,
                         burst: int = 2,
                         min_interval_s: Optional[float] = None) -> None:
    _RATE_LIMITS[host.lower()] = TokenBucket(rps, burst=burst, min_interval_s=min_interval_s)

def set_global_rate_limit_defaults(rps: Optional[float] = None,
                                   burst: int = 2,
                                   min_interval_s: Optional[float] = None) -> None:
    _GLOBAL_RL_DEFAULT["rps"] = float(rps) if rps else None
    _GLOBAL_RL_DEFAULT["burst"] = max(1, int(burst or 1))
    _GLOBAL_RL_DEFAULT["min_interval_s"] = float(min_interval_s) if min_interval_s else None

async def _rate_limit_gate(host: str, budget: Optional[Dict[str, Any]]) -> None:
    # Cooldown post-429
    until = _COOLDOWNS_UNTIL.get(host)
    if until:
        remaining = until - time.time()
        if remaining > 0:
            await trio.sleep(min(remaining, 60.0))

    # Token bucket (override dal budget se presente)
    rl_over = (budget or {}).get("rate_limit") if isinstance(budget, dict) else None
    if rl_over and (rl_over.get("rps") or rl_over.get("min_interval_s")):
        tb = TokenBucket(
            rps=rl_over.get("rps"),
            burst=int(rl_over.get("burst", _GLOBAL_RL_DEFAULT["burst"])),
            min_interval_s=rl_over.get("min_interval_s"),
        )
        await tb.acquire()
        return

    tb = _RATE_LIMITS.get(host)
    if tb is None:
        tb = TokenBucket(
            rps=_GLOBAL_RL_DEFAULT["rps"],
            burst=int(_GLOBAL_RL_DEFAULT["burst"]),
            min_interval_s=_GLOBAL_RL_DEFAULT["min_interval_s"],
        )
        _RATE_LIMITS[host] = tb
    await tb.acquire()

def _set_cooldown_from_retry_after(host: str, headers: Dict[str, Any], default_if_missing: float) -> None:
    ra = None
    for k, v in (headers or {}).items():
        if str(k).lower() == "retry-after":
            ra = str(v).strip()
            break
    seconds = None
    if ra:
        if ra.isdigit():
            seconds = int(ra)
        else:
            try:
                dt = parsedate_to_datetime(ra)
                seconds = max(0, int((dt.timestamp() - time.time())))
            except Exception:
                seconds = None
    if seconds is None:
        seconds = int(default_if_missing)
    _COOLDOWNS_UNTIL[host] = time.time() + max(0, seconds)

# --------------------------------------------------------------------------------------
# Circuit breaker
# --------------------------------------------------------------------------------------

class Circuit:
    def __init__(self, host: str, fail_max: int = 5, reset_timeout: float = 60.0):
        self.host = host
        self.fail_max = max(1, int(fail_max))
        self.reset_timeout = max(5.0, float(reset_timeout))
        self.fail_count = 0
        self.state = "CLOSED"  # CLOSED | OPEN | HALF_OPEN
        self.opened_at: Optional[float] = None

    def allow_request(self) -> bool:
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if self.opened_at and (_now() - self.opened_at) >= self.reset_timeout:
                self.state = "HALF_OPEN"
                return True
            return False
        if self.state == "HALF_OPEN":
            return True
        return True

    def record_success(self) -> None:
        self.fail_count = 0
        self.state = "CLOSED"
        self.opened_at = None

    def record_failure(self) -> None:
        self.fail_count += 1
        if self.state in ("CLOSED", "HALF_OPEN") and self.fail_count >= self.fail_max:
            self.state = "OPEN"
            self.opened_at = _now()

    def snapshot(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "state": self.state,
            "fail_count": self.fail_count,
            "fail_max": self.fail_max,
            "reset_timeout": self.reset_timeout,
            "opened_at": self.opened_at,
        }

def _percentile(data: list, pct: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    k = min(int(len(s) * pct / 100), len(s) - 1)
    return float(s[k])

def circuit_for_domain(domain: str,
                       fail_max: Optional[int] = None,
                       reset_timeout: Optional[float] = None) -> Circuit:
    dom = (domain or "").lower()
    c = _CIRCUITS.get(dom)
    if c is None:
        lat = _LAT_MS.get(dom, [])
        p95 = _percentile(lat, 95) / 1000.0 if lat else 0.0
        c = Circuit(dom,
                    fail_max=fail_max or 5,
                    reset_timeout=reset_timeout or max(30.0, 2.0 * p95 if p95 > 0 else 60.0))
        _CIRCUITS[dom] = c
    return c

# --------------------------------------------------------------------------------------
# Semafori (per-host e globale) — da usare lato orchestratore
# --------------------------------------------------------------------------------------

def get_host_semaphore(host: str, limit: int = 10) -> trio.Semaphore:
    """
    Ritorna un semaforo per-host. Se il limite cambia, il semaforo viene ricreato.
    """
    host = (host or "").lower()
    current = _HOST_SEMAPHORES.get(host)
    if current is None or current[1] != max(1, int(limit)):
        sem = trio.Semaphore(max(1, int(limit)))
        _HOST_SEMAPHORES[host] = (sem, max(1, int(limit)))
        return sem
    return current[0]

def set_global_semaphore(limit: Optional[int]) -> None:
    """
    Imposta/azzera il semaforo globale.
    """
    global _GLOBAL_SEM
    if limit is None:
        _GLOBAL_SEM = None
    else:
        _GLOBAL_SEM = trio.Semaphore(max(1, int(limit)))

# --------------------------------------------------------------------------------------
# Decoratore: retry/backoff solo su transient; hard stop 4xx; DNS fallback; budget-aware
# --------------------------------------------------------------------------------------

def _is_transient_exc(exc: BaseException) -> bool:
    name = exc.__class__.__name__.lower()
    text = str(exc).lower()
    transient_keys = [
        "timeout", "timed out", "temporarily", "temporary", "retry", "reset",
        "connectionreset", "connect", "readtimeout", "write timeout", "writeTimeout".lower(),
        "remote protocol", "server disconnected", "too many requests",
        "rate limit", "backoff", "econnreset", "broken pipe", "temporarily unavailable",
        "tls handshake", "network error",
    ]
    return any(k in name or k in text for k in transient_keys)

def _looks_transient_text(s: str) -> bool:
    s = s.lower()
    keys = ["timeout", "temporar", "retry", "reset", "throttle", "rate limit", "429", "backoff", "unavailable"]
    return any(k in s for k in keys)

async def _sleep_backoff(base: float, attempt: int) -> None:
    # backoff esponenziale con jitter deterministico [0.85..1.15]
    jitter = 0.85 + 0.3 * math.sin(attempt * 1.11)
    delay = min(16.0, base * (2 ** (attempt - 1)) * jitter)
    await trio.sleep(delay)

def with_retry_http(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """
    Decoratore per funzioni **async** che effettuano I/O HTTP (Trio-friendly).
    Regole:
      - Retry **solo** su errori transitori (timeout/reset/429/5xx noti).
      - **Stop immediato** su 4xx (eccetto 408/425/429).
      - **Budget-aware**: kwargs `budget={max_retries, deadline_s, rate_limit:{...}, max_concurrency_per_host, global_concurrency}`.
      - **Circuit breaker** per dominio: skip se OPEN; HALF_OPEN consente 1 prova.
      - **Rate limit per host** + cooldown da Retry-After su 429.
      - **DNS fallback**: un tentativo prima del primo try.
    La funzione decorata può:
      - lanciare eccezioni I/O, oppure
      - ritornare un dict con `status`/`error`/`headers`.
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Estrai URL per inferire host
        url = kwargs.get("url")
        if not url:
            for a in args:
                if isinstance(a, str) and ("://" in a or a.startswith("http")):
                    url = a
                    break
        url = str(url or "")
        host = _host_of(url)

        circuit = circuit_for_domain(host)
        budget = kwargs.get("budget") or {}
        max_retries = int(budget.get("max_retries", 2))
        deadline_s = float(budget.get("deadline_s", 0.0))  # 0 = nessuna deadline
        started = _now()
        attempt = 0
        backoff_base = 0.4  # secondi

        # DNS fallback (una volta, prima dei tentativi)
        if host:
            await ensure_dns(host)

        # Semafori opzionali (se il chiamante specifica il limite globale, impostalo)
        if "global_concurrency" in budget:
            set_global_semaphore(budget.get("global_concurrency"))

        host_limit = budget.get("max_concurrency_per_host")
        host_sem = get_host_semaphore(host, int(host_limit)) if host and host_limit else None
        global_sem = _GLOBAL_SEM

        async def _one_attempt():
            nonlocal attempt
            attempt += 1

            # Circuit check
            if not circuit.allow_request():
                logger.warning("Circuit OPEN for %s — skipping request", host)
                raise RuntimeError(f"CircuitOpen(host={host})")

            # Deadline check
            if deadline_s > 0 and (_now() - started) > deadline_s:
                logger.warning("Deadline exceeded before attempt %d for %s", attempt, host)
                raise TimeoutError(f"DeadlineExceeded(host={host})")

            # Rate limit gate
            await _rate_limit_gate(host, budget)

            # Esecuzione
            t0 = _now()
            result = await func(*args, **kwargs)
            rtt_ms = int((_now() - t0) * 1000)
            if rtt_ms > 0:
                # mantieni finestra scorrevole leggera (cap a 200 valori per host)
                hist = _LAT_MS.setdefault(host, [])
                hist.append(rtt_ms)
                if len(hist) > 200:
                    del hist[: len(hist) - 200]

            # Valuta risultato (dict-friendly)
            if isinstance(result, dict):
                status = result.get("status")
                error_msg = result.get("error")
                headers = result.get("headers") or {}
                if isinstance(status, int):
                    if status in _HARDSTOP_4XX:
                        circuit.record_failure()
                        return result
                    if status in _TRANSIENT_STATUS:
                        if status == 429:
                            _set_cooldown_from_retry_after(host, headers, default_if_missing=3.0 * (2 ** (attempt - 1)))
                        circuit.record_failure()
                        raise RuntimeError(f"TransientStatus({status})")
                    circuit.record_success()
                    return result
                if error_msg:
                    if _looks_transient_text(str(error_msg)):
                        circuit.record_failure()
                        raise RuntimeError("TransientErrorText")
                    circuit.record_failure()
                    return result
            circuit.record_success()
            return result

        # Applica semafori (globale → per-host) se presenti
        async def _guarded_attempt():
            if global_sem:
                async with global_sem:
                    if host_sem:
                        async with host_sem:
                            return await _one_attempt()
                    return await _one_attempt()
            if host_sem:
                async with host_sem:
                    return await _one_attempt()
            return await _one_attempt()

        last_exc: Optional[BaseException] = None
        while True:
            try:
                return await _guarded_attempt()
            except BaseException as e:
                last_exc = e
                # Status transient simulato (via RuntimeError)
                if isinstance(e, RuntimeError) and str(e).startswith("TransientStatus"):
                    if attempt > max_retries:
                        logger.info("Max retries reached for %s after transient status", host)
                        return {"status": None, "error": str(e)}
                    await _sleep_backoff(backoff_base, attempt)
                    continue
                # Eccezioni transient (timeout/reset/network)
                if _is_transient_exc(e):
                    circuit.record_failure()
                    if attempt > max_retries:
                        logger.info("Max retries reached for %s after transient exception: %s", host, e)
                        # Per coerenza con pipeline fail-soft, ritorna dict d'errore
                        return {"status": None, "error": f"{type(e).__name__}: {e}"}
                    await _sleep_backoff(backoff_base, attempt)
                    continue
                # Non-transient → propaga (o converti in dict se vuoi sempre fail-soft)
                circuit.record_failure()
                raise

    return wrapper

# --------------------------------------------------------------------------------------
# Utilities pubbliche
# --------------------------------------------------------------------------------------

def record_observed_latency(host: str, latency_ms: int) -> None:
    if latency_ms > 0:
        h = host.lower()
        hist = _LAT_MS.setdefault(h, [])
        hist.append(int(latency_ms))
        if len(hist) > 200:
            del hist[: len(hist) - 200]

def reset_circuits() -> None:
    _CIRCUITS.clear()
    _LAT_MS.clear()
    logger.info("Resilience reset: circuits + latency history cleared.")

def reset_rate_limits() -> None:
    _RATE_LIMITS.clear()
    _COOLDOWNS_UNTIL.clear()
    logger.info("Resilience reset: rate limits + cooldowns cleared.")

# --------------------------------------------------------------------------------------
# Self-test minimale
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    async def fake_http(url: str, *, budget: Optional[Dict[str, Any]] = None, plan: list[int] = None):
        """
        Simula risposte HTTP seguendo 'plan' (es. [500, 429, 200]); -1 simula eccezione transiente.
        """
        st = (plan or [200]).pop(0) if plan else 200
        await trio.sleep(0.05)
        if st == 429:
            return {"status": st, "headers": {"Retry-After": "1"}}
        if st == -1:
            raise TimeoutError("Simulated timeout")
        return {"status": st, "body": b"ok", "headers": {}}

    @with_retry_http
    async def call(url: str, *, budget: Optional[Dict[str, Any]] = None, plan: list[int] = None):
        return await fake_http(url, budget=budget, plan=plan)

    async def demo():
        print("→ DNS ensure (può loggare fallback):")
        await ensure_dns("example.com")

        print("→ Retry dopo transient (500, 429, 200):")
        print(await call("http://example.com", budget={"max_retries": 3}, plan=[500, 429, 200]))

        print("→ Hard stop 404 (no retry):")
        print(await call("http://example.com", budget={"max_retries": 3}, plan=[404]))

        print("→ Exception transient poi successo:")
        print(await call("http://example.com", budget={"max_retries": 2}, plan=[-1, 200]))

        print("Circuit snapshot:", circuit_for_domain("example.com").snapshot())

        print("→ Rate limit override (1 rps, burst 1, min_interval 0.8s):")
        res1 = await call("http://rate.example", budget={"rate_limit": {"rps": 1.0, "burst": 1, "min_interval_s": 0.8}}, plan=[200])
        res2 = await call("http://rate.example", budget={"rate_limit": {"rps": 1.0, "burst": 1, "min_interval_s": 0.8}}, plan=[200])
        print(res1, res2)

    trio.run(demo)
