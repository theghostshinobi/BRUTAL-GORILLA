# probe_smuggle.py (aggiornato)
# Sonda HTTP Trio (seriale per default, concorrente se richiesto) — nessun import circolare.
# Obiettivi: fail-soft su eccezioni httpx, timeouts/limits/redirects ben definiti,
# rispetto del budget (globale e per host) e marcatura degli errori nei record.

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple, Callable
from collections import deque
from urllib.parse import urlsplit, parse_qsl

import trio

try:
    import httpx  # type: ignore
except Exception as e:  # pragma: no cover
    raise ImportError("httpx non è installato. Installa 'httpx' (pip install httpx).") from e

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ─────────────────────────────────────────────────────────────────────────────
# BLOCCO 4: Strategy + request wrapper
# ─────────────────────────────────────────────────────────────────────────────
import time, random
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlsplit

try:
    import httpx
except Exception:
    httpx = None  # type: ignore

def apply_waf_strategy(url: str, waf_vendors: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Ritorna una strategia 'gentile' per l'host/URL:
      {
        "headers": List[Tuple[str,str]],   # header innocui + UA standardizzati (ordine preservabile da httpx.Headers)
        "method_order": List[str],         # es. ["HEAD","GET","OPTIONS","POST"]
        "spacing_ms": int                  # suggerimento spacing tra richieste sullo stesso host
      }
    """
    host = (urlsplit(url).hostname or "").lower()
    wafs = [str(x).lower() for x in (waf_vendors or []) if x]

    # UA "umano" e header neutrali (evita pattern 'tool')
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36",
    ]
    accept_lang = random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "it-IT,it;q=0.8,en;q=0.6"])

    base_headers: List[Tuple[str, str]] = [
        ("User-Agent", random.choice(uas)),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("Accept-Language", accept_lang),
        ("Cache-Control", "no-cache"),
        ("Pragma", "no-cache"),
        ("DNT", "1"),
        ("Upgrade-Insecure-Requests", "1"),
    ]

    # Ordine metodi: più "cauto" se WAF noto
    if any(w in wafs for w in ("cloudflare", "akamai", "imperva", "f5", "aws")):
        method_order = ["HEAD", "GET", "OPTIONS", "POST"]
        spacing_ms = random.randint(250, 750)
    else:
        method_order = ["GET", "HEAD", "OPTIONS", "POST"]
        spacing_ms = random.randint(120, 380)

    # Piccoli aggiustamenti per host "admin/auth"
    h = "." + host
    if any(k in h for k in (".admin.", ".auth.", ".login.", ".sso.", ".wp-admin.")):
        spacing_ms = max(spacing_ms, 400)
        if "HEAD" not in method_order:
            method_order.insert(0, "HEAD")

    return {
        "headers": base_headers,
        "method_order": method_order,
        "spacing_ms": spacing_ms,
    }

# --------------------------------------------------------------------------------------
# Config / Opzioni sonda
# --------------------------------------------------------------------------------------

@dataclass
class ProbeOpts:
    enrichment: bool = False          # abilita OPTIONS + POST benigno in deep
    user_agent: str = "BrutalGorilla/1.0 (+probe_smuggle)"
    connect_timeout_s: float = 3.0
    read_timeout_s: float = 5.0
    write_timeout_s: float = 5.0
    total_timeout_s: float = 10.0
    max_redirects: int = 5
    body_snippet_bytes: int = 4096
    concurrency: int = 1              # seriale di default
    extra_headers: Dict[str, str] = field(default_factory=dict)
    http2: bool = True                # httpx usa HTTP/2 dove disponibile, fallback automatico a h1
    retries: int = 1                  # retry su errori transitori (0 = disabilitato)
    retry_backoff_base_s: float = 0.2 # backoff esponenziale: base * 2**attempt
    retry_on_status: Tuple[int, ...] = (429, 502, 503, 504)  # opzionale: retry su questi status
    # --- NEW: annotation/Kb context (opzionali, non invasivi) ---
    kb_param_families_path: Optional[str] = None  # es. "kb_param_families.yaml"
    template_engine_hint: Optional[str] = None    # es. "jinja|twig"
    content_type_hint: Optional[str] = None       # override manuale, altrimenti usa quello della GET

@dataclass
class Budget:
    max_requests: Optional[int] = None          # totale richieste massime per run
    max_time_s: Optional[float] = None          # tempo massimo in secondi
    per_host_max_requests: Optional[int] = None # tetto per host

# Memoria temporale per dominio (ultime N richieste/risposte/decisioni)
_TEMP_MEMORY: Dict[str, Deque[Dict[str, Any]]] = {}
_TEMP_MEMORY_MAXLEN = 5

# --------------------------------------------------------------------------------------
# Import “soft” dal layer ingest/KB (fallback locale se assenti)
# --------------------------------------------------------------------------------------

try:
    from ingest_normalize import map_params_to_families as _map_params_to_families  # type: ignore
except Exception:
    _map_params_to_families = None  # type: ignore

try:
    from ingest_normalize import extract_params_from_url as _extract_params_from_url  # type: ignore
except Exception:
    _extract_params_from_url = None  # type: ignore

try:
    from ingest_normalize import _suggest_family as _kb_suggest_family  # type: ignore
except Exception:
    _kb_suggest_family = None  # type: ignore

def _fallback_param_families(url: str) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Fallback leggero se la KB non è disponibile."""
    params = []
    try:
        qs = urlsplit(url).query
        params = [n for n, _ in parse_qsl(qs, keep_blank_values=True)]
    except Exception:
        params = []
    fams: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}
    for p in params:
        if _kb_suggest_family:
            fam = _kb_suggest_family(p)
        else:
            lp = p.lower()
            if lp in ("id", "user_id", "uid") or lp.endswith("_id"):
                fam = "IDOR"
            elif lp in ("q", "query", "search", "s"):
                fam = "XSS"
            elif any(t in lp for t in ("order", "sort", "filter", "where", "columns", "fields")):
                fam = "SQLI"
            elif any(t in lp for t in ("redirect", "return", "next", "callback", "cb")):
                fam = "REDIRECT"
            elif any(t in lp for t in ("path", "file", "filename", "dir", "folder", "include")):
                fam = "TRAVERSAL"
            elif any(t in lp for t in ("host", "url", "endpoint", "target", "webhook")):
                fam = "SSRF_SAFE"
            else:
                fam = "GENERIC"
        fams.append({"param": p, "family": fam, "priority": 50, "confidence": "low", "source": "fallback"})
        counts[fam] = counts.get(fam, 0) + 1
    return fams, counts

def _classify_params_for_url(url: str,
                             kb_path: Optional[str],
                             content_type_hint: Optional[str],
                             engine_hint: Optional[str]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Wrapper sicuro: usa KB se disponibile, altrimenti fallback."""
    if callable(_map_params_to_families):
        try:
            res = _map_params_to_families(
                url,
                content_type_hint=content_type_hint,
                engine_hint=engine_hint,
                kb_path=kb_path
            ) or {}
            fams = list(res.get("param_families") or [])
            counts = dict(res.get("vuln_hints") or {})
            return fams, counts
        except Exception as e:
            logger.debug("map_params_to_families failed for %s: %s", url, e)
    return _fallback_param_families(url)

# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

_WAF_HEADER_HINTS = {
    "x-sucuri-id", "x-waf", "x-mod-security", "x-cdn", "cf-ray",
    "x-akamai-transformed", "x-akamai-request-id", "x-barracuda-urlfiltering",
    "x-powered-by-plesk", "x-iinfo", "x-litespeed-cache", "server", "x-amzn-waf-id",
    "cf-cache-status"
}
_WAF_BODY_PATTERNS = [
    re.compile(r"access\s*denied", re.I),
    re.compile(r"request\s*blocked", re.I),
    re.compile(r"malicious", re.I),
    re.compile(r"forbidden", re.I),
    re.compile(r"web\s*application\s*firewall", re.I),
    re.compile(r"incapsula", re.I),
    re.compile(r"imperva", re.I),
    re.compile(r"sucuri", re.I),
]

def _now() -> float:
    return time.monotonic()

def _norm_ctype(ct: Optional[str]) -> Optional[str]:
    if not ct:
        return None
    return ct.split(";")[0].strip().lower()

def _truncate(b: bytes, n: int) -> bytes:
    return b if len(b) <= n else b[:n]

def _host_of(url: str) -> str:
    try:
        return urlsplit(url).netloc.lower()
    except Exception:
        return ""

def _detect_waf(headers: Dict[str, str], body_snippet: bytes) -> Tuple[bool, Optional[str], List[str], List[str]]:
    """
    Rileva WAF e ritorna:
      (waf_bool, vendor_principale, vendors_list, signals_list)

    Regole:
      - Se troviamo un vendor certo → vendors_list=[<Vendor>] e vendor_principale=<Vendor>.
      - Se troviamo solo segnali generici → waf_bool=True ma vendors_list=[], vendor_principale=None.
      - Mai aggiungere token fittizi tipo 'Unknown-WAF'.
    """
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    try:
        text = (body_snippet or b"")[:2048].decode("iso-8859-1", errors="ignore")
    except Exception:
        text = ""
    server = (h.get("server") or "").lower()

    vendor: Optional[str] = None
    vendors: List[str] = []
    signals: List[str] = []

    # Header-based generic signals (tracciamo che "c'è qualcosa")
    for k in _WAF_HEADER_HINTS:
        if k in h:
            signals.append(f"hdr:{k}")

    # Vendor mapping (conservativo)
    if "cloudflare" in server or "cf-ray" in h or "cf-cache-status" in h:
        vendor = "Cloudflare"
    elif "akamai" in server or any(k.startswith("x-akamai") for k in h.keys()):
        vendor = "Akamai"
    elif "incapsula" in server or "imperva" in server or "x-iinfo" in h:
        vendor = "Imperva"
    elif "sucuri" in server or "x-sucuri-id" in h:
        vendor = "Sucuri"
    elif "big-ip" in server or "f5" in server:
        vendor = "F5"
    elif "barracuda" in server or "x-barracuda-urlfiltering" in h:
        vendor = "Barracuda"
    elif "awselb" in server or "x-amzn" in " ".join(h.keys()) or "x-amzn-waf-id" in h or "cloudfront" in server:
        vendor = "AWS"
    elif "mod_security" in server or "modsecurity" in server or "x-mod-security" in h:
        vendor = "ModSecurity"

    # Body patterns (segnali, e a volte vendor)
    body_hit = False
    for p in _WAF_BODY_PATTERNS:
        if p.search(text):
            signals.append(f"body:{p.pattern}")
            body_hit = True

    # Risultato
    waf_bool = bool(vendor) or bool(signals) or body_hit
    if vendor:
        vendors = [vendor]   # vendor certo
    else:
        vendors = []         # niente 'Unknown-WAF': lasciamo vuoto

    return waf_bool, vendor, vendors, signals


def _extract_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    h = {k.lower(): v for k, v in headers.items()}
    out = {
        "csp": h.get("content-security-policy"),
        "hsts": h.get("strict-transport-security"),
        "xfo": h.get("x-frame-options"),
        "x_content_type_options": h.get("x-content-type-options"),
        "referrer_policy": h.get("referrer-policy"),
    }
    out["missing"] = sorted([k for k, v in out.items() if k != "missing" and not v])
    return out

def _allow_methods(headers: Dict[str, str]) -> List[str]:
    allow = headers.get("Allow") or headers.get("allow") or ""
    methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
    return sorted(set(methods))

def _get_set_cookies(resp: httpx.Response) -> List[str]:
    try:
        return resp.headers.get_list("set-cookie")  # type: ignore[attr-defined]
    except Exception:
        v = resp.headers.get("set-cookie") or ""
        return [v] if v else []

# --------------------------------------------------------------------------------------
# Memoria temporale per dominio
# --------------------------------------------------------------------------------------

def _update_temporal_memory(url: str,
                            request: Dict[str, Any],
                            response: Dict[str, Any],
                            decision: str) -> None:
    dq = _TEMP_MEMORY.setdefault(_host_of(url) or url, deque(maxlen=_TEMP_MEMORY_MAXLEN))
    dq.append({
        "ts": time.time(),
        "url": url,
        "request": request,
        "response": {
            "status": response.get("status"),
            "latency_ms": response.get("latency_ms"),
            "content_type": response.get("content_type"),
            "size": response.get("size"),
            "waf": response.get("waf"),
            "waf_vendor": response.get("waf_vendor"),
        },
        "decision": decision,
    })

def get_temporal_memory(host_or_url: str) -> List[Dict[str, Any]]:
    dq = _TEMP_MEMORY.get(_host_of(host_or_url) or host_or_url, deque(maxlen=_TEMP_MEMORY_MAXLEN))
    return list(dq)

# --------------------------------------------------------------------------------------
# Scoring euristico
# --------------------------------------------------------------------------------------

def _score_heuristic(features: Dict[str, Any]) -> float:
    status = features.get("status") or 0
    latency = float(features.get("latency_ms") or 0.0)
    ctype = (features.get("content_type") or "").lower()
    waf = bool(features.get("waf"))

    score = 0.0

    if 500 <= status <= 599:
        score += 0.45
    elif 400 <= status <= 499:
        score += 0.25
    elif 200 <= status <= 299:
        score += 0.10
    else:
        score += 0.05

    lat_norm = max(0.0, min(1.0, latency / 3000.0))  # clamp su 3s
    score += 0.20 * lat_norm

    if "text/html" in ctype or "application/json" in ctype:
        score += 0.12
    elif "text" in ctype:
        score += 0.08
    else:
        score += 0.02

    if waf:
        score += 0.18

    return max(0.0, min(1.0, score))

# --------------------------------------------------------------------------------------
# Normalizzazione endpoints (fallback sicuro se ingest_normalize non è disponibile)
# --------------------------------------------------------------------------------------

# --- PATCH probe_smuggle.py -------------------------------------------------
import re
# --- FIX: regex case-insensitive corrette -----------------------------------
from urllib.parse import urlsplit, urlunsplit

_SCHEME_TOKEN_RE = re.compile(r'^(?:https?[:/]+)+', re.IGNORECASE)
_HTTP_FIX_RE     = re.compile(r'\b(https?):/', re.IGNORECASE)

def _fix_scheme_typos(u: str, default: str = "https") -> str:
    """
    Ripara prefissi rotti/duplicati e riporta a UNA forma canonica.
    Esempi:
      https/https:/https/https/https/example.com  -> https://example.com
      https//example.com                          -> https://example.com
      http:/example.com                           -> http://example.com
      ://example.com                              -> https://example.com
      //example.com                               -> https://example.com
      example.com                                 -> https://example.com
    """
    s = (u or "").strip().strip('\'"')
    if not s:
        return s

    # Normalizza separatori e rimuove spazi
    s = s.replace("\\", "/").replace(" ", "")

    # '://host' → default://host
    if s.startswith("://"):
        s = f"{default}{s}"
    # '//host' → default://host
    elif s.startswith("//"):
        s = f"{default}:{s}"

    # Fix 'https:/host' → 'https://host'
    s = _HTTP_FIX_RE.sub(r'\1://', s)

    # Collassa ripetizioni tipo 'https://https://'
    s = re.sub(r'^(https?://)+(.*)$',
               lambda m: f"{m.group(1).lower()}{m.group(2)}",
               s,
               flags=re.IGNORECASE)

    # Se ancora manca schema, aggiungi quello di default
    if not s.lower().startswith(("http://", "https://")):
        s = _SCHEME_TOKEN_RE.sub("", s.lstrip("/"))
        s = f"{default}://{s.lstrip('/')}"

    # Pulizia finale:
    # - rimuove 'https://https/' residui
    # - rimuove slash multipli dopo lo schema
    s = re.sub(r'^(https?://)(?:https?/?)+', r'\1', s, flags=re.IGNORECASE)
    s = re.sub(r'^(https?://)/+', r'\1', s, flags=re.IGNORECASE)

    return s



def _ensure_scheme(u: str, default: str = "https") -> str:
    """
    Garantisce 'http(s)://'; se ci sono più token, sceglie l'ULTIMO schema valido.
    """
    s = (u or "").strip()
    if not s:
        return s
    if "://" in s:
        last = s.rfind("://")
        scheme_blob = s[:last].lower()
        scheme = "https" if "https" in scheme_blob else ("http" if "http" in scheme_blob else default)
        tail = s[last + 3 :]
        return f"{scheme}://{tail.lstrip('/')}"
    return _fix_scheme_typos(s, default=default)

# --- PATCH probe_smuggle.py : robust normalize --------------------------------
import re
from urllib.parse import urlsplit, urlunsplit

def _safe_external_clean(s: str, cleaner, default_scheme: str = "https") -> str:
    """
    Applica il cleaner esterno, ma se il risultato è vuoto/malformato
    (niente hostname o netloc con backslash), fallback all'input 's'.
    Ricondiziona anche schema e backslash.
    """
    try:
        cand = cleaner(s)
    except Exception:
        return s

    if not isinstance(cand, str) or not cand.strip():
        return s

    cand = cand.strip().replace("\\", "/")
    cand = _HTTP_FIX_RE.sub(r'\1://', cand)
    if not cand.lower().startswith(("http://", "https://")):
        # il cleaner potrebbe aver tolto lo schema
        cand = _SCHEME_TOKEN_RE.sub("", cand.lstrip("/"))
        cand = f"{default_scheme}://{cand.lstrip('/')}"

    p = urlsplit(cand)
    # hostname valido?
    if not (p.hostname or "").strip():
        return s
    # netloc non deve contenere '/'
    if "/" in (p.netloc or "") or "\\" in (p.netloc or ""):
        # ripara forzando host da p.hostname e porta
        host = (p.hostname or "").strip().lower()
        port = f":{p.port}" if p.port else ""
        new = urlunsplit((p.scheme or default_scheme, f"{host}{port}", p.path or "/", p.query or "", ""))
        return new

    return cand


def _normalize_endpoints_again(endpoints: List[str], default_scheme: str = "https") -> List[str]:
    """
    Normalizza + dedup (case-insensitive). Mantiene path/query; host IDNA+lower;
    rimuove port di default, userinfo e fragment. Per host nudi aggiunge '/' finale.
    Tollerante verso cleaner esterno che rompe netloc/scheme.
    """
    raw = [e for e in (endpoints or []) if isinstance(e, str) and e.strip()]
    out: List[str] = []
    seen: set[str] = set()

    # Cleaner esterno (se presente)
    _clean = None
    try:
        from ingest_normalize import clean_url as _clean  # type: ignore
    except Exception:
        _clean = None

    for u in raw:
        try:
            # step 1: normalizza rumore locale
            s = (u or "").strip().strip('\'"').replace("\\", "/")
            if s.startswith("://"):
                s = f"{default_scheme}{s}"
            if s.startswith("//"):
                s = f"{default_scheme}:{s}"
            s = _HTTP_FIX_RE.sub(r'\1://', s)
            s = _SCHEME_TOKEN_RE.sub(lambda m: m.group(0).split(":")[0].lower() + "://", s)
            if not s.lower().startswith(("http://", "https://")):
                s = f"{default_scheme}://{s.lstrip('/')}"

            # step 2: cleaner esterno (con fallback)
            if _clean:
                s = _safe_external_clean(s, _clean, default_scheme=default_scheme)

            # step 3: parse robusto
            p = urlsplit(s)

            # host
            host = (p.hostname or "").strip().rstrip(".")
            if not host:
                # estrai da netloc e ripulisci da / o \
                net = (p.netloc or "").split("@")[-1]
                host = net.split(":")[0].split("/")[0].split("\\")[0].strip()
            if not host:
                continue

            # IDNA + lower
            try:
                host = host.encode("idna").decode("ascii")
            except Exception:
                pass
            host = host.lower()

            # porta
            scheme = (p.scheme or default_scheme).lower()
            port = p.port
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                port = None
            netloc = host if port is None else f"{host}:{port}"

            # path
            path = (p.path or "/").replace("\\", "/")
            if not path.startswith("/"):
                path = "/" + path
            path = re.sub(r"/{2,}", "/", path)

            # query
            query = (p.query or "").lstrip("?")

            normalized = urlunsplit((scheme, netloc, path, query, ""))

            key = normalized.casefold()
            if key in seen:
                continue
            seen.add(key)
            out.append(normalized)
        except Exception:
            continue

    n_in = len(raw)
    try:
        logger.info("Endpoints cleaned: %d → %d (dedup %d)", n_in, len(out), max(0, n_in - len(out)))
    except Exception:
        pass
    return out
# --- FINE PATCH probe_smuggle.py --------------------------------------------


def run_probe(endpoints: List[str],
              profile: str = "standard",
              budget: Optional[Dict[str, Any]] = None,
              *,
              concurrency: int = 1,
              retries: int = 1,
              timeout: Optional[float] = None,
              total_timeout_s: Optional[float] = None,
              connect_timeout_s: Optional[float] = None,
              read_timeout_s: Optional[float] = None,
              write_timeout_s: Optional[float] = None,
              http2: bool = True,
              user_agent: Optional[str] = None,
              extra_headers: Optional[Dict[str, str]] = None,
              max_redirects: int = 5,
              retry_backoff_base_s: float = 0.2,
              retry_on_status: Tuple[int, ...] = (429, 502, 503, 504),
              max_requests: Optional[int] = None,
              max_time_s: Optional[float] = None,
              per_host_max_requests: Optional[int] = None,
              export: Optional[str] = None,   # <- aggiungi questo
              **_ignored                         # <- o direttamente assorbi tutto
              ) -> List[Dict[str, Any]]:
    """
    Wrapper sincrono. **ADESSO** rispetta davvero concorrenza/timeout/retry.
    - endpoints: lista URL/host (anche nudi, es. 2kleague.nba.com)
    - profile: 'light' (GET+HEAD), 'standard' (GET+HEAD), 'deep' (GET+HEAD+OPTIONS+POST)
    - parametri runtime: concurrency/retries/timeout(s)/http2/UA/headers/redirects
    - budget: dict (opzionale) o singoli parametri max_*
    """
    if not isinstance(endpoints, list) or len(endpoints) == 0:
        logger.info("Nessun endpoint fornito: ritorno lista vuota.")
        return []

    # Normalizza input (evita qualsiasi prefisso Frankenstein)
    eps = _normalize_endpoints_again(endpoints)

    prof = (profile or "standard").strip().lower()
    enrichment = prof in ("deep", "standard+enrich", "enrich", "full", "deep+")

    # Timeouts: se 'timeout' singolo è passato, usalo per read/write e total se mancano
    if timeout is not None:
        read_timeout_s = read_timeout_s or float(timeout)
        write_timeout_s = write_timeout_s or float(timeout)
        total_timeout_s = total_timeout_s or max(float(timeout) * 2.0, float(timeout) + 2.0)
        connect_timeout_s = connect_timeout_s or min(3.0, float(timeout))

    # Defaults finali
    opts = ProbeOpts(
        enrichment=enrichment,
        user_agent=(user_agent or "BrutalGorilla/1.0 (+probe_smuggle)"),
        connect_timeout_s=float(connect_timeout_s or 3.0),
        read_timeout_s=float(read_timeout_s or 5.0),
        write_timeout_s=float(write_timeout_s or 5.0),
        total_timeout_s=float(total_timeout_s or 10.0),
        max_redirects=int(max_redirects),
        body_snippet_bytes=4096,
        concurrency=int(max(1, concurrency)),
        extra_headers=dict(extra_headers or {}),
        http2=bool(http2),
        retries=int(max(0, retries)),
        retry_backoff_base_s=float(retry_backoff_base_s),
        retry_on_status=tuple(retry_on_status or ()),
    )

    # Budget
    bud = Budget()
    if isinstance(budget, dict):
        bud.max_requests = budget.get("max_requests")
        bud.max_time_s = budget.get("max_time_s")
        bud.per_host_max_requests = budget.get("per_host_max_requests")
    bud.max_requests = bud.max_requests if bud.max_requests is not None else max_requests
    bud.max_time_s = bud.max_time_s if bud.max_time_s is not None else max_time_s
    bud.per_host_max_requests = bud.per_host_max_requests if bud.per_host_max_requests is not None else per_host_max_requests

    try:
        return trio.run(probe_pipeline, eps, opts, bud)
    except Exception as e:
        logger.error("Probe exception catturata (fail-soft): %s", e)
        return [
            {
                "url": u,
                "get": {"status": None, "error": f"{type(e).__name__}: {e}", "response_raw": b""},
                "flags": ["NORESP"],
                "score": 0.0,
            }
            for u in eps
        ]



# --------------------------------------------------------------------------------------
# Richiesta singola con retry/backoff (fail-soft)
# --------------------------------------------------------------------------------------

async def _request_once(client: httpx.AsyncClient,
                        method: str,
                        url: str,
                        opts: ProbeOpts) -> Dict[str, Any]:
    """
    Esegue una richiesta con N retry (come prima), ma ora con:
      - Circuit Breaker per host (resilience)
      - WAF-aware pacing (sleep + jitter)
      - Header strategici 'umani'
    """
    from resilience import host_pacing_policy, circuit_breaker_for_host, _update_pacing_after_send  # type: ignore

    host = _host_of(url)
    cb = circuit_breaker_for_host(host)

    attempt = 0
    while True:
        # Circuit gate
        if not cb.allow():
            return {
                "status": None,
                "latency_ms": 0,
                "size": 0,
                "content_type": None,
                "headers": {},
                "security_headers": {"missing": ["csp","hsts","xfo","x_content_type_options","referrer_policy"]},
                "allow_methods": [],
                "set_cookies": [],
                "body": b"",
                "response_raw": b"",
                "waf": False,
                "waf_vendor": None,
                "waf_vendors": [],
                "waf_signals": [],
                "http_version": None,
                "redirect_chain": [],
                "error": "CIRCUIT_OPEN",
            }

        # Header “umani” e strategy
        strat = apply_waf_strategy(url, waf_vendors=None)
        req_headers = {"User-Agent": opts.user_agent, **opts.extra_headers}
        for k, v in strat.get("headers", []):
            req_headers.setdefault(k, v)

        # Pacing prima della richiesta
        pol = host_pacing_policy(host, waf_vendors=None) or {}
        sleep_s = float(pol.get("sleep_s") or 0.0)
        if sleep_s > 0:
            await trio.sleep(sleep_s)

        # Payload benigno per POST
        data = None
        files = None
        if method.upper() == "POST":
            data = {"ping": "1"}
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        started = _now()
        try:
            resp = await client.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
                data=data,
                files=files,
            )
            elapsed_ms = int((_now() - started) * 1000)

            # Pacing dopo l'invio (⚠ usa *pol*, non 'policy'!)
            # Aggiorna pacing dopo l’invio
            _update_pacing_after_send(
                host,
                int(pol.get("base_ms", 150)),
                int(pol.get("jitter_ms", 200)),
            )

            headers = {k: v for k, v in resp.headers.items()}

            # Circuit logic: considera 429 come errore (usa Retry-After), altrimenti SUCCESS
            if resp.status_code == 429:
                # segnala errore con status=429 → aprirà cooldown (ma NON gonfiare fail_count su successi)
                cb.on_error(status=429, headers=headers)
            else:
                cb.on_success()

            headers = {k: v for k, v in resp.headers.items()}
            content_type = _norm_ctype(headers.get("Content-Type") or headers.get("content-type"))
            body_snip = _truncate(resp.content or b"", opts.body_snippet_bytes)
            size = len(resp.content or b"")
            waf_bool, waf_vendor, waf_vendors, waf_signals = _detect_waf(headers, body_snip)

            # Retry-After → informa CB (che a sua volta imposta il pacing)
            try:
                if headers.get("Retry-After"):
                    cb.on_error(status=None, headers=headers)
            except Exception:
                pass

            sec = _extract_security_headers(headers)
            allow_methods = _allow_methods(headers)
            set_cookies = _get_set_cookies(resp)

            return {
                "status": resp.status_code,
                "latency_ms": elapsed_ms,
                "size": size,
                "content_type": content_type,
                "headers": headers,
                "security_headers": sec,
                "allow_methods": allow_methods,
                "set_cookies": set_cookies,
                "body": body_snip,
                "response_raw": body_snip,  # compat
                "waf": waf_bool,
                "waf_vendor": waf_vendor,
                "waf_vendors": waf_vendors,
                "waf_signals": waf_signals,
                "http_version": getattr(resp, "http_version", None),
                "redirect_chain": [str(h.url) for h in getattr(resp, "history", [])],
            }

        except (httpx.TimeoutException, httpx.RequestError) as e:
            elapsed_ms = int((_now() - started) * 1000)
            # Transient → scalda il breaker
            cb.on_error(status=None, headers=None, exc=e)

            transient = isinstance(e, (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.ConnectError))
            if transient and attempt < opts.retries:
                backoff = opts.retry_backoff_base_s * (2 ** attempt)
                await trio.sleep(backoff)
                attempt += 1
                continue

            return {
                "status": None,
                "latency_ms": elapsed_ms,
                "size": 0,
                "content_type": None,
                "headers": {},
                "security_headers": {"missing": ["csp","hsts","xfo","x_content_type_options","referrer_policy"]},
                "allow_methods": [],
                "set_cookies": [],
                "body": b"",
                "response_raw": b"",
                "waf": False,
                "waf_vendor": None,
                "waf_vendors": [],
                "waf_signals": [],
                "http_version": None,
                "redirect_chain": [],
                "error": f"{type(e).__name__}: {e}",
            }

        except Exception as e:
            elapsed_ms = int((_now() - started) * 1000)
            cb.on_error(status=None, headers=None, exc=e)
            return {
                "status": None,
                "latency_ms": elapsed_ms,
                "size": 0,
                "content_type": None,
                "headers": {},
                "security_headers": {"missing": ["csp","hsts","xfo","x_content_type_options","referrer_policy"]},
                "allow_methods": [],
                "set_cookies": [],
                "body": b"",
                "response_raw": b"",
                "waf": False,
                "waf_vendor": None,
                "waf_vendors": [],
                "waf_signals": [],
                "http_version": None,
                "redirect_chain": [],
                "error": f"{type(e).__name__}: {e}",
            }



def _collect_features(resp: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": resp.get("status"),
        "latency_ms": resp.get("latency_ms"),
        "size": resp.get("size"),
        "content_type": resp.get("content_type"),
        "waf": bool(resp.get("waf")),
    }

# --------------------------------------------------------------------------------------
# Pipeline Trio (seriale o concorrente)
# --------------------------------------------------------------------------------------

async def probe_pipeline(endpoints: List[str],
                         opts: Optional[ProbeOpts] = None,
                         budget: Optional[Budget] = None) -> List[Dict[str, Any]]:
    """
    Profili:
      - light: GET + HEAD (no OPTIONS/POST)
      - deep : GET + HEAD + OPTIONS + POST(benigno)
    """
    if opts is None:
        opts = ProbeOpts()
    if budget is None:
        budget = Budget()

    # httpx client setup
    timeout = httpx.Timeout(
        timeout=opts.total_timeout_s,
        connect=opts.connect_timeout_s,
        read=opts.read_timeout_s,
        write=opts.write_timeout_s,
        pool=None,
    )
    limits = httpx.Limits(max_keepalive_connections=max(5, opts.concurrency),
                          max_connections=max(5, opts.concurrency))
    transport = httpx.AsyncHTTPTransport(retries=0)

    # Budget state
    t0 = _now()
    total_requests = 0
    per_host_count: Dict[str, int] = {}

    total_lock = trio.Lock()
    results: List[Dict[str, Any]] = []
    results_lock = trio.Lock()

    def budget_time_exceeded() -> bool:
        return (budget.max_time_s is not None) and ((_now() - t0) > budget.max_time_s)

    async def _inc(host: str, n: int = 1) -> None:
        nonlocal total_requests
        async with total_lock:
            total_requests += n
            per_host_count[host] = per_host_count.get(host, 0) + n

    def _per_host_exceeded(host: str) -> bool:
        if budget.per_host_max_requests is None:
            return False
        return per_host_count.get(host, 0) >= budget.per_host_max_requests

    def _total_exceeded() -> bool:
        return (budget.max_requests is not None) and (total_requests >= budget.max_requests)

    async def _process_one(client: httpx.AsyncClient, url: str) -> Optional[Dict[str, Any]]:
        host = _host_of(url)

        # Budget tempo globale
        if budget_time_exceeded():
            logger.info("Budget tempo esaurito: skip %s", url)
            return None
        # Budget per-host
        if _per_host_exceeded(host):
            logger.info("Budget per host esaurito (%s): skip", host)
            return None
        # Budget totale
        if _total_exceeded():
            logger.info("Budget richieste esaurito: skip %s", url)
            return None

        rec: Dict[str, Any] = {"url": url}

        try:
            # GET
            get_resp = await _request_once(client, "GET", url, opts)
            rec["get"] = get_resp

            # Circuit breaker aperto? non bruciare budget, marca e chiudi
            if get_resp.get("error") == "CIRCUIT_OPEN":
                rec["flags"] = sorted(set((rec.get("flags") or []) + ["CB_OPEN"]))
                return _finalize_record(rec, opts)

            await _inc(host, 1)
            _update_temporal_memory(url, {"method": "GET"}, get_resp, decision="get_base")
            if _PROGRESS_HOOK:
                _PROGRESS_HOOK(url, "GET", get_resp.get("status"), int(get_resp.get("latency_ms") or 0))

            if _total_exceeded() or budget_time_exceeded():
                return _finalize_record(rec, opts)

            # HEAD
            head_resp = await _request_once(client, "HEAD", url, opts)
            rec["head"] = head_resp

            if head_resp.get("error") == "CIRCUIT_OPEN":
                rec["flags"] = sorted(set((rec.get("flags") or []) + ["CB_OPEN"]))
                return _finalize_record(rec, opts)

            await _inc(host, 1)
            _update_temporal_memory(url, {"method": "HEAD"}, head_resp, decision="head_probe")
            if _PROGRESS_HOOK:
                _PROGRESS_HOOK(url, "HEAD", head_resp.get("status"), int(head_resp.get("latency_ms") or 0))

            if opts.enrichment:
                # OPTIONS
                if not (_total_exceeded() or budget_time_exceeded() or _per_host_exceeded(host)):
                    options_resp = await _request_once(client, "OPTIONS", url, opts)
                    rec["options"] = options_resp

                    if options_resp.get("error") == "CIRCUIT_OPEN":
                        rec["flags"] = sorted(set((rec.get("flags") or []) + ["CB_OPEN"]))
                        return _finalize_record(rec, opts)

                    await _inc(host, 1)
                    _update_temporal_memory(url, {"method": "OPTIONS"}, options_resp, decision="options_probe")
                    if _PROGRESS_HOOK:
                        _PROGRESS_HOOK(url, "OPTIONS", options_resp.get("status"),
                                       int(options_resp.get("latency_ms") or 0))

                # POST (benigno)
                if not (_total_exceeded() or budget_time_exceeded() or _per_host_exceeded(host)):
                    post_resp = await _request_once(client, "POST", url, opts)
                    rec["post"] = post_resp

                    if post_resp.get("error") == "CIRCUIT_OPEN":
                        rec["flags"] = sorted(set((rec.get("flags") or []) + ["CB_OPEN"]))
                        return _finalize_record(rec, opts)

                    await _inc(host, 1)
                    _update_temporal_memory(url, {"method": "POST", "benign": True}, post_resp,
                                            decision="post_benign")
                    if _PROGRESS_HOOK:
                        _PROGRESS_HOOK(url, "POST", post_resp.get("status"),
                                       int(post_resp.get("latency_ms") or 0))
            # -------- Proiezione convenience (top-level) --------
            try:
                # primario = GET se presente, poi POST, poi HEAD/OPTIONS
                prim_name = None
                prim = None
                for nm in ("get", "post", "head", "options"):
                    if isinstance(rec.get(nm), dict):
                        prim_name, prim = nm, rec[nm]
                        break
                if prim:
                    rec.setdefault("method", str(prim_name or "").upper() or None)
                    rec.setdefault("status", prim.get("status"))
                    rec.setdefault("latency_ms", prim.get("latency_ms"))
                    rec.setdefault("size", prim.get("size"))
                    if not rec.get("content_type_final"):
                        ct = prim.get("content_type")
                        if not ct:
                            hdrs = prim.get("headers") or {}
                            ct = hdrs.get("content-type") or hdrs.get("Content-Type")
                        rec["content_type_final"] = (ct or rec.get("content_type_final") or "")
            except Exception:
                pass

            return _finalize_record(rec, opts)

        except Exception as e:
            rec.setdefault("errors", []).append(f"fatal:{type(e).__name__}: {e}")
            if _PROGRESS_HOOK:
                _PROGRESS_HOOK(url, "ERROR", None, 0)
            return _finalize_record(rec, opts)

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        limits=limits,
        max_redirects=opts.max_redirects,
        transport=transport,
        verify=True,
        http2=bool(opts.http2),
        headers={"User-Agent": opts.user_agent, **opts.extra_headers},
    ) as client:

        if opts.concurrency <= 1:
            # Serial mode (default)
            for url in endpoints:
                if _total_exceeded() or budget_time_exceeded():
                    logger.info("Stop pipeline per budget.")
                    break
                rec = await _process_one(client, url)
                if rec:
                    results.append(rec)
        else:
            # Concurrent mode con semaforo + append protetto (hardening)
            sem = trio.Semaphore(max(1, opts.concurrency))

            async def worker(u: str):
                try:
                    async with sem:
                        if _total_exceeded() or budget_time_exceeded():
                            return
                        rec = await _process_one(client, u)
                        if rec:
                            async with results_lock:
                                results.append(rec)
                except Exception as e:
                    # Ultima rete di sicurezza: non far mai esplodere il nursery
                    logger.debug("worker fatal on %s: %s", u, e)
                    fallback = {
                        "url": u,
                        "get": {"status": None, "error": f"{type(e).__name__}: {e}", "response_raw": b""},
                        "flags": ["NORESP"],
                        "score": 0.0,
                    }
                    try:
                        finalized = _finalize_record(fallback, opts)
                    except Exception:
                        finalized = fallback
                    async with results_lock:
                        results.append(finalized)

            async with trio.open_nursery() as nursery:
                for u in endpoints:
                    if _total_exceeded() or budget_time_exceeded():
                        break
                    nursery.start_soon(worker, u)

    return results

_PROGRESS_HOOK: Optional[Callable[[str, str, Optional[int], int], None]] = None
def set_progress_hook(fn: Optional[Callable[[str, str, Optional[int], int], None]]) -> None:
    """
    Registra un callback di progresso.
    Firma: fn(url: str, method: str, status: Optional[int], latency_ms: int)
    """
    global _PROGRESS_HOOK
    _PROGRESS_HOOK = fn

# --- REPLACE this function in probe_smuggle.py ---

from typing import Dict, Any, Optional

def waf_fingerprint_from_headers(headers: dict) -> set:
    """
    Ritorna un set di vendor WAF/CDN dedotti SOLO dagli header.
    Conservativa e veloce; non solleva.
    """
    if not isinstance(headers, dict):
        return set()
    h = {str(k).lower(): str(v) for k, v in headers.items() if k is not None}

    server   = h.get("server", "").lower()
    via      = h.get("via", "").lower()
    powered  = h.get("x-powered-by", "").lower()
    sc       = h.get("set-cookie", "").lower()
    xcache   = h.get("x-cache", "").lower()
    servedby = h.get("x-served-by", "").lower()

    vendors = set()

    # Cloudflare
    if "cloudflare" in server or "cf-ray" in h or "cf-cache-status" in h or "cf-connecting-ip" in h or "cf_bm=" in sc:
        vendors.add("Cloudflare")

    # Akamai
    if ("akamai" in server or "akamai" in via
        or any(k.startswith("x-akamai") for k in h.keys())
        or "akamai-" in " ".join(h.keys())):
        vendors.add("Akamai")

    # Imperva/Incapsula
    if "imperva" in server or "incapsula" in server or "x-iinfo" in h or ("x-cdn" in h and "incapsula" in h["x-cdn"].lower()):
        vendors.add("Imperva")
    if "incap_ses" in sc or "visid_incap" in sc:
        vendors.add("Imperva")

    # F5 / BIG-IP / ASM
    if "big-ip" in server or "f5" in server or "x-waf-event" in h or "x-asm" in h or "x-waf-status" in h:
        vendors.add("F5")

    # AWS / CloudFront / ALB / WAF
    if ("cloudfront" in server or "x-amz-cf-id" in h
        or ("cloudfront" in xcache)
        or "awselb" in server or "x-amzn-" in " ".join(h.keys()) or "x-amzn-waf-id" in h):
        vendors.add("AWS")

    # Azure WAF / Front Door
    if "x-azure-ref" in h or "x-msedge-ref" in h or "azure" in server:
        vendors.add("Azure WAF")

    # Sucuri
    if "x-sucuri-id" in h or "x-sucuri-cache" in h or "sucuri" in server:
        vendors.add("Sucuri")

    # Barracuda
    if "barracuda" in server or "x-barracuda-urlfiltering" in h:
        vendors.add("Barracuda")

    # FortiWeb
    if "fortiweb" in server or "fortinet" in server or "x-fortinet" in h:
        vendors.add("FortiWeb")

    # Fastly
    if "fastly" in server or "fastly" in via or "fastly" in powered or ("fastly" in servedby):
        vendors.add("Fastly")

    return vendors


def waf_fingerprint_from_body(body_snip) -> set:
    """
    Ritorna un set di vendor WAF/CDN dedotti dal BODY (pagine di blocco/challenge).
    Accetta bytes/str; conservativa e veloce; non solleva.
    """
    if not body_snip:
        return set()
    try:
        if isinstance(body_snip, (bytes, bytearray)):
            b = body_snip[:4096].decode("utf-8", errors="ignore").lower()
        else:
            b = str(body_snip)[:4096].lower()
    except Exception:
        return set()

    vendors = set()

    # Cloudflare (challenge / 1020 / Ray ID)
    if "cloudflare" in b and ("attention required" in b or "error 1020" in b or "ray id" in b):
        vendors.add("Cloudflare")

    # Akamai deny page
    if "akamai" in b and ("reference number" in b or "access denied" in b):
        vendors.add("Akamai")

    # Imperva/Incapsula
    if "imperva" in b or "incapsula" in b:
        vendors.add("Imperva")

    # F5 ASM / BIG-IP
    if "big-ip" in b or ("asm" in b and "support id" in b) or ("f5" in b and "support id" in b):
        vendors.add("F5")

    # AWS / CloudFront
    if ("generated by cloudfront" in b) or ("request blocked" in b and "aws" in b):
        vendors.add("AWS")

    # Azure WAF
    if "azure waf" in b or ("request blocked" in b and "azure" in b):
        vendors.add("Azure WAF")

    # Sucuri
    if "sucuri" in b:
        vendors.add("Sucuri")

    # FortiWeb
    if "fortiweb" in b or "fortinet" in b:
        vendors.add("FortiWeb")

    # Barracuda
    if "barracuda" in b:
        vendors.add("Barracuda")

    # Fastly
    if "fastly error" in b or ("x-served-by" in b and "fastly" in b):
        vendors.add("Fastly")

    return vendors

def _finalize_record(rec: Dict[str, Any], opts: Optional[ProbeOpts] = None) -> Dict[str, Any]:
    """
    Consolidamento LOCALE del record sonda:
      - Seleziona il blocco 'migliore' e proietta: method/status/latency_ms/size
      - Determina content_type_final (redirect-aware/sniff) in MIME
      - Estrae allowed_methods / security_headers
      - Calcola body_snip, http_version, redirect_chain
      - Raccoglie WAF vendors (headers+body) da TUTTI i blocchi (filtrando token generici)
      - Classifica parametri (KB se presente) → param_families, family_counts, family
    Fail-soft garantito: mai eccezioni propagate.
    """
    try:
        # --- 0) helpers ---
        def _as_block(d):
            return d if isinstance(d, dict) else {}

        blocks = {k: _as_block(rec.get(k)) for k in ("get", "post", "head", "options")}
        order = ("get", "post", "head", "options")

        def _lat(b: Dict[str, Any]) -> float:
            try:
                return float(b.get("latency_ms") or b.get("latency") or 9e9)
            except Exception:
                return 9e9

        # preferisci blocchi con status valorizzato, poi GET>POST>HEAD>OPTIONS, poi latenza
        with_status = [(k, b) for k, b in blocks.items() if b and (b.get("status") is not None)]
        if with_status:
            best_key, best_blk = sorted(with_status, key=lambda it: (order.index(it[0]), _lat(it[1])))[0]
        else:
            cand = [(k, b) for k, b in blocks.items() if b]
            best_key, best_blk = (sorted(cand, key=lambda it: (order.index(it[0]), _lat(it[1])))[0] if cand else (None, {}))

        # --- 1) proiezione top-level: method/status/latency/size ---
        if best_key:
            rec["method"] = str(best_key).upper()
        else:
            # se non c'è nessun blocco (caso raro), mantieni eventuale method già presente o placeholder
            rec.setdefault("method", "—")

        # status / latency / size
        if rec.get("status") is None:
            rec["status"] = best_blk.get("status")
        try:
            if rec.get("latency_ms") is None:
                lat = best_blk.get("latency_ms", best_blk.get("latency"))
                rec["latency_ms"] = None if lat is None else float(lat)
        except Exception:
            rec.setdefault("latency_ms", None)
        if rec.get("size") in (None, "—"):
            rec["size"] = best_blk.get("size", rec.get("size"))

        # --- 2) content_type_final (redirect-aware / headers / content_type / sniff) ---
        def _norm_mime(val: object) -> str:
            if val is None:
                return ""
            s = str(val).strip().strip('"').strip("'")
            if not s:
                return ""
            if "," in s: s = s.split(",", 1)[0].strip()
            if ";" in s: s = s.split(";", 1)[0].strip()
            s = s.lower()
            # mapping di parole chiave a MIME (fallback)
            if "/" not in s:
                map_kw = {
                    "json": "application/json",
                    "html": "text/html",
                    "xml": "application/xml",
                    "plain": "text/plain",
                    "javascript": "text/javascript",
                    "js": "text/javascript",
                    "css": "text/css",
                    "octet": "application/octet-stream",
                }
                s = map_kw.get(s, s)
            return s if "/" in s else ""

        def _mime_from_block(b: dict) -> str:
            # redirect_chain last headers
            chain = b.get("redirect_chain") or []
            if isinstance(chain, (list, tuple)) and chain:
                last = chain[-1]
                if isinstance(last, dict):
                    hh = (last.get("headers") or {})
                    ct = hh.get("content-type") or hh.get("Content-Type")
                    ct = _norm_mime(ct)
                    if ct:
                        return ct
            # headers block
            hdrs = b.get("headers") or {}
            ct = hdrs.get("content-type") or hdrs.get("Content-Type")
            ct = _norm_mime(ct)
            if ct:
                return ct
            # field content_type
            ct = _norm_mime(b.get("content_type"))
            if ct:
                return ct
            # sniff minimale
            body = b.get("body") or b.get("text") or b""
            try:
                snippet = body[:1024].decode("utf-8", errors="ignore").lower() if isinstance(body, (bytes, bytearray)) else str(body)[:1024].lower()
            except Exception:
                snippet = ""
            if snippet.startswith("{") or snippet.startswith("["):
                return "application/json"
            if "<html" in snippet or "<!doctype html" in snippet:
                return "text/html"
            return ""

        ct_final = ""
        if best_blk:
            ct_final = _mime_from_block(best_blk)
        if not ct_final:
            for k in order:
                if blocks.get(k):
                    ct_final = _mime_from_block(blocks[k])
                    if ct_final:
                        break
        rec["content_type_final"] = ct_final

        # --- 3) allowed methods & security headers (conservativi) ---
        allowed: List[str] = []
        try:
            for k in ("options", "get", "post", "head"):
                b = blocks.get(k) or {}
                if not b:
                    continue
                hdrs = b.get("headers") or {}
                allow = hdrs.get("allow") or hdrs.get("Allow")
                acam  = hdrs.get("access-control-allow-methods") or hdrs.get("Access-Control-Allow-Methods")
                cand: List[str] = []
                if isinstance(allow, str) and allow.strip():
                    cand.extend([m.strip().upper() for m in allow.split(",") if m.strip()])
                if isinstance(acam, str) and acam.strip():
                    cand.extend([m.strip().upper() for m in acam.split(",") if m.strip()])
                if cand:
                    allowed = list(dict.fromkeys(cand))
                    break
        except Exception:
            pass
        rec["allowed_methods"] = allowed
        rec.setdefault("allow_methods", allowed)

        try:
            hdrs = (best_blk.get("headers") or {}) if best_blk else {}
            low = {str(k).lower(): v for k, v in hdrs.items()}
            need = {
                "strict-transport-security",
                "x-frame-options",
                "x-content-type-options",
                "content-security-policy",
            }
            miss = sorted([k for k in need if k not in low])
            sh = rec.get("security_headers")
            if not isinstance(sh, dict):
                sh = {}
            prev = set([str(x).lower() for x in (sh.get("missing") or [])]) if isinstance(sh.get("missing"), list) else set()
            sh["missing"] = sorted(list(prev.union(set(miss))))
            rec["security_headers"] = sh
        except Exception:
            rec.setdefault("security_headers", {"missing": []})

        # --- 4) body_snip (dal blocco migliore) ---
        try:
            body = best_blk.get("body") or b""
            if isinstance(body, (bytes, bytearray)):
                try:
                    snippet = body[:2048].decode("utf-8", errors="ignore")
                except Exception:
                    snippet = body[:2048].decode("iso-8859-1", errors="ignore")
            else:
                snippet = str(body)[:2048]
            rec["body_snip"] = snippet
        except Exception:
            rec.setdefault("body_snip", "")

        # --- 5) http_version / redirect_chain ---
        try:
            http_ver = best_blk.get("http_version") or rec.get("http_version")
            if http_ver:
                rec["http_version"] = str(http_ver)
        except Exception:
            pass
        try:
            rc = rec.get("redirect_chain")
            if rc is None:
                rc = best_blk.get("redirect_chain")
            rec["redirect_chain"] = list(rc) if isinstance(rc, (list, tuple)) else []
        except Exception:
            rec.setdefault("redirect_chain", [])

        # --- 6) WAF vendors: somma su TUTTI i blocchi (headers + body) ---
        try:
            vendors = set()
            for k in order:
                b = blocks.get(k) or {}
                if not b:
                    continue
                hdrs = b.get("headers") or {}
                body = b.get("body") or b.get("text") or b""
                vendors |= set(waf_fingerprint_from_headers(hdrs))
                vendors |= set(waf_fingerprint_from_body(body))

            # merge con eventuali campi già presenti
            if isinstance(rec.get("waf_vendors"), (list, tuple)):
                vendors |= {str(x) for x in rec.get("waf_vendors") if x}
            if rec.get("waf_vendor"):
                vendors.add(str(rec.get("waf_vendor")))

            # filtro token generici / vuoti
            bad = {"", "unknown", "unknown-waf", "waf", "none", "null", "false"}
            vendors = {v.strip() for v in vendors if isinstance(v, str)}
            vendors = {v for v in vendors if v.lower() not in bad}

            rec["waf_vendors"] = sorted(vendors)
        except Exception:
            rec.setdefault("waf_vendors", [])

        # --- 7) Param families (KB se disponibile) → family_counts / family ---
        try:
            fams, counts = _classify_params_for_url(
                rec.get("url") or "",
                getattr(opts, "kb_param_families_path", None) if opts else None,
                getattr(opts, "content_type_hint", None) if opts else None,
                getattr(opts, "template_engine_hint", None) if opts else None,
            )
            rec["param_families"] = fams
            rec["family_counts"] = counts

            # family principale: più frequente; fallback su MIME/percorso
            fam_best = None
            if counts:
                fam_best = max(counts.items(), key=lambda kv: kv[1])[0]
            if not fam_best:
                try:
                    from urllib.parse import urlparse
                    path = (urlparse(rec.get("url") or "").path or "").lower()
                except Exception:
                    path = ""
                t = rec.get("content_type_final", "").lower()
                if t.startswith("application/json") or path.startswith("/api"):
                    fam_best = "api"
                elif t.startswith("text/html"):
                    fam_best = "webpage"
                elif t.startswith(("text/javascript", "application/javascript", "text/css")):
                    fam_best = "static"
                elif t.startswith("image/"):
                    fam_best = "asset"
                elif t.startswith("application/pdf"):
                    fam_best = "document"
                elif t.startswith("text/"):
                    fam_best = "raw"
                elif t.startswith("application/octet-stream"):
                    fam_best = "binary"
                else:
                    fam_best = "unknown"
            rec["family"] = fam_best
        except Exception:
            rec.setdefault("param_families", [])
            rec.setdefault("family_counts", {})
            rec.setdefault("family", "unknown")

        return rec

    except Exception:
        # Fail-soft totale: restituisci il record com'è, ma garantendo campi minimi
        rec.setdefault("method", rec.get("method") or "—")
        rec.setdefault("status", rec.get("status"))
        rec.setdefault("latency_ms", rec.get("latency_ms"))
        rec.setdefault("size", rec.get("size"))
        rec.setdefault("content_type_final", rec.get("content_type_final") or "")
        rec.setdefault("waf_vendors", [])
        rec.setdefault("allowed_methods", [])
        rec.setdefault("security_headers", {"missing": []})
        rec.setdefault("body_snip", "")
        rec.setdefault("redirect_chain", [])
        rec.setdefault("family", "unknown")
        return rec


def _extract_final_content_type(resp: dict) -> str:
    """
    Restituisce il MIME 'secco' della RISPOSTA FINALE (post-redirect) per un blocco risposta (es. rec['get']).
    Ordine candidati:
      1) headers dell'ULTIMO hop in redirect_chain
      2) headers del blocco corrente (resp['headers'])
      3) resp['content_type']
    Se tutti assenti, prova a “sniffare” dal body (json/html).
    Normalizza rimuovendo parametri ('; charset=...'), prende il primo in caso di lista 'type1, type2'.
    """
    def _norm_mime(val: object) -> str:
        if val is None:
            return ""
        s = str(val).strip().strip('"').strip("'")
        if not s:
            return ""
        if "," in s:
            s = s.split(",", 1)[0].strip()
        if ";" in s:
            s = s.split(";", 1)[0].strip()
        s = s.lower()
        if "/" not in s:
            map_kw = {
                "json": "application/json",
                "html": "text/html",
                "xml": "application/xml",
                "plain": "text/plain",
                "javascript": "text/javascript",
                "js": "text/javascript",
                "css": "text/css",
                "octet": "application/octet-stream",
            }
            s = map_kw.get(s, s)
        return s if "/" in s else ""

    # 1) redirect_chain → ultimo hop con Content-Type
    try:
        chain = resp.get("redirect_chain") or []
        if isinstance(chain, (list, tuple)) and chain:
            last = chain[-1] or {}
            hdrs = (last.get("headers") or {}) if isinstance(last, dict) else {}
            ct = hdrs.get("content-type") or hdrs.get("Content-Type")
            ct = _norm_mime(ct)
            if ct:
                return ct
    except Exception:
        pass

    # 2) headers del blocco corrente
    try:
        hdrs = resp.get("headers") or {}
        ct = hdrs.get("content-type") or hdrs.get("Content-Type")
        ct = _norm_mime(ct)
        if ct:
            return ct
    except Exception:
        pass

    # 3) campo content_type del blocco corrente
    ct = _norm_mime(resp.get("content_type"))
    if ct:
        return ct

    # 4) sniff leggero dal body
    try:
        body = resp.get("body") or b""
        if isinstance(body, bytes):
            try:
                s = body[:2048].decode("utf-8", errors="ignore").strip().lower()
            except Exception:
                s = body[:2048].decode("iso-8859-1", errors="ignore").strip().lower()
        else:
            s = str(body)[:2048].strip().lower()
        if s.startswith("{") or s.startswith("["):
            return "application/json"
        if "<html" in s or "<!doctype html" in s:
            return "text/html"
    except Exception:
        pass

    return ""

