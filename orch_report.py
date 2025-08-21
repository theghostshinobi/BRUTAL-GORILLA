# orch_report.py
# Orchestratore sincrono con policy export selettiva + sanitizzazione bytes per JSON
# - Normalizza e deduplica SEMPRE gli endpoint prima di sondare (case-insensitive)
# - Non lascia MAI propagare eccezioni del probe: converte in record di errore e continua
# - Analisi/renderer tolleranti a status=None
# - Nessuna scrittura su disco se export=none
# - JSON/CSV/both secondo richiesta
# - Restituisce sempre un output in memoria per la CLI
# - INTEGRAZIONI: KB families (match_order exact>regex>substring), context overrides, composite rules

from __future__ import annotations

import os
import io
import json
import csv
import time
import logging
import inspect
from typing import List, Dict, Any, Tuple, Iterable, Optional

import re
# Trio è usato solo se dobbiamo avviare direttamente una coroutine
import trio

import numpy as np
import yaml


logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

# --------------------------------------------------------------------------- #
# INGEST NORMALIZE (opzionale)                                                #
# --------------------------------------------------------------------------- #

try:
    from ingest_normalize import clean_url as _ingest_clean_url  # type: ignore
except Exception:
    _ingest_clean_url = None

# --------------------------------------------------------------------------- #
# KB FAMILIES                                                                 #
# --------------------------------------------------------------------------- #

KB_FAMILIES: Dict[str, Any] = {}

def _load_kb_param_families(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Carica una KB YAML con le regole param->famiglia.
    Chiavi: meta.default_family, meta.default_priority, meta.match_order,
            exact, regex, substring, composite, context_overrides
    """
    global KB_FAMILIES
    path = cfg.get("kb_param_family_file")
    if not path or not os.path.exists(path):
        logger.warning("KB param families file non trovata: %r (uso defaults)", path)
        KB_FAMILIES = {
            "meta": {
                "default_family": "GENERIC",
                "default_priority": 10,
                "match_order": ["exact", "regex", "substring"],
                "confidence_scale": ["low","medium","high","certain"],
            },
            "exact": {}, "regex": [], "substring": [],
            "composite": [],
            "context_overrides": {
                "by_path_regex": [],
                "by_content_type": {},
                "by_template_engine_hint": {},
            },
        }
        return KB_FAMILIES

    with open(path, "r", encoding="utf-8") as f:
        KB_FAMILIES = yaml.safe_load(f) or {}

    # Defaults non distruttivi
    KB_FAMILIES.setdefault("meta", {})
    KB_FAMILIES["meta"].setdefault("default_family", "GENERIC")
    KB_FAMILIES["meta"].setdefault("default_priority", 10)
    KB_FAMILIES["meta"].setdefault("match_order", ["exact","regex","substring"])
    KB_FAMILIES.setdefault("exact", {})
    KB_FAMILIES.setdefault("regex", [])
    KB_FAMILIES.setdefault("substring", [])
    KB_FAMILIES.setdefault("composite", [])
    KB_FAMILIES.setdefault("context_overrides", {})
    KB_FAMILIES["context_overrides"].setdefault("by_path_regex", [])
    KB_FAMILIES["context_overrides"].setdefault("by_content_type", {})
    KB_FAMILIES["context_overrides"].setdefault("by_template_engine_hint", {})
    # opzionali
    KB_FAMILIES.setdefault("value_hints", {})
    KB_FAMILIES.setdefault("bypass_hints", {})
    KB_FAMILIES.setdefault("noise", {})
    KB_FAMILIES.setdefault("notes", [])
    return KB_FAMILIES

def _kb_match_order() -> List[str]:
    if not KB_FAMILIES:
        return ["exact","regex","substring"]
    mo = KB_FAMILIES.get("meta", {}).get("match_order") or ["exact","regex","substring"]
    # sanifica
    out = [m for m in mo if m in ("exact","regex","substring")]
    return out or ["exact","regex","substring"]

def _apply_context_overrides(fam: Dict[str, Any],
                             path_hint: str,
                             content_type: str,
                             template_engine_hint: str = "") -> Dict[str, Any]:
    """
    Applica gli override di contesto (path/ctype/template engine) aumentando priorità
    e/o preferendo una famiglia (non distruttivo).
    """
    co = KB_FAMILIES.get("context_overrides") or {}
    out = dict(fam)
    try:
        # path regex
        for r in co.get("by_path_regex", []) or []:
            pat = r.get("pattern")
            if not pat:
                continue
            if re.search(pat, path_hint or "", flags=re.IGNORECASE):
                pf = r.get("prefer_family")
                ap = int(r.get("add_priority", 0) or 0)
                if pf:
                    out["family"] = pf
                out["priority"] = int(out.get("priority", KB_FAMILIES["meta"]["default_priority"])) + ap
        # content-type
        ct_map = co.get("by_content_type") or {}
        ct_low = (content_type or "").lower()
        if ct_low in ct_map:
            d = ct_map[ct_low] or {}
            pf = d.get("prefer_family"); ap = int(d.get("add_priority", 0) or 0)
            if pf: out["family"] = pf
            out["priority"] = int(out.get("priority", KB_FAMILIES["meta"]["default_priority"])) + ap
        else:
            for key, d in ct_map.items():
                try:
                    k = str(key).lower()
                except Exception:
                    continue
                if k and k in ct_low:
                    pf = (d or {}).get("prefer_family"); ap = int((d or {}).get("add_priority", 0) or 0)
                    if pf: out["family"] = pf
                    out["priority"] = int(out.get("priority", KB_FAMILIES["meta"]["default_priority"])) + ap
        # template engine hint (se passato)
        if template_engine_hint:
            te_map = co.get("by_template_engine_hint") or {}
            for pat, d in te_map.items():
                try:
                    if re.search(pat, template_engine_hint, flags=re.IGNORECASE):
                        pf = (d or {}).get("prefer_family"); ap = int((d or {}).get("add_priority", 0) or 0)
                        if pf: out["family"] = pf
                        out["priority"] = int(out.get("priority", KB_FAMILIES["meta"]["default_priority"])) + ap
                except Exception:
                    continue
    except Exception:
        return fam
    return out

def match_param_to_family(name: str,
                          path_hint: str = "",
                          content_type: str = "",
                          value: str = "",
                          template_engine_hint: str = "") -> Dict[str, Any]:
    """
    Match case-insensitive con ordine: exact > regex > substring (configurabile da meta.match_order).
    Applica context_overrides (path/ctype/template engine). Non fa assunzioni sul valore.
    Ritorna dict con: family, priority, confidence, [notes]
    """
    if not KB_FAMILIES:
        return {"family": "GENERIC", "priority": 10, "confidence": "low"}

    name_cf = (name or "").casefold()
    base = {
        "family": KB_FAMILIES["meta"]["default_family"],
        "priority": KB_FAMILIES["meta"]["default_priority"],
        "confidence": "low",
    }

    def _match_exact() -> Optional[Dict[str, Any]]:
        for k, v in KB_FAMILIES.get("exact", {}).items():
            if str(k).casefold() == name_cf:
                out = dict(v or {})
                out.setdefault("family", base["family"])
                out.setdefault("priority", base["priority"])
                out.setdefault("confidence", "high")
                return out
        return None

    def _match_regex() -> Optional[Dict[str, Any]]:
        for rule in KB_FAMILIES.get("regex", []) or []:
            pat = rule.get("pattern")
            if not pat:
                continue
            try:
                if re.search(pat, name or "", flags=re.IGNORECASE):
                    out = {k: v for k, v in (rule or {}).items() if k != "pattern"}
                    out.setdefault("family", base["family"])
                    out.setdefault("priority", base["priority"])
                    out.setdefault("confidence", "high")
                    return out
            except Exception:
                continue
        return None

    def _match_sub() -> Optional[Dict[str, Any]]:
        for rule in KB_FAMILIES.get("substring", []) or []:
            sub = (rule.get("contains") or "").casefold()
            if sub and sub in name_cf:
                out = {k: v for k, v in (rule or {}).items() if k != "contains"}
                out.setdefault("family", base["family"])
                out.setdefault("priority", base["priority"])
                out.setdefault("confidence", "medium")
                return out
        return None

    order = _kb_match_order()
    found: Optional[Dict[str, Any]] = None
    for stage in order:
        if stage == "exact":
            found = _match_exact()
        elif stage == "regex":
            found = _match_regex()
        elif stage == "substring":
            found = _match_sub()
        if found:
            break

    fam = found or base
    # Apply context overrides
    fam = _apply_context_overrides(fam, path_hint=path_hint, content_type=content_type, template_engine_hint=template_engine_hint)
    return fam

def _evaluate_composite(params: List[str]) -> Dict[str, Any]:
    """
    Valuta regole composite su insiemi di parametri (when_all/when_any).
    Ritorna: {"raise_to": <fam or "">, "also_mark": [fam,...], "add_priority": int}
    """
    out = {"raise_to": "", "also_mark": [], "add_priority": 0}
    try:
        rules = KB_FAMILIES.get("composite") or []
        names = {str(p).lower() for p in (params or [])}
        for r in rules:
            when_all = {x.lower() for x in (r.get("when_all") or [])}
            when_any = {x.lower() for x in (r.get("when_any") or [])}
            ok_all = (not when_all) or all(x in names for x in when_all)
            ok_any = (not when_any) or any(x in names for x in when_any)
            if ok_all and ok_any:
                if r.get("raise_family_to"):
                    out["raise_to"] = str(r["raise_family_to"])
                if r.get("also_mark"):
                    als = r["also_mark"]
                    if isinstance(als, (list, tuple, set)):
                        out["also_mark"] = list({str(x) for x in als})
                    elif isinstance(als, str):
                        out["also_mark"] = list({als})
                ap = int(r.get("add_priority", 0) or 0)
                out["add_priority"] = max(out["add_priority"], ap)
        return out
    except Exception:
        return out

# --------------------------------------------------------------------------- #
# OPTIONAL LIBS (gestite in modo tollerante)                                  #
# --------------------------------------------------------------------------- #

try:
    import shap  # type: ignore
except Exception:
    shap = None

try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.feature_extraction.text import CountVectorizer
except Exception:
    LogisticRegression = None  # type: ignore
    CountVectorizer = None     # type: ignore

try:
    from pydantic import BaseModel, ValidationError
    PydanticAvailable = True
except Exception:
    BaseModel = object  # type: ignore
    ValidationError = Exception  # type: ignore
    PydanticAvailable = False

try:
    from pmdarima import auto_arima  # type: ignore
except Exception:
    auto_arima = None

# --------------------------------------------------------------------------- #
# NORMALIZZAZIONE ENDPOINTS                                                   #
# --------------------------------------------------------------------------- #

_SCHEME_TOKEN_RE = re.compile(r'^(?i)(?:https?[:/]+)+')
_HTTP_FIX_RE     = re.compile(r'(?i)\b(https?):/')

def _fix_scheme_typos(u: str, default_scheme: str = "https") -> str:
    s = (u or "").strip().strip('\'"')
    if not s:
        return s
    s = s.replace("\\", "/").replace(" ", "")

    if s.startswith("://"):
        s = f"{default_scheme}{s}"
    if s.startswith("//"):
        s = f"{default_scheme}:{s}"

    s = _HTTP_FIX_RE.sub(r'\1://', s)
    s = re.sub(r'^(?i)(https?://)+(.*)$', lambda m: m.group(1).lower() + m.group(2), s)

    if not s.lower().startswith(("http://","https://")):
        s = _SCHEME_TOKEN_RE.sub("", s.lstrip("/"))
        s = f"{default_scheme}://{s.lstrip('/')}"

    s = re.sub(r'^(?i)(https?://)(?:https?://)+', r'\1', s)
    s = re.sub(r'^(?i)(https?://)/+', r'\1', s)
    return s

def _ensure_scheme(u: str, default: str = "https") -> str:
    s = (u or "").strip()
    if not s:
        return s
    if "://" in s:
        last = s.rfind("://")
        scheme_blob = s[:last].lower()
        scheme = "https" if "https" in scheme_blob else ("http" if "http" in scheme_blob else default)
        tail = s[last + 3 :]
        return f"{scheme}://{tail.lstrip('/')}"
    return _fix_scheme_typos(s, default_scheme=default)

# --- PATCH orch_report.py : robust normalize --------------------------------
import re
from urllib.parse import urlsplit, urlunsplit

_SCHEME_TOKEN_RE = re.compile(r'^(?:https?[:/]+)+', re.IGNORECASE)
_HTTP_FIX_RE     = re.compile(r'\b(https?):/', re.IGNORECASE)

def _safe_external_clean(s: str, cleaner, default_scheme: str = "https") -> str:
    try:
        cand = cleaner(s)
    except Exception:
        return s
    if not isinstance(cand, str) or not cand.strip():
        return s
    cand = cand.strip().replace("\\", "/")
    cand = _HTTP_FIX_RE.sub(r'\1://', cand)
    if not cand.lower().startswith(("http://", "https://")):
        cand = _SCHEME_TOKEN_RE.sub("", cand.lstrip("/"))
        cand = f"{default_scheme}://{cand.lstrip('/')}"
    p = urlsplit(cand)
    if not (p.hostname or "").strip():
        return s
    if "/" in (p.netloc or "") or "\\" in (p.netloc or ""):
        host = (p.hostname or "").strip().lower()
        port = f":{p.port}" if p.port else ""
        return urlunsplit((p.scheme or default_scheme, f"{host}{port}", p.path or "/", p.query or "", ""))
    return cand

def _normalize_endpoints_again(endpoints: List[str]) -> List[str]:
    raw_input = [e for e in (endpoints or []) if isinstance(e, str) and e.strip()]
    cleaned_seq: List[str] = []

    # cleaner orchestratore (se lo esponi così) oppure None
    _clean_fn = globals().get("_ingest_clean_url", None)

    for e in raw_input:
        try:
            s = (e or "").strip().strip('\'"').replace("\\", "/")
            if s.startswith("://"):
                s = "https" + s
            if s.startswith("//"):
                s = "https:" + s
            s = _HTTP_FIX_RE.sub(r'\1://', s)
            s = _SCHEME_TOKEN_RE.sub(lambda m: m.group(0).split(":")[0].lower() + "://", s)
            if not s.lower().startswith(("http://", "https://")):
                s = "https://" + s.lstrip("/")

            if callable(_clean_fn):
                s = _safe_external_clean(s, _clean_fn, default_scheme="https")

            p = urlsplit(s)

            host = (p.hostname or "").rstrip(".")
            if not host:
                net = (p.netloc or "").split("@")[-1]
                host = net.split(":")[0].split("/")[0].split("\\")[0].strip()
            if not host:
                continue

            try:
                host = host.encode("idna").decode("ascii")
            except Exception:
                pass
            host = host.lower()

            scheme = (p.scheme or "https").lower()
            port = p.port
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                port = None
            netloc = host if port is None else f"{host}:{port}"

            path = (p.path or "/").replace("\\", "/")
            if not path.startswith("/"):
                path = "/" + path
            path = re.sub(r"/{2,}", "/", path)

            rebuilt = urlunsplit((scheme, netloc, path, p.query or "", ""))

            cleaned_seq.append(rebuilt)
        except Exception:
            continue

    seen: set[str] = set()
    out: List[str] = []
    for u in cleaned_seq:
        k = u.casefold()
        if k not in seen:
            seen.add(k)
            out.append(u)

    try:
        before, after = len(endpoints or []), len(out)
        dedup_n = max(0, len(cleaned_seq) - after)
        logger.info("Endpoints cleaned: %d → %d (dedup %d)", before, after, dedup_n)
    except Exception:
        pass

    return out
# --- FINE normalizzatori orch_report.py -------------------------------------



# --- FINE normalizzatori orch_report.py ------------------------------------


# --------------------------------------------------------------------------- #
# SECUREBERT ADAPTER (single-init)                                            #
# --------------------------------------------------------------------------- #

class _SecureBERTHandle:
    def __init__(self, adapter: Any):
        self.adapter = adapter

def _maybe_load_securebert(cfg: Dict[str, Any]) -> Optional[_SecureBERTHandle]:
    """
    Carica SecureBERT una sola volta (offline). Restituisce handle oppure None.
    Config keys (facoltative):
      securebert_path: str
    """
    path = cfg.get("securebert_path")
    if not path:
        return None
    try:
        import securebert_adapter  # type: ignore
    except Exception as e:
        logger.warning("SecureBERT adapter non disponibile: %s", e)
        return None
    t0 = time.perf_counter()
    adapter = None
    try:
        if hasattr(securebert_adapter, "load"):
            adapter = securebert_adapter.load(path)  # type: ignore[attr-defined]
        elif hasattr(securebert_adapter, "SecureBERT"):
            adapter = securebert_adapter.SecureBERT(path)  # type: ignore
    except Exception as e:
        logger.warning("Impossibile inizializzare SecureBERT da %r: %s", path, e)
        adapter = None
    if adapter is None:
        return None
    dt = time.perf_counter() - t0
    logger.info("SecureBERT caricato in %.3fs da %s", dt, path)
    return _SecureBERTHandle(adapter)

def _embed_similarity_score(secure: Optional[_SecureBERTHandle],
                            payload_text: str,
                            resp_bytes: bytes) -> float:
    """
    Se SecureBERT è disponibile: similarità coseno tra embed(payload) e embed(response_text).
    Altrimenti fallback su analysis_bypass.embed_score.
    """
    if not payload_text:
        return 0.0
    if secure and getattr(secure.adapter, "embed", None):
        try:
            try:
                resp_text = resp_bytes.decode("utf-8")
            except Exception:
                resp_text = resp_bytes.decode("iso-8859-1", errors="ignore")
            v1 = np.array(secure.adapter.embed(payload_text), dtype=float).reshape(-1)  # type: ignore
            v2 = np.array(secure.adapter.embed(resp_text), dtype=float).reshape(-1)    # type: ignore
            if v1.size == 0 or v2.size == 0:
                return 0.0
            num = float(np.dot(v1, v2))
            den = float(np.linalg.norm(v1) * np.linalg.norm(v2))
            return float(num / den) if den > 1e-12 else 0.0
        except Exception as e:
            logger.debug("SecureBERT embed similarity fallback: %s", e)
    # fallback legacy
    from analysis_bypass import embed_score  # type: ignore
    return float(embed_score([payload_text], resp_bytes or b""))

# --------------------------------------------------------------------------- #
# FALLBACK HELPERS (load endpoints + clean + unique)                          #
# --------------------------------------------------------------------------- #

def _maybe_ingest_helpers():
    """
    Prova a importare da ingest_normalize, altrimenti usa fallback basilari.
    Ritorna: (load_endpoints, clean_url, unique_filter)
    """
    try:
        from ingest_normalize import load_endpoints, clean_url, unique_filter  # type: ignore
        return load_endpoints, clean_url, unique_filter
    except Exception:
        logger.warning("[WARN] ingest_normalize non disponibile: uso fallback basilari.")

        def _load_endpoints_fallback(path: str) -> List[str]:
            eps: List[str] = []
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        eps.append(s)
            return eps

        def _clean_url_fallback(u: str) -> str:
            try:
                from url_normalize import url_normalize  # type: ignore
                return url_normalize(u.strip())
            except Exception:
                return u.strip()

        def _unique_filter_fallback(seq: List[str]) -> List[str]:
            seen = set()
            out: List[str] = []
            for item in seq:
                if item not in seen:
                    seen.add(item)
                    out.append(item)
            return out

        return _load_endpoints_fallback, _clean_url_fallback, _unique_filter_fallback

# --------------------------------------------------------------------------- #
# VALIDATION & SCHEMA                                                         #
# --------------------------------------------------------------------------- #

class OrchestratorOutput(BaseModel):  # type: ignore[misc]
    endpoints: List[str]
    probe_results: List[Dict[str, Any]]
    fuzz_results: List[Dict[str, Any]]
    diff_results: List[Dict[str, Any]]
    jwt_findings: List[List[Dict[str, Any]]]
    embed_scores: List[float]
    security_scores: List[float]
    dl_variants: List[str]
    schedule: List[str]
    report_svg: str
    forecast: Dict[str, float]
    # opzionali/extra
    render_ready: Optional[List[Dict[str, Any]]] = None
    legend: Optional[Dict[str, Dict[str, str]]] = None
    export_paths: Optional[Dict[str, str]] = None
    profile_used: Optional[str] = None
    probe_params: Optional[Dict[str, Any]] = None

    class Config:
        arbitrary_types_allowed = True
        extra = "allow"

def validate_schema(data: Dict[str, Any]) -> None:
    if not PydanticAvailable:
        logger.warning("[WARN] Pydantic non disponibile: skip schema validation.")
        return
    try:
        OrchestratorOutput(**data)  # type: ignore[call-arg]
    except ValidationError as e:  # type: ignore[misc]
        logger.error("Schema validation error:\n%s", e.json())
        raise

# --------------------------------------------------------------------------- #
# CONFIG + ENDPOINTS + EXPORT POLICY                                          #
# --------------------------------------------------------------------------- #

def _parse_bool_env(val: str | None) -> None | bool:
    if val is None:
        return None
    v = val.strip().lower()
    if v in ("1", "true", "yes", "y", "on"):
        return True
    if v in ("0", "false", "no", "n", "off"):
        return False
    return None

def _normalize_export_format(fmt: str | None) -> str:
    f = (fmt or "none").strip().lower()
    if f in ("none", "json", "csv", "both"):
        return f
    if f in ("all", "any"):
        return "both"
    return "none"

def _determine_export_policy(cfg: Dict[str, Any]) -> Tuple[str, bool]:
    env_fmt = os.getenv("SCAN_EXPORT_FORMAT") or os.getenv("EXPORT_FORMAT")
    env_write = _parse_bool_env(os.getenv("SCAN_WRITE_OUTPUTS") or os.getenv("WRITE_OUTPUTS"))

    cfg_fmt = _normalize_export_format(cfg.get("export_format"))
    export_format = _normalize_export_format(env_fmt) if env_fmt else cfg_fmt

    cfg_write = cfg.get("write_outputs", export_format != "none")
    write_outputs = env_write if env_write is not None else bool(cfg_write)

    if export_format == "none":
        write_outputs = False
    return export_format, write_outputs

def load_config_and_endpoints(config_path: str) -> Tuple[dict, List[str]]:
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    env_ep = os.getenv("SCAN_ENDPOINTS_FILE")
    ep_file = env_ep if env_ep else cfg.get("endpoints_file", "endpoints.txt")

    if not os.path.exists(ep_file):
        raise FileNotFoundError(f"Endpoints file not found: {ep_file}")

    load_endpoints, clean_url, unique_filter = _maybe_ingest_helpers()
    raw_eps = load_endpoints(ep_file)

    # normalizzazione preliminare: clean_url + unique_filter (può essere case-sensitive)
    prelim = unique_filter([clean_url(u) for u in raw_eps])

    # normalizzazione finale e dedup **case-insensitive**
    cleaned = _normalize_endpoints_again(prelim)
    logger.info("Endpoints cleaned: %d → %d", len(raw_eps), len(cleaned))
    return cfg, cleaned

# --------------------------------------------------------------------------- #
# PROBE (preferisci wrapper sync; fallback a Trio.run)                        #
# --------------------------------------------------------------------------- #

_run_probe_sync = None
_probe_pipeline_async = None
_probe_import_error: Exception | None = None
try:
    from probe_smuggle import run_probe as _run_probe_sync  # type: ignore
except Exception as e:
    _probe_import_error = e
    try:
        from probe_smuggle import probe_pipeline as _probe_pipeline_async  # type: ignore
    except Exception as e2:
        if _probe_import_error is None:
            _probe_import_error = e2

def _extract_probe_params_from_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Estrae i parametri di profilo/runtime dalla config CLI.
    NB: la sonda attuale accetta principalmente 'profile' e 'budget';
        altri campi verranno filtrati.
    """
    defaults = {
        "profile": cfg.get("profile", cfg.get("profile_default", "light")),
        "concurrency": cfg.get("concurrency"),           # potrebbe non essere supportato
        "retries": cfg.get("retries"),
        "timeout": cfg.get("timeout"),
        "max_requests": cfg.get("max_requests"),
    }
    prof = str(defaults["profile"]).strip().lower()
    defaults["profile"] = prof if prof in ("light", "standard", "deep") else "standard"
    return defaults
    try:
        from resilience import budget_guard as _budget_guard
        guard = _budget_guard(defaults["profile"])
        # Applica solo se non già impostati da config
        if defaults.get("timeout") is None:
            defaults["timeout"] = guard["timeout"]
        if defaults.get("retries") is None:
            defaults["retries"] = guard["retries"]
    except Exception:
        pass


def run_probe(endpoints: List[str], **probe_kwargs: Any) -> List[Dict[str, Any]]:
    """
    Esegue la sonda:
    - garantisce endpoints normalizzati/deduplicati
    - se la sonda espone run_probe (sync), usa quello (preferito);
    - altrimenti, se esiste probe_pipeline (async), usa trio.run(...);
    - non propaga MAI eccezioni: in caso di errore globale, genera record d'errore e continua.
    Propaga solo i kwargs supportati dalla sonda (filtrati via signature).
    """
    eps = _normalize_endpoints_again(endpoints)
    logger.info("Running probe on %d endpoints", len(eps))

    target = _run_probe_sync or _probe_pipeline_async
    if target is None:
        hint = f"probe_smuggle import error: {repr(_probe_import_error)}" if _probe_import_error else "probe_smuggle not found"
        return [
            {
                "url": u,
                "get": {"status": None, "error": f"ProbeUnavailable: {hint}", "response_raw": b""},
                "flags": ["NORESP"],
                "score": 0.0,
            }
            for u in eps
        ]

    # filtra kwargs compatibles
    filtered_kwargs: Dict[str, Any] = {}
    try:
        sig = inspect.signature(target)
        for k, v in probe_kwargs.items():
            if k in sig.parameters:
                filtered_kwargs[k] = v
    except Exception:
        filtered_kwargs = {}

    try:
        if _run_probe_sync is not None:
            return _run_probe_sync(eps, **filtered_kwargs)  # preferito: wrapper sync della sonda
        return trio.run(_probe_pipeline_async, eps, **filtered_kwargs)  # fallback: coroutine
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

# --------------------------------------------------------------------------- #
# ANALYSIS                                                                    #
# --------------------------------------------------------------------------- #

from analysis_bypass import (  # type: ignore
    differential_diff,
    param_fuzz,
    jwt_analysis,
    embed_score,           # usato come fallback dentro _embed_similarity_score
    security_classify,
    dl_mutate,
)

def run_analysis(probe_results: List[Dict[str, Any]],
                 secure: Optional[_SecureBERTHandle] = None) -> Tuple[
    List[Dict[str, Any]], List[Dict[str, Any]], List[List[Dict[str, Any]]],
    List[float], List[float], List[str]
]:
    # diff
    diff_results: List[Dict[str, Any]] = []
    for rec in probe_results:
        try:
            get_raw = rec.get("get", {}).get("response_raw", b"") or b""
            post_raw = rec.get("post", {}).get("response_raw", b"") or b""
            diff_results.append(
                differential_diff(
                    get_raw.decode("iso-8859-1", errors="ignore"),
                    post_raw.decode("iso-8859-1", errors="ignore")
                )
            )
        except Exception as e:
            logger.debug("differential_diff error: %s", e)
            diff_results.append({})

    # fuzz
    try:
        fuzz_results = param_fuzz(probe_results)
        if not isinstance(fuzz_results, list):
            fuzz_results = []
    except Exception as e:
        logger.debug("param_fuzz error: %s", e)
        fuzz_results = []

    # jwt
    jwt_findings: List[List[Dict[str, Any]]] = []
    for rec in probe_results:
        try:
            jwt_findings.append(jwt_analysis(rec.get("get", {}).get("headers", {})))
        except Exception as e:
            logger.debug("jwt_analysis error: %s", e)
            jwt_findings.append([])

    # embed/security
    embed_scores: List[float] = []
    security_scores: List[float] = []
    for rec in fuzz_results:
        try:
            raw = rec.get("payload_raw", b"")
            payload = raw.decode("iso-8859-1", errors="ignore") if raw else ""
            # match response body della stessa URL
            resp = b""
            for r in probe_results:
                if r.get("url") == rec.get("url"):
                    resp = r.get("get", {}).get("body", b"") or b""
                    break
            score = _embed_similarity_score(secure, payload, resp)
            embed_scores.append(float(score))
        except Exception as e:
            logger.debug("embed score error: %s", e)
            embed_scores.append(0.0)
        try:
            security_scores.append(float(security_classify(payload)))
        except Exception as e:
            logger.debug("security_classify error: %s", e)
            security_scores.append(0.0)

    # dl mutate
    try:
        payload_list = [
            (r.get("payload_raw") or b"").decode("iso-8859-1", errors="ignore")
            for r in fuzz_results
        ]
        dl_variants = dl_mutate(payload_list)
        if not isinstance(dl_variants, list):
            dl_variants = []
    except Exception as e:
        logger.debug("dl_mutate error: %s", e)
        dl_variants = []

    return diff_results, fuzz_results, jwt_findings, embed_scores, security_scores, dl_variants

# --------------------------------------------------------------------------- #
# SCHEDULING, FORECAST, SHAP                                                  #
# --------------------------------------------------------------------------- #

def schedule_bandit(features: List[List[float]],
                    hosts: List[str],
                    top_n: int | None = None) -> List[str]:
    """
    Politica di scelta tipo Thompson sampling su una singola feature [0..1].
    **Assume** che len(features) == len(hosts). Chiama con liste allineate.
    """
    if len(features) != len(hosts):
        f = (features or [])
        features = [f[i][0:1] if i < len(f) else [0.0] for i in range(len(hosts))]

    scale = 10.0
    n = top_n or len(hosts)
    samples = []
    for f in features:
        x = float(f[0]) if f and len(f) > 0 else 0.0
        x = max(0.0, min(1.0, x))
        samples.append(np.random.beta(x * scale + 1.0, (1.0 - x) * scale + 1.0))
    idx = sorted(range(len(hosts)), key=lambda i: samples[i], reverse=True)
    return [hosts[i] for i in idx[:n]]

def _clean_numeric_series(history: Iterable[Any]) -> List[float]:
    out: List[float] = []
    for x in (history or []):
        try:
            v = float(x)
            if np.isfinite(v):
                out.append(v)
        except Exception:
            continue
    return out

def rolling_forecast(history: List[float],
                     window: int,
                     min_len: int = 8) -> Dict[str, float]:
    """
    Forecast robusto: se pmdarima manca o la serie è corta/piatta, ritorna la media.
    """
    series_all = _clean_numeric_series(history)
    series = series_all[-int(window):] if window and len(series_all) >= int(window) else series_all
    if not series:
        return {"forecast": 0.0}
    mean_val = float(np.mean(series))
    if auto_arima is None:
        return {"forecast": mean_val}
    if len(series) < int(min_len):
        return {"forecast": mean_val}
    if float(np.std(series)) <= 1e-12:
        return {"forecast": mean_val}
    try:
        model = auto_arima(
            series,
            seasonal=False,
            error_action="ignore",
            suppress_warnings=True,
            stepwise=True,
            with_intercept=True
        )
        yhat = model.predict(n_periods=1)
        y0 = float(yhat[0]) if len(yhat) > 0 else mean_val
        if not np.isfinite(y0):
            y0 = mean_val
        return {"forecast": y0}
    except Exception as e:
        logger.debug("auto_arima failed, fallback to mean: %s", e)
        return {"forecast": mean_val}

def dynamic_model_averaging(forecasts: List[Dict[str, float]],
                            weights: List[float],
                            var_threshold: float = 0.1) -> Dict[str, float]:
    vals = np.array([f.get("forecast", 0.0) for f in forecasts], dtype=float)
    if len(vals) == 0:
        return {"dma": 0.0, "variance": 0.0}
    var = float(np.var(vals)) if np.all(np.isfinite(vals)) else 0.0
    if var < var_threshold or not any(weights) or not np.isfinite(var):
        avg = float(np.mean(vals)) if len(vals) else 0.0
    else:
        w = np.array(weights, dtype=float)
        s = w.sum()
        if s <= 0 or not np.isfinite(s):
            avg = float(np.mean(vals))
        else:
            w = w / s
            avg = float(np.dot(w, vals))
    return {"dma": avg, "variance": var}

def explain_shap(inputs: List[str], max_evals: int = 50) -> str:
    """
    Se SHAP+sklearn+matplotlib non sono disponibili, ritorna una piccola SVG “SHAP not available”.
    """
    if shap is None or LogisticRegression is None or CountVectorizer is None:
        return "<svg xmlns='http://www.w3.org/2000/svg' width='400' height='40'><text x='10' y='25'>SHAP not available</text></svg>"
    try:
        import matplotlib
        matplotlib.use("Agg")
        from matplotlib import pyplot as plt  # type: ignore
    except Exception:
        return "<svg xmlns='http://www.w3.org/2000/svg' width='400' height='40'><text x='10' y='25'>Matplotlib not available</text></svg>"

    try:
        vect = CountVectorizer().fit(inputs)
        X = vect.transform(inputs)
        y = np.random.randint(0, 2, size=X.shape[0])
        model = LogisticRegression(max_iter=200).fit(X, y)
        explainer = shap.Explainer(model.predict_proba, X, algorithm="auto")
        sv = explainer(X[:1])
        buf = io.BytesIO()
        plt.figure()
        shap.plots.waterfall(sv[0], show=False)
        plt.savefig(buf, format="svg", bbox_inches="tight")
        plt.close()
        return buf.getvalue().decode("utf-8", errors="ignore")
    except Exception as e:
        logger.warning("SHAP explain failed: %s", e)
        return "<svg xmlns='http://www.w3.org/2000/svg' width='400' height='40'><text x='10' y='25'>SHAP failed</text></svg>"

# --------------------------------------------------------------------------- #
# JSON SANITIZATION (solo per export)                                         #
# --------------------------------------------------------------------------- #

_PRINTABLE = set(chr(i) for i in range(32, 127)) | {"\n", "\r", "\t"}

def _string_is_mostly_printable(s: str, threshold: float = 0.7) -> bool:
    if not s:
        return True
    printable = sum(1 for ch in s if ch in _PRINTABLE)
    return (printable / len(s)) >= threshold

def _bytes_preview(b: bytes, limit: int = 1024) -> str:
    if not b:
        return ""
    txt = None
    try:
        txt = b.decode("utf-8")
    except Exception:
        try:
            txt = b.decode("iso-8859-1", errors="ignore")
        except Exception:
            txt = ""
    if txt and _string_is_mostly_printable(txt):
        if len(txt) > limit:
            return txt[:limit] + f"… <{len(b)} bytes total>"
        return txt
    import base64
    enc = base64.b64encode(b[:limit]).decode("ascii", errors="ignore")
    suffix = "" if len(b) <= limit else f"… <{len(b)} bytes total>"
    return f"<base64:{enc}>{suffix}"

def _to_json_safe(obj: Any, preview_bytes: int = 1024) -> Any:
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, bytes):
        return _bytes_preview(obj, limit=preview_bytes)
    if isinstance(obj, (list, tuple, set)):
        return [_to_json_safe(x, preview_bytes=preview_bytes) for x in obj]  # type: ignore
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            ks = k if isinstance(k, str) else str(k)
            out[ks] = _to_json_safe(v, preview_bytes=preview_bytes)
        return out
    try:
        json.dumps(obj)
        return obj
    except Exception:
        return str(obj)

# --------------------------------------------------------------------------- #
# SEVERITY, LEGEND, RENDER-READY VIEW                                         #
# --------------------------------------------------------------------------- #

DEFAULT_WAF_LEGEND = {
    "Akamai": "Akamai WAF/CDN rilevato",
    "Cloudflare": "Cloudflare WAF/CDN rilevato",
    "F5": "F5 BIG-IP ASM",
    "Imperva": "Imperva SecureSphere",
    "AWS": "AWS WAF/ALB",
}

DEFAULT_FLAGS_LEGEND = {
    "+AI": "Possibile AI/ML fingerprint",
    "+DNS": "Anomalia DNS/risoluzione",
    "+DIR": "Directory traversal o indizi di listing",
    "+BYP": "Tentativo bypass WAF applicato (solo deep)",
    "+JWT": "Token JWT presente/sospetto",
}

def _severity_from_score(score: float,
                         thresholds: Dict[str, float]) -> str:
    hi = float(thresholds.get("high", 0.75))
    md = float(thresholds.get("medium", 0.4))
    if score >= hi:
        return "High"
    if score >= md:
        return "Medium"
    return "Low"

def merge_summary_from_rows(
    render_ready: List[Dict[str, Any]],
    severity_thresholds: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Ricomputa il SUMMARY a partire dalle righe già pronte per il rendering.
    Usa le stesse soglie di severità che si applicano in tabella (uniformità 1:1).
    - render_ready: lista di dict con almeno 'score' (float 0..1).
    - severity_thresholds: dict con chiavi 'high' e 'medium' (default 0.75 / 0.40).
    Ritorna:
      {
        'total': int,
        'high': int, 'medium': int, 'low': int,
        'high_pct': float, 'medium_pct': float, 'low_pct': float,
      }
    """
    # Soglie default, sovrascrivibili via argomento
    thresholds = severity_thresholds or {"high": 0.75, "medium": 0.40}
    high_thr = float(thresholds.get("high", 0.75))
    med_thr = float(thresholds.get("medium", 0.40))

    total = len(render_ready)
    high = med = low = 0

    for row in render_ready:
        try:
            s = float(row.get("score", 0.0) or 0.0)
        except Exception:
            s = 0.0
        # clamp
        s = 0.0 if s < 0 else (1.0 if s > 1 else s)

        # Se esiste l'helper interno, usalo; altrimenti usa le soglie locali
        try:
            sev = _severity_from_score(s, thresholds)  # type: ignore[name-defined]
        except Exception:
            if s >= high_thr:
                sev = "High"
            elif s >= med_thr:
                sev = "Medium"
            else:
                sev = "Low"

        if sev == "High":
            high += 1
        elif sev == "Medium":
            med += 1
        else:
            low += 1

    def pct(n: int) -> float:
        return round((n / total) * 100.0, 1) if total else 0.0

    return {
        "total": total,
        "high": high,
        "medium": med,
        "low": low,
        "high_pct": pct(high),
        "medium_pct": pct(med),
        "low_pct": pct(low),
    }
try:
    from observability import report_populated_fields
    report_populated_fields(render_ready)
except Exception:
    pass
try:
    from observability import report_waf_coverage  # ADD
    report_waf_coverage(render_ready)              # CALL
except Exception:
    pass

# --- helper: normalizza Content-Type in classi brevi ---
def _normalize_content_type(ct_raw: str | None) -> str:
    """
    Converte un raw content-type (anche con charset/parametri) in classi compatte:
      html | json | text | image | xml | bin
    Se non disponibile o vuoto -> "—".
    """
    if not ct_raw:
        return "—"
    ct = str(ct_raw).strip().lower()
    if ";" in ct:
        ct = ct.split(";", 1)[0].strip()

    if ct == "text/html" or ct.endswith("/html"):
        return "html"
    if ct == "application/json" or ct.endswith("/json"):
        return "json"
    if ct.startswith("text/"):
        return "text"
    if ct.startswith("image/"):
        return "image"
    if ct in ("application/xml", "text/xml") or ct.endswith("/xml"):
        return "xml"
    return "bin"

def _pick_best_http_block(rec: dict) -> tuple[str | None, dict | None]:
    """
    Sceglie il miglior blocco HTTP disponibile tra GET/POST/HEAD/OPTIONS.
    Supporta sia blocchi top-level (get/post/...) sia annidati in rec['http'].
    Criteri:
      1) Preferisci blocchi con status presente
      2) Ordine metodi: GET > POST > HEAD > OPTIONS
      3) Tra pari, scegli latenza minore
    """
    candidates: list[tuple[str, dict]] = []

    # Top-level
    for m in ("get", "post", "head", "options"):
        b = rec.get(m) or rec.get(m.upper())
        if isinstance(b, dict) and b:
            candidates.append((m.upper(), b))

    # Annidati in "http"
    http = rec.get("http")
    if isinstance(http, dict):
        for m in ("GET","POST","HEAD","OPTIONS","get","post","head","options"):
            b = http.get(m)
            if isinstance(b, dict) and b:
                candidates.append((m.upper(), b))

    if not candidates:
        return None, None

    # split: con status vs senza status
    with_status = [(m, b) for (m, b) in candidates if b.get("status") is not None]
    without_status = [(m, b) for (m, b) in candidates if b.get("status") is None]

    def latency_key(item: tuple[str, dict]) -> float:
        _, blk = item
        lat = blk.get("latency_ms", blk.get("latency"))
        try:
            return float(lat) if lat is not None else float("inf")
        except Exception:
            return float("inf")

    method_rank = {"GET": 0, "POST": 1, "HEAD": 2, "OPTIONS": 3}

    def composite_key(item: tuple[str, dict]) -> tuple[int, float]:
        m, _ = item
        return (method_rank.get(m, 9), latency_key(item))

    if with_status:
        return sorted(with_status, key=composite_key)[0]
    return sorted(without_status, key=composite_key)[0]

def _extract_content_type(rec: dict, preferred_method: str | None = None) -> str:
    """
    Estrae il Content-Type 'classificato' per la riga:
      1) rec['content_type_final']
      2) headers/content_type dei blocchi HTTP (preferendo 'preferred_method', poi GET>POST>HEAD>OPTIONS)
      3) headers/content_type nella redirect_chain (ultimo hop con header valido)
      4) euristica _finalize_type(rec)
      5) classi brevi: html/json/text/image/xml/bin ; altrimenti '—'
    """
    # 1) campo finale (livello record)
    ct_final = rec.get("content_type_final")
    if isinstance(ct_final, str) and ct_final.strip():
        return _normalize_content_type(ct_final)

    # 2) prova sui blocchi HTTP
    order = ["GET", "POST", "HEAD", "OPTIONS"]
    if preferred_method and preferred_method.upper() in order:
        order.remove(preferred_method.upper())
        order.insert(0, preferred_method.upper())

    def _from_block(blk: dict) -> str | None:
        hdrs = blk.get("headers") or {}
        if isinstance(hdrs, dict) and hdrs:
            for k, v in hdrs.items():
                if isinstance(k, str) and k.lower() == "content-type":
                    return _normalize_content_type(v if isinstance(v, str) else str(v))
        direct = blk.get("content_type") or blk.get("content-type")
        if direct:
            return _normalize_content_type(direct if isinstance(direct, str) else str(direct))
        return None

    http = rec.get("http") if isinstance(rec.get("http"), dict) else None
    for m in order:
        blk = rec.get(m.lower()) or rec.get(m) or (http.get(m) if http else None)
        if isinstance(blk, dict) and blk:
            ct = _from_block(blk)
            if ct and ct != "—":
                return ct

    # 3) fallback: redirect_chain (ultimo hop con header valido)
    rc = rec.get("redirect_chain")
    if isinstance(rc, list) and rc:
        for step in reversed(rc):
            if not isinstance(step, dict):
                continue
            # headers nel passo della redirect
            hdrs = step.get("headers") or {}
            if isinstance(hdrs, dict) and hdrs:
                for k, v in hdrs.items():
                    if isinstance(k, str) and k.lower() == "content-type":
                        ct = _normalize_content_type(v if isinstance(v, str) else str(v))
                        if ct and ct != "—":
                            return ct
            direct = step.get("content_type") or step.get("content-type")
            if direct:
                ct = _normalize_content_type(direct if isinstance(direct, str) else str(direct))
                if ct and ct != "—":
                    return ct

    # 4) euristica
    try:
        mime = _finalize_type(rec)  # può restituire "text/html" o ""
        if mime:
            return _normalize_content_type(mime)
    except Exception:
        pass

    # 5) niente trovato
    return "—"


def _row_from_probe(rec: dict, **_ignored) -> dict:
    """
    Costruisce una riga 'render_ready' robusta a dati parziali.
    Campi: meth, stat, type (compatto), waf, flags, lat/latency_ms, size, url.
    - TYPE usa _finalize_type(rec) (che guarda content_type_final, GET/POST, headers, euristiche).
    - Se TYPE manca dal blocco migliore, NON restiamo a '—': facciamo fallback sugli altri blocchi.
    """
    url = rec.get("url") or rec.get("endpoint") or "—"

    # 1) Scegli blocco migliore (preferenza GET>POST>HEAD>OPTIONS + latenza)
    meth, blk = _pick_best_http_block(rec)
    if not blk:
        return {
            "url": url,
            "meth": "—",
            "stat": None,
            "type": "—",
            "waf": "None",
            "flags": [],
            "lat": None,
            "latency_ms": None,
            "size": None,
        }

    # 2) Status: se mancante nel best, prova negli altri blocchi
    status = blk.get("status")
    if status is None:
        for mm in ("get", "post", "head", "options"):
            bb = rec.get(mm) or rec.get(mm.upper())
            if isinstance(bb, dict) and bb.get("status") is not None:
                status = bb.get("status"); meth = mm.upper()
                break

    # 3) TYPE robusto: usa sempre _finalize_type(rec), poi compatta
    try:
        ct_full = _finalize_type(rec)  # es. "text/html" | "application/json" | ""
    except Exception:
        ct_full = ""

    # se ancora vuoto, riprova guardando prima il blocco migliore e poi gli altri
    if not ct_full:
        # dal blocco migliore
        headers = blk.get("headers") or {}
        ct_full = (blk.get("content_type")
                   or headers.get("content-type")
                   or headers.get("Content-Type")
                   or "")
        # dagli altri blocchi
        if not ct_full:
            for mm in ("get", "post", "head", "options"):
                bb = rec.get(mm) or rec.get(mm.upper())
                if not isinstance(bb, dict):
                    continue
                hh = bb.get("headers") or {}
                cand = (bb.get("content_type")
                        or hh.get("content-type")
                        or hh.get("Content-Type") or "")
                if cand:
                    ct_full = cand
                    break

    ct_compact = _normalize_content_type(ct_full if isinstance(ct_full, str) else str(ct_full) if ct_full is not None else None)

    # 4) Latenza e size: preferisci il blocco migliore, con fallback
    def _first_num(*vals):
        for v in vals:
            try:
                if v is None:
                    continue
                return float(v)
            except Exception:
                continue
        return None

    lat = _first_num(blk.get("latency_ms"), blk.get("latency"))
    if lat is None:
        # prova altri blocchi
        for mm in ("get", "post", "head", "options"):
            bb = rec.get(mm) or rec.get(mm.upper())
            if isinstance(bb, dict):
                lat = _first_num(bb.get("latency_ms"), bb.get("latency"))
                if lat is not None:
                    break

    size = None
    for key in ("size", "bytes", "content_length"):
        if blk.get(key) is not None:
            try:
                size = int(blk.get(key))
                break
            except Exception:
                pass

    # 5) WAF e flags
    waf_vendors = rec.get("waf_vendors")
    if isinstance(waf_vendors, (list, tuple)) and any(waf_vendors):
        waf = ",".join(sorted(str(x) for x in waf_vendors if x))
    else:
        waf = "None"
        if isinstance(blk.get("waf"), str) and blk.get("waf").strip():
            waf = blk.get("waf").strip()

    raw_flags = rec.get("flags") or blk.get("flags") or []
    if isinstance(raw_flags, str):
        # supporta separatori diversi
        toks = []
        for part in raw_flags.replace(",", " ").replace("|", " ").split():
            if part.strip():
                toks.append(part.strip())
        flags = toks
    elif isinstance(raw_flags, (list, tuple, set)):
        flags = [str(x) for x in raw_flags if x]
    else:
        flags = []

    return {
        "url": url,
        "meth": meth or "—",
        "stat": status,
        "type": ct_compact,                   # ← compatto: html/json/text/image/xml/bin/—
        "waf": waf or "None",
        "flags": flags,
        "lat": float(lat) if lat is not None else None,
        "latency_ms": float(lat) if lat is not None else None,  # compat per renderer alternativi
        "size": size,
    }

def _backfill_enriched_fields_into_probe_results(output: dict) -> None:
    """
    Propaga nei record sorgente (probe_results) i campi calcolati in render_ready
    così che 'method', 'content_type_final', 'waf_vendors', ecc. risultino valorizzati
    anche nel JSON principale salvato a disco.
    Fail-soft: non solleva.
    """
    try:
        enriched_by_url = {}
        for r in (output.get("render_ready") or []):
            u = r.get("url")
            if u:
                enriched_by_url[u] = r

        KEYS = [
            "method", "status", "latency_ms", "size",
            "content_type_final",
            "waf_vendors", "allowed_methods", "security_headers",
            "family", "param_families", "family_counts",
            "body_snip", "http_version", "redirect_chain",
        ]

        changed = 0
        for rec in (output.get("probe_results") or []):
            er = enriched_by_url.get(rec.get("url"))
            if not er:
                continue
            for k in KEYS:
                if k in er and er.get(k) is not None:
                    rec[k] = er[k]
                    changed += 1

        # mantiene l'alias 'rows' allineato, se presente
        if "rows" in output:
            output["rows"] = output.get("probe_results") or output.get("rows")
    except Exception:
        # fail-soft
        pass


def _build_render_ready(probe_results,
                        url_score_hint=None,
                        severity_thresholds=None,
                        kb_params=None):
    """
    Builder UNICO per le righe 'render_ready'.

    Requisiti:
      - TYPE = MIME 'finale' (da content_type_final/_finalize_type), NON etichetta corta.
      - WAF = stringa già joinata (es. "Akamai|Cloudflare"); se vuota => "" (il renderer mostrerà '—').
      - FAMILY dalla KB (match parametri + overrides) con fallback su path/ctype/host.
      - METH/STAT/LAT/SIZE prelevati dal blocco HTTP "migliore" (preferenza GET>POST>HEAD>OPTIONS + status presente + latenza minore).
      - SCORE mantenuto se presente; altrimenti policy.compute_risk_score(); altrimenti euristica soft.
      - SEVERITY da soglie passate (default: high=0.75, medium=0.40).
      - FLAGS mantenute (normalizzate a lista di token stringa).
    """
    from urllib.parse import urlparse, parse_qsl

    url_score_hint = url_score_hint or {}
    kb = kb_params or {}
    thr = severity_thresholds or {"high": 0.75, "medium": 0.40}
    T_HIGH = float(thr.get("high", 0.75))
    T_MED  = float(thr.get("medium", 0.40))

    # hook policy (soft)
    try:
        from policy import compute_risk_score, score_reasons  # type: ignore
    except Exception:
        compute_risk_score = None
        def score_reasons(_):  # type: ignore
            return []

    def _registrable(url: str) -> str:
        try:
            h = urlparse(url).hostname or ""
        except Exception:
            h = ""
        parts = (h or "").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else (h or "—")

    def _best_block(rec: dict):
        try:
            m, b = _pick_best_http_block(rec)  # usa helper se presente nel modulo
            if m:
                return m, b
        except Exception:
            pass
        # fallback locale
        cand = []
        order = {"GET": 0, "POST": 1, "HEAD": 2, "OPTIONS": 3}
        for name in ("get", "post", "head", "options"):
            blk = rec.get(name) or rec.get(name.upper())
            if isinstance(blk, dict) and blk:
                meth = name.upper()
                st = blk.get("status")
                try:
                    lat = float(blk.get("latency_ms") or blk.get("latency") or 9e9)
                except Exception:
                    lat = 9e9
                cand.append((st is not None, order.get(meth, 9), lat, meth, blk))
        if not cand:
            return None, None
        cand.sort(key=lambda t: (not t[0], t[1], t[2]))  # status presente, poi ordine metodo, poi latenza
        return cand[0][3], cand[0][4]

    def _mime_from_any(rec: dict, blk: Optional[dict]) -> str:
        # 1) content_type_final a livello record
        ct = rec.get("content_type_final")
        if isinstance(ct, str) and ct.strip():
            return ct.strip()
        # 2) dal blocco migliore
        if isinstance(blk, dict):
            hdrs = blk.get("headers") or {}
            ct = blk.get("content_type") or hdrs.get("content-type") or hdrs.get("Content-Type")
            if isinstance(ct, str) and ct.strip():
                return ct.strip()
        # 3) altri blocchi
        for name in ("get", "post", "head", "options", "GET", "POST", "HEAD", "OPTIONS"):
            b = rec.get(name)
            if isinstance(b, dict):
                hdrs = b.get("headers") or {}
                ct = b.get("content_type") or hdrs.get("content-type") or hdrs.get("Content-Type")
                if isinstance(ct, str) and ct.strip():
                    return ct.strip()
        # 4) helper di sniffing completo
        try:
            ct = _finalize_type(rec)  # può ritornare "text/html", "application/json", ...
            if isinstance(ct, str) and ct:
                return ct
        except Exception:
            pass
        return ""

    def _join_waf(rec: dict, blk: Optional[dict]) -> str:
        vendors = []
        vv = rec.get("waf_vendors")
        if isinstance(vv, (list, tuple, set)):
            vendors.extend([str(x) for x in vv if str(x).strip()])
        v = rec.get("waf_vendor")
        if v and str(v).strip() not in vendors:
            vendors.append(str(v).strip())
        if not vendors and isinstance(blk, dict):
            w = blk.get("waf")
            if isinstance(w, str) and w.strip():
                vendors.append(w.strip())
        # de-dup mantendendo ordine
        seen = set()
        out = []
        for x in vendors:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return "|".join(out)

    def _family_from_kb(url: str, mime: str) -> str:
        # 1) param->family con priorità (match exact/regex/substring + context overrides)
        best = ("", -10)  # (family, priority)
        try:
            pr = urlparse(url)
            params = [k for (k, _v) in parse_qsl(pr.query, keep_blank_values=True)]
        except Exception:
            params = []
        for p in params:
            try:
                m = match_param_to_family(p, path_hint=urlparse(url).path or "/", content_type=mime or "")
            except Exception:
                m = {"family": "", "priority": 0}
            fam = str(m.get("family") or "").strip()
            pri = int(m.get("priority") or 0)
            if fam and pri > best[1]:
                best = (fam, pri)
        if best[0]:
            return best[0]
        # 2) fallback leggeri su path/mime
        path = ""
        try:
            path = (urlparse(url).path or "").lower()
        except Exception:
            pass
        lo = (mime or "").lower()
        if "/api/" in path or lo.endswith("/json") or lo == "application/json":
            return "API"
        if lo.endswith("/html") or lo == "text/html":
            return "WEBPAGE"
        if lo.startswith("image/"):
            return "ASSET"
        if lo in ("application/xml", "text/xml") or lo.endswith("/xml"):
            return "FEED"
        if lo == "application/pdf":
            return "DOCUMENT"
        return "GENERIC"

    def _norm_flags(v) -> list[str]:
        if not v:
            return []
        if isinstance(v, (list, tuple, set)):
            toks = [str(x) for x in v if str(x).strip()]
        elif isinstance(v, str):
            # supporto "A|B|C"
            if "|" in v or "," in v:
                raw = v.replace(",", "|").split("|")
                toks = [t.strip() for t in raw if t.strip()]
            else:
                toks = [v.strip()]
        else:
            toks = [str(v)]
        # dedup stabile
        seen = set()
        out = []
        for t in toks:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out

    rows: list[dict] = []

    for i, rec in enumerate(probe_results or [], start=1):
        if not isinstance(rec, dict):
            continue

        url = str(rec.get("url") or rec.get("endpoint") or "")
        meth, blk = _best_block(rec)

        # status / lat / size con fallback agli altri blocchi
        status = blk.get("status") if isinstance(blk, dict) else None
        if status is None:
            for name in ("get", "post", "head", "options", "GET", "POST", "HEAD", "OPTIONS"):
                b = rec.get(name)
                if isinstance(b, dict) and b.get("status") is not None:
                    status = b.get("status")
                    if not meth:
                        meth = name.upper()
                    break

        def _num_first(*vals):
            for v in vals:
                try:
                    if v is None:
                        continue
                    return float(v)
                except Exception:
                    continue
            return None

        lat = _num_first(*((
            (blk or {}).get("latency_ms"),
            (blk or {}).get("latency"),
            *((rec.get(n) or rec.get(n.upper()) or {}).get("latency_ms")
               for n in ("get","post","head","options"))
        )))
        size = None
        for key in ("size", "bytes", "content_length"):
            try:
                vv = (blk or {}).get(key)
                if vv is not None:
                    size = int(vv)
                    break
            except Exception:
                pass

        # MIME completo
        mime = _mime_from_any(rec, blk)
        # WAF stringa
        waf_str = _join_waf(rec, blk)  # "" se non disponibile
        # FAMILY: KB -> fallback
        fam = (rec.get("family") or rec.get("family_hint_kb") or "").strip()
        if not fam:
            fam = _family_from_kb(url, mime)

        # FLAGS normalizzate
        flags = _norm_flags(rec.get("flags") or (blk or {}).get("flags"))

        # SCORE
        score = None
        raw_sc = rec.get("score")
        try:
            if raw_sc is not None:
                score = float(raw_sc)
        except Exception:
            score = None
        if score is None and url and url in url_score_hint:
            try:
                score = float(url_score_hint.get(url) or 0.0)
            except Exception:
                score = None
        if score is None and compute_risk_score:
            try:
                score = float(compute_risk_score(rec))
            except Exception:
                score = None
        if score is None:
            # euristica soft, clamp [0..1]
            s = 0.0
            try:
                if isinstance(status, int):
                    if 500 <= status <= 599:
                        s += 0.50
                    elif 400 <= status <= 499:
                        s += 0.25
                s += 0.20 * min(1.0, (float(lat or 0.0) / 3000.0))
                up = {f.upper() for f in flags}
                if "+SQLI" in up or "SQLI" in up: s += 0.25
                if "+XSS"  in up or "XSS"  in up: s += 0.15
                if waf_str: s += 0.03
            except Exception:
                pass
            score = max(0.0, min(1.0, s))
        score = float(max(0.0, min(1.0, score)))

        # SEVERITY
        severity = "High" if score >= T_HIGH else ("Medium" if score >= T_MED else "Low")

        # REASONS (soft)
        try:
            reasons = score_reasons({
                "url": url, "status": status, "latency_ms": lat, "type": mime,
                "flags": flags, "waf": waf_str, "family": fam, "score": score
            }) or []
        except Exception:
            reasons = []

        rows.append({
            "rank": i,
            "severity": severity,
            "score": round(score, 4),
            "meth": (meth or "—"),
            "stat": status,
            "lat": lat,
            "latency_ms": lat,
            "size": size,
            # TYPE = MIME COMPLETO + anche field content_type_final per compat
            "type": (mime or "—"),
            "content_type_final": (mime or ""),
            # FAMILY dalla KB → fallback
            "family": (fam or "GENERIC"),
            # WAF STRINGA (join) — se vuota, il renderer mostrerà "—"
            "waf": (waf_str or ""),
            # flags come lista normalizzata
            "flags": flags,
            "reasons": reasons,
            "url": url,
            "root_domain": _registrable(url),
        })

    return rows


# --- helpers locali per mapping campi di resa ---
def _pick_method_and_fields(rec):
    """Sceglie il 'metodo vincente' con precedenza POST>GET>HEAD>OPTIONS e restituisce (METH, STAT, LAT, SIZE, TYPE)."""
    order = ("post", "get", "head", "options")
    for m in order:
        blk = rec.get(m) or {}
        if blk and (blk.get("status") is not None or blk.get("latency_ms") is not None or blk.get(
                "size") is not None or blk.get("content_type")):
            ctype = rec.get("content_type_final") or blk.get("content_type") or ""
            return m.upper(), blk.get("status"), blk.get("latency_ms"), blk.get("size"), ctype
    for m in order:
        blk = rec.get(m) or {}
        if blk:
            ctype = rec.get("content_type_final") or blk.get("content_type") or ""
            return m.upper(), blk.get("status"), blk.get("latency_ms"), blk.get("size"), ctype
    return "—", None, None, None, (rec.get("content_type_final") or "")


def _score_percent(score) -> int:
    try:
        return int(round(100.0 * float(score)))
    except Exception:
        return 0


def _reason_text(reason) -> str:
    if isinstance(reason, (list, tuple, set)):
        return "|".join([str(x) for x in reason if x])
    return str(reason or "")

    thresholds = severity_thresholds or {"high": 0.75, "medium": 0.40}
    high_thr = float(thresholds.get("high", 0.75))
    med_thr = float(thresholds.get("medium", 0.40))

    rows: List[Dict[str, Any]] = []
    url_score_hint = url_score_hint or {}

    for i, rec in enumerate(probe_results, start=1):
        url = rec.get("url", "")
        g = rec.get("get") or {}
        p = rec.get("post") or {}
        prim = g if g else p

        meth = "GET" if g else ("POST" if p else "-")
        stat = prim.get("status") if prim else None
        lat = prim.get("latency_ms") if prim else None
        size = prim.get("size") if prim else None

        # TYPE (MIME finale) via helper centralizzato
        try:
            ctype = _finalize_type(rec)  # type: ignore[name-defined]
        except Exception:
            ctype = str(rec.get("content_type_final") or prim.get("content_type") or "")
            if isinstance(ctype, str) and ";" in ctype:
                ctype = ctype.split(";", 1)[0].strip()

        # SCORE (preferisci rec/url_hint; baseline se 0)
        raw_score = rec.get("score")
        score: float = 0.0
        if isinstance(raw_score, (int, float)):
            score = float(raw_score)
        elif url and url_score_hint:
            score = float(url_score_hint.get(str(url), 0.0) or 0.0)

        # baseline policy.compute_risk_score(rec)
        base_score, base_reasons = 0.0, ""
        try:
            from policy import compute_risk_score  # type: ignore
            base_score, base_reasons = compute_risk_score(rec)
        except Exception:
            pass

        # scegli il massimo per non “abbassare” score esistenti
        score = max(0.0, min(1.0, float(max(score, base_score))))

        # Severity uniforme con la legenda
        if score >= high_thr:
            severity = "High"
        elif score >= med_thr:
            severity = "Medium"
        else:
            severity = "Low"

        # WAF vendor list → string (oppure "None")
        waf_vendors: List[str] = []
        vv = rec.get("waf_vendors")
        if isinstance(vv, (list, tuple)):
            waf_vendors.extend([str(x) for x in vv if x])
        v = rec.get("waf_vendor")
        if v and str(v) not in waf_vendors:
            waf_vendors.append(str(v))
        waf_vendors = list(dict.fromkeys([w.strip() for w in waf_vendors if w and str(w).strip()]))
        waf_str = "|".join(waf_vendors) if waf_vendors else "None"

        # FLAGS consolidati
        flags_field = rec.get("flags")
        if isinstance(flags_field, str):
            flags_tokens = [t for t in flags_field.split("|") if t]
        elif isinstance(flags_field, (list, tuple)):
            flags_tokens = [str(t) for t in flags_field if t]
        else:
            flags_tokens = []
        norm = []
        for t in flags_tokens:
            t = str(t).strip()
            if not t:
                continue
            if t.startswith("+") or t.upper().startswith("WAF:"):
                norm.append(t)
            else:
                norm.append("+" + t)
        flags_tokens = list(dict.fromkeys(norm))

        # risk_family (se assente, derivala e merge flags)
        risk_fam = rec.get("risk_family") or ""
        if not risk_fam:
            try:
                rf, add_flags = _derive_risk_family(rec)  # type: ignore[name-defined]
                if rf:
                    risk_fam = rf
                for f in add_flags or []:
                    if f not in flags_tokens:
                        flags_tokens.append(f)
            except Exception:
                pass

        # (opzionale) riflesso di alcuni reasons del baseline in flags “noti”
        # Nota: evitiamo flag non previsti in legenda; usiamo solo marker principali.
        if base_reasons:
            rset = {tok.strip().lower() for tok in base_reasons.split("+") if tok.strip()}
            if "weak_hdrs" in rset and "+WEAKHDRS" not in flags_tokens:
                flags_tokens.append("+WEAKHDRS")
            if "cors" in rset and "+CORS" not in flags_tokens:
                flags_tokens.append("+CORS")
            # altri token (5xx/4xx/latency/redirects) restano descrittivi, non flags.

        # FAMILY funzionale
        family = rec.get("family") or rec.get("family_hint_kb") or ""

        row = {
            "rank": i,
            "severity": severity,
            "score": round(score, 4),
            "meth": meth or "-",
            "stat": stat if (isinstance(stat, int) or stat is None) else str(stat),
            "lat": float(lat) if isinstance(lat, (int, float)) else None,
            "size": int(size) if isinstance(size, (int, float)) else None,
            "type": ctype or "",
            "family": family,
            "risk_family": risk_fam,
            "waf": waf_str,
            "flags": "|".join(flags_tokens),
            "url": str(url or ""),
        }

        rows.append(row)

    return rows



def _derive_risk_family(rec: Dict[str, Any], kb: Optional[Dict[str, Any]] = None) -> Tuple[str, List[str]]:
    """
    Calcola la 'risk_family' per un singolo record sonda e aggiorna i FLAGS corrispondenti.
    - Tenta di usare analysis_bypass.risk_markers(rec) se disponibile.
    - In fallback, applica euristiche leggere su headers/CONTENT/URL/metodi.
    Ritorna: (risk_family_pipe, flags_list_normalized)
    """
    # --- flags esistenti -------------------------------------------------------
    raw_flags = rec.get("flags")
    if isinstance(raw_flags, str):
        flags = [t for t in raw_flags.split("|") if t]
    elif isinstance(raw_flags, (list, tuple)):
        flags = [str(t) for t in raw_flags if t]
    else:
        flags = []

    # normalizza "+TOKEN" per coerenza visuale
    norm_flags = []
    for t in flags:
        t = str(t).strip()
        if not t:
            continue
        if t.startswith("+") or t.upper().startswith("WAF:"):
            norm_flags.append(t)
        else:
            norm_flags.append("+" + t)
    flags = list(dict.fromkeys(norm_flags))  # de-dup stabile

    # --- prova ad usare analysis_bypass.risk_markers ---------------------------
    markers: Set[str] = set()
    try:
        from analysis_bypass import risk_markers as _risk_markers  # type: ignore
        try:
            # preferisci firma semplice
            m = _risk_markers(rec)  # expected: Iterable[str]
        except TypeError:
            # alcuni wrapper accettano anche kb
            m = _risk_markers(rec, kb=kb)  # type: ignore
        if m:
            markers.update(str(x).lower().strip() for x in m if x)
    except Exception:
        # fallback euristico locale (cheap)
        pass

    # --- fallback euristico (se markers vuoto o per integrazione) -------------
    try:
        url = str(rec.get("url") or "")
        ctype = str(rec.get("content_type_final") or rec.get("content_type") or "").lower()
        if ";" in ctype:
            ctype = ctype.split(";", 1)[0].strip()

        sec = rec.get("security_headers") or {}
        missing = set(map(lambda s: str(s).lower(), sec.get("missing") or []))

        headers = rec.get("headers") or {}
        # Alcuni record portano gli header finali dentro GET/POST
        if not headers:
            prim = (rec.get("get") or rec.get("post") or {})
            headers = prim.get("headers") or {}

        # body snippet ridotto (solo per firme light)
        body_snip = (rec.get("body_snip") or rec.get("body_snippet") or "")
        body_low = str(body_snip).lower()[:1024]

        # allowed methods
        allow = rec.get("allow_methods") or rec.get("allowed_methods") or []
        allow = [str(m).upper() for m in allow if m]

        # --- weak-headers ------------------------------------------------------
        weak_hdrs_needed = {"strict-transport-security", "x-frame-options", "x-content-type-options", "content-security-policy"}
        if missing & weak_hdrs_needed:
            markers.add("weak-headers")

        # --- xss ---------------------------------------------------------------
        if "content-security-policy" in missing and ("text/html" in ctype or ctype == ""):
            markers.add("xss")
        # riflessi/markup evidenti sono gestiti da analysis_bypass; qui restiamo conservativi

        # --- sqli --------------------------------------------------------------
        sql_err_tokens = ("sql syntax", "mysql", "mariadb", "psql", "postgres", "odbc", "ora-", "sqlite", "sqlstate")
        if any(tok in body_low for tok in sql_err_tokens):
            markers.add("sqli")

        # --- cors --------------------------------------------------------------
        aco = str(headers.get("access-control-allow-origin") or headers.get("Access-Control-Allow-Origin") or "").strip()
        acc = str(headers.get("access-control-allow-credentials") or headers.get("Access-Control-Allow-Credentials") or "").strip().lower()
        if aco in ("*", "null") or (aco and acc == "true"):
            markers.add("cors")

        # --- auth / admin surface ---------------------------------------------
        lower_url = url.lower()
        if any(x in lower_url for x in ("/login", "/signin", "/wp-login", "/oauth", "/auth")):
            markers.add("auth")
        if any(x in lower_url for x in ("/wp-admin", "/admin/", "/administrator")):
            markers.add("auth")

        # --- directory listing -------------------------------------------------
        if "index of /" in body_low or ("text/html" in ctype and "<title>index of /" in body_low):
            markers.add("dirlist")

        # --- methods larghi ----------------------------------------------------
        if any(m in allow for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND")):
            markers.add("weak-headers")  # trattiamo metodi pericolosi come hardening debole
    except Exception:
        # non bloccare mai
        pass

    # normalizza set → lista ordinata deterministica
    canon_order = ("sqli", "xss", "cors", "auth", "dirlist", "weak-headers")
    ordered = [m for m in canon_order if m in markers]
    # aggiungi eventuali marker extra non in canon_order (ordinamento alfabetico stabile)
    extras = sorted([m for m in markers if m not in canon_order])
    ordered.extend(extras)

    risk_family_pipe = "|".join(ordered)

    # aggiorna flags con i marker principali in forma +MAIUSC
    marker2flag = {
        "xss": "+XSS",
        "sqli": "+SQLI",
        "cors": "+CORS",
        "auth": "+AUTH",
        "dirlist": "+DIR",
        "weak-headers": "+WEAKHDRS",
    }
    for m in ordered:
        f = marker2flag.get(m)
        if f and f not in flags:
            flags.append(f)

    return risk_family_pipe, flags

def _finalize_type(rec: Dict[str, Any]) -> str:
    """
    Restituisce il MIME 'finale' (stringa completa, es. 'text/html' o 'application/json').
    Ordine:
      1) rec['content_type_final'] / rec['content_type']
      2) GET/POST/HEAD/OPTIONS .content_type
      3) Header 'Content-Type' (case-insensitive) su tutti i blocchi
      4) Sniff dai body raw (get['body']/post['body']) se disponibili
      5) Euristiche su body_snip/body_snippet
    Se non determinabile, ritorna "" (il caller mostrerà '—').
    """

    def _norm_mime(s: Any) -> str:
        if s is None:
            return ""
        val = str(s).strip().strip('"').strip("'")
        if not val:
            return ""
        if "," in val:
            val = val.split(",", 1)[0].strip()
        if ";" in val:
            val = val.split(";", 1)[0].strip()
        val = val.lower()
        if "/" not in val:
            map_kw = {
                "json": "application/json",
                "html": "text/html",
                "xml": "application/xml",
                "plain": "text/plain",
                "javascript": "text/javascript",
                "js": "text/javascript",
                "css": "text/css",
            }
            val = map_kw.get(val, val)
        return val if "/" in val else ""

    def _sniff_from_bytes(b: bytes) -> str:
        if not b:
            return ""
        head = b[:4096]
        try:
            low = head.lstrip().lower()
        except Exception:
            # fallback lossless-ish: ispeziona pattern binari
            low = head.lstrip().decode("iso-8859-1", errors="ignore").lower().encode("utf-8", errors="ignore")
            low = bytes(low)
        # JSON
        if low.startswith(b"{") or low.startswith(b"["):
            return "application/json"
        # HTML
        if b"<html" in low or b"<!doctype html" in low:
            return "text/html"
        # XML/RSS
        if low.startswith(b"<?xml") or b"<rss" in low or b"<feed" in low:
            return "application/xml"
        # Immagini comuni
        if head.startswith(b"\x89PNG"):
            return "image/png"
        if head.startswith(b"\xff\xd8"):
            return "image/jpeg"
        if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
            return "image/gif"
        return ""

    # 1) preferisci campi "finali"
    for key in ("content_type_final", "content_type"):
        nv = _norm_mime(rec.get(key))
        if nv:
            return nv

    # 2) campi diretti nei blocchi
    for mm in ("get", "post", "head", "options"):
        blk = rec.get(mm) or rec.get(mm.upper())
        if not isinstance(blk, dict):
            continue
        nv = _norm_mime(blk.get("content_type"))
        if nv:
            return nv

    # 3) header Content-Type in qualunque blocco
    for mm in ("get", "post", "head", "options"):
        blk = rec.get(mm) or rec.get(mm.upper())
        if not isinstance(blk, dict):
            continue
        hdrs = blk.get("headers") or {}
        if isinstance(hdrs, dict) and hdrs:
            ct = hdrs.get("content-type")
            if not ct:
                ct = hdrs.get("Content-Type")
            nv = _norm_mime(ct)
            if nv:
                return nv

    # 4) sniff dai body raw (GET/POST tipicamente)
    for mm in ("get", "post"):
        blk = rec.get(mm) or rec.get(mm.upper())
        if not isinstance(blk, dict):
            continue
        b = blk.get("body") or b""
        if isinstance(b, (bytes, bytearray)) and b:
            nv = _sniff_from_bytes(bytes(b))
            if nv:
                return nv

    # 5) euristiche su body_snip/body_snippet (testo)
    body_snip = (rec.get("body_snip") or rec.get("body_snippet") or "")[:4096]
    low = str(body_snip).strip().lower()
    if low.startswith("{") or low.startswith("["):
        return "application/json"
    if "<html" in low or "<!doctype html" in low:
        return "text/html"

    return ""


# --------------------------------------------------------------------------- #
# EXPORT (selezione formati + atomico + nessun side-effect se none)           #
# --------------------------------------------------------------------------- #

def _export_json_atomic(safe_output: Dict[str, Any], out_json: str) -> str:
    os.makedirs(os.path.dirname(out_json) or ".", exist_ok=True)
    tmp_json = out_json + ".tmp"
    with open(tmp_json, "w", encoding="utf-8") as f:
        json.dump(safe_output, f, ensure_ascii=False, indent=2)
    os.replace(tmp_json, out_json)
    return out_json

def _flatten_row_for_csv(rec: Dict[str, Any]) -> Dict[str, Any]:
    g = rec.get("get", {}) or {}
    p = rec.get("post", {}) or {}
    return {
        "url": rec.get("url", ""),
        "get_status": g.get("status"),
        "get_latency_ms": g.get("latency_ms"),
        "get_size": g.get("size"),
        "get_type": g.get("content_type"),
        "post_status": p.get("status"),
        "post_latency_ms": p.get("latency_ms"),
        "post_size": p.get("size"),
        "post_type": p.get("content_type"),
    }

def _export_csv_atomic(output: Dict[str, Any], out_csv: str) -> str:
    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    rows = [_flatten_row_for_csv(r) for r in (output.get("probe_results") or [])]
    fieldnames = [
        "url",
        "get_status", "get_latency_ms", "get_size", "get_type",
        "post_status", "post_latency_ms", "post_size", "post_type",
    ]
    tmp_csv = out_csv + ".tmp"
    with open(tmp_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    os.replace(tmp_csv, out_csv)
    return out_csv

def _export_selected(output: Dict[str, Any],
                     export_format: str,
                     out_json: str,
                     out_csv: str) -> Dict[str, str]:
    export_paths: Dict[str, str] = {}
    if export_format in ("json", "both"):
        safe_output = _to_json_safe(output, preview_bytes=1024)
        export_paths["json_path"] = _export_json_atomic(safe_output, out_json)
    if export_format in ("csv", "both"):
        export_paths["csv_path"] = _export_csv_atomic(output, out_csv)
    return export_paths

# --------------------------------------------------------------------------- #
# MAIN ORCHESTRATOR                                                           #
# --------------------------------------------------------------------------- #
def _build_legends(cfg: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    waf_legend = cfg.get("legend", {}).get("waf") or DEFAULT_WAF_LEGEND
    flags_legend = cfg.get("legend", {}).get("flags") or DEFAULT_FLAGS_LEGEND
    return {"waf": dict(waf_legend), "flags": dict(flags_legend)}

def _severity_thresholds(cfg: Dict[str, Any]) -> Dict[str, float]:
    thr = cfg.get("severity_thresholds") or {}
    return {
        "high": float(thr.get("high", 0.75)),
        "medium": float(thr.get("medium", 0.40)),
    }

# --- Helpers per il render (top-level, NON dentro main_orchestrator) ---

# orch_report.py — sostituisci SOLO questa funzione, a livello top (no indent extra)
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

def build_domain_summaries(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Restituisce {domain: {high, med, p95_latency, top_flags}} ordinato per priorità:
      - #High (desc)
      - #Med (desc)
      - P95 latency (asc)
    """
    from collections import defaultdict, Counter
    import math

    acc = defaultdict(lambda: {"high": 0, "med": 0, "lat": [], "flags": []})

    for r in rows or []:
        dom = r.get("root_domain") or "—"

        sev = (r.get("severity") or "").upper()
        if sev.startswith("H"):
            acc[dom]["high"] += 1
        elif sev.startswith("M"):
            acc[dom]["med"] += 1

        # latency: prova prima "lat", poi "latency_ms"
        lat_val = r.get("lat")
        if lat_val is None:
            lat_val = r.get("latency_ms")
        try:
            acc[dom]["lat"].append(float(lat_val or 0.0))
        except Exception:
            pass

        # flags
        fl = r.get("flags") or []
        acc[dom]["flags"].extend([str(x).upper() for x in fl])

    out: Dict[str, Dict[str, Any]] = {}
    for dom, st in acc.items():
        lat = sorted(st["lat"]) or [0.0]
        p95 = 0.0
        if lat:
            idx = min(len(lat) - 1, int(math.ceil(len(lat) * 0.95) - 1))
            p95 = float(lat[idx])
        top = [k for k, _ in Counter(st["flags"]).most_common(5)]
        out[dom] = {
            "high": int(st["high"]),
            "med": int(st["med"]),
            "p95_latency": int(p95),
            "top_flags": top
        }

    ordered = dict(sorted(
        out.items(),
        key=lambda kv: (-kv[1]["high"], -kv[1]["med"], kv[1]["p95_latency"])
    ))
    return ordered

def main_orchestrator(config_path: str = "config.yaml") -> Dict[str, Any]:
    """
    Pipeline sincrona:
      1) carica config + endpoints (normalizzati e deduplicati)
      2) policy export
      3) probe (fail-soft)
      4) analisi (diff, fuzz, jwt, embed/security, dl_variants)
      5) hint KB families nel probe (soft)
      6) render_ready con _build_render_ready (UNICO builder)
      7) summary + top_domains
      8) validate (soft)
      9) export selettivo (se richiesto)
    """
    # 1) Config + endpoints normalizzati
    cfg, endpoints = load_config_and_endpoints(config_path)

    # 2) Export policy
    export_format, write_outputs = _determine_export_policy(cfg)

    # 3) Carica KB globale
    _load_kb_param_families(cfg)
    kb_params = {}
    try:
        kb_path = (cfg.get("kb_param_family_file")
                   or os.environ.get("KB_PARAM_FAMILY_FILE")
                   or "kb_param_families.yaml")
        if kb_path and os.path.exists(kb_path):
            with open(kb_path, "r", encoding="utf-8") as f:
                kb_params = yaml.safe_load(f) or {}
    except Exception:
        kb_params = {}

    # 4) SecureBERT opzionale
    secure_handle = _maybe_load_securebert(cfg)

    # progress tty (soft)
    set_progress_hook_ref = None
    try:
        from probe_smuggle import set_progress_hook as _set_progress_hook  # type: ignore
        def _progress(url: str, method: str, status: Optional[int], latency_ms: int) -> None:
            s = "-" if status is None else str(status)
            print(f"[{method:<7}] {s:>3}  {latency_ms:>4}ms  {url}")
        set_progress_hook_ref = _set_progress_hook
        if bool(cfg.get("progress_tty", True)):
            _set_progress_hook(_progress)
        else:
            _set_progress_hook(None)
    except Exception:
        set_progress_hook_ref = None  # type: ignore

    # 5) Parametri probe
    probe_params = _extract_probe_params_from_cfg(cfg)

    # 6) Esecuzione probe (fail-soft)
    try:
        probe_results = run_probe(endpoints, **probe_params)
    except Exception as e:
        logger.error("main_orchestrator: run_probe ha sollevato (fail-soft): %s", e)
        probe_results = [
            {"url": u,
             "get": {"status": None, "error": f"{type(e).__name__}: {e}", "response_raw": b""},
             "flags": ["NORESP"], "score": 0.0}
            for u in endpoints
        ]
    finally:
        try:
            if set_progress_hook_ref:
                set_progress_hook_ref(None)  # type: ignore
        except Exception:
            pass

    # 6.b) Hint KB sul probe (soft, non bloccante)
    try:
        import urllib.parse as _urlparse
        for rec in probe_results:
            url = rec.get("url") or ""
            qs = _urlparse.urlsplit(url).query
            params = [k for k, _ in _urlparse.parse_qsl(qs, keep_blank_values=True)]
            best_fam, best_pri = "", int(KB_FAMILIES.get("meta", {}).get("default_priority", 10)) - 1
            for p in params:
                m = match_param_to_family(p)
                fam = str(m.get("family", "")).strip()
                pri = int(m.get("priority", KB_FAMILIES["meta"]["default_priority"]))
                if fam and pri > best_pri:
                    best_fam, best_pri = fam, pri
            if best_fam:
                rec["family_hint_kb"] = best_fam
    except Exception:
        pass

    # 7) Analisi
    diff, fuzz, jwt, embeds, scores, dlvars = run_analysis(probe_results, secure=secure_handle)

    # 7.b) feature per scheduling
    url_to_embed: Dict[str, float] = {}
    for rec, s in zip(fuzz, embeds):
        u = rec.get("url") or ""
        if not u:
            continue
        try:
            url_to_embed[u] = max(url_to_embed.get(u, 0.0), float(s))
        except Exception:
            pass
    features = [[url_to_embed.get(u, 0.0)] for u in endpoints]

    # 8) Scheduling, forecast, SHAP (soft)
    try:
        schedule = schedule_bandit(features, endpoints, top_n=cfg.get("top_n"))
    except Exception as e:
        logger.debug("schedule_bandit failed, fallback to endpoints: %s", e)
        schedule = list(endpoints)

    try:
        hist = cfg.get("avg_score_history", embeds) or []
        forecasts = [rolling_forecast(hist, int(cfg.get("window", 10)))]
    except Exception as e:
        logger.debug("rolling_forecast failed: %s", e)
        forecasts = [{"forecast": 0.0}]

    try:
        dma = dynamic_model_averaging(forecasts, [1.0] * len(forecasts))
        if not np.isfinite(dma.get("dma", 0.0)):
            dma = {"dma": 0.0, "variance": 0.0}
    except Exception as e:
        logger.debug("dynamic_model_averaging failed: %s", e)
        dma = {"dma": 0.0, "variance": 0.0}

    try:
        shap_input = [json.dumps(diff[0])] if diff else ["{}"]
        report_svg = explain_shap(shap_input, cfg.get("shap_max_evals", 50))
    except Exception as e:
        logger.debug("explain_shap failed: %s", e)
        report_svg = "<svg xmlns='http://www.w3.org/2000/svg' width='400' height='40'><text x='10' y='25'>SHAP failed</text></svg>"

    # 9) Legend e soglie
    legends_obj = _build_legends(cfg)
    if isinstance(legends_obj, dict):
        legend_text = legends_obj.get("text") or legends_obj.get("legend") or "\n".join(
            str(v) for v in legends_obj.values() if isinstance(v, str)
        )
    else:
        legend_text = str(legends_obj or "")
    thr = _severity_thresholds(cfg)

    # 10) OUTPUT base
    output: Dict[str, Any] = {
        "endpoints": endpoints,
        "probe_results": probe_results,
        "fuzz_results": fuzz,
        "diff_results": diff,
        "jwt_findings": jwt,
        "embed_scores": embeds,
        "security_scores": scores,
        "dl_variants": dlvars,
        "schedule": schedule,
        "report_svg": report_svg,
        "forecast": dma,
        "legend": legend_text,
        "profile_used": probe_params.get("profile"),
        "probe_params": {k: v for k, v in probe_params.items() if k not in ("profile",)},
    }

    # 11) Render-ready con UNICO builder (niente attach_render_context)
    try:
        render_ready = _build_render_ready(
            probe_results,
            url_score_hint=url_to_embed,
            severity_thresholds=thr,
            kb_params=kb_params
        )
    except Exception as e:
        logger.exception("_build_render_ready crashed: %s", e)
        render_ready = []

    output["render_ready"] = render_ready

    # summary e top_domains
    try:
        output["summary"] = merge_summary_from_rows(render_ready, thr)
    except Exception as e:
        logger.warning("merge_summary_from_rows failed: %s", e)

    try:
        output["top_domains"] = build_domain_summaries(render_ready)
    except Exception as e:
        logger.warning("build_domain_summaries failed: %s", e)

    # Propaga alcuni enriched fields nel JSON principale (soft)
    try:
        _backfill_enriched_fields_into_probe_results(output)
    except Exception:
        pass

    # 12) Validazione schema (soft)
    try:
        validate_schema(output)
    except Exception:
        pass

    # 13) Export selettivo (sanitizza bytes SOLO per export)
    def _sanitize_for_json(obj: Any) -> Any:
        import base64
        if isinstance(obj, dict):
            return {k: _sanitize_for_json(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_sanitize_for_json(x) for x in obj]
        if isinstance(obj, bytes):
            if not obj:
                return ""
            b = obj[:8192]
            return {"__base64__": base64.b64encode(b).decode("ascii"), "len": len(obj)}
        return obj

    export_format, write_outputs = _determine_export_policy(cfg)
    if write_outputs and export_format != "none":
        out_json = cfg.get("output_file", cfg.get("output_json", "orchestrator_output.json"))
        out_csv  = cfg.get("output_csv", "orchestrator_results.csv")
        export_payload = _sanitize_for_json(output)
        export_paths = _export_selected(export_payload, export_format, out_json, out_csv)
        output["export_paths"] = export_paths
        for k, v in (export_paths or {}).items():
            logger.info("Orchestrator %s saved to %s", k.replace("_path", "").upper(), v)
    else:
        logger.info("Export disabilitato (export_format=%s, write_outputs=%s). Nessuna scrittura su disco.",
                    export_format, write_outputs)

    return output
