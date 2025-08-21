# analysis_bypass.py
# Heuristics / AI / Payload engine (on-demand, no heavy imports at module import time)
# Aggiunte (questa patch NON distrugge nulla):
# - Regole FLAGS coerenti (+AI, +BYP, +DNS, +DIR, +JWT, +CORS, +OPENRED, +SENSITIVE, +TRACE)
# - Dedup & ordinamento stabile
# - Coerenza WAF (es. Akamai → no caratteri spezzati nei bypass)
# - Mantiene tutte le funzioni esistenti (differential_diff, param_fuzz, jwt_analysis, embed_score, security_classify, dl_mutate)

from __future__ import annotations

import base64
import logging
import os
import random
import re
import string
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ------------------------------------------------------------------------------
# Optional deps are lazily imported inside functions. No heavy top-level imports.
# ------------------------------------------------------------------------------

# === Utility comuni ============================================================

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


def _common_prefix_len(a: str, b: str) -> int:
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i


def _common_suffix_len(a: str, b: str) -> int:
    i = 0
    while i < len(a) and i < len(b) and a[-1 - i] == b[-1 - i]:
        i += 1
    return i


# ------------------------------------------------------------------------------
# Deep/structural diff (optional)
# ------------------------------------------------------------------------------

def differential_diff(clean: str, fuzzed: str) -> Dict[str, Any]:
    """
    Return structural/text diff using deepdiff if available; otherwise naive diff stats.
    """
    try:
        from deepdiff import DeepDiff  # type: ignore
        return DeepDiff(clean, fuzzed, ignore_order=True).to_dict()
    except Exception:
        # Fallback minimal info
        return {
            "equal": clean == fuzzed,
            "len_clean": len(clean or ""),
            "len_fuzzed": len(fuzzed or ""),
            "prefix_match_len": _common_prefix_len(clean or "", fuzzed or ""),
            "suffix_match_len": _common_suffix_len(clean or "", fuzzed or ""),
        }


# ------------------------------------------------------------------------------
# KB euristica param→famiglia
# ------------------------------------------------------------------------------

_DEFAULT_PARAM_KB = {
    # family labels: XSS, SQLI, OPEN_REDIRECT, IDOR_BENIGN, JSONP, SSRF_SAFE, TRAVERSAL_SOFT
    "redirect": "OPEN_REDIRECT",
    "redir": "OPEN_REDIRECT",
    "return_url": "OPEN_REDIRECT",
    "next": "OPEN_REDIRECT",
    "url": "OPEN_REDIRECT",
    "callback": "OPEN_REDIRECT",
    "cb": "JSONP",
    "callback_func": "JSONP",
    "q": "XSS",
    "query": "XSS",
    "s": "XSS",
    "search": "XSS",
    "id": "IDOR_BENIGN",
    "uid": "IDOR_BENIGN",
    "user_id": "IDOR_BENIGN",
    "post_id": "IDOR_BENIGN",
    "order": "SQLI",
    "sort": "SQLI",
    "filter": "SQLI",
    "path": "TRAVERSAL_SOFT",
    "file": "TRAVERSAL_SOFT",
    "filename": "TRAVERSAL_SOFT",
    "image": "TRAVERSAL_SOFT",
    "avatar": "TRAVERSAL_SOFT",
    "target": "SSRF_SAFE",
    "endpoint": "SSRF_SAFE",
    "addr": "SSRF_SAFE",
}

def load_param_kb(path: Optional[str] = None) -> Dict[str, str]:
    """
    Carica la mappa param→famiglia da JSON/YAML. ENV: AB_PARAM_KB_PATH.
    Fallback: _DEFAULT_PARAM_KB.
    """
    kb_path = path or os.getenv("AB_PARAM_KB_PATH")
    if not kb_path:
        return dict(_DEFAULT_PARAM_KB)
    if not os.path.exists(kb_path):
        logger.warning("Param KB not found at %s. Using defaults.", kb_path)
        return dict(_DEFAULT_PARAM_KB)

    # prova YAML poi JSON
    try:
        import yaml  # type: ignore
        with open(kb_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if isinstance(data, dict):
            # consente formati: {"param_name": "FAMILY", ...} o {"map": {...}}
            mapping = data.get("map") if "map" in data and isinstance(data["map"], dict) else data
            return {str(k).lower(): str(v).upper() for k, v in mapping.items()}
    except Exception:
        pass
    try:
        import json  # stdlib
        with open(kb_path, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        if isinstance(data, dict):
            mapping = data.get("map") if "map" in data and isinstance(data["map"], dict) else data
            return {str(k).lower(): str(v).upper() for k, v in mapping.items()}
    except Exception as e:
        logger.warning("Param KB load failed: %s. Using defaults.", e)

    return dict(_DEFAULT_PARAM_KB)


def families_from_url_params(url: str, kb: Optional[Dict[str, str]] = None) -> List[str]:
    """
    Restituisce una lista de-duplicata di famiglie suggerite in base ai nomi dei param del URL.
    """
    mapping = kb or load_param_kb()
    params = parse_qsl(urlparse(url).query, keep_blank_values=True)
    ordered: List[str] = []
    seen = set()
    for name, _ in params:
        fam = mapping.get(name.lower())
        if fam and fam not in seen:
            ordered.append(fam)
            seen.add(fam)
    return ordered


# ------------------------------------------------------------------------------
# Heuristics + (optional) model classification
# ------------------------------------------------------------------------------

def classify_endpoint(scan_result: Dict[str, Any],
                      knowledge: Optional[Dict[str, Any]] = None,
                      memory: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Decide archetipo/vuln-candidate/next-step.
    Heuristics always; SecureBERT optionally if present.
    """
    url = scan_result.get("url", "")
    get_block = scan_result.get("get", {}) or {}
    ctype = (get_block.get("content_type") or "").lower()
    status = get_block.get("status") or 0
    body_snip = (get_block.get("body") or b"")[:2048].decode("iso-8859-1", errors="ignore")

    # --- euristiche base ---
    archetype, hints = _heuristic_archetype(url, ctype, body_snip, knowledge)
    vuln_candidates = _heuristic_vulns(archetype, hints, status, ctype, body_snip, knowledge)

    # --- modello opzionale (SecureBERT) per affinare ---
    score_model = 0.0
    try:
        text_for_model = " ".join([url, ctype, str(status), body_snip[:512]])
        score_model = security_classify(text_for_model)  # lazy inside
    except Exception as e:
        logger.debug("Model classify fallback: %s", e)

    next_action = "stop"
    if score_model >= 0.75 or "login" in archetype or "upload" in archetype:
        next_action = "enrich"
    if "api" in archetype and ("json" in ctype or "graphql" in hints):
        next_action = "enrich"

    return {
        "archetype": archetype,
        "hints": hints,
        "vuln_candidates": vuln_candidates,
        "model_score": float(score_model),
        "next_action": next_action,
    }


def _heuristic_archetype(url: str, ctype: str, body_snip: str,
                         knowledge: Optional[Dict[str, Any]]) -> Tuple[str, List[str]]:
    u = url.lower()
    hints: List[str] = []
    arche = "generic"

    # path-based clues
    if any(k in u for k in ("/login", "signin", "auth", "oauth")):
        arche = "login"
    elif any(k in u for k in ("search", "q=")):
        arche = "search"
    elif any(k in u for k in ("upload", "multipart", "file=")):
        arche = "upload"
    elif any(k in u for k in ("admin", "/wp-admin", "/dashboard")):
        arche = "admin"
    elif any(k in u for k in ("/api/", "api.", "/v1/", "/v2/", "/graphql")):
        arche = "api"
    elif any(k in u for k in ("callback", "webhook", "redirect", "return_url")):
        arche = "callback"

    # content-type clues
    if "json" in ctype:
        hints.append("json")
    if "html" in ctype:
        hints.append("html")
    if "/graphql" in u or "graphql" in body_snip.lower():
        hints.append("graphql")
        if arche == "generic":
            arche = "api"

    # knowledge extensions (optional)
    if knowledge and isinstance(knowledge.get("archetype_rules"), dict):
        # Hook espandibile in futuro
        pass

    return arche, hints


def _heuristic_vulns(archetype: str, hints: List[str], status: int, ctype: str,
                     body_snip: str, knowledge: Optional[Dict[str, Any]]) -> List[str]:
    candidates: List[str] = []
    if archetype == "login":
        candidates += ["weak_auth", "rate_limit", "2fa_missing"]
    if archetype == "search":
        candidates += ["xss_reflected", "sqli_like"]
    if archetype == "upload":
        candidates += ["upload_bypass", "content_type_mismatch"]
    if archetype == "admin":
        candidates += ["idor", "weak_auth", "csrf"]
    if archetype == "api":
        candidates += ["idor", "mass_assignment", "sqli_like"]
        if "graphql" in hints:
            candidates += ["graphql_introspection", "graphql_injection"]
    if archetype == "callback":
        candidates += ["open_redirect", "csrf"]

    if 500 <= int(status) <= 599:
        candidates.append("error_leak")
    if "json" in ctype:
        candidates.append("json_misuse")

    # Optional knowledge-based enrich
    if knowledge and isinstance(knowledge.get("vuln_bias"), dict):
        for v, w in knowledge["vuln_bias"].items():
            if isinstance(w, (int, float)) and w > 0 and v not in candidates:
                candidates.append(v)

    return sorted(set(candidates))


# ------------------------------------------------------------------------------
# Embedding score (SentenceTransformers, optional)
# ------------------------------------------------------------------------------

_MINI_MODEL = None
_ST_UTIL = None

def _ensure_sentence_model() -> Tuple[Any, Any] | Tuple[None, None]:
    global _MINI_MODEL, _ST_UTIL
    if _MINI_MODEL is not None and _ST_UTIL is not None:
        return _MINI_MODEL, _ST_UTIL
    try:
        from sentence_transformers import SentenceTransformer, util  # type: ignore
        _MINI_MODEL = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")
        _ST_UTIL = util
        return _MINI_MODEL, _ST_UTIL
    except Exception:
        logger.warning("SentenceTransformer not available. embed_score() returns 0.0.")
        return None, None

def embed_score(payloads: List[str], response: bytes, threshold: float = 0.9) -> float:
    model, util_mod = _ensure_sentence_model()
    if model is None or util_mod is None:
        return 0.0
    resp_text = (response or b"").decode("utf-8", errors="ignore")
    if not resp_text.strip():
        return 0.0
    emb_r = model.encode(resp_text, convert_to_tensor=True)
    best = 0.0
    for p in payloads or []:
        emb_p = model.encode(p, convert_to_tensor=True)
        s = float(util_mod.cos_sim(emb_p, emb_r).item())
        if s >= threshold:
            return s
        if s > best:
            best = s
    return best


# ------------------------------------------------------------------------------
# SecureBERT (optional)
# ------------------------------------------------------------------------------

_VULN_PIPE = None

def _ensure_securebert_pipeline():
    global _VULN_PIPE
    if _VULN_PIPE is not None:
        return _VULN_PIPE
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline  # type: ignore
        tokenizer = AutoTokenizer.from_pretrained("seyonec/SecureBERT")
        model = AutoModelForSequenceClassification.from_pretrained("seyonec/SecureBERT")
        _VULN_PIPE = pipeline("text-classification", model=model, tokenizer=tokenizer, return_all_scores=True)
        return _VULN_PIPE
    except Exception:
        logger.warning("SecureBERT not available. security_classify() returns 0.0.")
        _VULN_PIPE = None
        return None

def security_classify(text_snippet: str) -> float:
    pipe = _ensure_securebert_pipeline()
    if pipe is None:
        return 0.0
    try:
        results = pipe(text_snippet)
        best = 0.0
        for r in results:
            try:
                if r["label"].lower().startswith("vuln"):
                    return float(r["score"])
                best = max(best, float(r["score"]))
            except Exception:
                pass
        return best
    except Exception as e:
        logger.debug("SecureBERT classify failed: %s", e)
        return 0.0

def risk_markers(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Restituisce un elenco ordinato di marker rischio:
      ['sqli','xss','cors','auth','dirlist','weak-headers']
    È un wrapper leggero, allineato a policy.classify_attack_surface.
    Non solleva eccezioni: in caso di errore ritorna [].
    """
    try:
        # URL / path / metodo primario
        url = str(record.get("url") or "")
        get_rec = record.get("get") or {}
        post_rec = record.get("post") or {}
        prim = get_rec if get_rec else post_rec

        # Content-Type finale (se secco) con fallback
        def _norm_mime(v: Any) -> str:
            s = (str(v or "").strip().strip('"').strip("'")).lower()
            if not s:
                return ""
            if "," in s:
                s = s.split(",", 1)[0].strip()
            if ";" in s:
                s = s.split(";", 1)[0].strip()
            return s

        ctype = _norm_mime(
            record.get("content_type_final")
            or record.get("content_type")
            or prim.get("content_type")
            or (prim.get("headers") or {}).get("content-type")
            or (prim.get("headers") or {}).get("Content-Type")
        )

        # Headers finali (record-level o primario)
        headers = (record.get("headers") or {}) or (prim.get("headers") or {})

        # Security headers mancanti (shape compatibile con sonda)
        sec = record.get("security_headers") or {}
        missing = {str(x).lower() for x in (sec.get("missing") or [])}

        # Allowed/Allow methods
        allow = record.get("allow_methods") or record.get("allowed_methods") or []
        allow = [str(m).upper() for m in allow if m]

        # Body snippet (tollerante a bytes)
        body_snip = record.get("body_snip") or record.get("body_snippet") or prim.get("body") or b""
        if isinstance(body_snip, bytes):
            try:
                body_low = body_snip.decode("utf-8", errors="ignore").lower()
            except Exception:
                body_low = body_snip.decode("iso-8859-1", errors="ignore").lower()
        else:
            body_low = str(body_snip).lower()

        marks: List[str] = []

        # --- weak-headers ------------------------------------------------------
        needed = {"strict-transport-security", "x-frame-options", "x-content-type-options", "content-security-policy"}
        if missing & needed:
            marks.append("weak-headers")

        # --- xss (conservativa: CSP mancante + HTML) --------------------------
        if "content-security-policy" in missing and ("text/html" in ctype or ctype == ""):
            marks.append("xss")

        # --- sqli: error-based hints nel body ---------------------------------
        sql_err = ("sql syntax", "mysql", "mariadb", "psql", "postgres", "odbc", "ora-", "sqlite", "sqlstate")
        if any(tok in body_low for tok in sql_err):
            marks.append("sqli")

        # --- cors permissivo ---------------------------------------------------
        aco = str(headers.get("access-control-allow-origin") or headers.get("Access-Control-Allow-Origin") or "").strip()
        acc = str(headers.get("access-control-allow-credentials") or headers.get("Access-Control-Allow-Credentials") or "").strip().lower()
        if aco in ("*", "null") or (aco and acc == "true"):
            marks.append("cors")

        # --- auth surface (URL path) ------------------------------------------
        low_url = url.lower()
        if any(x in low_url for x in ("/login", "/signin", "/wp-login", "/oauth", "/auth")):
            marks.append("auth")
        if any(x in low_url for x in ("/wp-admin", "/admin/", "/administrator")):
            marks.append("auth")

        # --- directory listing -------------------------------------------------
        if "index of /" in body_low or ("text/html" in ctype and "<title>index of /" in body_low):
            marks.append("dirlist")

        # --- metodi “larghi” ---------------------------------------------------
        if any(m in allow for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND")):
            if "weak-headers" not in marks:
                marks.append("weak-headers")

        # Ordine canonico deterministico
        canon = ("sqli", "xss", "cors", "auth", "dirlist", "weak-headers")
        in_set = {m for m in marks if m}
        ordered = [m for m in canon if m in in_set]
        # Eventuali extra non previsti (non dovrebbero esserci) → in coda
        extra = sorted([m for m in in_set if m not in canon])
        ordered.extend(extra)
        return ordered
    except Exception:
        return []


# ------------------------------------------------------------------------------
# DL payload mutator (optional)
# ------------------------------------------------------------------------------

_NP_GENERATOR = None

def _ensure_neuralpayloads():
    global _NP_GENERATOR
    if _NP_GENERATOR is not None:
        return _NP_GENERATOR
    try:
        from neuralpayloads import PayloadGenerator  # type: ignore
        _NP_GENERATOR = PayloadGenerator()
        return _NP_GENERATOR
    except Exception:
        logger.warning("NeuralPayloads not available. dl_mutate() returns [].")
        _NP_GENERATOR = None
        return None

def dl_mutate(payloads: List[str], variants_per: int = 5) -> List[str]:
    gen = _ensure_neuralpayloads()
    if gen is None:
        return []
    out: List[str] = []
    for p in payloads or []:
        try:
            out.extend(list(gen.generate(p, variants_per)))
        except Exception as e:
            logger.debug("DL mutate error for payload %r: %s", p, e)
    return out


# ------------------------------------------------------------------------------
# JWT analysis (optional jwcrypto)
# ------------------------------------------------------------------------------

def jwt_analysis_if_present(headers_or_body: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Try to parse/mutate JWT (Authorization: Bearer ... or raw token).
    Returns [] if jwcrypto missing or token invalid.
    """
    token_str = _extract_bearer_or_token(headers_or_body)
    if not token_str:
        return []

    try:
        from jwcrypto import jwt as jwc  # type: ignore
    except Exception:
        logger.warning("jwcrypto not available. jwt_analysis_if_present() returns [].")
        return []

    findings: List[Dict[str, str]] = []
    try:
        parsed = jwc.JWT(jwt=token_str)
        claims = parsed.claims
        header = parsed.token.jose_header.copy()
    except Exception:
        return findings

    # alg=none variant
    try:
        h = header.copy(); h["alg"] = "none"
        t = jwc.JWT(header=h, claims=claims)
        findings.append({"variant": "alg_none", "token": t.serialize()})
    except Exception:
        pass

    # kid tamper (string reverse)
    if "kid" in header:
        try:
            h = header.copy(); h["kid"] = str(header["kid"])[::-1]
            t = jwc.JWT(header=h, claims=claims)
            findings.append({"variant": "kid_swap", "token": t.serialize()})
        except Exception:
            pass

    # signature bit flip
    try:
        parts = token_str.split(".")
        if len(parts) == 3:
            sig = parts[2]; pad = "=" * (-len(sig) % 4)
            bs = bytearray(base64.urlsafe_b64decode(sig + pad))
            if bs:
                bs[0] ^= 0x80
                new_sig = base64.urlsafe_b64encode(bs).rstrip(b"=").decode()
                findings.append({"variant": "bit_flip", "token": f"{parts[0]}.{parts[1]}.{new_sig}"})
    except Exception:
        pass

    return findings

def jwt_analysis(headers: Dict[str, str]) -> List[Dict[str, str]]:
    """
    Backward-compatible wrapper used by orchestrator.
    Looks into Authorization header; falls back to empty list if not applicable.
    """
    return jwt_analysis_if_present(headers or {})

def _extract_bearer_or_token(headers_or_body: Dict[str, Any]) -> Optional[str]:
    # Try Authorization header
    auth = (headers_or_body.get("Authorization") or headers_or_body.get("authorization") or "").strip()
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    # Or raw token-ish in dict
    for k, v in headers_or_body.items():
        if isinstance(v, str) and v.count(".") == 2 and len(v) > 20:
            return v
    return None


# ------------------------------------------------------------------------------
# Fuzzing lightweight (boofuzz optional; altrimenti fallback deterministico/evo)
# ------------------------------------------------------------------------------

def param_fuzz(records: List[Dict[str, Any]],
               mutations_per_param: int = 5,
               max_total: int = 100) -> List[Dict[str, Any]]:
    """
    Try boofuzz-based string fuzzing per-parameter. If boofuzz is missing,
    fall back to deterministic safe mutations. If still nothing, try evolutionary fuzz.
    Returns list of {url, param, payload_raw: bytes}.
    """
    fuzz_results: List[Dict[str, Any]] = []
    seen = set()

    # -- attempt boofuzz path --
    boofuzz_ok = False
    try:
        from boofuzz import Session, Target, s_initialize, s_string, s_get  # type: ignore
        boofuzz_ok = True
    except Exception:
        logger.info("boofuzz not available. Using fallback mutations.")

    for rec in records or []:
        url = rec.get("url", "")
        params = parse_qsl(urlparse(url).query, keep_blank_values=True)

        local_added = 0
        if boofuzz_ok and params:
            try:
                class _DummyConnection:
                    def __init__(self):
                        self.requests: List[bytes] = []
                    def send(self, data: bytes): self.requests.append(data)
                    def recv(self, size: int, timeout=None) -> bytes: return b""
                    def close(self): pass

                for name, value in params:
                    dummy = _DummyConnection()
                    target = Target(connection=dummy)
                    session = Session(target=target, sleep_time=0)
                    s_initialize(name)
                    s_string(value, fuzzable=True)
                    session.connect(s_get(name))
                    session.fuzz(mutations_per_param)
                    for raw in dummy.requests:
                        entry = {"url": url, "param": name, "payload_raw": raw}
                        key = (url, name, raw)
                        if key not in seen:
                            fuzz_results.append(entry)
                            seen.add(key)
                            local_added += 1
                            if len(fuzz_results) >= max_total:
                                return fuzz_results
            except Exception as e:
                logger.debug("boofuzz path failed: %s", e)

        # Fallback deterministic mutations if no boofuzz or no params captured
        if local_added == 0 and params:
            for name, value in params:
                for m in _safe_mutations(value, limit=mutations_per_param):
                    raw = m.encode("utf-8", errors="ignore")
                    entry = {"url": url, "param": name, "payload_raw": raw}
                    key = (url, name, raw)
                    if key not in seen:
                        fuzz_results.append(entry)
                        seen.add(key)
                        if len(fuzz_results) >= max_total:
                            return fuzz_results

        # Last resort: evolutionary fuzz on available params (optional deap)
        if local_added == 0 and params:
            try:
                evo = evolutionary_fuzz_if_enabled(
                    [{"url": url, "param": n, "payload_raw": str(v).encode()} for n, v in params],
                    generations=2, pop_size=10
                )
                for entry in evo:
                    key = (entry["url"], entry.get("param", ""), entry["payload_raw"])
                    if key not in seen:
                        fuzz_results.append(entry)
                        seen.add(key)
                        if len(fuzz_results) >= max_total:
                            return fuzz_results
            except Exception as e:
                logger.debug("evolutionary fallback failed: %s", e)

    return fuzz_results


def _safe_mutations(value: str, limit: int = 5) -> List[str]:
    """
    Deterministic, safe, non-destructive string mutations.
    """
    seeds = [
        value,
        value + "'",
        value + "\"",
        value + ">",              # xss-ish
        value + "<script>",
        f"{value} OR 1=1",
        "../" + value,
        value.replace(" ", "+"),
        value[::-1],
        value[:1] + "*" + value[1:] if len(value) > 1 else value + "*",
    ]
    uniq: List[str] = []
    for s in seeds:
        if s not in uniq:
            uniq.append(s)
        if len(uniq) >= limit:
            break
    return uniq


def evolutionary_fuzz_if_enabled(records: List[Dict[str, Any]],
                                 generations: int = 2,
                                 pop_size: int = 10) -> List[Dict[str, Any]]:
    """
    Optional evolutionary fuzz using deap. Returns [] if deap unavailable.
    """
    try:
        from deap import base, creator, tools, algorithms  # type: ignore
    except Exception:
        logger.info("deap not available. evolutionary_fuzz_if_enabled() returns [].")
        return []

    variants: List[Dict[str, Any]] = []
    for rec in records or []:
        orig = (rec.get("payload_raw") or b"").decode("utf-8", errors="ignore")
        if not orig:
            continue
        try:
            # create once per record to avoid type collisions
            FitnessMulti = type("FitnessMulti", (base.Fitness,), {})  # lightweight
            FitnessMulti.weights = (1.0, 1.0)  # type: ignore[attr-defined]
            Individual = type("Individual", (list,), {"fitness": FitnessMulti()})  # type: ignore
            toolbox = base.Toolbox()
            toolbox.register("attr_char", random.choice, list(string.printable))
            toolbox.register("individual", tools.initRepeat, Individual, toolbox.attr_char, n=len(orig))
            toolbox.register("population", tools.initRepeat, list, toolbox.individual)

            def eval_fn(ind):
                return (len(ind), sum(c in string.printable for c in ind))

            toolbox.register("evaluate", eval_fn)
            toolbox.register("mate", tools.cxOnePoint)
            toolbox.register("mutate", tools.mutShuffleIndexes, indpb=0.05)
            toolbox.register("select", tools.selNSGA2)

            pop = toolbox.population(n=pop_size)
            algorithms.eaMuPlusLambda(pop, toolbox, mu=pop_size // 2, lambda_=pop_size,
                                      cxpb=0.6, mutpb=0.3, ngen=generations, verbose=False)
            for ind in pop:
                payload = "".join(ind).encode("utf-8", errors="ignore")
                variants.append({
                    "url": rec.get("url", ""),
                    "param": rec.get("param", ""),
                    "payload_raw": payload
                })
        except Exception as e:
            logger.debug("Evolutionary fuzz error: %s", e)
    return variants


# ------------------------------------------------------------------------------
# Payload families + WAF-bypass (soft) + Reflection canary + Context aware
# ------------------------------------------------------------------------------

@dataclass
class PayloadConstraints:
    max_len: int = 512
    allow_unicode: bool = True
    numeric_only: bool = False
    allowed_chars: Optional[str] = None  # regex char class, es. r"[A-Za-z0-9_]"
    content_type: str = ""               # "application/json", "application/xml", "application/x-www-form-urlencoded"
    wrap_json: bool = False
    wrap_xml: bool = False


def _apply_constraints(s: str, c: PayloadConstraints) -> str:
    if c.numeric_only:
        s = "".join(ch for ch in s if ch.isdigit()) or "1"
    if c.allowed_chars:
        try:
            s = "".join(ch for ch in s if re.match(c.allowed_chars, ch))
        except Exception:
            pass
    if not c.allow_unicode:
        s = s.encode("ascii", errors="ignore").decode("ascii", errors="ignore")
    if len(s) > c.max_len:
        s = s[: c.max_len]
    if c.wrap_json:
        s = f'{{"q":"{s}"}}'
    if c.wrap_xml:
        s = f"<q>{s}</q>"
    return s


def make_canary(tag: str = "BG") -> str:
    """
    Crea un canary leggero per riflessioni/normalizzazioni.
    """
    rnd = random.randint(1000, 9999)
    # caratteri innocui + Unicode "sicuro" opzionale
    return f"{tag}{rnd}—CANARY—{rnd}{tag}"  # EN DASH per vedere eventuali normalizzazioni


def add_canary(payload: str, canary: Optional[str] = None, mode: str = "suffix") -> str:
    """
    Inserisce il canary nel payload senza “rompere” sintassi comuni.
    mode: prefix|suffix|wrap
    """
    c = canary or make_canary()
    if mode == "prefix":
        return c + payload
    if mode == "wrap":
        return f"{c}{payload}{c}"
    return payload + c  # suffix default


def generate_payloads(endpoint_ctx: Dict[str, Any],
                      family: str,
                      memory: Optional[List[Dict[str, Any]]] = None,
                      limit: int = 8,
                      constraints: Optional[PayloadConstraints] = None,
                      add_reflection_canary: bool = True) -> List[str]:
    """
    Deterministic, context-aware payload families (safe by default).
    family in: XSS, SQLI, IDOR_BENIGN, SSRF_SAFE, UPLOAD_BENIGN, OPEN_REDIRECT, JSONP, TRAVERSAL_SOFT
    """
    family = (family or "").upper()
    url = endpoint_ctx.get("url", "")
    params = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    ctype = (endpoint_ctx.get("content_type") or "").lower()

    c = constraints or PayloadConstraints(content_type=ctype)
    if "json" in ctype and not (c.wrap_xml or c.wrap_json):
        c.wrap_json = True
    elif "xml" in ctype and not (c.wrap_xml or c.wrap_json):
        c.wrap_xml = True

    base: List[str] = []
    if family == "XSS":
        base = [
            "<script>alert(1)</script>",
            "\"'><svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "<sCrIpT>alert(1)</sCrIpT>",
        ]
    elif family == "SQLI":
        base = [
            "' OR 1=1 -- ",
            "\" OR 1=1 -- ",
            "admin'--",
            "') OR ('1'='1",
            "0 UNION SELECT NULL",
        ]
    elif family == "IDOR_BENIGN":
        base = []
        for k, v in params.items():
            if v.isdigit():
                base += [v, str(max(0, int(v) - 1)), str(int(v) + 1)]
        if not base:
            base = ["1", "2", "3"]
    elif family == "SSRF_SAFE":
        base = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/",
            "http://example.com/",
        ]
    elif family == "UPLOAD_BENIGN":
        base = ["test.txt", "image.jpg", "document.pdf", "x.php.jpg", "shell.asp;.jpg"]
    elif family == "OPEN_REDIRECT":
        base = [
            "https://example.com",
            "//example.com",
            "/\\example.com",
            "/////example.com",
            "https:%2f%2fexample.com",
        ]
    elif family == "JSONP":
        base = ["alert", "confirm", "console.log", "callback", "cb"]
    elif family == "TRAVERSAL_SOFT":
        base = ["../etc/passwd", "..\\..\\windows\\win.ini", "../../var/log/system.log", "./././", "%2e%2e/"]
    else:
        base = ["test", "1", "true", "<>\"'"]

    # Adattamento al content-type / constraints
    out: List[str] = []
    canary = make_canary()
    seen = set()

    if memory:
        for m in memory[-5:]:
            try:
                seen.add((m.get("request", {}).get("payload") or "").strip())
            except Exception:
                pass

    for p in base:
        q = _apply_constraints(p, c)
        if add_reflection_canary and family in ("XSS", "SQLI", "OPEN_REDIRECT", "TRAVERSAL_SOFT"):
            q = add_canary(q, canary, mode="suffix")
        if q not in seen:
            out.append(q)
            seen.add(q)
        if len(out) >= limit:
            break
    return out


def _normalize_waf_name(waf_signals: Dict[str, Any]) -> str:
    """
    Ricava un nome WAF 'canonico' da segnali vari (headers/server/waf field).
    """
    name = (waf_signals.get("waf") or "").strip()
    if not name:
        srv = (waf_signals.get("headers", {}) or {}).get("Server") or (waf_signals.get("headers", {}) or {}).get("server")
        srv = (srv or "").lower()
        if "akamai" in srv:
            name = "Akamai"
        elif "cloudflare" in srv or "cf-ray" in (waf_signals.get("headers", {}) or {}):
            name = "Cloudflare"
        elif "imperva" in srv:
            name = "Imperva"
        elif "f5" in srv or "big-ip" in srv:
            name = "F5"
        elif "aws" in srv:
            name = "AWS"
    return str(name)


def apply_waf_bypass(payloads: List[str],
                     waf_signals: Dict[str, Any],
                     policy: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Apply soft transformations if WAF suspected: encoding, spacing, case, wrappers, unicode-safe.
    policy flags (bool): encode, spacing, swapcase, json_wrap, xml_wrap, unicode_zws
    **Coerenza con WAF**:
      - Se WAF canonico == "Akamai" → disabilita unicode_zws (niente caratteri spezzati) e swapcase.
    """
    suspected = bool(waf_signals.get("waf")) or any(
        k.lower() in ("x-waf", "x-mod-security", "cf-ray", "server") for k in (waf_signals.get("headers") or {}).keys()
    )
    if not suspected:
        return payloads or []

    waf_name = _normalize_waf_name(waf_signals)

    p = {
        "encode": True,
        "spacing": True,
        "swapcase": True,
        "json_wrap": True,
        "xml_wrap": False,
        "unicode_zws": True,
    }
    if isinstance(policy, dict):
        p.update({k: bool(v) for k, v in policy.items()})

    # Regola speciale Akamai: NO ZWS/NO swapcase
    if waf_name == "Akamai":
        p["unicode_zws"] = False
        p["swapcase"] = False

    variants: List[str] = []
    for s in payloads or []:
        variants.append(s)
        if p["spacing"]:
            variants.append(s.replace(" ", "/**/"))
        if p["encode"]:
            enc = s.replace("<", "%3C").replace(">", "%3E").replace("'", "%27").replace('"', "%22")
            variants.append(enc)
        if p["swapcase"]:
            variants.append(s.swapcase())
        if p["json_wrap"]:
            variants.append(f"JSONSTART{s}JSONEND")
        if p["xml_wrap"]:
            variants.append(f"<wrap>{s}</wrap>")
        if p["unicode_zws"]:
            zws = "\u200b"
            variants.append(zws.join(list(s)))

    # dedup preserving order
    seen: set = set()
    out: List[str] = []
    for v in variants:
        if v not in seen:
            out.append(v)
            seen.add(v)
    return out


# ------------------------------------------------------------------------------
# Coverage “senza login” (light)
# ------------------------------------------------------------------------------

_SENSITIVE_FILES = [
    "/.git/config",
    "/.env",
    "/.DS_Store",
    "/server-status",
    "/phpinfo.php",
    "/config.json",
    "/admin/config.php",
    "/.well-known/security.txt",
]

def _set_query_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[key] = value
    new_q = urlencode(list(q.items()))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))

def build_light_coverage_suite(base_url: str) -> List[Dict[str, Any]]:
    """
    Ritorna una lista di probe “senza login”:
      - Open Redirect (next/redirect/return_url ecc.)
      - CORS/headers (OPTIONS preflight)
      - JSONP callback
      - Path traversal soft
      - Sensitive files
      - Method probing (HEAD/OPTIONS/TRACE/PUT light)
    Ogni item: {method, url, headers?, body?}
    """
    items: List[Dict[str, Any]] = []

    # Open Redirect probes
    for k in ("next", "redirect", "return_url", "url", "callback"):
        items.append({"method": "GET", "url": _set_query_param(base_url, k, "https://example.com")})
        items.append({"method": "GET", "url": _set_query_param(base_url, k, "//example.com")})

    # CORS / headers preflight
    items.append({
        "method": "OPTIONS",
        "url": base_url,
        "headers": {
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Test-Header",
        },
    })

    # JSONP callback
    for k in ("callback", "cb", "jsonp"):
        items.append({"method": "GET", "url": _set_query_param(base_url, k, "alert")})

    # Path traversal soft (aggiunta param “path” o “file”)
    for k in ("path", "file", "filename"):
        items.append({"method": "GET", "url": _set_query_param(base_url, k, "../etc/passwd")})
        items.append({"method": "GET", "url": _set_query_param(base_url, k, "..\\..\\windows\\win.ini")})

    # Sensitive files (diretti)
    parsed = urlparse(base_url)
    root = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    for p in _SENSITIVE_FILES:
        items.append({"method": "GET", "url": root + p})

    # Method probing light
    items.append({"method": "HEAD", "url": base_url})
    items.append({"method": "TRACE", "url": base_url})
    items.append({"method": "PUT", "url": base_url, "headers": {"Content-Type": "text/plain"}, "body": b"probe"})

    return items


# ------------------------------------------------------------------------------
# Feature selection (optional sklearn)
# ------------------------------------------------------------------------------

def select_top_features(matrix: Any, k: int) -> Any:
    """
    PCA if sklearn available; else identity/fallback slice.
    """
    try:
        from sklearn.decomposition import PCA  # type: ignore
        return PCA(n_components=k).fit_transform(matrix)
    except Exception:
        logger.warning("sklearn PCA not available. Returning first k columns (fallback).")
        try:
            return [row[:k] for row in matrix]
        except Exception:
            return matrix


# ------------------------------------------------------------------------------
# FLAG ENGINE — derivazione, dedup e ordinamento stabile
# ------------------------------------------------------------------------------

# Ordine stabile desiderato in output
_FLAG_ORDER = [
    "+AI",
    "+BYP",
    "+DNS",
    "+DIR",
    "+JWT",
    "+CORS",
    "+OPENRED",
    "+SENSITIVE",
    "+TRACE",
]

def _stable_dedup(seq: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in seq:
        if not x:
            continue
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out

def _ordered_flags(flags: List[str]) -> List[str]:
    flags = _stable_dedup([str(f).strip() for f in flags])
    # mantieni l'ordine definito; tutto il resto accodato in coda
    ordered = [f for f in _FLAG_ORDER if f in flags]
    rest = [f for f in flags if f not in _FLAG_ORDER]
    return ordered + rest

def _body_text(rec: Dict[str, Any]) -> str:
    g = rec.get("get", {}) or {}
    p = rec.get("post", {}) or {}
    body = g.get("body") or p.get("body") or b""
    try:
        return body.decode("utf-8")
    except Exception:
        return body.decode("iso-8859-1", errors="ignore")

def _headers(rec: Dict[str, Any]) -> Dict[str, str]:
    g = rec.get("get", {}) or {}
    p = rec.get("post", {}) or {}
    h = g.get("headers") or p.get("headers") or {}
    if not isinstance(h, dict):
        return {}
    return {str(k): str(v) for k, v in h.items()}

def _status_for_method(rec: Dict[str, Any], method: str) -> Optional[int]:
    blk = rec.get(method.lower(), {}) or {}
    st = blk.get("status")
    return int(st) if isinstance(st, (int, float)) else None

def _families_hint_from_url(url: str) -> List[str]:
    try:
        return families_from_url_params(url)
    except Exception:
        return []

def derive_flags_for_record(rec: Dict[str, Any],
                            profile: str = "light",
                            jwt_variants: Optional[List[Dict[str, str]]] = None,
                            embed_sim: Optional[float] = None,
                            dns_anomaly: Optional[bool] = None,
                            bypass_attempted: Optional[bool] = None) -> List[str]:
    """
    Regole:
      +AI  → se embed_sim >= 0.75 oppure security_classify(url+headers+snippet) >= 0.75
      +BYP → SOLO se profile == "deep" E bypass_attempted True (o rec['tests']['bypass_attempted'])
      +DNS → se dns_anomaly True o header/server indicano problemi noti (es. NXDOMAIN/Retry-After DNS)
      +DIR → se body contiene pattern tipo 'Index of /' o families suggeriscono TRAVERSAL_SOFT e status 200
      +JWT → se jwt_variants non vuoto
      +CORS → se Access-Control-Allow-Origin presente e permissivo (* o origine non-matching)
      +OPENRED → se families suggeriscono OPEN_REDIRECT
      +SENSITIVE → se richiesta a file sensibili ha status 200
      +TRACE → se metodo TRACE ha status 200
    Dedup & ordering sempre applicati.
    """
    flags: List[str] = []
    url = rec.get("url", "") or ""
    hdrs = _headers(rec)
    body = _body_text(rec)
    waf_name = _normalize_waf_name({"waf": rec.get("waf"), "headers": hdrs})

    # +AI
    ai_score = 0.0
    try:
        ai_score = float(security_classify(" ".join([url, body[:256]])))
    except Exception:
        ai_score = 0.0
    es = float(embed_sim or 0.0)
    if max(ai_score, es) >= 0.75:
        flags.append("+AI")

    # +BYP
    bypass_flag = bypass_attempted
    if bypass_flag is None:
        bypass_flag = bool(rec.get("tests", {}).get("bypass_attempted"))
    if profile.lower() == "deep" and bool(bypass_flag):
        flags.append("+BYP")

    # +DNS
    if dns_anomaly is None:
        # euristiche semplici: Retry-After DNS, X-DNS-Prefetch-Control, errori NXDOMAIN in body
        text_low = body.lower()
        if "nxdomain" in text_low or "dns probe finished" in text_low:
            dns_anomaly = True
        else:
            # se non evidente, lascia None/False
            dns_anomaly = False
    if dns_anomaly:
        flags.append("+DNS")

    # +DIR (listing/traversal soft riuscito)
    if ("index of /" in body.lower()) or ("directory listing" in body.lower()):
        flags.append("+DIR")
    else:
        fams = _families_hint_from_url(url)
        if "TRAVERSAL_SOFT" in fams and (_status_for_method(rec, "GET") == 200):
            flags.append("+DIR")

    # +JWT
    if jwt_variants and len(jwt_variants) > 0:
        flags.append("+JWT")

    # +CORS
    aco = hdrs.get("Access-Control-Allow-Origin") or hdrs.get("access-control-allow-origin") or ""
    if aco == "*" or (aco and not urlparse(url).netloc.endswith(urlparse(aco).netloc or "")):
        flags.append("+CORS")

    # +OPENRED (solo hint da famiglie)
    fams = _families_hint_from_url(url)
    if "OPEN_REDIRECT" in fams:
        flags.append("+OPENRED")

    # +SENSITIVE (se endpoint tocca file sensibili e 200)
    path_low = urlparse(url).path.lower()
    if any(path_low.endswith(p.lower()) for p in _SENSITIVE_FILES) and (_status_for_method(rec, "GET") == 200):
        flags.append("+SENSITIVE")

    # +TRACE (metodo consentito)
    st_trace = _status_for_method(rec, "TRACE")
    if st_trace and 200 <= st_trace < 400:
        flags.append("+TRACE")

    # Dedup & ordine
    final_flags = _ordered_flags(flags)

    # Coerenza con WAF Akamai: i FLAGS non vengono “spezzati” (qui li manteniamo semplici token).
    # (La protezione “no caratteri spezzati” è già applicata in apply_waf_bypass per i payload.)
    return final_flags


def assign_flags(records: List[Dict[str, Any]],
                 profile: str = "light",
                 jwt_findings_per_record: Optional[List[List[Dict[str, str]]]] = None,
                 embed_scores: Optional[List[float]] = None,
                 dns_anomalies: Optional[List[bool]] = None,
                 bypass_attempts: Optional[List[bool]] = None) -> List[Dict[str, Any]]:
    """
    Assegna flags ad una lista di record (in-place friendly ma ritorna sempre la lista).
    - Mantiene flags esistenti unendoli con i nuovi, poi dedup & ordering stabile.
    - Array opzionali devono essere allineati per indice ai records.
    """
    for i, rec in enumerate(records or []):
        jwtv = jwt_findings_per_record[i] if jwt_findings_per_record and i < len(jwt_findings_per_record) else None
        es = embed_scores[i] if embed_scores and i < len(embed_scores) else None
        dns = dns_anomalies[i] if dns_anomalies and i < len(dns_anomalies) else None
        byp = bypass_attempts[i] if bypass_attempts and i < len(bypass_attempts) else None

        new_flags = derive_flags_for_record(rec, profile=profile, jwt_variants=jwtv, embed_sim=es,
                                            dns_anomaly=dns, bypass_attempted=byp)
        old_flags = rec.get("flags", [])
        merged = _ordered_flags(_stable_dedup((old_flags or []) + new_flags))
        rec["flags"] = merged
    return records


# ------------------------------------------------------------------------------
# Module banner
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("analysis_bypass.py ready: KB param, heuristics, context payloads, WAF soft, canary, light coverage, FLAGS engine.")
