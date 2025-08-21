# policy.py — Regia decisionale (il “quando”)
# Decide in modo deterministico se: STOP / ENRICH / AI / PAYLOAD_<FAMILY>
# Legge score/flags/memoria temporale e applica gating Top-K + WAF bypass “a due colpi”.

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse, parse_qsl

# --------------------------------------------------------------------------- #
# SCORING / THRESHOLDS                                                        #
# --------------------------------------------------------------------------- #

from typing import Optional, Dict

def map_score_to_severity(score: float, thresholds: Optional[Dict[str, float]] = None) -> str:
    thr = thresholds or {"high": 0.75, "medium": 0.40}
    try:
        s = float(score)
    except Exception:
        s = 0.0
    if s >= float(thr.get("high", 0.75)):
        return "High"
    if s >= float(thr.get("medium", 0.40)):
        return "Medium"
    return "Low"

from typing import Dict, Any, Optional, List, Set, Tuple
import re
from urllib.parse import urlsplit, parse_qsl

def compute_risk_score(row) -> float:
    """
    Punteggio 0..1 “realistico”, non 0 fisso:
      - status: 5xx>4xx>2xx
      - latency: normalizzata su 3s
      - content-type: html/json leggermente più rischiosi
      - security headers mancanti: +0.03 ciascuno (cap a 0.12)
      - flags: XSS/SQLI/… pesano di più
      - ENV:QA/BETA/DEV sconta -0.1
    """
    try:
        status = row.get("status")
        lat_ms = float(row.get("latency_ms") or 0.0)
        ctype = (row.get("content_type_final") or "").lower()
        flags = [str(x).upper() for x in (row.get("flags") or [])]
        sec = row.get("security_headers") or {}
        missing = [str(x).lower() for x in (sec.get("missing") or [])]
    except Exception:
        status, lat_ms, ctype, flags, missing = None, 0.0, "", [], []

    score = 0.0

    # Status
    if isinstance(status, int):
        if 500 <= status <= 599:
            score += 0.55
        elif 400 <= status <= 499:
            score += 0.35
        elif 200 <= status <= 299:
            score += 0.10
        else:
            score += 0.05

    # Latenza (clamp 0..1 su 3s) * 0.2
    score += min(1.0, max(0.0, lat_ms / 3000.0)) * 0.20

    # Content-Type
    if "application/json" in ctype or "text/html" in ctype or "html" in ctype or "json" in ctype:
        score += 0.10
    elif "text" in ctype:
        score += 0.05
    else:
        score += 0.02

    # Security headers mancanti (piccolo boost cumulativo)
    score += min(0.12, 0.03 * len(missing))

    # Flags forti
    strong = {
        "SQLI": 0.35, "XSS": 0.25, "SSRF": 0.35, "RCE": 0.50,
        "DIR": 0.15, "WEAKHDRS": 0.08, "CB_OPEN": 0.05, "BYP": 0.05
    }
    for f in flags:
        if f.startswith("ENV:"):
            continue
        score += strong.get(f, 0.0)

    # Ambiente di test/qa → sconto
    if any(f.startswith("ENV:") for f in flags):
        score -= 0.10

    # Clamp
    return max(0.0, min(1.0, score))


def score_reasons(row) -> list[str]:
    """
    Motivi sintetici coordinati con lo score.
    """
    out = []
    st = row.get("status")
    if isinstance(st, int):
        if 500 <= st <= 599:
            out.append("Server error 5xx")
        elif 400 <= st <= 499:
            out.append("Client error 4xx")

    lat_ms = float(row.get("latency_ms") or 0.0)
    if lat_ms >= 2000:
        out.append("Slow (>2s)")

    sec = row.get("security_headers") or {}
    missing = [str(x).upper() for x in (sec.get("missing") or [])]
    if missing:
        out.append("Weak headers: " + ",".join(sorted(set(missing))[:4]))

    flags = [str(x).upper() for x in (row.get("flags") or [])]
    for k in ("XSS", "SQLI", "SSRF", "DIR", "CB_OPEN", "WEAKHDRS", "BYP"):
        if k in flags:
            out.append(k)

    if not out:
        out.append("Heuristics")
    return out


def family_from_context(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None) -> str:
    """
    Determina la FAMILY 'funzionale' dell'endpoint combinando:
      1) KB params: exact/regex/substring sui NOMI dei parametri query
      2) Host hint: api/cdn/ott/auth/dev/qa/uat/stage/... → categorie funzionali
      3) Path hint: login/watch/admin/v1/graphql/wp-... → categorie funzionali
      4) Type hint: application/json → API
    Restituisce una singola stringa (es. 'API', 'AUTH', 'CACHE', 'OTT', 'MASS_ASSIGNMENT', 'IDOR', 'TRAVERSAL', 'GENERIC').
    Non solleva eccezioni.
    """
    try:
        url = str(record.get("url") or "")
        ct = (
            str(record.get("content_type_final")
                or (record.get("get") or {}).get("content_type")
                or (record.get("post") or {}).get("content_type")
                or "")
            .lower()
        )
        if ";" in ct:
            ct = ct.split(";", 1)[0].strip()

        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = parts.path or "/"
        qparams = [k for k, _ in parse_qsl(parts.query or "", keep_blank_values=True)]

        # --- 1) KB params ------------------------------------------------------
        fam_votes: List[Tuple[str, int]] = []  # (family, weight/priority)
        if kb:
            meta = kb.get("meta", {})
            def_pri = int(meta.get("default_priority", 10) or 10)
            # exact
            for name in qparams:
                ncf = name.casefold()
                for k, v in (kb.get("exact") or {}).items():
                    try:
                        if str(k).casefold() == ncf:
                            fam = str((v or {}).get("family") or meta.get("default_family") or "GENERIC")
                            pri = int((v or {}).get("priority", def_pri))
                            fam_votes.append((fam, max(pri, def_pri)))
                    except Exception:
                        continue
            # regex
            for name in qparams:
                for rule in (kb.get("regex") or []):
                    pat = (rule or {}).get("pattern")
                    if not pat:
                        continue
                    try:
                        if re.search(pat, name, flags=re.IGNORECASE):
                            fam = str((rule or {}).get("family") or meta.get("default_family") or "GENERIC")
                            pri = int((rule or {}).get("priority", def_pri))
                            fam_votes.append((fam, max(pri, def_pri)))
                    except Exception:
                        continue
            # substring
            for name in qparams:
                ncf = name.casefold()
                for rule in (kb.get("substring") or []):
                    sub = str((rule or {}).get("contains") or "").casefold()
                    if not sub:
                        continue
                    if sub in ncf:
                        fam = str((rule or {}).get("family") or meta.get("default_family") or "GENERIC")
                        pri = int((rule or {}).get("priority", def_pri))
                        fam_votes.append((fam, max(pri, def_pri)))

        # prendi il voto KB con priorità più alta
        kb_fam = ""
        if fam_votes:
            kb_fam = sorted(fam_votes, key=lambda x: x[1], reverse=True)[0][0]

        # --- 2) Host hint ------------------------------------------------------
        host_map = {
            "api": "API",
            "auth": "AUTH", "login": "AUTH", "sso": "AUTH", "saml": "AUTH",
            "cdn": "CACHE", "origin": "CACHE",
            "ott": "OTT", "stream": "OTT",
            "admin": "MASS_ASSIGNMENT",
            "portal": "AUTH",
            "lockervision": "IDOR",
            "content": "TRAVERSAL",
        }
        env_tokens = ("dev", "qa", "uat", "staging", "stage", "test", "beta", "preview", "preprod", "int", "devint")
        host_fam = ""
        for token, fam in host_map.items():
            if host.startswith(token + ".") or f".{token}." in f".{host}." or host.endswith(f".{token}.nba.com"):
                host_fam = fam
                break
        # env non determina family ma è un segnale; qui non lo usiamo per la scelta finale.

        # --- 3) Path hint ------------------------------------------------------
        path_low = path.lower()
        path_map = [
            (r"/(login|signin|oauth|auth)(/|$)", "AUTH"),
            (r"/wp-admin(/|$)", "MASS_ASSIGNMENT"),
            (r"/admin(/|$)", "MASS_ASSIGNMENT"),
            (r"/watch(/|/featured|$)", "OTT"),
            (r"/v\\d+(/|$)", "API"),
            (r"/graphql(/|$)", "API"),
            (r"/wp-(json|content|includes)(/|$)", "CMS"),
            (r"/(export|download|upload)(/|$)", "UPLOAD"),
        ]
        path_fam = ""
        for pat, fam in path_map:
            try:
                if re.search(pat, path_low, flags=re.IGNORECASE):
                    path_fam = fam
                    break
            except Exception:
                continue

        # --- 4) Type hint ------------------------------------------------------
        type_fam = "API" if ct == "application/json" else ""

        # Risoluzione finale (priorità: KB > Path > Host > Type)
        for cand in (kb_fam, path_fam, host_fam, type_fam):
            if cand:
                return cand

        return "GENERIC"
    except Exception:
        return "GENERIC"

def classify_attack_surface(record: Dict[str, Any]) -> Set[str]:
    """
    Ritorna un set di marker di superficie d'attacco:
      { 'xss', 'sqli', 'cors', 'auth', 'dirlist', 'weak-headers' }
    Basato su: headers, security_headers.missing, content-type finale, body snippet,
    metodi consentiti/OPTIONS e path/URL. Non solleva eccezioni.
    """
    marks: Set[str] = set()
    try:
        url = str(record.get("url") or "")
        ct = (
            str(record.get("content_type_final")
                or (record.get("get") or {}).get("content_type")
                or (record.get("post") or {}).get("content_type")
                or "")
            .lower()
        )
        if ";" in ct:
            ct = ct.split(";", 1)[0].strip()

        prim = (record.get("get") or record.get("post") or {}) or {}
        headers = (record.get("headers") or {}) or (prim.get("headers") or {}) or {}
        sh = (record.get("security_headers") or {}) or {}
        missing = {str(x).lower() for x in (sh.get("missing") or [])}

        allow = record.get("allow_methods") or record.get("allowed_methods") or []
        allow = [str(m).upper() for m in allow if m]

        body_snip = (record.get("body_snip") or record.get("body_snippet") or b"")
        if isinstance(body_snip, bytes):
            try:
                body_low = body_snip.decode("utf-8", errors="ignore").lower()
            except Exception:
                body_low = body_snip.decode("iso-8859-1", errors="ignore").lower()
        else:
            body_low = str(body_snip).lower()

        # weak-headers (hardening mancante)
        weak_needed = {"strict-transport-security", "x-frame-options", "x-content-type-options", "content-security-policy"}
        if missing & weak_needed:
            marks.add("weak-headers")

        # XSS (euristica conservativa)
        if "content-security-policy" in missing and ("text/html" in ct or ct == ""):
            marks.add("xss")

        # SQLi (error-based hints)
        sql_err = ("sql syntax", "mysql", "mariadb", "psql", "postgres", "odbc", "ora-", "sqlite", "sqlstate")
        if any(tok in body_low for tok in sql_err):
            marks.add("sqli")

        # CORS permissivo
        aco = str(headers.get("access-control-allow-origin") or headers.get("Access-Control-Allow-Origin") or "").strip()
        acc = str(headers.get("access-control-allow-credentials") or headers.get("Access-Control-Allow-Credentials") or "").strip().lower()
        if aco in ("*", "null") or (aco and acc == "true"):
            marks.add("cors")

        # Auth surface
        low_url = url.lower()
        if any(x in low_url for x in ("/login", "/signin", "/wp-login", "/oauth", "/auth")):
            marks.add("auth")
        if any(x in low_url for x in ("/wp-admin", "/admin/", "/administrator")):
            marks.add("auth")

        # Directory listing
        if "index of /" in body_low or ("text/html" in ct and "<title>index of /" in body_low):
            marks.add("dirlist")

        # Metodi pericolosi
        if any(m in allow for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND")):
            marks.add("weak-headers")

        return marks
    except Exception:
        return marks

def compute_risk_score(row, kb=None) -> float:
    """
    Punteggio 0..1 KB-aware e calibrabile.
    Usa pesi di default ma consente override via KB:
      kb = {
        "weights": {
          "status_5xx":0.55,"status_4xx":0.35,"status_2xx":0.10,"status_other":0.05,
          "latency":0.20, "ctype_html_json":0.10, "ctype_text":0.05, "ctype_other":0.02,
          "sec_missing_per":0.03, "sec_missing_cap":0.12,
          "waf_vendor":0.06, "env_discount":0.10
        },
        "flag_weights": {"SQLI":0.35,"XSS":0.25,"SSRF":0.35,"RCE":0.50,"DIR":0.15,"WEAKHDRS":0.08,"CB_OPEN":0.05,"BYP":0.05},
        "family_weights": {"AUTH":0.15,"API":0.10,"ADMIN":0.12,"STATIC":0.02,"GENERIC":0.05},
        "waf_vendor_weights": {"Cloudflare":0.04,"Akamai":0.04,"Imperva":0.05,"F5":0.04,"AWS":0.04,"Azure WAF":0.04,"Sucuri":0.04},
        "lat_ref_ms": 3000,
        "sensitive_paths": [r"/admin\b", r"/wp-admin\b", r"/manage\b"],
        "dangerous_params": {"token":{"weight":0.15}, "redirect":{"weight":0.12}, "id":{"weight":0.08}},
      }
    """
    kb = kb or {}
    W = {
        "status_5xx":0.55,"status_4xx":0.35,"status_2xx":0.10,"status_other":0.05,
        "latency":0.20, "ctype_html_json":0.10, "ctype_text":0.05, "ctype_other":0.02,
        "sec_missing_per":0.03, "sec_missing_cap":0.12,
        "waf_vendor":0.06, "env_discount":0.10
    }
    W.update(kb.get("weights") or {})

    FLAG_W = {
        "SQLI":0.35,"XSS":0.25,"SSRF":0.35,"RCE":0.50,"DIR":0.15,"WEAKHDRS":0.08,"CB_OPEN":0.05,"BYP":0.05
    }
    FLAG_W.update(kb.get("flag_weights") or {})

    FAM_W = {"AUTH":0.15,"API":0.10,"ADMIN":0.12,"STATIC":0.02,"GENERIC":0.05}
    FAM_W.update(kb.get("family_weights") or {})

    WAF_W = {"Cloudflare":0.04,"Akamai":0.04,"Imperva":0.05,"F5":0.04,"AWS":0.04,"Azure WAF":0.04,"Sucuri":0.04}
    WAF_W.update(kb.get("waf_vendor_weights") or {})

    lat_ref = float(kb.get("lat_ref_ms", 3000) or 3000)

    try:
        status = row.get("status")
        lat_ms = float(row.get("latency_ms") or 0.0)
        ctype = (row.get("content_type_final") or "").lower()
        flags = [str(x).upper() for x in (row.get("flags") or [])]
        sec = row.get("security_headers") or {}
        missing = [str(x).lower() for x in (sec.get("missing") or [])]
        wafs = row.get("waf_vendors") or []
        family = (row.get("family") or "").upper()
        url = row.get("url") or ""
    except Exception:
        status, lat_ms, ctype, flags, missing, wafs, family, url = None, 0.0, "", [], [], [], "", ""

    score = 0.0

    # Status
    if isinstance(status, int):
        if 500 <= status <= 599:
            score += W["status_5xx"]
        elif 400 <= status <= 499:
            score += W["status_4xx"]
        elif 200 <= status <= 299:
            score += W["status_2xx"]
        else:
            score += W["status_other"]

    # Latenza (clamp 0..1 su lat_ref) * weight
    if lat_ref <= 0: lat_ref = 3000.0
    score += min(1.0, max(0.0, lat_ms / lat_ref)) * W["latency"]

    # Content-Type
    if "application/json" in ctype or "text/html" in ctype or "html" in ctype or "json" in ctype:
        score += W["ctype_html_json"]
    elif "text" in ctype:
        score += W["ctype_text"]
    else:
        score += W["ctype_other"]

    # Security headers mancanti
    score += min(W["sec_missing_cap"], W["sec_missing_per"] * len(missing))

    # Flags pesate
    for f in flags:
        if f.startswith("ENV:"):
            continue
        score += float(FLAG_W.get(f, 0.0))

    # Ambiente di test/qa → sconto
    if any(f.startswith("ENV:") for f in flags):
        score -= float(W["env_discount"])

    # WAF vendor (leggero boost: superficie “protetta ma sensibile”)
    for v in (wafs or []):
        score += float(WAF_W.get(str(v), 0.0))

    # Family
    score += float(FAM_W.get(family, 0.0))

    # Sensitive paths (KB)
    import re
    for pat in (kb.get("sensitive_paths") or []):
        try:
            if re.search(pat, url):
                score += 0.06
        except Exception:
            pass

    # Dangerous params (KB)
    dp = kb.get("dangerous_params") or {}
    q = ""
    try:
        from urllib.parse import urlsplit
        q = urlsplit(url).query
    except Exception:
        q = ""
    if q:
        from urllib.parse import parse_qsl
        for name, _ in parse_qsl(q, keep_blank_values=True):
            info = dp.get(name)
            if isinstance(info, dict):
                score += float(info.get("weight", 0.0))

    # Clamp
    return max(0.0, min(1.0, score))


def score_reasons(row) -> list[str]:
    """
    Motivi sintetici coordinati con lo score.
    """
    out = []
    st = row.get("status")
    if isinstance(st, int):
        if 500 <= st <= 599:
            out.append("Server error 5xx")
        elif 400 <= st <= 499:
            out.append("Client error 4xx")

    lat_ms = float(row.get("latency_ms") or 0.0)
    if lat_ms >= 2000:
        out.append("Slow (>2s)")

    sec = row.get("security_headers") or {}
    missing = [str(x).upper() for x in (sec.get("missing") or [])]
    if missing:
        out.append("Weak headers: " + ",".join(sorted(set(missing))[:4]))

    flags = [str(x).upper() for x in (row.get("flags") or [])]
    for k in ("XSS", "SQLI", "SSRF", "DIR", "CB_OPEN", "WEAKHDRS", "BYP"):
        if k in flags:
            out.append(k)

    if not out:
        out.append("Heuristics")
    return out


# --------------------------------------------------------------------------- #
# Action model                                                                #
# --------------------------------------------------------------------------- #

@dataclass
class Action:
    type: str                     # "STOP" | "ENRICH" | "AI" | "PAYLOAD"
    family: Optional[str] = None  # "XSS" | "SQLI" | "IDOR" | "SSRF" | "UPLOAD" | "AUTH" | "REDIRECT" | "TRAVERSAL" | "CORS" | "GENERIC"
    waf_bypass: bool = False
    reason: str = ""
    score: float = 0.0
    archetype: Optional[str] = None
    gated: bool = True            # True se l’azione rispetta il gating Top-K (se applicato)

# --------------------------------------------------------------------------- #
# Knowledge base (default)                                                    #
# --------------------------------------------------------------------------- #

_DEFAULT_KNOWLEDGE: Dict[str, Any] = {
    "thresholds": {
        # soglie base (profile=standard). Light alza, Deep abbassa.
        "enrich": 0.35,
        "ai": 0.60,
        "payload_hint": 0.45,
        "waf_bypass_repeats": 2,     # ripetizioni di blocco WAF nella finestra recente
        "waf_bypass_max_iters": 2,   # max iterazioni con bypass
        "improve_delta_score": 0.05, # miglioramento minimo di “score” per mantenere il bypass
    },
    "weights": {
        # contributi (0..1) al punteggio grezzo
        "waf": 0.20,
        "params": 0.10,
        "err5xx": 0.40,
        "err4xx": 0.15,        # applicato solo se utile (es. 401/403/429 più rilevanti di 404)
        "json_api": 0.10,      # API / JSON → test mirati
        "login": 0.10,
        "upload": 0.20,
        "search": 0.05,
        "redirects": 0.05,     # catene redirect → interessante
        "latency_norm": 0.10,  # latenze alte → filtri/server-side complessi
    },
    "families": {
        # mapping euristico archetipi → famiglie
        "login": "AUTH",
        "upload": "UPLOAD",
        "search": "XSS",
        "api": "IDOR",     # spesso IDOR/logic
        "json": "SQLI",    # input “query-like”
        "generic": "GENERIC",
    },
    "family_thresholds": {
        # delta alle soglie per famiglia (applicati su payload_hint; clamp 0..1)
        # negativi = più aggressivo, positivi = più conservativo
        "XSS":       {"payload_hint": -0.05},
        "IDOR":      {"payload_hint": +0.05},
        "REDIRECT":  {"payload_hint": -0.05},
        "TRAVERSAL": {"payload_hint": -0.05},
        "CORS":      {"payload_hint": +0.05},
        "SQLI":      {"payload_hint": +0.00},
        "UPLOAD":    {"payload_hint": -0.02},
        "AUTH":      {"payload_hint": +0.03},
        "GENERIC":   {"payload_hint": +0.00},
    },
    "interesting_4xx": [401, 403, 405, 406, 415, 422, 429],
    "max_history_window": 8,
}

# --------------------------------------------------------------------------- #
# Helpers: estrazione segnali dal risultato sonda                             #
# --------------------------------------------------------------------------- #

def _safe_get(d: Dict[str, Any], path: Sequence[str], default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def _extract_signals(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Estrae segnali neutrali dal record sonda (shape compat con probe_smuggle).
    """
    url = str(scan_result.get("url", ""))
    u = urlparse(url)
    q = parse_qsl(u.query, keep_blank_values=True)
    param_names = [k.lower() for (k, _v) in q]

    g = scan_result.get("get") or {}
    status = int(g.get("status") or 0)
    latency_ms = int(g.get("latency_ms") or 0)
    size = int(g.get("size") or 0)
    ctype = (g.get("content_type") or "").lower()
    waf = bool(g.get("waf") or False)
    redirects = len(g.get("redirect_chain") or [])

    path_lower = (u.path or "").lower()
    flags = {str(x).lower() for x in (scan_result.get("flags") or [])}

    is_login  = any(t in path_lower for t in ("/login", "/signin", "auth", "oauth")) or "login" in flags
    is_upload = any(t in path_lower for t in ("/upload", "/media", "/file")) or "upload" in flags
    is_search = any(t in path_lower for t in ("/search", "q=")) or "search" in flags
    is_api    = "/api/" in path_lower or "application/json" in ctype or "api" in flags

    # indizi SQLi-like (benigni)
    p_ind_sql = 0
    if q:
        if any(p in param_names for p in ("id", "user_id", "uid", "product_id", "order", "sort")):
            p_ind_sql += 1
        if any("'" in v or '"' in v for _, v in q):
            p_ind_sql += 1
        if any(re.fullmatch(r"\d+", v or "") for _, v in q):
            p_ind_sql += 1

    looks_json = ("application/json" in ctype) or is_api

    return {
        "url": url,
        "host": u.netloc.lower(),
        "status": status,
        "latency_ms": latency_ms,
        "size": size,
        "content_type": ctype,
        "waf": waf,
        "redirects": redirects,
        "param_count": len(q),
        "param_names": param_names,
        "p_ind_sql": p_ind_sql,
        "is_login": is_login,
        "is_upload": is_upload,
        "is_search": is_search,
        "is_api": is_api,
        "looks_json": looks_json,
        "flags": flags,
    }

def _compute_score(sig: Dict[str, Any], kb: Dict[str, Any]) -> Tuple[float, str]:
    w = kb.get("weights", _DEFAULT_KNOWLEDGE["weights"])
    interesting_4xx = set(kb.get("interesting_4xx", _DEFAULT_KNOWLEDGE["interesting_4xx"]))
    score = 0.0
    reasons: List[str] = []

    if 500 <= sig["status"] <= 599:
        score += w["err5xx"]; reasons.append("5xx")
    if sig["status"] in interesting_4xx:
        score += w["err4xx"] * 0.8; reasons.append(f"4xx:{sig['status']}")
    if sig["waf"] or ("waf" in sig["flags"]) or ("blocked" in sig["flags"]):
        score += w["waf"]; reasons.append("WAF?")
    if sig["redirects"] >= 2:
        score += w["redirects"] * min(1.0, sig["redirects"] / 5.0); reasons.append("redirects")
    if sig["param_count"] > 0:
        score += w["params"] * min(1.0, sig["param_count"] / 6.0); reasons.append("params")
    if sig["is_login"]:
        score += w["login"]; reasons.append("login")
    if sig["is_upload"]:
        score += w["upload"]; reasons.append("upload")
    if sig["is_search"]:
        score += w["search"]; reasons.append("search")
    if sig["looks_json"]:
        score += w["json_api"]; reasons.append("api/json")
    if sig["latency_ms"] >= 800:
        score += w["latency_norm"]; reasons.append("slow")

    score = max(0.0, min(1.0, score))
    return score, "+".join(reasons) if reasons else "baseline"

def _derive_archetype(sig: Dict[str, Any]) -> str:
    if sig["is_upload"]:
        return "upload"
    if sig["is_login"]:
        return "login"
    if sig["is_search"]:
        return "search"
    if sig["is_api"]:
        return "api"
    return "generic"

def _profile_thresholds(profile: str, kb: Dict[str, Any]) -> Dict[str, float]:
    thr = dict(kb.get("thresholds", _DEFAULT_KNOWLEDGE["thresholds"]))
    if profile == "light":
        for k in thr: thr[k] = float(min(1.0, thr[k] * 1.10))
    elif profile == "deep":
        for k in thr: thr[k] = float(max(0.0, thr[k] * 0.90))
    return thr

def _apply_family_thresholds(base_thr: Dict[str, float], family: str, kb: Dict[str, Any]) -> Dict[str, float]:
    out = dict(base_thr)
    fam = (family or "GENERIC").upper()
    delta = (kb.get("family_thresholds") or {}).get(fam, {})
    if "payload_hint" in delta:
        out["payload_hint"] = float(min(1.0, max(0.0, out["payload_hint"] + float(delta["payload_hint"]))))
    return out

def _decide_family(sig: Dict[str, Any], kb: Dict[str, Any]) -> Tuple[str, str]:
    arche = _derive_archetype(sig)
    fam_map = kb.get("families", _DEFAULT_KNOWLEDGE["families"])
    reason = f"archetype:{arche}"

    # Affinamento su indizi SQL-like
    if arche in ("api", "generic") and sig.get("p_ind_sql", 0) >= 2:
        return "SQLI", reason + "+params_sqlish"
    if arche == "api" and sig["looks_json"]:
        return fam_map.get("api", "GENERIC"), reason + "+json"
    if arche == "search":
        return fam_map.get("search", "XSS"), reason
    if arche == "upload":
        return fam_map.get("upload", "UPLOAD"), reason
    if arche == "login":
        return fam_map.get("login", "AUTH"), reason
    if "json" in fam_map and sig["looks_json"]:
        return fam_map["json"], reason + "+json"
    return fam_map.get("generic", "GENERIC"), reason

# --------------------------------------------------------------------------- #
# Gating Top-K                                                                #
# --------------------------------------------------------------------------- #

def _rank_for_gate(rec: Dict[str, Any]) -> float:
    """
    Punteggio per gating: score + bonus flags/WAF.
    """
    s = float(rec.get("score") or 0.0)
    flags = {str(x).lower() for x in (rec.get("flags") or [])}
    if "waf?" in flags or "waf" in flags:
        s += 0.06
    if "err" in flags:
        s += 0.04
    if "warn" in flags:
        s += 0.02
    return max(0.0, min(1.2, s))

def select_topk_for_ai(results: List[Dict[str, Any]], k: int = 20, min_score: float = 0.35) -> List[str]:
    """
    Restituisce la lista di URL ammessi a passi “costosi” (AI/bypass),
    ordinati per rank. Applica una soglia di sicurezza min_score.
    """
    ranked = sorted((r for r in results or []), key=_rank_for_gate, reverse=True)
    out: List[str] = []
    for r in ranked:
        if len(out) >= max(1, int(k)):
            break
        s = float(r.get("score") or 0.0)
        if s >= float(min_score):
            out.append(str(r.get("url") or ""))
    return [u for u in out if u]

# --------------------------------------------------------------------------- #
# WAF bypass policy (“due colpi” con miglioramento)                           #
# --------------------------------------------------------------------------- #

def _improved_after_bypass(history: List[Dict[str, Any]], improve_delta: float) -> bool:
    """
    Valuta se l’ultimo tentativo con bypass ha migliorato la situazione.
    Criteri (any):
      - status passa a 2xx/3xx
      - score aumenta di >= improve_delta
      - latenza diminuisce del 10%+
      - size aumenta del 10%+ (più contenuto → meno blocco)
    """
    # Trova ultimi due eventi rilevanti
    post = None
    pre = None
    for ev in reversed(history):
        if ev.get("waf_bypass_used"):
            post = ev
            break
    if not post:
        return False
    # cerca un evento precedente “comparable”
    for ev in reversed(history):
        if ev is post:
            continue
        pre = ev
        break
    if not pre:
        return False

    # status
    st_post = _safe_get(post, ["response", "status"], post.get("status"))
    if isinstance(st_post, int) and 200 <= st_post < 400:
        return True

    # score
    sc_post = float(post.get("score") or 0.0)
    sc_pre  = float(pre.get("score") or 0.0)
    if (sc_post - sc_pre) >= float(improve_delta):
        return True

    # latenza ↓
    lat_post = _safe_get(post, ["response", "latency_ms"], post.get("latency_ms") or 0)
    lat_pre  = _safe_get(pre,  ["response", "latency_ms"], pre.get("latency_ms") or 0)
    try:
        if lat_pre and isinstance(lat_pre, (int, float)) and isinstance(lat_post, (int, float)):
            if (float(lat_pre) - float(lat_post)) / float(lat_pre) >= 0.10:
                return True
    except Exception:
        pass

    # size ↑
    sz_post = _safe_get(post, ["response", "size"], post.get("size") or 0)
    sz_pre  = _safe_get(pre,  ["response", "size"], pre.get("size") or 0)
    try:
        if sz_pre and isinstance(sz_pre, (int, float)) and isinstance(sz_post, (int, float)):
            if (float(sz_post) - float(sz_pre)) / float(sz_pre) >= 0.10:
                return True
    except Exception:
        pass

    return False

def should_apply_waf_bypass(
    flags: Sequence[str] | set[str],
    history: List[Dict[str, Any]],
    *,
    knowledge: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    True SOLO se:
      1) segnali WAF ripetuti nella finestra recente (>= soglia), e
      2) numero di iterazioni bypass < max_iters, e
      3) se c’è già stato un tentativo, ha migliorato qualcosa (altrimenti si ferma).
    """
    kb = knowledge or _DEFAULT_KNOWLEDGE
    thr_repeats = int(kb.get("thresholds", {}).get("waf_bypass_repeats", _DEFAULT_KNOWLEDGE["thresholds"]["waf_bypass_repeats"]))
    max_iters   = int(kb.get("thresholds", {}).get("waf_bypass_max_iters", _DEFAULT_KNOWLEDGE["thresholds"]["waf_bypass_max_iters"]))
    improve_d   = float(kb.get("thresholds", {}).get("improve_delta_score", _DEFAULT_KNOWLEDGE["thresholds"]["improve_delta_score"]))
    max_win     = int(kb.get("max_history_window", _DEFAULT_KNOWLEDGE["max_history_window"]))

    fl_now = {str(x).lower() for x in (flags or [])}
    waf_now = ("waf" in fl_now) or ("blocked" in fl_now) or ("waf?" in fl_now)

    # Conta eventi con segnali WAF nella finestra
    waf_count = 1 if waf_now else 0
    bypass_tries = 0
    recent = history[-max_win:] if history else []
    for ev in reversed(recent):
        try:
            ev_flags = {str(x).lower() for x in (ev.get("flags") or [])}
            waf_sig = ev.get("waf_blocked") or ("waf" in ev_flags) or ("blocked" in ev_flags) or ("waf?" in ev_flags)
            if waf_sig:
                waf_count += 1
            if ev.get("waf_bypass_used"):
                bypass_tries += 1
        except Exception:
            continue

    if waf_count < thr_repeats:
        return False
    if bypass_tries >= max_iters:
        return False
    if bypass_tries >= 1:
        # consenti il secondo colpo solo se c’è stato miglioramento
        return _improved_after_bypass(recent, improve_d)
    return True

# --------------------------------------------------------------------------- #
# Decisione principale                                                        #
# --------------------------------------------------------------------------- #

def _budget_exhausted(budget: Optional[Dict[str, Any]]) -> bool:
    if not budget:
        return False
    max_req = budget.get("max_requests")
    spent = budget.get("spent_requests")
    if isinstance(max_req, int) and isinstance(spent, int) and spent >= max_req > 0:
        return True
    deadline_s = budget.get("deadline_s") or budget.get("max_time_s")
    started = budget.get("started_at_ts")
    if isinstance(deadline_s, (int, float)) and isinstance(started, (int, float)):
        if (time.time() - started) >= float(deadline_s) > 0:
            return True
    return False

def decide_next_action(
    scan_result: Dict[str, Any],
    memory: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    profile: str = "standard",
    budget: Optional[Dict[str, Any]] = None,
    knowledge: Optional[Dict[str, Any]] = None,
    *,
    heavy_gate_allowlist: Optional[Sequence[str]] = None,  # se passato, limita AI/PAYLOAD a questi URL
) -> Action:
    """
    Ritorna un'Action deterministica basata su:
      - segnali sonda (status, params, WAF, archetipi, ecc.)
      - profilo (light/standard/deep) → soglie diverse
      - budget (STOP se esaurito)
      - knowledge base (pesi/soglie/famiglie)
      - memoria temporale (history per WAF “due colpi”)
      - gating Top-K (se heavy_gate_allowlist è passato)
    """
    kb = dict(_DEFAULT_KNOWLEDGE)
    if knowledge:
        for k, v in knowledge.items():
            if isinstance(v, dict) and k in kb and isinstance(kb[k], dict):
                kb[k].update(v)
            else:
                kb[k] = v

    if _budget_exhausted(budget):
        return Action(type="STOP", reason="budget_exhausted")

    sig = _extract_signals(scan_result)
    base_thr = _profile_thresholds(profile, kb)
    score, reason = _compute_score(sig, kb)
    arche = _derive_archetype(sig)

    # Famiglia consigliata + soglia per famiglia
    fam, fam_reason = _decide_family(sig, kb)
    fam_thr = _apply_family_thresholds(base_thr, fam, kb)

    # Gating Top-K (se fornito)
    url = sig["url"]
    gated_ok = True
    if heavy_gate_allowlist is not None:
        allow = {str(u) for u in heavy_gate_allowlist}
        gated_ok = url in allow

    # LIGHT: solo ENRICH se sopra soglia
    if profile == "light":
        if score >= base_thr["enrich"]:
            return Action(type="ENRICH", reason=f"{reason}>=enrich", score=score, archetype=arche, gated=True)
        return Action(type="STOP", reason=f"{reason}<enrich", score=score, archetype=arche, gated=True)

    # WAF bypass policy (due colpi)
    hist = (memory or {}).get(url, []) if memory else []
    waf_b = should_apply_waf_bypass(scan_result.get("flags") or [], hist, knowledge=kb)

    # PAYLOAD (family) se sopra soglia dedicata
    if score >= fam_thr["payload_hint"]:
        if gated_ok:
            return Action(
                type="PAYLOAD",
                family=fam,
                waf_bypass=waf_b,
                reason=f"{reason}|{fam_reason}>=payload_hint({fam})",
                score=score,
                archetype=arche,
                gated=True,
            )
        # gated non consente: fallback ENRICH/STOP
        if score >= base_thr["enrich"]:
            return Action(type="ENRICH", reason=f"gated_block|{reason}", score=score, archetype=arche, gated=False)
        return Action(type="STOP", reason=f"gated_block|{reason}", score=score, archetype=arche, gated=False)

    # AI se sopra soglia AI
    if score >= base_thr["ai"]:
        if gated_ok:
            return Action(type="AI", waf_bypass=waf_b, reason=f"{reason}>=ai", score=score, archetype=arche, gated=True)
        if score >= base_thr["enrich"]:
            return Action(type="ENRICH", reason=f"gated_block|{reason}", score=score, archetype=arche, gated=False)
        return Action(type="STOP", reason=f"gated_block|{reason}", score=score, archetype=arche, gated=False)

    # ENRICH se sopra soglia enrich
    if score >= base_thr["enrich"]:
        return Action(type="ENRICH", reason=f"{reason}>=enrich", score=score, archetype=arche, gated=True)

    # STOP
    return Action(type="STOP", reason=f"{reason}<enrich", score=score, archetype=arche, gated=True)

# --------------------------------------------------------------------------- #
# Convenienze: applicare gating su batch                                      #
# --------------------------------------------------------------------------- #

def build_heavy_gate_allowlist(
    results: List[Dict[str, Any]],
    profile: str = "standard",
    knowledge: Optional[Dict[str, Any]] = None,
    *,
    top_k_ratio: float = 0.25,
    min_cap: int = 10,
    max_cap: int = 100,
) -> List[str]:
    """
    Crea una allowlist di URL per operazioni “pesanti” (AI / BYP / fuzz extra):
      - classifica per _rank_for_gate()
      - seleziona top_k_ratio * N, clamp [min_cap, max_cap]
      - richiede score >= soglia enrich del profilo
    """
    kb = dict(_DEFAULT_KNOWLEDGE)
    if knowledge:
        for k, v in knowledge.items():
            if isinstance(v, dict) and k in kb and isinstance(kb[k], dict):
                kb[k].update(v)
            else:
                kb[k] = v
    thr = _profile_thresholds(profile, kb)
    n = len(results or [])
    k = max(min_cap, min(max_cap, int(math.ceil((top_k_ratio or 0.25) * n))))
    ranked = sorted((r for r in results or []), key=_rank_for_gate, reverse=True)
    allow: List[str] = []
    for r in ranked:
        if len(allow) >= k:
            break
        s = float(r.get("score") or 0.0)
        if s >= thr["enrich"]:
            u = str(r.get("url") or "")
            if u:
                allow.append(u)
    return allow

# ======================== SEZIONE NUOVA: KB Param → Famiglia =================
# Loader YAML + classifier + helpers (additivo, opzionale)
# ============================================================================

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

_KB_CACHE: Dict[str, Any] = {}
_KB_MTIME: Optional[float] = None
_KB_PATH_DEFAULT = "kb_param_families.yaml"

_FAMILY_KEYS_ORDER = [
    "XSS", "SQLI", "NOSQLI", "IDOR", "REDIRECT", "TRAVERSAL", "XXE_SAFE", "SSRF_SAFE",
    "JSONP", "CORS", "MASS_ASSIGNMENT", "AUTH", "CSRF", "UPLOAD", "HEADER_INJECTION",
    "CACHE", "DESERIALIZATION", "GRAPHQL", "SSTI", "PROTO_POLLUTION", "RCE_HINT",
    "RATE_LIMIT", "FEATURE_FLAG", "OBSERVABILITY", "LOCALE", "TRACKING", "GENERIC"
]

def _stat_mtime(path: str) -> Optional[float]:
    try:
        import os
        st = os.stat(path)
        return float(getattr(st, "st_mtime", 0.0))
    except Exception:
        return None

def load_param_families(path: Optional[str] = None, *, force_reload: bool = False) -> Dict[str, Any]:
    """
    Carica la KB YAML 'kb_param_families.yaml' con caching. Se PyYAML non c'è,
    ritorna struttura minima con default GENERIC.
    """
    global _KB_CACHE, _KB_MTIME
    kb_path = path or _KB_PATH_DEFAULT

    if yaml is None:
        return _KB_CACHE or {
            "meta": {"default_family": "GENERIC", "match_order": ["exact", "regex", "substring"]},
            "exact": {}, "regex": [], "substring": [], "composite": [], "context_overrides": {},
            "value_hints": {}, "bypass_hints": {}, "noise": {"low_value_params": []}, "families_legend": {}
        }

    mtime = _stat_mtime(kb_path)
    if (not _KB_CACHE) or force_reload or (_KB_MTIME is None) or (mtime and _KB_MTIME and mtime > _KB_MTIME):
        try:
            with open(kb_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            data.setdefault("exact", {})
            data.setdefault("regex", [])
            data.setdefault("substring", [])
            data.setdefault("composite", [])
            data.setdefault("context_overrides", {})
            data.setdefault("value_hints", {})
            data.setdefault("bypass_hints", {})
            data.setdefault("noise", {"low_value_params": []})
            meta = data.setdefault("meta", {})
            meta.setdefault("match_order", ["exact", "regex", "substring"])
            meta.setdefault("default_family", "GENERIC")
            fl = data.get("meta", {}).get("families_legend") or data.get("families_legend") or {}
            if fl:
                ordered = {k: fl[k] for k in _FAMILY_KEYS_ORDER if k in fl}
                for k, v in fl.items():
                    if k not in ordered:
                        ordered[k] = v
                data["families_legend"] = ordered
            _KB_CACHE = data
            _KB_MTIME = mtime or time.time()
        except Exception:
            _KB_CACHE = {
                "meta": {"default_family": "GENERIC", "match_order": ["exact", "regex", "substring"]},
                "exact": {}, "regex": [], "substring": [], "composite": [], "context_overrides": {},
                "value_hints": {}, "bypass_hints": {}, "noise": {"low_value_params": []}, "families_legend": {}
            }
            _KB_MTIME = None
    return _KB_CACHE

def families_legend(path: Optional[str] = None) -> Dict[str, str]:
    kb = load_param_families(path)
    return kb.get("families_legend") or kb.get("meta", {}).get("families_legend") or {}

def value_hints(path: Optional[str] = None) -> Dict[str, str]:
    kb = load_param_families(path)
    return kb.get("value_hints") or {}

def bypass_hints(path: Optional[str] = None) -> Dict[str, Any]:
    kb = load_param_families(path)
    return kb.get("bypass_hints") or {}

def is_noise_param(name: str, path_yaml: Optional[str] = None) -> bool:
    kb = load_param_families(path_yaml)
    lows = set((kb.get("noise") or {}).get("low_value_params") or [])
    return name.lower() in {s.lower() for s in lows}

_REGEX_CACHE: Dict[str, Any] = {}

def _cached_re(pattern: str, flags: int = re.IGNORECASE):
    key = f"{pattern}::{flags}"
    rx = _REGEX_CACHE.get(key)
    if rx is None:
        rx = re.compile(pattern, flags)
        _REGEX_CACHE[key] = rx
    return rx

def _match_exact(name: str, exact: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not exact:
        return None
    low = name.lower()
    for k, v in exact.items():
        if low == k.lower():
            return {"family": v.get("family", "GENERIC"), "priority": v.get("priority", 10),
                    "confidence": v.get("confidence", "low"), "source": "exact", "raw": v}
    return None

def _match_regex(name: str, rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for rule in rules or []:
        pat = rule.get("pattern")
        if not pat:
            continue
        rx = _cached_re(pat)
        if rx.match(name):
            return {"family": rule.get("family", "GENERIC"), "priority": rule.get("priority", 10),
                    "confidence": rule.get("confidence", "low"), "source": "regex", "raw": rule}
    return None

def _match_substring(name: str, rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    low = name.lower()
    for rule in rules or []:
        contains = (rule.get("contains") or "").lower()
        if contains and contains in low:
            return {"family": rule.get("family", "GENERIC"), "priority": rule.get("priority", 10),
                    "confidence": rule.get("confidence", "low"), "source": "substring", "raw": rule}
    return None

def _apply_context_overrides(match: Dict[str, Any], kb: Dict[str, Any], *, path: Optional[str], ctype: Optional[str], engine_hint: Optional[str]) -> Dict[str, Any]:
    out = dict(match or {})
    ctx = kb.get("context_overrides") or {}

    for rule in (ctx.get("by_path_regex") or []):
        pat = rule.get("pattern")
        if pat and path:
            rx = _cached_re(pat)
            if rx.search(path):
                out["family"] = rule.get("prefer_family", out.get("family"))
                out["priority"] = int(out.get("priority", 10)) + int(rule.get("add_priority", 0))

    c_map = ctx.get("by_content_type") or {}
    if ctype:
        for c_key, c_rule in c_map.items():
            if c_key.lower() == ctype.lower():
                out["family"] = c_rule.get("prefer_family", out.get("family"))
                out["priority"] = int(out.get("priority", 10)) + int(c_rule.get("add_priority", 0))

    t_map = ctx.get("by_template_engine_hint") or {}
    if engine_hint and t_map:
        for pat, t_rule in t_map.items():
            rx = _cached_re(pat)
            if rx.search(engine_hint):
                out["family"] = t_rule.get("prefer_family", out.get("family"))
                out["priority"] = int(out.get("priority", 10)) + int(t_rule.get("add_priority", 0))
    return out

def classify_param(
    name: str,
    *,
    path_hint: Optional[str] = None,
    content_type_hint: Optional[str] = None,
    engine_hint: Optional[str] = None,
    kb_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Classifica un *parametro singolo* in una famiglia (XSS/SQLI/IDOR/...).
    Ordine: exact > regex > substring. Applica context overrides.
    """
    kb = load_param_families(kb_path)
    order = (kb.get("meta") or {}).get("match_order") or ["exact", "regex", "substring"]
    exact = kb.get("exact") or {}
    regex_rules = kb.get("regex") or []
    substr_rules = kb.get("substring") or []

    match: Optional[Dict[str, Any]] = None
    for stage in order:
        if stage == "exact":
            match = _match_exact(name, exact)
        elif stage == "regex":
            match = _match_regex(name, regex_rules)
        elif stage == "substring":
            match = _match_substring(name, substr_rules)
        if match:
            break
    if not match:
        match = {"family": (kb.get("meta") or {}).get("default_family", "GENERIC"),
                 "priority": (kb.get("meta") or {}).get("default_priority", 10),
                 "confidence": "low", "source": "default"}

    match = _apply_context_overrides(match, kb, path=path_hint, ctype=content_type_hint, engine_hint=engine_hint)
    return match

def classify_params_for_url(
    url: str,
    *,
    content_type_hint: Optional[str] = None,
    engine_hint: Optional[str] = None,
    kb_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analizza l'URL, classifica *tutti i parametri* e applica regole composite.
    Ritorna:
    {
      "url": ...,
      "param_families": [{"param":"id","family":"IDOR","priority":98,"confidence":"high"}, ...],
      "vuln_hints": {"IDOR": 3, "XSS": 2, ...}
    }
    """
    u = urlparse(url or "")
    params = parse_qsl(u.query, keep_blank_values=True)
    kb = load_param_families(kb_path)

    param_families: List[Dict[str, Any]] = []
    family_counts: Dict[str, int] = {}

    for k, _ in params:
        cl = classify_param(k, path_hint=u.path or "/", content_type_hint=content_type_hint, engine_hint=engine_hint, kb_path=kb_path)
        entry = {"param": k, **cl}
        param_families.append(entry)
        fam = cl.get("family", "GENERIC")
        family_counts[fam] = family_counts.get(fam, 0) + 1

    names_lower = [k.lower() for k, _ in params]
    c_rules = kb.get("composite") or []
    for rule in c_rules:
        if "when_all" in rule:
            needs = [s.lower() for s in (rule.get("when_all") or [])]
            if all(n in names_lower for n in needs):
                fam = rule.get("raise_family_to")
                addp = int(rule.get("add_priority", 0))
                if fam:
                    family_counts[fam] = family_counts.get(fam, 0) + 1
                for pf in param_families:
                    if pf.get("param", "").lower() in needs:
                        pf["priority"] = int(pf.get("priority", 10)) + addp
        elif "when_any" in rule:
            needs = [s.lower() for s in (rule.get("when_any") or [])]
            fam = rule.get("also_mark")
            addp = int(rule.get("add_priority", 0))
            if any(n in names_lower for n in needs):
                if fam:
                    family_counts[fam] = family_counts.get(fam, 0) + 1
                for pf in param_families:
                    if pf.get("param", "").lower() in needs:
                        pf["priority"] = int(pf.get("priority", 10)) + addp

    noise_low = set((kb.get("noise") or {}).get("low_value_params") or [])
    for pf in param_families:
        if pf.get("param", "").lower() in {s.lower() for s in noise_low}:
            pf["priority"] = max(1, int(pf.get("priority", 10)) - 20)

    return {
        "url": url,
        "param_families": param_families,
        "vuln_hints": family_counts
    }

def families_for_params(params: Iterable[str], *, path_hint: str = "/", kb_path: Optional[str] = None) -> Dict[str, int]:
    """
    Utility leggera: dato un iterable di nomi param, mappa le famiglie e restituisce conteggi.
    """
    kb = load_param_families(kb_path)
    counts: Dict[str, int] = {}
    for name in params:
        cl = classify_param(name, path_hint=path_hint, kb_path=kb_path)
        fam = cl.get("family", (kb.get("meta") or {}).get("default_family", "GENERIC"))
        counts[fam] = counts.get(fam, 0) + 1
    return counts

def top_families(vuln_hints: Dict[str, int], top_n: int = 3) -> List[Tuple[str, int]]:
    """
    Restituisce le famiglie più presenti (per riepilogo CLI).
    """
    def _ord_key(item: Tuple[str, int]) -> Tuple[int, int]:
        fam, cnt = item
        try:
            idx = _FAMILY_KEYS_ORDER.index(fam)
        except ValueError:
            idx = 999
        return (-cnt, idx)

    return sorted((vuln_hints or {}).items(), key=_ord_key)[:max(1, top_n)]
# ============================== FINE SEZIONE KB ==============================
