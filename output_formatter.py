# output_formatter.py — Renderer ASCII (paginato)
# Obiettivi:
# - Larghezze fisse per colonna
# - Ellissi a parole (mai spezzare a metà parola)
# - Join corretto per liste: waf = "Akamai|Cloudflare", flags = "+AI|+DNS"
# - Allineamenti: numeri a destra; testi a sinistra
# - Footer compatto con legenda WAF/FLAGS (2 righe max)
# - CSV opzionale perfetto: quoting standard (QUOTE_ALL), celle vuote = ""

from __future__ import annotations

import math
import re
import csv
from io import StringIO
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlparse, parse_qsl


import importlib, traceback
try:
    of = importlib.import_module("output_formatter")

except Exception:
    traceback.print_exc()
# === BLOCCO 1/2 Helper (DA INCOLLARE SOPRA) ===

def format_score_percent(score):
    try:
        if score is None:
            return "—"
        val = float(score) * 100.0
        return f"{val:.1f}%" if (val % 1) else f"{int(val)}%"
    except Exception:
        return "—"

def badge_flags(flags):
    """
    Ordina e compatta le FLAGS in badge ad alto impatto visivo.
    Ordine: XSS, SQLI, IDOR, AUTH, CORS, OPENREDIR, SSRF, TPL, WEAKHDRS, DIR
    """
    if not flags:
        return []
    order = ["XSS","SQLI","IDOR","AUTH","CORS","OPENREDIR","SSRF","TPL","WEAKHDRS","DIR"]
    fs = [f.upper() for f in (flags if isinstance(flags, (list, set, tuple)) else [flags])]
    uniq = []
    for k in order:
        if k in fs:
            uniq.append(k)
    for f in fs:
        if f not in uniq:
            uniq.append(f)
    return uniq

def render_reasons(reasons):
    """Mostra 2–3 motivi forti; se ce ne sono altri, +N."""
    if not reasons:
        return "—"
    top = [str(x) for x in reasons if x][:3]
    extra = max(0, len(reasons) - len(top))
    return "; ".join(top) + (f" +{extra}" if extra else "")

def sort_rows_attack_first(rows):
    def sev_rank(s):
        s = (s or "").upper()
        if s.startswith("H"): return 0
        if s.startswith("M"): return 1
        if s.startswith("L"): return 2
        return 3
    def score_key(r):
        sc = r.get("score")
        try:
            return float(sc) if sc is not None else -1.0
        except Exception:
            return -1.0
    def lat_key(r):
        try:
            return float(r.get("latency_ms") or 0.0)
        except Exception:
            return 1e9
    return sorted(rows, key=lambda r: (sev_rank(r.get("severity")), -score_key(r), lat_key(r)))

def render_top_domains(dom_summaries):
    """
    Pannello Top Domains: Domain | High | Med | P95(ms) | Top Flags
    Accetta sia dict che lista normalizzata.
    """
    if not dom_summaries:
        return ""
    items = []
    if isinstance(dom_summaries, dict):
        for d, st in dom_summaries.items():
            items.append({
                "domain": d,
                "high": st.get("high", 0),
                "med": st.get("med", 0),
                "p95": st.get("p95_latency", st.get("p95", 0)),
                "top_flags": st.get("top_flags", []),
            })
    else:
        items = dom_summaries

    hdr = [("Top Domains", 20), ("High", 6), ("Med", 6), ("P95(ms)", 9), ("Top Flags", 28)]
    sep = "-" * (sum(w for _, w in hdr) + len(hdr) - 1)
    out = [sep, " ".join(h.ljust(w) for h, w in hdr), sep]
    for it in items:
        dom = str(it.get("domain","—"))[:20].ljust(20)
        hi  = str(it.get("high",0)).rjust(6)
        md  = str(it.get("med",0)).rjust(6)
        p95 = str(int(it.get("p95",0))).rjust(9)
        tfl = " ".join(badge_flags(it.get("top_flags",[])))[:28].ljust(28)
        out.append(" ".join([dom, hi, md, p95, tfl]))
    out.append(sep)
    out.append("")
    return "\n".join(out)
# === FINE HELPER ===

def _legend_to_text(legend) -> str:
    """
    Accetta legend come str|dict|None e ritorna una stringa pronta da stampare.
    - Se dict, prova a evidenziare le soglie e poi elenca gli altri campi.
    """
    if legend is None:
        return ""
    if isinstance(legend, str):
        return legend.strip()

    # dict → costruisci testo
    try:
        lines = []
        # Prova a pescare thresholds in varie forme
        thr = legend.get("thresholds") if isinstance(legend, dict) else None
        if isinstance(thr, dict):
            hi = thr.get("high"); md = thr.get("medium")
        else:
            hi = legend.get("high") if isinstance(legend, dict) else None
            md = legend.get("medium") if isinstance(legend, dict) else None
        if isinstance(hi, (int, float)) and isinstance(md, (int, float)):
            lines.append(f"SEVERITY — High ≥ {hi:.2f} · Medium ≥ {md:.2f} · Low < {md:.2f}")

        # Elenca eventuali altri campi informativi
        for k, v in (legend.items() if isinstance(legend, dict) else []):
            if k in ("thresholds", "high", "medium"):
                continue
            if isinstance(v, dict):
                vv = ", ".join(f"{kk}={vvv}" for kk, vvv in v.items())
            elif isinstance(v, (list, tuple, set)):
                vv = ", ".join(map(str, v))
            else:
                vv = str(v)
            if vv:
                lines.append(f"{str(k).upper()}: {vv}")

        return "\n".join(lines).strip()
    except Exception:
        return str(legend).strip()

def render_table(rows, legend, top_domains=None, **_ignore):
    """
    Tabella principale (ASCII):
      - Ordinamento: High → Med → Low; a parità: score decrescente, latenza crescente.
      - SCORE in % (1 decimale solo se serve).
      - TYPE stampa il MIME (se presente in content_type_final).
      - WAF atteso come stringa; se non disponibile, '—'. Retro-compat: se trovi 'waf_vendors' lista, fai join '|'.
      - FLAGS come badge (ordine d'impatto).
      - REASONS sintetiche.
    """
    out = []
    if top_domains:
        out.append(render_top_domains(top_domains))

    rows_sorted = sort_rows_attack_first(rows)

    hdr = [
        ("#", 4),
        ("SEV", 6),
        ("SCORE", 7),
        ("METH", 6),
        ("STAT", 6),
        ("LAT(ms)", 8),
        ("SIZE", 8),
        ("TYPE", 18),
        ("FAMILY", 10),
        ("WAF", 18),
        ("FLAGS", 20),
        ("REASONS", 38),
        ("URL", 52),
    ]

    sep = "-" * (sum(w for _, w in hdr) + len(hdr) - 1)
    out.append(sep)
    out.append(" ".join(h.ljust(w) for h, w in hdr))
    out.append(sep)

    def _sev(s):
        s = (s or "").upper()
        if s.startswith("H"): return "HIGH"
        if s.startswith("M"): return "MED"
        if s.startswith("L"): return "LOW"
        return s or "—"

    def _choose_block(r):
        for m in ("get", "post", "head", "options"):
            b = r.get(m)
            if isinstance(b, dict) and ("status" in b or "error" in b or b):
                return m, b
        return None, None

    def _num(v, default="0"):
        try:
            return f"{float(v):.0f}"
        except Exception:
            return default

    for idx, r in enumerate(rows_sorted, 1):
        # SCORE → percentuale (supporta sia score_percent che score 0..1)
        scp = r.get("score_percent")
        score = f"{scp:.0f}%" if isinstance(scp, (int, float)) else format_score_percent(r.get("score") or None)

        sev = _sev(r.get("severity"))

        blk_name, blk = _choose_block(r)

        # Metodo
        meth = (r.get("method") or r.get("METH") or r.get("meth"))
        if not meth:
            meth = blk_name.upper() if blk_name else "—"

        # Status
        stat = (r.get("status") or r.get("STAT") or r.get("stat"))
        if stat is None and isinstance(blk, dict):
            stat = blk.get("status")
        stat = str(stat) if stat is not None else "—"

        # Latenza
        lat = (r.get("latency_ms") or r.get("LAT(ms)") or r.get("lat"))
        if lat is None and isinstance(blk, dict):
            lat = blk.get("latency_ms") or 0
        lat = _num(lat or 0)

        # Size
        size = (r.get("size") or r.get("SIZE"))
        if (size in (None, "—")) and isinstance(blk, dict):
            size = blk.get("size", "—")

        # TYPE: preferisci MIME in content_type_final; fallback a 'type'
        ctype = (r.get("content_type_final") or r.get("TYPE") or r.get("type") or "—")
        ctype = str(ctype)[:18]

        # FAMILY
        fam = str(r.get("family") or r.get("FAMILY") or "—")[:10]

        # WAF: atteso stringa; se manca, compat con lista 'waf_vendors'
        waf_val = r.get("waf")
        if isinstance(waf_val, str):
            waf_txt = waf_val.strip()
        elif isinstance(r.get("waf_vendors"), (list, tuple, set)):
            waf_txt = "|".join([str(x) for x in r.get("waf_vendors") if str(x).strip()])
        else:
            waf_txt = ""
        if not waf_txt or waf_txt.lower() == "none":
            waf_txt = "—"
        waf_txt = waf_txt[:18]

        # FLAGS
        flags = r.get("flags") or r.get("FLAGS") or []
        flags_str = " ".join(badge_flags(flags))[:20]

        # REASONS
        reasons = r.get("reasons") or []
        reasons_str = render_reasons(reasons)[:38]

        # URL
        url = (r.get("url") or r.get("URL") or "—")[:52]

        row = [
            str(idx).ljust(4),
            sev.ljust(6),
            (score or "—").ljust(7),
            (meth or "—")[:5].ljust(6),
            (stat or "—")[:5].ljust(6),
            lat.rjust(8),
            str(size if size is not None else "—").rjust(8),
            ctype.ljust(18),
            fam.ljust(10),
            waf_txt.ljust(18),
            flags_str.ljust(20),
            reasons_str.ljust(38),
            url.ljust(52),
        ]
        out.append(" ".join(row))

    out.append(sep)

    if legend:
        out.append("")
        legend_text = _legend_to_text(legend)
        if legend_text:
            out.append(legend_text)

    return "\n".join(out)


def format_score_percent(score):
    try:
        if score is None:
            return "—"
        val = float(score) * 100.0
        return f"{val:.1f}%" if (val % 1) else f"{int(val)}%"
    except Exception:
        return "—"

def badge_flags(flags):
    """
    Ordina e compatta le FLAGS in badge ad alto impatto visivo.
    Ordine: XSS, SQLI, IDOR, AUTH, CORS, OPENREDIR, SSRF, TPL, WEAKHDRS, DIR
    """
    if not flags:
        return []
    order = ["XSS","SQLI","IDOR","AUTH","CORS","OPENREDIR","SSRF","TPL","WEAKHDRS","DIR"]
    fs = [f.upper() for f in (flags if isinstance(flags, (list, set, tuple)) else [flags])]
    uniq = []
    for k in order:
        if k in fs:
            uniq.append(k)
    for f in fs:
        if f not in uniq:
            uniq.append(f)
    return uniq

def render_reasons(reasons):
    """Mostra 2–3 motivi forti; se ce ne sono altri, +N."""
    if not reasons:
        return "—"
    top = [str(x) for x in reasons if x][:3]
    extra = max(0, len(reasons) - len(top))
    return "; ".join(top) + (f" +{extra}" if extra else "")

def sort_rows_attack_first(rows):
    def sev_rank(s):
        s = (s or "").upper()
        if s.startswith("H"): return 0
        if s.startswith("M"): return 1
        if s.startswith("L"): return 2
        return 3
    def score_key(r):
        sc = r.get("score")
        try:
            return float(sc) if sc is not None else -1.0
        except Exception:
            return -1.0
    def lat_key(r):
        try:
            return float(r.get("latency_ms") or 0.0)
        except Exception:
            return 1e9
    return sorted(rows, key=lambda r: (sev_rank(r.get("severity")), -score_key(r), lat_key(r)))

def render_top_domains(dom_summaries):
    """
    Pannello Top Domains: Domain | High | Med | P95(ms) | Top Flags
    Accetta sia dict che lista normalizzata.
    """
    if not dom_summaries:
        return ""
    items = []
    if isinstance(dom_summaries, dict):
        for d, st in dom_summaries.items():
            items.append({
                "domain": d,
                "high": st.get("high", 0),
                "med": st.get("med", 0),
                "p95": st.get("p95_latency", st.get("p95", 0)),
                "top_flags": st.get("top_flags", []),
            })
    else:
        items = dom_summaries

    hdr = [("Top Domains", 20), ("High", 6), ("Med", 6), ("P95(ms)", 9), ("Top Flags", 28)]
    sep = "-" * (sum(w for _, w in hdr) + len(hdr) - 1)
    out = [sep, " ".join(h.ljust(w) for h, w in hdr), sep]
    for it in items:
        dom = str(it.get("domain","—"))[:20].ljust(20)
        hi  = str(it.get("high",0)).rjust(6)
        md  = str(it.get("med",0)).rjust(6)
        p95 = str(int(it.get("p95",0))).rjust(9)
        tfl = " ".join(badge_flags(it.get("top_flags",[])))[:28].ljust(28)
        out.append(" ".join([dom, hi, md, p95, tfl]))
    out.append(sep)
    out.append("")
    return "\n".join(out)
# === FINE HELPER ===


# ----------------------------- util comuni -------------------------------- #

_PRINTABLE_RE = re.compile(r"[^\x20-\x7E]")          # toglie non stampabili
_WS_RE = re.compile(r"[\r\n\t]")                     # normalizza whitespace

def _clean(s: str) -> str:
    s = s or ""
    s = _WS_RE.sub(" ", s)
    s = _PRINTABLE_RE.sub("", s)
    return s

def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default

def _percent(n: int, d: int) -> str:
    return f"{(100.0 * n / max(1, d)):.1f}%"

def _ellipsize_words(s: str, maxlen: int) -> str:
    """Taglia a parole: se supera maxlen, tronca all'ultimo spazio utile e aggiunge '…'."""
    s = _clean((s or "").strip())
    if len(s) <= maxlen:
        return s
    if maxlen <= 1:
        return "…"
    # nessuno spazio utile prima del taglio → taglio secco
    if " " not in s[: maxlen]:
        return s[: maxlen - 1] + "…"
    cut = s[: maxlen - 1].rstrip()
    space = cut.rfind(" ")
    if space <= 0:
        return s[: maxlen - 1] + "…"
    return cut[:space] + "…"

# ------------------------ schema helpers (RR vs grezzo) -------------------- #

def _get_field(rec: Dict[str, Any], key: str, *, default: Any = None) -> Any:
    """
    Estrae campo sia da render_ready (stat/lat/size/type/meth/family)
    sia da record grezzo (get.*). Ritorna default se assente.
    """
    if key == "meth":
        if "meth" in rec:
            return rec.get("meth") or "-"
        # compat grezzo → compattazione metodi presenti
        return _meth_compact(rec)

    if key == "stat":
        if "stat" in rec:
            return rec.get("stat")
        return (rec.get("get", {}) or {}).get("status", default)

    if key == "lat":
        if "lat" in rec:
            return rec.get("lat")
        return (rec.get("get", {}) or {}).get("latency_ms", default)

    if key == "size":
        if "size" in rec:
            return rec.get("size")
        return (rec.get("get", {}) or {}).get("size", default)

    if key == "type":
        if "type" in rec:
            return rec.get("type")
        return (rec.get("get", {}) or {}).get("content_type", default)

    if key == "waf":
        # ✅ Preferisci i vendor (lista) → vendor singolo → "WAF"/"" come fallback
        vendors: List[str] = []
        if isinstance(rec.get("waf_vendors"), (list, tuple, set)):
            vendors = [str(x) for x in rec.get("waf_vendors") if x]
        elif rec.get("waf_vendor"):
            vendors = [str(rec.get("waf_vendor"))]
        if vendors:
            return vendors
        g = rec.get("get", {}) or {}
        waf_bool = bool(rec.get("waf") or g.get("waf"))
        return "WAF" if waf_bool else ""

    if key == "family":
        # preferisci 'family' (render_ready), poi hint KB
        if rec.get("family"):
            return rec.get("family")
        return rec.get("family_hint_kb", default)

    return rec.get(key, default)


# --------------------------- severità/flags -------------------------------- #

def _severity_bucket(rec: Dict[str, Any]) -> str:
    # Preferisci RR; fallback grezzo
    st = _get_field(rec, "stat", default=0)
    waf_text = str(_get_field(rec, "waf", default="") or "").strip()
    if isinstance(st, int) and 500 <= st <= 599:
        return "high"
    if waf_text:
        return "medium"
    if isinstance(st, int) and 400 <= st <= 499:
        return "medium"
    return "low"

_SHORT_FLAG = re.compile(r"^[A-Z0-9_]{2,8}$")  # token brevi in MAIUSCOLO

def _normalize_flag_token(tok: str) -> str:
    t = (tok or "").strip()
    if not t:
        return ""
    if t.startswith("+"):
        return t
    if _SHORT_FLAG.match(t):
        return "+" + t
    return t

def _split_flags_maybe(s: Any) -> List[str]:
    """
    Accetta lista o stringa. Se stringa, splitta su '|' o ','.
    """
    if s is None:
        return []
    if isinstance(s, (list, tuple, set)):
        return [str(x) for x in s if str(x)]
    if isinstance(s, str):
        txt = s.strip()
        if not txt:
            return []
        if "|" in txt:
            return [p.strip() for p in txt.split("|") if p.strip()]
        if "," in txt:
            return [p.strip() for p in txt.split(",") if p.strip()]
        return [txt]
    return [str(s)]

def _augment_flags(rec: Dict[str, Any], flags_in: Sequence[str] | str) -> List[str]:
    """Aggiunge badge AI/BYP (con +) se rilevabili; dedup & ordine stabile."""
    base = _split_flags_maybe(flags_in)

    # segnali aggiuntivi
    try:
        ai_used = bool(rec.get("ai_used") or rec.get("ai_notes") or rec.get("next_step") or rec.get("policy_action"))
        byp_used = bool(rec.get("bypass_used") or rec.get("waf_bypass_used") or rec.get("transform"))
    except Exception:
        ai_used = byp_used = False
    if ai_used and "AI" not in base and "+AI" not in base:
        base.append("AI")
    if byp_used and "BYP" not in base and "+BYP" not in base:
        base.append("BYP")

    # dedup + normalizzazione simboli
    seen = set()
    out: List[str] = []
    for t in base:
        n = _normalize_flag_token(t)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out

# --------------------------- metodi compatti ------------------------------- #

def _meth_compact(rec: Dict[str, Any]) -> str:
    # Se RR fornisce già la stringa, usala
    if "meth" in rec and rec.get("meth"):
        return str(rec.get("meth"))[:3]
    present = []
    for name in ("GET", "HEAD", "OPTIONS", "POST"):
        if rec.get(name.lower()):
            present.append(name[0])
    return "".join(present)[:3] or "G"

# --------------------------- 1) SUMMARY TOP -------------------------------- #

def render_summary(rows_or_summary, thresholds=None, **_ignore):
    """
    Rende una riga di riepilogo.
    - Se riceve una LISTA di rows, calcola i conteggi High/Med/Low usando 'severity' se presente,
      altrimenti derivando la severity dallo 'score' con le soglie.
    - Se riceve un DICT (già pre-calcolato), lo usa direttamente.
    - Accetta kwargs extra (es. profile=...) senza errori.
    """
    # soglie di default robuste
    thr = thresholds or {"high": 0.75, "medium": 0.40}
    try:
        hi_thr = float(thr.get("high", 0.75))
        md_thr = float(thr.get("medium", 0.40))
    except Exception:
        hi_thr, md_thr = 0.75, 0.40

    def _pct(x, tot):
        tot = max(1, tot)
        return f"{(100.0 * x / tot):.1f}%"

    # Caso 1: LISTA di righe → calcola summary
    if isinstance(rows_or_summary, list):
        rows = rows_or_summary or []
        total = len(rows)

        def _sev_from_row(r):
            # usa 'severity' se già presente
            s = (r.get("severity") or "").upper()
            if s.startswith("H"): return "HIGH"
            if s.startswith("M"): return "MED"
            if s.startswith("L"): return "LOW"
            # altrimenti, deriva da 'score'
            sc = r.get("score")
            try:
                sc = float(sc)
            except Exception:
                sc = None
            if sc is None:
                return "LOW"
            if sc >= hi_thr: return "HIGH"
            if sc >= md_thr: return "MED"
            return "LOW"

        high = med = low = 0
        for r in rows:
            b = _sev_from_row(r)
            if b == "HIGH":   high += 1
            elif b == "MED":  med  += 1
            else:             low  += 1

        return (f"Results: {total}  |  High: {high} ({_pct(high, total)})  "
                f"Med: {med} ({_pct(med, total)})  Low: {low} ({_pct(low, total)})")

    # Caso 2: DICT già pronto
    if isinstance(rows_or_summary, dict):
        summary = rows_or_summary
        try:
            tot = int(summary.get("total") or 0)
        except Exception:
            tot = 0
        high = int(summary.get("high") or summary.get("High") or 0)
        med  = int(summary.get("medium") or summary.get("Med") or 0)
        low  = int(summary.get("low") or summary.get("Low") or 0)
        return (f"Results: {tot}  |  High: {high} ({_pct(high, tot)})  "
                f"Med: {med} ({_pct(med, tot)})  Low: {low} ({_pct(low, tot)})")

    # Fallback difensivo
    try:
        total = len(rows_or_summary)
    except Exception:
        total = 0
    return f"Results: {total}  |  High: 0 (0.0%)  Med: 0 (0.0%)  Low: 0 (0.0%)"



# --------------------------- 2) TABLE PAGED -------------------------------- #

_COL = {
    "rank": 5, "score": 6, "meth": 5, "status": 6, "lat": 7, "size": 8,
    "type": 14, "family": 10, "waf": 18, "flags": 18, "url": 60
}

def _header_line() -> str:
    return (
        f"{'#':>{_COL['rank']}}  "
        f"{'SCORE':>{_COL['score']}}  "
        f"{'METH':^{_COL['meth']}}  "
        f"{'STAT':^{_COL['status']}}  "
        f"{'LAT(ms)':>{_COL['lat']}}  "
        f"{'SIZE':>{_COL['size']}}  "
        f"{'TYPE':<{_COL['type']}}  "
        f"{'FAMILY':<{_COL['family']}}  "
        f"{'WAF':<{_COL['waf']}}  "
        f"{'FLAGS':<{_COL['flags']}}  "
        f"{'URL':<{_COL['url']}}"
    )


def _apply_filters(items: Iterable[Dict[str, Any]], filters: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not filters:
        return list(items)
    inc = {str(x).lower() for x in (filters.get("include_flags") or [])}
    exc = {str(x).lower() for x in (filters.get("exclude_flags") or [])}
    fam_req = str(filters.get("require_family") or "").lower()

    out: List[Dict[str, Any]] = []
    for r in items:
        f_aug = _augment_flags(r, r.get("flags") or [])
        low = {x.lower() for x in f_aug}
        if inc and not (inc & low):
            continue
        if exc and (exc & low):
            continue
        fam_val = str(_get_field(r, "family") or "").lower()
        if fam_req and fam_val != fam_req:
            continue
        out.append(r)
    return out

def _join_list_or_str(val: Any, sep: str = "|") -> str:
    if isinstance(val, (list, tuple, set)):
        parts = [str(x) for x in val if x is not None and str(x) != ""]
        seen = set()
        out: List[str] = []
        for p in parts:
            if p not in seen:
                seen.add(p)
                out.append(p)
        return sep.join(out)
    if isinstance(val, str):
        return val
    return ""

def _legend_footer(chunk: List[Dict[str, Any]]) -> List[str]:
    """Footer compatto (max 2 righe): WAF visti e FLAGS visti nella pagina."""
    waf_set: List[str] = []
    flag_set: List[str] = []
    seen_w = set()
    seen_f = set()

    for r in chunk:
        wtxt = _join_list_or_str(_get_field(r, "waf", default=""), sep="|")
        for part in [p for p in wtxt.split("|") if p]:
            if part not in seen_w:
                seen_w.add(part)
                waf_set.append(part)

        flags = _augment_flags(r, r.get("flags") or [])
        for f in flags:
            if f not in seen_f:
                seen_f.add(f)
                flag_set.append(f)

    waf_line = "WAF seen: " + ("|".join(waf_set) if waf_set else "—")
    flag_line = "FLAGS seen: " + ("|".join(flag_set) if flag_set else "—")
    return [waf_line[:118], flag_line[:118]]

    def format_score_percent(score):
        try:
            if score is None:
                return "—"
            val = float(score) * 100.0
            # 1 decimale solo se serve
            return f"{val:.1f}%" if (val % 1) else f"{int(val)}%"
        except Exception:
            return "—"

    def badge_flags(flags):
        """
        Ordina e compatta le FLAGS in badge ad alto impatto visivo.
        Ordine di priorità: XSS, SQLI, IDOR, AUTH, CORS, OPENREDIR, SSRF, TPL, WEAKHDRS, DIR
        """
        if not flags:
            return []
        order = ["XSS", "SQLI", "IDOR", "AUTH", "CORS", "OPENREDIR", "SSRF", "TPL", "WEAKHDRS", "DIR"]
        fs = [f.upper() for f in (flags if isinstance(flags, (list, set, tuple)) else [flags])]
        uniq = []
        for k in order:
            if k in fs:
                uniq.append(k)
        # aggiungi eventuali flag sconosciute alla fine
        for f in fs:
            if f not in uniq:
                uniq.append(f)
        return uniq

    def render_reasons(reasons):
        """
        Sintetizza i motivi: mostra le 2–3 ragioni più forti, poi '+N'.
        """
        if not reasons:
            return "—"
        top = [str(x) for x in reasons if x][:3]
        extra = max(0, len(reasons) - len(top))
        return "; ".join(top) + (f" +{extra}" if extra else "")

    def sort_rows_attack_first(rows):
        def sev_rank(s):
            s = (s or "").upper()
            if s.startswith("H"): return 0
            if s.startswith("M"): return 1
            if s.startswith("L"): return 2
            return 3

        def score_key(r):
            sc = r.get("score")
            try:
                return float(sc) if sc is not None else -1.0
            except Exception:
                return -1.0

        def lat_key(r):
            try:
                return float(r.get("latency_ms") or 0.0)
            except Exception:
                return 1e9

        return sorted(rows, key=lambda r: (sev_rank(r.get("severity")), -score_key(r), lat_key(r)))

    def render_top_domains(dom_summaries):
        """
        Pannello compatto sopra la tabella: Domain | High | Med | P95(ms) | Top Flags
        dom_summaries: lista o dict normalizzato -> [{'domain':..., 'high':..., 'med':..., 'p95':..., 'top_flags':[...]}]
        """
        if not dom_summaries:
            return ""
        # normalizza input (supporta dict o lista)
        items = []
        if isinstance(dom_summaries, dict):
            for d, st in dom_summaries.items():
                items.append({
                    "domain": d,
                    "high": st.get("high", 0),
                    "med": st.get("med", 0),
                    "p95": st.get("p95_latency", st.get("p95", 0)),
                    "top_flags": st.get("top_flags", []),
                })
        else:
            items = dom_summaries

        # header
        hdr = [("Top Domains", 20), ("High", 6), ("Med", 6), ("P95(ms)", 9), ("Top Flags", 28)]
        sep = "-" * (sum(w for _, w in hdr) + len(hdr) - 1)
        out = [sep, " ".join(h.ljust(w) for h, w in hdr), sep]

        for it in items:
            dom = str(it.get("domain", "—"))[:20].ljust(20)
            hi = str(it.get("high", 0)).rjust(6)
            md = str(it.get("med", 0)).rjust(6)
            p95 = str(int(it.get("p95", 0))).rjust(9)
            tfl = " ".join(badge_flags(it.get("top_flags", [])))[:28].ljust(28)
            out.append(" ".join([dom, hi, md, p95, tfl]))
        out.append(sep)
        out.append("")  # spazio prima della tabella
        return "\n".join(out)



    def _header_line() -> str:
        return (
            f"{'#':>{_COL['rank']}}  "
            f"{'SCORE':>{_COL['score']}}  "
            f"{'METH':^{_COL['meth']}}  "
            f"{'STAT':^{_COL['status']}}  "
            f"{'LAT(ms)':>{_COL['lat']}}  "
            f"{'SIZE':>{_COL['size']}}  "
            f"{'TYPE':<{_COL['type']}}  "
            f"{'FAMILY':<{_COL['family']}}  "
            f"{'WAF':<{_COL['waf']}}  "
            f"{'FLAGS':<{_COL['flags']}}  "
            f"{'URL':<{_COL['url']}}"
        )

    def _apply_filters(items: Iterable[Dict[str, Any]], filters: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not filters:
            return list(items)
        inc = {str(x).lower() for x in (filters.get("include_flags") or [])}
        exc = {str(x).lower() for x in (filters.get("exclude_flags") or [])}
        fam_req = str(filters.get("require_family") or "").lower()

        out: List[Dict[str, Any]] = []
        for r in items:
            f_aug = _augment_flags(r, r.get("flags") or [])
            low = {x.lower() for x in f_aug}
            if inc and not (inc & low):
                continue
            if exc and (exc & low):
                continue
            fam_val = (r.get("family") or r.get("family_hint_kb") or "").lower()
            if fam_req and fam_val != fam_req:
                continue
            out.append(r)
        return out

    items = _apply_filters(results, filters)
    if not items:
        return "[no results after filtering]"

    # Ordina per score decrescente
    items = sorted(items, key=lambda r: -(float(r.get("score") or 0.0)))

    tot = len(items)
    pages = max(1, math.ceil(tot / max(1, page_size)))
    page = max(1, min(page, pages))
    start = (page - 1) * page_size
    end = min(start + page_size, tot)
    chunk = items[start:end]

    head = []
    head.append(f"Results: {tot}  |  Page {page}/{pages}")
    head.append("-" * len(_header_line()))

    lines = [*head, _header_line(), "-" * len(_header_line())]

    for enum_idx, r in enumerate(chunk, start=start + 1):
        rank = r.get("rank") if isinstance(r.get("rank"), int) else enum_idx

        score = f"{float(r.get('score') or 0.0):.2f}"
        meth = _get_field(r, "meth", default="-")
        stat = _get_field(r, "stat", default="")
        lat = _get_field(r, "lat", default="")
        size = _get_field(r, "size", default="")
        ctype_raw = str(_get_field(r, "type", default="") or "")
        ctype = _ellipsize_words(ctype_raw, _COL["type"])

        waf_txt = _join_list_or_str(_get_field(r, "waf", default=""), sep="|")
        waf_txt = _ellipsize_words(waf_txt, _COL["waf"])

        flags = _augment_flags(r, r.get("flags") or [])
        flags_s = _ellipsize_words("|".join(flags), _COL["flags"])

        family = str(r.get("family") or r.get("family_hint_kb") or "")
        family = _ellipsize_words(family, _COL["family"])

        url = _ellipsize_words(str(r.get("url") or ""), _COL["url"])

        lines.append(
            f"{rank:>{_COL['rank']}}  "
            f"{score:>{_COL['score']}}  "
            f"{str(meth)[:_COL['meth']]:^{_COL['meth']}}  "
            f"{str(stat):^{_COL['status']}}  "
            f"{str(lat):>{_COL['lat']}}  "
            f"{str(size):>{_COL['size']}}  "
            f"{ctype:<{_COL['type']}}  "
            f"{family:<{_COL['family']}}  "
            f"{waf_txt:<{_COL['waf']}}  "
            f"{flags_s:<{_COL['flags']}}  "
            f"{url:<{_COL['url']}}"
        )

    # Footer legenda compatta
    foot = _legend_footer(chunk)
    lines.append("-" * len(_header_line()))
    for ln in foot:
        lines.append(ln)
    return "\n".join(lines)


# --------------------------- 3) DETAILS PANEL ------------------------------ #

def render_details(result: Dict[str, Any], memory: Optional[List[Dict[str, Any]]] = None) -> str:
    url = str(result.get("url") or "")
    parsed = urlparse(url)
    qparams = parse_qsl(parsed.query, keep_blank_values=True)

    def _fmt_headers(section: Dict[str, Any]) -> List[str]:
        hdrs = section.get("headers") or {}
        hdrs_ci = {k.lower(): (k, v) for k, v in hdrs.items()}
        out = []
        for k in ("server", "x-powered-by", "content-type", "set-cookie", "www-authenticate", "via", "cf-ray", "x-amzn-trace-id"):
            if k in hdrs_ci:
                hk, hv = hdrs_ci[k]
                out.append(f"{hk}: {_clean(str(hv))[:120]}")
        if not out and hdrs:
            for i, (hk, hv) in enumerate(hdrs.items()):
                if i >= 5:
                    break
                out.append(f"{hk}: {_clean(str(hv))[:120]}")
        return out

    def _flags_anomalies() -> List[str]:
        flags = _augment_flags(result, result.get("flags") or [])
        st = _as_int(_get_field(result, "stat", default=0))
        anom = []
        if str(_get_field(result, "waf", default="")).strip(): anom.append("WAF?")
        if 500 <= st <= 599: anom.append("ServerError")
        if 400 <= st <= 499: anom.append("ClientErr")
        redirs = (result.get("get", {}) or {}).get("redirect_chain") or []
        if isinstance(redirs, list) and len(redirs) >= 2: anom.append("MultiRedirect")
        if _as_int((result.get("get", {}) or {}).get("latency_ms")) >= 800: anom.append("Slow")
        if flags: anom.append("Flags:" + "|".join(flags))
        return anom

    header = [
        "═" * 118,
        f"DETAILS  |  {url}",
        "═" * 118
    ]

    g = result.get("get", {}) or {}
    fam_line = f"Family: {str(_get_field(result, 'family') or '')}"
    overview = [
        f"Status: {_get_field(result, 'stat')}   Latency: {_get_field(result, 'lat')} ms   Size: {_get_field(result, 'size')}   Type: {_get_field(result, 'type') or ''}",
        f"{fam_line}   WAF: {_join_list_or_str(_get_field(result, 'waf'), sep='|') or ('Y' if g.get('waf') else 'N')}   Score: {(result.get('score') or 0.0):.2f}"
    ]

    methods = []
    for name in ("get", "head", "options", "post"):
        if result.get(name) or {}:
            methods.append(name.upper())
    if not methods and result.get("meth"):
        methods = [str(result.get("meth"))]
    methods_line = "Methods seen: " + (", ".join(methods) if methods else "GET")

    hdr_lines = _fmt_headers(g)
    hdr_block = ["Headers (sample):"] + (hdr_lines if hdr_lines else ["<none>"])

    params_block = ["Query params:"] + ([f"- {k} = {_clean(v)}" for (k, v) in qparams] if qparams else ["<none>"])

    anomalies = _flags_anomalies()
    anom_block = ["Anomalies:", ("- " + ", ".join(anomalies))] if anomalies else ["Anomalies:", "<none>"]

    ai_notes = result.get("ai_notes")
    next_step = result.get("next_step") or result.get("policy_action")
    ai_block = ["AI notes:", f"- {_clean(str(ai_notes))}"] if ai_notes else ["AI notes:", "<none>"]
    next_block = ["Next step:", f"- {_clean(str(next_step))}"] if next_step else ["Next step:", "<none>"]

    hist_lines = []
    for ev in (memory or [])[-8:]:
        tag = ev.get("decision") or ev.get("action") or "event"
        st = ev.get("response", {}).get("status", ev.get("status", ""))
        wafb = " WAF" if ev.get("response", {}).get("waf") or ev.get("waf_blocked") else ""
        fam = f" {ev.get('family')}" if ev.get("family") else ""
        hist_lines.append(f"- {tag}{fam}{wafb}  status={st}")
    history_block = ["Recent history:"] + (hist_lines if hist_lines else ["<none>"])

    parts = [
        *header,
        methods_line,
        *overview,
        "-" * 118,
        *hdr_block,
        "-" * 118,
        *params_block,
        "-" * 118,
        *anom_block,
        "-" * 118,
        *ai_block,
        "-" * 118,
        *next_block,
        "-" * 118,
        *history_block,
        "═" * 118,
    ]
    return "\n".join(parts)

# --------------------------- 4) CSV helper -------------------------------- #

# aggiunta colonna 'family'
_CSV_COLS = ("rank", "score", "meth", "stat", "lat", "size", "type", "family", "waf", "flags", "url")

def _row_from_render_ready(r: Dict[str, Any]) -> Dict[str, str]:
    """Converte un record 'render_ready' in righe CSV uniformi (stringhe)."""
    waf_txt = _join_list_or_str(_get_field(r, "waf"), sep="|")
    flags = _augment_flags(r, r.get("flags") or [])
    flags_txt = "|".join(flags)
    family = str(_get_field(r, "family") or "")

    return {
        "rank": str(r.get("rank") or ""),
        "score": f"{(float(r.get('score') or 0.0)):.4f}" if r.get("score") is not None else "",
        "meth": str(_get_field(r, "meth") or ""),
        "stat": str(_get_field(r, "stat") or ""),
        "lat": str(_get_field(r, "lat") or ""),
        "size": str(_get_field(r, "size") or ""),
        "type": str(_get_field(r, "type") or ""),
        "family": family,
        "waf": waf_txt,
        "flags": flags_txt,
        "url": str(r.get("url") or ""),
    }

def render_csv(results: List[Dict[str, Any]]) -> str:
    """
    Ritorna CSV in stringa:
      - quoting=QUOTE_ALL (celle vuote = "")
      - nessuno spazio extra
    """
    buf = StringIO()
    w = csv.DictWriter(buf, fieldnames=_CSV_COLS, quoting=csv.QUOTE_ALL, lineterminator="\n")
    w.writeheader()
    for r in results or []:
        w.writerow(_row_from_render_ready(r))
    return buf.getvalue()
