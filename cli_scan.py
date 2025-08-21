# cli_scan.py — Thin wrapper per orchestrated scan (no circular imports)
# UX: menu senza flag, riepilogo parametri, export chiaro, tabella con paging + legenda compatta.
# NOTE: non tocca il resto del progetto; usa solo output in memoria dell’orchestratore.

from __future__ import annotations

import os
import re
import json
import math
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("cli_scan")

# Renderer centralizzato (summary + tabella), opzionale
try:
    from output_formatter import render_summary as _of_render_summary, render_table as _of_render_table  # type: ignore
except Exception:
    _of_render_summary = None
    _of_render_table = None


# ───────────────────────────────────────────────────────────────────────── #
# Prompt helpers                                                            #
# ───────────────────────────────────────────────────────────────────────── #

def _ask(prompt: str, default: Optional[str] = None) -> str:
    hint = f" [{default}]" if default is not None else ""
    try:
        s = input(f"{prompt}{hint}: ").strip()
    except EOFError:
        s = ""
    return s or (default or "")

def _count_endpoints(path: Path) -> int:
    try:
        n = 0
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    n += 1
        return n
    except Exception:
        return 0

def _normalize_int(val: str) -> Optional[int]:
    try:
        return int(val)
    except Exception:
        return None

def _normalize_float(val: str) -> Optional[float]:
    try:
        return float(val)
    except Exception:
        return None

def _bool_env(val: bool) -> str:
    return "1" if val else "0"


# ───────────────────────────────────────────────────────────────────────── #
# Doctor (riassunto pulito) + AI banner                                     #
# ───────────────────────────────────────────────────────────────────────── #

def doctor(show_json: bool = False) -> Dict[str, Any]:
    import shutil, socket
    report: Dict[str, Any] = {"ok": True, "warnings": [], "features": {}}

    # Disco
    try:
        usage = shutil.disk_usage(".")
        free_gb = usage.free / (1024**3)
        report["disk_free_gb"] = round(free_gb, 2)
        if free_gb < 1.0:
            report["ok"] = False
            report["warnings"].append("Spazio disco < 1GB")
    except Exception as e:
        report["warnings"].append(f"Disk check errore: {e}")

    # Permessi scrittura
    try:
        tmp = Path(".bg_write_test_scan")
        tmp.write_text("ok", encoding="utf-8"); tmp.unlink()
    except Exception as e:
        report["ok"] = False
        report["warnings"].append(f"Nessun permesso di scrittura nella dir corrente: {e}")

    # Rete
    try:
        socket.gethostbyname("example.com")
        s = socket.create_connection(("example.com", 80), 3)
        s.close()
        report["network"] = "ok"
    except Exception:
        report["warnings"].append("Rete non raggiungibile (example.com:80)")
        report["network"] = "fail"

    # Feature flags
    def _has(name: str) -> bool:
        try:
            __import__(name)
            return True
        except Exception:
            return False

    features = {
        "httpx": _has("httpx"),
        "sentence_transformers": _has("sentence_transformers"),
        "transformers": _has("transformers"),
        "sklearn": _has("sklearn"),
        "shap": _has("shap"),
        "faiss": _has("faiss"),
        "umap": _has("umap"),
        "bs4": _has("bs4"),
        "PyPDF2": _has("PyPDF2"),
        "datasketch": _has("datasketch"),
        "jwcrypto": _has("jwcrypto"),
        "boofuzz": _has("boofuzz"),
        "deap": _has("deap"),
        "pydantic": _has("pydantic"),
        "pmdarima": _has("pmdarima"),
    }
    report["features"] = features

    if not features["httpx"]:
        report["ok"] = False
        report["warnings"].append("Manca httpx (sonda HTTP indisponibile).")
    if not features["sentence_transformers"]:
        report["warnings"].append("Embeddings disabilitati (manca sentence_transformers).")
    if not features["transformers"]:
        report["warnings"].append("SecureBERT non disponibile (classificatore in fallback).")
    if not (features["shap"] and features["sklearn"]):
        report["warnings"].append("Explainability SHAP/Sklearn non disponibile (render SVG di cortesia).")
    if not features["faiss"]:
        report["warnings"].append("FAISS non disponibile (search avanzata degrada a keyword).")

    # Output pulito (no graffe di default)
    if show_json or (os.getenv("BG_VERBOSE_PREFLIGHT", "").lower() in ("1","true","yes","on")):
        print(json.dumps(report, indent=2))
    else:
        ok_txt = "OK" if report["ok"] else "FAIL"
        warn_n = len(report["warnings"])
        feats_short = ", ".join([f"{k}={str(v)}" for k, v in {
            "httpx": features["httpx"],
            "transformers": features["transformers"],
            "sklearn": features["sklearn"],
            "shap": features["shap"],
            "faiss": features["faiss"]
        }.items()])
        print(f"{ok_txt} — warnings: {warn_n} | disk_free_gb: {report.get('disk_free_gb','?')} | network: {report.get('network')}")
        if warn_n:
            for w in report["warnings"]:
                print(f"  - {w}")
        print(f"features: {feats_short}")

    return report

def _ai_status_banner() -> str:
    def _has(name: str) -> bool:
        try:
            __import__(name)
            return True
        except Exception:
            return False
    parts = []
    parts.append(f"Embeddings: {'ON' if _has('sentence_transformers') else 'OFF'}")
    parts.append(f"SecureBERT: {'ON' if _has('transformers') else 'OFF'}")
    parts.append(f"Explain (SHAP): {'ON' if (_has('shap') and _has('sklearn')) else 'OFF'}")
    parts.append(f"DL mutate: {'ON' if _has('neuralpayloads') else 'OFF'}")
    return " | ".join(parts)


# ───────────────────────────────────────────────────────────────────────── #
# Config / Renderer                                                          #
# ───────────────────────────────────────────────────────────────────────── #

def _ensure_config(cfg_path: Path) -> Dict[str, Any]:
    """
    Crea un config YAML minimale se non esiste; ritorna dict (best-effort).
    """
    base = {
        "endpoints_file": "endpoints.txt",
        "output_file": "orchestrator_output.json",
        "output_csv": "orchestrator_results.csv",
        "top_n": None,
        "shap_max_evals": 50,
        "window": 10,
        "write_outputs": False,
        "export_format": "none",
        "profile_default": "light",
        "export_default": "none",
        "page_size_default": 100,
        "concurrency_default": 8,
        "timeout_s_default": 10.0,
        "retries_default": 1,
    }
    if not cfg_path.exists():
        try:
            import yaml  # type: ignore
            cfg_path.write_text(yaml.safe_dump(base), encoding="utf-8")
            return base
        except Exception:
            cfg_path.write_text(json.dumps(base, indent=2), encoding="utf-8")
            return base
    # Se esiste e non è YAML valido, continuiamo con base
    try:
        import yaml  # type: ignore
        loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        if isinstance(loaded, dict):
            base.update(loaded)
    except Exception:
        pass
    return base

def _severity_bucket_from_row(row: Dict[str, Any]) -> str:
    """
    Mappa severità rapida (solo per summary fallback).
    Preferisce schema render_ready; fallback a blocchi GET.
    """
    if "stat" in row:  # render_ready
        st = row.get("stat")
        waf_text = (row.get("waf") or "").strip()
        if isinstance(st, int) and 500 <= st <= 599:
            return "high"
        if waf_text:
            return "medium"
        if isinstance(st, int) and 400 <= st <= 499:
            return "medium"
        return "low"
    # fallback su schema grezzo
    g = row.get("get", {}) or {}
    st = g.get("status") or 0
    waf = bool(g.get("waf"))
    if isinstance(st, int) and 500 <= st <= 599:
        return "high"
    if waf:
        return "medium"
    if isinstance(st, int) and 400 <= st <= 499:
        return "medium"
    return "low"

def _legend_compact() -> str:
    # 2–3 righe max
    l1 = "LEGEND — WAF: nome/i del WAF se rilevati; vuoto = assente/sconosciuto."
    l2 = "FLAGS — +AI(model assist) | +DNS(DNS) | +BYP(bypass tentato, deep) | +DIR(dir listing) | +XSS | +SQLI"
    return f"{l1}\n{l2}"


def _extract_waf_from_flags(flags_text: str) -> str:
    """
    Se FLAGS contiene 'WAF:Vendor1|Vendor2', ritorna i vendor.
    """
    if not flags_text:
        return ""
    m = re.search(r"WAF:([A-Za-z0-9_\-|\s]+)", flags_text)
    if not m:
        return ""
    vendors = [v.strip() for v in (m.group(1) or "").split("|") if v.strip()]
    return "|".join(dict.fromkeys(vendors))


def render_ascii(
    results: List[Dict[str, Any]],
    page: int = 1,
    page_size: int = 100,
    profile: str = "light",
    legend: Optional[str] = None,
    top_domains: Optional[dict] = None,
) -> str:
    """
    Usa output_formatter se presente; altrimenti fallback tabellare interno robusto per:
    - schema render_ready (preferito)
    - schema grezzo (GET/POST)
    """
    if not results:
        return "[no results]"

    # Se abbiamo il renderer avanzato, usiamolo e passiamo legend/top_domains
    if _of_render_summary and _of_render_table:
        summary = _of_render_summary(results)  # tollera kwargs extra se presenti
        table = _of_render_table(
            results,
            legend=legend,
            top_domains=top_domains,
            page=page,
            page_size=page_size,
        )
        return summary + "\n" + table + "\n" + _legend_compact()

    # ───── Fallback minimale (stabile) ─────

    # Ordina per score (se disponibile) poi per status
    def _score_of(r: Dict[str, Any]) -> float:
        if "score" in r and isinstance(r.get("score"), (int, float)):
            return float(r.get("score") or 0.0)
        return 0.0

    def _status_of(r: Dict[str, Any]) -> int:
        if "stat" in r:
            return int(r.get("stat") or 0)
        return int((r.get("get", {}) or {}).get("status") or 0)

    results = sorted(results, key=lambda r: (-_score_of(r), _status_of(r)))
    tot = len(results)
    sev = {"high": 0, "medium": 0, "low": 0}
    for r in results:
        sev[_severity_bucket_from_row(r)] += 1

    def pct(x: int) -> str:
        return f"{(100.0 * x / max(1, tot)):.1f}%"

    pages = max(1, math.ceil(tot / max(1, page_size)))
    page = max(1, min(page, pages))
    start = (page - 1) * page_size
    end = min(start + page_size, tot)
    chunk = results[start:end]

    head: List[str] = []
    head.append(
        f"Results: {tot}  |  Page {page}/{pages}  |  High: {sev['high']} ({pct(sev['high'])})  "
        f"Med: {sev['medium']} ({pct(sev['medium'])})  Low: {sev['low']} ({pct(sev['low'])})"
    )
    head.append("-" * 140)

    # Colonne fisse
    col = {
        "rank": 4,
        "score": 6,
        "meth": 5,
        "stat": 6,
        "lat": 7,
        "size": 8,
        "type": 16,
        "waf": 18,
        "flags": 20,
        "url": 52,
    }
    header = (
        f"{'#':>{col['rank']}}  {'SCORE':>{col['score']}}  {'METH':^{col['meth']}}  "
        f"{'STAT':^{col['stat']}}  {'LAT(ms)':>{col['lat']}}  {'SIZE':>{col['size']}}  "
        f"{'TYPE':<{col['type']}}  {'WAF':<{col['waf']}}  {'FLAGS':<{col['flags']}}  {'URL':<{col['url']}}"
    )
    lines = [header, "-" * len(header)]

    for i, r in enumerate(chunk, start=start + 1):
        if "meth" in r:  # schema render_ready
            meth = (r.get("meth") or "-")[:col["meth"]]
            stat = r.get("stat")
            lat = r.get("lat")
            size = r.get("size")
            ctype = (str(r.get("type") or "")).replace("\n", " ")[:col["type"]]

            # WAF: se 'False' → vuoto; se 'True' → prova a estrarre vendor dai FLAGS
            waf_raw = r.get("waf")
            flags_val = r.get("flags")
            flags_txt = flags_val if isinstance(flags_val, str) else (",".join(flags_val or []))
            waf = ""
            if isinstance(waf_raw, bool):
                waf = _extract_waf_from_flags(flags_txt) or ("WAF" if waf_raw else "")
            else:
                wr = str(waf_raw or "").strip()
                if wr.lower() == "true":
                    waf = _extract_waf_from_flags(flags_txt) or "WAF"
                elif wr.lower() == "false" or wr == "":
                    waf = ""
                else:
                    waf = wr
            waf = waf.replace("\n", " ")[:col["waf"]]

            flags = (flags_txt or "")[:col["flags"]]
            url = (str(r.get("url") or ""))[:col["url"]]
            score = f"{float(r.get('score') or 0.0):.2f}"

        else:  # schema grezzo
            g = r.get("get", {}) or {}
            p = r.get("post", {}) or {}
            meth = "GET" if g else ("POST" if p else "-")
            stat = g.get("status") if g else p.get("status")
            lat = g.get("latency_ms") if g else p.get("latency_ms")
            size = g.get("size") if g else p.get("size")
            ctype = (g.get("content_type") if g else p.get("content_type")) or ""

            # WAF: usa vendors lista se disponibile; altrimenti vendor singolo; altrimenti 'WAF'/''
            waf_vendors = []
            if isinstance(r.get("waf_vendors"), (list, tuple, set)):
                waf_vendors = [str(x) for x in r.get("waf_vendors") if x]
            elif r.get("waf_vendor"):
                waf_vendors = [str(r.get("waf_vendor"))]
            waf = "|".join(dict.fromkeys(waf_vendors)) if waf_vendors else ("WAF" if g.get("waf") else "")

            fv = r.get("flags") or []
            if isinstance(fv, list):
                flags = ",".join([str(x) for x in fv])
            else:
                flags = str(fv)
            url = (r.get("url") or "")
            score = f"{float(r.get('score') or 0.0):.2f}"
            # normalizza tipi
            ctype = str(ctype)[:col["type"]]
            waf = str(waf)[:col["waf"]]
            flags = str(flags)[:col["flags"]]
            url = str(url)[:col["url"]]

        lines.append(
            f"{i:>{col['rank']}}  {score:>{col['score']}}  {meth:^{col['meth']}}  "
            f"{str(stat or ''):^{col['stat']}}  {str(lat or ''):>{col['lat']}}  {str(size or ''):>{col['size']}}  "
            f"{ctype:<{col['type']}}  {waf:<{col['waf']}}  {flags:<{col['flags']}}  {url:<{col['url']}}"
        )

    return "\n".join(head + lines + ["", _legend_compact()])

# ───────────────────────────────────────────────────────────────────────── #
# Interactive Scan                                                           #
# ───────────────────────────────────────────────────────────────────────── #

def run_scan_interactive() -> None:
    # Doctor (mostra stato prima di tutto)
    print("[Doctor] Preflight:")
    doctor(show_json=False)  # niente graffe di default

    # 1) Input: path endpoints
    ep_in = _ask("→ Path del file endpoints (.txt)", "endpoints.txt")
    ep_path = Path(os.path.abspath(os.path.expanduser(os.path.expandvars(ep_in))))
    if not ep_path.exists():
        print(f"[X] File non trovato: {ep_path}")
        return
    if not ep_path.name.lower().endswith(".txt"):
        print("[!] Consigliato un file .txt con un endpoint per riga.")
    total = _count_endpoints(ep_path)
    if total == 0:
        print(f"[X] Nessun endpoint valido in: {ep_path} (righe vuote o commenti)")
        return
    print(f"[i] Endpoints da scansionare: {total}")
    print(f"[i] File: {ep_path}")

    # 2) Carica config per default sensati
    cfg_path = Path("config.yaml")
    cfg = _ensure_config(cfg_path)

    # 3) Profilo
    default_profile = str(cfg.get("profile_default", "light")).strip().lower()
    profile = _ask("Profile [light/deep]", default_profile if default_profile in ("light", "deep") else "light").strip().lower()
    if profile not in ("light", "deep"):
        profile = "light"

    # 4) Paging
    page_size = _normalize_int(_ask("Rows per page", str(int(cfg.get("page_size_default", 100))))) or int(cfg.get("page_size_default", 100))

    # 5) Concurrency / Timeout / Retries (default sensati)
    default_conc = int(cfg.get("concurrency_default", 8))
    default_timeout = float(cfg.get("timeout_s_default", 10.0))
    default_retries = int(cfg.get("retries_default", 1))

    conc = _normalize_int(_ask("Concurrency (requests in parallel)", str(default_conc))) or default_conc
    timeout_s = _normalize_float(_ask("Request timeout (s)", str(default_timeout))) or default_timeout
    retries = _normalize_int(_ask("Retries per request", str(default_retries))) or default_retries

    # 6) Export policy
    default_export = str(cfg.get("export_default", cfg.get("export_format", "none"))).lower()
    export_choice = _ask("Export [none/json/csv/both]", default_export if default_export in ("none", "json", "csv", "both") else "none").strip().lower()
    if export_choice not in ("none", "json", "csv", "both"):
        export_choice = "none"
    write_outputs = export_choice != "none"

    # 7) Banner AI
    print(f"[AI] {_ai_status_banner()}")

    # 8) Riepilogo chiaro dei parametri
    print("\n[Riepilogo]")
    print(f"  Profile: {profile}")
    print(f"  Export: {export_choice}")
    print(f"  Concurrency: {conc}  |  Timeout: {timeout_s}s  |  Retries: {retries}")
    print(f"  Rows/page: {page_size}")
    if write_outputs:
        print(f"  Output JSON: {cfg.get('output_file', 'orchestrator_output.json')}  |  CSV: {cfg.get('output_csv', 'orchestrator_results.csv')}")
    print("")

    # 9) Prepara config e ENV per l'orchestratore
    cfg["endpoints_file"] = str(ep_path)
    cfg["profile"] = profile
    cfg["concurrency"] = conc
    cfg["retries"] = retries
    cfg["timeout"] = float(timeout_s)  # orch_report usa questo come timeout del profilo scelto
    cfg["write_outputs"] = write_outputs
    cfg["export_format"] = export_choice
    if profile == "light":
        cfg["top_n"] = 0  # solo probe base

    try:
        import yaml  # type: ignore
        cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    except Exception:
        cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    # Env per orchestratore (rispetta priorità ENV del modulo)
    os.environ["SCAN_ENDPOINTS_FILE"] = str(ep_path)           # per load_endpoints()
    os.environ["SCAN_EXPORT_FORMAT"] = export_choice           # per policy export
    os.environ["SCAN_WRITE_OUTPUTS"] = _bool_env(write_outputs)
    # Env di cortesia per backend (alcuni moduli potrebbero leggerli)
    os.environ["BG_PROFILE"] = profile
    os.environ["BG_BUDGET_JSON"] = json.dumps({"concurrency": conc, "timeout_s": timeout_s, "retries": retries})
    os.environ["PROBE_CONCURRENCY"] = str(conc)
    os.environ["PROBE_TIMEOUT_S"] = str(timeout_s)
    os.environ["PROBE_RETRIES"] = str(retries)

    # 10) Esegui orchestratore (import locale → no import circolari)
    try:
        from orch_report import main_orchestrator  # type: ignore
    except Exception as e:
        print(f"[X] Impossibile importare orchestratore: {e}")
        return

    print("[…] Starting full scan via orchestrator…")
    output: Optional[Dict[str, Any]] = None
    try:
        maybe = main_orchestrator(str(cfg_path))
        if isinstance(maybe, dict):
            output = maybe
    except Exception as e:
        print(f"[X] Scan failed: {e}")
        return

    # 11) Uso output in memoria. Se export=none, NON leggere file post-run.
    if output is None and write_outputs:
        out_file = Path(cfg.get("output_file", "orchestrator_output.json"))
        if out_file.exists():
            try:
                output = json.loads(out_file.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"[?] Impossibile leggere output JSON: {e}")

    if output is None:
        print("[?] Nessun output ritornato dall'orchestratore.")
        if write_outputs:
            print(f"[i] Controlla i file: {cfg.get('output_file')} / {cfg.get('output_csv')}")
        return

    # 12) Resa tabellare + paging
    # Preferisci render_ready (già JSON-safe)
    probe = output.get("render_ready")
    if not isinstance(probe, list) or not probe:
        probe = output.get("probe_results") or []
        if not isinstance(probe, list):
            probe = []

    print("\n" + render_ascii(
        probe,
        page=1,
        page_size=page_size,
        profile=profile,
        legend=output.get("legend"),
        top_domains=output.get("top_domains"),
    ))

    # 13) Export paths: mostrali se export richiesto
    if write_outputs:
        exp_paths = output.get("export_paths") or {}
        json_path = exp_paths.get("json_path") or cfg.get("output_file")
        csv_path = exp_paths.get("csv_path") or (cfg.get("output_csv") if export_choice in ("csv", "both") else None)
        print("\n[i] Export paths:")
        print(f"    JSON: {Path(str(json_path)).resolve() if json_path else '—'}")
        if export_choice in ("csv", "both"):
            print(f"    CSV : {Path(str(csv_path)).resolve() if csv_path else '—'}")

    # 14) Paging interattivo
    total = len(probe)
    pages = max(1, math.ceil(total / max(1, page_size)))
    current = 1
    while pages > 1:
        cmd = _ask("\n[N]ext / [P]rev / [Q]uit", "N").lower()
        if cmd.startswith("q"):
            break
        if cmd.startswith("p"):
            current = max(1, current - 1)
        else:
            current = min(pages, current + 1)
        print("\n" + render_ascii(
            probe,
            page=current,
            page_size=page_size,
            profile=profile,
            legend=output.get("legend"),
            top_domains=output.get("top_domains"),
        ))


if __name__ == "__main__":
    try:
        run_scan_interactive()
    except KeyboardInterrupt:
        print("\n[Interrupted]")
