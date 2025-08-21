# cli.py
# Entrypoint unico: Menu principale + Config persistente + prime dirs
# Menu: 1) Scan  2) Ingest  3) Config  4) Legend/Help
# Persistenza: securebert_path, profile_default, export_default, ecc.
# Prima esecuzione: crea dirs (models/, cache/, exports/)

from __future__ import annotations

import os
import sys
import json
import math
import shutil
import socket
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


import subprocess

# Renderer opzionale (summary + tabella)
try:
    from output_formatter import render_summary as _of_render_summary, render_table as _of_render_table  # type: ignore
except Exception:
    _of_render_summary = None
    _of_render_table = None

# Entrate dirette a sottocmd se disponibili (evita duplicati logica)
try:
    from cli_scan import run_scan_interactive as _scan_entry  # type: ignore
except Exception:
    _scan_entry = None
try:
    from cli_ingest import run_ingest_interactive as _ingest_entry  # type: ignore
except Exception:
    _ingest_entry = None

def _print_scan_output(output: dict) -> None:
    """
    Stampa summary + tabella in modo robusto.
    - Usa SEMPRE attach_render_context prima del renderer (popola meth/stat/type/waf/score/severity)
    - legend: accetta stringa o dict {"table": "..."}
    - top_domains: se mancante, lo calcola da rows
    """
    # 1) prendi le righe effettivamente da renderizzare
    rows = output.get("render_ready")
    if not rows:
        rows = output.get("probe_results") or output.get("rows") or []
    if not isinstance(rows, list):
        rows = []

    # 2) carica KB e arricchisci le righe (qui si popolano METH/STAT/TYPE/WAF/SCORE/SEVERITY/REASONS)
    try:
        import yaml  # type: ignore
        KB = yaml.safe_load(open("kb_param_families.yaml", encoding="utf-8")) or {}
    except Exception:
        KB = {}
    try:
        from orch_report import attach_render_context, build_domain_summaries  # type: ignore
        attach_render_context(rows, kb=KB)
    except Exception as e:
        print(f"[!] attach_render_context fallita: {e}")

    # 3) legend e top_domains
    legend_obj = output.get("legend")
    if isinstance(legend_obj, str):
        legend_str = legend_obj
    elif isinstance(legend_obj, dict):
        legend_str = legend_obj.get("table") or ""
    else:
        legend_str = ""

    top_domains = output.get("top_domains")
    if not isinstance(top_domains, dict):
        try:
            # se l'orchestratore non l'ha calcolato, ricavalo qui
            from orch_report import build_domain_summaries  # type: ignore
            top_domains = build_domain_summaries(rows)
        except Exception:
            top_domains = None

    # 4) stampa summary (se disponibile)
    try:
        from output_formatter import render_summary as _render_summary  # type: ignore
    except Exception:
        _render_summary = None

    if _render_summary:
        try:
            # se l'orchestratore ha già fatto il summary, passalo; altrimenti lascia il fallback interno del renderer
            print(_render_summary(output.get("summary") or {}, total=len(rows)))
        except Exception:
            pass
    else:
        # fallback minimale
        tot = len(rows)
        highs = sum(1 for r in rows if str(r.get("severity","")).upper().startswith("H"))
        meds  = sum(1 for r in rows if str(r.get("severity","")).upper().startswith("M"))
        lows  = max(0, tot - highs - meds)
        print(f"Results: {tot}  |  High: {highs} ({100*highs/max(1,tot):.1f}%)  "
              f"Med: {meds} ({100*meds/max(1,tot):.1f}%)  Low: {lows} ({100*lows/max(1,tot):.1f}%)")

    # 5) stampa tabella (usa esattamente la firma del tuo render_table: (rows, legend, top_domains=...))
    try:
        from output_formatter import render_table as _render_table  # type: ignore
        print(_render_table(rows, legend_str, top_domains=top_domains))
    except Exception as e:
        # fallback asciutto se proprio il renderer non è disponibile
        from textwrap import shorten
        print(f"[!] Renderer tabella non disponibile: {e}")
        print("\nURL                                   METH  STAT  LAT  TYPE  WAF  FLAGS")
        for r in rows:
            waf = ",".join(r.get("waf_vendors") or []) or "None"
            flags = " ".join(r.get("flags") or [])
            print(f"{shorten(str(r.get('url','—')), 37):37}  "
                  f"{(r.get('method') or '—'):>4}  "
                  f"{str(r.get('status','—')):>3}  "
                  f"{str(r.get('latency_ms','—')):>4}  "
                  f"{shorten(str(r.get('content_type_final','—')),5):>5}  "
                  f"{shorten(waf,8):>8}  "
                  f"{shorten(flags,18):<18}")

ASCII_HEADER = r"""
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
|
| ⣿⣿⠁⢠⣶⣶⣦⡀⢹⣷⠀⠀⣾⣿⣿⣟⣛⠛⠛⢿⣿⣿⣿⣿⣿⣌⢻⣧⡙⣿⠛⣿⡏⣱⡿⢋⣵⣿⣿⡿⠟⡛⠛⠛⢛⣛⣿⣿⣿⡄⠀⢀⣿⠀⣥⣶⣶⣄⠈⢻⣿⣿    | __ )|  _ \ | | | ||__  __|  / \  | | 
| ⣿⡇⢀⠟⠉⠉⠻⣧⠈⣿⠀⠈⢿⣿⣿⣿⠋⠀⠀⣀⠈⠙⢾⣿⣿⣿⣧⡙⠃⣿⠀⣿⠁⠟⣱⣿⣿⣿⣯⠖⠋⢀⠀⠀⠙⣿⣿⣿⣿⠇⠀⣸⡏⢰⡿⠋⠉⠛⡇⠈⣿     |  _ \| |_)| | | | |  | |    / _ \ | | 
| ⣿⡇⠈⣶⣿⠟⣡⡘⠀⢿⡇⠀⠈⠻⣿⣿⣧⡀⠀⠙⠄⠀⠀⠈⠛⠿⠿⠃⠀⠀⠀⠀⠀⠈⠿⠿⠟⠋⠀⣀⠀⠛⠁⢀⣴⣿⣿⠟⠁⠀⢀⣿⠁⠎⢀⡛⢿⣷⡇⠀⣿⣿    | |_) |  _ < | |_| |  | |   / ___ \| |__
| ⣿⣿⠀⢻⣇⣾⣿⡧⠁⣸⡇⠀⢀⣤⠈⡿⢿⣿⣥⣀⣀⣀⣀⣠⡤⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⠤⣀⣀⣀⣀⣀⣀⣽⣿⡿⠏⣠⡀⠀⠘⣿⠐⢰⣿⣿⣌⣿⠁⣸⣿     |____/|_|_\_\ \___/ _ | |_ /_/   \_\_____|
| ⣿⣿⣧⠀⢿⡿⢋⣴⣾⠟⠀⠀⣾⣿⣿⣿⣶⣾⣿⣿⣿⣿⣿⡟⢠⡖⠒⢶⣤⣤⣤⣤⣤⣤⠖⠲⢄⠹⣿⣿⣿⣿⣿⣯⣵⣾⣿⣿⡧⡆⠀⠙⢿⣦⡍⠻⢿⠇⢠⣿⣿⣿
| ⣿⣿⣿⡇⠀⠴⣿⡍⠁⠀⠀⠀⠸⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡈⠀⣿⡰⠇⠀⠙⣿⣿⣿⠟⠁⠘⠆⢸⡄⠋⣼⣿⣿⣿⣿⣿⡿⠿⠫⠝⠀⠀⠀⠀⠈⣙⠃⠀⠀⢿⣿⣿     / ___|/ _ \ |  _ \|_  | |   | |      / \  
| ⣿⣿⣿⠄⢠⡾⠋⠀⠀⠀⡀⠀⠀⠀⠉⠙⠛⠻⢿⣿⣿⡿⣿⣦⣤⡙⢷⣦⣤⠸⣿⠿⣠⣤⡶⢟⣁⣴⣾⣿⢛⣭⣥⠴⠒⠋⠀⠀⠀⠀⡀⢄⠀⠀⠈⠳⣄⠐⢦⣿⣿     | |  _| | | | |_) || || |   | |     / _ \ 
| ⣿⣿⠋⢠⡟⠁⠀⠀⠈⣴⡰⢂⡤⠀⠀⠀⠀⠀⠈⠙⢱⣷⣿⣿⣿⣿⣿⣿⣿⣷⡖⣾⣿⣿⣿⣿⣿⣿⣿⣿⣆⠙⠁⠀⠀⡀⠀⢄⡘⢶⣌⣾⣦⠀⠀⠀⠹⣆⠀⢿⣿⣿    | |_| | |_| |  _ < | || |___| |___ / ___ \ 
| ⣿⠃⠠⢋⡀⠀⠀⠀⣾⣿⣿⡿⣡⡞⣀⡴⠀⠀⠀⠀⢛⣫⣭⣿⣿⣿⣿⣿⣿⠛⠁⠻⣿⣿⣿⣿⣿⣿⣿⣿⣷⡆⠀⠀⠀⠈⢦⡌⢿⣬⣿⣿⣿⡆⠀⠀⠀⢨⣆⠀⢻      \____|\___/|_| \_\___|_____|_____/_/   \_\
| ⠇⠀⢀⡿⠀⠀⠀⠀⢿⣿⣿⣿⣿⣼⡟⠀⠀⠀⢠⣾⣿⣿⣿⠿⠿⠿⠿⠿⠿⠿⣿⣷⣦⣽⣿⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠈⢿⣿⣿⣿⣿⢿⠁⠀⠀⠀⢸⣇⠀⠀⢿
|
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘                            
                          |       GHOSTSHINOBI 2025 CYBERSEC PROJECT          |
                          └───────────────────────────────────────────────────┘
"""

DB_PATH = "db_ingest.db"

VENV_CONFIG = {
    "ingest_env":  "requirements_ingest.txt",
    "scan_env":    "requirements_scan.txt",
    "ai_env":      "requirements_ai.txt",
}

# ───────────────────────────────────────────────────────────────────────── #
# LOG                                                                       #
# ───────────────────────────────────────────────────────────────────────── #
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("cli")

# ───────────────────────────────────────────────────────────────────────── #
# DIRS & ENV INIT                                                           #
# ───────────────────────────────────────────────────────────────────────── #

BASE_DIRS = ["models", "cache", "exports", "ingest_exports"]

def init_dirs() -> None:
    for d in BASE_DIRS:
        Path(d).mkdir(parents=True, exist_ok=True)

def init_envs():
    python_exe = sys.executable  # interpreter corrente
    for env, req in VENV_CONFIG.items():
        if not os.path.isdir(env):
            print(f"[+] Creating venv '{env}'")
            subprocess.run([python_exe, "-m", "venv", env], check=True)
            pip_path = os.path.join(env, "bin", "pip") if os.name != "nt" else os.path.join(env, "Scripts", "pip.exe")
            if os.path.exists(req):
                print(f"[+] Installing {req} into {env}")
                subprocess.run([pip_path, "install", "-r", req], check=True)
            else:
                print(f"[!] {req} not found, skipping installs for {env}.")
        else:
            print(f"[+] Environment '{env}' already exists.")

# ───────────────────────────────────────────────────────────────────────── #
# DB INIT & STORAGE                                                         #
# ───────────────────────────────────────────────────────────────────────── #

def init_db():
    if not os.path.exists(DB_PATH):
        print("[+] Creating local ingestion database...")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS ingestions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                type TEXT NOT NULL,
                content TEXT,
                timestamp TEXT
            );
        """)
        conn.commit()
        conn.close()
    else:
        print("[+] Ingestion database found.")

def save_ingestion(source: str, content: str, content_type: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO ingestions (source, type, content, timestamp) VALUES (?, ?, ?, ?)",
              (source, content_type, content[:10000], datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    print(f"[✓] Ingestion from '{source}' saved in database.")

# ───────────────────────────────────────────────────────────────────────── #
# UTIL                                                                      #
# ───────────────────────────────────────────────────────────────────────── #

def _ask(prompt: str, default: Optional[str] = None) -> str:
    hint = f" [{default}]" if default is not None else ""
    try:
        s = input(f"{prompt}{hint}: ").strip()
    except EOFError:
        s = ""
    return s or (default or "")

def _resolve_path(p: str) -> str:
    return os.path.abspath(os.path.expandvars(os.path.expanduser(p)))

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

def _bool_env(val: bool) -> str:
    return "1" if val else "0"

# ───────────────────────────────────────────────────────────────────────── #
# CONFIG                                                                    #
# ───────────────────────────────────────────────────────────────────────── #

CONFIG_PATH = Path("config.yaml")

def _ensure_config(config_path: Path) -> Dict[str, Any]:
    """
    Crea/aggiorna config minimo e chiavi richieste:
      - securebert_path
      - profile_default, export_default
      - defaults per renderer/sonda
    """
    base: Dict[str, Any] = {
        "endpoints_file": "endpoints.txt",
        "output_file": "exports/orchestrator_output.json",
        "output_csv": "exports/orchestrator_results.csv",
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
        "securebert_path": "models/SecureBERT/",  # percorso locale snapshot
        "probe": {"profile": "light", "budget": {}},
    }
    if not config_path.exists():
        try:
            import yaml  # type: ignore
            config_path.write_text(yaml.safe_dump(base), encoding="utf-8")
        except Exception:
            config_path.write_text(json.dumps(base, indent=2), encoding="utf-8")
        return base

    # merge con esistente
    try:
        import yaml  # type: ignore
        existing = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if isinstance(existing, dict):
            base.update(existing)
    except Exception:
        try:
            existing = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                base.update(existing)
        except Exception:
            pass

    # Normalizza campi noti
    if base.get("profile_default") not in ("light", "standard", "deep"):
        base["profile_default"] = "light"
    if base.get("export_default") not in ("none", "json", "csv", "both"):
        base["export_default"] = "none"

    # Scrivi back (idempotente)
    try:
        import yaml  # type: ignore
        config_path.write_text(yaml.safe_dump(base), encoding="utf-8")
    except Exception:
        config_path.write_text(json.dumps(base, indent=2), encoding="utf-8")
    return base

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

def doctor() -> Dict[str, Any]:
    """
    Preflight: disco, permessi, rete, dipendenze opzionali, feature flags.
    """
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
        tmp = Path(".bg_write_test")
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

    print(json.dumps(report, indent=2))
    return report

# ───────────────────────────────────────────────────────────────────────── #
# ASCII Renderer (fallback se manca output_formatter)                        #
# ───────────────────────────────────────────────────────────────────────── #

def _severity_bucket(rec: Dict[str, Any]) -> str:
    g = rec.get("get", {}) or {}
    st = g.get("status") or 0
    waf = bool(g.get("waf"))
    if isinstance(st, int) and 500 <= st <= 599:
        return "high"
    if waf:
        return "medium"
    if isinstance(st, int) and 400 <= st <= 499:
        return "medium"
    return "low"

def render_ascii(results: List[Dict[str, Any]], page: int = 1, page_size: int = 100, profile: str = "standard",
                 legend: Optional[str] = None, top_domains: Optional[dict] = None) -> str:
    if _of_render_summary and _of_render_table:
        summary = _of_render_summary(results)
        table = _of_render_table(results, legend=legend, top_domains=top_domains, page=page, page_size=page_size)
        return summary + "\n" + table

    # Fallback minimale
    results = sorted(results, key=lambda r: (-(r.get("score") or 0.0), (r.get("get", {}) or {}).get("status") or 0))
    tot = len(results)
    sev = {"high": 0, "medium": 0, "low": 0}
    for r in results:
        sev[_severity_bucket(r)] += 1

    def pct(x: int) -> str:
        return f"{(100.0 * x / max(1, tot)):.1f}%"

    import math
    pages = max(1, math.ceil(tot / max(1, page_size)))
    page = max(1, min(page, pages))
    start = (page - 1) * page_size
    end = min(start + page_size, tot)
    chunk = results[start:end]

    head: List[str] = []
    head.append(f"Results: {tot}  |  Page {page}/{pages}  |  High: {sev['high']} ({pct(sev['high'])})  "
                f"Med: {sev['medium']} ({pct(sev['medium'])})  Low: {sev['low']} ({pct(sev['low'])})")
    head.append("-" * 140)
    col = {"rank": 5, "score": 6, "meth": 5, "status": 6, "lat": 7, "size": 8, "type": 14, "waf": 5, "flags": 18, "url": 60}
    header = (f"{'#':>{col['rank']}}  {'SCORE':>{col['score']}}  {'METH':^{col['meth']}}  "
              f"{'STAT':^{col['status']}}  {'LAT(ms)':>{col['lat']}}  {'SIZE':>{col['size']}}  "
              f"{'TYPE':<{col['type']}}  {'WAF':^{col['waf']}}  {'FLAGS':<{col['flags']}}  {'URL':<{col['url']}}")
    lines = [header, "-" * len(header)]
    for i, r in enumerate(chunk, start=start + 1):
        g = r.get("get", {}) or {}
        st = g.get("status", "")
        lat = g.get("latency_ms", "")
        size = g.get("size", "")
        ctype = (g.get("content_type") or "")[:col["type"]]
        waf = "Y" if g.get("waf") else ""
        flags = ",".join(r.get("flags") or [])[:col["flags"]]
        meth = "".join([m[0] for m in ["GET", "HEAD", "OPTIONS", "POST"] if r.get(m.lower())])[:3]
        score = f"{(r.get('score') or 0.0):.2f}"
        url = (r.get("url") or "")[:col["url"]]
        lines.append(f"{i:>{col['rank']}}  {score:>{col['score']}}  {meth:^{col['meth']}}  "
                     f"{str(st):^{col['status']}}  {str(lat):>{col['lat']}}  {str(size):>{col['size']}}  "
                     f"{ctype:<{col['type']}}  {waf:^{col['waf']}}  {flags:<{col['flags']}}  {url:<{col['url']}}")
    return "\n".join(head + lines)

# ───────────────────────────────────────────────────────────────────────── #
# FLOWS: Ingest / Scan (deleghe o fallback locali)                           #
# ───────────────────────────────────────────────────────────────────────── #

def ingest_flow():
    """
    Preferisci cli_ingest.run_ingest_interactive(); fallback a sottoprocesso.
    """
    if _ingest_entry:
        return _ingest_entry()
    path = input("→ Enter file path or URL to ingest: ").strip()
    if not path:
        print("[!] No input provided.")
        return
    try:
        pybin = "ingest_env/bin/python" if os.name != "nt" else "ingest_env\\Scripts\\python.exe"
        subprocess.run([pybin, "-u", "cli_ingest.py", path], check=True)
        print("[✓] Ingestion completed.")
    except Exception as e:
        print(f"[X] Ingestion failed: {e}")

def scan_flow():
    """
    Preferisci cli_scan.run_scan_interactive(); fallback locale minimale.
    """
    if _scan_entry:
        return _scan_entry()

    ep_path = _ask("→ Enter path to endpoints .txt file", "endpoints.txt")
    if not ep_path:
        print("[!] No endpoints file provided.")
        return
    ep_path = _resolve_path(ep_path)
    p = Path(ep_path)
    if not p.exists():
        print(f"[X] File non trovato: {ep_path}")
        return
    if _count_endpoints(p) == 0:
        print(f"[X] Nessun endpoint valido in: {ep_path}")
        return

    profile = _ask("Profile [light/standard/deep]", "standard").strip().lower()
    if profile not in ("light", "standard", "deep"):
        profile = "standard"
    page_size = int(_ask("Page size", "100") or "100")
    export_choice = _ask("Export [none/json/csv/both]", "none").strip().lower()
    if export_choice not in ("none", "json", "csv", "both"):
        export_choice = "none"
    write_outputs = export_choice != "none"

    print(f"[AI] {_ai_status_banner()}")

    cfg = _ensure_config(CONFIG_PATH)
    cfg["endpoints_file"] = ep_path
    cfg["probe"] = {"profile": profile, "budget": {}}
    cfg["write_outputs"] = write_outputs
    cfg["export_format"] = export_choice
    if profile == "light":
        cfg["top_n"] = 0
    try:
        import yaml  # type: ignore
        CONFIG_PATH.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    except Exception:
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    os.environ["SCAN_ENDPOINTS_FILE"] = ep_path
    os.environ["BG_PROFILE"] = profile
    os.environ["BG_WRITE_OUTPUTS"] = _bool_env(write_outputs)
    os.environ["SCAN_EXPORT_FORMAT"] = export_choice

    try:
        from orch_report import main_orchestrator  # type: ignore
    except Exception as e:
        print(f"[X] Impossibile importare orchestratore: {e}")
        return

    print("[…] Starting full scan via orchestrator…")
    try:
        output = main_orchestrator(str(CONFIG_PATH))
        if not isinstance(output, dict):
            print("[?] Nessun output ritornato dall'orchestratore.")
            return
    except Exception as e:
        print(f"[X] Scan failed: {e}")
        return

    _print_scan_output(output)


# ───────────────────────────────────────────────────────────────────────── #
# EXPORTS DB (conservati)                                                    #
# ───────────────────────────────────────────────────────────────────────── #

def export_txt(filename="export_ingestions.txt"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, source, type, timestamp, content FROM ingestions")
    rows = c.fetchall()
    conn.close()
    with open(filename, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(f"[{row[0]}] {row[1]} ({row[2]}) at {row[3]}\n")
            f.write(f"{row[4][:500]}\n{'-'*80}\n")
    print(f"[✓] Exported to {filename}")

def export_pdf(filename="export_ingestions.pdf"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, source, type, timestamp, content FROM ingestions")
    rows = c.fetchall()
    conn.close()
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    for row in rows:
        pdf.multi_cell(0, 6, f"[{row[0]}] {row[1]} ({row[2]}) at {row[3]}", 0, 1)
        pdf.multi_cell(0, 6, row[4][:1000], 0, 1)
        pdf.cell(0, 10, "-" * 80, ln=True)
    pdf.output(filename)
    print(f"[✓] Exported to {filename}")

# ───────────────────────────────────────────────────────────────────────── #
# CONFIG MENU                                                                #
# ───────────────────────────────────────────────────────────────────────── #

def _save_config(cfg: Dict[str, Any]) -> None:
    try:
        import yaml  # type: ignore
        CONFIG_PATH.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    except Exception:
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

def config_menu():
    cfg = _ensure_config(CONFIG_PATH)
    print("\n[Config — valori attuali]")
    print(json.dumps({
        "securebert_path": cfg.get("securebert_path"),
        "profile_default": cfg.get("profile_default"),
        "export_default": cfg.get("export_default"),
        "page_size_default": cfg.get("page_size_default"),
        "concurrency_default": cfg.get("concurrency_default"),
        "timeout_s_default": cfg.get("timeout_s_default"),
        "retries_default": cfg.get("retries_default"),
        "output_file": cfg.get("output_file"),
        "output_csv": cfg.get("output_csv"),
    }, indent=2))

    # Edit interattivo (invio = mantieni)
    sb = _ask("→ SecureBERT path", cfg.get("securebert_path") or "models/SecureBERT/")
    prof = _ask("→ Default profile [light/standard/deep]", cfg.get("profile_default") or "light").lower()
    if prof not in ("light", "standard", "deep"):
        prof = "light"
    exp = _ask("→ Default export [none/json/csv/both]", cfg.get("export_default") or "none").lower()
    if exp not in ("none", "json", "csv", "both"):
        exp = "none"
    psize = _ask("→ Default rows/page", str(int(cfg.get("page_size_default", 100))))
    conc = _ask("→ Default concurrency", str(int(cfg.get("concurrency_default", 8))))
    tout = _ask("→ Default timeout (s)", str(float(cfg.get("timeout_s_default", 10.0))))
    retr = _ask("→ Default retries", str(int(cfg.get("retries_default", 1))))

    cfg["securebert_path"] = sb
    cfg["profile_default"] = prof
    cfg["export_default"] = exp
    try:
        cfg["page_size_default"] = max(1, int(psize))
    except Exception:
        pass
    try:
        cfg["concurrency_default"] = max(1, int(conc))
    except Exception:
        pass
    try:
        cfg["timeout_s_default"] = max(0.1, float(tout))
    except Exception:
        pass
    try:
        cfg["retries_default"] = max(0, int(retr))
    except Exception:
        pass

    # Crea dirs e setta ENV utili
    init_dirs()
    os.environ["SECUREBERT_PATH"] = str(cfg["securebert_path"])

    _save_config(cfg)
    print("\n[✓] Config salvata.")
    print(f"[i] Modelli: {cfg['securebert_path']}")
    print(f"[i] Profili default: {cfg['profile_default']}  |  Export default: {cfg['export_default']}")
    print("[i] Dirs verificate: " + ", ".join(str(Path(d).resolve()) for d in BASE_DIRS))
    print("")

# ───────────────────────────────────────────────────────────────────────── #
# LEGEND / HELP                                                              #
# ───────────────────────────────────────────────────────────────────────── #

def print_legend(thresholds=None) -> None:
    """
    Stampa la legenda/guida alla lettura della tabella.
    thresholds: dict opzionale con chiavi {'high': float, 'medium': float}.
    """
    thresholds = thresholds or {"high": 0.75, "medium": 0.40}
    try:
        hi = float(thresholds.get("high", 0.75))
        md = float(thresholds.get("medium", 0.40))
    except Exception:
        hi, md = 0.75, 0.40

    legend = f"""
LEGEND
------

COLUMNS (render_ready):
- SCORE     … rischio [0–1]
- SEVERITY  … High ≥ {hi:.2f} · Medium ≥ {md:.2f} · altrimenti Low
- TYPE      … MIME finale post-redirect (es. application/json)
- FAMILY    … famiglia funzionale (API/AUTH/OTT/CACHE/… da KB+path+host+type)
- RISK      … superfici d’attacco rilevate: xss|sqli|cors|auth|dirlist|weak-headers
- WAF       … vendor WAF/CDN rilevati; "None" = nessun WAF rilevato
- METH      … metodo osservato (GET/POST)
- STAT      … status code finale
- LAT(ms)   … latenza in millisecondi
- SIZE      … dimensione body risposta (bytes)
- FLAGS     … marcatori compatti: +XSS +SQLI +CORS +AUTH +DIR +WEAKHDRS (+ENV:DEV, +GEO:HK, …)
- URL       … endpoint sondato

NOTE
- RISK vs FLAGS: RISK è la stringa pipe-delimited (es. "xss|cors"); FLAGS sono token prefissati (+XSS/+SQLI/…).
- Le soglie High/Medium sono **le stesse** usate nel Summary.
- WAF="None" indica endpoint apparentemente **privo** di protezione WAF/CDN comune.
"""
    print(legend.strip())

# ───────────────────────────────────────────────────────────────────────── #
# MENU                                                                       #
# ───────────────────────────────────────────────────────────────────────── #

def main_menu():
    print(ASCII_HEADER)
    init_dirs()
    _ = _ensure_config(CONFIG_PATH)
    os.environ["SECUREBERT_PATH"] = str(_["securebert_path"])
    init_db()

    print("Welcome to the GHOSTSHINOBI Cybersec CLI\n")
    print("Select an option:\n")
    print("1 - Start Scan")
    print("2 - Ingest File or URL")
    print("3 - Config")
    print("4 - Legend / Help")
    print("9 - Doctor (preflight)")
    print("0 - Exit\n")

    while True:
        try:
            choice = input("Your choice > ").strip()
        except KeyboardInterrupt:
            print("\n[!] Exit requested.")
            break

        if choice == "1":
            print(f"[AI] {_ai_status_banner()}")
            scan_flow()
        elif choice == "2":
            ingest_flow()
        elif choice == "3":
            config_menu()
        elif choice == "4":
            print_legend()
        elif choice == "9":
            doctor()
        elif choice == "0":
            print("Goodbye.")
            break
        else:
            print("Invalid option. Try again.")

if __name__ == "__main__":
    try:
        init_dirs()
        init_envs()
        main_menu()
    except KeyboardInterrupt:
        print("\n[Interrupted]")
