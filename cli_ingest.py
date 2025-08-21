# cli_ingest.py — Wrapper ingest (manifest + export + summary + endpoints clean)
# Obiettivo: caricare endpoints o dataset per NLP/scan.
# - Validazioni file (txt,csv,json,yaml,pdf) → lista endpoints pulita (http/https)
# - Feedback: quanti validi, quanti scartati, perché
# - Mantiene export di testo/parsed + (opz.) indicizzazione in vector_store

from __future__ import annotations

import os
import sys
import re
import json
import time
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("cli_ingest")

EXPORT_DIR = Path("ingest_exports")


# ───────────────────────────────────────────────────────────────────────── #
# Helpers                                                                   #
# ───────────────────────────────────────────────────────────────────────── #

def _ask(prompt: str, default: Optional[str] = None) -> str:
    hint = f" [{default}]" if default is not None else ""
    try:
        s = input(f"{prompt}{hint}: ").strip()
    except EOFError:
        s = ""
    return s or (default or "")

def _is_url(s: str) -> bool:
    s = (s or "").lower()
    return s.startswith("http://") or s.startswith("https://")

def _detect_type(path_or_url: str) -> str:
    if _is_url(path_or_url):
        return "url"
    suffix = Path(path_or_url).suffix.lower()
    if suffix in (".txt", ".json", ".yaml", ".yml", ".csv", ".pdf"):
        return suffix[1:]
    return "unknown"

def _slugify(name: str) -> str:
    base = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in (name or "").strip())
    return base.strip("._") or f"ingest_{int(time.time())}"

def _abs_path(p: Path) -> str:
    try:
        return str(p.resolve())
    except Exception:
        return str(p.absolute())

def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="ignore")

def _write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")

def _summary_from_parsed(parsed: Any) -> Tuple[str, Dict[str, Any]]:
    """
    Ritorna (text, meta) dove:
      - text: testo “utile” da salvare/indicizzare
      - meta: metadati leggeri per manifest
    Funziona sia con ParsedDoc dict (ingest_auto return_parsed=True) sia con str/list/altro.
    """
    text = ""
    meta: Dict[str, Any] = {}
    if isinstance(parsed, dict):
        text = str(parsed.get("text") or "")
        urls = parsed.get("urls") or []
        hints = parsed.get("hints") or []
        ctype = parsed.get("content_type") or parsed.get("type")
        meta = {
            "type": parsed.get("type") or "unknown",
            "content_type": ctype,
            "url_count": len(urls) if isinstance(urls, list) else 0,
            "hints": hints,
            "meta": parsed.get("meta") or {},
        }
    elif isinstance(parsed, list):
        text = "\n".join(map(lambda x: str(x), parsed))
        meta = {"type": "list", "items": len(parsed)}
    elif isinstance(parsed, str):
        text = parsed
        meta = {"type": "text", "chars": len(text)}
    else:
        text = str(parsed)
        meta = {"type": type(parsed).__name__}
    return text, meta

# Estrazione regex robusta (fallback): http(s)://… senza spazi/virgolette finali
_URL_RE = re.compile(r"https?://[^\s\"\'<>]+", re.IGNORECASE)

def _regex_extract_urls(text: str) -> List[str]:
    return list(dict.fromkeys(_URL_RE.findall(text or "")))

def _maybe_ingest_helpers():
    """
    Prova a importare da ingest_normalize; ritorna (load_endpoints, clean_url, unique_filter).
    Fallback a impl. semplici e sicure.
    """
    try:
        from ingest_normalize import load_endpoints, clean_url, unique_filter  # type: ignore
        return load_endpoints, clean_url, unique_filter
    except Exception:
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

def _validate_and_clean_endpoints(raw_eps: List[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
    """
    - Normalizza e deduplica
    - Tiene solo http/https con netloc valido
    Ritorna (validi, scartati_con_motivo)
    """
    load_endpoints, clean_url, unique_filter = _maybe_ingest_helpers()
    cleaned = unique_filter([clean_url(u) for u in (raw_eps or [])])

    valid: List[str] = []
    rejected: List[Tuple[str, str]] = []
    from urllib.parse import urlparse
    for u in cleaned:
        try:
            p = urlparse(u)
            if p.scheme not in ("http", "https"):
                rejected.append((u, "non-http(s)"))
                continue
            if not p.netloc:
                rejected.append((u, "netloc mancante"))
                continue
            # sanitize: strip spaces and control chars
            su = u.strip().replace("\r", "").replace("\n", "")
            valid.append(su)
        except Exception:
            rejected.append((u, "malformato"))
    # dedup finale preservando ordine
    seen = set()
    out: List[str] = []
    for u in valid:
        if u not in seen:
            out.append(u)
            seen.add(u)
    return out, rejected

def _guess_endpoints_mode(kind: str, parsed: Any, path: Optional[Path]) -> bool:
    """
    Euristica per proporre 'modalità endpoints':
    - file .txt con >0 righe non commentate
    - parsed.urls presenti
    - testo con ≥3 URL http(s) distinti
    """
    if kind == "txt" and path and path.exists():
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        return True
        except Exception:
            pass
    if isinstance(parsed, dict) and isinstance(parsed.get("urls"), list) and len(parsed.get("urls")) > 0:
        return True
    text, _ = _summary_from_parsed(parsed)
    if len(set(_regex_extract_urls(text))) >= 3:
        return True
    return False


# ───────────────────────────────────────────────────────────────────────── #
# Run                                                                       #
# ───────────────────────────────────────────────────────────────────────── #

def run_ingest_interactive() -> None:
    # 1) Input
    target = sys.argv[1] if len(sys.argv) > 1 else _ask("→ Path o URL da ingerire")
    if not target:
        print("[X] Nessun input fornito.")
        return
    kind = _detect_type(target)

    # Validazione file/URL
    if not _is_url(target):
        p = Path(target)
        if not p.exists():
            print(f"[X] File non trovato: {p}")
            return
        abs_in = _abs_path(p)
    else:
        p = None
        abs_in = target

    # 2) Ingestion (parsed)
    try:
        from ingest_normalize import ingest_auto  # type: ignore
    except Exception as e:
        print(f"[X] Modulo ingest_normalize non disponibile: {e}")
        return

    print("[…] Ingestion in corso (seriale)…")
    try:
        parsed = ingest_auto(target, opts={"return_parsed": True})
    except Exception as e:
        print(f"[X] Ingestion fallita: {e}")
        return

    text, meta = _summary_from_parsed(parsed)
    text_len = len(text or "")

    # 3) Chiedi modalità: endpoints o dataset
    default_mode_is_endpoints = _guess_endpoints_mode(kind, parsed, p)
    mode = _ask("Trattare come endpoints? [y/N]", "Y" if default_mode_is_endpoints else "N").strip().lower()
    as_endpoints = mode.startswith("y")

    # 4) Export base (manifest + testo + parsed)
    ts = int(time.time())
    base = _slugify(Path(target).name if not _is_url(target) else target.replace("://", "_"))
    base_dir = EXPORT_DIR / f"{base}_{ts}"
    text_path = base_dir / "content.txt"
    parsed_path = base_dir / "parsed.json"
    manifest_path = base_dir / "manifest.json"

    try:
        _write_text(text_path, text)
        _write_json(parsed_path, parsed if isinstance(parsed, dict) else {"value": parsed})
    except Exception as e:
        print(f"[X] Export fallito: {e}")
        return

    # 5) Se endpoints: estrai/valida/normalizza + export
    endpoints_valid: List[str] = []
    endpoints_rejected: List[Tuple[str, str]] = []
    endpoints_from = "none"

    if as_endpoints:
        raw_eps: List[str] = []

        # Fonte 1: file .txt line-by-line
        if kind == "txt" and p:
            try:
                with p.open("r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        s = line.strip()
                        if s and not s.startswith("#"):
                            raw_eps.append(s)
                endpoints_from = "txt_lines"
            except Exception:
                pass

        # Fonte 2: parsed.urls (se presenti)
        if not raw_eps and isinstance(parsed, dict) and isinstance(parsed.get("urls"), list):
            raw_eps = [str(x) for x in parsed.get("urls") if isinstance(x, (str, bytes))]
            endpoints_from = "parsed.urls"

        # Fonte 3: regex sul testo
        if not raw_eps and text_len:
            raw_eps = _regex_extract_urls(text)
            endpoints_from = "text_regex"

        # Validazione + cleaning
        endpoints_valid, endpoints_rejected = _validate_and_clean_endpoints(raw_eps)

        # Export endpoints
        endpoints_txt = base_dir / "endpoints_clean.txt"
        rejected_txt = base_dir / "endpoints_rejected.txt"
        if endpoints_valid:
            _write_text(endpoints_txt, "\n".join(endpoints_valid) + "\n")
        if endpoints_rejected:
            rej_lines = [f"# {reason} | {raw}" for (raw, reason) in endpoints_rejected]
            _write_text(rejected_txt, "\n".join(rej_lines) + ("\n" if rej_lines else ""))

    # 6) Manifest completo
    manifest: Dict[str, Any] = {
        "source": target,
        "source_abs": abs_in if not _is_url(target) else None,
        "detected_type": kind,
        "mode": "endpoints" if as_endpoints else "dataset",
        "export": {
            "text": _abs_path(text_path),
            "parsed": _abs_path(parsed_path),
        },
        "summary": {
            "text_chars": text_len,
            "preview": text[:160].replace("\n", " ") if text_len else "",
            **meta,
        },
        "generated_at": ts,
        "version": 2,
    }
    if as_endpoints:
        manifest["endpoints"] = {
            "source_kind": endpoints_from,
            "valid": len(endpoints_valid),
            "rejected": len(endpoints_rejected),
            "export_txt": _abs_path(base_dir / "endpoints_clean.txt") if endpoints_valid else None,
            "export_rejected": _abs_path(base_dir / "endpoints_rejected.txt") if endpoints_rejected else None,
            "reasons": _aggregate_reasons(endpoints_rejected),
        }
    _write_json(manifest_path, manifest)

    # 7) (Opzionale) indicizzazione in vector_store (solo dataset o sempre? teniamo sempre)
    added_to_store = False
    vs_stats = None
    try:
        from vector_store import add_document, stats  # type: ignore
        if text_len:
            add_document(text, meta={"source": target, "export": str(text_path)})
            vs_stats = stats()
            added_to_store = True
    except Exception:
        pass

    # 8) Summary chiaro a schermo
    print("\n[✓] Ingestion completata.")
    print(f"[i] Sorgente: {abs_in if not _is_url(target) else target}")
    print(f"[i] Tipo rilevato: {kind}  |  Modalità: {'endpoints' if as_endpoints else 'dataset'}")
    print(f"[i] Testo estratto: {text_len} chars")
    if isinstance(meta.get("url_count"), int):
        print(f"[i] URL trovati (parser): {meta.get('url_count')}")
    if meta.get("hints"):
        print(f"[i] Hints: {', '.join(map(str, meta.get('hints', [])))[:120]}")
    print(f"[i] Export (testo):   {_abs_path(text_path)}")
    print(f"[i] Export (parsed):  {_abs_path(parsed_path)}")
    print(f"[i] Manifest:         {_abs_path(manifest_path)}")

    if as_endpoints:
        v = len(endpoints_valid)
        r = len(endpoints_rejected)
        print(f"[i] Endpoints validi: {v}  |  Scartati: {r}")
        if v:
            print(f"    → {_abs_path(base_dir / 'endpoints_clean.txt')}")
        if r:
            print(f"    → {_abs_path(base_dir / 'endpoints_rejected.txt')}")
            reasons = _aggregate_reasons(endpoints_rejected)
            if reasons:
                print("    Motivi scarto (top): " + ", ".join([f"{k}={reasons[k]}" for k in list(reasons.keys())[:5]]))

    if added_to_store:
        print(f"[i] Aggiunto a search store. Stats: {vs_stats}")
    print("")


# ───────────────────────────────────────────────────────────────────────── #
# Utils interni                                                              #
# ───────────────────────────────────────────────────────────────────────── #

def _aggregate_reasons(rejected: List[Tuple[str, str]]) -> Dict[str, int]:
    acc: Dict[str, int] = {}
    for _, reason in rejected or []:
        acc[reason] = acc.get(reason, 0) + 1
    return acc


if __name__ == "__main__":
    try:
        run_ingest_interactive()
    except KeyboardInterrupt:
        print("\n[Interrupted]")
