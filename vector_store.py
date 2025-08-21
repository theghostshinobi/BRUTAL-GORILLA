# vector_store.py
# Store & memoria temporale — leggero, senza import pesanti a top-level.
# Patch NON distruttiva:
# - Aggiunto supporto embeddings SecureBERT (solo backbone) per dedup/cluster/similar
# - Persistenza locale semplice via SQLite (fallback Parquet se pandas+pyarrow)
# - API per "trova host simili" (by URL o testo) + dedup/cluster
# - Mantiene API esistenti (stats/history/ingest/search) e continua a funzionare senza embeddings

from __future__ import annotations

import os
import io
import pickle
import sqlite3
import logging
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Cache prototipi (etichetta -> embedding vettoriale)
_LABEL_EMB_CACHE: dict[str, list[float]] = {}

def _cos_sim(a: list[float], b: list[float]) -> float:
    import math
    if not a or not b or len(a) != len(b):
        return 0.0
    num = sum(x*y for x, y in zip(a, b))
    da = math.sqrt(sum(x*x for x in a))
    db = math.sqrt(sum(y*y for y in b))
    if da <= 1e-12 or db <= 1e-12:
        return 0.0
    return float(num / (da * db))

def _ensure_adapter(secure_handle=None):
    """
    Ritorna un oggetto con metodo .embed(text) oppure None.
    - Se è passato un handle tipo orch_report._SecureBERTHandle, usa quello.
    - Altrimenti prova a importare securebert_adapter e caricare da env SECUREBERT_PATH.
    """
    if secure_handle is not None and getattr(secure_handle, "adapter", None):
        return secure_handle.adapter
    try:
        import os
        import securebert_adapter  # type: ignore
        path = os.getenv("SECUREBERT_PATH", "")
        if hasattr(securebert_adapter, "load") and path:
            return securebert_adapter.load(path)  # type: ignore
        if hasattr(securebert_adapter, "embed"):
            return securebert_adapter  # type: ignore
        if hasattr(securebert_adapter, "SecureBERT") and path:
            return securebert_adapter.SecureBERT(path)  # type: ignore
    except Exception:
        return None
    return None

def _label_set_default() -> dict[str, str]:
    """
    Descrizioni compatte per creare prototipi semantici.
    (etichettario limitato e stabile)
    """
    return {
        "API":              "REST JSON API endpoint, application/json, versioned path like /v1/, graphql",
        "AUTH":             "login, signin, oauth, token, sso, saml, authorize",
        "CACHE":            "cdn, cache, static content, image delivery, origin",
        "OTT":              "video streaming, watch, playback, stream, hls, dash",
        "MASS_ASSIGNMENT":  "admin backend, wp-admin, backoffice, privileged forms",
        "IDOR":             "user id parameter access object reference predictable ids",
        "TRAVERSAL":        "path traversal, directory structure, content browsing",
        "CMS":              "wordpress wp-json wp-content wp-includes drupal joomla",
        "UPLOAD":           "file upload media multipart form-data put file",
        "GENERIC":          "generic web endpoint, html page, miscellaneous",
    }

def _embed_text(adapter, text: str) -> list[float]:
    """
    Chiama adapter.embed(text) e ritorna una lista di float (flatten).
    """
    try:
        vec = adapter.embed(text)  # type: ignore
        # supporta sia list che np.array
        if hasattr(vec, "tolist"):
            vec = vec.tolist()
        # flatten
        return [float(x) for x in (vec or [])]
    except Exception:
        return []

def _prototypes(adapter, labels_desc: dict[str, str]) -> dict[str, list[float]]:
    """
    Costruisce o recupera da cache gli embedding dei prototipi.
    """
    global _LABEL_EMB_CACHE
    out: dict[str, list[float]] = {}
    for lab, desc in (labels_desc or {}).items():
        if lab in _LABEL_EMB_CACHE and _LABEL_EMB_CACHE[lab]:
            out[lab] = _LABEL_EMB_CACHE[lab]
            continue
        emb = _embed_text(adapter, f"{lab}: {desc}")
        if emb:
            _LABEL_EMB_CACHE[lab] = emb
            out[lab] = emb
    return out

def _serialize_context(ctx: dict) -> str:
    """
    Concatena segnali testuali stabili dal record/contesto.
    """
    url = str(ctx.get("url") or "")
    path = str(ctx.get("path") or "")
    ctype = str(ctx.get("content_type_final") or ctx.get("type") or "")
    params = ctx.get("params") or []
    flags = ctx.get("flags") or []
    headers = ctx.get("headers") or {}
    allow = ctx.get("allowed_methods") or ctx.get("allow_methods") or []
    hints = []
    if ctype:
        hints.append(f"ctype={ctype}")
    if path:
        hints.append(f"path={path}")
    if params:
        hints.append("params=" + ",".join(sorted({str(p) for p in params})))
    if flags:
        hints.append("flags=" + ",".join(sorted({str(f) for f in flags})))
    if allow:
        hints.append("methods=" + ",".join(sorted({str(m) for m in allow})))
    if headers:
        hsel = []
        for k in ("access-control-allow-origin","content-security-policy","x-frame-options","strict-transport-security"):
            v = headers.get(k) or headers.get(k.title())
            if v:
                hsel.append(f"{k}={v}")
        if hsel:
            hints.append("headers=" + ",".join(hsel))
    if url and not path:
        from urllib.parse import urlsplit
        path = urlsplit(url).path or ""
        if path:
            hints.append(f"path={path}")
    return " | ".join(hints) if hints else (url or path or ctype or "")

def semantic_family_vote(
    context: dict,
    *,
    secure_handle=None,
    labels_desc: dict[str, str] | None = None,
    min_confidence: float = 0.58
) -> str:
    """
    Assegna una FAMILY funzionale via similarità semantica (fallback AI).
    - Usa SecureBERT (se disponibile) per confrontare il testo di contesto con prototipi fissi.
    - Ritorna una stringa tra le etichette note (API/AUTH/...) oppure "" se confidenza bassa.
    """
    adapter = _ensure_adapter(secure_handle)
    if adapter is None:
        return ""
    labels = labels_desc or _label_set_default()
    protos = _prototypes(adapter, labels)
    if not protos:
        return ""

    text = _serialize_context(context)
    if not text:
        return ""

    vec = _embed_text(adapter, text)
    if not vec:
        return ""

    # Seleziona la label col coseno massimo
    best_lab, best_sim = "", 0.0
    for lab, proto in protos.items():
        sim = _cos_sim(vec, proto)
        if sim > best_sim:
            best_lab, best_sim = lab, sim

    return best_lab if best_sim >= float(min_confidence) else ""
s
# ------------------------------------------------------------------------------
# Stato in-memory (compat pre-esistente)
# ------------------------------------------------------------------------------

_SCAN_RESULTS: List[Dict[str, Any]] = []
_URL_HISTORY: Dict[str, Deque[Dict[str, Any]]] = {}
_BY_DOMAIN: Dict[str, List[int]] = {}
_BY_URL: Dict[str, List[int]] = {}
_DOCS: List[Dict[str, Any]] = []
_KEYWORD_INDEX: Dict[str, set] = {}

# Embedding backend (legacy per funzioni di ricerca compat)
_EMB_MODEL = None       # SentenceTransformer
_FAISS = None
_EMBEDDINGS = None
_REDUCER = None
_FAISS_INDEX = None

# --- NOVITÀ: stats per dominio + storia tentativi -----------------------------
_DOMAIN_STATS: Dict[str, Dict[str, Any]] = {}  # {domain: {"families": {...}, "transforms": {...}, "last_updated": ts}}
_ATTEMPT_HISTORY_GLOBAL: Deque[Dict[str, Any]] = deque(maxlen=1000)
_ATTEMPT_HISTORY_BY_DOMAIN: Dict[str, Deque[Dict[str, Any]]] = {}
_ATTEMPT_HISTORY_BY_URL: Dict[str, Deque[Dict[str, Any]]] = {}

# Persistenza (compat con vecchi nomi file)
REDUCER_PATH = "vector_reducer.pkl"
INDEX_PATH = "vector_index.faiss"
CHUNKS_PATH = "vector_chunks.pkl"
EMB_PATH = "vector_embeddings.pkl"
STATS_PATH = "vector_domain_stats.pkl"
ATTEMPTS_PATH = "vector_attempts.pkl"

# --- NOVITÀ persistenza SecureBERT -------------------------------------------
DB_PATH = "vector_store.sqlite"         # default SQLite
PARQUET_PATH = "vector_store.parquet"   # fallback opzionale

# Schema SQLite:
#   vectors(url TEXT PRIMARY KEY, text TEXT, dim INTEGER, embedding BLOB)
#   meta(key TEXT PRIMARY KEY, value TEXT)

# ------------------------------------------------------------------------------
# Utils base
# ------------------------------------------------------------------------------

def _domain_of(url: str) -> str:
    try:
        return urlsplit(url).netloc.lower()
    except Exception:
        return ""

def _tokenize(text: str) -> List[str]:
    import re
    return re.findall(r"[A-Za-z0-9_]{2,}", (text or "").lower())

def _ensure_numpy():
    try:
        import numpy as np  # type: ignore
        return np
    except Exception as e:
        logger.debug("numpy non disponibile: %s", e)
        return None

def _ensure_sentence_model():
    global _EMB_MODEL
    if _EMB_MODEL is not None:
        return _EMB_MODEL
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore
        _EMB_MODEL = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")
        return _EMB_MODEL
    except Exception as e:
        logger.warning("SentenceTransformer non disponibile (ricerca compat ok). %s", e)
        _EMB_MODEL = None
        return None

def _ensure_faiss():
    global _FAISS
    if _FAISS is not None:
        return _FAISS
    try:
        import faiss  # type: ignore
        _FAISS = faiss
        return _FAISS
    except Exception:
        _FAISS = None
        return None

def _ensure_umap():
    try:
        import umap  # type: ignore
        return umap
    except Exception:
        return None

def _safe_time() -> float:
    import time
    return time.time()

# ------------------------------------------------------------------------------
# SecureBERT: caricamento/uso (backbone) — preferisce handle esterno
# ------------------------------------------------------------------------------

@dataclass
class SecureHandle:
    """Semplice wrapper per adattatore SecureBERT; deve esporre .embed(text)->vector."""
    adapter: Any

_SECURE_HANDLE: Optional[SecureHandle] = None

def set_secure_handle(adapter: Any) -> None:
    """Inietta un handle già inizializzato (da orch_report via securebert_adapter)."""
    global _SECURE_HANDLE
    if adapter is None:
        _SECURE_HANDLE = None
    else:
        _SECURE_HANDLE = SecureHandle(adapter=adapter)
    logger.info("SecureBERT handle %s", "set" if _SECURE_HANDLE else "cleared")

def _ensure_secure_adapter() -> Optional[SecureHandle]:
    """Se non c'è un handle iniettato, prova caricamento lazy via securebert_adapter (path da ENV)."""
    global _SECURE_HANDLE
    if _SECURE_HANDLE is not None:
        return _SECURE_HANDLE
    path = os.getenv("SECUREBERT_PATH") or os.getenv("SECUREBERT_MODEL_PATH")
    if not path:
        return None
    try:
        import securebert_adapter  # type: ignore
        adapter = getattr(securebert_adapter, "load", None)
        model = adapter(path) if callable(adapter) else getattr(securebert_adapter, "SecureBERT")(path)  # type: ignore
        _SECURE_HANDLE = SecureHandle(adapter=model)
        logger.info("SecureBERT adapter caricato da %s", path)
        return _SECURE_HANDLE
    except Exception as e:
        logger.warning("SecureBERT adapter non disponibile: %s", e)
        return None

def _embed_secure(texts: List[str]) -> Optional[Any]:
    """
    Ritorna np.ndarray (N,D) se SecureBERT è disponibile; altrimenti None.
    """
    np = _ensure_numpy()
    if np is None:
        return None
    h = _ensure_secure_adapter()
    if h is None or not getattr(h.adapter, "embed", None):
        return None
    vecs: List[List[float]] = []
    for t in texts:
        try:
            v = h.adapter.embed(t or "")
            if v is None:
                return None
            vecs.append(list(v))
        except Exception:
            return None
    try:
        arr = np.asarray(vecs, dtype="float32")
        return arr
    except Exception:
        return None

# ------------------------------------------------------------------------------
# Layer di persistenza (SQLite primario, Parquet opzionale)
# ------------------------------------------------------------------------------

def _open_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    _init_schema(conn)
    return conn

def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vectors (
            url TEXT PRIMARY KEY,
            text TEXT,
            dim INTEGER,
            embedding BLOB
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()

def _serialize_vec(vec: Any) -> bytes:
    # pickle è sufficiente e semplice; dimensioni piccole (headers/short text)
    return pickle.dumps(vec, protocol=pickle.HIGHEST_PROTOCOL)

def _deserialize_vec(b: bytes) -> Any:
    return pickle.loads(b)

def upsert_secure_embedding(url: str, text: str, db_path: str = DB_PATH) -> bool:
    """
    Calcola embedding con SecureBERT e upserta in SQLite.
    Ritorna True se scritto, False se SecureBERT non disponibile.
    """
    url = (url or "").strip()
    if not url:
        return False
    embs = _embed_secure([text or ""])
    if embs is None:
        return False
    dim = int(embs.shape[1])
    blob = _serialize_vec(embs[0])
    try:
        conn = _open_db(db_path)
        with conn:
            conn.execute(
                "INSERT INTO vectors(url,text,dim,embedding) VALUES(?,?,?,?) "
                "ON CONFLICT(url) DO UPDATE SET text=excluded.text, dim=excluded.dim, embedding=excluded.embedding",
                (url, text or "", dim, blob)
            )
        conn.close()
        return True
    except Exception as e:
        logger.debug("upsert_secure_embedding failed for %s: %s", url, e)
        return False

def get_embedding_by_url(url: str, db_path: str = DB_PATH) -> Optional[Any]:
    try:
        conn = _open_db(db_path)
        cur = conn.execute("SELECT dim, embedding FROM vectors WHERE url=?", (url,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        dim, blob = row
        vec = _deserialize_vec(blob)
        return vec
    except Exception as e:
        logger.debug("get_embedding_by_url failed: %s", e)
        return None

def export_parquet(parquet_path: str = PARQUET_PATH, db_path: str = DB_PATH) -> bool:
    """
    Esporta la tabella vectors in Parquet se pandas+pyarrow disponibili. Ritorna True/False.
    """
    try:
        import pandas as pd  # type: ignore
    except Exception:
        logger.info("pandas non disponibile: skip export_parquet.")
        return False
    try:
        conn = _open_db(db_path)
        df = pd.read_sql_query("SELECT url, text, dim, embedding FROM vectors", conn)
        conn.close()
        # embedding è BLOB pickled; lo teniamo così per compat
        df.to_parquet(parquet_path, index=False)
        return True
    except Exception as e:
        logger.debug("export_parquet failed: %s", e)
        return False

# ------------------------------------------------------------------------------
# Similarità e clustering (SecureBERT → cosine)
# ------------------------------------------------------------------------------

def _cosine_matrix(A, B=None):
    np = _ensure_numpy()
    if np is None:
        return None
    if B is None:
        B = A
    A = A.astype("float32")
    B = B.astype("float32")
    An = A / (np.linalg.norm(A, axis=1, keepdims=True) + 1e-9)
    Bn = B / (np.linalg.norm(B, axis=1, keepdims=True) + 1e-9)
    return An @ Bn.T

def similar_hosts_by_url(url: str, top_k: int = 5, db_path: str = DB_PATH) -> List[Tuple[str, float]]:
    """
    Trova host simili ad un URL (cosine su SecureBERT).
    """
    np = _ensure_numpy()
    if np is None:
        return []
    target = get_embedding_by_url(url, db_path=db_path)
    if target is None:
        return []
    # carica tutte le altre voci
    try:
        conn = _open_db(db_path)
        cur = conn.execute("SELECT url, embedding FROM vectors WHERE url<>?", (url,))
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.debug("similar_hosts_by_url load failed: %s", e)
        return []
    urls: List[str] = []
    vecs: List[Any] = []
    for u, blob in rows:
        try:
            urls.append(u)
            vecs.append(_deserialize_vec(blob))
        except Exception:
            pass
    if not urls:
        return []
    M = np.vstack([target] + vecs)
    S = _cosine_matrix(M)
    if S is None:
        return []
    sims = S[0, 1:]
    idx = sims.argsort()[::-1][:max(1, top_k)]
    return [(urls[i], float(sims[i])) for i in idx]

def similar_hosts_by_text(text: str, top_k: int = 5, db_path: str = DB_PATH) -> List[Tuple[str, float]]:
    """
    Embedda un testo e trova host simili in base ai vettori esistenti.
    """
    np = _ensure_numpy()
    if np is None:
        return []
    q = _embed_secure([text or ""])
    if q is None:
        return []
    try:
        conn = _open_db(db_path)
        cur = conn.execute("SELECT url, embedding FROM vectors")
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.debug("similar_hosts_by_text load failed: %s", e)
        return []
    urls: List[str] = []
    vecs: List[Any] = []
    for u, blob in rows:
        try:
            urls.append(u)
            vecs.append(_deserialize_vec(blob))
        except Exception:
            pass
    if not urls:
        return []
    M = np.vstack([q[0]] + vecs)
    S = _cosine_matrix(M)
    if S is None:
        return []
    sims = S[0, 1:]
    idx = sims.argsort()[::-1][:max(1, top_k)]
    return [(urls[i], float(sims[i])) for i in idx]

def dedup_urls(urls: Sequence[str],
               threshold: float = 0.92,
               db_path: str = DB_PATH) -> List[str]:
    """
    Rimuove URL molto simili in base alla similarità coseno su SecureBERT.
    Mantiene il primo di ciascun cluster (greedy).
    """
    np = _ensure_numpy()
    if np is None:
        return list(dict.fromkeys(urls))
    # carica embedding esistenti; se mancano, non deduplica quel record
    vecs: List[Any] = []
    keep_idx: List[int] = []
    for i, u in enumerate(urls):
        v = get_embedding_by_url(u, db_path=db_path)
        if v is None:
            keep_idx.append(i)  # fallback: tieni
            vecs.append(None)
        else:
            vecs.append(v)
    # costruisci maschera greedy
    result: List[str] = []
    seen = set()
    for i, u in enumerate(urls):
        if i in seen:
            continue
        result.append(u)
        vi = vecs[i]
        if vi is None:
            continue
        # confronta con successivi
        for j in range(i + 1, len(urls)):
            if j in seen:
                continue
            vj = vecs[j]
            if vj is None:
                continue
            M = np.vstack([vi, vj])
            S = _cosine_matrix(M)
            if S is not None and float(S[0, 1]) >= float(threshold):
                seen.add(j)
    return result

def cluster_urls(urls: Sequence[str],
                 min_sim: float = 0.85,
                 db_path: str = DB_PATH) -> List[List[str]]:
    """
    Clustering greedy per soglia di similarità (SecureBERT). Ogni cluster è una lista di URL.
    """
    np = _ensure_numpy()
    if np is None or not urls:
        return [[u] for u in urls]
    vecs: Dict[str, Any] = {}
    order: List[str] = []
    for u in urls:
        v = get_embedding_by_url(u, db_path=db_path)
        if v is not None:
            vecs[u] = v
            order.append(u)
    clusters: List[List[str]] = []
    used = set()
    for i, u in enumerate(order):
        if u in used:
            continue
        used.add(u)
        cluster = [u]
        for v in order[i + 1:]:
            if v in used:
                continue
            M = np.vstack([vecs[u], vecs[v]])
            S = _cosine_matrix(M)
            if S is not None and float(S[0, 1]) >= float(min_sim):
                cluster.append(v)
                used.add(v)
        clusters.append(cluster)
    # aggiungi eventuali URL senza embedding
    for u in urls:
        if u not in vecs:
            clusters.append([u])
    return clusters

# ------------------------------------------------------------------------------
# 1) put_scan_result — normalizza, salva, indicizza (compat) + upsert Secure
# ------------------------------------------------------------------------------

def put_scan_result(scan_result: Dict[str, Any], secure_text_fields: Optional[List[str]] = None) -> None:
    """
    Normalizza e salva un record di scan. Indicizza per dominio e URL.
    Inoltre, se SecureBERT è disponibile, genera e persiste un embedding per la URL
    usando un testo breve (headers/descrizione) costruito dai campi indicati.

    secure_text_fields: lista di chiavi da concatenare (es: ["get.headers.Server","get.content_type"])
    """
    url = str(scan_result.get("url", "")).strip()
    if not url:
        logger.debug("put_scan_result: URL vuoto, skip.")
        return

    def _norm_block(b: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        b = b or {}
        return {
            "status": b.get("status"),
            "latency_ms": b.get("latency_ms"),
            "size": b.get("size"),
            "content_type": b.get("content_type"),
            "waf": bool(b.get("waf")),
            "headers": b.get("headers") or {},
            "body": b.get("body") or b.get("response_raw") or b"",
            "response_raw": b.get("response_raw") or b.get("body") or b"",
            "redirect_chain": b.get("redirect_chain") or [],
            "error": b.get("error"),
        }

    rec = {
        "url": url,
        "get": _norm_block(scan_result.get("get")),
        "post": _norm_block(scan_result.get("post")) if scan_result.get("post") else None,
        "score": float(scan_result.get("score") or 0.0),
        "flags": list(scan_result.get("flags") or []),
    }

    idx = len(_SCAN_RESULTS)
    _SCAN_RESULTS.append(rec)
    dom = _domain_of(url)
    _BY_DOMAIN.setdefault(dom, []).append(idx)
    _BY_URL.setdefault(url, []).append(idx)

    ev = {
        "ts": _safe_time(),
        "request": {"method": "GET"},
        "response": {
            "status": rec["get"]["status"],
            "latency_ms": rec["get"]["latency_ms"],
            "content_type": rec["get"]["content_type"],
            "size": rec["get"]["size"],
            "waf": rec["get"]["waf"],
        },
        "decision": "get_observe",
        "score": rec["score"],
        "flags": rec["flags"],
    }
    dq = _URL_HISTORY.setdefault(url, deque(maxlen=5))
    dq.append(ev)

    # --- NOVITÀ: SecureBERT upsert ---
    # Costruisci un testo breve dai campi noti: Server header, content-type, primi byte del body
    text = _build_secure_short_text(rec, secure_text_fields)
    if text:
        upsert_secure_embedding(url, text)

def _get_nested(d: Dict[str, Any], dotted: str) -> Any:
    cur = d
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur

def _build_secure_short_text(rec: Dict[str, Any], fields: Optional[List[str]]) -> str:
    """
    Prepara un testo conciso per l'embedding SecureBERT:
    - di default usa: get.headers.Server, get.content_type, primi 256 byte del body come stringa latin-1 safe
    - se fields è specificato (lista di chiavi dotted), usa quelle.
    """
    parts: List[str] = []
    if fields:
        for key in fields:
            val = _get_nested(rec, key)
            if isinstance(val, (str, int, float)):
                parts.append(str(val))
            elif isinstance(val, (bytes, bytearray)):
                try:
                    parts.append(bytes(val[:256]).decode("utf-8"))
                except Exception:
                    parts.append(bytes(val[:256]).decode("iso-8859-1", errors="ignore"))
    else:
        server = _get_nested(rec, "get.headers.Server") or _get_nested(rec, "get.headers.server")
        ctype = _get_nested(rec, "get.content_type")
        body = _get_nested(rec, "get.body") or b""
        parts.extend([str(server or ""), str(ctype or "")])
        try:
            parts.append((body or b"")[:256].decode("utf-8"))
        except Exception:
            parts.append((body or b"")[:256].decode("iso-8859-1", errors="ignore"))
    text = " | ".join([p for p in parts if p])
    return text.strip()

# ------------------------------------------------------------------------------
# 2) get_recent_history — finestra temporale per AI (per URL)
# ------------------------------------------------------------------------------

def get_recent_history(url: str, n: int = 5) -> List[Dict[str, Any]]:
    dq = _URL_HISTORY.get(url, deque())
    if not dq:
        return []
    if n <= 0:
        return list(dq)
    return list(dq)[-n:]

# ------------------------------------------------------------------------------
# 2b) Attempts (globale/per dominio/per URL) — invariato
# ------------------------------------------------------------------------------

def record_attempt_outcome(url: str,
                           family: str,
                           transformation: Optional[str],
                           success: bool,
                           score: Optional[float] = None,
                           extra: Optional[Dict[str, Any]] = None) -> None:
    ts = _safe_time()
    url = (url or "").strip()
    family = (family or "GENERIC").upper()
    transformation = (transformation or "NONE").strip() or "NONE"
    domain = _domain_of(url) or "unknown"

    d = _DOMAIN_STATS.setdefault(domain, {"families": {}, "transforms": {}, "last_updated": ts})
    fam = d["families"].setdefault(family, {"attempts": 0, "successes": 0})
    fam["attempts"] += 1
    if success:
        fam["successes"] += 1
    tr = d["transforms"].setdefault(transformation, {"attempts": 0, "successes": 0})
    tr["attempts"] += 1
    if success:
        tr["successes"] += 1
    d["last_updated"] = ts

    evt = {
        "ts": ts,
        "url": url,
        "domain": domain,
        "family": family,
        "transformation": transformation,
        "success": bool(success),
        "score": float(score) if score is not None else None,
        "extra": extra or {},
    }
    _ATTEMPT_HISTORY_GLOBAL.append(evt)
    _ATTEMPT_HISTORY_BY_DOMAIN.setdefault(domain, deque(maxlen=500)).append(evt)
    _ATTEMPT_HISTORY_BY_URL.setdefault(url, deque(maxlen=100)).append(evt)

def get_recent_attempts(n: int = 50,
                        domain: Optional[str] = None,
                        url: Optional[str] = None) -> List[Dict[str, Any]]:
    if url:
        dq = _ATTEMPT_HISTORY_BY_URL.get(url, deque())
    elif domain:
        dq = _ATTEMPT_HISTORY_BY_DOMAIN.get(domain, deque())
    else:
        dq = _ATTEMPT_HISTORY_GLOBAL
    if n <= 0:
        return list(dq)
    return list(dq)[-n:]

# ------------------------------------------------------------------------------
# 3) Ricerca compat (keyword/embeddings legacy) — invariato
# ------------------------------------------------------------------------------

def add_document(text: str, meta: Optional[Dict[str, Any]] = None) -> int:
    doc_id = len(_DOCS)
    _DOCS.append({"id": doc_id, "text": text or "", "meta": meta or {}})
    for tok in _tokenize(text or ""):
        _KEYWORD_INDEX.setdefault(tok, set()).add(doc_id)
    return doc_id

def search(text_or_vector: Union[str, List[float], Any], k: int = 5) -> List[Dict[str, Any]]:
    if isinstance(text_or_vector, str):
        q = text_or_vector.strip()
        results = _keyword_search(q, k)
        if _have_embeddings():
            try:
                emb_scores = _embedding_search(q, k)
                return _merge_results(q, results, emb_scores, k)
            except Exception as e:
                logger.debug("embedding rerank fallito: %s", e)
        return results
    else:
        if not _have_embeddings():
            return []
        return _vector_search(text_or_vector, k)

def _keyword_search(query: str, k: int) -> List[Dict[str, Any]]:
    tokens = _tokenize(query)
    scores: Dict[int, int] = {}
    for t in tokens:
        for doc_id in _KEYWORD_INDEX.get(t, []):
            scores[doc_id] = scores.get(doc_id, 0) + 1
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:max(k, 1)]
    out: List[Dict[str, Any]] = []
    for doc_id, sc in ranked:
        doc = _DOCS[doc_id]
        out.append({"doc_id": doc_id, "score": float(sc), "text": doc["text"], "meta": doc["meta"]})
    return out

def _have_embeddings() -> bool:
    return _EMBEDDINGS is not None and len(_DOCS) > 0

def _embedding_search(query_text: str, k: int) -> List[Dict[str, Any]]:
    model = _ensure_sentence_model()
    np = _ensure_numpy()
    if model is None or np is None or _EMBEDDINGS is None:
        return []
    q_emb = model.encode([query_text], convert_to_numpy=True)
    return _vector_search(q_emb[0], k)

def _vector_search(vector: Union[List[float], Any], k: int) -> List[Dict[str, Any]]:
    np = _ensure_numpy()
    if np is None or _EMBEDDINGS is None:
        return []
    if _FAISS_INDEX is not None and _FAISS is not None:
        import numpy as _np_mod  # noqa
        vec = np.asarray(vector, dtype="float32")
        if vec.ndim == 1:
            vec = vec.reshape(1, -1)
        if _REDUCER is not None:
            try:
                vec = _REDUCER.transform(vec)
            except Exception:
                pass
        distances, indices = _FAISS_INDEX.search(vec, max(1, k))
        hits: List[Dict[str, Any]] = []
        for dist, idx in zip(distances[0], indices[0]):
            if 0 <= idx < len(_DOCS):
                doc = _DOCS[idx]
                hits.append({"doc_id": idx, "score": float(1.0 / (1.0 + dist)), "text": doc["text"], "meta": doc["meta"]})
        return hits
    try:
        vec = np.asarray(vector, dtype="float32")
        if vec.ndim == 1:
            vec = vec.reshape(1, -1)
        emb = _EMBEDDINGS
        num = emb @ vec.T
        denom = (np.linalg.norm(emb, axis=1, keepdims=True) * np.linalg.norm(vec, axis=1))
        sims = (num / (denom + 1e-9)).ravel()
        top_idx = sims.argsort()[::-1][:max(1, k)]
        hits: List[Dict[str, Any]] = []
        for idx in top_idx:
            doc = _DOCS[int(idx)]
            hits.append({"doc_id": int(idx), "score": float(sims[int(idx)]), "text": doc["text"], "meta": doc["meta"]})
        return hits
    except Exception as e:
        logger.debug("vector brute-force failed: %s", e)
        return []

def _merge_results(query: str,
                   kw_results: List[Dict[str, Any]],
                   emb_results: List[Dict[str, Any]],
                   k: int) -> List[Dict[str, Any]]:
    np = _ensure_numpy()
    if np is None:
        return kw_results[:k]
    all_ids = set([r["doc_id"] for r in kw_results]) | set([r["doc_id"] for r in emb_results])
    if not all_ids:
        return []
    def _norm(scores_list: List[Tuple[int, float]]) -> Dict[int, float]:
        if not scores_list:
            return {}
        vs = [s for _, s in scores_list]
        vmin, vmax = min(vs), max(vs)
        rng = (vmax - vmin) or 1.0
        return {i: (s - vmin) / rng for i, s in scores_list}

    kwn = _norm([(r["doc_id"], r["score"]) for r in kw_results])
    embn = _norm([(r["doc_id"], r["score"]) for r in emb_results])

    merged: List[Tuple[int, float]] = []
    for i in all_ids:
        s = 0.6 * kwn.get(i, 0.0) + 0.4 * embn.get(i, 0.0)
        merged.append((i, s))
    merged.sort(key=lambda x: x[1], reverse=True)
    out: List[Dict[str, Any]] = []
    for i, s in merged[:max(1, k)]:
        doc = _DOCS[i]
        out.append({"doc_id": i, "score": float(s), "text": doc["text"], "meta": doc["meta"]})
    return out

# ------------------------------------------------------------------------------
# 4) stats — conteggi + per-dominio (invariato)
# ------------------------------------------------------------------------------

def stats() -> Dict[str, Any]:
    num_urls = len(_BY_URL)
    num_domains = len(_BY_DOMAIN)
    num_results = len(_SCAN_RESULTS)
    num_docs = len(_DOCS)
    return {
        "scan_results": num_results,
        "unique_urls": num_urls,
        "unique_domains": num_domains,
        "docs": num_docs,
        "has_embeddings": bool(_EMBEDDINGS is not None),
        "faiss_index": bool(_FAISS_INDEX is not None),
        "securebert_db": os.path.exists(DB_PATH),
    }

def get_domain_stats(domain: str,
                     top_n: int = 5) -> Dict[str, Any]:
    d = _DOMAIN_STATS.get(domain)
    if not d:
        return {"families": {}, "top_transforms": [], "last_updated": None}

    fam_out: Dict[str, Dict[str, float]] = {}
    for fam, cnt in (d.get("families") or {}).items():
        a = int(cnt.get("attempts", 0))
        s = int(cnt.get("successes", 0))
        hr = float(s) / a if a > 0 else 0.0
        fam_out[fam] = {"attempts": a, "successes": s, "hit_rate": hr}

    trans = []
    for name, cnt in (d.get("transforms") or {}).items():
        a = int(cnt.get("attempts", 0))
        s = int(cnt.get("successes", 0))
        hr = float(s) / a if a > 0 else 0.0
        trans.append((name, s, hr, a))
    trans.sort(key=lambda x: (x[1], x[2], x[3]), reverse=True)
    top = [{"name": n, "successes": s, "hit_rate": hr, "attempts": a} for (n, s, hr, a) in trans[:max(1, top_n)]]

    return {
        "families": fam_out,
        "top_transforms": top,
        "last_updated": d.get("last_updated"),
    }

def get_global_stats(top_n: int = 8) -> Dict[str, Any]:
    fam_acc: Dict[str, Tuple[int, int]] = {}
    tr_acc: Dict[str, Tuple[int, int]] = {}
    for d in _DOMAIN_STATS.values():
        for fam, cnt in (d.get("families") or {}).items():
            a, s = fam_acc.get(fam, (0, 0))
            fam_acc[fam] = (a + int(cnt.get("attempts", 0)), s + int(cnt.get("successes", 0)))
        for tr, cnt in (d.get("transforms") or {}).items():
            a, s = tr_acc.get(tr, (0, 0))
            tr_acc[tr] = (a + int(cnt.get("attempts", 0)), s + int(cnt.get("successes", 0)))
    fam_out: Dict[str, Dict[str, float]] = {}
    for fam, (a, s) in fam_acc.items():
        hr = float(s) / a if a > 0 else 0.0
        fam_out[fam] = {"attempts": a, "successes": s, "hit_rate": hr}
    trans = []
    for name, (a, s) in tr_acc.items():
        hr = float(s) / a if a > 0 else 0.0
        trans.append((name, s, hr, a))
    trans.sort(key=lambda x: (x[1], x[2], x[3]), reverse=True)
    top = [{"name": n, "successes": s, "hit_rate": hr, "attempts": a} for (n, s, hr, a) in trans[:max(1, top_n)]]
    return {"families": fam_out, "top_transforms": top}

def recommend_for_domain(domain: str,
                         k_families: int = 3,
                         k_transforms: int = 5) -> Dict[str, List[str]]:
    ds = get_domain_stats(domain)
    fam_map = ds.get("families") or {}
    if not fam_map:
        fam_map = get_global_stats().get("families") or {}
    fam_sorted = sorted(
        [(f, v["hit_rate"], v.get("successes", 0), v.get("attempts", 0)) for f, v in fam_map.items()],
        key=lambda x: (x[1], x[2], x[3]),
        reverse=True
    )
    families = [f for f, _, __, ___ in fam_sorted[:max(1, k_families)]]
    trans = ds.get("top_transforms") or get_global_stats().get("top_transforms") or []
    transforms = [t["name"] for t in trans[:max(1, k_transforms)]]
    return {"families": families, "transforms": transforms}

# ------------------------------------------------------------------------------
# Funzioni COMPAT: chunk/ingest/index/query (legacy) — invariato
# ------------------------------------------------------------------------------

def chunk_text(text: str, window_size: int = 1000, overlap: int = 200) -> List[str]:
    chunks: List[str] = []
    step = max(1, window_size - max(0, overlap))
    for start in range(0, len(text or ""), step):
        ch = (text or "")[start:start + window_size].strip()
        if ch:
            chunks.append(ch)
    return chunks

def apply_min_hash_dedup(chunks: List[str], threshold: float = 0.8) -> List[str]:
    try:
        from datasketch import MinHash, MinHashLSH  # type: ignore
    except Exception:
        return list(dict.fromkeys(chunks or []))
    def shingles(txt: str, k: int = 5):
        return (txt[i:i+k] for i in range(max(0, len(txt) - k + 1)))
    lsh = MinHashLSH(threshold=threshold, num_perm=128)
    unique: List[str] = []
    for idx, txt in enumerate(chunks or []):
        m = MinHash(num_perm=128)
        for sh in shingles(txt):
            m.update(sh.encode("utf-8", errors="ignore"))
        if not lsh.query(m):
            lsh.insert(str(idx), m)
            unique.append(txt)
    return unique

def compute_embeddings(chunks: List[str], batch_size: int = 32):
    model = _ensure_sentence_model()
    np = _ensure_numpy()
    if model is None or np is None or not chunks:
        return None
    embs = model.encode(chunks, batch_size=batch_size, show_progress_bar=False, convert_to_numpy=True)
    return np.asarray(embs, dtype="float32")

def reduce_dimensions(embeddings, n_components: int = 128):
    umap = _ensure_umap()
    if umap is None or embeddings is None:
        return embeddings
    try:
        reducer = umap.UMAP(n_components=n_components, metric="cosine", random_state=42)
        global _REDUCER
        _REDUCER = reducer
        return reducer.fit_transform(embeddings)
    except Exception as e:
        logger.debug("UMAP reduce fallito: %s", e)
        return embeddings

def build_index(embeddings):
    faiss = _ensure_faiss()
    if faiss is None or embeddings is None:
        return None
    try:
        dim = embeddings.shape[1]
        index = faiss.IndexFlatIP(dim)
        np = _ensure_numpy()
        if np is not None:
            norms = (np.linalg.norm(embeddings, axis=1, keepdims=True) + 1e-9)
            normed = embeddings / norms
        else:
            normed = embeddings
        index.add(normed)
        return index
    except Exception as e:
        logger.debug("FAISS build fallito: %s", e)
        return None

def ingest_and_index(text: str,
                     window_size: int = 1000,
                     overlap: int = 200,
                     threshold: float = 0.8,
                     n_components: int = 128) -> None:
    global _EMBEDDINGS, _FAISS_INDEX
    chunks = chunk_text(text or "", window_size, overlap)
    chunks = apply_min_hash_dedup(chunks, threshold)
    for ch in chunks:
        add_document(ch, meta={"source": "ingest"})
    embs = compute_embeddings(chunks)
    if embs is None:
        _EMBEDDINGS = None
        _FAISS_INDEX = None
        save_state()
        return
    reduced = reduce_dimensions(embs, n_components)
    _EMBEDDINGS = reduced
    _FAISS_INDEX = build_index(reduced)
    save_state()

def query_index(query: str, top_k: int = 5) -> List[Tuple[str, float]]:
    if _have_embeddings():
        hits = _embedding_search(query, top_k)
        if hits:
            return [(h["text"], float(h["score"])) for h in hits]
    hits = _keyword_search(query, top_k)
    return [(h["text"], float(h["score"])) for h in hits]

# ------------------------------------------------------------------------------
# Persistenza (legacy + nuove tabelle)
# ------------------------------------------------------------------------------

def save_state():
    try:
        if _REDUCER is not None:
            with open(REDUCER_PATH, "wb") as f:
                pickle.dump(_REDUCER, f)
    except Exception as e:
        logger.debug("save reducer fallito: %s", e)
    try:
        with open(CHUNKS_PATH, "wb") as f:
            pickle.dump([d.get("text", "") for d in _DOCS], f)
    except Exception as e:
        logger.debug("save chunks fallito: %s", e)
    try:
        if _EMBEDDINGS is not None:
            with open(EMB_PATH, "wb") as f:
                pickle.dump(_EMBEDDINGS, f)
    except Exception as e:
        logger.debug("save embeddings fallito: %s", e)
    try:
        faiss = _ensure_faiss()
        if faiss is not None and _FAISS_INDEX is not None:
            faiss.write_index(_FAISS_INDEX, INDEX_PATH)
    except Exception as e:
        logger.debug("save faiss index fallito: %s", e)
    try:
        with open(STATS_PATH, "wb") as f:
            pickle.dump(_DOMAIN_STATS, f)
    except Exception as e:
        logger.debug("save domain stats fallito: %s", e)
    try:
        with open(ATTEMPTS_PATH, "wb") as f:
            payload = {
                "global": list(_ATTEMPT_HISTORY_GLOBAL),
                "by_domain": {k: list(v) for k, v in _ATTEMPT_HISTORY_BY_DOMAIN.items()},
                "by_url": {k: list(v) for k, v in _ATTEMPT_HISTORY_BY_URL.items()},
            }
            pickle.dump(payload, f)
    except Exception as e:
        logger.debug("save attempts fallito: %s", e)

def load_state():
    global _DOCS, _KEYWORD_INDEX, _EMBEDDINGS, _FAISS_INDEX, _REDUCER
    global _DOMAIN_STATS, _ATTEMPT_HISTORY_GLOBAL, _ATTEMPT_HISTORY_BY_DOMAIN, _ATTEMPT_HISTORY_BY_URL
    if os.path.exists(CHUNKS_PATH):
        try:
            with open(CHUNKS_PATH, "rb") as f:
                texts = pickle.load(f)
            _DOCS = []
            _KEYWORD_INDEX = {}
            for t in texts or []:
                add_document(t, meta={"source": "ingest"})
        except Exception as e:
            logger.debug("load chunks fallito: %s", e)
    if os.path.exists(EMB_PATH):
        try:
            with open(EMB_PATH, "rb") as f:
                _EMBEDDINGS = pickle.load(f)
        except Exception as e:
            logger.debug("load embeddings fallito: %s", e)
    if os.path.exists(REDUCER_PATH):
        try:
            with open(REDUCER_PATH, "rb") as f:
                _REDUCER = pickle.load(f)
        except Exception as e:
            logger.debug("load reducer fallito: %s", e)
    faiss = _ensure_faiss()
    if faiss is not None and os.path.exists(INDEX_PATH):
        try:
            _FAISS_INDEX = faiss.read_index(INDEX_PATH)
        except Exception as e:
            logger.debug("load faiss index fallito: %s", e)
    if os.path.exists(STATS_PATH):
        try:
            with open(STATS_PATH, "rb") as f:
                _DOMAIN_STATS = pickle.load(f)
        except Exception as e:
            logger.debug("load domain stats fallito: %s", e)
    if os.path.exists(ATTEMPTS_PATH):
        try:
            with open(ATTEMPTS_PATH, "rb") as f:
                payload = pickle.load(f) or {}
            _ATTEMPT_HISTORY_GLOBAL = deque(payload.get("global", []), maxlen=1000)
            _ATTEMPT_HISTORY_BY_DOMAIN = {k: deque(v, maxlen=500) for k, v in (payload.get("by_domain", {}) or {}).items()}
            _ATTEMPT_HISTORY_BY_URL = {k: deque(v, maxlen=100) for k, v in (payload.get("by_url", {}) or {}).items()}
        except Exception as e:
            logger.debug("load attempts fallito: %s", e)

# ------------------------------------------------------------------------------
# Utilities reset (invariato)
# ------------------------------------------------------------------------------

def clear_attempts(domain: Optional[str] = None, url: Optional[str] = None) -> None:
    global _ATTEMPT_HISTORY_GLOBAL
    if url:
        _ATTEMPT_HISTORY_BY_URL.pop(url, None)
    elif domain:
        _ATTEMPT_HISTORY_BY_DOMAIN.pop(domain, None)
    else:
        _ATTEMPT_HISTORY_GLOBAL = deque(maxlen=1000)

def reset_domain_stats(domain: Optional[str] = None) -> None:
    if domain:
        _DOMAIN_STATS.pop(domain, None)
    else:
        _DOMAIN_STATS.clear()
