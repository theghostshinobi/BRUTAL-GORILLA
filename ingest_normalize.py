# ingest_normalize.py (rev)
# NOTE: punti chiave:
# - clean_url ora ripara input patologici (double-scheme, netloc='https', ecc.)
# - host nudi → https://host/
# - IDNA → ASCII
# - trailing slash coerente per host-only

from __future__ import annotations

import re
import os
import io
import json
import csv
import yaml
import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse, urlunparse, urljoin, urlsplit, parse_qsl
import re
from urllib.parse import urlsplit, urlunsplit

def fix_url(u: str) -> str:
    if not u: return ""
    u = u.strip()

    # collassa pattern assurdi tipo "https://https/https:/https/https/host"
    u = re.sub(r'^(https?:/+)+', lambda m: m.group(0).split(':')[0] + '://', u, flags=re.I)

    # se manca lo scheme ma inizia con //, aggiungi https:
    if u.startswith("//"):
        u = "https:" + u

    # se non ha scheme, aggiungi https://
    if "://" not in u:
        u = "https://" + u

    # normalizza // multipli dopo lo scheme
    u = re.sub(r'^(https?://)/+', r'\1', u, flags=re.I)

    # parse & ricostruisci pulito
    try:
        sp = urlsplit(u)
        # host vuoto? scarta come invalido
        if not sp.netloc:
            return ""
        # strip path doppi slash
        path = re.sub(r'/+', '/', sp.path or '/')
        return urlunsplit((sp.scheme.lower(), sp.netloc.lower(), path, sp.query, sp.fragment))
    except Exception:
        return ""

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

__all__ = [
    "load_endpoints", "clean_url", "unique_filter", "apply_min_hash_dedup",
    "_ingest_txt", "_ingest_json", "_ingest_yaml", "_ingest_csv", "_ingest_pdf", "_ingest_url",
    "_duplicate_filter", "_payload_filter_constrained",
    "extract_params_from_url", "extract_params_from_html", "extract_params_from_openapi",
    "fetch_text", "parse_robots_for_sitemaps", "extract_params_from_sitemap_xml",
    "extract_params_from_html_url", "extract_params_from_openapi_url", "extract_params_from_robots_url",
    "harvest_param_names", "load_param_kb", "save_param_kb", "update_param_kb_suggestions",
    "ingest_auto",
    # --- ADD: KB-driven annotation ---
    "map_params_to_families", "annotate_urls_with_hints", "families_legend_safe",
]

# --------------------------------------------------------------------------------------
# Helpers URL
# --------------------------------------------------------------------------------------

_HOST_RE = re.compile(
    r"(?<![A-Za-z0-9-])([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9-]{1,63})+)(?::\d+)?(?![A-Za-z0-9-])"
)

def load_endpoints(path: str = "endpoints.txt") -> List[str]:
    eps: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                eps.append(s)
    return eps

def _ensure_scheme(u: str, default: str = "https") -> str:
    u = (u or "").strip()
    if not u:
        return u
    # niente schema? aggiungi default
    if "://" not in u.split("/")[0]:
        return f"{default}://{u}"
    return u

def _salvage_host(raw: str) -> Optional[str]:
    """
    Es. 'https://https/https:/https/https/2kleague.nba.com' -> '2kleague.nba.com'
    """
    m = _HOST_RE.search(raw or "")
    if not m:
        return None
    host = m.group(0)
    # togli eventuale :porta per l'IDNA poi la ri-aggiungiamo con urlparse
    return host

def _idna(host: str) -> str:
    try:
        import idna  # type: ignore
        if host and ":" not in host and not (host.startswith("[") and host.endswith("]")):
            return idna.encode(host).decode("ascii")
        return host
    except Exception:
        return host

def url_unparse_safe(scheme: str, netloc: str, path: str, params: str, query: str, fragment: str) -> str:
    try:
        return urlunparse((scheme, netloc, path, params, query, fragment))
    except Exception:
        return f"{scheme}://{netloc}{path}{('?' + query) if query else ''}{('#' + fragment) if fragment else ''}"

def clean_url(raw: str) -> str:
    """
    Normalizza e **ripara** URL:
      - schema default se mancante
      - riparazione double-scheme/netloc=scheme (glitch comuni)
      - host → IDNA ASCII
      - ricostruzione sicura; per host-only aggiunge '/' finale
    """
    s = (raw or "").strip()
    if not s:
        return s

    # Quick path: se è un host nudo (niente slash/spazi), fallo URL
    if "/" not in s and " " not in s and not s.startswith(("http://", "https://")):
        host_port = s
        # split porta (se presente)
        if ":" in host_port and host_port.count(":") == 1:
            h, p = host_port.split(":", 1)
            host_ascii = _idna(h)
            return f"https://{host_ascii}:{p}/"
        return f"https://{_idna(host_port)}/"

    # 1) garantisci schema
    s = _ensure_scheme(s)

    # 2) parse
    parts = urlparse(s)

    # 3) ripara casi patologici: netloc == 'http' o 'https' o netloc vuoto
    if parts.netloc in ("http", "https", ""):
        salv = _salvage_host(s)
        if salv:
            # separa eventuale :porta
            host_only, port = salv, None
            if ":" in salv and not salv.startswith("["):
                host_only, port = salv.split(":", 1)
            host_ascii = _idna(host_only)
            netloc = f"{host_ascii}:{port}" if port else host_ascii
            # se il path sembra “solo rumore di scheme”, azzera
            path = ""
            return url_unparse_safe(parts.scheme or "https", netloc, "/", "", "", "")
        # altrimenti, se non si riesce a salvare: prova almeno a restituire schema+stringa “ripulita”
        return f"{parts.scheme or 'https'}://{_idna(parts.netloc or s)}/"

    # 4) normal path/netloc
    host_ascii = _idna(parts.hostname or "")
    netloc = host_ascii
    if parts.port:
        netloc = f"{host_ascii}:{parts.port}"
    if parts.username:
        cred = parts.username
        if parts.password:
            cred += f":{parts.password}"
        netloc = f"{cred}@{netloc}"

    path = parts.path or "/"
    return url_unparse_safe(parts.scheme or "https", netloc, path, parts.params or "", parts.query or "", parts.fragment or "")

def unique_filter(urls: List[str], use_minhash: bool = False, threshold: float = 0.8) -> List[str]:
    if not use_minhash:
        seen, out = set(), []
        for u in urls or []:
            cu = clean_url(u)
            if cu not in seen:
                seen.add(cu)
                out.append(cu)
        return out
    return apply_min_hash_dedup([clean_url(u) for u in (urls or [])], threshold=threshold)

# --------------------------------------------------------------------------------------
# Dedup MinHash (identico al tuo, invariato)
# --------------------------------------------------------------------------------------

def apply_min_hash_dedup(texts: List[str], threshold: float = 0.8) -> List[str]:
    try:
        from datasketch import MinHash, MinHashLSH  # type: ignore
    except Exception:
        logger.warning("datasketch non disponibile: fallback a dedup basato su set().")
        return list(dict.fromkeys(texts or []))

    def shingles(text: str, k: int = 5):
        n = max(0, len(text) - k + 1)
        for i in range(n):
            yield text[i:i+k]

    lsh = MinHashLSH(threshold=threshold, num_perm=128)
    unique: List[str] = []
    for idx, txt in enumerate(texts or []):
        m = MinHash(num_perm=128)
        for sh in shingles(txt or ""):
            m.update(sh.encode("utf-8", errors="ignore"))
        if not lsh.query(m):
            lsh.insert(str(idx), m)
            unique.append(txt)
    return unique

# --------------------------------------------------------------------------------------
# HTTP fetch (HTTP/2→HTTP/1.1 switch) — invariato salvo robustezze minori
# --------------------------------------------------------------------------------------

_DEFAULT_UA = "BrutalGorilla/ingest/1.0"
_DEFAULT_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,"
    "text/plain;q=0.8,*/*;q=0.5"
)

def _best_effort_decode(content: bytes, content_type: str | None) -> str:
    if not content:
        return ""
    if content_type:
        m = re.search(r"charset=([A-Za-z0-9_\-]+)", content_type, re.I)
        if m:
            enc = m.group(1).strip().strip('"').strip("'")
            try:
                return content.decode(enc, errors="ignore")
            except Exception:
                pass
    try:
        import chardet  # type: ignore
        det = chardet.detect(content) or {}
        enc = det.get("encoding") or "utf-8"
        return content.decode(enc, errors="ignore")
    except Exception:
        return content.decode("utf-8", errors="ignore")

def _http_fetch(url: str, timeout: int = 10, max_size: int = 2_000_000) -> Tuple[int, Dict[str, str], bytes]:
    try:
        import httpx  # type: ignore
        headers = {"User-Agent": _DEFAULT_UA, "Accept": _DEFAULT_ACCEPT}
        timeout_cfg = httpx.Timeout(connect=timeout, read=timeout, write=timeout, pool=timeout)
        for use_h2 in (True, False):
            try:
                with httpx.Client(http2=use_h2, headers=headers, follow_redirects=True, timeout=timeout_cfg) as client:
                    resp = client.get(url)
                    status = resp.status_code
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
                    data = resp.content or b""
                    if len(data) > max_size:
                        data = data[:max_size]
                    return status, hdrs, data
            except Exception:
                continue
    except Exception:
        pass

    try:
        import requests  # type: ignore
    except Exception as e:
        raise RuntimeError(f"Nessun backend HTTP disponibile per fetch {url}: {e}")

    try:
        resp = requests.get(
            url,
            headers={"User-Agent": _DEFAULT_UA, "Accept": _DEFAULT_ACCEPT},
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )
        buf = io.BytesIO()
        for chunk in resp.iter_content(chunk_size=16384):
            if not chunk:
                continue
            if buf.tell() + len(chunk) > max_size:
                buf.write(chunk[: max(0, max_size - buf.tell())])
                break
            buf.write(chunk)
        data = buf.getvalue()
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        return int(resp.status_code), hdrs, data
    except Exception as e:
        raise RuntimeError(f"Fetch fallito {url}: {e}")

# --------------------------------------------------------------------------- #
# Parsers                                                                     #
# --------------------------------------------------------------------------- #

def _ingest_txt(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def _ingest_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def _ingest_yaml(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return yaml.safe_load(f)


def _ingest_csv(path: str) -> List[List[str]]:
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        return list(csv.reader(f))


def _ingest_pdf(path: str, max_pages: int = 50) -> Dict[str, Any]:
    """
    Estrae testo e URL basilari da un PDF. Import di PyPDF2 è lazy.
    Limita le pagine per evitare RAM spike.
    """
    try:
        from PyPDF2 import PdfReader  # type: ignore
    except Exception:
        logger.warning("PyPDF2 non disponibile: impossibile parse PDF.")
        return {"type": "pdf", "text": "", "urls": [], "meta": {"pages": 0}}

    try:
        reader = PdfReader(path)
        pages = reader.pages[:max_pages] if hasattr(reader, "pages") else []
        texts: List[str] = []
        for p in pages:
            try:
                t = p.extract_text() or ""
            except Exception:
                t = ""
            texts.append(t)
        text_all = "\n".join(texts)
        urls = sorted(set(re.findall(r"https?://[^\s)>\]]+", text_all)))
        return {"type": "pdf", "text": text_all, "urls": urls, "meta": {"pages": len(pages)}}
    except Exception as e:
        logger.warning("Errore lettura PDF %s: %s", path, e)
        return {"type": "pdf", "text": "", "urls": [], "meta": {"error": str(e)}}


def _ingest_url(url: str, timeout: int = 10, max_size: int = 2_000_000) -> Dict[str, Any]:
    """
    Fetch URL (HTTP/2→HTTP/1.1), parse HTML con BS4 (se disponibile).
    Estrae testo “pulito”, link e indizi (login/search/upload/admin/api).
    """
    status, headers, raw = _http_fetch(url, timeout=timeout, max_size=max_size)
    content_type = (headers.get("content-type") or "").lower()
    text = _best_effort_decode(raw, content_type)

    urls: List[str] = []
    hints: List[str] = []

    # euristica HTML
    is_html = ("text/html" in content_type) or ("<html" in (text[:200].lower()))
    if is_html:
        try:
            from bs4 import BeautifulSoup  # type: ignore
        except Exception:
            # fallback: tag strip grezzo
            cleaned = re.sub(r"<script.*?</script>|<style.*?</style>", "", text, flags=re.I | re.S)
            text = re.sub(r"<[^>]+>", " ", cleaned)
            urls = sorted(set(re.findall(r"https?://[^\s)>\]]+", text)))
        else:
            soup = BeautifulSoup(text, "html.parser")
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()
            text = soup.get_text(separator="\n", strip=True)
            # link extraction (solo <a href>)
            for a in soup.find_all("a", href=True):
                href = a.get("href")
                try:
                    full = urljoin(url, href)
                    urls.append(full)
                except Exception:
                    pass
            # form action params
            for form in soup.find_all("form", action=True):
                try:
                    act = urljoin(url, str(form.get("action")))
                    urls.append(act)
                except Exception:
                    pass
            urls = sorted(set(urls))
            # hints
            low = (text[:10000] or "").lower()
            if any(k in low for k in ("login", "signin", "oauth")):
                hints.append("login")
            if any(k in low for k in ("search", "query", "q=")):
                hints.append("search")
            if "upload" in low:
                hints.append("upload")
            if "admin" in low:
                hints.append("admin")
            if any(k in low for k in ("api", "graphql", "/v1/", "/v2/")):
                hints.append("api")
    elif "application/json" in content_type:
        # JSON: mantieni come testo “pretty” limitato
        try:
            j = json.loads(text)
            text = json.dumps(j, indent=2, ensure_ascii=False)[: max_size // 2]
        except Exception:
            text = text[: max_size // 2]
        urls = sorted(set(re.findall(r"https?://[^\s)>\]]+", text)))
    elif "text/plain" in content_type:
        text = text[: max_size]
        urls = sorted(set(re.findall(r"https?://[^\s)>\]]+", text)))
    else:
        # altri content-type: decode best-effort
        text = text[: max_size]
        urls = sorted(set(re.findall(r"https?://[^\s)>\]]+", text)))

    return {
        "type": "url",
        "url": url,
        "content_type": content_type,
        "text": text,
        "urls": urls,
        "hints": hints,
        "meta": {"status": status, "len": len(raw)},
    }

# --------------------------------------------------------------------------- #
# Constraints / Dedup                                                         #
# --------------------------------------------------------------------------- #

def _duplicate_filter(docs: Sequence[str], use_minhash: bool = True, threshold: float = 0.8) -> List[str]:
    """
    Dedupe di documenti testuali: MinHash (se disponibile) o fallback a set().
    """
    if not docs:
        return []
    if use_minhash:
        return apply_min_hash_dedup(list(docs), threshold=threshold)
    return list(dict.fromkeys(docs))


def _payload_filter_constrained(text: str,
                                constraints: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Estrae candidati payload innocui dal testo e applica vincoli:
    - Se z3 è disponibile **e** constraints.use_z3 → verifica Length/Charset con z3.
    - Altrimenti: filtro per lunghezza/regex semplice (fallback).
    """
    constraints = constraints or {}
    max_length = int(constraints.get("max_length", 4096))
    allowed_re = constraints.get("allowed_charset", r"[\x20-\x7E]")

    # Estrai “token” candidati (stringhe tra virgolette, parametri query, ecc.)
    candidates: List[str] = []
    candidates += re.findall(r'"([^"\n]{1,200})"', text or "")
    candidates += re.findall(r"'([^'\n]{1,200})'", text or "")
    for _, v in parse_qsl(urlsplit("http://x/?" + (text or "")).query, keep_blank_values=True):
        if v:
            candidates.append(v)

    # Filtro base
    base = [c for c in candidates if len(c) <= max_length and re.fullmatch(f"{allowed_re}*", c or "")]
    if not constraints.get("use_z3"):
        return list(dict.fromkeys(base))[:200]

    # Verifica con Z3, se disponibile
    try:
        import z3  # type: ignore
    except Exception:
        logger.warning("z3 non disponibile: uso fallback senza SMT.")
        return list(dict.fromkeys(base))[:200]

    out: List[str] = []
    for c in base[:1000]:  # piccolo tetto per evitare esplosioni
        s = z3.String("s")
        solver = z3.Solver()
        solver.add(z3.Length(s) <= max_length)
        solver.add(z3.InRe(s, z3.ReAllChar()))  # vincolo generico; charset già filtrato con regex
        solver.add(s == c)
        if solver.check() == z3.sat:
            out.append(c)
        if len(out) >= 200:
            break
    return out

# --------------------------------------------------------------------------- #
# Estrazione nomi parametro (URL/HTML/OpenAPI/robots/sitemap)                 #
# --------------------------------------------------------------------------- #

def _suggest_family(param: str) -> str:
    p = (param or "").lower()
    if any(k in p for k in ("redirect", "return_url", "redir", "next", "callback", "cb")):
        return "OPEN_REDIRECT" if "cb" not in p else "JSONP"
    if p in ("callback", "cb", "jsonp"):
        return "JSONP"
    if p in ("q", "query", "search", "s"):
        return "XSS"
    if p in ("id", "uid", "user_id", "post_id", "order_id"):
        return "IDOR_BENIGN"
    if any(k in p for k in ("order", "sort", "filter", "where")):
        return "SQLI"
    if p in ("path", "file", "filename", "image", "avatar"):
        return "TRAVERSAL_SOFT"
    if p in ("target", "endpoint", "addr", "host", "url"):
        return "SSRF_SAFE"
    return "GENERIC"


def extract_params_from_url(url: str) -> List[str]:
    """
    Estrae i nomi parametro dalla query string di una singola URL.
    """
    try:
        qs = urlsplit(url).query
        names = [name for name, _ in parse_qsl(qs, keep_blank_values=True)]
        out, seen = [], set()
        for n in names:
            if n and n not in seen:
                out.append(n); seen.add(n)
        return out
    except Exception:
        return []


def extract_params_from_html(html_text: str) -> List[str]:
    """
    Estrae nomi 'name=' dei campi form + param in URL presenti nel markup.
    Usa BeautifulSoup se disponibile, altrimenti regex semplice.
    """
    names: List[str] = []
    try:
        from bs4 import BeautifulSoup  # type: ignore
        soup = BeautifulSoup(html_text, "html.parser")
        # fields
        for inp in soup.find_all(["input", "select", "textarea"]):
            n = inp.get("name")
            if n:
                names.append(n)
        # href query params da <a>
        for a in soup.find_all("a", href=True):
            names += extract_params_from_url(str(a["href"]))
        # action query params da <form>
        for form in soup.find_all("form", action=True):
            names += extract_params_from_url(str(form["action"]))
    except Exception:
        # regex fallback
        names += re.findall(r'name=["\']([A-Za-z0-9_\-\[\]]{1,100})["\']', html_text or "")
        for href in re.findall(r'href=["\']([^"\']+)["\']', html_text or ""):
            names += extract_params_from_url(href)
        for action in re.findall(r'action=["\']([^"\']+)["\']', html_text or ""):
            names += extract_params_from_url(action)

    out, seen = [], set()
    for n in names:
        if n and n not in seen:
            out.append(n); seen.add(n)
    return out


def extract_params_from_openapi(doc: Any) -> List[str]:
    """
    Estrae parametri di query da un documento OpenAPI/Swagger (JSON/YAML già caricato).
    Cerca in: paths.*.*.parameters[*].in == "query"
    """
    if not isinstance(doc, dict):
        try:
            if isinstance(doc, str) and doc.strip().startswith("{"):
                return extract_params_from_openapi(json.loads(doc))
            if isinstance(doc, str):
                return extract_params_from_openapi(yaml.safe_load(doc))
        except Exception:
            return []
    params: List[str] = []
    paths = doc.get("paths") or {}
    if not isinstance(paths, dict):
        return []
    for _, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        # parametri a livello di path
        for p in path_item.get("parameters") or []:
            try:
                if p.get("in") == "query" and p.get("name"):
                    params.append(str(p["name"]))
            except Exception:
                pass
        # metodi
        for method, op in path_item.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch", "options", "head"):
                continue
            for p in op.get("parameters") or []:
                try:
                    if p.get("in") == "query" and p.get("name"):
                        params.append(str(p["name"]))
                except Exception:
                    pass
    out, seen = [], set()
    for n in params:
        if n and n not in seen:
            out.append(n); seen.add(n)
    return out

# --------------------------------------------------------------------------- #
# Fetch helpers (alto livello)                                                #
# --------------------------------------------------------------------------- #

def fetch_text(url: str, timeout: int = 10, max_size: int = 2_000_000) -> Tuple[str, str]:
    """
    Scarica una risorsa come testo. Ritorna (content_type, text).
    """
    status, headers, content = _http_fetch(url, timeout=timeout, max_size=max_size)
    # anche per status >=400 ritorniamo ciò che abbiamo per visibilità
    ctype = (headers.get("content-type") or "").lower()
    text = _best_effort_decode(content, ctype)
    return ctype, text


def parse_robots_for_sitemaps(text: str) -> List[str]:
    """
    Estrae le righe 'Sitemap: <URL>' da robots.txt (case-insensitive).
    """
    sitemaps: List[str] = []
    for line in (text or "").splitlines():
        if line.lower().startswith("sitemap:"):
            sm = line.split(":", 1)[1].strip()
            if sm:
                sitemaps.append(sm)
    return sitemaps


def extract_params_from_sitemap_xml(xml_text: str) -> List[str]:
    """
    Estrae le URL da sitemap e colleziona i nomi parametro presenti in 'loc'.
    """
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_text)
    except Exception:
        return []
    ns = ""
    try:
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0].strip("{")
    except Exception:
        ns = ""
    locs: List[str] = []
    if ns:
        for elem in root.findall(f".//{{{ns}}}loc"):
            if elem.text:
                locs.append(elem.text.strip())
    else:
        for elem in root.findall(".//loc"):
            if elem.text:
                locs.append(elem.text.strip())
    params: List[str] = []
    for u in locs:
        params += extract_params_from_url(u)
    out, seen = [], set()
    for n in params:
        if n and n not in seen:
            out.append(n); seen.add(n)
    return out


def extract_params_from_html_url(url: str, timeout: int = 10) -> List[str]:
    """
    Scarica una pagina HTML e estrae nomi dei parametri dai form/link.
    """
    try:
        ctype, text = fetch_text(url, timeout=timeout)
    except Exception as e:
        logger.debug("fetch HTML failed %s: %s", url, e)
        return []
    if "text/html" not in ctype and "<html" not in (text[:200].lower()):
        return []
    return extract_params_from_html(text)


def extract_params_from_openapi_url(url: str, timeout: int = 10) -> List[str]:
    """
    Scarica swagger/openapi JSON/YAML e estrae parametri query.
    """
    try:
        ctype, text = fetch_text(url, timeout=timeout)
    except Exception as e:
        logger.debug("fetch openapi failed %s: %s", url, e)
        return []
    try:
        if "json" in ctype or text.strip().startswith("{"):
            doc = json.loads(text)
        else:
            doc = yaml.safe_load(text)
        return extract_params_from_openapi(doc)
    except Exception as e:
        logger.debug("parse openapi failed %s: %s", url, e)
        return []


def extract_params_from_robots_url(url: str, timeout: int = 10) -> List[str]:
    """
    Scarica robots.txt, trova sitemaps, scarica sitemap e accumula param.
    """
    try:
        _, text = fetch_text(url, timeout=timeout)
        sitemaps = parse_robots_for_sitemaps(text)
    except Exception as e:
        logger.debug("fetch robots failed %s: %s", url, e)
        return []
    params: List[str] = []
    for sm in sitemaps[:10]:  # piccola soglia
        try:
            ctype, sm_text = fetch_text(sm, timeout=timeout)
            if "xml" in ctype or sm_text.strip().startswith("<"):
                params += extract_params_from_sitemap_xml(sm_text)
        except Exception as e:
            logger.debug("fetch sitemap failed %s: %s", sm, e)
    out, seen = [], set()
    for n in params:
        if n and n not in seen:
            out.append(n); seen.add(n)
    return out

# --------------------------------------------------------------------------- #
# Harvest massivo + contatori per host                                        #
# --------------------------------------------------------------------------- #

def _host(url: str) -> str:
    try:
        return urlsplit(url).netloc.lower()
    except Exception:
        return ""


def harvest_param_names(endpoints: List[str],
                        opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Colleziona nomi param da query/HTML/OpenAPI/robots+sitemap con contatori per host e globali.
    Throttling minimo: per host si visita la base una sola volta per fonte.
    """
    opts = opts or {}
    fetch_html = bool(opts.get("fetch_html_forms", False))
    fetch_openapi = bool(opts.get("fetch_openapi", False))
    fetch_robots = bool(opts.get("fetch_robots_sitemap", False))
    timeout = int(opts.get("timeout", 10))
    max_hosts = int(opts.get("max_hosts", 500))

    cleaned = unique_filter([clean_url(u) for u in (endpoints or [])])
    by_host: Dict[str, Dict[str, int]] = {}
    gcount: Dict[str, int] = {}
    sources: Dict[str, Dict[str, bool]] = {}

    base_for_host: Dict[str, str] = {}
    for u in cleaned:
        h = _host(u)
        if h and h not in base_for_host:
            base_for_host[h] = u
        if len(base_for_host) >= max_hosts:
            break

    # 1) Query params dagli endpoints
    for u in cleaned:
        h = _host(u)
        if not h:
            continue
        names = extract_params_from_url(u)
        if not names:
            continue
        dst = by_host.setdefault(h, {})
        for n in names:
            dst[n] = dst.get(n, 0) + 1
            gcount[n] = gcount.get(n, 0) + 1

    # 2) HTML forms (opzionale)
    if fetch_html:
        for h, base in base_for_host.items():
            sources.setdefault(h, {})["html_checked"] = True
            try:
                params = extract_params_from_html_url(base, timeout=timeout)
            except Exception as e:
                logger.debug("html forms failed for %s: %s", base, e)
                params = []
            dst = by_host.setdefault(h, {})
            for n in params:
                dst[n] = dst.get(n, 0) + 1
                gcount[n] = gcount.get(n, 0) + 1

    # 3) OpenAPI/Swagger (opzionale)
    if fetch_openapi:
        candidates = ("openapi.json", "swagger.json", "swagger.yaml", "openapi.yaml")
        for h, base in base_for_host.items():
            sources.setdefault(h, {})["openapi_checked"] = True
            parsed = urlsplit(base)
            root = f"{parsed.scheme}://{parsed.netloc}"
            params_all: List[str] = []
            for path in candidates:
                url = root.rstrip("/") + "/" + path
                try:
                    params_all = extract_params_from_openapi_url(url, timeout=timeout)
                except Exception:
                    params_all = []
                if params_all:
                    break
            dst = by_host.setdefault(h, {})
            for n in params_all:
                dst[n] = dst.get(n, 0) + 1
                gcount[n] = gcount.get(n, 0) + 1

    # 4) robots.txt + sitemap (opzionale)
    if fetch_robots:
        for h, base in base_for_host.items():
            sources.setdefault(h, {})["robots_checked"] = True
            parsed = urlsplit(base)
            robots = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            try:
                params = extract_params_from_robots_url(robots, timeout=timeout)
            except Exception as e:
                logger.debug("robots/sitemap failed for %s: %s", robots, e)
                params = []
            dst = by_host.setdefault(h, {})
            for n in params:
                dst[n] = dst.get(n, 0) + 1
                gcount[n] = gcount.get(n, 0) + 1

    return {"by_host": by_host, "global": gcount, "sources": sources}

# --------------------------------------------------------------------------- #
# Writer KB param→famiglia (merge non distruttivo)                            #
# --------------------------------------------------------------------------- #

def load_param_kb(path: str) -> Dict[str, str]:
    """
    Carica un KB param→famiglia da JSON o YAML. Se assente, ritorna {}.
    """
    if not path or not os.path.exists(path):
        return {}
    try:
        if path.lower().endswith((".yaml", ".yml")):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        else:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        if isinstance(data, dict):
            m = data.get("map") if "map" in data and isinstance(data.get("map"), dict) else data
            return {str(k): str(v) for k, v in m.items()}
    except Exception as e:
        logger.warning("Param KB load fallita per %s: %s", path, e)
    return {}


def save_param_kb(mapping: Dict[str, str], path: str) -> None:
    """
    Salva il mapping param→famiglia. Se YAML, usa yaml.safe_dump; altrimenti JSON.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    if path.lower().endswith((".yaml", ".yml")):
        with open(tmp, "w", encoding="utf-8") as f:
            yaml.safe_dump(mapping, f, sort_keys=True, allow_unicode=True)
    else:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(mapping, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp, path)


def update_param_kb_suggestions(param_counts_global: Dict[str, int],
                                kb_path: Optional[str] = None,
                                extra_rules: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Merge non distruttivo:
      - carica kb esistente (se c'è)
      - per ogni parametro NON presente nel kb, aggiunge un suggerimento euristico
        (o dalle extra_rules, se passate)
      - salva se kb_path è fornito
    Ritorna il mapping risultante.
    """
    current = load_param_kb(kb_path) if kb_path else {}
    # Applica regole extra prima (prioritarie)
    if extra_rules:
        for k, v in extra_rules.items():
            if k not in current:
                current[k] = str(v)

    # Aggiungi suggerimenti per i param non ancora mappati
    for p in sorted(param_counts_global.keys()):
        if p not in current:
            current[p] = _suggest_family(p)

    if kb_path:
        save_param_kb(current, kb_path)
        logger.info("Param KB aggiornato (%d entries) → %s", len(current), kb_path)
    return current

# --------------------------------------------------------------------------- #
# === NEW (ADD): Annotazione famiglie/hints via policy.KB ==================== #
# --------------------------------------------------------------------------- #

# Import “soft” dalla policy: se non disponibile, degrada con fallback generici.
try:
    from policy import classify_params_for_url as _policy_classify_params_for_url  # type: ignore
    from policy import families_legend as _policy_families_legend  # type: ignore
except Exception:  # pragma: no cover
    _policy_classify_params_for_url = None  # type: ignore
    _policy_families_legend = None  # type: ignore

def families_legend_safe(kb_path: Optional[str] = None) -> Dict[str, str]:
    """
    Legenda famiglie (per UI/CLI). Se policy non c'è, torna un fallback minimale.
    """
    if callable(_policy_families_legend):
        try:
            return _policy_families_legend(kb_path) or {}
        except Exception:
            pass
    # Fallback minimale
    return {
        "XSS": "Reflected/DOM XSS benign payloads",
        "SQLI": "Benign SQL-like probes",
        "IDOR": "Insecure Direct Object Reference",
        "REDIRECT": "Open Redirect / Forward",
        "TRAVERSAL": "Path traversal soft",
        "SSRF_SAFE": "SSRF-safe probes",
        "GENERIC": "Fallback safe mutations",
    }

def map_params_to_families(
    url: str,
    *,
    content_type_hint: Optional[str] = None,
    engine_hint: Optional[str] = None,
    kb_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Usa la KB (policy) per classificare i parametri dell'URL in famiglie e
    restituire anche i conteggi 'vuln_hints'.
    Shape:
      {
        "url": ...,
        "param_families": [{"param":"id","family":"IDOR","priority":98,"confidence":"high"}, ...],
        "vuln_hints": {"IDOR": 3, "XSS": 2, ...}
      }
    """
    if callable(_policy_classify_params_for_url):
        try:
            return _policy_classify_params_for_url(
                url,
                content_type_hint=content_type_hint,
                engine_hint=engine_hint,
                kb_path=kb_path
            )
        except Exception as e:
            logger.debug("policy.classify_params_for_url failed for %s: %s", url, e)

    # Fallback: nessuna KB, costruiamo un output compatibile ma generico
    params = extract_params_from_url(url)
    fams: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}
    for p in params:
        fam = _suggest_family(p)
        fams.append({"param": p, "family": fam, "priority": 50, "confidence": "low", "source": "fallback"})
        counts[fam] = counts.get(fam, 0) + 1
    return {"url": url, "param_families": fams, "vuln_hints": counts}

def annotate_urls_with_hints(
    urls: List[str],
    *,
    content_type_hint: Optional[str] = None,
    engine_hint: Optional[str] = None,
    kb_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Normalizza una lista di URL e le arricchisce con:
      - clean_url
      - host, path, query
      - param_families[] (param→famiglia)
      - vuln_hints {famiglia:conteggio}
    Non rimuove campi esistenti: è pensata per essere consumata da orch_report/probe.
    """
    out: List[Dict[str, Any]] = []
    for raw in urls or []:
        try:
            cu = clean_url(raw)
            parsed = urlsplit(cu)
            klass = map_params_to_families(
                cu,
                content_type_hint=content_type_hint,
                engine_hint=engine_hint,
                kb_path=kb_path,
            )
            rec = {
                "url": cu,
                "clean_url": cu,
                "host": parsed.netloc,
                "path": parsed.path or "/",
                "query": parsed.query or "",
                "param_families": klass.get("param_families") or [],
                "vuln_hints": klass.get("vuln_hints") or {},
            }
            out.append(rec)
        except Exception as e:
            logger.debug("annotate failed for %s: %s", raw, e)
            out.append({
                "url": raw,
                "clean_url": clean_url(raw),
                "host": "",
                "path": "",
                "query": "",
                "param_families": [],
                "vuln_hints": {},
                "error": str(e),
            })
    return out

# --------------------------------------------------------------------------- #
# Dispatcher                                                                  #
# --------------------------------------------------------------------------- #

def ingest_auto(path_or_url: str,
                opts: Optional[Dict[str, Any]] = None) -> Union[str, list, dict]:
    """
    Router di ingestion.
    Default: mantiene la compatibilità dei **tipi** originali (str/list/dict).
    Opzionale: opts={"return_parsed": True} → ritorna un ParsedDoc strutturato.
    """
    opts = opts or {}
    ret_parsed = bool(opts.get("return_parsed"))

    # URL remoto
    if path_or_url.lower().startswith(("http://", "https://")):
        parsed = _ingest_url(path_or_url, timeout=int(opts.get("timeout", 10)),
                             max_size=int(opts.get("max_size", 2_000_000)))
        return parsed if ret_parsed else (parsed.get("text") or "")

    # File locale
    lower = path_or_url.lower()
    if lower.endswith(".txt"):
        return _ingest_txt(path_or_url)
    if lower.endswith(".json"):
        return _ingest_json(path_or_url)
    if lower.endswith((".yaml", ".yml")):
        return _ingest_yaml(path_or_url)
    if lower.endswith(".csv"):
        return _ingest_csv(path_or_url)
    if lower.endswith(".pdf"):
        parsed_pdf = _ingest_pdf(path_or_url, max_pages=int(opts.get("max_pages", 50)))
        return parsed_pdf if ret_parsed else (parsed_pdf.get("text") or "")

    raise ValueError(f"Formato non supportato o path/URL invalido: {path_or_url}")

# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    print("ingest_normalize.py pronto: HTTP/2→HTTP/1.1 fallback, parsers lazy, dedup opzionale, estrazione param, KB merge.")
