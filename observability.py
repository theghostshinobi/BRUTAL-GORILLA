# observability.py
# Metriche & log strutturati — API minimali e collegate:
#  - track_scan_event(event_type, labels)
#  - time_block(stage, labels)  → Histogram per p50/p95 (probe/enrich/orchestrate)
#  - record_detection(family, outcome, source) → hit-rate per famiglia
#  - record_bypass(family, policy, activated, reason) → % bypass attivati
#  - snapshot_hit_rates() / snapshot_bypass_rates() → viste pronte all’uso
#  - log_decision(domain, action, decision, result, **extras) → log strutturati
#
# Dipendenze opzionali: structlog, prometheus_client, opentelemetry
# Nessuna dipendenza è obbligatoria: in assenza, tutto degrada a no-op sicuri.

from __future__ import annotations

import os
import re
import time
import threading
import logging
from typing import Any, Dict, Generator, Optional, Tuple
from contextlib import contextmanager

# ------------------------------------------------------------------------------
# Optional deps: structlog / prometheus_client / opentelemetry (lazy/no-op)
# ------------------------------------------------------------------------------

# structlog (fallback a logging standard)
try:
    import structlog  # type: ignore
    _HAS_STRUCTLOG = True
except Exception:
    structlog = None  # type: ignore
    _HAS_STRUCTLOG = False

def _configure_structlog() -> None:
    if not _HAS_STRUCTLOG:
        logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
        return
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(format="%(message)s", level=logging.INFO)

_configure_structlog()

def get_structured_logger(name: str = "brutal_gorilla"):
    if _HAS_STRUCTLOG:
        return structlog.get_logger(name=name)
    return logging.getLogger(name)

# Prometheus (fallback a no-op compatibile)
try:
    from prometheus_client import (
        Counter, Histogram, CollectorRegistry,
        CONTENT_TYPE_LATEST, generate_latest,
    )  # type: ignore
    _HAS_PROM = True
except Exception:
    _HAS_PROM = False
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

    class _NoopMetric:
        def __init__(self, *_args, **_kwargs):  # accetta qualsiasi firma
            pass
        def labels(self, **_kwargs):
            return self
        def inc(self, *_a, **_kw):
            pass
        def observe(self, *_a, **_kw):
            pass

    class Counter(_NoopMetric):  # type: ignore
        pass
    class Histogram(_NoopMetric):  # type: ignore
        pass

    class CollectorRegistry:  # type: ignore
        def __init__(self, *_a, **_k): pass

    def generate_latest(_r=None):  # type: ignore
        return b""

from wsgiref.simple_server import make_server

# OpenTelemetry tracing (fallback a no-op span)
try:
    from opentelemetry import trace  # type: ignore
    _HAS_OTEL = True
except Exception:
    trace = None  # type: ignore
    _HAS_OTEL = False

# ------------------------------------------------------------------------------
# Run ID (obbligatorio in ogni evento)
# ------------------------------------------------------------------------------

_RUN_ID: str = os.getenv("BG_RUN_ID") or f"run-{int(time.time())}"

def set_run_id(run_id: str) -> None:
    global _RUN_ID
    _RUN_ID = str(run_id).strip() or _RUN_ID

def get_run_id() -> str:
    return _RUN_ID


# ------------------------------------------------------------------------------
# Prometheus registry + metriche collegate
# ------------------------------------------------------------------------------

_registry = CollectorRegistry() if _HAS_PROM else None

# HTTP
request_counter = Counter(
    "bg_http_requests_total",
    "Numero di richieste HTTP effettuate",
    ["host", "method", "status", "run_id"],
    registry=_registry,
)
request_latency = Histogram(
    "bg_http_request_latency_seconds",
    "Tempo di risposta (RTT) in secondi",
    ["host", "method", "run_id"],
    registry=_registry,
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
)

# Eventi + errori + findings
events_total = Counter(
    "bg_events_total",
    "Eventi generici (scan/ingest/enrich/ai/etc.)",
    ["event_type", "source", "run_id"],
    registry=_registry,
)
errors_total = Counter(
    "bg_errors_total",
    "Errori registrati",
    ["source", "kind", "run_id"],
    registry=_registry,
)
findings_high = Counter("bg_findings_high_total", "Findings HIGH", ["source", "run_id"], registry=_registry)
findings_med  = Counter("bg_findings_medium_total", "Findings MED", ["source", "run_id"], registry=_registry)
findings_low  = Counter("bg_findings_low_total", "Findings LOW", ["source", "run_id"], registry=_registry)

# Latenze per fasi pipeline
stage_latency = Histogram(
    "bg_stage_latency_seconds",
    "Latenza per fase pipeline",
    ["stage", "run_id"],
    registry=_registry,
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)

# Detection/bypass per famiglia/policy
detection_counter = Counter(
    "bg_detection_total",
    "Detection attempts/hits per family",
    ["family", "outcome", "source", "run_id"],  # outcome: attempt|hit
    registry=_registry,
)
bypass_counter = Counter(
    "bg_bypass_total",
    "Bypass decisions per policy/family",
    ["policy", "family", "activated", "run_id"],  # activated: yes|no
    registry=_registry,
)


# ------------------------------------------------------------------------------
# API 1: track_scan_event — incrementa contatori con run_id
# ------------------------------------------------------------------------------

def track_scan_event(event_type: str, labels: Optional[Dict[str, Any]] = None) -> None:
    lbl = labels or {}
    run_id = get_run_id()
    src = str(lbl.get("source", "unknown"))

    # http_request
    if event_type == "http_request":
        host = str(lbl.get("host", "unknown"))
        method = str(lbl.get("method", "GET"))
        status = str(lbl.get("status", "0"))
        request_counter.labels(host=host, method=method, status=status, run_id=run_id).inc()
        latency = lbl.get("latency")
        if isinstance(latency, (int, float)):
            request_latency.labels(host=host, method=method, run_id=run_id).observe(float(latency))

    # finding by severity
    if event_type == "finding":
        sev = str(lbl.get("severity", "low")).lower()
        if sev.startswith("h"):
            findings_high.labels(source=src, run_id=run_id).inc()
        elif sev.startswith("m"):
            findings_med.labels(source=src, run_id=run_id).inc()
        else:
            findings_low.labels(source=src, run_id=run_id).inc()

    # error
    if event_type == "error":
        kind = str(lbl.get("kind", "generic"))
        errors_total.labels(source=src, kind=kind, run_id=run_id).inc()

    # evento generico
    events_total.labels(event_type=event_type, source=src, run_id=run_id).inc()

    # log strutturato
    logger = get_structured_logger("obs")
    safe_lbl = {k: v for k, v in lbl.items() if k not in ("latency",)}
    logger.info("event", event_type=event_type, run_id=run_id, **safe_lbl)


# ------------------------------------------------------------------------------
# API 1b: detection & bypass helpers
# ------------------------------------------------------------------------------

def record_detection(family: str, outcome: str = "attempt", source: str = "analysis") -> None:
    family = (family or "GENERIC").upper()
    outcome = "hit" if str(outcome).lower().startswith("h") else "attempt"
    detection_counter.labels(family=family, outcome=outcome, source=source, run_id=get_run_id()).inc()
    get_structured_logger("obs").info("detection", run_id=get_run_id(), family=family, outcome=outcome, source=source)

def record_bypass(family: str, policy: str, activated: bool, reason: Optional[str] = None) -> None:
    family = (family or "GENERIC").upper()
    policy = (policy or "default").lower()
    activated_str = "yes" if activated else "no"
    bypass_counter.labels(policy=policy, family=family, activated=activated_str, run_id=get_run_id()).inc()
    get_structured_logger("obs").info(
        "bypass",
        run_id=get_run_id(),
        family=family,
        policy=policy,
        activated=activated,
        reason=reason or "",
    )


# ------------------------------------------------------------------------------
# API 2: time_block — context manager per misurare fasi pipeline
# ------------------------------------------------------------------------------

@contextmanager
def time_block(stage: str, labels: Optional[Dict[str, Any]] = None) -> Generator[None, None, None]:
    run_id = get_run_id()
    t0 = time.perf_counter()
    try:
        yield
    except Exception as exc:
        track_scan_event("error", {"source": (labels or {}).get("source", stage), "kind": type(exc).__name__})
        raise
    finally:
        dt = time.perf_counter() - t0
        stage_latency.labels(stage=str(stage), run_id=run_id).observe(dt)
        logger = get_structured_logger("obs")
        logger.info("timing", stage=stage, duration=dt, run_id=run_id, **(labels or {}))
        track_scan_event("timing", {"source": (labels or {}).get("source", stage), "stage": stage, "duration": dt})


# ------------------------------------------------------------------------------
# Log di decisione
# ------------------------------------------------------------------------------

def log_decision(domain: str,
                 action: str,
                 decision: str,
                 result: str,
                 **extras: Any) -> None:
    get_structured_logger("obs").info(
        "decision",
        run_id=get_run_id(),
        domain=(domain or "unknown"),
        action=action,
        decision=decision,
        result=result,
        **extras,
    )

def report_populated_fields(rows, *, log_level=None):
    """
    Logga qualità dei dati del render_ready:
      - % righe con score / type / family
      - % WAF=None
      - Top-5 family e Top-5 risk_family markers
      - P95 latenza per family (ms)
      - In DEBUG: fino a 3 URL esempio mancanti per ciascun campo (score/type/family)
    Ritorna anche un dict riepilogativo (utile per test o ulteriori report).
    """
    import logging
    lvl = logging.INFO if log_level is None else log_level
    log = logging.getLogger(__name__)

    rows = rows or []
    n = len(rows)

    def _has_score(r):
        try:
            s = r.get("score", None)
            return isinstance(s, (int, float))
        except Exception:
            return False

    def _has_text(r, key):
        v = r.get(key, "")
        return bool(str(v).strip())

    def _pct(num, den):
        if not den:
            return 0.0
        return round((float(num) / float(den)) * 100.0, 1)

    # --- coverage campi
    n_score  = sum(1 for r in rows if _has_score(r))
    n_type   = sum(1 for r in rows if _has_text(r, "type"))
    n_family = sum(1 for r in rows if _has_text(r, "family"))

    # --- WAF=None
    def _is_waf_none(r):
        w = r.get("waf", "")
        wtxt = str(w or "").strip().lower()
        return (wtxt == "") or (wtxt == "none") or (wtxt == "no") or (wtxt == "false") or (wtxt == "0")

    n_waf_none = sum(1 for r in rows if _is_waf_none(r))

    # --- top family
    from collections import Counter, defaultdict
    fam_counter = Counter()
    for r in rows:
        fam = str(r.get("family") or "").strip() or "—"
        fam_counter[fam] += 1
    top_fam = fam_counter.most_common(5)

    # --- top risk_family markers (pipe-separated: "xss|sqli|...")
    risk_counter = Counter()
    for r in rows:
        rf = str(r.get("risk_family") or "").strip()
        if not rf:
            continue
        for tok in (t.strip().lower() for t in rf.split("|")):
            if tok:
                risk_counter[tok] += 1
    top_risk = risk_counter.most_common(5)

    # --- P95 latenza per family
    lat_by_fam = defaultdict(list)
    for r in rows:
        try:
            lat = r.get("lat", None)
            if lat is None:
                continue
            lat = float(lat)
            fam = str(r.get("family") or "").strip() or "—"
            lat_by_fam[fam].append(lat)
        except Exception:
            continue

    def _perc(v, q=0.95):
        if not v:
            return None
        vv = sorted(v)
        # indice tipo "nearest rank"
        idx = int(round(q * (len(vv) - 1)))
        idx = max(0, min(len(vv) - 1, idx))
        return float(vv[idx])

    p95_by_fam = {fam: int(_perc(v) or 0) for fam, v in lat_by_fam.items() if v}

    # --- esempi mancanti (DEBUG)
    def _collect_missing_examples(key_check, max_n=3):
        out = []
        for r in rows:
            ok = False
            if key_check == "score":
                ok = _has_score(r)
            else:
                ok = _has_text(r, key_check)
            if not ok:
                u = str(r.get("url") or "")
                if u:
                    out.append(u)
                if len(out) >= max_n:
                    break
        return out

    miss_score  = _collect_missing_examples("score")
    miss_type   = _collect_missing_examples("type")
    miss_family = _collect_missing_examples("family")

    # --- log sintetico
    log.log(lvl,
        "Data coverage — SCORE: %.1f%%  TYPE: %.1f%%  FAMILY: %.1f%%  |  WAF=None: %.1f%%  (n=%d)",
        _pct(n_score, n), _pct(n_type, n), _pct(n_family, n), _pct(n_waf_none, n), n
    )

    if top_fam:
        top_fam_str = ", ".join(f"{k}:{v}" for k, v in top_fam)
        log.log(lvl, "Top-5 FAMILY: %s", top_fam_str)
    if top_risk:
        top_risk_str = ", ".join(f"{k}:{v}" for k, v in top_risk)
        log.log(lvl, "Top-5 risk_family markers: %s", top_risk_str)
    if p95_by_fam:
        p95_str = ", ".join(f"{k}={v}ms" for k, v in sorted(p95_by_fam.items(), key=lambda x: (-x[1], x[0])))
        log.log(lvl, "P95 latency by FAMILY: %s", p95_str)

    # --- esempi in DEBUG
    if log.isEnabledFor(logging.DEBUG):
        if miss_score:
            log.debug("Missing SCORE examples: %s", ", ".join(miss_score))
        if miss_type:
            log.debug("Missing TYPE examples: %s", ", ".join(miss_type))
        if miss_family:
            log.debug("Missing FAMILY examples: %s", ", ".join(miss_family))

    # payload di ritorno (utile per test/unit o export interno)
    return {
        "total": n,
        "score_pct": _pct(n_score, n),
        "type_pct": _pct(n_type, n),
        "family_pct": _pct(n_family, n),
        "waf_none_pct": _pct(n_waf_none, n),
        "top_family": top_fam,
        "top_risk_markers": top_risk,
        "p95_latency_by_family": p95_by_fam,
        "missing_examples": {
            "score": miss_score,
            "type": miss_type,
            "family": miss_family,
        },
    }
def report_waf_coverage(rows):
    """
    Logga copertura WAF: % con vendor, % None, e top vendor con conteggi.
    """
    try:
        n = len(rows or [])
        if n == 0:
            print("WAF coverage: n=0")
            return
        import collections
        cnt = 0
        flat = []
        for r in rows:
            v = r.get("waf_vendors") or []
            if v:
                cnt += 1
                flat.extend(v)
        pct = (100.0 * cnt / max(1, n))
        top = collections.Counter([x for x in flat if x]).most_common(5)
        print(f"WAF coverage — any: {pct:.1f}%  None: {100.0-pct:.1f}%  (n={n})  Top: " +
              ", ".join(f"{k}:{c}" for k,c in top) if top else "WAF coverage — any: 0.0%  None: 100.0%")
    except Exception as e:
        print(f"[obs] report_waf_coverage failed: {e}")

# ------------------------------------------------------------------------------
# Metrics HTTP server / percentili (p50/p95)
# ------------------------------------------------------------------------------

def _metrics_app(environ, start_response):
    if not _HAS_PROM:
        start_response("200 OK", [("Content-Type", CONTENT_TYPE_LATEST)])
        return [b""]
    if environ.get("PATH_INFO") == "/metrics":
        data = generate_latest(_registry)
        start_response("200 OK", [("Content-Type", CONTENT_TYPE_LATEST)])
        return [data]
    start_response("404 Not Found", [])
    return [b""]

def init_metrics_server(port: int = 8000, host: str = "0.0.0.0") -> None:
    def run_server():
        with make_server(host, port, _metrics_app) as httpd:
            logger = get_structured_logger("metrics")
            logger.info("metrics_server_started", host=host, port=port, run_id=get_run_id())
            httpd.serve_forever()
    t = threading.Thread(target=run_server, daemon=True)
    t.start()

def _percentiles_from_histogram_text(metric_name: str, label_filter: Optional[Dict[str, str]] = None) -> Dict[str, float]:
    if not _HAS_PROM:
        return {"p50": 0.0, "p95": 0.0}
    data = generate_latest(_registry).decode("utf-8")
    label_filter = label_filter or {}

    def _match_labels(line: str) -> bool:
        for k, v in label_filter.items():
            if f'{k}="{v}"' not in line:
                return False
        return True

    buckets = []
    pattern = re.compile(rf'.*{re.escape(metric_name)}_bucket\{{.*le="([^"]+)"\}} (\d+)')
    for line in data.splitlines():
        if metric_name not in line:
            continue
        if not _match_labels(line):
            continue
        m = pattern.match(line)
        if m:
            bound = float(m.group(1))
            count = int(m.group(2))
            buckets.append((bound, count))
    if not buckets:
        return {"p50": 0.0, "p95": 0.0}
    buckets.sort(key=lambda x: x[0])
    total = buckets[-1][1]
    if total <= 0:
        return {"p50": 0.0, "p95": 0.0}
    p50 = p95 = 0.0
    for bound, count in buckets:
        frac = count / total
        if p50 == 0.0 and frac >= 0.5:
            p50 = bound
        if frac >= 0.95:
            p95 = bound
            break
    return {"p50": p50, "p95": p95}

def rolling_http_percentiles() -> Dict[str, float]:
    return _percentiles_from_histogram_text("bg_http_request_latency_seconds")

def stage_percentiles(stage: str) -> Dict[str, float]:
    return _percentiles_from_histogram_text("bg_stage_latency_seconds", {"stage": str(stage)})

def start_metrics_collector(interval_sec: int = 30) -> None:
    logger = get_structured_logger("metrics_collector")
    def collector():
        while True:
            http_vals = rolling_http_percentiles()
            probe_vals = stage_percentiles("probe")
            enrich_vals = stage_percentiles("enrich")
            logger.info(
                "rolling_metrics",
                run_id=get_run_id(),
                http_p50=http_vals["p50"], http_p95=http_vals["p95"],
                probe_p50=probe_vals["p50"], probe_p95=probe_vals["p95"],
                enrich_p50=enrich_vals["p50"], enrich_p95=enrich_vals["p95"],
            )
            time.sleep(interval_sec)
    t = threading.Thread(target=collector, daemon=True)
    t.start()


# ------------------------------------------------------------------------------
# Snapshot helpers
# ------------------------------------------------------------------------------

def snapshot_hit_rates() -> Dict[str, Dict[str, float]]:
    if not _HAS_PROM:
        return {}
    text = generate_latest(_registry).decode("utf-8")
    det_re = re.compile(r'.*bg_detection_total\{[^}]*family="([^"]+)"[^}]*outcome="([^"]+)"[^}]*\}\s+(\d+)')
    acc: Dict[str, Dict[str, int]] = {}
    for line in text.splitlines():
        m = det_re.match(line)
        if not m:
            continue
        fam, outcome, val = m.group(1), m.group(2), int(m.group(3))
        d = acc.setdefault(fam, {"attempt": 0, "hit": 0})
        if outcome == "hit":
            d["hit"] += val
        else:
            d["attempt"] += val
    out: Dict[str, Dict[str, float]] = {}
    for fam, d in acc.items():
        a = int(d.get("attempt", 0))
        h = int(d.get("hit", 0))
        denom = a if a > 0 else (h if h > 0 else 1)
        out[fam] = {"attempts": float(a), "hits": float(h), "hit_rate": float(h) / float(denom)}
    return out

def snapshot_bypass_rates() -> Dict[str, Any]:
    if not _HAS_PROM:
        return {"by_policy": {}, "by_family": {}}
    text = generate_latest(_registry).decode("utf-8")
    by_pol: Dict[str, Dict[str, int]] = {}
    by_fam: Dict[str, Dict[str, int]] = {}
    re_b = re.compile(r'.*bg_bypass_total\{[^}]*policy="([^"]+)"[^}]*family="([^"]+)"[^}]*activated="([^"]+)"[^}]*\}\s+(\d+)')
    for line in text.splitlines():
        m = re_b.match(line)
        if not m:
            continue
        pol, fam, act, val = m.group(1), m.group(2), m.group(3), int(m.group(4))
        pol_d = by_pol.setdefault(pol, {"attempts": 0, "activated": 0})
        fam_d = by_fam.setdefault(fam, {"attempts": 0, "activated": 0})
        pol_d["attempts"] += val
        fam_d["attempts"] += val
        if act == "yes":
            pol_d["activated"] += val
            fam_d["activated"] += val

    def _mk(out_map: Dict[str, Dict[str, int]]) -> Dict[str, Dict[str, float]]:
        out: Dict[str, Dict[str, float]] = {}
        for k, d in out_map.items():
            a = int(d.get("attempts", 0))
            s = int(d.get("activated", 0))
            denom = a if a > 0 else (s if s > 0 else 1)
            out[k] = {"attempts": float(a), "activated": float(s), "activation_rate": float(s) / float(denom)}
        return out

    return {"by_policy": _mk(by_pol), "by_family": _mk(by_fam)}


# ------------------------------------------------------------------------------
# Tracing (opzionale)
# ------------------------------------------------------------------------------

_tracer = trace.get_tracer(__name__) if _HAS_OTEL else None  # type: ignore

def init_tracer(service_name: str = "brutal-gorilla") -> None:
    if not _HAS_OTEL:
        get_structured_logger("otel").info("otel_disabled", reason="opentelemetry not available", run_id=get_run_id())
        return
    try:
        from opentelemetry.sdk.resources import Resource  # type: ignore
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter  # type: ignore
        resource = Resource(attributes={"service.name": service_name})
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        trace.set_tracer_provider(provider)
        global _tracer
        _tracer = trace.get_tracer(__name__)  # type: ignore
        get_structured_logger("otel").info("otel_initialized", service_name=service_name, run_id=get_run_id())
    except Exception as e:
        get_structured_logger("otel").info("otel_init_failed", error=str(e), run_id=get_run_id())

@contextmanager
def trace_span(name: str, attrs: Optional[Dict[str, Any]] = None) -> Generator[None, None, None]:
    if not _HAS_OTEL or _tracer is None:
        logger = get_structured_logger("trace")
        logger.info("span_start", name=name, run_id=get_run_id(), **(attrs or {}))
        try:
            yield
        except Exception as exc:
            logger.error("span_error", name=name, err=type(exc).__name__, run_id=get_run_id())
            raise
        finally:
            logger.info("span_end", name=name, run_id=get_run_id())
        return

    from opentelemetry.trace import Status, StatusCode  # type: ignore
    with _tracer.start_as_current_span(name) as span:  # type: ignore
        try:
            if attrs:
                for k, v in attrs.items():
                    try:
                        span.set_attribute(k, v)  # type: ignore
                    except Exception:
                        pass
            yield
        except Exception as exc:
            span.record_exception(exc)  # type: ignore
            span.set_status(Status(StatusCode.ERROR, str(exc)))  # type: ignore
            raise


# ------------------------------------------------------------------------------
# Self-test (facoltativo)
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    set_run_id("demo-run")
    init_metrics_server(8000)

    import random
    log = get_structured_logger("demo")
    hosts = ["example.com", "api.test", "slow.net"]
    methods = ["GET", "POST"]

    for _ in range(30):
        host = random.choice(hosts)
        method = random.choice(methods)
        status = random.choice([200, 404, 500, 429])
        with time_block("probe", {"source": "probe"}):
            t0 = time.perf_counter()
            time.sleep(random.uniform(0.05, 0.25))
            rtt = time.perf_counter() - t0
            track_scan_event("http_request", {"host": host, "method": method, "status": status, "latency": rtt})
            if status >= 500:
                track_scan_event("error", {"source": "probe", "kind": "http_5xx"})
            fam = random.choice(["XSS", "SQLI", "IDOR_BENIGN"])
            record_detection(fam, "attempt")
            if random.random() < 0.4:
                record_detection(fam, "hit")
            pol = random.choice(["soft_encode", "json_wrap"])
            record_bypass(fam, pol, activated=random.random() < 0.5, reason="heuristic")

    log_decision("example.com", action="waf_bypass", decision="activate", result="ok", family="XSS")

    print("Hit-rates:", snapshot_hit_rates())
    print("Bypass rates:", snapshot_bypass_rates())
    print("HTTP p50/p95:", rolling_http_percentiles())
    print("Probe p50/p95:", stage_percentiles("probe"))

    print("Demo ready: visit http://localhost:8000/metrics")
