# GHOSTSHINOBI Cybersec CLI (aka **brutal\_gorilla\2.0**)

Command-line toolkit to **map web attack surface** from endpoint lists, orchestrate parallel HTTP probes, score findings, and render **clean ASCII reports** (plus JSON/CSV) you can drop into a workflow or paste into tickets.

---

## Highlights

* **Endpoint-driven scanning** (from `endpoints.txt`)
* **Parallel HTTP probes** (GET/HEAD/POST/OPTIONS), configurable **concurrency/timeout/retries**
* **Light/Deep profiles** (deep adds bypass attempts, A/B corroboration, extra heuristics)
* **Top-10 “Attackable Paths”**, **Quality Gate**, **Family Sources**, **Cookie & Cache audit**, and a **paged Full Results** table
* **Graceful AI fallbacks**: banners show what’s ON/OFF (SecureBERT, Embeddings, SHAP, FAISS, etc.)
* **Export** to **JSON/CSV** with normalized rows (`render_ready`) and section text blocks

> **Note:** The **Ingest** flow is **disabled** (beta development). Only **Scan** is enabled.

---

## Installation

```bash
git clone https://github.com/<org>/<repo>.git
cd brutal_gorilla_3
python3 -m venv .venv
source .venv/bin/activate
# Two requirement sets are provided; install what you need:
pip install -r requirements.txt
pip install -r requirements_scan.txt    # scan-focused extras
```

---

## Run a Scan (quick)

1. Create `endpoints.txt` (one per line; `#` for comments):

```txt
https://www.example.com/
https://api.example.com/v1/items?id=1
https://auth.example.com/login
```

2. Launch:

```bash
# helper script
./gscli
# or directly
python cli.py
```

3. Choose **1 – Start Scan** and answer prompts:

* **Profile**: `light` or `deep`
* **Rows per page** (for the table)
* **Concurrency / Timeout / Retries**
* **Export**: `none | json | csv | both`

You’ll get rich **ASCII sections in terminal** and, if selected, files:

* `orchestrator_output.json`
* `orchestrator_results.csv`

---

## How the Scan Works (pipeline)

1. **Endpoint loading & cleaning**
   Reads `endpoints.txt`, drops comments/empties, de-dups, applies basic normalization.

2. **Budget & profile**
   Applies your **concurrency**, **timeout**, and **retries**; `light` keeps it lean, **`deep` adds**:

   * extra verb/method probes,
   * **A/B checks** (compare responses to corroborate anomalies),
   * simple **bypass attempts**,
   * additional heuristics and hint flags.

3. **Probing**
   Orchestrator fans out **HTTPX** requests (GET/HEAD/POST/OPTIONS). It captures:

   * status, latency, size
   * **headers** (CORS, cache, cookies, CSP)
   * basic **WAF signals** (vendors from headers/behavior)
   * **edge vs origin** hints (where visible)

4. **Scoring & signals**
   Each row is enriched with:

   * **confidence/severity**, **score** (0–1 or %)
   * **flags** (e.g., `+OPENREDIR`, `+CORS`, `+AUTH`, `+SQLI` hints)
   * **reasons/psi hits** (signature/heuristic IDs)
   * family/type (API/AUTH/WEBPAGE/etc.)
   * optional **A/B evidence** deltas (status/size/reflection)
   * optional model signals (if available: **SecureBERT**, embeddings, SHAP)

5. **Normalization**
   Results are flattened into `render_ready` (stable keys and types) and grouped stats (e.g., **Top Domains**).

6. **Section building BETA ONLY( NOT AVAIBLE YET ) **
   `analysis_extend.finalize_report_hook(...)` composes human-readable sections:

   * **ATTACKABLE PATHS — TOP 10** (signature, evidence, reasons, next steps, context)
   * **QUALITY GATE** (totals, reliability, latency p95/IQR, notes/seeds)
   * **FAMILY SOURCES (KB vs AI)** (share of knowledge-base vs model-assisted)
   * **COOKIE & CACHE AUDIT** (host/path issues)
   * **FULL RESULTS** (paged table)

7. **Rendering**

   * If present, `output_formatter.render_ascii(...)` renders all sections.
   * Otherwise, a resilient **adapter** (`cli_render_ascii`) prints a compact **fallback** with pagination.

8. **Export**
   Depending on your choice: write **JSON** (sections + `render_ready`) and/or **CSV** (flat rows) to disk.

---

## Output Sections (at a glance)

* **ATTACKABLE PATHS — TOP 10(( IN DEVELOPMENT, NOT AVAIBLE YET)**
  Rank, score, confidence, family, method, flags, URL

  * **SIG** (signature), **EVIDENCE** (A/B deltas/reflection/DB hints), **REASONS** (rules), **NEXT** (what to try), **CONTEXT** (PSI hits, edge/origin, WAF)

* **QUALITY GATE( IN DEVELOPMENT, NOT AVAIBLE YET) **
  High/Med/Low totals & %, verdict, reliability (A/B corroborated, edge blocks), latency stats, notes/seeds to explore.

* **FAMILY SOURCES (KB vs AI)(( IN DEVELOPMENT, NOT AVAIBLE YET)**
  Bar split indicating how much came from hard rules/KB vs model assistance.

* **COOKIE & CACHE AUDIT(( IN DEVELOPMENT, NOT AVAIBLE YET)**
  Per host/path, shows cookie/caching misconfigs relevant to auth/API pages.

* **FULL RESULTS (paged)**
  `# | SEV | SCORE | METH | STAT | LAT(ms) | SIZE | TYPE | FAMILY | WAF | FLAGS | REASONS | URL`

---

## Configuration & Environment

A `config.yaml` is created/updated automatically:

```yaml
endpoints_file: endpoints.txt
output_file: orchestrator_output.json
output_csv: orchestrator_results.csv
write_outputs: false
export_format: none            # none|json|csv|both
profile_default: light         # light|deep
page_size_default: 100
concurrency_default: 8
timeout_s_default: 10.0
retries_default: 1
```

The CLI also sets these env vars (read by the orchestrator and helpers):

* `SCAN_ENDPOINTS_FILE`
* `SCAN_EXPORT_FORMAT` (`none|json|csv|both`)
* `SCAN_WRITE_OUTPUTS` (`0|1`)
* `BG_PROFILE` (`light|deep`)
* `BG_BUDGET_JSON` (JSON with `concurrency/timeout_s/retries`)
* `PROBE_CONCURRENCY`, `PROBE_TIMEOUT_S`, `PROBE_RETRIES`

---

## Ingest Status

The **Ingest** pipeline is **not enabled** yet — it’s in **beta development**. All menus/options related to ingestion are placeholders until the feature is stabilized.

---

## Contributing

PRs welcome. Keep changes testable, avoid global side-effects, prefer pure functions, and extend `render_ready`/sections consistently when adding new signals or columns.

---

## Legal

Use **only on assets you are authorized to test**. The authors and contributors are not responsible for misuse.

---

RENDER

```text
[gscli] Using: /Users/ghostshinobi/Desktop/brutal_gorilla_3/scan_env/bin/python
[+] Environment 'ingest_env' already exists.
[+] Environment 'scan_env' already exists.
[+] Environment 'ai_env' already exists.

┌───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
|
| ⣿⣿⠁⢠⣶⣶⣦⡀⢹⣷⠀⠀⣾⣿⣿⣟⣛⠛⠛⢿⣿⣿⣿⣿⣿⣌⢻⣧⡙⣿⠛⣿⡏⣱⡿⢋⣵⣿⣿⡿⠟⡛⠛⠛⢛⣛⣿⣿⣿⡄⠀⢀⣿⠀⣥⣶⣶⣄⠈⢻⣿⣿    | __ )|  _ \ | | | ||__  __|  / \  | |
| ⣿⡇⢀⠟⠉⠉⠻⣧⠈⣿⠀⠈⢿⣿⣿⣿⠋⠀⠀⣀⠈⠙⢾⣿⣿⣿⣧⡙⠃⣿⠀⣿⠁⠟⣱⣿⣿⣿⣯⠖⠋⢀⠀⠀⠙⣿⣿⣿⣿⠇⠀⣸⡏⢰⡿⠋⠉⠛⡇⠈⣿⣿    |  _ \| |_)| | | | |  | |    / _ \ | |
| ⣿⡇⠈⣶⣿⠟⣡⡘⠀⢿⡇⠀⠈⠻⣿⣿⣧⡀⠀⠙⠄⠀⠀⠈⠛⠿⠿⠃⠀⠀⠀⠀⠀⠈⠿⠿⠟⠋⠀⣀⠀⠛⠁⢀⣴⣿⣿⠟⠁⠀⢀⣿⠁⠎⢀⡛⢿⣷⡇⠀⣿⣿    | |_) |  _ < | |_| |  | |   / ___ \| |__
| ⣿⣿⠀⢻⣇⣾⣿⡧⠁⣸⡇⠀⢀⣤⠈⡿⢿⣿⣥⣀⣀⣀⣀⣠⡤⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⠤⣀⣀⣀⣀⣀⣀⣽⣿⡿⠏⣠⡀⠀⠘⣿⠐⢰⣿⣿⣌⣿⠁⣸⣿⣿    |____/|_|_\_\ \___/ _ | |_ /_/   \_\_____|
| ⣿⣿⣧⠀⢿⡿⢋⣴⣾⠟⠀⠀⣾⣿⣿⣿⣶⣾⣿⣿⣿⣿⣿⡟⢠⡖⠒⢶⣤⣤⣤⣤⣤⣤⠖⠲⢄⠹⣿⣿⣿⣿⣿⣯⣵⣾⣿⣿⡧⡆⠀⠙⢿⣦⡍⠻⢿⠇⢠⣿⣿⣿
| ⣿⣿⣿⡇⠀⠴⣿⡍⠁⠀⠀⠀⠸⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡈⠀⣿⡰⠇⠀⠙⣿⣿⣿⠟⠁⠘⠆⢸⡄⠋⣼⣿⣿⣿⣿⣿⡿⠿⠫⠝⠀⠀⠀⠀⠈⣙⠃⠀⠀⢿⣿⣿    / ___|/ _ \ |  _ \|_  | |   | |      / \
| ⣿⣿⣿⠄⢠⡾⠋⠀⠀⠀⡀⠀⠀⠀⠉⠙⠛⠻⢿⣿⣿⡿⣿⣦⣤⡙⢷⣦⣤⠸⣿⠿⣠⣤⡶⢟⣁⣴⣾⣿⢛⣭⣥⠴⠒⠋⠀⠀⠀⠀⡀⢄⠀⠀⠈⠳⣄⠐⢦⣿⣿⣿    | |  _| | | | |_) || || |   | |     / _ \
| ⣿⣿⠋⢠⡟⠁⠀⠀⠈⣴⡰⢂⡤⠀⠀⠀⠀⠀⠈⠙⢱⣷⣿⣿⣿⣿⣿⣿⣿⣷⡖⣾⣿⣿⣿⣿⣿⣿⣿⣿⣆⠙⠁⠀⠀⡀⠀⢄⡘⢶⣌⣾⣦⠀⠀⠀⠹⣆⠀⢿⣿⣿    | |_| | |_| |  _ < | || |___| |___ / ___ \
| ⣿⠃⠠⢋⡀⠀⠀⠀⣾⣿⣿⡿⣡⡞⣀⡴⠀⠀⠀⠀⢛⣫⣭⣿⣿⣿⣿⣿⣿⠛⠁⠻⣿⣿⣿⣿⣿⣿⣿⣿⣷⡆⠀⠀⠀⠈⢦⡌⢿⣬⣿⣿⣿⡆⠀⠀⠀⢨⣆⠀⢻⣿     \____|\___/|_| \_\___|_____|_____/_/   \_\
| ⠇⠀⢀⡿⠀⠀⠀⠀⢿⣿⣿⣿⣿⣼⡟⠀⠀⠀⢠⣾⣿⣿⣿⠿⠿⠿⠿⠿⠿⠿⣿⣷⣦⣽⣿⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠈⢿⣿⣿⣿⣿⢿⠁⠀⠀⠀⢸⣇⠀⠀⢿
|   
                          |        GHOSTSHINOBI 2025 CYBERSEC EXTREME  +      |
                          └───────────────────────────────────────────────────┘

[+] Ingestion database found.
Welcome to the GHOSTSHINOBI Cybersec CLI

Select an option:

1 - Start Scan
2 - Ingest File or URL
3 - Config
4 - Legend / Help
9 - Doctor (preflight)
0 - Exit

════════════════════════════════ ATTACKABLE PATHS — TOP 10 ═══════════════════════════════
#  SCORE  CONF  FAMILY   METH  FLAGS                   URL
-- ------ ----- -------- ----- ----------------------- ---------------------------------------------------
1  9.5    HIGH  API      GET   +SQLI|+IDOR            https://api.example.com/v1/items?id=*
   SIG        : {/v1/items?{id}}
   EVIDENCE   : A/B Δstatus=+100, Δsize=+2.3KB, reflect=YES, DB=MYSQL
   REASONS    : E-SQL-ERR | E-REFLECT | W-IDOR-HINT | H-CSP-MISS
   NEXT       : UNION/boolean tests, param tampering on id
   CONTEXT    : PSI=0.82 hits={id}  Edge=FALSE  WAF=Cloudflare(origin)

2  8.7    HIGH  AUTH     POST  +CORS|+AUTH            https://auth.example.com/login
   SIG        : {/login?{user,pwd}}
   EVIDENCE   : CORS(* + credentials), Cookie SameSite=None, Cache-Control=public
   REASONS    : C-CORS-ANY | H-COOKIE-UNSAFE | H-CACHE-PUBLIC
   NEXT       : CSRF checks, session fixation
   CONTEXT    : PSI=0.61 hits={user,pwd}  Edge=TRUE  WAF=Cloudflare(edge)

3  8.4    MED   WEBPAGE  GET   +OPENREDIR             https://www.example.com/continue?next=*
   SIG        : {/continue?{next}}
   EVIDENCE   : accepts absolute URL, redir out of domain
   REASONS    : W-OPENREDIR
   NEXT       : External redirect to attacker URL + token capture
   CONTEXT    : PSI=0.77 hits={next}  Edge=FALSE  WAF=None

... (fino a #10)

════════════════════════════════ QUALITY GATE ════════════════════════════════════════════
Totals     High: 6 (4.5%)   Medium: 18 (13.6%)   Low: 108 (81.8%)   Verdict: POOR
Signals    Strong flags: LOW    API/AUTH surface: MED    Static assets: HIGH
Reliab.    A/B corroborated: 2/10    Edge-only blocks: 7    CT mismatch: 3
Latency    p95(ms): 940   IQR(ms): 120   (capped outliers: YES)
Notes      Seeds to explore next: /api/*  /login/*  /admin/*  /callback/*  /export/*  /search/*

════════════════════════════════ FAMILY SOURCES (KB vs AI) ═══════════════════════════════
KB  ████████████████████████  78%
AI  ████████                  22%

════════════════════════════════ COOKIE & CACHE AUDIT ════════════════════════════════════
Host/Path                                   Issues
------------------------------------------- -------------------------------------------------------
auth.example.com /login                     H-COOKIE-UNSAFE (SameSite=None), H-CACHE-PUBLIC
www.example.com  /account/reset             H-COOKIE-NOHTTPONLY, H-CACHE-STALE
api.example.com  /v1/export                 H-CACHE-PUBLIC (sensitive API), H-COOKIE-NOSEC

════════════════════════════════ FULL RESULTS (paged table) ═══════════════════════════════
---- ---- ------- ------ ------ -------- -------- ------------------ ---------- ------------------ -------------------- ------------------------------------ ----------------------------------------
#    SEV  SCORE   METH   STAT   LAT(ms)  SIZE     TYPE               FAMILY    WAF                FLAGS                REASONS                             URL
---- ---- ------- ------ ------ -------- -------- ------------------ ---------- ------------------ -------------------- ------------------------------------ ----------------------------------------
1    HIGH 95%     GET    500       210   12.4KB   json               API       Cloudflare         +SQLI +IDOR          E-SQL-ERR|E-REFLECT|H-CSP-MISS      https://api.example.com/v1/items?id=...
2    HIGH 87%     POST   200       180   3.1KB    html               AUTH      Cloudflare(edge)   +CORS +AUTH          C-CORS-ANY|H-COOKIE-UNSAFE          https://auth.example.com/login
3    MED  84%     GET    302        90   0.8KB    html               WEBPAGE   None               +OPENREDIR           W-OPENREDIR                         https://www.example.com/continue?next=...
4    MED  79%     GET    200       240   9.2KB    html               API       Akamai             +XSS                  E-REFLECT|H-CSP-MISS               https://api.example.com/search?q=...
...
---- ---- ------- ------ ------ -------- -------- ------------------ ---------- ------------------ -------------------- ------------------------------------ ----------------------------------------

Legend: WAF seen: Cloudflare|Akamai|AWS     FLAGS seen: +SQLI|+IDOR|+OPENREDIR|+XSS|+CORS|+AUTH|+WEAKHDRS

Select an option:

1 - Start Scan
2 - Ingest File or URL
3 - Config
4 - Legend / Help
9 - Doctor (preflight)
0 - Exit
```







## License
OPEN SOURCE

