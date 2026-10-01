# ReconToReport

A CLI pipeline that orchestrates **open-source** security tools into a
client-facing vulnerability assessment report. No commercial software required.

> ⚠️ **Authorized testing only.** ReconToReport runs *active* scans against the
> target. Only use it against systems you have explicit, written permission to
> test. Active phases refuse to run unless you pass `--i-have-authorization`.

## Status

This is an **incremental build**. What's implemented and working today:

- ✅ Project scaffold, packaging (`pyproject.toml`), YAML config
- ✅ Full SQLite data model (SQLAlchemy 2.0) + Alembic migrations
- ✅ Orchestrator: phase sequencing, per-phase retry/error isolation,
  `--phases` subset selection, authorization gate
- ✅ **Phase 1**: `subfinder` + `ffuf`
  (subdomain discovery + content bruteforce with sensitive-file flagging)
- ✅ **Phase 2**: `mitmproxy` capture addon (logs every request/response +
  WebSocket message into `http_transactions`) and Playwright auth capture
  (persists `storage_state` per role into `auth_contexts`)
- ✅ **Phase 3**: `nuclei` scanner → `findings`, privilege-escalation diffing
  (replays high-priv transactions with lower-priv contexts), and a reflected/DOM
  XSS canary (Playwright)
- ✅ **Phase 4**: JWT weakness analysis (alg=none / weak secret / no-exp) over
  captured traffic, and `sqlmap` against parameterized in-scope URLs
- ✅ **Phase 5**: secret scraping (emails, keys, Luhn-checked cards) over
  captured transactions → `secret_matches`
- ✅ Jinja2 HTML report (and XML) grouped by severity
- ⏳ Remaining Phase 1 tools (`amass`, `prance`/OpenAPI, `katana`) and the
  higher-impact Phase 4 integrations (`interactsh` OOB, `hydra`) are stubbed /
  documented for an explicit per-engagement decision.

### Phases & dependencies

Selecting a phase auto-runs its prerequisites (ascending order):

| Phase | Name    | Active? | Depends on |
|------:|---------|---------|------------|
| 1     | recon   | yes     | —          |
| 2     | traffic | yes     | —          |
| 3     | scan    | yes     | 1          |
| 4     | exploit | yes     | 3 (→1)     |
| 5     | harvest | no      | —          |

So `--phases 4` actually runs `1, 3, 4`. "Active" phases need
`--i-have-authorization`; Phase 5 is offline and does not.

## Quick start (one command each)

A `Makefile` wraps the whole workflow — everything runs inside a local `.venv`,
no manual `source activate` needed. Run `make help` to see all targets.

```bash
make setup            # create venv + install the package
make config           # create config.yaml from the example (then edit it)
make db               # create/upgrade the database schema (Alembic)

# install the external CLI tools (subfinder, ffuf, ...) — review the script first
bash scripts/install-tools.sh
make check-tools      # verify which tools are installed

make run              # DRY RUN: active phases SKIPPED (no authorization)
make scan             # AUTHORIZED run: active phases EXECUTE (needs permission!)
make report           # render HTML/XML report from the store

make query Q="SELECT title, severity FROM findings ORDER BY severity DESC"
make test             # run the unit tests
make clean            # remove venv, reports, caches
```

Override defaults inline, e.g. run a different phase subset or config file:

```bash
make scan PHASES=1 CONFIG=client-a.yaml
```

## Architecture

```
recontoreport/
├── cli.py            # click entrypoint (run / report / initdb)
├── config.py         # YAML config loader + scope matching
├── schema.py         # shared enums / normalized vocabulary
├── models.py         # SQLAlchemy ORM — the shared data store
├── db.py             # engine/session helpers
├── orchestrator.py   # main loop: sequencing, retries, auth gate
├── tools/runner.py   # safe subprocess wrapper (no shell=True, timeouts)
├── phases/
│   ├── base.py       # Phase ABC + PhaseContext/PhaseResult
│   └── phase1_recon.py   # subfinder + ffuf (reference impl)
└── report/
    ├── generator.py
    └── templates/report.html.j2  (+ report.xml.j2)
migrations/           # Alembic
```

### Data model

`targets`, `auth_contexts`, `assets`, `http_transactions`, `findings`,
`evidence`, `secret_matches`, `reports` — see `recontoreport/models.py`. Every
phase writes into this store; later phases query it for context from earlier
phases.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .                      # core
pip install -e ".[dev]"               # + tests/lint
pip install -e ".[proxy,browser,scan]"  # Phase 2–4 python libs, as you get there
```

The **external CLI tools** (`subfinder`, `ffuf`, `amass`, `katana`, `nuclei`,
`mitmproxy`, `sqlmap`, …) are **not** bundled or installed by this project —
install them yourself and point `config.yaml` at them (or rely on `$PATH`).

## Configure

```bash
cp config.example.yaml config.yaml
# edit: target.url, scope.include/exclude, wordlists.content_discovery, tool paths
```

Nothing is assumed for you: the **wordlist path**, **nuclei template set**, and
any **API keys** are empty by default. Steps that need them error out early with
a clear message rather than guessing.

## Database setup

```bash
# Option A — Alembic (recommended; reads database.url from config.yaml)
RECONTOREPORT_CONFIG=config.yaml alembic upgrade head

# Option B — quick start (creates tables directly)
r2r initdb --config config.yaml
```

## Run

```bash
# Dry run (no authorization): active phases are SKIPPED, report still renders
r2r run --config config.yaml --phases 1

# target on the command line (overrides config target.url; host auto-added to scope)
r2r run --url https://target.com --config config.yaml --phases 1 --i-have-authorization

# run everything (1-5); dependencies are resolved automatically
r2r run --config config.yaml --phases all --i-have-authorization

# a single phase pulls in its prerequisites: this runs 1, 3, 4
r2r run --config config.yaml --phases 4 --i-have-authorization

# phases accept commas or spaces
r2r run --config config.yaml --phases "1 2 3" --i-have-authorization

# Render a report from the existing store without scanning
r2r report --config config.yaml
```

## Phase 2 — traffic capture & auth

Needs the proxy/browser extras and a browser binary:

```bash
pip install -e ".[proxy,browser]"
playwright install chromium
```

**Authenticated capture** — configure `auth.roles` in `config.yaml` (a login
URL + form selectors, or a custom `script` exposing `login(page, role)` for
SSO/MFA). Each role is logged in via Playwright through the proxy; its session
is saved to `auth_contexts` and its traffic to `http_transactions`:

```bash
r2r run --config config.yaml --phases 2 --i-have-authorization
```

**Passive capture** — with no roles configured, the proxy stays up for
`proxy.capture_window_seconds`. Point your browser (or another tool) at
`http://127.0.0.1:8080` and drive traffic through it; everything is logged.

The mitmproxy addon is also runnable standalone:

```bash
RECONTOREPORT_DB_URL="sqlite:////abs/path/recontoreport.db" \
RECONTOREPORT_TARGET_ID=1 \
mitmdump -s recontoreport/tools/mitm_addon.py --listen-port 8080
```

TLS interception uses Playwright's `ignore_https_errors`, so no mitmproxy CA
install is required for the automated login flows.

## Adding a phase

1. Create `recontoreport/phases/phaseN_*.py` with a `Phase` subclass
   (`number`, `name`, `active`, and a `run() -> PhaseResult`).
2. Register it in `recontoreport/phases/__init__.py` (`_load_registry`).
3. Normalize tool output into the shared models inside a `session_scope(...)`.
4. Mark `active = True` if it sends traffic to the target (so the auth gate
   applies). Set `active = False` for purely offline steps (e.g. report-only or
   secret scraping over already-captured transactions).

See `phase1_recon.py` for the reference pattern (shell out via
`tools.runner.run`, parse JSON, de-dupe assets, raise findings).

## Testing

```bash
pytest -q
```
