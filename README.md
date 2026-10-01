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
- ✅ **Phase 1 reference implementation**: `subfinder` + `ffuf`
  (subdomain discovery + content bruteforce with sensitive-file flagging)
- ✅ Jinja2 HTML report (and XML) grouped by severity
- ⏳ Phases 2–5 and the remaining Phase 1 tools (`amass`, `prance`/OpenAPI,
  `katana`) are stubbed with `TODO` markers and a phase registry ready to
  accept them.

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

# Authorized run of Phase 1
r2r run --config config.yaml --phases 1 --i-have-authorization

# Render a report from the existing store without scanning
r2r report --config config.yaml
```

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
