#!/usr/bin/env bash
#
# ReconToReport one-shot setup. Run it from the repo root (the folder with
# pyproject.toml), on macOS or Linux:
#
#   bash setup.sh                 # core install
#   bash setup.sh --with-browser  # also install Phase 2 deps (mitmproxy, playwright + chromium)
#
# It creates a .venv tied to THIS folder and installs the package into it, which
# is what prevents the "Phase N not implemented" stale-install problem: the venv
# always matches the code sitting next to it.

set -euo pipefail

# --- locate ourselves: always operate in the script's own directory -----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f pyproject.toml ] || [ ! -d recontoreport ]; then
  echo "ERROR: run this from the ReconToReport repo root (no pyproject.toml / recontoreport/ here)."
  exit 1
fi

WITH_BROWSER=0
for arg in "$@"; do
  case "$arg" in
    --with-browser) WITH_BROWSER=1 ;;
    *) echo "Unknown option: $arg"; exit 2 ;;
  esac
done

# --- pick a python ------------------------------------------------------------
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "ERROR: $PY not found. Install Python 3.10+ (macOS: brew install python)."
  exit 1
fi
echo "==> Using $("$PY" --version) at $(command -v "$PY")"

# --- venv (recreate cleanly so it's always bound to this folder) --------------
echo "==> Creating virtualenv at ./.venv"
rm -rf .venv
"$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -q --upgrade pip

# --- install the package ------------------------------------------------------
if [ "$WITH_BROWSER" -eq 1 ]; then
  echo "==> Installing recontoreport with Phase 2 extras (proxy, browser)"
  pip install -q -e ".[proxy,browser]"
  echo "==> Installing Playwright's Chromium browser"
  python -m playwright install chromium
else
  echo "==> Installing recontoreport (core)"
  pip install -q -e "."
fi

# --- config -------------------------------------------------------------------
if [ ! -f config.yaml ]; then
  cp config.example.yaml config.yaml
  echo "==> Created config.yaml from the example — edit target.url, scope, wordlists."
else
  echo "==> config.yaml already exists (left as-is)."
fi

# --- database -----------------------------------------------------------------
echo "==> Initializing the database"
r2r initdb --config config.yaml

# --- verify -------------------------------------------------------------------
echo "==> Verifying installed code"
python - <<'PY'
import recontoreport.phases as p
print("    package loaded from:", p.__file__)
print("    phases available   :", sorted(p._load_registry()))
PY

cat <<'MSG'

================================================================================
Setup complete.

Activate the venv in each new terminal before running:
    source .venv/bin/activate

Run a phase (dry = safe, no scanning):
    r2r run --config config.yaml --phases 1
    r2r run --config config.yaml --phases 1 --i-have-authorization   # authorized
    r2r run --config config.yaml --phases 2 --i-have-authorization   # needs --with-browser setup

Report / query:
    r2r report --config config.yaml
    open reports/report-*.html
    python scripts/query.py --config config.yaml "SELECT title, severity FROM findings"
================================================================================
MSG
