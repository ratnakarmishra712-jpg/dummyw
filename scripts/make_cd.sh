#!/usr/bin/env bash
# Build a self-contained, OFFLINE CD/USB bundle of ReconToReport.
#
# Run this ONCE on a machine WITH internet. It gathers the source, builds the
# project wheel, and downloads every Python dependency as a wheel for the common
# OS/Python combinations (plus source fallbacks). The resulting folder installs
# and runs with NO internet on the target machine — just Python 3.10+.
#
#   bash scripts/make_cd.sh
#   -> dist/ReconToReport-CD/   (burn this whole folder to the CD/USB)
#
# What's bundled: the full ReconToReport core + web UI + JWT support, all offline.
# What's NOT bundled (document to users): the optional external CLIs
# (subfinder/ffuf/nuclei/sqlmap) and the Playwright browser + mitmproxy — those
# are large, platform-specific binaries. The tool runs its full built-in check
# suite (crawler, error-based SQLi, privilege-escalation diff, header/CORS audit,
# open-redirect, path-traversal, secret harvesting, report, grade, ATT&CK) with
# none of them installed.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/ReconToReport-CD"
WHEELS="$OUT/wheels"

# Dependencies to bundle (core + ui + scan extras). proxy/browser are omitted on
# purpose — see note above.
PKGS=(
  "SQLAlchemy>=2.0,<3.0" "alembic>=1.13" "Jinja2>=3.1" "PyYAML>=6.0"
  "click>=8.1" "rich>=13.0" "prance>=23.6" "openapi-spec-validator>=0.7"
  "Flask>=3.0" "PyJWT>=2.8"
)
PYVERS=("310" "311" "312" "313")
PLATS=(
  "manylinux2014_x86_64" "manylinux2014_aarch64"
  "win_amd64"
  "macosx_11_0_x86_64" "macosx_11_0_arm64"
)

echo "==> clean $OUT"
rm -rf "$OUT"; mkdir -p "$WHEELS"

echo "==> copy source"
# Everything needed to run, minus local junk.
mkdir -p "$OUT/source"
( cd "$ROOT" && git archive --format=tar HEAD 2>/dev/null || tar cf - \
    --exclude='.git' --exclude='.venv' --exclude='dist' --exclude='__pycache__' \
    --exclude='*.pyc' --exclude='r2r_ui_data' --exclude='*.db' . ) | tar xf - -C "$OUT/source"

echo "==> build the ReconToReport wheel (pure-python, universal)"
python3 -m pip wheel "$ROOT" --no-deps -w "$WHEELS" >/dev/null

echo "==> download dependency wheels for all common platforms/python versions"
for py in "${PYVERS[@]}"; do
  for plat in "${PLATS[@]}"; do
    python3 -m pip download "${PKGS[@]}" \
      --only-binary=:all: --python-version "$py" --platform "$plat" \
      -d "$WHEELS" >/dev/null 2>&1 || true
  done
done

echo "==> download source fallbacks (for any platform a wheel was missing)"
python3 -m pip download "${PKGS[@]}" --no-binary=:all: -d "$WHEELS" >/dev/null 2>&1 || true

echo "==> write installers + README"
cat > "$OUT/install.sh" <<'SH'
#!/usr/bin/env bash
# Offline installer (macOS / Linux). Needs only Python 3.10+.
set -euo pipefail
cd "$(dirname "$0")"
PY="$(command -v python3 || command -v python)"
[ -z "$PY" ] && { echo "Python 3.10+ not found. Install it and re-run."; exit 1; }
echo "Creating virtual environment (.venv)…"
"$PY" -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip --no-index --find-links wheels >/dev/null 2>&1 || true
echo "Installing ReconToReport from the bundled wheels (offline)…"
pip install --no-index --find-links wheels "recontoreport[ui,scan]"
echo
echo "Done.  Activate it with:   source .venv/bin/activate"
echo "Then run the UI:           r2r ui"
echo "Or a CLI scan:             r2r scan --url http://TARGET --i-have-authorization"
SH
chmod +x "$OUT/install.sh"

cat > "$OUT/install.ps1" <<'PS'
# Offline installer (Windows PowerShell). Needs only Python 3.10+.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { Write-Error "Python 3.10+ not found. Install it and re-run."; exit 1 }
Write-Host "Creating virtual environment (.venv)…"
& $py -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip --no-index --find-links wheels 2>$null
Write-Host "Installing ReconToReport from the bundled wheels (offline)…"
& .\.venv\Scripts\pip.exe install --no-index --find-links wheels "recontoreport[ui,scan]"
Write-Host ""
Write-Host "Done.  Activate it with:   .\.venv\Scripts\Activate.ps1"
Write-Host "Then run the UI:           r2r ui"
PS

cat > "$OUT/README.txt" <<'TXT'
ReconToReport — offline bundle
==============================
Authorized security testing only.

REQUIREMENT: Python 3.10 or newer already installed. Nothing else; no internet.

INSTALL
  macOS / Linux:   bash install.sh
  Windows:         powershell -ExecutionPolicy Bypass -File install.ps1

RUN  (after install)
  macOS / Linux:   source .venv/bin/activate   then   r2r ui
  Windows:         .\.venv\Scripts\Activate.ps1  then   r2r ui
  The UI opens in your browser. Click "Start demo target" to try it safely.

  CLI instead of UI:
    r2r initdb --config config.yaml
    r2r scan --url http://YOUR-AUTHORIZED-TARGET --i-have-authorization

WHAT'S INCLUDED
  The full ReconToReport core + web UI, all Python libraries, fully offline.
  Built-in checks need no extra tools: crawler, error-based SQL injection,
  privilege-escalation diff, security-header/CORS audit, open-redirect,
  path-traversal, secret harvesting, the report, the A–F grade, and the
  MITRE ATT&CK mapping.

NOT INCLUDED (optional, large, platform-specific — the tool runs fine without them)
  External CLIs: subfinder, ffuf, nuclei, sqlmap  (install separately to enable
  those phases). The Playwright browser (for the live-browser XSS/login checks)
  and mitmproxy (passive capture). Everything else works without these.

NOTE: wheels are bundled for Linux/Windows/macOS on Python 3.10–3.13. If your
exact Python/OS combo isn't covered, install.sh/ps1 falls back to building from
the bundled source (may need a C compiler for a couple of packages).
TXT

echo
echo "==> built: $OUT"
du -sh "$OUT" 2>/dev/null || true
echo "Burn that whole folder to the CD/USB."
