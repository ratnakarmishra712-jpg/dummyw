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

echo "==> fetch external CLIs (subfinder/ffuf/nuclei/sqlmap) unless R2R_SKIP_TOOLS=1"
if [ "${R2R_SKIP_TOOLS:-0}" != "1" ]; then
  bash "$ROOT/scripts/fetch_tools.sh" "$OUT" || echo "   (tools fetch had problems; core still works)"
fi

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

# Wire the bundled external CLIs onto PATH (venv bin), if present for this host.
BIN=".venv/bin"
OS=$(uname -s); ARCH=$(uname -m)
case "$OS" in Linux) o=linux;; Darwin) o=macos;; *) o=;; esac
case "$ARCH" in x86_64|amd64) a=amd64;; arm64|aarch64) a=arm64;; *) a=;; esac
KEY="$o-$a"
if [ -n "$o" ] && [ -d "tools/$KEY" ]; then
  echo "Installing external tools for $KEY…"
  cp tools/$KEY/* "$BIN"/ 2>/dev/null || true
  chmod +x "$BIN"/subfinder "$BIN"/ffuf "$BIN"/nuclei 2>/dev/null || true
fi
if [ -f tools/sqlmap/sqlmap.py ]; then
  # sqlmap is pure-Python; expose a 'sqlmap' command that runs the bundled copy.
  SQLMAP_DIR="$(cd tools/sqlmap && pwd)"
  printf '#!/usr/bin/env bash\nexec "%s" "%s/sqlmap.py" "$@"\n' "$PY" "$SQLMAP_DIR" > "$BIN/sqlmap"
  chmod +x "$BIN/sqlmap"
fi
echo
echo "Done.  Activate it with:   source .venv/bin/activate"
echo "Then run the UI:           r2r ui"
echo "Or a CLI scan:             r2r scan --url http://TARGET --i-have-authorization"
echo "Bundled tools (if shown above) are active while the venv is activated."
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

# Wire the bundled Windows CLIs + a sqlmap shim into the venv Scripts dir.
$bin = ".\.venv\Scripts"
if (Test-Path "tools\windows-amd64") {
  Write-Host "Installing external tools for windows-amd64…"
  Copy-Item "tools\windows-amd64\*" $bin -Force -ErrorAction SilentlyContinue
}
if (Test-Path "tools\sqlmap\sqlmap.py") {
  $sq = (Resolve-Path "tools\sqlmap\sqlmap.py").Path
  "@echo off`r`npython `"$sq`" %*" | Out-File -Encoding ascii "$bin\sqlmap.bat"
}
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
  ALSO the external CLIs — subfinder, ffuf, nuclei (binaries for Linux/Windows/
  macOS, x64 + arm64) and sqlmap (Python). install.sh/ps1 wires the ones matching
  your machine onto PATH automatically. See tools/THIRD_PARTY_TOOLS.txt.

NOT INCLUDED (optional, very large/awkward to bundle)
  The Playwright browser (for the live-browser XSS/login checks) and mitmproxy
  (passive capture). The tool runs fine without these; install them separately to
  enable those two checks. nuclei is bundled WITHOUT its template set — run
  'nuclei -update-templates' once online, or rely on R2R's built-in fast tags.

SIZE NOTE: with the external tools bundled this folder is ~750 MB, which is
LARGER than a 700 MB CD. Use a DVD or a USB stick. To fit a CD, rebuild with
R2R_SKIP_TOOLS=1 (Python-only, ~150 MB) and install the CLIs separately.

NOTE: wheels are bundled for Linux/Windows/macOS on Python 3.10–3.13. If your
exact Python/OS combo isn't covered, install.sh/ps1 falls back to building from
the bundled source (may need a C compiler for a couple of packages).
TXT

echo
echo "==> built: $OUT"
du -sh "$OUT" 2>/dev/null || true
echo "Burn that whole folder to the CD/USB."
