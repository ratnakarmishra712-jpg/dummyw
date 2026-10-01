<#
  ReconToReport one-shot setup for Windows (PowerShell).
  Run from the repo root (the folder with pyproject.toml):

      powershell -ExecutionPolicy Bypass -File setup.ps1
      powershell -ExecutionPolicy Bypass -File setup.ps1 -WithBrowser

  -WithBrowser also installs Phase 2 deps (mitmproxy, playwright + chromium).

  It creates a .venv bound to THIS folder and installs the package into it, so the
  venv always matches the code beside it (prevents the "Phase N not implemented"
  stale-install problem).
#>

param(
    [switch]$WithBrowser
)

$ErrorActionPreference = "Stop"

# --- operate in the script's own directory -----------------------------------
Set-Location -Path $PSScriptRoot

if (-not (Test-Path "pyproject.toml") -or -not (Test-Path "recontoreport")) {
    Write-Error "Run this from the ReconToReport repo root (no pyproject.toml / recontoreport\ here)."
    exit 1
}

# --- pick a python ------------------------------------------------------------
function Get-Python {
    if (Get-Command py -ErrorAction SilentlyContinue)     { return @("py", "-3") }
    if (Get-Command python -ErrorAction SilentlyContinue) { return @("python") }
    Write-Error "Python not found. Install Python 3.10+ from https://www.python.org/downloads/ (check 'Add to PATH')."
    exit 1
}
$pyCmd = Get-Python
Write-Host "==> Using Python: $($pyCmd -join ' ')"
& $pyCmd[0] $pyCmd[1..($pyCmd.Count-1)] --version

# --- venv (recreate cleanly so it's bound to this folder) --------------------
Write-Host "==> Creating virtualenv at .\.venv"
if (Test-Path ".venv") { Remove-Item -Recurse -Force ".venv" }
& $pyCmd[0] $pyCmd[1..($pyCmd.Count-1)] -m venv .venv

$venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $venvPy -m pip install -q --upgrade pip

# --- install the package ------------------------------------------------------
if ($WithBrowser) {
    Write-Host "==> Installing recontoreport with Phase 2 extras (proxy, browser)"
    & $venvPy -m pip install -q -e ".[proxy,browser]"
    Write-Host "==> Installing Playwright's Chromium browser"
    & $venvPy -m playwright install chromium
} else {
    Write-Host "==> Installing recontoreport (core)"
    & $venvPy -m pip install -q -e "."
}

# --- config -------------------------------------------------------------------
if (-not (Test-Path "config.yaml")) {
    Copy-Item "config.example.yaml" "config.yaml"
    Write-Host "==> Created config.yaml from the example - edit target.url, scope, wordlists."
} else {
    Write-Host "==> config.yaml already exists (left as-is)."
}

# --- database -----------------------------------------------------------------
Write-Host "==> Initializing the database"
& $venvPy -m recontoreport.cli initdb --config config.yaml

# --- verify -------------------------------------------------------------------
Write-Host "==> Verifying installed code"
& $venvPy -c "import recontoreport.phases as p; print('    package loaded from:', p.__file__); print('    phases available   :', sorted(p._load_registry()))"

Write-Host ""
Write-Host "================================================================================"
Write-Host "Setup complete."
Write-Host ""
Write-Host "Activate the venv in each new terminal before running:"
Write-Host "    .\.venv\Scripts\Activate.ps1      (PowerShell)"
Write-Host "    .\.venv\Scripts\activate.bat      (cmd.exe)"
Write-Host ""
Write-Host "Run a phase:"
Write-Host "    r2r run --config config.yaml --phases 1"
Write-Host "    r2r run --config config.yaml --phases 1 --i-have-authorization"
Write-Host "    r2r run --config config.yaml --phases 2 --i-have-authorization   (needs -WithBrowser)"
Write-Host ""
Write-Host "Report / query:"
Write-Host "    r2r report --config config.yaml"
Write-Host "    start reports\report-*.html"
Write-Host "    python scripts\query.py --config config.yaml ""SELECT title, severity FROM findings"""
Write-Host "================================================================================"
