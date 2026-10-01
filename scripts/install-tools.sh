#!/usr/bin/env bash
# Install the external CLI tools ReconToReport orchestrates.
# These are NOT Python packages — most are Go binaries from ProjectDiscovery.
#
# Usage:  bash scripts/install-tools.sh
#
# Review before running. This installs software on your machine. Nothing here
# scans anything — it only fetches tools. You still need explicit authorization
# before pointing ReconToReport at any target.

set -euo pipefail

have() { command -v "$1" >/dev/null 2>&1; }

echo "== ReconToReport external tool installer =="

# --- Go (required for subfinder/ffuf/katana/nuclei) --------------------------
if ! have go; then
  cat <<'MSG'
Go is not installed. The ProjectDiscovery tools need it.
  - macOS:        brew install go
  - Debian/Ubuntu: sudo apt-get install -y golang-go
  - or:           https://go.dev/dl/
Re-run this script once Go is on PATH (and $(go env GOPATH)/bin is on PATH).
MSG
  exit 1
fi

export PATH="$PATH:$(go env GOPATH)/bin"

install_go() { # name  module
  if have "$1"; then
    echo "  ✓ $1 already installed ($(command -v "$1"))"
  else
    echo "  → installing $1 ..."
    go install "$2"@latest
  fi
}

install_go subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder
install_go ffuf      github.com/ffuf/ffuf/v2
install_go katana    github.com/projectdiscovery/katana/cmd/katana
install_go nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei

# --- Tools better installed via package manager ------------------------------
echo
echo "The following are not installed by this script — use your package manager:"
echo "  amass      : https://github.com/owasp-amass/amass        (snap/brew/go)"
echo "  mitmproxy  : pip install mitmproxy   (or: make dev)"
echo "  sqlmap     : https://github.com/sqlmapproject/sqlmap     (apt/brew/git)"
echo "  hydra      : apt-get install hydra   /  brew install hydra"
echo
echo "Wordlists (SecLists), needed for the ffuf step:"
echo "  git clone https://github.com/danielmiessler/SecLists.git"
echo "  then set wordlists.content_discovery in config.yaml"
echo
echo "Done. Verify with:  make check-tools"
