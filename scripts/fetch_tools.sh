#!/usr/bin/env bash
# Download the optional external CLIs into the offline CD bundle, for every
# OS/arch, so the target machine needs no internet to get them either.
#
#   bash scripts/fetch_tools.sh            # into dist/ReconToReport-CD/tools
#   bash scripts/fetch_tools.sh <dir>      # into a custom bundle dir
#
# Layout produced:
#   tools/<os>-<arch>/{subfinder,ffuf,nuclei}[.exe]   (Go binaries, per platform)
#   tools/sqlmap/                                     (pure-Python, any OS)
#
# The installer picks the folder matching the host and wires the binaries onto
# PATH. sqlmap runs via the system Python.
#
# Pinned versions (bump here to refresh):
FFUF=2.1.0
SUBFINDER=2.6.6
NUCLEI=3.3.5
SQLMAP=1.8

set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist/ReconToReport-CD}"
T="$OUT/tools"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$T"

# platform key -> (projectdiscovery os, pd arch, ffuf os, ffuf arch, ffuf ext)
# PD assets: <tool>_<ver>_<os>_<arch>.zip  (os: linux|windows|macOS, arch: amd64|arm64)
# ffuf:      ffuf_<ver>_<os>_<arch>.(tar.gz|zip)  (os: linux|windows|macOS)
PLATFORMS="linux-amd64 linux-arm64 windows-amd64 macos-amd64 macos-arm64"

pd_os()   { case $1 in linux*) echo linux;; windows*) echo windows;; macos*) echo macOS;; esac; }
arch()    { case $1 in *-amd64) echo amd64;; *-arm64) echo arm64;; esac; }

fetch() { # url dest
  curl -sS -L -o "$2" "$1" && [ -s "$2" ]
}

for p in $PLATFORMS; do
  os=$(pd_os "$p"); ar=$(arch "$p"); dir="$T/$p"; mkdir -p "$dir"
  winext=""; [ "$os" = windows ] && winext=".exe"
  echo "==> $p"

  # subfinder (PD .zip)
  if fetch "https://github.com/projectdiscovery/subfinder/releases/download/v$SUBFINDER/subfinder_${SUBFINDER}_${os}_${ar}.zip" "$TMP/sf.zip"; then
    (cd "$TMP" && unzip -oq sf.zip subfinder$winext 2>/dev/null) && mv "$TMP/subfinder$winext" "$dir/" 2>/dev/null && echo "   subfinder ok"
  fi
  # nuclei (PD .zip)
  if fetch "https://github.com/projectdiscovery/nuclei/releases/download/v$NUCLEI/nuclei_${NUCLEI}_${os}_${ar}.zip" "$TMP/nu.zip"; then
    (cd "$TMP" && unzip -oq nu.zip nuclei$winext 2>/dev/null) && mv "$TMP/nuclei$winext" "$dir/" 2>/dev/null && echo "   nuclei ok"
  fi
  # ffuf (.zip on windows, .tar.gz otherwise)
  if [ "$os" = windows ]; then
    if fetch "https://github.com/ffuf/ffuf/releases/download/v$FFUF/ffuf_${FFUF}_${os}_${ar}.zip" "$TMP/ff.zip"; then
      (cd "$TMP" && unzip -oq ff.zip ffuf.exe 2>/dev/null) && mv "$TMP/ffuf.exe" "$dir/" 2>/dev/null && echo "   ffuf ok"
    fi
  else
    if fetch "https://github.com/ffuf/ffuf/releases/download/v$FFUF/ffuf_${FFUF}_${os}_${ar}.tar.gz" "$TMP/ff.tgz"; then
      (cd "$TMP" && tar xzf ff.tgz ffuf 2>/dev/null) && mv "$TMP/ffuf" "$dir/" 2>/dev/null && echo "   ffuf ok"
    fi
  fi
  chmod +x "$dir"/* 2>/dev/null || true
  rmdir "$dir" 2>/dev/null || true   # drop empty platform dirs
done

echo "==> sqlmap (pure-Python, any OS)"
rm -rf "$T/sqlmap"
if git clone --depth 1 -b "$SQLMAP" https://github.com/sqlmapproject/sqlmap.git "$T/sqlmap" >/dev/null 2>&1; then
  rm -rf "$T/sqlmap/.git"; echo "   sqlmap ok"
else
  echo "   sqlmap FAILED (clone)"
fi

cat > "$T/THIRD_PARTY_TOOLS.txt" <<TXT
Bundled external tools (optional; the core runs without them):
  subfinder  v$SUBFINDER   MIT        github.com/projectdiscovery/subfinder
  nuclei     v$NUCLEI      MIT        github.com/projectdiscovery/nuclei
  ffuf       v$FFUF        Apache-2.0 github.com/ffuf/ffuf
  sqlmap     v$SQLMAP      GPLv2      github.com/sqlmapproject/sqlmap
Each is redistributed under its own license. nuclei ships with no templates
here; run 'nuclei -update-templates' once online, or R2R uses its built-in
fast tag set.
TXT

echo; echo "==> tools in $T:"; du -sh "$T" 2>/dev/null; ls "$T"
