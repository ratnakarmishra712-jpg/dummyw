#!/usr/bin/env python3
"""Refresh the bundled ATT&CK technique data from MITRE's live STIX bundle.

Downloads MITRE ATT&CK Enterprise (STIX 2.1) and distils it down to the fields
ReconToReport needs — technique id -> {name, tactics, url} — writing
``recontoreport/data/attack_techniques.json``.

The full bundle is ~50 MB; the distilled file is ~95 KB and is what the tool
loads at runtime, so scans stay offline and fast. Re-run this whenever you want
to pull a newer ATT&CK release.

    python scripts/fetch_attack.py
    python scripts/fetch_attack.py --url <alternate STIX bundle url>
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path

DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
OUT = Path(__file__).resolve().parent.parent / "recontoreport" / "data" / "attack_techniques.json"


def distil(bundle: dict) -> dict:
    out: dict[str, dict] = {}
    for o in bundle.get("objects", []):
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = url = None
        for r in o.get("external_references", []):
            if r.get("source_name") == "mitre-attack":
                tid, url = r.get("external_id"), r.get("url")
        if not tid:
            continue
        tactics = [
            p["phase_name"]
            for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        out[tid] = {"name": o.get("name"), "tactics": tactics, "url": url}
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default=DEFAULT_URL, help="STIX bundle URL")
    args = ap.parse_args()

    print(f"Downloading STIX bundle: {args.url}")
    with urllib.request.urlopen(args.url, timeout=120) as resp:  # noqa: S310
        bundle = json.loads(resp.read())

    techniques = distil(bundle)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "_source": "MITRE ATT&CK Enterprise STIX bundle (mitre-attack/attack-stix-data)",
        "_spec_version": bundle.get("spec_version", ""),
        "techniques": techniques,
    }
    OUT.write_text(json.dumps(doc, indent=0, sort_keys=True))
    print(f"Wrote {len(techniques)} techniques -> {OUT}")


if __name__ == "__main__":
    main()
