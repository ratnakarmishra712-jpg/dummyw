"""MITRE ATT&CK mapping + attack-path correlation (red-team presentation layer).

Purely additive: it does NOT change how any phase or tool works. It reads the
findings the pipeline already produced and (a) tags each with an ATT&CK
technique/tactic and (b) strings them into a kill-chain path with a narrative.

Where the numbers come from
---------------------------
* The technique **name** and official **URL** for every ID are loaded from
  ``data/attack_techniques.json``, which is distilled directly from MITRE's
  ATT&CK Enterprise STIX bundle (regenerate with ``scripts/fetch_attack.py``).
  So the ATT&CK metadata is authoritative, offline, and version-pinned.
* Which technique **ID** a given vulnerability class maps to is our own curated
  ruleset (:func:`_classify`) — MITRE publishes no canonical CWE→technique map,
  so this mapping is a deliberate, auditable judgment call.
* The six-stage kill chain (:data:`TACTIC_ORDER`) is our simplified narrative
  framing; a technique's full ATT&CK tactics live in the STIX data.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).parent / "data" / "attack_techniques.json"

# Our simplified kill chain, rendered left-to-right / top-to-bottom.
TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Credential Access",
    "Privilege Escalation",
    "Impact",
]


@lru_cache(maxsize=1)
def _stix() -> dict:
    """Load the STIX-distilled technique table (id -> {name, tactics, url})."""
    try:
        return json.loads(_DATA.read_text()).get("techniques", {})
    except (OSError, ValueError):
        return {}


def _classify(cwe: str, src: str) -> tuple[str, str]:
    """Curated rule: (CWE / tool source) -> (technique_id, our kill-chain tactic).

    This is the judgment layer. MITRE has no CWE→technique map, so we own it.
    """
    if cwe == "CWE-89" or "sqli" in src or "sqlmap" in src:
        return "T1190", "Initial Access"
    if cwe == "CWE-79" or "xss" in src:
        return "T1059.007", "Execution"
    if cwe == "CWE-285" or "privesc" in src:
        return "T1548", "Privilege Escalation"
    if cwe in ("CWE-347", "CWE-326", "CWE-613") or "jwt" in src:
        return "T1550.001", "Credential Access"
    if cwe == "CWE-538" or "secret" in src or "ffuf" in src:
        return "T1552", "Credential Access"
    if "nuclei" in src:
        return "T1190", "Initial Access"
    return "T1595", "Reconnaissance"


def attack_for(cwe_id: str | None, tool_source: str | None) -> tuple[str, str, str]:
    """Return (technique_id, technique_name, kill-chain tactic) for a finding.

    The id/tactic come from our curated rule; the name is the authoritative
    MITRE name from the STIX data (falling back to the id if the data is absent).
    """
    tid, tactic = _classify((cwe_id or "").upper(), (tool_source or "").lower())
    name = (_stix().get(tid) or {}).get("name") or tid
    return tid, name, tactic


def technique_url(tid: str) -> str:
    """Official MITRE ATT&CK URL for a technique id (from the STIX data)."""
    return (_stix().get(tid) or {}).get("url") or f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"


def tactic_for(cwe_id: str | None, tool_source: str | None) -> str:
    return attack_for(cwe_id, tool_source)[2]


def build_attack_path(findings) -> dict:
    """Group findings by tactic (kill-chain order) and build a narrative.

    `findings` is any iterable of objects/dicts with .cwe_id/.tool_source/.title
    (works for ORM Finding rows and plain dicts).
    """
    def get(f, k):
        return getattr(f, k, None) if not isinstance(f, dict) else f.get(k)

    by_tactic: dict[str, list] = {t: [] for t in TACTIC_ORDER}
    for f in findings:
        tech_id, tech_name, tactic = attack_for(get(f, "cwe_id"), get(f, "tool_source"))
        by_tactic.setdefault(tactic, []).append({
            "title": get(f, "title"),
            "severity": get(f, "severity"),
            "technique": f"{tech_id} {tech_name}",
        })

    reached = [t for t in TACTIC_ORDER if by_tactic.get(t)]

    parts = []
    if "Initial Access" in reached:
        parts.append("gained an initial foothold on the public-facing app")
    if "Credential Access" in reached:
        parts.append("harvested credentials/tokens exposed by the application")
    if "Privilege Escalation" in reached:
        parts.append("escalated to a higher-privilege role via broken access control")
    if "Execution" in reached:
        parts.append("achieved client-side code execution (XSS)")
    narrative = (
        "Simulated adversary path: " + " → ".join(parts) + "."
        if parts else "No exploitable attack path was established."
    )

    return {"by_tactic": by_tactic, "reached": reached, "narrative": narrative}
