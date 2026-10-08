"""MITRE ATT&CK mapping + attack-path correlation (red-team presentation layer).

Purely additive: it does NOT change how any phase or tool works. It reads the
findings the pipeline already produced and (a) tags each one with an ATT&CK
technique/tactic and (b) strings them into a kill-chain path with a narrative.
This is what reframes the output from a vulnerability list into an adversary story.
"""

from __future__ import annotations

# Tactic order = the kill chain we render left-to-right / top-to-bottom.
TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Credential Access",
    "Privilege Escalation",
    "Impact",
]


def attack_for(cwe_id: str | None, tool_source: str | None) -> tuple[str, str, str]:
    """Return (technique_id, technique_name, tactic) for a finding.

    Classifies by CWE first, then by which tool produced it — both are fields
    every finding already carries, so nothing new has to be collected.
    """
    cwe = (cwe_id or "").upper()
    src = (tool_source or "").lower()

    if cwe == "CWE-89" or "sqli" in src or "sqlmap" in src:
        return ("T1190", "Exploit Public-Facing Application", "Initial Access")
    if cwe == "CWE-79" or "xss" in src:
        return ("T1059.007", "Command & Scripting: JavaScript", "Execution")
    if cwe == "CWE-285" or "privesc" in src:
        return ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation")
    if cwe in ("CWE-347", "CWE-326", "CWE-613") or "jwt" in src:
        return ("T1550.001", "Use Alternate Auth Material: App Tokens", "Credential Access")
    if cwe == "CWE-538" or "secret" in src or "ffuf" in src:
        return ("T1552", "Unsecured Credentials", "Credential Access")
    if "nuclei" in src:
        return ("T1190", "Exploit Public-Facing Application", "Initial Access")
    return ("T1595", "Active Scanning", "Reconnaissance")


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
