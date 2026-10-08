"""Tests for the MITRE ATT&CK mapping + attack-path layer (red-team view)."""

from recontoreport.attack import attack_for, build_attack_path, tactic_for, technique_url


def test_attack_for_known_cwes():
    assert attack_for("CWE-89", "sqli-error")[0] == "T1190"
    assert attack_for("CWE-79", "xss-canary")[0] == "T1059.007"
    assert attack_for("CWE-285", "privesc-diff")[2] == "Privilege Escalation"
    assert attack_for("CWE-347", "jwt")[2] == "Credential Access"


def test_names_come_from_stix_data():
    # Authoritative MITRE names loaded from the distilled STIX bundle.
    assert attack_for("CWE-89", "sqli-error")[1] == "Exploit Public-Facing Application"
    assert attack_for("CWE-285", "privesc-diff")[1] == "Abuse Elevation Control Mechanism"
    assert technique_url("T1190") == "https://attack.mitre.org/techniques/T1190"


def test_attack_for_tool_source_fallback():
    assert attack_for(None, "nuclei")[0] == "T1190"
    assert tactic_for(None, "something-else") == "Reconnaissance"


def test_build_attack_path_orders_kill_chain_and_narrates():
    findings = [
        {"cwe_id": "CWE-285", "tool_source": "privesc-diff", "title": "p", "severity": "high"},
        {"cwe_id": "CWE-89", "tool_source": "sqli-error", "title": "s", "severity": "critical"},
    ]
    path = build_attack_path(findings)
    assert path["reached"] == ["Initial Access", "Privilege Escalation"]
    assert "initial foothold" in path["narrative"]
    assert "escalated" in path["narrative"]


def test_build_attack_path_empty():
    path = build_attack_path([])
    assert path["reached"] == []
    assert "No exploitable attack path" in path["narrative"]
