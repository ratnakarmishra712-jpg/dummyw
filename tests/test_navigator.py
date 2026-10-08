"""Tests for ATT&CK coverage, next-move prediction, and Navigator layer export."""

from recontoreport.navigator import coverage, navigator_layer, next_moves

_F = [
    {"cwe_id": "CWE-89", "tool_source": "sqli-error", "title": "s", "severity": "critical"},
    {"cwe_id": "CWE-285", "tool_source": "privesc-diff", "title": "p", "severity": "high"},
]


def test_coverage_groups_by_kill_chain():
    cov = {c["tactic"]: c["techniques"] for c in coverage(_F)}
    assert any(t["id"] == "T1190" for t in cov["Initial Access"])
    assert any(t["id"] == "T1548" for t in cov["Privilege Escalation"])
    assert cov["Execution"] == []  # not reached


def test_next_moves_predicts_forward():
    moves = next_moves(_F)
    ids = {m["id"] for m in moves}
    # Having reached Privilege Escalation, exfiltration/impact are suggested next.
    assert "T1041" in ids
    assert all("why" in m and "name" in m and m["name"] != m["id"] for m in moves)


def test_navigator_layer_shape():
    layer = navigator_layer(_F, "http://x")
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    tids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1190", "T1548"} <= tids
    assert all(t["enabled"] and t["score"] == 100 for t in layer["techniques"])


def test_empty():
    assert next_moves([]) == []
    assert navigator_layer([], "")["techniques"] == []
