"""Tests for the security grade + attacker-story crowd-facing features."""

from recontoreport.attack import attacker_story
from recontoreport.scoring import grade


def test_grade_clean_is_a():
    g = grade({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    assert g["grade"] == "A" and g["score"] == 100 and g["color"] == "green"


def test_grade_critical_tanks_to_f():
    g = grade({"critical": 2, "high": 1})
    assert g["grade"] == "F" and g["color"] == "red" and g["score"] < 55


def test_grade_monotonic():
    assert grade({"low": 3})["score"] > grade({"high": 3})["score"]


def test_story_empty():
    s = attacker_story([])
    assert "couldn't find a way in" in s


def test_story_mentions_chained_techniques():
    s = attacker_story([
        {"cwe_id": "CWE-89", "tool_source": "sqli-error"},
        {"cwe_id": "CWE-285", "tool_source": "privesc-diff"},
    ])
    assert "database" in s and "access control" in s and "break-in" in s
