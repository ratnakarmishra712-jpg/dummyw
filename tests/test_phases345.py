"""Tests for Phases 3-5 pure logic and the dependency resolver."""

from __future__ import annotations

import base64
import json

from recontoreport.orchestrator import parse_phase_arg
from recontoreport.phases import resolve_phases
from recontoreport.tools.jwt_analysis import analyze_jwt, decode_jwt, find_jwts
from recontoreport.tools.secrets import luhn_check, scan_text


# -- dependency resolution ---------------------------------------------------
def test_resolve_pulls_dependencies():
    # Phase 4 depends on 3, which depends on 1 -> running 4 runs [1,3,4].
    ordered, auto = resolve_phases([4])
    assert ordered == [1, 3, 4]
    assert auto == [1, 3]


def test_resolve_no_deps():
    ordered, auto = resolve_phases([1, 2])
    assert ordered == [1, 2]
    assert auto == []


def test_resolve_all_ordered():
    ordered, auto = resolve_phases([5, 3, 1])
    assert ordered == [1, 3, 5]      # sorted
    assert auto == []                # all were requested


def test_parse_phase_arg_variants():
    assert parse_phase_arg("all", [1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]
    assert parse_phase_arg("1 2 3", [9]) == [1, 2, 3]   # space-separated
    assert parse_phase_arg("3", [9]) == [3]


# -- secret scraping ---------------------------------------------------------
def test_luhn_check():
    assert luhn_check("4111111111111111")      # valid test Visa
    assert not luhn_check("4111111111111112")
    assert not luhn_check("1234")


def test_scan_text_finds_secrets_and_filters_cards():
    text = (
        "contact me at alice@example.com key AKIAABCDEFGHIJKLMNOP "
        "card 4111 1111 1111 1111 but not 1234 5678 9012 3456"
    )
    hits = {h.kind: h.value for h in scan_text(text)}
    assert hits["email"] == "alice@example.com"
    assert hits["aws_access_key"] == "AKIAABCDEFGHIJKLMNOP"
    assert hits["credit_card"].replace(" ", "") == "4111111111111111"
    # The non-Luhn card must not appear.
    cards = [h.value for h in scan_text(text) if h.kind == "credit_card"]
    assert all("3456" not in c for c in cards)


def test_scan_text_empty():
    assert scan_text("") == []
    assert scan_text(None) == []


# -- JWT analysis ------------------------------------------------------------
def _make_jwt(header: dict, payload: dict, sig: str = "sig") -> str:
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg(header)}.{seg(payload)}.{sig}"


def test_find_and_decode_jwt():
    tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
    found = find_jwts(f"Authorization: Bearer {tok}")
    assert tok in found
    header, payload = decode_jwt(tok)
    assert header["alg"] == "HS256"
    assert payload["sub"] == "1"


def test_analyze_jwt_alg_none_and_missing_exp():
    tok = _make_jwt({"alg": "none"}, {"sub": "1"}, sig="")
    issues = {i.title for i in analyze_jwt(tok)}
    assert any("alg: none" in t for t in issues)
    assert any("no expiry" in t for t in issues)


def test_analyze_jwt_clean_token_with_exp():
    tok = _make_jwt({"alg": "RS256"}, {"sub": "1", "exp": 9999999999})
    issues = analyze_jwt(tok)
    # RS256 with exp and no weak-secret path -> no issues flagged.
    assert issues == []
