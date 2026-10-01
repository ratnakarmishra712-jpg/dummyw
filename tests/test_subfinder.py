"""Tests for subfinder domain derivation and output parsing."""

from __future__ import annotations

import logging

from recontoreport.config import Config
from recontoreport.phases.base import PhaseContext
from recontoreport.phases.phase1_recon import ReconPhase


def _phase(url: str) -> ReconPhase:
    ctx = PhaseContext(
        config=Config.from_url(url),
        target_id=1,
        session_factory=None,  # not used by the helpers under test
        log=logging.getLogger("test"),
    )
    return ReconPhase(ctx)


def test_registrable_domain_strips_www():
    assert _phase("http://www.itsecgames.com/")._registrable_domain() == "itsecgames.com"
    assert _phase("https://itsecgames.com")._registrable_domain() == "itsecgames.com"
    assert _phase("https://api.example.com")._registrable_domain() == "api.example.com"


def test_registrable_domain_leaves_ip():
    assert _phase("http://10.0.0.5/")._registrable_domain() == "10.0.0.5"


def test_parse_subfinder_line_json_and_plain():
    p = _phase("http://x.com")
    assert p._parse_subfinder_line('{"host":"a.x.com","source":"crtsh"}') == ("a.x.com", "crtsh")
    assert p._parse_subfinder_line("B.X.com") == ("b.x.com", None)
    assert p._parse_subfinder_line("   ") == ("", None)
    assert p._parse_subfinder_line('{"bad json') == ("", None)
