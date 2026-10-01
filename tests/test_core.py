"""Unit tests for scope logic, phase-arg parsing, and report rendering.

None of these touch external tools or the network.
"""

from __future__ import annotations

from pathlib import Path

from recontoreport.config import ScopeConfig
from recontoreport.db import (
    create_all,
    make_engine,
    make_session_factory,
    session_scope,
)
from recontoreport.models import Asset, Finding, Target
from recontoreport.orchestrator import parse_phase_arg
from recontoreport.report import generate_reports
from recontoreport.schema import AssetType, Severity


def test_scope_include_exclude_and_wildcards():
    scope = ScopeConfig(
        include=["example.com", "*.example.com"],
        exclude=["secret.example.com"],
    )
    assert scope.in_scope("example.com")
    assert scope.in_scope("api.example.com")
    assert scope.in_scope("a.b.example.com")
    assert not scope.in_scope("secret.example.com")   # excluded
    assert not scope.in_scope("example.org")          # not included
    assert not scope.in_scope("notexample.com")       # suffix must be dotted
    assert not scope.in_scope("")


def test_parse_phase_arg():
    assert parse_phase_arg(None, [1, 2, 3]) == [1, 2, 3]
    assert parse_phase_arg("1,2,3", [9]) == [1, 2, 3]
    assert parse_phase_arg("3,1,3,2,1", [9]) == [3, 1, 2]   # order preserved, deduped
    assert parse_phase_arg(" 2 , 4 ", [9]) == [2, 4]


def test_report_generation(tmp_path: Path):
    engine = make_engine(f"sqlite:///{tmp_path/'t.db'}")
    create_all(engine)
    factory = make_session_factory(engine)

    with session_scope(factory) as s:
        target = Target(url="https://example.com", engagement_ref="TEST")
        s.add(target)
        s.flush()
        asset = Asset(
            target_id=target.id,
            type=AssetType.FILE.value,
            url="https://example.com/.git/config",
            source_tool="ffuf",
            meta={"status_code": 200, "sensitive": True},
        )
        s.add(asset)
        s.flush()
        s.add(
            Finding(
                target_id=target.id,
                asset_id=asset.id,
                title="Exposed .git directory",
                cwe_id="CWE-538",
                severity=Severity.HIGH.value,
                description="Git metadata reachable.",
                poc_steps="GET /.git/config -> 200",
                remediation="Block access to VCS metadata.",
                tool_source="ffuf",
            )
        )
        target_id = target.id

    out = tmp_path / "reports"
    written = generate_reports(factory, target_id, out, ["html", "xml"])
    assert len(written) == 2

    html = next(p for p in written if p.suffix == ".html").read_text()
    assert "Exposed .git directory" in html
    assert "CWE-538" in html
    assert "example.com" in html
    assert "High" in html  # severity grouping header / pill

    xml = next(p for p in written if p.suffix == ".xml").read_text()
    assert "<finding" in xml and "Exposed .git directory" in xml


def test_normalize_url_adds_scheme():
    from recontoreport.config import normalize_url, Config
    assert normalize_url("itsecgames.com") == "http://itsecgames.com"
    assert normalize_url("https://x.com/a") == "https://x.com/a"
    assert normalize_url("  example.com  ") == "http://example.com"
    # scheme-less --url must still yield a usable scope
    cfg = Config.from_url("itsecgames.com")
    assert cfg.scope.in_scope("itsecgames.com")
    assert cfg.scope.in_scope("sub.itsecgames.com")
