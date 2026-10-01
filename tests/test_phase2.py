"""Tests for Phase 2 plumbing that doesn't require mitmproxy/playwright."""

from __future__ import annotations

from pathlib import Path

from recontoreport.config import Config
from recontoreport.db import create_all, make_engine, make_session_factory
from recontoreport.models import Target
from recontoreport.tools.capture import (
    MAX_BODY_BYTES,
    CapturedTransaction,
    _truncate,
    save_transaction,
)


def _write_config(tmp_path: Path, extra: str = "") -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"""
target:
  url: "https://example.com"
database:
  url: "sqlite:///{tmp_path/'r2r.db'}"
{extra}
"""
    )
    return cfg


def test_config_defaults_for_proxy_and_auth(tmp_path):
    cfg = Config.load(_write_config(tmp_path))
    assert cfg.proxy.listen_host == "127.0.0.1"
    assert cfg.proxy.listen_port == 8080
    assert cfg.proxy.capture_window_seconds == 60
    assert cfg.auth_roles == []


def test_config_parses_auth_roles_with_env(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_PASS", "s3cret")
    extra = """
proxy:
  listen_port: 9090
auth:
  roles:
    - name: "low_priv"
      privilege_level: 2
      login_url: "https://example.com/login"
      username: "alice"
      password: "${APP_PASS}"
      submit_selector: "#go"
"""
    cfg = Config.load(_write_config(tmp_path, extra))
    assert cfg.proxy.listen_port == 9090
    assert len(cfg.auth_roles) == 1
    role = cfg.auth_roles[0]
    assert role.name == "low_priv"
    assert role.privilege_level == 2
    assert role.password == "s3cret"          # env expanded
    assert role.submit_selector == "#go"
    assert role.username_selector == "input[name=username]"  # default kept


def test_save_transaction_roundtrip(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path/'t.db'}")
    create_all(engine)
    factory = make_session_factory(engine)
    with factory() as s:
        t = Target(url="https://example.com")
        s.add(t)
        s.commit()
        target_id = t.id

    tx = CapturedTransaction(
        url="https://example.com/api",
        method="POST",
        status_code=200,
        request_headers={"Content-Type": "application/json"},
        request_body='{"a":1}',
        response_body="ok",
        response_length=2,
    )
    row_id = save_transaction(factory, target_id, tx)
    assert row_id > 0

    from recontoreport.models import HttpTransaction

    with factory() as s:
        row = s.get(HttpTransaction, row_id)
        assert row.method == "POST"
        assert row.status_code == 200
        assert row.request_headers["Content-Type"] == "application/json"
        assert row.tool_source == "mitmproxy"


def test_truncate_caps_body():
    big = "x" * (MAX_BODY_BYTES + 500)
    out = _truncate(big)
    assert out is not None
    assert "truncated" in out
    assert len(out) < len(big) + 100
    assert _truncate(None) is None
    assert _truncate("short") == "short"
