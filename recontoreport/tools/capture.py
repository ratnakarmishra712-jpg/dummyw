"""Shared capture helpers used by the mitmproxy addon and Phase 2.

Deliberately imports no mitmproxy/playwright so it stays unit-testable. The
addon (loaded inside mitmdump) imports these functions and feeds them plain
dicts extracted from mitmproxy flow objects.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from ..db import make_engine, make_session_factory
from ..models import HttpTransaction

# Response/request bodies are truncated to keep the SQLite store manageable.
MAX_BODY_BYTES = 200_000


@dataclass
class CapturedTransaction:
    url: str
    method: str = "GET"
    tool_source: str = "mitmproxy"
    request_headers: dict[str, str] | None = None
    request_body: str | None = None
    status_code: int | None = None
    response_headers: dict[str, str] | None = None
    response_body: str | None = None
    response_length: int | None = None
    auth_context_id: int | None = None
    asset_id: int | None = None
    origin_transaction_id: int | None = None
    meta: dict[str, Any] = field(default_factory=dict)


def _truncate(text: str | None) -> str | None:
    if text is None:
        return None
    if len(text) > MAX_BODY_BYTES:
        return text[:MAX_BODY_BYTES] + f"\n...[truncated {len(text) - MAX_BODY_BYTES} bytes]"
    return text


def save_transaction(
    session_factory: sessionmaker[Session],
    target_id: int,
    tx: CapturedTransaction,
) -> int:
    """Persist one captured transaction. Returns the new row id."""
    session = session_factory()
    try:
        row = HttpTransaction(
            target_id=target_id,
            asset_id=tx.asset_id,
            auth_context_id=tx.auth_context_id,
            origin_transaction_id=tx.origin_transaction_id,
            tool_source=tx.tool_source,
            method=tx.method,
            url=tx.url,
            request_headers=tx.request_headers,
            request_body=_truncate(tx.request_body),
            status_code=tx.status_code,
            response_headers=tx.response_headers,
            response_body=_truncate(tx.response_body),
            response_length=tx.response_length,
        )
        session.add(row)
        session.commit()
        return row.id
    finally:
        session.close()


def session_factory_from_env() -> tuple[sessionmaker[Session], int]:
    """Build a session factory + target_id from environment variables.

    Used by the mitmproxy addon, which runs in a separate ``mitmdump`` process
    and receives its context through the environment:

      RECONTOREPORT_DB_URL     — SQLAlchemy URL (required)
      RECONTOREPORT_TARGET_ID  — target row id (required)
    """
    db_url = os.environ.get("RECONTOREPORT_DB_URL")
    target_id = os.environ.get("RECONTOREPORT_TARGET_ID")
    if not db_url or not target_id:
        raise RuntimeError(
            "mitmproxy addon requires RECONTOREPORT_DB_URL and "
            "RECONTOREPORT_TARGET_ID environment variables."
        )
    engine = make_engine(db_url)
    return make_session_factory(engine), int(target_id)
