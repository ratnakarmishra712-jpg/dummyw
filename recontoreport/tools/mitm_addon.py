"""mitmproxy addon — logs every request/response (and WebSocket message) into
the ReconToReport store.

Run it with mitmdump, passing context via environment variables:

    RECONTOREPORT_DB_URL="sqlite:////abs/path/recontoreport.db" \
    RECONTOREPORT_TARGET_ID=1 \
    mitmdump -s recontoreport/tools/mitm_addon.py --listen-host 127.0.0.1 --listen-port 8080

Phase 2 launches this for you; this module is also runnable standalone for
manual/interactive capture sessions.

Optional environment variable:
    RECONTOREPORT_AUTH_CONTEXT_ID — tag captured transactions with an auth context.
"""

from __future__ import annotations

import logging
import os

# mitmproxy is only available inside the mitmdump process; importing this module
# elsewhere (e.g. unit tests) would fail, which is why the DB logic lives in
# capture.py instead.
from mitmproxy import http  # type: ignore

# mitmproxy loads this file with `mitmdump -s mitm_addon.py` as a standalone
# module (no parent package), so RELATIVE imports would fail. Use the absolute
# package path, which resolves because recontoreport is pip-installed in the
# same venv as this mitmdump.
from recontoreport.tools.capture import (
    CapturedTransaction,
    save_transaction,
    session_factory_from_env,
)

log = logging.getLogger("recontoreport.mitm")


def _headers_to_dict(headers) -> dict[str, str]:
    try:
        return {k: v for k, v in headers.items()}
    except Exception:
        return {}


def _text_or_none(message) -> str | None:
    try:
        return message.get_text(strict=False)
    except Exception:
        return None


class ReconCapture:
    def __init__(self) -> None:
        self.session_factory, self.target_id = session_factory_from_env()
        ac = os.environ.get("RECONTOREPORT_AUTH_CONTEXT_ID")
        self.auth_context_id = int(ac) if ac else None
        self.count = 0
        log.info("ReconCapture addon loaded (target_id=%s)", self.target_id)

    def response(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        resp = flow.response
        tx = CapturedTransaction(
            url=req.pretty_url,
            method=req.method,
            tool_source="mitmproxy",
            request_headers=_headers_to_dict(req.headers),
            request_body=_text_or_none(req),
            status_code=resp.status_code if resp else None,
            response_headers=_headers_to_dict(resp.headers) if resp else None,
            response_body=_text_or_none(resp) if resp else None,
            response_length=len(resp.raw_content) if resp and resp.raw_content else None,
            auth_context_id=self.auth_context_id,
        )
        try:
            save_transaction(self.session_factory, self.target_id, tx)
            self.count += 1
        except Exception:
            log.exception("failed to persist transaction for %s", req.pretty_url)

    def websocket_message(self, flow) -> None:
        """Capture each WebSocket message as a WS 'transaction'."""
        try:
            msg = flow.websocket.messages[-1]
            direction = "outbound" if msg.from_client else "inbound"
            content = msg.text if hasattr(msg, "text") else str(msg.content)
            tx = CapturedTransaction(
                url=flow.request.pretty_url,
                method="WS",
                tool_source="mitmproxy-ws",
                request_body=content if direction == "outbound" else None,
                response_body=content if direction == "inbound" else None,
                auth_context_id=self.auth_context_id,
            )
            save_transaction(self.session_factory, self.target_id, tx)
            self.count += 1
        except Exception:
            log.exception("failed to persist websocket message")

    def done(self) -> None:
        log.info("ReconCapture addon captured %s transactions", self.count)


addons = [ReconCapture()]
