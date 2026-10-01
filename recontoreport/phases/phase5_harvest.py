"""Phase 5 — Harvesting & reporting.

* **Secret scraping** — regex pass (with a Luhn check for card numbers) over
  captured ``http_transactions`` bodies/headers, writing hits into
  ``secret_matches`` (kept separate from findings until manually promoted).

This phase is offline: it reads data other phases captured and needs no external
tools or network. It is marked ``active = False`` so it runs without the
authorization flag. Report rendering is handled by the orchestrator/CLI after the
run completes.
"""

from __future__ import annotations

from sqlalchemy import select

from ..db import session_scope
from ..models import HttpTransaction, SecretMatch
from ..tools.secrets import scan_text
from .base import Phase, PhaseResult


class HarvestPhase(Phase):
    number = 5
    name = "harvest"
    active = False          # offline: no traffic to the target
    depends_on = ()         # operates on whatever transactions already exist

    def _existing_keys(self, session) -> set[tuple[str, str]]:
        rows = session.execute(
            select(SecretMatch.kind, SecretMatch.matched_value).where(
                SecretMatch.target_id == self.ctx.target_id
            )
        ).all()
        return {(k, v) for (k, v) in rows}

    def run(self) -> PhaseResult:
        created = 0
        with session_scope(self.ctx.session_factory) as s:
            txs = s.execute(
                select(HttpTransaction).where(
                    HttpTransaction.target_id == self.ctx.target_id
                )
            ).scalars().all()
            existing = self._existing_keys(s)

            for tx in txs:
                blob = "\n".join(
                    str(x) for x in (
                        tx.request_headers, tx.request_body,
                        tx.response_headers, tx.response_body,
                    ) if x
                )
                for hit in scan_text(blob):
                    key = (hit.kind, hit.value)
                    if key in existing:
                        continue
                    existing.add(key)
                    s.add(SecretMatch(
                        target_id=self.ctx.target_id,
                        http_transaction_id=tx.id,
                        kind=hit.kind,
                        matched_value=hit.value,
                        context=hit.context,
                    ))
                    created += 1

        self.log.info("secrets: %s new matches", created)
        # Secret matches are not findings, so findings_created stays 0.
        return self._result(ok=True, assets_created=0, findings_created=0, errors=[])
