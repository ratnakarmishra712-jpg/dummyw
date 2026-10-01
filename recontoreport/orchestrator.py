"""The orchestrator: runs phases in sequence with per-phase error handling.

Guarantees:
* A failure (or crash) in one phase is caught, logged, and does not kill the run;
  the orchestrator moves on to the next phase. The per-phase result records the
  error.
* Active phases (those that send traffic to the target) refuse to run unless the
  caller passed authorization. This is the scope-confirmation gate.
"""

from __future__ import annotations

import logging
import time

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker, Session

from .config import Config
from .db import create_all, make_engine, make_session_factory, session_scope
from .models import Target
from .phases import get_phase
from .phases.base import PhaseContext, PhaseResult
from .schema import TargetStatus

log = logging.getLogger("recontoreport.orchestrator")


class AuthorizationError(RuntimeError):
    """Raised when an active phase is requested without authorization."""


class Orchestrator:
    def __init__(
        self,
        config: Config,
        *,
        authorized: bool = False,
        init_db: bool = True,
    ) -> None:
        self.config = config
        self.authorized = authorized
        self.engine = make_engine(config.database_url)
        if init_db:
            # Convenience for first runs; Alembic is the real migration path.
            create_all(self.engine)
        self.session_factory: sessionmaker[Session] = make_session_factory(self.engine)

    # -- target bookkeeping --------------------------------------------------
    def _get_or_create_target(self) -> int:
        with session_scope(self.session_factory) as s:
            existing = s.execute(
                select(Target).where(Target.url == self.config.target_url)
            ).scalar_one_or_none()
            if existing is not None:
                return existing.id
            target = Target(
                url=self.config.target_url,
                engagement_ref=self.config.engagement_ref,
                status=TargetStatus.CREATED.value,
            )
            s.add(target)
            s.flush()
            return target.id

    def _set_target_status(self, target_id: int, status: TargetStatus) -> None:
        with session_scope(self.session_factory) as s:
            target = s.get(Target, target_id)
            if target is not None:
                target.status = status.value

    # -- main loop -----------------------------------------------------------
    def run(self, phase_numbers: list[int]) -> list[PhaseResult]:
        target_id = self._get_or_create_target()
        self._set_target_status(target_id, TargetStatus.RUNNING)

        results: list[PhaseResult] = []
        any_failed = False

        for number in phase_numbers:
            try:
                phase_cls = get_phase(number)
            except KeyError as exc:
                log.warning("%s", exc)
                results.append(
                    PhaseResult(
                        number=number, name=f"phase{number}", ok=False,
                        skipped=True, skip_reason=str(exc),
                    )
                )
                continue

            ctx = PhaseContext(
                config=self.config,
                target_id=target_id,
                session_factory=self.session_factory,
                log=logging.getLogger(f"recontoreport.phase{number}"),
            )
            phase = phase_cls(ctx)

            # Authorization gate: refuse active phases without the flag.
            if phase.active and not self.authorized:
                msg = (
                    f"Phase {number} ({phase.name}) performs ACTIVE scanning and "
                    f"requires --i-have-authorization. Skipping."
                )
                log.error(msg)
                results.append(
                    PhaseResult(
                        number=number, name=phase.name, ok=False,
                        skipped=True, skip_reason=msg,
                    )
                )
                any_failed = True
                continue

            result = self._run_phase_with_retries(phase)
            results.append(result)
            log.info("%s", result.summary())
            if not result.ok and not result.skipped:
                any_failed = True

        self._set_target_status(
            target_id,
            TargetStatus.FAILED if any_failed else TargetStatus.COMPLETED,
        )
        return results

    def _run_phase_with_retries(self, phase) -> PhaseResult:
        policy = self.config.phase_policy
        attempts = max(1, policy.retries + 1)
        last_result: PhaseResult | None = None

        for attempt in range(1, attempts + 1):
            try:
                result = phase.run()
            except Exception as exc:  # isolate: one phase crash != whole-run crash
                log.exception("Phase %s raised on attempt %s/%s", phase.number, attempt, attempts)
                result = PhaseResult(
                    number=phase.number, name=phase.name, ok=False,
                    errors=[f"{type(exc).__name__}: {exc}"],
                )

            last_result = result
            if result.ok or result.skipped:
                return result

            if attempt < attempts:
                backoff = policy.retry_backoff_seconds * attempt
                log.warning(
                    "Phase %s failed (attempt %s/%s); retrying in %.1fs",
                    phase.number, attempt, attempts, backoff,
                )
                time.sleep(backoff)

        assert last_result is not None
        return last_result


def parse_phase_arg(value: str | None, default: list[int]) -> list[int]:
    """Parse ``--phases 1,2,3`` (or ``all``) into an ordered, de-duplicated list.

    Accepts commas or spaces as separators, so ``--phases "1 2 3"`` and
    ``--phases 1,2,3`` are equivalent.
    """
    if not value:
        return list(default)
    if value.strip().lower() == "all":
        return list(default)
    out: list[int] = []
    for part in value.replace(",", " ").split():
        part = part.strip()
        if not part:
            continue
        out.append(int(part))
    # preserve order, drop dupes
    seen: set[int] = set()
    ordered = [n for n in out if not (n in seen or seen.add(n))]
    return ordered
