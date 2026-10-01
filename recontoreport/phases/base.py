"""Base class and shared context for phase modules."""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field

from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session

from ..config import Config


@dataclass
class PhaseContext:
    """Everything a phase needs to run, handed in by the orchestrator."""

    config: Config
    target_id: int
    session_factory: sessionmaker[Session]
    log: logging.Logger


@dataclass
class PhaseResult:
    number: int
    name: str
    ok: bool
    assets_created: int = 0
    findings_created: int = 0
    errors: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str | None = None

    def summary(self) -> str:
        if self.skipped:
            return f"Phase {self.number} ({self.name}): SKIPPED — {self.skip_reason}"
        state = "OK" if self.ok else "FAILED"
        return (
            f"Phase {self.number} ({self.name}): {state} — "
            f"{self.assets_created} assets, {self.findings_created} findings"
            + (f", {len(self.errors)} errors" if self.errors else "")
        )


class Phase(abc.ABC):
    """A pipeline phase. Subclasses implement :meth:`run`.

    ``active`` marks phases that send traffic to / probe the target. The
    orchestrator refuses to run active phases without the authorization flag.
    """

    number: int
    name: str
    active: bool = True

    def __init__(self, ctx: PhaseContext) -> None:
        self.ctx = ctx
        self.config = ctx.config
        self.log = ctx.log

    @abc.abstractmethod
    def run(self) -> PhaseResult:  # pragma: no cover - interface
        ...

    def _result(self, **kwargs) -> PhaseResult:
        return PhaseResult(number=self.number, name=self.name, **kwargs)
