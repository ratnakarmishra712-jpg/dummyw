"""Phase modules. Each phase normalizes external tool output into the shared store."""

from __future__ import annotations

from .base import Phase, PhaseContext, PhaseResult

__all__ = ["Phase", "PhaseContext", "PhaseResult", "get_phase", "ALL_PHASES"]


def _load_registry() -> dict[int, type[Phase]]:
    # Imported lazily so that importing the package doesn't require every phase's
    # heavy optional dependencies (mitmproxy, playwright, ...).
    from .phase1_recon import ReconPhase

    registry: dict[int, type[Phase]] = {
        1: ReconPhase,
    }
    # Phases 2-5 are registered here as their modules land.
    return registry


ALL_PHASES = _load_registry()


def get_phase(number: int) -> type[Phase]:
    registry = _load_registry()
    if number not in registry:
        raise KeyError(
            f"Phase {number} is not implemented yet. "
            f"Available: {sorted(registry)}"
        )
    return registry[number]
