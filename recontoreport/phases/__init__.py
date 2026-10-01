"""Phase modules. Each phase normalizes external tool output into the shared store."""

from __future__ import annotations

from .base import Phase, PhaseContext, PhaseResult

__all__ = [
    "Phase", "PhaseContext", "PhaseResult",
    "get_phase", "ALL_PHASES", "resolve_phases",
]


def _load_registry() -> dict[int, type[Phase]]:
    # Imported lazily so that importing the package doesn't require every phase's
    # heavy optional dependencies (mitmproxy, playwright, ...).
    from .phase1_recon import ReconPhase
    from .phase2_traffic import TrafficPhase
    from .phase3_scan import ScanPhase
    from .phase4_exploit import ExploitPhase
    from .phase5_harvest import HarvestPhase

    registry: dict[int, type[Phase]] = {
        1: ReconPhase,
        2: TrafficPhase,
        3: ScanPhase,
        4: ExploitPhase,
        5: HarvestPhase,
    }
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


def resolve_phases(requested: list[int]) -> tuple[list[int], list[int]]:
    """Expand ``requested`` to include transitive dependencies.

    Returns (ordered_phases, auto_added) where ordered_phases is the full set to
    run in ascending order, and auto_added lists the dependency phases that were
    pulled in but not explicitly requested.
    """
    registry = _load_registry()
    requested_set = set(requested)
    resolved: set[int] = set()

    def visit(n: int) -> None:
        if n in resolved or n not in registry:
            return
        resolved.add(n)
        for dep in registry[n].depends_on:
            visit(dep)

    for n in requested:
        visit(n)

    ordered = sorted(resolved)
    auto_added = sorted(resolved - requested_set)
    return ordered, auto_added
