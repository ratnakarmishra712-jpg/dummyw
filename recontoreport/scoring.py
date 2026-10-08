"""Security grade (A–F) — a layperson-facing roll-up of the findings.

Turns the severity counts into a single letter grade + 0–100 score + a one-line
verdict. Deliberately simple and deterministic so it's explainable on a stall:
each severity subtracts weighted points from 100.
"""

from __future__ import annotations

_WEIGHTS = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}

_BANDS = [
    (90, "A", "Strong — no serious issues surfaced."),
    (80, "B", "Good — minor issues worth cleaning up."),
    (70, "C", "Fair — real weaknesses an attacker could use."),
    (55, "D", "Weak — serious, exploitable problems present."),
    (0,  "F", "Critical — an attacker can break in with ease."),
]


def grade(counts: dict) -> dict:
    """counts: {'critical':n,'high':n,...} -> {grade, score, label, color}."""
    penalty = sum(_WEIGHTS.get(sev, 0) * int(n or 0) for sev, n in (counts or {}).items())
    score = max(0, 100 - penalty)
    for threshold, letter, label in _BANDS:
        if score >= threshold:
            color = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}[letter]
            return {"grade": letter, "score": score, "label": label, "color": color}
    return {"grade": "F", "score": 0, "label": _BANDS[-1][2], "color": "red"}
