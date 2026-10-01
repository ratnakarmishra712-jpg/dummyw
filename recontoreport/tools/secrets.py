"""Regex-based secret scraping with a Luhn check for card numbers.

Pure-Python and unit-testable. Used by Phase 5 over captured transaction bodies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b"),
    "generic_api_key": re.compile(r"(?i)(?:api[_-]?key|secret|token)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]"),
    # Candidate card numbers (13-16 digits, optional separators); Luhn-filtered below.
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
}


@dataclass
class SecretHit:
    kind: str
    value: str
    context: str


def luhn_check(number: str) -> bool:
    """True if the digit string passes the Luhn checksum (card number heuristic)."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _context(text: str, start: int, end: int, width: int = 30) -> str:
    lo = max(0, start - width)
    hi = min(len(text), end + width)
    return text[lo:hi].replace("\n", " ")


def scan_text(text: str | None) -> list[SecretHit]:
    """Return all secret hits in ``text``. Card numbers are Luhn-filtered."""
    if not text:
        return []
    hits: list[SecretHit] = []
    seen: set[tuple[str, str]] = set()
    for kind, pat in _PATTERNS.items():
        for m in pat.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            if kind == "credit_card" and not luhn_check(value):
                continue
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            hits.append(SecretHit(kind=kind, value=value, context=_context(text, m.start(), m.end())))
    return hits
