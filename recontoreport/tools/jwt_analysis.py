"""JWT discovery and weakness analysis (pure-Python, unit-testable).

Decoding uses only base64/json so it works without PyJWT. Weak-secret cracking
uses PyJWT when available (optional ``scan`` extra); without it that check is
skipped.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass

# A JWT: three base64url segments separated by dots; payload starts with eyJ.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")

# Small built-in list of commonly-used weak HMAC secrets.
DEFAULT_WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "jwt", "admin",
    "key", "test", "secretkey", "your-256-bit-secret", "s3cr3t",
]


@dataclass
class JwtIssue:
    severity: str          # matches schema.Severity values
    title: str
    detail: str
    cwe_id: str


def find_jwts(text: str | None) -> list[str]:
    if not text:
        return []
    return list(dict.fromkeys(_JWT_RE.findall(text)))  # de-duped, order-preserving


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt(token: str) -> tuple[dict, dict]:
    """Return (header, payload) dicts. Raises ValueError on malformed tokens."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a 3-part JWT")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"cannot decode JWT segments: {exc}") from exc
    return header, payload


def _try_crack_hs256(token: str, secrets: list[str]) -> str | None:
    try:
        import jwt as pyjwt  # type: ignore
    except Exception:
        return None
    for secret in secrets:
        try:
            pyjwt.decode(token, secret, algorithms=["HS256"], options={"verify_exp": False})
            return secret
        except Exception:
            continue
    return None


def analyze_jwt(token: str, weak_secrets: list[str] | None = None) -> list[JwtIssue]:
    """Return a list of issues for a single JWT."""
    issues: list[JwtIssue] = []
    try:
        header, payload = decode_jwt(token)
    except ValueError:
        return issues

    alg = str(header.get("alg", "")).lower()

    if alg == "none":
        issues.append(JwtIssue(
            severity="critical",
            title="JWT accepts 'alg: none' (unsigned)",
            detail="The token header declares alg=none, meaning it carries no signature.",
            cwe_id="CWE-347",
        ))

    if alg.startswith("hs"):
        cracked = _try_crack_hs256(token, weak_secrets or DEFAULT_WEAK_SECRETS)
        if cracked is not None:
            issues.append(JwtIssue(
                severity="high",
                title="JWT signed with a weak/guessable HMAC secret",
                detail=f"The HS* signature verified against the weak secret '{cracked}'.",
                cwe_id="CWE-326",
            ))

    if "exp" not in payload:
        issues.append(JwtIssue(
            severity="low",
            title="JWT has no expiry (exp) claim",
            detail="Tokens without an exp claim remain valid indefinitely if leaked.",
            cwe_id="CWE-613",
        ))

    return issues
