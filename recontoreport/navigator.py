"""ATT&CK coverage, predicted next moves, and Navigator layer export.

Builds on :mod:`recontoreport.attack`. Three red-team views, all from findings
the pipeline already produced plus the MITRE STIX-derived technique data:

* :func:`coverage`   — which techniques, per kill-chain tactic, were achieved.
* :func:`next_moves` — given what was achieved, the techniques an attacker would
  most plausibly try next (the forward-looking "next step in the kill chain").
* :func:`navigator_layer` — an official MITRE ATT&CK Navigator v4.5 layer the
  client can open in the real Navigator (a genuine engagement deliverable).
"""

from __future__ import annotations

from .attack import TACTIC_ORDER, _stix, attack_for, technique_url

# After achieving tactic X, these are the techniques an operator typically
# reaches for next. Curated (MITRE has no "what next" edge); names come from STIX.
_NEXT_MOVES = {
    "Reconnaissance": [("T1190", "Exploit the public-facing app you just mapped")],
    "Initial Access": [
        ("T1059", "Run commands on the host once you have a foothold"),
        ("T1505.003", "Drop a web shell for durable access"),
    ],
    "Execution": [("T1505.003", "Persist via a web shell")],
    "Credential Access": [
        ("T1078", "Reuse the stolen credentials/tokens as valid accounts"),
        ("T1021", "Move laterally into internal services"),
    ],
    "Privilege Escalation": [
        ("T1041", "Exfiltrate data now that you can reach it"),
        ("T1565", "Tamper with application data"),
        ("T1486", "Impact: ransom / destroy data"),
    ],
}


def _tech(tid: str) -> dict:
    return {"id": tid, "name": (_stix().get(tid) or {}).get("name") or tid, "url": technique_url(tid)}


def _get(f, k):
    return getattr(f, k, None) if not isinstance(f, dict) else f.get(k)


def coverage(findings) -> list[dict]:
    """Per kill-chain tactic: the distinct techniques achieved (deduped)."""
    by_tactic: dict[str, dict[str, dict]] = {t: {} for t in TACTIC_ORDER}
    for f in findings:
        tid, name, tactic = attack_for(_get(f, "cwe_id"), _get(f, "tool_source"))
        by_tactic.setdefault(tactic, {})[tid] = {"id": tid, "name": name, "url": technique_url(tid)}
    return [{"tactic": t, "techniques": list(by_tactic[t].values())} for t in TACTIC_ORDER]


def next_moves(findings) -> list[dict]:
    """Techniques the attacker would likely attempt next, given what was reached."""
    reached = {attack_for(_get(f, "cwe_id"), _get(f, "tool_source"))[2] for f in findings}
    seen: set[str] = set()
    out: list[dict] = []
    for tactic in TACTIC_ORDER:
        if tactic not in reached:
            continue
        for tid, why in _NEXT_MOVES.get(tactic, []):
            if tid in seen:
                continue
            seen.add(tid)
            out.append({**_tech(tid), "why": why, "after": tactic})
    return out


def navigator_layer(findings, target_url: str = "") -> dict:
    """An official ATT&CK Navigator (v4.5) layer of the achieved techniques."""
    techniques = []
    seen: set[str] = set()
    for f in findings:
        tid, name, _ = attack_for(_get(f, "cwe_id"), _get(f, "tool_source"))
        if tid in seen:
            continue
        seen.add(tid)
        techniques.append({
            "techniqueID": tid,
            "score": 100,
            "color": "#ff4d4d",
            "comment": name,
            "enabled": True,
        })
    return {
        "name": f"ReconToReport — {target_url}".strip(" —"),
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack",
        "description": "Techniques achieved by ReconToReport against the target.",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#ff4d4d"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "achieved", "color": "#ff4d4d"}],
    }
