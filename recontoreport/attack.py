"""MITRE ATT&CK mapping + attack-path correlation (red-team presentation layer).

Purely additive: it does NOT change how any phase or tool works. It reads the
findings the pipeline already produced and (a) tags each with an ATT&CK
technique/tactic and (b) strings them into a kill-chain path with a narrative.

Where the numbers come from
---------------------------
* The technique **name** and official **URL** for every ID are loaded from
  ``data/attack_techniques.json``, which is distilled directly from MITRE's
  ATT&CK Enterprise STIX bundle (regenerate with ``scripts/fetch_attack.py``).
  So the ATT&CK metadata is authoritative, offline, and version-pinned.
* Which technique **ID** a given vulnerability class maps to is our own curated
  ruleset (:func:`_classify`) — MITRE publishes no canonical CWE→technique map,
  so this mapping is a deliberate, auditable judgment call.
* The six-stage kill chain (:data:`TACTIC_ORDER`) is our simplified narrative
  framing; a technique's full ATT&CK tactics live in the STIX data.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).parent / "data" / "attack_techniques.json"

# Our simplified kill chain, rendered left-to-right / top-to-bottom.
TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Credential Access",
    "Privilege Escalation",
    "Impact",
]


@lru_cache(maxsize=1)
def _stix() -> dict:
    """Load the STIX-distilled technique table (id -> {name, tactics, url})."""
    try:
        return json.loads(_DATA.read_text()).get("techniques", {})
    except (OSError, ValueError):
        return {}


# Curated CWE -> (technique_id, our kill-chain tactic), covering the OWASP Top 10
# / common web weakness families. MITRE publishes no canonical CWE→technique map
# (CAPEC's ATT&CK coverage is sparse and skips the core web CWEs), so this is our
# deliberate, auditable judgment layer. Technique NAMES/URLs still come from STIX.
_CWE_MAP: dict[str, tuple[str, str]] = {
    # --- Injection -> get code/queries running on the app --------------------
    "CWE-89":  ("T1190", "Initial Access"),       # SQL injection
    "CWE-564": ("T1190", "Initial Access"),       # ORM/HQL injection
    "CWE-943": ("T1190", "Initial Access"),       # NoSQL / data-query injection
    "CWE-77":  ("T1059", "Execution"),            # command injection
    "CWE-78":  ("T1059", "Execution"),            # OS command injection
    "CWE-94":  ("T1059", "Execution"),            # code injection
    "CWE-95":  ("T1059", "Execution"),            # eval injection
    "CWE-98":  ("T1505.003", "Execution"),        # PHP file inclusion -> web shell
    "CWE-502": ("T1059", "Execution"),            # insecure deserialization (RCE)
    "CWE-611": ("T1083", "Credential Access"),    # XXE -> file read
    "CWE-1336": ("T1059", "Execution"),           # template injection (SSTI)
    # --- XSS / client-side execution ----------------------------------------
    "CWE-79":  ("T1059.007", "Execution"),        # XSS
    "CWE-80":  ("T1059.007", "Execution"),
    "CWE-83":  ("T1059.007", "Execution"),
    # --- Broken access control / privilege -----------------------------------
    "CWE-285": ("T1548", "Privilege Escalation"), # improper authorization
    "CWE-862": ("T1548", "Privilege Escalation"), # missing authorization
    "CWE-863": ("T1548", "Privilege Escalation"), # incorrect authorization
    "CWE-639": ("T1548", "Privilege Escalation"), # IDOR
    "CWE-266": ("T1548", "Privilege Escalation"), # incorrect privilege assignment
    "CWE-269": ("T1548", "Privilege Escalation"), # improper privilege management
    # --- Authentication -> valid accounts / foothold -------------------------
    "CWE-287": ("T1078", "Initial Access"),       # improper authentication
    "CWE-306": ("T1190", "Initial Access"),       # missing auth for critical function
    "CWE-798": ("T1552", "Credential Access"),    # hardcoded credentials
    "CWE-521": ("T1078", "Initial Access"),       # weak password requirements
    # --- Tokens / session / crypto material ----------------------------------
    "CWE-347": ("T1550.001", "Credential Access"),# improper signature verification (JWT)
    "CWE-345": ("T1550.001", "Credential Access"),
    "CWE-290": ("T1550.001", "Credential Access"),# auth bypass by spoofing
    "CWE-613": ("T1550.001", "Credential Access"),# insufficient session expiry
    "CWE-384": ("T1550", "Credential Access"),    # session fixation
    "CWE-326": ("T1550.001", "Credential Access"),# weak crypto strength
    # --- Exposed data / secrets ---------------------------------------------
    "CWE-538": ("T1552", "Credential Access"),    # file/dir exposure
    "CWE-540": ("T1552", "Credential Access"),    # source code exposure
    "CWE-615": ("T1552", "Credential Access"),    # info in comments
    "CWE-200": ("T1213", "Credential Access"),    # information exposure
    # --- File read / traversal ----------------------------------------------
    "CWE-22":  ("T1083", "Credential Access"),    # path traversal
    "CWE-23":  ("T1083", "Credential Access"),
    "CWE-36":  ("T1083", "Credential Access"),
    # --- Redirect / request forgery -----------------------------------------
    "CWE-601": ("T1566", "Initial Access"),       # open redirect -> phishing
    "CWE-352": ("T1204", "Execution"),            # CSRF -> forced user action
    "CWE-918": ("T1190", "Initial Access"),       # SSRF
}

# tool-source hints (for findings with no / vague CWE).
_SRC_MAP: list[tuple[tuple[str, ...], tuple[str, str]]] = [
    (("sqli", "sqlmap"), ("T1190", "Initial Access")),
    (("xss",), ("T1059.007", "Execution")),
    (("privesc",), ("T1548", "Privilege Escalation")),
    (("jwt",), ("T1550.001", "Credential Access")),
    (("traversal", "lfi"), ("T1083", "Credential Access")),
    (("redirect",), ("T1566", "Initial Access")),
    (("secret", "ffuf"), ("T1552", "Credential Access")),
    (("header", "cors"), ("T1595", "Reconnaissance")),
    (("nuclei",), ("T1190", "Initial Access")),
]


def _classify(cwe: str, src: str) -> tuple[str, str]:
    """(CWE / tool source) -> (technique_id, our kill-chain tactic).

    CWE is authoritative when we recognise it; otherwise fall back to the tool
    that produced the finding; otherwise default to reconnaissance.
    """
    if cwe in _CWE_MAP:
        return _CWE_MAP[cwe]
    for needles, result in _SRC_MAP:
        if any(n in src for n in needles):
            return result
    return "T1595", "Reconnaissance"


def attack_for(cwe_id: str | None, tool_source: str | None) -> tuple[str, str, str]:
    """Return (technique_id, technique_name, kill-chain tactic) for a finding.

    The id/tactic come from our curated rule; the name is the authoritative
    MITRE name from the STIX data (falling back to the id if the data is absent).
    """
    tid, tactic = _classify((cwe_id or "").upper(), (tool_source or "").lower())
    name = (_stix().get(tid) or {}).get("name") or tid
    return tid, name, tactic


def technique_url(tid: str) -> str:
    """Official MITRE ATT&CK URL for a technique id (from the STIX data)."""
    return (_stix().get(tid) or {}).get("url") or f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"


def tactic_for(cwe_id: str | None, tool_source: str | None) -> str:
    return attack_for(cwe_id, tool_source)[2]


def build_attack_path(findings) -> dict:
    """Group findings by tactic (kill-chain order) and build a narrative.

    `findings` is any iterable of objects/dicts with .cwe_id/.tool_source/.title
    (works for ORM Finding rows and plain dicts).
    """
    def get(f, k):
        return getattr(f, k, None) if not isinstance(f, dict) else f.get(k)

    by_tactic: dict[str, list] = {t: [] for t in TACTIC_ORDER}
    for f in findings:
        tech_id, tech_name, tactic = attack_for(get(f, "cwe_id"), get(f, "tool_source"))
        by_tactic.setdefault(tactic, []).append({
            "title": get(f, "title"),
            "severity": get(f, "severity"),
            "technique": f"{tech_id} {tech_name}",
        })

    reached = [t for t in TACTIC_ORDER if by_tactic.get(t)]

    parts = []
    if "Initial Access" in reached:
        parts.append("gained an initial foothold on the public-facing app")
    if "Credential Access" in reached:
        parts.append("harvested credentials/tokens exposed by the application")
    if "Privilege Escalation" in reached:
        parts.append("escalated to a higher-privilege role via broken access control")
    if "Execution" in reached:
        parts.append("achieved client-side code execution (XSS)")
    narrative = (
        "Simulated adversary path: " + " → ".join(parts) + "."
        if parts else "No exploitable attack path was established."
    )

    return {"by_tactic": by_tactic, "reached": reached, "narrative": narrative}


def attacker_story(findings) -> str:
    """A short first-person 'if I were attacking you' narrative from the findings.

    Pure presentation — reads the same findings and writes them as an attacker's
    account, ordered along the kill chain. Great for a stall / executive summary.
    """
    def get(f, k):
        return getattr(f, k, None) if not isinstance(f, dict) else f.get(k)

    kinds = set()
    for f in findings:
        cwe = (get(f, "cwe_id") or "").upper()
        src = (get(f, "tool_source") or "").lower()
        if cwe == "CWE-89" or "sqli" in src or "sqlmap" in src:
            kinds.add("sqli")
        elif cwe == "CWE-79" or "xss" in src:
            kinds.add("xss")
        elif cwe == "CWE-285" or "privesc" in src:
            kinds.add("privesc")
        elif cwe in ("CWE-347", "CWE-326", "CWE-613") or "jwt" in src:
            kinds.add("jwt")
        elif cwe == "CWE-538" or "secret" in src or "ffuf" in src:
            kinds.add("secret")
        else:
            kinds.add("recon")

    if not kinds:
        return ("I ran my playbook against this target and couldn't find a way in — "
                "nothing I tried gave me a foothold. Good sign for the defender.")

    lines = ["Here's how I'd break in:"]
    lines.append("First, I'd map the site and quietly note every page, form and "
                 "parameter — my way around the building.")
    if "sqli" in kinds:
        lines.append("Then I'd hit a vulnerable input and inject into the database — "
                     "that alone can hand me your entire user table.")
    if "secret" in kinds:
        lines.append("Along the way I'd scoop up the keys and tokens you've left "
                     "lying in responses — often the pivot into your other systems.")
    if "jwt" in kinds:
        lines.append("I'd forge one of your login tokens and walk in as any user I like, "
                     "including an administrator.")
    if "privesc" in kinds:
        lines.append("With a throwaway account anyone can register, I'd reach pages "
                     "meant only for staff — your access control isn't actually enforced.")
    if "xss" in kinds:
        lines.append("And I'd plant script in a page that runs in your users' browsers — "
                     "enough to hijack their sessions.")
    lines.append("Chaining these together, I don't just find one bug — I get an "
                 "end-to-end break-in. That's what this report proves.")
    return " ".join(lines)
