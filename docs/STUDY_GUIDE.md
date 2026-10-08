# ReconToReport — In-Depth Study Guide (for the viva)

Read this top to bottom twice. It is written so you can **explain, defend, and
reason** about the project — not memorise trivia. Every claim here matches the
actual code.

---

## 0. The one-paragraph truth you must internalise

ReconToReport is a **pipeline orchestrator**. It does not invent new hacking
techniques. It takes the dozen specialised tools a human penetration tester
already uses, **runs them in a dependency-ordered sequence**, forces all their
different outputs into **one shared database schema**, and then **generates a
report** from that database. The intellectual contribution is the
**integration** — the shared data model that lets a later tool use what an
earlier tool found. Everything else is plumbing around that idea.

If you understand *why the shared store matters*, you can answer almost anything.

---

## 1. System architecture (the 4 layers)

```
INPUT            cli.py  /  web/app.py        → parse flags / form, pick target & phases
  │
CONFIG           config.py                    → one Config object (target, scope, phases, auth, tools)
  │
ORCHESTRATION    orchestrator.py              → create target row, resolve phase deps,
  │              phases/__init__.py             authorization gate, run phases with error isolation
  │
EXECUTION        phases/phase1..5             → each phase: shell out to tools → capture → normalise
  │              tools/* (runner, crawler,      → read/write the shared store
  │                       capture, jwt,
  │                       secrets, mitm_addon)
  │
STORAGE          models.py + db.py (SQLite)   → 8 tables, one schema every phase shares
  │
OUTPUT           report/generator.py          → Jinja2 → severity-ranked HTML/XML report
                 report/templates/*.j2
```

**Why layered?** Separation of concerns. The orchestrator knows *nothing* about
how to find XSS; a phase knows nothing about sequencing or retries; the store
knows nothing about tools. You can add a phase without touching the others.

---

## 2. The data model — know these 8 tables cold

All in `models.py`, SQLAlchemy ORM over SQLite. Every row ties back to a
`target` via `target_id` (so one database can hold many engagements).

| Table | Holds | Written by | Read by |
|---|---|---|---|
| `targets` | the root scope (url, status, created_at) | orchestrator | everything |
| `assets` | anything discovered: subdomain, endpoint, file, js_file, api_route, websocket (type, url, method, source_tool, metadata JSON, optional parent_asset_id) | P1 recon | P3 scan, P4 exploit |
| `http_transactions` | every request/response pair (method, url, headers, body, status, length, tool_source, **origin_transaction_id** for replays, **auth_context_id**) | P1, P2, P3 | P3, P4, P5 |
| `auth_contexts` | a named login session (name, **privilege_level**, cookies, headers, storage_state) | P2 traffic | P3 privesc |
| `findings` | the central output: title, cwe_id, owasp_category, severity, confidence, description, poc_steps, remediation, status, asset_id | P1, P3, P4 | report |
| `evidence` | proof attached to a finding (type, payload_used, raw_data) | phases | report |
| `secret_matches` | regex hits (kind, matched_value, context) — kept **separate** from findings until promoted | P5 harvest | report |
| `reports` | metadata about generated report files (format, path) | report gen | — |

**Three fields that win viva points** — be ready to explain *why they exist*:
- `origin_transaction_id` (self-FK on http_transactions): links a **replayed**
  request back to the original. This is what makes the privilege-escalation
  diff possible — you can store "this is the admin request, replayed as the low
  user" and compare.
- `auth_context_id` on a transaction: tags **which identity** made the request.
  Without it you can't tell admin traffic from normal-user traffic.
- `privilege_level` on auth_contexts: lets the privesc check order roles
  (higher number = more privileged) and know which replay *should* be denied.

> **Design Q:** "Why SQLite / one schema, not separate JSON files per tool?"
> **A:** Later phases must *query* earlier results (the scanner needs the
> endpoint list; the privesc check needs two identities + their captured
> traffic). A relational store with foreign keys makes correlation trivial and
> the whole run reproducible. Files would force every phase to re-parse every
> other tool's bespoke format.

---

## 3. The orchestrator — how a run actually executes (`orchestrator.py`)

1. **`_get_or_create_target()`** → inserts/loads the `targets` row, sets status `running`.
2. **`resolve_phases(requested)`** (`phases/__init__.py`) → each phase class
   declares `depends_on`; this does a transitive expansion and returns the full
   ordered list + which were auto-added. So `--phases 4` becomes `[1,3,4]`
   because 4 depends on 3, and 3 depends on 1.
3. For each phase number:
   - build a **`PhaseContext`** = `{config, target_id, session_factory, logger}`.
   - **Authorization gate:** if `phase.active` is True and the user did **not**
     pass authorization → skip it with a clear message. (Only Phase 5 harvest is
     `active = False`, because it's offline over already-captured data.)
   - **`_run_phase_with_retries()`** → runs `phase.run()` inside a try/except so
     one phase crashing never kills the run; applies the retry policy (now
     default **0** retries so a slow tool can't double its wait).
4. Sets target status `completed`/`failed`, returns a list of `PhaseResult`.

**Fault isolation** is a real design choice: a `PhaseResult(ok=False, errors=[…])`
is data, not an exception that aborts everything. That's why a missing tool or a
timeout degrades gracefully instead of crashing.

---

## 4. The five phases — exact behaviour

### Phase 1 — Recon (`phase1_recon.py`), active
Goal: build the attack surface. Three sub-steps, each tolerant of failure:
- **subfinder** → run on the *registrable* domain (we strip `www.` because
  subfinder enumerates subdomains *of* what you give it). Output parsed (JSON or
  plain) → `assets(type=subdomain)`.
- **built-in crawler** (`tools/crawler.py`, our own, no external dep) → BFS from
  the target, same-scope only; each page stored as an `http_transaction`, each
  link/form/script/param as an `asset`. This guarantees surface even with zero
  tools installed, and captures bodies P4/P5 later mine.
- **ffuf** (optional) → wordlist path brute-force; hits → assets; sensitive
  extensions (.git/.env/.bak) → a `finding`.

### Phase 2 — Traffic / Auth (`phase2_traffic.py`), active
Goal: record real traffic and capture logins.
- **mitmproxy** runs with our addon (`tools/mitm_addon.py` → `tools/capture.py`)
  logging every request/response + WebSocket message into `http_transactions`.
- **Playwright** logs in per configured role, saves `storage_state` →
  `auth_contexts`, routed through the proxy so login traffic is captured too.
- **Skips cleanly** when no auth roles are configured (nothing to authenticate).

### Phase 3 — Scan (`phase3_scan.py`), active, depends_on (1)
Three detectors:
- **nuclei** → runs over discovered asset URLs; each JSON hit → a `finding`,
  with severity/CWE/description/remediation read **from the template metadata**
  (dynamic, thousands of possible classes).
- **Reflected/DOM-XSS canary** (Playwright) → injects a unique marker into query
  params; if it appears unescaped in the DOM or fires a dialog → XSS `finding`
  (HIGH if it executed, MEDIUM if only reflected).
- **Privilege-escalation diff** (our code) → the flagship. Reads ≥2
  `auth_contexts`; takes the high-priv user's successful captured GETs; replays
  each with the **low-priv** user's cookies; if the low user still gets 2xx →
  broken-access-control `finding` (CWE-285). Needs the shared store to exist.

### Phase 4 — Exploit (`phase4_exploit.py`), active, depends_on (3)
- **JWT analysis** (`tools/jwt_analysis.py`) → scans captured traffic for JWTs,
  decodes them, flags `alg:none` (critical), weak HMAC secret, missing expiry.
- **sqlmap** → run against parameterised in-scope URLs; confirmed injection →
  critical `finding`. Time-bounded so it can't stall the run.

### Phase 5 — Harvest (`phase5_harvest.py`), **offline (active=False)**
- **Secret scraper** (`tools/secrets.py`) → regex over all captured bodies/headers
  for emails, AWS keys, API keys, private keys, cards (**Luhn-checked**) →
  `secret_matches`. Kept separate from findings until a human promotes them
  (reduces false alarms). Offline → runs without the authorization flag.

Then the **report generator** (`report/generator.py`) reads the finished store,
groups findings by severity, and renders the HTML/XML via Jinja2, adding
CVSS/impact fields from severity lookup tables in the template.

---

## 5. Security concepts — explain each in one breath

- **XSS (Cross-Site Scripting, CWE-79):** the site echoes your input back into
  the page without cleaning it, so you can inject JavaScript that runs in other
  users' browsers. We detect it by injecting a marker and seeing if it executes.
- **SQL Injection (CWE-89):** user input is concatenated into a database query,
  letting an attacker change the query — read/dump/modify data. sqlmap confirms it.
- **Broken Access Control (CWE-285, OWASP A01):** the server trusts the UI
  instead of re-checking permissions, so a low-privilege user can call an
  admin-only action directly. We find it by replaying admin requests as a normal user.
- **JWT weaknesses:** JWTs are signed login tokens. `alg:none` = unsigned, anyone
  can forge one → account takeover. Weak secret = guessable signature. No expiry
  = a leaked token works forever.
- **Secret exposure:** credentials/keys accidentally left in page source or API
  responses — an attacker just reads them.

---

## 6. Key design decisions (viva gold — they ask "why")

| Decision | Why |
|---|---|
| One shared SQLite schema | lets later phases query earlier results; enables cross-tool findings like privesc |
| Normalising every tool into `findings` | one report format regardless of which tool found it; comparable severities |
| Dependency-resolved phases | user picks an outcome (`--phases 4`) and prerequisites run automatically |
| Authorization gate on active phases | legal/ethical safety — never scan without explicit consent |
| Per-phase fault isolation + per-tool timeouts | one slow/broken tool can't hang or crash the whole run |
| Built-in crawler (no external dep) | guarantees an attack surface and captured bodies even with nothing installed |
| Secrets kept separate from findings | avoid false positives polluting the report; human promotes real ones |
| Confidence levels on findings | an automated scanner can't be 100% sure; we're honest about it |

---

## 7. Limitations — say these *proactively*, it builds credibility

- Finds **common and known-pattern** vulnerabilities; **not** deep
  business-logic flaws a human would reason out.
- Some findings are **"possible"** and need manual confirmation — true of
  commercial scanners too.
- Coverage depends on what the crawler reaches; **auth roles must be configured**
  for the privesc check and behind-login scanning to run.
- External tools (nuclei/sqlmap) must be installed; without them those phases
  degrade gracefully but find less.

---

## 8. Hard-viva Q&A (deep answers)

**Q: Walk me through what happens when I type the command.**
A: cli.py parses flags → builds a Config (or from_url) → Orchestrator creates a
targets row → resolve_phases expands dependencies → for each phase: auth gate
check, build PhaseContext, run with error isolation → each phase shells out via
tools/runner.py, parses output, writes assets/transactions/findings → report
generator reads the store and renders HTML.

**Q: How do two different tools share data? Give a concrete path.**
A: The crawler writes a page body into `http_transactions`; Phase 5's secret
scraper later reads that same row and finds an AWS key in it. Neither knows about
the other — they meet only in the shared table. (Demonstrated: `secrets: 3 new
matches` on a crawled page.)

**Q: What's genuinely novel vs. just running tools in a shell script?**
A: A shell script's tools can't see each other's results. Ours share a schema,
so a phase can *correlate* — e.g. privesc needs the admin's recorded request
*and* the low-priv identity *and* a replay, three things from different tools,
only joinable because they're in one database.

**Q: How do you prevent one tool hanging the whole thing?**
A: Each external call goes through `tools/runner.py` with a timeout; nuclei and
sqlmap have their own tighter budgets; phases run in try/except and return a
result object instead of throwing; retries default to 0.

**Q: How do you keep false positives down?**
A: Confidence levels per finding; XSS only HIGH if it actually executed; secrets
quarantined in a separate table until promoted; privesc only fires on a genuine
2xx the low user shouldn't get.

**Q: Show me the privilege-escalation logic.**
A: Open `phase3_scan.py`, function `_run_privesc_diff`: order auth_contexts by
privilege, take the top one's successful GET transactions, replay each with a
lower context's cookies, compare status; 2xx for the low user → finding.

**Q: Why Flask + a background thread for the UI?**
A: Scans take time; the thread runs the orchestrator while the page polls
`/status` for live log + results, so the browser never blocks. Per-run data goes
in `r2r_ui_data/<run_id>/` so history survives restarts.

**Q: How would you extend classification?**
A: Three ways — write a nuclei YAML template (no code change), add more template
tags, or add a custom Python check in a phase for logic nuclei can't express.

---

## 8.5 The red-team angle — how to set this apart from a plain scanner

Another team is building "the same project." The way you win the room is to stop
describing ReconToReport as a *vulnerability scanner* and start describing it as a
small **adversary-emulation pipeline**. This is not spin — it is a more accurate
description of what the code already does. A scanner answers *"what is broken?"*.
An adversary emulator answers *"what could an attacker actually chain together,
end to end?"* Our architecture answers the second question; a bag of independent
tools cannot.

**The one sentence:** *"We don't just list findings — we reproduce the attacker's
workflow: discover the surface, operate as real authenticated identities, and
prove that one weakness leads to the next, all off a single shared evidence store."*

Three differentiators you can defend with the actual code:

1. **Chaining, not scanning (the shared store).** Each phase reads what the
   previous phase wrote. Recon (P1) populates `assets`; P2 establishes
   `auth_contexts` (real sessions); P3/P4 attack *those specific assets as those
   specific identities*. A classic scanner fires templates at a URL in isolation.
   We model the kill-chain order — **recon → authenticated access → privilege
   escalation → reportable impact** — and the data model is what makes the chain
   possible. *This is the novelty slide, reframed as tradecraft.*

2. **Operating as an identity, not an anonymous prober (`auth_contexts`).** A real
   red-teamer rarely tests logged-out. P2 captures/loads named sessions with a
   `privilege_level`; P3 then *replays a privileged user's own requests using a
   lower-privileged user's cookies.* That is exactly how an operator tests for
   broken access control by hand — we automated it. No anonymous scanner can do
   this, because it has no concept of "who am I right now."

3. **Proving impact, not flagging patterns (`_run_privesc_diff`).** The flagship
   finding is a *differential* result: anonymous denied, high-priv allowed,
   low-priv **also** allowed → broken access control with a concrete two-line PoC.
   That is an attacker demonstrating escalation, not a signature match. It is
   only expressible because three facts from three different steps live in one
   joinable store.

**If asked "is this really red-team?":** Be honest and precise. "It automates the
*reconnaissance-to-access-to-escalation* workflow and produces operator evidence.
It does not do C2, lateral movement, or evasion — it is pre-exploitation adversary
emulation for web apps. Framing it that way is accurate, and it's the part of a
red-team engagement that is most mechanisable." Honesty here reads as competence.

**Roadmap line (say "planned", never "done"):** mapping each finding to a MITRE
ATT&CK technique and rendering the achieved tactics as a kill-chain strip is the
natural next step — the phase structure already lines up with ATT&CK tactics, so
it's a presentation layer over data we already collect. *Do not claim it ships
today; claiming features you can't open in the editor is how you lose a viva.*

---

## 9. 5-minute cram (if you only have minutes before)

1. **Hook:** "Not a scanner — a small adversary-emulation pipeline: recon → authenticated access → privilege escalation → report, from one URL."
2. **Novelty:** shared database lets each step attack what the last step found, as a real identity — that's the chain, and a bag of tools can't do it.
3. **Flow:** input → config → orchestrator → 5 phases (read/write shared DB) → report.
4. **Flagship finding:** broken access control by replaying an admin's own requests as a normal user — attacker proving escalation, impossible without the shared store.
5. **Proof:** 20 real XSS on Google Firing Range, auto-reported.
6. **Honesty:** finds common/known patterns, not business logic; some findings need manual confirmation.

If you can say those six things confidently and open the right file when asked,
you can hold the viva.
