"""Phase 3 — Automated & custom vulnerability discovery.

Steps:
* **nuclei** — runs against in-scope asset URLs (falls back to the target URL),
  parsing JSONL output into ``findings``.
* **Privilege-escalation diffing** — replays captured GET transactions from a
  higher-privilege ``auth_context`` using a lower-privilege context's cookies and
  flags cases where access is NOT properly denied (broken access control).
* **Reflected/DOM XSS canary** — best-effort Playwright check that injects a
  canary into query parameters and reports it if it reaches the DOM unescaped or
  fires a dialog.

Depends on Phase 1 (needs discovered assets). The privesc and XSS steps also use
Phase 2 data (auth_contexts / transactions) when present, and no-op otherwise.
"""

from __future__ import annotations

import json
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import select

from ..db import session_scope
from ..models import Asset, AuthContext, Finding, HttpTransaction
from ..schema import Confidence, FindingStatus, Severity
from ..tools.runner import ToolNotFoundError, run
from .base import Phase, PhaseResult

# nuclei severity string -> our Severity
_SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}

XSS_CANARY = "r2rXSS9134"


class ScanPhase(Phase):
    number = 3
    name = "scan"
    active = True
    depends_on = (1,)

    # -- helpers -------------------------------------------------------------
    def _in_scope_urls(self, limit: int = 2000) -> list[str]:
        urls: list[str] = []
        with session_scope(self.ctx.session_factory) as s:
            assets = s.execute(
                select(Asset).where(Asset.target_id == self.ctx.target_id)
            ).scalars().all()
            for a in assets:
                host = urlparse(a.url).hostname or a.url
                if self.config.scope.in_scope(host):
                    urls.append(a.url)
        # De-dupe, keep the target URL as a guaranteed entry.
        if self.config.target_url not in urls:
            urls.insert(0, self.config.target_url)
        seen: set[str] = set()
        out = [u for u in urls if not (u in seen or seen.add(u))]
        return out[:limit]

    # -- nuclei --------------------------------------------------------------
    def _run_nuclei(self, errors: list[str]) -> int:
        binary = self.config.tool("nuclei")
        nuclei_cfg = self.config.nuclei or {}
        max_urls = int(nuclei_cfg.get("max_urls", 25))
        urls = self._in_scope_urls(limit=max_urls)
        if not urls:
            errors.append("nuclei: no in-scope URLs to scan")
            return 0

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as uf:
            uf.write("\n".join(urls))
            urls_path = uf.name
        out_path = urls_path + ".jsonl"

        cmd = [
            binary, "-l", urls_path, "-jsonl", "-o", out_path, "-silent",
            "-disable-update-check",
            "-timeout", "10", "-retries", "1",
            "-rate-limit", str(nuclei_cfg.get("rate_limit", 150)),
        ]
        templates_dir = nuclei_cfg.get("templates_dir") or ""
        tags = nuclei_cfg.get("tags") or []
        if templates_dir:
            cmd += ["-t", str(Path(templates_dir).expanduser())]
        elif tags:
            cmd += ["-tags", ",".join(tags)]
        else:
            # Fast, high-signal default instead of the full ~10k-template set.
            default_tags = "misconfiguration,exposure,default-login,takeover,tech"
            cmd += ["-tags", default_tags]
            self.log.info("nuclei: using fast default tags (%s); set nuclei.tags to customize.", default_tags)

        # nuclei gets its OWN budget so it can't eat the whole phase timeout.
        nuclei_timeout = int(nuclei_cfg.get("timeout_seconds", 180))
        try:
            res = run(cmd, timeout=nuclei_timeout)
        except ToolNotFoundError as exc:
            errors.append(str(exc))
            Path(urls_path).unlink(missing_ok=True)
            return 0

        created = 0
        try:
            lines = Path(out_path).read_text().splitlines() if Path(out_path).exists() else []
        except OSError:
            lines = []
        finally:
            Path(urls_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

        if res.timed_out:
            # Not a phase failure — just note it and keep going (no retry).
            self.log.warning(
                "nuclei: hit its %ss budget and was stopped; parsed %s partial result(s). "
                "Lower nuclei.max_urls or set narrower nuclei.tags to finish faster.",
                nuclei_timeout, len(lines),
            )
        elif not lines and not res.ok:
            errors.append(f"nuclei: exited {res.returncode}: {res.stderr.strip()[:300]}")
            return 0

        with session_scope(self.ctx.session_factory) as s:
            for line in lines:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                created += self._store_nuclei_finding(s, rec)
        self.log.info("nuclei: %s findings", created)
        return created

    def _store_nuclei_finding(self, session, rec: dict) -> int:
        info = rec.get("info") or {}
        sev = _SEV_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        classification = info.get("classification") or {}
        cwe = classification.get("cwe-id")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        matched = rec.get("matched-at") or rec.get("host") or ""
        title = info.get("name") or rec.get("template-id") or "nuclei finding"

        session.add(
            Finding(
                target_id=self.ctx.target_id,
                title=title,
                cwe_id=str(cwe) if cwe else None,
                owasp_category=None,
                severity=sev.value,
                confidence=Confidence.FIRM.value,
                description=info.get("description") or f"nuclei template {rec.get('template-id')}",
                tool_source="nuclei",
                poc_steps=f"Matched at: {matched}\nTemplate: {rec.get('template-id')}",
                remediation=info.get("remediation") or "Review the matched template guidance.",
                status=FindingStatus.OPEN.value,
            )
        )
        return 1

    # -- privilege-escalation diffing ----------------------------------------
    def _http_get(self, url: str, cookies: dict | None, headers: dict | None):
        """Return (status_code, body_len). Overridable for tests."""
        req = urllib.request.Request(url, method="GET")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        if cookies:
            cookie_str = "; ".join(f"{c.get('name')}={c.get('value')}" for c in cookies
                                   if isinstance(c, dict) and c.get("name"))
            if cookie_str:
                req.add_header("Cookie", cookie_str)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                body = resp.read()
                return resp.status, len(body)
        except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
            return e.code, 0
        except Exception:
            return None, 0

    def _run_privesc_diff(self, errors: list[str]) -> int:
        with session_scope(self.ctx.session_factory) as s:
            contexts = s.execute(
                select(AuthContext)
                .where(AuthContext.target_id == self.ctx.target_id)
                .order_by(AuthContext.privilege_level.desc())
            ).scalars().all()
            if len(contexts) < 2:
                self.log.info("privesc: need >=2 auth_contexts; skipping")
                return 0

            high = contexts[0]
            lowers = contexts[1:]
            # Baseline: successful GETs captured under the high-priv context.
            baseline = s.execute(
                select(HttpTransaction).where(
                    HttpTransaction.target_id == self.ctx.target_id,
                    HttpTransaction.auth_context_id == high.id,
                    HttpTransaction.method == "GET",
                )
            ).scalars().all()
            baseline = [t for t in baseline if (t.status_code or 0) < 400][:200]

            # Snapshot the data we need before leaving the session.
            baseline_data = [(t.id, t.url, t.response_length or 0) for t in baseline]
            lower_data = [(c.id, c.name, c.cookies, c.headers) for c in lowers]

        created = 0
        for (lc_id, lc_name, lc_cookies, lc_headers) in lower_data:
            for (origin_id, url, base_len) in baseline_data:
                host = urlparse(url).hostname or ""
                if not self.config.scope.in_scope(host):
                    continue
                status, length = self._http_get(url, lc_cookies, lc_headers)
                if status is None:
                    continue
                # Record the replay transaction.
                with session_scope(self.ctx.session_factory) as s:
                    s.add(HttpTransaction(
                        target_id=self.ctx.target_id,
                        auth_context_id=lc_id,
                        origin_transaction_id=origin_id,
                        tool_source="privesc-replay",
                        method="GET",
                        url=url,
                        status_code=status,
                        response_length=length,
                    ))
                # Broken access control: lower-priv got a 2xx on a high-priv resource.
                if 200 <= status < 300:
                    with session_scope(self.ctx.session_factory) as s:
                        s.add(Finding(
                            target_id=self.ctx.target_id,
                            title=f"Possible broken access control: {lc_name} reached {url}",
                            cwe_id="CWE-285",
                            owasp_category="A01:2021 Broken Access Control",
                            severity=Severity.HIGH.value,
                            confidence=Confidence.TENTATIVE.value,
                            description=(
                                f"A resource captured under higher-privilege context "
                                f"'{self.config.target_url}' returned HTTP {status} "
                                f"when replayed with the lower-privilege context "
                                f"'{lc_name}'. Review whether this endpoint should be "
                                f"accessible to that role."
                            ),
                            tool_source="privesc-diff",
                            poc_steps=f"Replay GET {url} with '{lc_name}' cookies -> HTTP {status}",
                            remediation=(
                                "Enforce server-side authorization checks per role on "
                                "this endpoint; do not rely on UI/navigation hiding."
                            ),
                            status=FindingStatus.OPEN.value,
                        ))
                    created += 1
        self.log.info("privesc: %s findings", created)
        return created

    # -- reflected / DOM XSS canary ------------------------------------------
    def _run_xss_canary(self, errors: list[str]) -> int:
        try:
            from playwright.sync_api import sync_playwright  # lazy
        except Exception:
            self.log.info("xss: playwright not installed; skipping")
            return 0

        # Candidate URLs that already carry query params.
        with session_scope(self.ctx.session_factory) as s:
            assets = s.execute(
                select(Asset).where(Asset.target_id == self.ctx.target_id)
            ).scalars().all()
            candidates = []
            for a in assets:
                p = urlparse(a.url)
                host = p.hostname or ""
                if p.query and self.config.scope.in_scope(host):
                    candidates.append(a.url)
        candidates = candidates[:50]
        if not candidates:
            self.log.info("xss: no parameterized in-scope URLs; skipping")
            return 0

        created = 0
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            for url in candidates:
                injected = url.replace("=", f"={XSS_CANARY}<b>", 1)
                dialog_fired = {"v": False}
                ctx = browser.new_context(ignore_https_errors=True)
                page = ctx.new_page()
                page.on("dialog", lambda d: (dialog_fired.__setitem__("v", True), d.dismiss()))
                try:
                    page.goto(injected, wait_until="domcontentloaded", timeout=15000)
                    html = page.content()
                    reflected_raw = f"{XSS_CANARY}<b>" in html
                    if reflected_raw or dialog_fired["v"]:
                        created += self._store_xss_finding(url, injected, dialog_fired["v"])
                except Exception:
                    pass
                finally:
                    ctx.close()
            browser.close()
        self.log.info("xss: %s findings", created)
        return created

    def _store_xss_finding(self, url: str, injected: str, dialog: bool) -> int:
        with session_scope(self.ctx.session_factory) as s:
            s.add(Finding(
                target_id=self.ctx.target_id,
                title=f"Possible XSS (reflected canary): {urlparse(url).path}",
                cwe_id="CWE-79",
                owasp_category="A03:2021 Injection",
                severity=Severity.HIGH.value if dialog else Severity.MEDIUM.value,
                confidence=Confidence.FIRM.value if dialog else Confidence.TENTATIVE.value,
                description=(
                    "A canary injected into a query parameter was reflected into the "
                    "DOM without encoding" + (" and executed (dialog fired)." if dialog else ".")
                ),
                tool_source="xss-canary",
                poc_steps=f"Load: {injected}",
                remediation=(
                    "Context-encode output and validate input; apply a strict "
                    "Content-Security-Policy."
                ),
                status=FindingStatus.OPEN.value,
            ))
        return 1

    # -- entrypoint ----------------------------------------------------------
    def run(self) -> PhaseResult:
        errors: list[str] = []
        findings = 0
        findings += self._run_nuclei(errors)
        try:
            findings += self._run_privesc_diff(errors)
        except Exception as exc:
            errors.append(f"privesc: {type(exc).__name__}: {exc}")
        try:
            findings += self._run_xss_canary(errors)
        except Exception as exc:
            errors.append(f"xss: {type(exc).__name__}: {exc}")

        ok = findings > 0 or not errors
        return self._result(ok=ok, assets_created=0, findings_created=findings, errors=errors)
