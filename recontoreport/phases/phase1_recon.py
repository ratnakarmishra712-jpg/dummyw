"""Phase 1 — Recon & attack surface mapping (reference implementation).

Wires up two self-contained tools (no auth context needed):

* ``subfinder`` — passive subdomain discovery. Parsed from its JSONL output into
  ``asset`` rows of type ``subdomain``.
* ``ffuf`` — directory/file content discovery against a wordlist. Parsed from its
  JSON output into ``asset`` rows of type ``endpoint``/``file``. Hits whose path
  ends in a sensitive marker (.git/.bak/.zip/.env/...) are flagged in metadata
  and additionally recorded as a low-severity ``finding``.

Both steps honor the configured scope: discovered hosts outside scope are stored
but ffuf is only ever pointed at the in-scope target host.

The katana (JS crawl), amass, and prance/OpenAPI steps are stubbed with clear
TODO markers for the incremental build-out.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import select

from ..db import session_scope
from ..models import Asset, Finding, HttpTransaction, Target
from ..schema import (
    SENSITIVE_FILE_MARKERS,
    AssetType,
    Confidence,
    FindingStatus,
    Severity,
)
from ..tools.crawler import crawl, parse_html
from ..tools.runner import ToolNotFoundError, run
from .base import Phase, PhaseResult


class ReconPhase(Phase):
    number = 1
    name = "recon"
    active = True  # subfinder is passive, but ffuf actively probes the target.

    # -- helpers -------------------------------------------------------------
    def _target_host(self) -> str:
        parsed = urlparse(self.config.target_url)
        return parsed.hostname or ""

    def _registrable_domain(self) -> str:
        """Domain to hand subfinder: the registrable/apex domain, not the full host.

        subfinder enumerates subdomains OF the domain it's given, so passing
        'www.itsecgames.com' would look for '*.www.itsecgames.com' (nothing).
        We strip a leading 'www.' so 'www.itsecgames.com' -> 'itsecgames.com'.
        Hosts that are already apex, or IPs, are returned unchanged.
        """
        host = self._target_host()
        if not host:
            return ""
        # Leave IP addresses alone.
        if all(part.isdigit() for part in host.split(".")):
            return host
        if host.startswith("www."):
            return host[4:]
        return host

    def _store_asset(self, session, **kwargs) -> bool:
        """Insert an asset if (type, url) is not already present. Returns True if new."""
        exists = session.execute(
            select(Asset.id).where(
                Asset.target_id == self.ctx.target_id,
                Asset.type == kwargs["type"],
                Asset.url == kwargs["url"],
            )
        ).first()
        if exists:
            return False
        session.add(Asset(target_id=self.ctx.target_id, **kwargs))
        return True

    # -- subfinder -----------------------------------------------------------
    def _parse_subfinder_line(self, line: str) -> tuple[str, str | None]:
        """Return (host, source) from a subfinder output line.

        Tolerates both JSONL (``-json``) and plain host-per-line (``-silent``)
        output so it works across subfinder versions.
        """
        line = line.strip()
        if not line:
            return "", None
        if line.startswith("{"):
            try:
                rec = json.loads(line)
                return (
                    str(rec.get("host") or rec.get("input") or "").strip().lower(),
                    rec.get("source"),
                )
            except json.JSONDecodeError:
                return "", None
        # Plain hostname line.
        return line.lower(), None

    def _run_subfinder(self, errors: list[str]) -> int:
        domain = self._registrable_domain()
        if not domain:
            errors.append("subfinder: could not derive domain from target.url")
            return 0

        binary = self.config.tool("subfinder")
        cmd = [binary, "-d", domain, "-silent", "-json"]
        self.log.info("subfinder: enumerating subdomains of %s", domain)
        try:
            res = run(cmd, timeout=self.config.phase_policy.tool_timeout)
        except ToolNotFoundError as exc:
            errors.append(str(exc))
            return 0

        if not res.ok and not res.stdout.strip():
            errors.append(f"subfinder: exited {res.returncode}: {res.stderr.strip()[:300]}")
            return 0

        created = 0
        with session_scope(self.ctx.session_factory) as s:
            for line in res.stdout.splitlines():
                sub, source = self._parse_subfinder_line(line)
                if not sub:
                    continue
                rec = {"source": source}
                in_scope = self.config.scope.in_scope(sub)
                new = self._store_asset(
                    s,
                    type=AssetType.SUBDOMAIN.value,
                    url=sub,
                    source_tool="subfinder",
                    meta={"in_scope": in_scope, "source": rec.get("source")},
                )
                if new:
                    created += 1
        self.log.info("subfinder: %s new subdomains", created)
        return created

    # -- ffuf ----------------------------------------------------------------
    def _run_ffuf(self, errors: list[str]) -> tuple[int, int]:
        """Returns (assets_created, findings_created)."""
        wordlist = (self.config.wordlists or {}).get("content_discovery") or ""
        wordlist = str(Path(wordlist).expanduser()) if wordlist else ""
        if not wordlist:
            # Optional step, not an error — don't fail the phase over it.
            self.log.info(
                "ffuf: skipped (no wordlists.content_discovery configured)."
            )
            return 0, 0
        if not Path(wordlist).is_file():
            errors.append(f"ffuf: wordlist not found at '{wordlist}'")
            return 0, 0

        host = self._target_host()
        if host and not self.config.scope.in_scope(host):
            errors.append(f"ffuf: target host '{host}' is not in configured scope; refusing to fuzz")
            return 0, 0

        base = self.config.target_url.rstrip("/")
        binary = self.config.tool("ffuf")

        with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tmp:
            out_path = tmp.name

        cmd = [
            binary,
            "-u", f"{base}/FUZZ",
            "-w", f"{wordlist}:FUZZ",
            "-mc", "200,201,202,203,204,301,302,307,401,403",
            "-of", "json",
            "-o", out_path,
            "-s",  # silent
        ]
        try:
            res = run(cmd, timeout=self.config.phase_policy.tool_timeout)
        except ToolNotFoundError as exc:
            errors.append(str(exc))
            return 0, 0

        try:
            data = json.loads(Path(out_path).read_text() or "{}")
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"ffuf: could not read output: {exc}")
            if not res.ok:
                errors.append(f"ffuf: exited {res.returncode}: {res.stderr.strip()[:300]}")
            return 0, 0
        finally:
            Path(out_path).unlink(missing_ok=True)

        assets_created = 0
        findings_created = 0
        with session_scope(self.ctx.session_factory) as s:
            for hit in data.get("results") or []:
                url = (hit.get("url") or "").strip()
                if not url:
                    continue
                status = hit.get("status")
                length = hit.get("length")
                path = urlparse(url).path.lower()
                is_sensitive = any(path.endswith(m) or m in path for m in SENSITIVE_FILE_MARKERS)
                atype = AssetType.FILE.value if "." in Path(path).name else AssetType.ENDPOINT.value

                new = self._store_asset(
                    s,
                    type=atype,
                    url=url,
                    method="GET",
                    source_tool="ffuf",
                    meta={
                        "status_code": status,
                        "length": length,
                        "sensitive": is_sensitive,
                    },
                )
                if new:
                    assets_created += 1

                if is_sensitive and new:
                    asset = s.execute(
                        select(Asset).where(
                            Asset.target_id == self.ctx.target_id,
                            Asset.type == atype,
                            Asset.url == url,
                        )
                    ).scalar_one()
                    s.add(
                        Finding(
                            target_id=self.ctx.target_id,
                            asset_id=asset.id,
                            title=f"Sensitive file exposed: {Path(path).name}",
                            cwe_id="CWE-538",
                            owasp_category="A05:2021 Security Misconfiguration",
                            severity=Severity.MEDIUM.value,
                            confidence=Confidence.FIRM.value,
                            description=(
                                f"Content discovery found a potentially sensitive file "
                                f"reachable at {url} (HTTP {status})."
                            ),
                            tool_source="ffuf",
                            poc_steps=f"GET {url}  ->  HTTP {status}",
                            remediation=(
                                "Remove the file from the web root or block access to "
                                "it. Do not deploy VCS metadata, backups, archives, or "
                                "environment files to production."
                            ),
                            status=FindingStatus.OPEN.value,
                        )
                    )
                    findings_created += 1

        self.log.info("ffuf: %s new assets, %s findings", assets_created, findings_created)
        return assets_created, findings_created

    # -- built-in crawler ----------------------------------------------------
    def _run_crawler(self, errors: list[str]) -> int:
        """Crawl the target, store pages as transactions and discovered URLs as assets.

        Runs without external tools so a bare `--url` scan still produces an
        attack surface for later phases.
        """
        crawl_cfg = getattr(self.config, "crawl", None) or {}
        max_pages = int((crawl_cfg or {}).get("max_pages", 50))
        max_depth = int((crawl_cfg or {}).get("max_depth", 2))

        try:
            pages, crawl_errors = crawl(
                self.config.target_url,
                in_scope=self.config.scope.in_scope,
                max_pages=max_pages,
                max_depth=max_depth,
            )
        except Exception as exc:
            errors.append(f"crawler: {type(exc).__name__}: {exc}")
            return 0

        if not pages:
            # Surface the real reason (timeout, DNS, TLS, 0 in scope) instead of a guess.
            if crawl_errors:
                url, msg = crawl_errors[0]
                errors.append(f"crawler: could not fetch {url} — {msg}")
            else:
                errors.append(
                    "crawler: nothing fetched — target host may be out of scope "
                    f"(scope include={self.config.scope.include})"
                )
            return 0

        created = 0
        with session_scope(self.ctx.session_factory) as s:
            for page in pages:
                parsed_qs = urlparse(page.url).query
                atype = (
                    AssetType.API_ROUTE.value if parsed_qs else
                    (AssetType.FILE.value if "." in Path(urlparse(page.url).path).name
                     else AssetType.ENDPOINT.value)
                )
                if self._store_asset(
                    s, type=atype, url=page.url, method="GET", source_tool="crawler",
                    meta={"status_code": page.status, "has_params": bool(parsed_qs)},
                ):
                    created += 1
                # Persist the fetched page so later phases have bodies to analyze.
                s.add(HttpTransaction(
                    target_id=self.ctx.target_id,
                    tool_source="crawler",
                    method="GET",
                    url=page.url,
                    status_code=page.status,
                    response_headers=page.headers or None,
                    response_body=(page.body[:200_000] if page.body else None),
                    response_length=len(page.body) if page.body else None,
                ))
                # Expand links/forms/scripts into assets.
                if page.body:
                    parsed = parse_html(page.url, page.body)
                    for js in parsed.scripts:
                        if self.config.scope.in_scope(urlparse(js).hostname or ""):
                            if self._store_asset(s, type=AssetType.JS_FILE.value, url=js,
                                                  source_tool="crawler", meta=None):
                                created += 1
                    for link in parsed.links:
                        if not link.startswith(("http://", "https://")):
                            continue
                        if not self.config.scope.in_scope(urlparse(link).hostname or ""):
                            continue
                        has_q = bool(urlparse(link).query)
                        lt = AssetType.API_ROUTE.value if has_q else AssetType.ENDPOINT.value
                        if self._store_asset(s, type=lt, url=link, method="GET",
                                             source_tool="crawler",
                                             meta={"has_params": has_q}):
                            created += 1
                    for form in parsed.forms:
                        if self._store_asset(
                            s, type=AssetType.API_ROUTE.value, url=form["action"],
                            method=form["method"], source_tool="crawler",
                            meta={"params": form["params"]},
                        ):
                            created += 1
        self.log.info("crawler: %s pages, %s new assets", len(pages), created)
        return created

    # -- stubs for the remaining Phase 1 tools -------------------------------
    def _run_amass(self, errors: list[str]) -> int:
        # TODO(phase1): amass enum -d <host> -json <out>, merge into subdomain assets.
        self.log.debug("amass step not yet implemented")
        return 0

    def _run_openapi_ingest(self, errors: list[str]) -> int:
        # TODO(phase1): prance.ResolvingParser over a configured swagger/openapi
        #   URL or file; expand every path+method into api_route assets.
        self.log.debug("OpenAPI ingest step not yet implemented")
        return 0

    def _run_katana(self, errors: list[str]) -> int:
        # TODO(phase1): katana -u <url> -jc -jsl -json; store endpoint/js_file assets.
        self.log.debug("katana step not yet implemented")
        return 0

    # -- entrypoint ----------------------------------------------------------
    def run(self) -> PhaseResult:
        errors: list[str] = []

        # Guard: the target row must exist.
        with session_scope(self.ctx.session_factory) as s:
            if s.get(Target, self.ctx.target_id) is None:
                return self._result(ok=False, errors=["target row missing"])

        subs = self._run_subfinder(errors)
        crawled = self._run_crawler(errors)
        ffuf_assets, findings = self._run_ffuf(errors)

        # Implemented-but-stubbed steps (no-ops for now).
        self._run_amass(errors)
        self._run_openapi_ingest(errors)
        self._run_katana(errors)

        assets_created = subs + crawled + ffuf_assets
        # Phase succeeds if at least one tool produced data OR nothing errored.
        ok = assets_created > 0 or not errors
        return self._result(
            ok=ok,
            assets_created=assets_created,
            findings_created=findings,
            errors=errors,
        )
