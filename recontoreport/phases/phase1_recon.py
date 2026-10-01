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
from ..models import Asset, Finding, Target
from ..schema import (
    SENSITIVE_FILE_MARKERS,
    AssetType,
    Confidence,
    FindingStatus,
    Severity,
)
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
    def _run_subfinder(self, errors: list[str]) -> int:
        host = self._target_host()
        if not host:
            errors.append("subfinder: could not derive host from target.url")
            return 0

        binary = self.config.tool("subfinder")
        cmd = [binary, "-d", host, "-silent", "-json"]
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
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sub = (rec.get("host") or rec.get("input") or "").strip().lower()
                if not sub:
                    continue
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
            errors.append(
                "ffuf: no wordlist configured (wordlists.content_discovery). "
                "Set it in config.yaml — no default is assumed."
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
        ffuf_assets, findings = self._run_ffuf(errors)

        # Implemented-but-stubbed steps (no-ops for now).
        self._run_amass(errors)
        self._run_openapi_ingest(errors)
        self._run_katana(errors)

        assets_created = subs + ffuf_assets
        # Phase succeeds if at least one tool produced data OR nothing errored.
        ok = assets_created > 0 or not errors
        return self._result(
            ok=ok,
            assets_created=assets_created,
            findings_created=findings,
            errors=errors,
        )
