"""Phase 2 — Traffic interception & analysis.

Orchestrates:
* ``mitmdump`` running the ReconCapture addon, logging every request/response
  (and WebSocket message) into ``http_transactions``.
* Playwright login flows that authenticate as each configured role and persist
  ``storage_state`` into ``auth_contexts``. The login traffic is routed through
  the proxy, so each role's session is also captured and tagged.

Modes:
* **Authenticated capture** — when ``auth.roles`` are configured, one capture
  session runs per role (proxy tagged with that role's auth_context).
* **Passive capture** — when no roles are configured, the proxy stays up for
  ``proxy.capture_window_seconds`` so traffic can be driven through it manually.

mitmproxy (``make dev`` / ``pip install mitmproxy``) and Playwright
(``pip install playwright && playwright install chromium``) are required.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from pathlib import Path

from sqlalchemy import func, select

from ..config import AuthRole
from ..db import session_scope
from ..models import AuthContext, HttpTransaction
from ..tools.runner import ensure_available
from .base import Phase, PhaseResult

_ADDON = Path(__file__).resolve().parent.parent / "tools" / "mitm_addon.py"


class TrafficPhase(Phase):
    number = 2
    name = "traffic"
    active = True

    # -- proxy process -------------------------------------------------------
    def _wait_for_port(
        self, host: str, port: int, proc: subprocess.Popen, timeout: float = 15.0
    ) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            # If mitmdump already exited (e.g. addon import error, port in use),
            # stop waiting — the port will never open.
            if proc.poll() is not None:
                return False
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                if s.connect_ex((host, port)) == 0:
                    return True
            time.sleep(0.3)
        return False

    def _start_proxy(self, auth_context_id: int | None) -> subprocess.Popen:
        proxy = self.config.proxy
        env = dict(os.environ)
        env["RECONTOREPORT_DB_URL"] = self.config.database_url
        env["RECONTOREPORT_TARGET_ID"] = str(self.ctx.target_id)
        if auth_context_id is not None:
            env["RECONTOREPORT_AUTH_CONTEXT_ID"] = str(auth_context_id)
        else:
            env.pop("RECONTOREPORT_AUTH_CONTEXT_ID", None)

        binary = self.config.tool("mitmproxy")  # defaults to "mitmdump"
        cmd = [
            binary,
            "-s", str(_ADDON),
            "--listen-host", proxy.listen_host,
            "--listen-port", str(proxy.listen_port),
            "--set", "flow_detail=0",
            "-q",
        ]
        self.log.info("starting proxy: %s", " ".join(cmd))
        proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if not self._wait_for_port(proxy.listen_host, proxy.listen_port, proc):
            # Surface mitmdump's own output so the real cause is visible
            # (addon import error, port already in use, cert prompt, etc.).
            output = ""
            if proc.poll() is not None and proc.stdout is not None:
                output = proc.stdout.read() or ""
            else:
                proc.terminate()
                try:
                    output = proc.communicate(timeout=5)[0] or ""
                except subprocess.TimeoutExpired:
                    proc.kill()
            detail = output.strip().splitlines()[-5:] if output.strip() else []
            raise RuntimeError(
                f"mitmdump did not start listening on "
                f"{proxy.listen_host}:{proxy.listen_port}."
                + (f" mitmdump output:\n  " + "\n  ".join(detail) if detail else
                   " (no output captured — check the port isn't already in use)")
            )
        return proc

    def _stop_proxy(self, proc: subprocess.Popen) -> None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    # -- playwright login ----------------------------------------------------
    def _proxy_url(self) -> str:
        p = self.config.proxy
        return f"http://{p.listen_host}:{p.listen_port}"

    def _login_and_capture_state(self, role: AuthRole) -> dict:
        """Run the login flow through the proxy and return Playwright storage_state."""
        from playwright.sync_api import sync_playwright  # lazy import

        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
            )
            # ignore_https_errors lets us MITM TLS without installing mitmproxy's CA.
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            try:
                if role.script:
                    self._run_custom_script(role, page)
                else:
                    self._generic_form_login(role, page)
                state = context.storage_state()
            finally:
                context.close()
                browser.close()
        return state

    def _generic_form_login(self, role: AuthRole, page) -> None:
        if not role.login_url:
            raise ValueError(f"auth role '{role.name}' has no login_url")
        page.goto(role.login_url, wait_until="domcontentloaded")
        page.fill(role.username_selector, role.username)
        page.fill(role.password_selector, role.password)
        page.click(role.submit_selector)
        if role.success_selector:
            page.wait_for_selector(role.success_selector, timeout=15000)
        else:
            page.wait_for_load_state("networkidle")

    def _run_custom_script(self, role: AuthRole, page) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location(f"login_{role.name}", role.script)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"could not load login script: {role.script}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if not hasattr(mod, "login"):
            raise RuntimeError(f"login script {role.script} must define login(page, role)")
        mod.login(page, role)

    def _persist_auth_context(self, role: AuthRole, state: dict) -> int:
        cookies = state.get("cookies")
        with session_scope(self.ctx.session_factory) as s:
            existing = s.execute(
                select(AuthContext).where(
                    AuthContext.target_id == self.ctx.target_id,
                    AuthContext.name == role.name,
                )
            ).scalar_one_or_none()
            if existing is None:
                existing = AuthContext(target_id=self.ctx.target_id, name=role.name)
                s.add(existing)
            existing.privilege_level = role.privilege_level
            existing.storage_state = state
            existing.cookies = cookies
            s.flush()
            return existing.id

    def _create_pending_auth_context(self, role: AuthRole) -> int:
        with session_scope(self.ctx.session_factory) as s:
            existing = s.execute(
                select(AuthContext).where(
                    AuthContext.target_id == self.ctx.target_id,
                    AuthContext.name == role.name,
                )
            ).scalar_one_or_none()
            if existing is None:
                existing = AuthContext(
                    target_id=self.ctx.target_id,
                    name=role.name,
                    privilege_level=role.privilege_level,
                )
                s.add(existing)
                s.flush()
            return existing.id

    # -- transaction counting ------------------------------------------------
    def _tx_count(self) -> int:
        with session_scope(self.ctx.session_factory) as s:
            return int(
                s.execute(
                    select(func.count(HttpTransaction.id)).where(
                        HttpTransaction.target_id == self.ctx.target_id
                    )
                ).scalar_one()
            )

    # -- entrypoint ----------------------------------------------------------
    def _cookie_string_to_list(self, cookie: str) -> list[dict]:
        """Parse 'a=1; b=2' into [{'name':'a','value':'1'}, ...]."""
        out = []
        for part in cookie.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out.append({"name": k.strip(), "value": v.strip()})
        return out

    def _persist_cookie_context(self, role) -> None:
        """Create an auth_context directly from a pasted cookie — no browser."""
        cookies = self._cookie_string_to_list(role.cookie)
        with session_scope(self.ctx.session_factory) as s:
            existing = s.execute(
                select(AuthContext).where(
                    AuthContext.target_id == self.ctx.target_id,
                    AuthContext.name == role.name,
                )
            ).scalar_one_or_none()
            if existing is None:
                existing = AuthContext(target_id=self.ctx.target_id, name=role.name)
                s.add(existing)
            existing.privilege_level = role.privilege_level
            existing.cookies = cookies
            existing.storage_state = {"cookies": cookies}

    def run(self) -> PhaseResult:
        errors: list[str] = []

        if not self.config.auth_roles:
            self.log.info("traffic: no auth roles configured; skipping capture.")
            return self._result(ok=True, errors=[])

        # Split roles: cookie-only (no browser needed) vs. real logins.
        cookie_roles = [r for r in self.config.auth_roles if r.cookie and not r.login_url]
        login_roles = [r for r in self.config.auth_roles if not (r.cookie and not r.login_url)]

        contexts_created = 0
        for role in cookie_roles:
            self._persist_cookie_context(role)
            contexts_created += 1
            self.log.info("traffic: created auth context '%s' from cookie", role.name)

        if not login_roles:
            # All roles were cookie-based — done, no browser required.
            return self._result(ok=True, errors=[])

        before = self._tx_count()

        for role in login_roles:
            try:
                self._create_pending_auth_context(role)
                self.log.info("logging in as '%s' via Playwright…", role.name)
                state = self._login_and_capture_state(role)
                self._persist_auth_context(role, state)
                contexts_created += 1
                self.log.info("captured auth context '%s' (%d cookies)",
                              role.name, len(state.get("cookies") or []))
            except Exception as exc:
                errors.append(f"auth role '{role.name}': {type(exc).__name__}: {exc}")

        captured = self._tx_count() - before
        ok = not errors or captured > 0 or contexts_created > 0
        return self._result(
            ok=ok,
            assets_created=0,
            findings_created=0,
            errors=errors,
        )
