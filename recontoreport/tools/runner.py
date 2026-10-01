"""Thin, safe subprocess helper for shelling out to external tools.

All external tool invocations go through :func:`run`. It never uses ``shell=True``
(arguments are passed as a list), enforces a timeout, and captures stdout/stderr.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass

log = logging.getLogger("recontoreport.tools")


class ToolNotFoundError(RuntimeError):
    """Raised when a configured tool binary is not on PATH / at the given path."""


@dataclass
class ToolResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def ensure_available(binary: str) -> str:
    """Return the resolved path to ``binary`` or raise ToolNotFoundError."""
    resolved = shutil.which(binary)
    if resolved is None:
        raise ToolNotFoundError(
            f"Required tool '{binary}' was not found on PATH. "
            f"Install it or set its path in config.yaml under 'tools'."
        )
    return resolved


def run(
    cmd: list[str],
    *,
    timeout: int = 600,
    check_binary: bool = True,
    input_text: str | None = None,
) -> ToolResult:
    """Run ``cmd`` (a list of args) and capture its output.

    Does not raise on nonzero exit — callers inspect ``ToolResult.ok`` so the
    orchestrator can apply its own retry/skip policy per phase.
    """
    if not cmd:
        raise ValueError("run() requires a non-empty command list")

    if check_binary:
        ensure_available(cmd[0])

    log.debug("exec: %s", " ".join(cmd))
    try:
        proc = subprocess.run(  # noqa: S603 - args are a list, shell is never used
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
    except subprocess.TimeoutExpired as exc:
        log.warning("tool timed out after %ss: %s", timeout, cmd[0])
        return ToolResult(
            command=cmd,
            returncode=-1,
            stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
            stderr=exc.stderr or "" if isinstance(exc.stderr, str) else "",
            timed_out=True,
        )

    return ToolResult(
        command=cmd,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )
