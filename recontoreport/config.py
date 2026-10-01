"""Configuration loading and validation.

Loads the YAML config, expands ``${ENV_VAR}`` references in string values, and
exposes typed accessors. Intentionally light on dependencies (PyYAML only) so it
can be imported before the heavier phase modules.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: Any) -> Any:
    """Recursively expand ${VAR} references in strings within a nested structure."""
    if isinstance(value, str):
        def repl(m: re.Match[str]) -> str:
            return os.environ.get(m.group(1), "")
        return _ENV_RE.sub(repl, value)
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    return value


@dataclass
class ScopeConfig:
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    max_concurrency: int = 4

    def _host_matches(self, host: str, pattern: str) -> bool:
        host = host.lower().strip()
        pattern = pattern.lower().strip()
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            return host == pattern[2:] or host.endswith(suffix)
        return host == pattern

    def in_scope(self, host: str) -> bool:
        """True if ``host`` matches an include rule and no exclude rule."""
        if not host:
            return False
        if any(self._host_matches(host, p) for p in self.exclude):
            return False
        return any(self._host_matches(host, p) for p in self.include)


@dataclass
class PhasePolicy:
    retries: int = 1
    retry_backoff_seconds: float = 3.0
    tool_timeout: int = 600


@dataclass
class Config:
    target_url: str
    engagement_ref: str
    scope: ScopeConfig
    database_url: str
    output_dir: Path
    output_formats: list[str]
    tools: dict[str, str]
    wordlists: dict[str, str]
    nuclei: dict[str, Any]
    api_keys: dict[str, str]
    phase_policy: PhasePolicy
    source_path: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        path = Path(path).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Config file not found: {path}")
        raw = yaml.safe_load(path.read_text()) or {}
        raw = _expand_env(raw)

        target = raw.get("target") or {}
        scope_raw = raw.get("scope") or {}
        db_raw = raw.get("database") or {}
        out_raw = raw.get("output") or {}
        phases_raw = raw.get("phases") or {}

        if not target.get("url"):
            raise ValueError("config: target.url is required")

        return cls(
            target_url=str(target["url"]).strip(),
            engagement_ref=str(target.get("engagement_ref", "")).strip(),
            scope=ScopeConfig(
                include=list(scope_raw.get("include") or []),
                exclude=list(scope_raw.get("exclude") or []),
                max_concurrency=int(scope_raw.get("max_concurrency", 4)),
            ),
            database_url=str(db_raw.get("url") or "sqlite:///recontoreport.db"),
            output_dir=Path(str(out_raw.get("dir") or "./reports")).expanduser(),
            output_formats=list(out_raw.get("formats") or ["html"]),
            tools=dict(raw.get("tools") or {}),
            wordlists=dict(raw.get("wordlists") or {}),
            nuclei=dict(raw.get("nuclei") or {}),
            api_keys=dict(raw.get("api_keys") or {}),
            phase_policy=PhasePolicy(
                retries=int(phases_raw.get("retries", 1)),
                retry_backoff_seconds=float(phases_raw.get("retry_backoff_seconds", 3.0)),
                tool_timeout=int(phases_raw.get("tool_timeout", 600)),
            ),
            source_path=path,
        )

    def tool(self, name: str) -> str:
        """Resolve a configured tool binary, defaulting to the bare name on $PATH."""
        return self.tools.get(name) or name
