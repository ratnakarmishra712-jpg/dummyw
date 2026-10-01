"""SQLAlchemy 2.0 ORM models — the shared data store for all phases.

Design notes:
* Every phase writes into these tables; later phases query them for context
  (e.g. the scanner reads ``assets`` produced by recon).
* ``metadata`` is a reserved attribute name on SQLAlchemy's declarative base, so
  the free-form JSON columns are named ``meta`` in Python and mapped to a
  ``metadata`` column in SQLite.
* JSON is stored via the portable ``JSON`` type (works on SQLite 3.9+).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    engagement_ref: Mapped[str] = mapped_column(String(512), default="")
    status: Mapped[str] = mapped_column(String(32), default="created", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)

    auth_contexts: Mapped[list["AuthContext"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    assets: Mapped[list["Asset"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class AuthContext(Base):
    """A named authenticated session (e.g. 'anon', 'low_priv', 'admin')."""

    __tablename__ = "auth_contexts"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # Privilege ordering for the Phase 3 privesc diff (higher = more privileged).
    privilege_level: Mapped[int] = mapped_column(Integer, default=0)
    cookies: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    headers: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    storage_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    target: Mapped[Target] = relationship(back_populates="auth_contexts")


class Asset(Base):
    """Anything discovered: subdomain, endpoint, file, js_file, api_route, ws."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    parent_asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id"), nullable=True
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    url: Mapped[str] = mapped_column(String(4096), nullable=False)
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    source_tool: Mapped[str] = mapped_column(String(64), default="")
    # status code, params schema, content-type, etc.
    meta: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    target: Mapped[Target] = relationship(back_populates="assets")
    parent: Mapped["Asset | None"] = relationship(remote_side=[id])
    findings: Mapped[list["Finding"]] = relationship(back_populates="asset")


class HttpTransaction(Base):
    """A captured request/response pair (mitmproxy, replays, scanners)."""

    __tablename__ = "http_transactions"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    auth_context_id: Mapped[int | None] = mapped_column(
        ForeignKey("auth_contexts.id"), nullable=True
    )
    # When this transaction is a replay, points at the original.
    origin_transaction_id: Mapped[int | None] = mapped_column(
        ForeignKey("http_transactions.id"), nullable=True
    )
    tool_source: Mapped[str] = mapped_column(String(64), default="")

    method: Mapped[str] = mapped_column(String(16), default="GET")
    url: Mapped[str] = mapped_column(String(4096), nullable=False)
    request_headers: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_headers: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class Finding(Base):
    """The central output table."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info", nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), default="tentative")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_source: Mapped[str] = mapped_column(String(64), default="")
    poc_steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    asset: Mapped["Asset | None"] = relationship(back_populates="findings")
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    payload_used: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Optional link to the transaction that proves this finding.
    http_transaction_id: Mapped[int | None] = mapped_column(
        ForeignKey("http_transactions.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class SecretMatch(Base):
    """Regex hits from log/body scraping — kept separate from findings until
    manually promoted."""

    __tablename__ = "secret_matches"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    http_transaction_id: Mapped[int | None] = mapped_column(
        ForeignKey("http_transactions.id"), nullable=True
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False)  # email, aws_key, ...
    matched_value: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    promoted_finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    path: Mapped[str] = mapped_column(String(4096), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    target: Mapped[Target] = relationship(back_populates="reports")
