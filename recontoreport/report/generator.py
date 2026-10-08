"""Render the finished data store into client-facing report files."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker, Session

from ..attack import attack_for, build_attack_path, technique_url
from ..models import Asset, Finding, Report, SecretMatch, Target
from ..schema import Severity


def attack_technique(f) -> dict:
    """{id, name, url} for one finding — a Jinja global for the ATT&CK cell."""
    tid, tname, _ = attack_for(getattr(f, "cwe_id", None), getattr(f, "tool_source", None))
    return {"id": tid, "name": tname, "url": technique_url(tid)}

_TEMPLATE_DIR = Path(__file__).parent / "templates"

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.globals["attack_technique"] = attack_technique
    return env


def _collect(session: Session, target_id: int) -> dict:
    target = session.get(Target, target_id)
    findings = session.execute(
        select(Finding).where(Finding.target_id == target_id)
    ).scalars().all()
    assets = session.execute(
        select(Asset).where(Asset.target_id == target_id)
    ).scalars().all()
    secrets = session.execute(
        select(SecretMatch).where(SecretMatch.target_id == target_id)
    ).scalars().all()

    # Group findings by severity, most-severe first.
    grouped: dict[str, list[Finding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)
    grouped = {k: v for k, v in grouped.items() if v}

    counts = {s: len(grouped.get(s, [])) for s in _SEVERITY_ORDER}

    return {
        "target": target,
        "findings": findings,
        "grouped_findings": grouped,
        "severity_order": _SEVERITY_ORDER,
        "counts": counts,
        "total_findings": len(findings),
        "assets": assets,
        "asset_count": len(assets),
        "secrets": secrets,
        "attack": build_attack_path(findings),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def generate_reports(
    session_factory: sessionmaker[Session],
    target_id: int,
    output_dir: Path,
    formats: list[str],
) -> list[Path]:
    """Render the requested report formats and record them in the ``reports`` table."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    env = _env()
    written: list[Path] = []

    session = session_factory()
    try:
        ctx = _collect(session, target_id)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

        for fmt in formats:
            fmt = fmt.lower().strip()
            if fmt == "html":
                template = env.get_template("report.html.j2")
                out = output_dir / f"report-{target_id}-{stamp}.html"
            elif fmt == "xml":
                template = env.get_template("report.xml.j2")
                out = output_dir / f"report-{target_id}-{stamp}.xml"
            else:
                continue
            out.write_text(template.render(**ctx), encoding="utf-8")
            written.append(out)
            session.add(Report(target_id=target_id, format=fmt, path=str(out.resolve())))

        session.commit()
    finally:
        session.close()

    return written
