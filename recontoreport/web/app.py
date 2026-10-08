"""Local Flask UI: drive the whole pipeline from a browser form.

Every setting (target, scope, phases, wordlist, nuclei tags, auth roles) is a
form field — no config files or terminal flags. Runs live on the user's machine
only; nothing is exposed externally.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, request, send_file

from ..attack import attack_for, attacker_story, build_attack_path
from ..navigator import coverage as atk_coverage, navigator_layer, next_moves
from ..scoring import grade as security_grade
from ..config import (
    AuthRole,
    Config,
    PhasePolicy,
    ProxyConfig,
    ScopeConfig,
    normalize_url,
)
from ..orchestrator import Orchestrator
from ..phases import resolve_phases

DATA_DIR = Path("r2r_ui_data")


@dataclass
class Run:
    id: str
    status: str = "running"          # running | done | error
    log: list[str] = field(default_factory=list)
    phases: list[dict] = field(default_factory=list)
    report_path: str | None = None
    error: str | None = None


RUNS: dict[str, Run] = {}


class _ListHandler(logging.Handler):
    def __init__(self, run: Run) -> None:
        super().__init__()
        self.run = run

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.run.log.append(self.format(record))
        except Exception:
            pass


def _build_config(form: dict) -> tuple[Config, list[int], bool]:
    url = normalize_url(form.get("url", ""))
    host = urlparse(url).hostname or ""

    include = [s.strip() for s in (form.get("scope_include") or "").splitlines() if s.strip()]
    if not include and host:
        include = [host, f"*.{host}"]
    exclude = [s.strip() for s in (form.get("scope_exclude") or "").splitlines() if s.strip()]

    tags = [t.strip() for t in (form.get("nuclei_tags") or "").split(",") if t.strip()]

    roles: list[AuthRole] = []
    for r in form.get("auth_roles") or []:
        # A role is usable if it has a cookie, or a login_url + username.
        if not (r.get("cookie") or (r.get("login_url") and r.get("username"))):
            continue
        roles.append(AuthRole(
            name=r.get("name") or "role",
            privilege_level=int(r.get("privilege_level") or 0),
            login_url=r.get("login_url", ""),
            username=r.get("username", ""),
            password=r.get("password", ""),
            username_selector=r.get("username_selector") or "input[name=username]",
            password_selector=r.get("password_selector") or "input[name=password]",
            submit_selector=r.get("submit_selector") or "button[type=submit]",
            success_selector=r.get("success_selector") or "",
            cookie=r.get("cookie", ""),
        ))

    run_id = form["_run_id"]
    base = DATA_DIR / run_id
    base.mkdir(parents=True, exist_ok=True)

    cfg = Config(
        target_url=url,
        engagement_ref=form.get("engagement_ref", ""),
        scope=ScopeConfig(include=include, exclude=exclude),
        database_url=f"sqlite:///{(base / 'scan.db').resolve()}",
        output_dir=base / "reports",
        output_formats=["html"],
        tools={},
        wordlists={"content_discovery": form.get("wordlist", "")},
        nuclei={"tags": tags, "templates_dir": form.get("nuclei_templates_dir", ""),
                "max_urls": int(form.get("nuclei_max_urls") or 100)},
        api_keys={},
        phase_policy=PhasePolicy(),
        proxy=ProxyConfig(capture_window_seconds=int(form.get("capture_window") or 30)),
        auth_roles=roles,
    )
    phases, _ = resolve_phases([int(p) for p in form.get("phases") or [1]])
    return cfg, phases, bool(form.get("authorized"))


def _run_scan(form: dict) -> None:
    run = RUNS[form["_run_id"]]
    handler = _ListHandler(run)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root = logging.getLogger("recontoreport")
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    try:
        cfg, phases, authorized = _build_config(form)
        run.log.append(f"Target: {cfg.target_url}  Phases: {phases}")
        orch = Orchestrator(cfg, authorized=authorized)
        results = orch.run(phases)
        run.phases = [{
            "number": r.number, "name": r.name,
            "result": "SKIPPED" if r.skipped else ("OK" if r.ok else "FAILED"),
            "assets": r.assets_created, "findings": r.findings_created,
            "errors": r.errors,
        } for r in results]
        # render report
        from ..report import generate_reports
        from sqlalchemy import select
        from ..models import Target
        from ..db import make_session_factory
        factory = make_session_factory(orch.engine)
        s = factory()
        t = s.execute(select(Target).where(Target.url == cfg.target_url)).scalar_one_or_none()
        s.close()
        if t:
            written = generate_reports(factory, t.id, cfg.output_dir, ["html"])
            if written:
                run.report_path = str(Path(written[0]).resolve())
        run.status = "done"
        run.log.append("Scan complete.")
    except Exception as exc:  # noqa: BLE001
        run.status = "error"
        run.error = f"{type(exc).__name__}: {exc}"
        run.log.append(f"ERROR: {run.error}")
    finally:
        root.removeHandler(handler)


def create_app() -> Flask:
    app = Flask(__name__)
    tpl = (Path(__file__).parent / "templates" / "index.html").read_text()

    @app.get("/")
    def index():  # noqa: ANN202
        return tpl

    @app.post("/scan")
    def scan():  # noqa: ANN202
        form = request.get_json(force=True)
        run_id = uuid.uuid4().hex[:12]
        form["_run_id"] = run_id
        RUNS[run_id] = Run(id=run_id)
        threading.Thread(target=_run_scan, args=(form,), daemon=True).start()
        return jsonify({"run_id": run_id})

    @app.get("/status/<run_id>")
    def status(run_id):  # noqa: ANN202
        run = RUNS.get(run_id)
        if not run:
            return jsonify({"error": "unknown run"}), 404
        return jsonify({
            "status": run.status, "log": run.log, "phases": run.phases,
            "has_report": bool(run.report_path), "error": run.error,
        })

    @app.post("/demo")
    def demo():  # noqa: ANN202
        """Start the bundled zero-install vulnerable target in a background thread."""
        global _DEMO_STARTED
        url = "http://127.0.0.1:8911/"
        if not globals().get("_DEMO_STARTED"):
            from .demo_target import start_demo
            try:
                url = start_demo()
                globals()["_DEMO_STARTED"] = True
            except OSError:
                pass  # already running on the port
        base = url.rstrip("/")
        return jsonify({"url": url, "roles": [
            {"name": "admin", "privilege_level": 10, "login_url": base + "/login",
             "username": "admin", "password": "admin",
             "username_selector": "input[name=username]", "password_selector": "input[name=password]",
             "submit_selector": "button[type=submit]"},
            {"name": "user", "privilege_level": 1, "login_url": base + "/login",
             "username": "user", "password": "user",
             "username_selector": "input[name=username]", "password_selector": "input[name=password]",
             "submit_selector": "button[type=submit]"},
        ]})

    @app.get("/report/<run_id>")
    def report(run_id):  # noqa: ANN202
        run = RUNS.get(run_id)
        if run and run.report_path:
            return send_file(run.report_path)
        return _serve_disk_report(run_id)

    @app.get("/runs")
    def runs():  # noqa: ANN202
        """List past runs from disk so history survives restarts."""
        import sqlite3
        out = []
        if DATA_DIR.is_dir():
            for d in sorted(DATA_DIR.iterdir(), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True):
                reps = sorted((d / "reports").glob("*.html")) if (d / "reports").is_dir() else []
                if not reps:
                    continue
                target = ""
                try:
                    con = sqlite3.connect(d / "scan.db")
                    row = con.execute("SELECT url FROM targets LIMIT 1").fetchone()
                    con.close()
                    target = row[0] if row else ""
                except Exception:
                    pass
                import datetime
                when = datetime.datetime.fromtimestamp(reps[-1].stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                out.append({"id": d.name, "target": target, "when": when})
        return jsonify(out[:50])

    @app.get("/findings/<run_id>")
    def findings(run_id):  # noqa: ANN202
        import sqlite3
        safe = "".join(c for c in run_id if c.isalnum() or c in "-_")
        db = DATA_DIR / safe / "scan.db"
        if not db.is_file():
            return jsonify({"findings": [], "counts": {}})
        con = sqlite3.connect(db); con.row_factory = sqlite3.Row
        try:
            rows = con.execute(
                "SELECT f.title,f.severity,f.cwe_id,f.owasp_category,f.tool_source,a.url "
                "FROM findings f LEFT JOIN assets a ON a.id=f.asset_id "
                "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
            ).fetchall()
            order = ["critical", "high", "medium", "low", "info"]
            counts = {s: 0 for s in order}
            out = []
            for r in rows:
                sev = r["severity"] or "info"
                counts[sev] = counts.get(sev, 0) + 1
                tid, tname, tactic = attack_for(r["cwe_id"], r["tool_source"])
                out.append({"title": r["title"], "severity": sev, "cwe": r["cwe_id"] or "",
                            "category": r["owasp_category"] or "", "source": r["tool_source"] or "",
                            "url": r["url"] or "", "attack": f"{tid} {tname}", "tactic": tactic})
            assets = con.execute("SELECT count(*) FROM assets").fetchone()[0]
            secrets = con.execute("SELECT count(*) FROM secret_matches").fetchone()[0]
        finally:
            con.close()
        plain = [{"cwe_id": f["cwe"], "tool_source": f["source"], "title": f["title"],
                  "severity": f["severity"]} for f in out]
        path = build_attack_path(plain)
        attack_path = {"reached": path["reached"], "narrative": path["narrative"],
                       "tactics": {t: len(v) for t, v in path["by_tactic"].items()}}
        return jsonify({"findings": out, "counts": counts, "assets": assets,
                        "secrets": secrets, "attack_path": attack_path,
                        "grade": security_grade(counts),
                        "story": attacker_story(plain)})

    def _run_findings(run_id):
        """(target_url, [findings]) for a run, read from its DB. [] if none."""
        import sqlite3
        safe = "".join(c for c in run_id if c.isalnum() or c in "-_")
        db = DATA_DIR / safe / "scan.db"
        if not db.is_file():
            return "", []
        con = sqlite3.connect(db); con.row_factory = sqlite3.Row
        try:
            target = con.execute("SELECT url FROM targets LIMIT 1").fetchone()
            rows = con.execute("SELECT title,severity,cwe_id,tool_source FROM findings").fetchall()
            fs = [{"title": r["title"], "severity": r["severity"], "cwe_id": r["cwe_id"],
                   "tool_source": r["tool_source"]} for r in rows]
        finally:
            con.close()
        return (target[0] if target else ""), fs

    @app.get("/attack/<run_id>")
    def attack(run_id):  # noqa: ANN202
        _, fs = _run_findings(run_id)
        return jsonify({
            "coverage": atk_coverage(fs),
            "next_moves": next_moves(fs),
            "has_findings": bool(fs),
        })

    @app.get("/navigator/<run_id>")
    def navigator(run_id):  # noqa: ANN202
        import json
        target, fs = _run_findings(run_id)
        layer = navigator_layer(fs, target)
        return Response(
            json.dumps(layer, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="r2r-navigator-{run_id}.json"'},
        )

    def _serve_disk_report(run_id):
        safe = "".join(c for c in run_id if c.isalnum() or c in "-_")
        reps = sorted((DATA_DIR / safe / "reports").glob("*.html")) if (DATA_DIR / safe / "reports").is_dir() else []
        if not reps:
            return "No report", 404
        return send_file(reps[-1].resolve())

    return app


def main(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> None:
    app = create_app()
    url = f"http://{host}:{port}/"
    if open_browser:
        import webbrowser
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    print(f"ReconToReport UI running at {url}  (Ctrl+C to stop)")
    app.run(host=host, port=port, debug=False)
