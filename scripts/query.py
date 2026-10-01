#!/usr/bin/env python3
"""Run a read-only SQL query against the ReconToReport store and print a table.

Uses Python's built-in sqlite3 (no external `sqlite3` binary needed). The DB
path is resolved from the project config's database.url.

Usage:
    python scripts/query.py --config config.yaml "SELECT title, severity FROM findings"
    python scripts/query.py --config config.yaml --tables
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

# Make the package importable when run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recontoreport.config import Config  # noqa: E402


def _db_path(config_path: str) -> str:
    url = Config.load(config_path).database_url
    if not url.startswith("sqlite:///"):
        print(f"query.py only supports sqlite:/// URLs (got: {url})", file=sys.stderr)
        sys.exit(2)
    return url.replace("sqlite:///", "", 1)


def _print_table(rows: list[sqlite3.Row]) -> None:
    if not rows:
        print("(no rows)")
        return
    cols = rows[0].keys()
    widths = {c: len(c) for c in cols}
    for r in rows:
        for c in cols:
            widths[c] = max(widths[c], len(str(r[c])))
    header = "  ".join(c.ljust(widths[c]) for c in cols)
    print(header)
    print("  ".join("-" * widths[c] for c in cols))
    for r in rows:
        print("  ".join(str(r[c]).ljust(widths[c]) for c in cols))
    print(f"\n{len(rows)} row(s)")


def main() -> None:
    ap = argparse.ArgumentParser(description="Query the ReconToReport store.")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--tables", action="store_true", help="List tables and exit.")
    ap.add_argument("sql", nargs="?", help="SQL query to run.")
    args = ap.parse_args()

    db = _db_path(args.config)
    if not Path(db).is_file():
        print(f"Database not found: {db} (run `make db` first)", file=sys.stderr)
        sys.exit(2)

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        if args.tables:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            _print_table(rows)
            return
        if not args.sql:
            ap.error("provide a SQL query, or use --tables")
        rows = conn.execute(args.sql).fetchall()
        _print_table(rows)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
