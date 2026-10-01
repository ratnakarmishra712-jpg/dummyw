"""Alembic migration environment.

Resolves the database URL in this order:
1. RECONTOREPORT_DB_URL environment variable
2. RECONTOREPORT_CONFIG env var -> that config.yaml's database.url
3. ./config.yaml database.url (if present)
4. the sqlalchemy.url in alembic.ini
"""

from __future__ import annotations

import os
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make the project package importable.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recontoreport.models import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _resolve_url() -> str:
    env_url = os.environ.get("RECONTOREPORT_DB_URL")
    if env_url:
        return env_url

    cfg_path = os.environ.get("RECONTOREPORT_CONFIG")
    candidate = Path(cfg_path) if cfg_path else Path("config.yaml")
    if candidate.is_file():
        try:
            from recontoreport.config import Config

            return Config.load(candidate).database_url
        except Exception:
            pass

    return config.get_main_option("sqlalchemy.url")


def run_migrations_offline() -> None:
    url = _resolve_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _resolve_url()
    connectable = engine_from_config(
        section, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # needed for SQLite ALTER support
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
