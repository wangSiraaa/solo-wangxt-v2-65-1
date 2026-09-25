"""
Database migration entry point.

Two starting states must both work:

1. Fresh database: every table is created through Alembic revisions
   (0001_baseline -> 0002_releases) and alembic_version stamped at head.
2. Legacy development database created by Base.metadata.create_all before
   migrations existed (tables present, no alembic_version): stamp at the
   baseline revision and apply later revisions idempotently.

`upgrade()` is called on API startup and from `app.seed`.  Run manually with

    python -m app.migrate
"""
from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from .config import DATABASE_URL
from .db import engine

_HERE = Path(__file__).resolve().parents[1]
_HEAD = "0002_releases"
_BASELINE = "0001_baseline"


def _alembic_config() -> Config:
    cfg = Config(str(_HERE / "migrations" / "alembic.ini"))
    cfg.set_main_option("script_location", str(_HERE / "migrations"))
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL)
    return cfg


def current_revision() -> str | None:
    from alembic.runtime.migration import MigrationContext
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def upgrade() -> str:
    """Bring the configured database up to head; return the head revision."""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    cfg = _alembic_config()

    if "alembic_version" not in tables:
        if {"policies", "snapshots", "runs"} & tables:
            # legacy create_all database: its shape is the 0001 baseline
            command.stamp(cfg, _BASELINE)
        # fresh or stamped legacy -> run remaining revisions (or all on fresh)
    command.upgrade(cfg, _HEAD)
    return _HEAD


if __name__ == "__main__":
    rev = upgrade()
    print(f"database at {rev} ({DATABASE_URL})")
