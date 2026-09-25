"""
Tiny versioned schema migration runner (no Alembic dependency).

Both the zero-setup SQLite path and the PostgreSQL compose stack run the
same migrations.  A fresh database is stamped at the latest revision after
``Base.metadata.create_all``; an existing one is upgraded one revision at a
time inside a transaction.

Migrations MUST stay idempotent on the column-set they add so that a fresh
``create_all`` (which already has the new columns) stamping at head never
runs them.
"""
from __future__ import annotations

from sqlalchemy import text

from . import db as dbmod

SCHEMA_REVISION = 1


def _table_exists(conn, name: str) -> bool:
    eng = conn.engine
    if eng.dialect.name == "sqlite":
        row = conn.execute(text(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=:n"),
            {"n": name}).first()
    else:
        row = conn.execute(text(
            "SELECT 1 FROM information_schema.tables WHERE table_name=:n"),
            {"n": name}).first()
    return row is not None


def _column_exists(conn, table: str, column: str) -> bool:
    eng = conn.engine
    if eng.dialect.name == "sqlite":
        rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
        return any(r[1] == column for r in rows)
    row = conn.execute(text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name=:t AND column_name=:c"),
        {"t": table, "c": column}).first()
    return row is not None


def _add_column(conn, table: str, column: str, ddl_type: str) -> None:
    if not _column_exists(conn, table, column):
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}"))


def _partial_unique_indexes(conn) -> None:
    """
    Concurrency invariants for the release pipeline:

    * at most one status='applying' release per (policy, node)
    * at most one status='active'   release per (policy, node)

    Expressed as partial unique indexes (WHERE predicates) on both dialects.
    These are what make "duplicate or concurrent publishes -> only one
    version takes effect" hold even under racing transactions.
    """
    is_sqlite = conn.engine.dialect.name == "sqlite"
    qual = '"' if is_sqlite else ""
    bool_lit = "1" if is_sqlite else "TRUE"
    for name, status in (("ux_releases_applying", "applying"),
                         ("ux_releases_active", "active")):
        where = f"{qual}status{qual} = '{status}'"
        conn.execute(text(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {name} ON releases "
            f"(policy_id, node) WHERE {where}"))
    # idempotency table: key is globally unique
    if not is_sqlite:
        # nothing extra needed (primary key on key)
        pass
    _ = bool_lit  # reserved for future boolean-style predicates


def upgrade_1(conn) -> None:
    """Release pipeline: snapshot lifecycle + releases + idempotency keys."""
    for col, typ in (
        ("status", "VARCHAR(24) DEFAULT 'draft'"),
        ("content_hash", "VARCHAR(64)"),
        ("validation", "JSON"),
        ("approval", "JSON"),
        ("invalidated_reason", "VARCHAR(256)"),
    ):
        _add_column(conn, "snapshots", col, typ)
    conn.execute(text(
        "UPDATE snapshots SET status='draft' WHERE status IS NULL"))

    if not _table_exists(conn, "releases"):
        ts = "DATETIME" if is_sqlite else "TIMESTAMP"
        conn.execute(text(f"""
            CREATE TABLE releases (
                id INTEGER PRIMARY KEY,
                policy_id INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
                snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
                node VARCHAR(16) DEFAULT 'a',
                kind VARCHAR(16) DEFAULT 'publish',
                status VARCHAR(16) DEFAULT 'applying',
                baseline_release_id INTEGER REFERENCES releases(id),
                rolled_back_release_id INTEGER REFERENCES releases(id),
                idempotency_key VARCHAR(128),
                attempts INTEGER DEFAULT 1,
                applied_config TEXT,
                events JSON,
                detail JSON,
                created_at {ts},
                updated_at {ts},
                created_by VARCHAR(64) DEFAULT 'lab'
            )"""))

    if not _table_exists(conn, "idempotency_keys"):
        ts = "DATETIME" if is_sqlite else "TIMESTAMP"
        conn.execute(text(f"""
            CREATE TABLE idempotency_keys (
                key VARCHAR(128) PRIMARY KEY,
                scope VARCHAR(64) DEFAULT 'default',
                request_hash VARCHAR(64) NOT NULL,
                method_path VARCHAR(256) DEFAULT '',
                response JSON,
                created_at {ts}
            )"""))
    _partial_unique_indexes(conn)


REVISIONS = {1: upgrade_1}


def run_migrations() -> int:
    """Create missing tables then apply pending revisions; return revision."""
    eng = dbmod.engine
    with eng.begin() as conn:
        had_rev_table = _table_exists(conn, "schema_revisions")
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS schema_revisions ("
            "  id INTEGER PRIMARY KEY, "
            "  applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)"))
        row = conn.execute(text(
            "SELECT COALESCE(MAX(id), 0) FROM schema_revisions")).first()
        current = row[0] if row else 0

        if not had_rev_table and current == 0:
            # Unmanaged database predating the migration system.
            if _table_exists(conn, "policies"):
                # Legacy schema exists: upgrade it revision by revision.
                for rev in range(1, SCHEMA_REVISION + 1):
                    REVISIONS[rev](conn)
                    conn.execute(text(
                        "INSERT INTO schema_revisions (id) VALUES (:r)"),
                        {"r": rev})
                return SCHEMA_REVISION
            # Truly fresh database: create everything from the current
            # models and stamp at head without replaying additive steps.
            dbmod.Base.metadata.create_all(bind=conn)
            _partial_unique_indexes(conn)
            for rev in range(1, SCHEMA_REVISION + 1):
                conn.execute(text("INSERT INTO schema_revisions (id) VALUES (:r)"),
                             {"r": rev})
            return SCHEMA_REVISION

        for rev in range(current + 1, SCHEMA_REVISION + 1):
            REVISIONS[rev](conn)
            conn.execute(text("INSERT INTO schema_revisions (id) VALUES (:r)"),
                         {"r": rev})
        return SCHEMA_REVISION
