"""reviewable release pipeline: releases, release_events

Revision ID: 0002_releases
Revises: 0001_baseline
Create Date: 2026-09-25

Adds the auditable release state machine:

    draft -> validating -> validation_failed
                         -> pending_approval -> approved
                                             -> simulated_published
                                             -> superseded
and an append-only event log.  A partial unique index guarantees that at
most one simulated_published release exists per policy even under
concurrent/duplicate publish requests (idempotency enforced by the database,
not just the application).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_releases"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "releases",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("snapshot_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False,
                  server_default="release"),
        sa.Column("state", sa.String(length=32), nullable=False,
                  server_default="draft"),
        sa.Column("version_label", sa.String(length=128), nullable=False,
                  server_default=""),
        sa.Column("created_by", sa.String(length=64), nullable=False,
                  server_default="lab"),
        sa.Column("approved_by", sa.String(length=64), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("approval", sa.JSON(), nullable=True),
        sa.Column("last_error", sa.JSON(), nullable=True),
        sa.Column("published_nodes", sa.JSON(), nullable=True),
        sa.Column("published_config", sa.Text(), nullable=False,
                  server_default=""),
        sa.Column("published_config_checksum", sa.String(length=64),
                  nullable=False, server_default=""),
        sa.Column("rollback_of_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["snapshots.id"]),
        sa.ForeignKeyConstraint(["rollback_of_id"], ["releases.id"]),
        # no unique(policy_id, snapshot_id): rollbacks legitimately create a
        # new release row reusing an old snapshot.
    )
    op.create_index("ix_release_policy_snapshot", "releases",
                    ["policy_id", "snapshot_id"])
    op.create_index("ix_releases_policy_id", "releases", ["policy_id"])
    op.create_index("ix_releases_snapshot_id", "releases", ["snapshot_id"])
    op.create_index("ix_releases_state", "releases", ["state"])

    op.create_table(
        "release_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("release_id", sa.Integer(), nullable=False),
        sa.Column("at", sa.DateTime(), nullable=True),
        sa.Column("actor", sa.String(length=64), nullable=False,
                  server_default="lab"),
        sa.Column("event", sa.String(length=48), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["release_id"], ["releases.id"],
                                ondelete="CASCADE"),
    )
    op.create_index("ix_release_events_release_id", "release_events",
                    ["release_id"])

    # at most one ACTIVE (simulated_published) release per policy.
    # SQLite >= 3.8 and PostgreSQL both support partial indexes with WHERE.
    bind = op.get_bind()
    bind.exec_driver_sql(
        "CREATE UNIQUE INDEX uq_release_active_per_policy "
        "ON releases (policy_id) WHERE state = 'simulated_published'"
    )


def downgrade() -> None:
    op.drop_index("uq_release_active_per_policy", table_name="releases")
    op.drop_table("release_events")
    op.drop_table("releases")
