"""baseline: neighbors, policies, rules, snapshots, scenarios, runs

Revision ID: 0001_baseline
Revises:
Create Date: 2026-09-25

Baseline of the schema as it existed before the reviewable-release pipeline.
Written by hand (the project shipped with Base.metadata.create_all, so this
revision exists to give every database a reproducible starting point and an
alembic_version row).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    op.create_table(
        "neighbors",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=False),
        sa.Column("family", sa.Integer(), nullable=False),
        sa.Column("asn", sa.Integer(), nullable=True),
        sa.Column("inbound_policy", sa.String(length=128), nullable=True),
        sa.Column("outbound_policy", sa.String(length=128), nullable=True),
        sa.Column("description", sa.String(length=256), nullable=False,
                  server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("name", name="uq_neighbors_name"),
    )
    op.create_table(
        "policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("family", sa.Integer(), nullable=False),
        sa.Column("default_action", sa.String(length=8), nullable=False),
        sa.Column("description", sa.String(length=256), nullable=False,
                  server_default=""),
        sa.Column("draft", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("name", name="uq_policies_name"),
    )
    op.create_table(
        "rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("prefix", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=8), nullable=False),
        sa.Column("ge", sa.Integer(), nullable=True),
        sa.Column("le", sa.Integer(), nullable=True),
        sa.Column("remark", sa.String(length=256), nullable=False,
                  server_default=""),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"],
                                ondelete="CASCADE"),
        sa.UniqueConstraint("policy_id", "seq", name="uq_policy_seq"),
    )
    op.create_table(
        "snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=False,
                  server_default=""),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("frr_config", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=False,
                  server_default="lab"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"],
                                ondelete="CASCADE"),
        sa.UniqueConstraint("policy_id", "version", name="uq_policy_version"),
    )
    op.create_table(
        "scenarios",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=512), nullable=False,
                  server_default=""),
        sa.Column("from_snapshot_id", sa.Integer(), nullable=True),
        sa.Column("to_snapshot_id", sa.Integer(), nullable=True),
        sa.Column("probes", sa.JSON(), nullable=True),
        sa.Column("results", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["from_snapshot_id"], ["snapshots.id"]),
        sa.ForeignKeyConstraint(["to_snapshot_id"], ["snapshots.id"]),
        sa.UniqueConstraint("name", name="uq_scenarios_name"),
    )
    op.create_table(
        "runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), nullable=True),
        sa.Column("node", sa.String(length=16), nullable=False,
                  server_default="a"),
        sa.Column("status", sa.String(length=16), nullable=False,
                  server_default="ok"),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["snapshot_id"], ["snapshots.id"]),
    )
    # indexes SQLAlchemy emits implicitly on existing SQLite dev DBs
    op.create_index("ix_rules_policy_id", "rules", ["policy_id"])
    op.create_index("ix_snapshots_policy_id", "snapshots", ["policy_id"])


def downgrade() -> None:
    op.drop_table("runs")
    op.drop_table("scenarios")
    op.drop_table("snapshots")
    op.drop_table("rules")
    op.drop_table("policies")
    op.drop_table("neighbors")
