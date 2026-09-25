"""SQLAlchemy models: neighbors, policies + ordered rules, snapshots, runs."""
from __future__ import annotations

import datetime as dt
from typing import List

from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, Integer, String, Text,
    UniqueConstraint, create_engine, select,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session,
)

from .config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Neighbor(Base):
    __tablename__ = "neighbors"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    ip: Mapped[str] = mapped_column(String(64))
    family: Mapped[int] = mapped_column(Integer, default=4)
    asn: Mapped[int] = mapped_column(Integer, nullable=True)
    inbound_policy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    outbound_policy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    family: Mapped[int] = mapped_column(Integer, default=4)       # 4 or 6
    default_action: Mapped[str] = mapped_column(String(8), default="deny")
    description: Mapped[str] = mapped_column(String(256), default="")
    draft: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow)

    rules: Mapped[List["Rule"]] = relationship(
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="Rule.seq",
    )
    snapshots: Mapped[List["Snapshot"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan",
        order_by="Snapshot.version.desc()",
    )


class Rule(Base):
    __tablename__ = "rules"
    __table_args__ = (UniqueConstraint("policy_id", "seq", name="uq_policy_seq"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    prefix: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(8))                  # permit/deny
    ge: Mapped[int | None] = mapped_column(Integer, nullable=True)
    le: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remark: Mapped[str] = mapped_column(String(256), default="")

    policy: Mapped[Policy] = relationship(back_populates="rules")


# Snapshot lifecycle states for the auditable release pipeline.
#
#   draft              freshly captured, never validated
#   validating         validation in progress (transient, synchronous API)
#   validation_failed  validation failed OR an earlier approval was
#                      invalidated by a later rule/neighbor/default edit
#   pending_approval   validation passed, awaiting approval
#   approved           approval frozen (rule order, neighbors, default
#                      action, semantic diff, probe results, FRR evidence)
#   simulated_published  applied to the local isolated FRR node (active)
#   superseded         replaced by a later active release / rolled back
#
# Snapshots themselves are immutable (payload + frr_config never change);
# only lifecycle metadata transitions.  Every edit to the working policy
# captures a NEW draft snapshot — old versions are never rewritten.
SNAPSHOT_STATES = (
    "draft", "validating", "validation_failed", "pending_approval",
    "approved", "simulated_published", "superseded",
)

# Release records are append-only audit rows; only ONE row per
# (policy, node) may be status='applying' and only ONE 'active'.
RELEASE_STATES = ("applying", "active", "failed", "superseded")


class Snapshot(Base):
    """
    Immutable configuration snapshot.  payload is the exact, replayable
    policy body: ordered rules + default action + family, plus FRR-rendered
    config and metadata.  Replays never depend on later edits.

    Lifecycle columns (release pipeline) are kept separate from payload so
    the frozen configuration can never be mutated after capture.
    """
    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    label: Mapped[str] = mapped_column(String(128), default="")
    payload: Mapped[dict] = mapped_column(JSON)
    frr_config: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="lab")

    # ---- release pipeline lifecycle ----
    status: Mapped[str] = mapped_column(String(24), default="draft")
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    validation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    approval: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    invalidated_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)

    policy: Mapped[Policy] = relationship(back_populates="snapshots")
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)


class Release(Base):
    """
    One simulated-publish attempt against a local isolated FRR node.

    Append-only: rollbacks create NEW rows (kind='rollback') pointing at the
    historical snapshot restored; the previous release is marked
    'superseded' but never rewritten.  Compensating action on apply failure
    is recorded so DB and container state stay reconcilable.
    """
    __tablename__ = "releases"

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"))
    node: Mapped[str] = mapped_column(String(16), default="a")
    kind: Mapped[str] = mapped_column(String(16), default="publish")  # publish/rollback
    status: Mapped[str] = mapped_column(String(16), default="applying")
    # snapshot that was live before this record (target of compensation /
    # the version restored when the apply fails)
    baseline_release_id: Mapped[int | None] = mapped_column(
        ForeignKey("releases.id"), nullable=True)
    # for kind='rollback': the earlier release being rolled back from
    rolled_back_release_id: Mapped[int | None] = mapped_column(
        ForeignKey("releases.id"), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    applied_config: Mapped[str | None] = mapped_column(Text, nullable=True)
    # append-only per-attempt outcome log (start/success/failure/compensate)
    events: Mapped[list] = mapped_column(JSON, default=list)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="lab")

    # Partial unique indexes enforcing "one applying / one active release
    # per (policy, node)" are created in DDL (migrations.py) because the
    # WHERE-clause syntax differs between SQLite and PostgreSQL.


class IdempotencyKey(Base):
    """Stored Idempotency-Key -> response, so retried mutating calls replay."""
    __tablename__ = "idempotency_keys"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    scope: Mapped[str] = mapped_column(String(64), default="default")
    request_hash: Mapped[str] = mapped_column(String(64))
    method_path: Mapped[str] = mapped_column(String(256), default="")
    response: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Scenario(Base):
    """Saved replay bundle: from/to snapshots, probe inputs, observed results."""
    __tablename__ = "scenarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    from_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    to_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    probes: Mapped[list] = mapped_column(JSON, default=list)   # ordered prefix list
    results: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Run(Base):
    """One cross-validation run against a local FRR container."""
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    node: Mapped[str] = mapped_column(String(16), default="a")      # router-a/b
    status: Mapped[str] = mapped_column(String(16), default="ok")   # ok/mismatch/error
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


def init_db() -> None:
    from .migrations import run_migrations
    run_migrations()


def get_session() -> Session:
    return SessionLocal()
