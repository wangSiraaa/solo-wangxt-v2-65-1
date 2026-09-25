"""SQLAlchemy models: neighbors, policies + ordered rules, snapshots, runs."""
from __future__ import annotations

import datetime as dt
from typing import List

from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint, create_engine, select, text,
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


class Snapshot(Base):
    """
    Immutable configuration snapshot.  payload is the exact, replayable
    policy body: ordered rules + default action + family, plus FRR-rendered
    config and metadata.  Replays never depend on later edits.
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

    policy: Mapped[Policy] = relationship(back_populates="snapshots")
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)


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


class Release(Base):
    """
    A reviewable release record carrying one IMMUTABLE snapshot through the
    draft -> validating -> (validation_failed | pending_approval |
    approved -> simulated_published) -> superseded state machine.

    Evidence captured at validation time and frozen again at approval is
    stored as JSON blobs; a release never mutates historical rows.  Editing
    a policy's rules/neighbors invalidates every open release of that policy
    (state -> superseded, reason invalidated_by_edit); a rollback never
    overwrites this row, it creates a NEW release of kind='rollback'.
    """
    __tablename__ = "releases"

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"))
    kind: Mapped[str] = mapped_column(String(16), default="release")  # release|rollback
    state: Mapped[str] = mapped_column(String(32), default="draft")
    version_label: Mapped[str] = mapped_column(String(128), default="")
    created_by: Mapped[str] = mapped_column(String(64), default="lab")
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # frozen validation evidence (set when pending_approval is reached)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    # approval packet: a re-freeze of evidence hashes/content at approve time
    approval: Mapped[dict] = mapped_column(JSON, default=dict)
    # last failure detail (validation_failed / publish error) - retryable
    last_error: Mapped[dict] = mapped_column(JSON, default=dict)

    # simulated publish bookkeeping
    published_nodes: Mapped[list] = mapped_column(JSON, default=list)
    published_config: Mapped[str] = mapped_column(Text, default="")
    published_config_checksum: Mapped[str] = mapped_column(String(64), default="")

    # rollback provenance: the release this rollback reverts
    rollback_of_id: Mapped[int | None] = mapped_column(
        ForeignKey("releases.id"), nullable=True)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow)

    policy: Mapped[Policy] = relationship(foreign_keys=[policy_id])
    snapshot: Mapped[Snapshot] = relationship(foreign_keys=[snapshot_id])
    rollback_of: Mapped["Release | None"] = relationship(
        remote_side=[id], foreign_keys=[rollback_of_id])

    # NOTE: deliberately NO unique constraint on (policy_id, snapshot_id):
    # a rollback creates a brand-new release record that points at a
    # historical snapshot already used by an older release, without
    # rewriting that older release.  The only uniqueness invariant is the
    # partial index on the single active release per policy (see migration).
    __table_args__ = (
        Index("ix_release_policy_snapshot", "policy_id", "snapshot_id"),
    )


class ReleaseEvent(Base):
    """Append-only audit trail for a release record."""
    __tablename__ = "release_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    release_id: Mapped[int] = mapped_column(
        ForeignKey("releases.id", ondelete="CASCADE"))
    at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(64), default="lab")
    event: Mapped[str] = mapped_column(String(48))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_session() -> Session:
    return SessionLocal()
