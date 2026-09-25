"""
Auditable release pipeline for policy snapshots.

States (per snapshot):
    draft -> validating -> validation_failed / pending_approval
          -> approved -> simulated_published -> superseded

Rules enforced here:

* Snapshots are immutable configuration. Any later rule / default-action /
  neighbor edit INVALIDATES open approvals (-> validation_failed); the next
  edit is published as a brand-new draft version.
* Approval FREEZES a bundle: rule order (ordered seq list + content hash),
  bound neighbors, default action, semantic diff vs. current baseline,
  probe results and FRR cross-validation evidence.
* Simulated publish writes ONLY to the local isolated FRR node. The apply
  is verified (post-install show + probe re-check) BEFORE the DB switches
  the active pointer. A failed apply is compensated (baseline restored) and
  the release stays 'failed' and retryable — DB/container cannot diverge.
* Rollback appends a NEW release record (kind='rollback'); old records are
  never rewritten.
* Partial unique indexes (one applying / one active release per
  policy+node) make duplicate and concurrent publishes collapse to a single
  effective version.
"""
from __future__ import annotations

import hashlib
import json
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import db as dbmod
from .config import RLAB_REQUIRE_FRR
from .engine import Policy as EnginePolicy
from .frr_bridge import FRRBridge, FRRUnavailable, get_bridge
from .service import engine_policy_from_snapshot
from .validate import cross_validate


class WorkflowError(Exception):
    """Illegal state transition / bad workflow input (-> HTTP 409)."""


# --------------------------------------------------------------------------
# Hashing & frozen content
# --------------------------------------------------------------------------

def _canonical_payload(snap: dbmod.Snapshot) -> dict:
    p = snap.payload
    return {
        "name": p["name"],
        "family": p["family"],
        "default_action": p["default_action"],
        # ordered by seq — rule ORDER is part of the frozen semantics
        "rules": sorted(
            ({"seq": r["seq"], "prefix": r["prefix"], "action": r["action"],
              "ge": r.get("ge"), "le": r.get("le")}
             for r in p["rules"]),
            key=lambda r: r["seq"]),
    }


def content_hash(snap: dbmod.Snapshot) -> str:
    blob = json.dumps(_canonical_payload(snap),
                      sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def _require_state(snap: dbmod.Snapshot, allowed: tuple[str, ...]) -> None:
    if snap.status not in allowed:
        raise WorkflowError(
            f"snapshot v{snap.version} is {snap.status!r}; allowed states "
            f"for this action: {', '.join(allowed)}")


def _set_state(snap: dbmod.Snapshot, state: str, reason: Optional[str] = None) -> None:
    snap.status = state
    if reason is not None:
        snap.invalidated_reason = reason


def _add_event(rel: dbmod.Release, kind: str, detail: Optional[dict] = None) -> None:
    events = list(rel.events or [])
    events.append({"at": dbmod.utcnow().isoformat(), "kind": kind,
                   "detail": detail or {}})
    rel.events = events


# --------------------------------------------------------------------------
# Neighbors / semantic diff / automatic witness probes
# --------------------------------------------------------------------------

def _frozen_neighbors(session: Session, policy_name: str) -> list[dict]:
    ns = session.query(dbmod.Neighbor).order_by(
        dbmod.Neighbor.name).all()
    return [
        {"id": n.id, "name": n.name, "ip": n.ip, "family": n.family,
         "asn": n.asn, "inbound_policy": n.inbound_policy,
         "outbound_policy": n.outbound_policy,
         "bound": bool(n.inbound_policy == policy_name
                       or n.outbound_policy == policy_name)}
        for n in ns
    ]


def _active_release(session: Session, policy_id: int,
                    node: str) -> Optional[dbmod.Release]:
    return session.scalar(
        select(dbmod.Release)
        .where(dbmod.Release.policy_id == policy_id,
               dbmod.Release.node == node,
               dbmod.Release.status == "active"))


def _baseline_snapshot(session: Session, policy_id: int,
                       node: str) -> Optional[dbmod.Snapshot]:
    rel = _active_release(session, policy_id, node)
    return session.get(dbmod.Snapshot, rel.snapshot_id) if rel else None


def _semantic_diff(session: Session, old: Optional[dbmod.Snapshot],
                   new: dbmod.Snapshot) -> Optional[dict]:
    if old is None:
        return None
    oldp, newp = engine_policy_from_snapshot(old), engine_policy_from_snapshot(new)
    witnesses = [w.to_dict() for w in oldp.witness_diff(newp)]
    return {
        "baseline_snapshot_id": old.id,
        "baseline_version": old.version,
        "witness_count": len(witnesses),
        "witnesses": witnesses,
        "newly_permitted": [w for w in witnesses if w["change"] == "deny->permit"],
        "newly_denied": [w for w in witnesses if w["change"] == "permit->deny"],
        "old_default": oldp.default_action.value,
        "new_default": newp.default_action.value,
    }


def default_probes(session: Session, snap: dbmod.Snapshot) -> List[str]:
    """
    Deterministic witness probes: semantic-diff witnesses vs. current
    baseline (behavior regions actually changing), plus an outside prefix
    that exercises the implicit default action. Ordered, de-duplicated.
    """
    ep = engine_policy_from_snapshot(snap)
    probes: List[str] = []
    baseline = _baseline_snapshot(session, snap.policy_id, "a")
    if baseline is not None:
        diff = _semantic_diff(session, baseline, snap)
        probes.extend(w["prefix"] for w in diff["witnesses"])
    # every rule base is a witness of its own exact-length behavior
    probes.extend(r.prefix for r in ep.rules)
    outsider = "0.0.0.0/0" if ep.family == 4 else "::/0"
    probes.append(outsider)
    return list(dict.fromkeys(probes))


# --------------------------------------------------------------------------
# Validation (draft -> pending_approval | validation_failed)
# --------------------------------------------------------------------------

def validate_snapshot(session: Session, snapshot_id: int,
                      probes: Optional[List[str]] = None,
                      node: str = "a",
                      bridge: Optional[FRRBridge] = None) -> dict:
    snap = session.get(dbmod.Snapshot, snapshot_id)
    if snap is None:
        raise WorkflowError("snapshot not found")
    # 'validating' is included so an interrupted validation (process crash
    # while the transient marker was committed) can be re-driven instead of
    # getting stuck forever.
    _require_state(snap, ("draft", "validation_failed", "pending_approval",
                          "validating"))

    ep = engine_policy_from_snapshot(snap)
    if not ep.rules:
        _set_state(snap, "validating")
        _fail_validation(session, snap, probes or [], node,
                         setup_error="snapshot has zero rules")
        raise WorkflowError("snapshot has zero rules; cannot validate")

    if probes is None:
        probes = default_probes(session, snap)
    if not probes:
        raise WorkflowError("validation needs at least one probe")

    # transient marker; the terminal state is committed in the same flow so
    # a snapshot can never be left stuck in 'validating'
    _set_state(snap, "validating")
    session.commit()

    diff = _semantic_diff(session, _baseline_snapshot(session, snap.policy_id, node),
                          snap)
    neighbors = _frozen_neighbors(session, snap.payload["name"])

    owns = bridge is None
    if bridge is None:
        bridge = get_bridge(node=node, timeout=40.0)
    frr_error = None
    try:
        bridge.connect()
        cv = cross_validate(ep, probes, node=node, bridge=bridge,
                            remove_after=True)
    except (FRRUnavailable, WorkflowError) as e:
        frr_error = str(e)
        cv = None
    finally:
        if owns:
            try:
                bridge.close()
            except Exception:
                pass

    if cv is None:
        if RLAB_REQUIRE_FRR:
            _fail_validation(
                session, snap, probes, node,
                setup_error=f"FRR cross-validation unavailable: {frr_error}")
            raise WorkflowError(
                f"FRR node {node!r} unavailable: {frr_error}")
        cv = {"status": "skipped", "rows": [], "mismatches": [],
              "mismatch_count": 0, "setup_error": None,
              "note": "FRR unavailable and RLAB_REQUIRE_FRR=0"}

    evidence = {
        "validated_at": dbmod.utcnow().isoformat(),
        "node": node,
        "probes": probes,
        "content_hash": content_hash(snap),
        "rule_order": [r["seq"] for r in _canonical_payload(snap)["rules"]],
        "neighbors": neighbors,
        "default_action": ep.default_action.value,
        "semantic_diff": diff,
        "frr": {
            "status": cv["status"],
            "mismatch_count": cv.get("mismatch_count", 0),
            "mismatches": cv.get("mismatches", []),
            "rows": cv.get("rows", []),
            "setup_error": cv.get("setup_error"),
        },
    }
    snap.validation = evidence
    ok = cv["status"] == "match" or cv["status"] == "skipped"
    if ok and not cv.get("setup_error"):
        _set_state(snap, "pending_approval")
        snap.invalidated_reason = None
    else:
        _set_state(snap, "validation_failed",
                   reason=cv.get("setup_error")
                          or f"{cv.get('mismatch_count', 0)} FRR mismatch(es)")
    session.commit()
    return snapshot_evidence_dict(snap)


def _fail_validation(session: Session, snap: dbmod.Snapshot,
                     probes: List[str], node: str,
                     setup_error: str) -> None:
    snap.validation = {
        "validated_at": dbmod.utcnow().isoformat(),
        "node": node, "probes": probes,
        "content_hash": content_hash(snap),
        "rule_order": [r["seq"] for r in _canonical_payload(snap)["rules"]],
        "neighbors": _frozen_neighbors(session, snap.payload["name"]),
        "default_action": snap.payload["default_action"],
        "frr": {"status": "error", "setup_error": setup_error,
                "rows": [], "mismatches": []},
    }
    _set_state(snap, "validation_failed", reason=setup_error)
    session.commit()


# --------------------------------------------------------------------------
# Approval (pending_approval -> approved), freezes the evidence bundle
# --------------------------------------------------------------------------

def approve_snapshot(session: Session, snapshot_id: int,
                     approver: str = "reviewer",
                     comment: str = "") -> dict:
    snap = session.get(dbmod.Snapshot, snapshot_id)
    if snap is None:
        raise WorkflowError("snapshot not found")
    _require_state(snap, ("pending_approval",))
    if not snap.validation:
        raise WorkflowError("no validation evidence on snapshot")

    h = content_hash(snap)
    if snap.validation.get("content_hash") != h:
        raise WorkflowError("snapshot content drifted after validation")

    bundle = {
        "approved_at": dbmod.utcnow().isoformat(),
        "approver": approver,
        "comment": comment,
        # frozen evidence — copied from validation, never recomputed later
        "frozen_rule_order": snap.validation["rule_order"],
        "frozen_content_hash": h,
        "frozen_rules": _canonical_payload(snap)["rules"],
        "frozen_neighbors": snap.validation["neighbors"],
        "frozen_default_action": snap.validation["default_action"],
        "frozen_semantic_diff": snap.validation["semantic_diff"],
        "frozen_probe_results": snap.validation["frr"]["rows"],
        "frozen_probes": snap.validation["probes"],
        "frozen_frr_evidence": snap.validation["frr"],
        "frozen_frr_config": snap.frr_config,
        "frozen_node": snap.validation["node"],
    }
    snap.approval = bundle
    _set_state(snap, "approved")
    snap.invalidated_reason = None
    session.commit()
    return snapshot_evidence_dict(snap)


# --------------------------------------------------------------------------
# Invalidation: later rule / default / neighbor edits
# --------------------------------------------------------------------------

def invalidate_open_versions(session: Session, policy: dbmod.Policy,
                             reason: str) -> int:
    """
    Rule/default edits invalidate drafts that had passed validation but were
    never published. Released/superseded versions are HISTORY and stay
    untouched (they remain replayable; a new edit is captured as a new
    draft).
    """
    snaps = session.query(dbmod.Snapshot).filter_by(policy_id=policy.id).all()
    n = 0
    for snap in snaps:
        if snap.status in ("pending_approval", "approved"):
            _set_state(snap, "validation_failed", reason=reason)
            n += 1
    session.commit()
    return n


# --------------------------------------------------------------------------
# Simulated publish
# --------------------------------------------------------------------------

def _verify_installed(show_output: str, ep: EnginePolicy) -> Optional[str]:
    if not ep.rules:
        return "snapshot has zero rules"
    for r in ep.rules:
        if f"seq {r.seq} {r.action.value}" not in show_output:
            return f"post-install verification failed: missing seq {r.seq}"
    return None


def _do_apply(session: Session, rel: dbmod.Release,
              bridge: Optional[FRRBridge]) -> None:
    """
    Apply release.snapshot to the isolated FRR node, verify, then in ONE
    local transaction switch the active pointer. On ANY failure: restore
    the baseline config on the device and leave the row 'failed' (retryable).
    """
    snap = session.get(dbmod.Snapshot, rel.snapshot_id)
    ep = engine_policy_from_snapshot(snap)
    probes = (snap.approval or {}).get("frozen_probes") or \
             (snap.validation or {}).get("probes") or []

    baseline = session.get(dbmod.Release, rel.baseline_release_id) \
        if rel.baseline_release_id else None
    baseline_snap = session.get(dbmod.Snapshot, baseline.snapshot_id) \
        if baseline else None

    owns = bridge is None
    if bridge is None:
        bridge = get_bridge(node=rel.node)
    try:
        bridge.connect()
    except FRRUnavailable as e:
        _mark_failed(session, rel, f"container unreachable: {e}")
        if owns:
            bridge.close()
        raise WorkflowError(str(e))

    try:
        show = bridge.apply_policy(ep)
        verify_err = _verify_installed(show, ep)
        if verify_err:
            raise FRRUnavailable(verify_err)
        # independent re-observation of the frozen probes against the
        # ACTUAL installed config (do not reinstall; it's already there).
        # A default-PERMIT policy cannot be expressed by an FRR prefix-list
        # (implicit deny), so only probes that terminate on a REAL rule are
        # compared post-apply; default-terminating probes are covered by the
        # structural show verification above.
        rule_probes = [p for p in probes
                       if ep.classify(p).rule is not None]
        post = cross_validate(ep, rule_probes, node=rel.node, bridge=bridge,
                              install=False, remove_after=False) \
            if rule_probes else {"status": "match", "mismatch_count": 0,
                                 "mismatches": [], "rows": [], "setup_error": None}
        if post["status"] not in ("match",) or post.get("setup_error"):
            raise FRRUnavailable(
                post.get("setup_error")
                or f"post-install probe mismatch: {post['mismatch_count']}")
    except Exception as e:
        # ---- compensation: restore the previous active version ----
        comp_ok, comp_err = True, None
        try:
            if baseline_snap is not None:
                bridge.apply_policy(engine_policy_from_snapshot(baseline_snap))
            else:
                bridge.remove_policy(ep.name, ep.family)
        except Exception as ce:
            comp_ok, comp_err = False, str(ce)
        if owns:
            try:
                bridge.close()
            except Exception:
                pass
        _mark_failed(session, rel, f"apply failed: {e}",
                     compensation_ok=comp_ok, compensation_error=comp_err)
        raise WorkflowError(str(e))

    rel.applied_config = snap.frr_config
    rel.detail = {**(rel.detail or {}),
                  "post_apply_check": {"status": post["status"],
                                       "mismatch_count": post.get("mismatch_count", 0),
                                       "probes": probes}}
    _add_event(rel, "applied", {"snapshot": snap.version})

    # ---- atomic state switch (only after the device is verified) ----
    prev_active = _active_release(session, rel.policy_id, rel.node)
    if prev_active is not None and prev_active.id != rel.id:
        prev_active.status = "superseded"
        prev_snap = session.get(dbmod.Snapshot, prev_active.snapshot_id)
        if prev_snap is not None:
            _set_state(prev_snap, "superseded")
        _add_event(rel, "superseded_release", {"release_id": prev_active.id})

    # other simulated_published snapshots of this policy become superseded
    for other in session.query(dbmod.Snapshot).filter_by(
            policy_id=rel.policy_id).all():
        if other.id != snap.id and other.status == "simulated_published":
            _set_state(other, "superseded")

    rel.status = "active"
    _set_state(snap, "simulated_published")
    _add_event(rel, "active")
    if owns:
        try:
            bridge.close()
        except Exception:
            pass
    try:
        session.commit()
    except IntegrityError:
        # The device already holds OUR config, but the DB switch lost the
        # race with a concurrent release. Reconcile the device back to the
        # version that won the DB, then mark this row failed/retryable so
        # database and container cannot stay diverged.
        session.rollback()
        winner = _active_release(session, rel.policy_id, rel.node)
        comp_ok, comp_err = True, None
        if winner is not None and winner.snapshot_id != snap.id:
            try:
                win_snap = session.get(dbmod.Snapshot, winner.snapshot_id)
                bridge.apply_policy(engine_policy_from_snapshot(win_snap))
            except Exception as ce:
                comp_ok, comp_err = False, str(ce)
        _mark_failed(session, session.get(dbmod.Release, rel.id),
                     "DB state switch lost the race with release "
                     f"{winner.id if winner else '?'}",
                     compensation_ok=comp_ok, compensation_error=comp_err)
        raise WorkflowError(
            "container applied but DB commit lost the race; device "
            "reconciled to the winning version, this release is retryable")


def _mark_failed(session: Session, rel: dbmod.Release, error: str,
                 compensation_ok: bool = True,
                 compensation_error: Optional[str] = None) -> None:
    """
    Persist failure WITHOUT rolling the row away: it stays 'failed' and
    retryable. Container compensation was already attempted by the caller,
    so DB (failed row) and device (baseline restored) stay consistent.
    """
    rel.status = "failed"
    rel.detail = {**(rel.detail or {}), "last_error": error,
                  "compensation_ok": compensation_ok,
                  "compensation_error": compensation_error}
    _add_event(rel, "failed",
               {"error": error, "compensation_ok": compensation_ok,
                "compensation_error": compensation_error})
    session.commit()


def publish_snapshot(session: Session, snapshot_id: int,
                     node: str = "a", created_by: str = "lab",
                     idempotency_key: Optional[str] = None,
                     bridge: Optional[FRRBridge] = None) -> dbmod.Release:
    snap = session.get(dbmod.Snapshot, snapshot_id)
    if snap is None:
        raise WorkflowError("snapshot not found")
    _require_state(snap, ("approved", "simulated_published"))

    # idempotent replay of a completed publish
    if idempotency_key:
        existing = session.scalar(select(dbmod.Release).where(
            dbmod.Release.idempotency_key == idempotency_key))
        if existing is not None:
            return existing

    # already active -> duplicate publish collapses to the same version
    active = _active_release(session, snap.policy_id, node)
    if active is not None and active.snapshot_id == snap.id:
        return active

    baseline = active
    if baseline is not None and baseline.snapshot_id != snap.id:
        # only a NEWER snapshot may replace the active one; an older
        # approval cannot be re-published over a newer live version
        b_snap = session.get(dbmod.Snapshot, baseline.snapshot_id)
        if b_snap is not None and b_snap.version > snap.version:
            raise WorkflowError(
                f"snapshot v{snap.version} is older than active "
                f"v{b_snap.version}; refusing older publish")

    rel = dbmod.Release(
        policy_id=snap.policy_id, snapshot_id=snap.id, node=node,
        kind="publish", status="applying",
        baseline_release_id=baseline.id if baseline else None,
        idempotency_key=idempotency_key, attempts=1,
        created_by=created_by, events=[])
    _add_event(rel, "applying")
    session.add(rel)
    try:
        session.commit()
    except IntegrityError:
        # another concurrent publish holds the single 'applying' slot
        session.rollback()
        inflight = session.scalar(select(dbmod.Release).where(
            dbmod.Release.policy_id == snap.policy_id,
            dbmod.Release.node == node,
            dbmod.Release.status.in_(["applying", "active"])))
        raise WorkflowError(
            "another publish for this policy/node is in flight "
            f"(release {inflight.id if inflight else '?'})")

    _do_apply(session, rel, bridge)
    return session.get(dbmod.Release, rel.id)


def retry_release(session: Session, release_id: int,
                  bridge: Optional[FRRBridge] = None) -> dbmod.Release:
    rel = session.get(dbmod.Release, release_id)
    if rel is None:
        raise WorkflowError("release not found")
    if rel.status != "failed":
        raise WorkflowError(
            f"release {release_id} is {rel.status!r}; only failed releases retry")
    rel.status = "applying"
    rel.attempts = (rel.attempts or 1) + 1
    _add_event(rel, "retrying", {"attempt": rel.attempts})
    session.commit()
    _do_apply(session, rel, bridge)
    return session.get(dbmod.Release, rel.id)


# --------------------------------------------------------------------------
# Rollback (append-only)
# --------------------------------------------------------------------------

def rollback(session: Session, target_snapshot_id: int, node: str = "a",
             created_by: str = "lab", idempotency_key: Optional[str] = None,
             bridge: Optional[FRRBridge] = None) -> dbmod.Release:
    target = session.get(dbmod.Snapshot, target_snapshot_id)
    if target is None:
        raise WorkflowError("snapshot not found")
    if idempotency_key:
        existing = session.scalar(select(dbmod.Release).where(
            dbmod.Release.idempotency_key == idempotency_key))
        if existing is not None:
            return existing

    active = _active_release(session, target.policy_id, node)
    if active is None:
        raise WorkflowError("no active release to roll back from")
    if active.snapshot_id == target.id:
        raise WorkflowError("target snapshot is already active")

    # only a snapshot that was successfully published before can be restored
    prior = session.scalar(select(dbmod.Release).where(
        dbmod.Release.snapshot_id == target.id,
        dbmod.Release.node == node,
        dbmod.Release.kind.in_(["publish", "rollback"])))
    if prior is None:
        raise WorkflowError(
            f"snapshot v{target.version} was never published; cannot roll back")

    rel = dbmod.Release(
        policy_id=target.policy_id, snapshot_id=target.id, node=node,
        kind="rollback", status="applying",
        baseline_release_id=active.id,           # restore this if apply fails
        rolled_back_release_id=active.id,
        idempotency_key=idempotency_key, attempts=1,
        created_by=created_by, events=[])
    _add_event(rel, "applying", {"rollback_to": target.version,
                                 "from_release": active.id})
    session.add(rel)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise WorkflowError("another release for this policy/node is in flight")

    _do_apply(session, rel, bridge)
    return session.get(dbmod.Release, rel.id)


# --------------------------------------------------------------------------
# Drift check: does the container still hold the active config?
# --------------------------------------------------------------------------

def check_drift(session: Session, policy_id: int, node: str = "a",
                bridge: Optional[FRRBridge] = None) -> dict:
    active = _active_release(session, policy_id, node)
    if active is None:
        return {"policy_id": policy_id, "node": node, "active": False,
                "drift": False, "detail": "no active release"}
    snap = session.get(dbmod.Snapshot, active.snapshot_id)
    ep = engine_policy_from_snapshot(snap)
    owns = bridge is None
    if bridge is None:
        bridge = get_bridge(node=node)
    try:
        bridge.connect()
        show = bridge.show_prefix_list(ep.name, ep.family)
    except FRRUnavailable as e:
        return {"policy_id": policy_id, "node": node, "active": True,
                "drift": None, "error": str(e),
                "active_snapshot_id": snap.id}
    finally:
        if owns:
            try:
                bridge.close()
            except Exception:
                pass
    missing = [f"seq {r.seq} {r.action.value}"
               for r in ep.rules
               if f"seq {r.seq} {r.action.value}" not in show]
    return {
        "policy_id": policy_id, "node": node, "active": True,
        "active_snapshot_id": snap.id, "active_version": snap.version,
        "drift": bool(missing), "missing_entries": missing,
        "device_show": show,
    }


# --------------------------------------------------------------------------
# Serialization
# --------------------------------------------------------------------------

def release_dict(rel: dbmod.Release,
                 snap: Optional[dbmod.Snapshot] = None,
                 session: Optional[Session] = None) -> dict:
    if snap is None and session is not None:
        snap = session.get(dbmod.Snapshot, rel.snapshot_id)
    return {
        "id": rel.id,
        "policy_id": rel.policy_id,
        "snapshot_id": rel.snapshot_id,
        "snapshot_version": getattr(snap, "version", None),
        "snapshot_label": getattr(snap, "label", None),
        "node": rel.node,
        "kind": rel.kind,
        "status": rel.status,
        "baseline_release_id": rel.baseline_release_id,
        "rolled_back_release_id": rel.rolled_back_release_id,
        "idempotency_key": rel.idempotency_key,
        "attempts": rel.attempts,
        "applied_config": rel.applied_config,
        "events": rel.events or [],
        "detail": rel.detail or {},
        "created_by": rel.created_by,
        "created_at": rel.created_at.isoformat() if rel.created_at else None,
        "updated_at": rel.updated_at.isoformat() if rel.updated_at else None,
    }


def snapshot_evidence_dict(snap: dbmod.Snapshot) -> dict:
    return {
        "id": snap.id, "policy_id": snap.policy_id, "version": snap.version,
        "label": snap.label, "status": snap.status,
        "content_hash": content_hash(snap),
        "validation": snap.validation,
        "approval": snap.approval,
        "invalidated_reason": snap.invalidated_reason,
        "created_at": snap.created_at.isoformat() if snap.created_at else None,
    }
