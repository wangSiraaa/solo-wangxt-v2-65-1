"""
Reviewable release pipeline for policy snapshots.

State machine (see README §release):

    draft
      └─ validate ─▶ validating ─┬─▶ pending_approval ─▶ approved
                                 │                        └─ publish ─▶ simulated_published
                                 └─▶ validation_failed        (then any newer
                                                              publish makes it
                                                              superseded)
    any non-terminal state ─▶ superseded when the policy is edited or a newer
                              release of the same policy is approved/published

Guarantees enforced here:

* A release points at an IMMUTABLE snapshot. Creating a draft mints a new
  snapshot from the current live policy; later edits never change it.
* Approval freezes a complete evidence packet: ordered rules + checksum,
  neighbor bindings, default action, semantic diff (minimal witnesses),
  probe results and per-node FRR cross-validation evidence.
* Any later edit to the policy invalidates open releases
  (invalidate_open_releases, called from the rules/meta write path).
* Simulated publish writes ONLY to the isolated FRR lab containers under a
  dedicated prefix-list name (rlabpub{policy_id}). It applies to every node
  before any DB state changes, restores the previous config on partial
  failure, and leaves the row retryable (state stays approved) on failure —
  database and container can never diverge silently.
* A partial unique index (migration 0002) plus a process lock make
  duplicate/concurrent publishes idempotent: exactly one version is active.
* Rollback never mutates history: it creates a NEW release (kind=rollback)
  from a historical snapshot and walks validate -> approve -> publish again.
"""
from __future__ import annotations

import hashlib
import ipaddress
import threading
from typing import Iterable, List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import db as dbmod
from .config import PUBLISH_NODES, PUBLISH_PLIST_PREFIX
from .engine import Action, PolicyError, policy_from_dicts
from .frr_bridge import FRRBridge, FRRUnavailable
from .service import (
    ValidationError, engine_policy_from_snapshot, snapshot_diff,
)
from .validate import cross_validate

# ---------------------------------------------------------------- states
DRAFT = "draft"
VALIDATING = "validating"
VALIDATION_FAILED = "validation_failed"
PENDING_APPROVAL = "pending_approval"
APPROVED = "approved"
SIMULATED_PUBLISHED = "simulated_published"
SUPERSEDED = "superseded"

OPEN_STATES = {DRAFT, VALIDATING, VALIDATION_FAILED, PENDING_APPROVAL, APPROVED}
STATE_LABELS = {
    DRAFT: "草稿",
    VALIDATING: "验证中",
    VALIDATION_FAILED: "验证失败",
    PENDING_APPROVAL: "待审批",
    APPROVED: "已批准",
    SIMULATED_PUBLISHED: "已模拟发布",
    SUPERSEDED: "已替代",
}

# serializes publish attempts per policy within this process (the partial
# unique index is the cross-process guarantee; the lock turns the race into
# one clean winner instead of surfacing an IntegrityError). Different
# policies publish concurrently.
_PUBLISH_LOCKS: dict = {}
_LOCKS_GUARD = threading.Lock()


def _publish_lock(policy_id: int) -> threading.RLock:
    with _LOCKS_GUARD:
        lk = _PUBLISH_LOCKS.get(policy_id)
        if lk is None:
            lk = threading.RLock()
            _PUBLISH_LOCKS[policy_id] = lk
        return lk


class ReleaseError(Exception):
    """Illegal state transition / stale release. Mapped to HTTP 409."""


# ------------------------------------------------------------- utilities
def policy_fingerprint(db_pol: dbmod.Policy) -> str:
    """Stable content hash: ordered rules + default action + family.

    Bound to the live (mutable) policy; a release is 'fresh' only while its
    snapshot hash equals the policy's current hash.
    """
    payload = {
        "family": db_pol.family,
        "default_action": db_pol.default_action,
        "rules": [
            [r.seq, r.prefix, r.action, r.ge, r.le]
            for r in sorted(db_pol.rules, key=lambda r: r.seq)
        ],
    }
    return hashlib.sha256(repr(payload).encode()).hexdigest()


def snapshot_fingerprint(snap: dbmod.Snapshot) -> str:
    p = snap.payload
    payload = {
        "family": p["family"],
        "default_action": p["default_action"],
        "rules": [
            [r["seq"], r["prefix"], r["action"], r.get("ge"), r.get("le")]
            for r in sorted(p["rules"], key=lambda r: r["seq"])
        ],
    }
    return hashlib.sha256(repr(payload).encode()).hexdigest()


def publish_plist_name(policy_id: int) -> str:
    return f"{PUBLISH_PLIST_PREFIX}{policy_id}"


def _add_event(s: Session, release: dbmod.Release, event: str,
               actor: str = "lab", detail: Optional[dict] = None) -> None:
    s.add(dbmod.ReleaseEvent(
        release_id=release.id, actor=actor, event=event, detail=detail or {}))


def _neighbors_frozen(s: Session) -> list:
    ns = s.query(dbmod.Neighbor).order_by(dbmod.Neighbor.name).all()
    return [
        {"id": n.id, "name": n.name, "ip": n.ip, "family": n.family,
         "asn": n.asn, "inbound_policy": n.inbound_policy,
         "outbound_policy": n.outbound_policy, "description": n.description}
        for n in ns
    ]


def default_probes(policy, witnesses: Iterable[dict]) -> List[str]:
    """Deterministic witness-bearing probe list for a snapshot policy.

    Bounded, exact (no sampling), and guaranteed to exercise:
      * every rule base at its base length,
      * one inside-window prefix per rule (ge/le boundary behavior),
      * the default-action region (root),
      * every semantic-diff witness from the baseline comparison.
    """
    probes: List[str] = []
    maxlen = 32 if policy.family == 4 else 128
    root = "0.0.0.0/0" if policy.family == 4 else "::/0"

    def add(pfx: str):
        try:
            net = ipaddress.ip_network(pfx, strict=True)
        except ValueError:
            return
        if net.version != policy.family:
            return
        if pfx not in probes:
            probes.append(pfx)

    for w in witnesses:
        add(w["prefix"])
    add(root)
    for r in policy.rules:
        add(str(r.net))
        # one prefix strictly inside the rule's window (when room exists)
        target = min(max(r.min_len + 1, r.net.prefixlen + 1), r.max_len)
        if target <= maxlen and target > r.net.prefixlen:
            shift = maxlen - target
            base = int(r.net.network_address)
            add(str(ipaddress.ip_network((((base >> shift) + 1) << shift, target))))
        # the le boundary itself
        if r.max_len > r.net.prefixlen:
            shift = maxlen - r.max_len
            add(str(ipaddress.ip_network(
                (int(r.net.network_address) + (1 << shift), r.max_len))))
    return probes[:200]


# ------------------------------------------------------------- invalidation
def _diff_against_empty(target) -> tuple:
    """Semantic diff of the first-ever release vs an implicit deny-all.

    Returns a payload with the same shape as service.snapshot_diff plus the
    witness list.  An empty v4/v6 policy with the same default action has no
    witnesses (nothing changes).
    """
    empty = policy_from_dicts(
        name="__empty_baseline__", rules=[],
        default_action=Action.DENY.value, family=target.family)
    witnesses = [w.to_dict() for w in empty.witness_diff(target)]
    return ({
        "old_snapshot_id": None,
        "new_snapshot_id": None,
        "baseline": "implicit_empty_default_deny",
        "witness_count": len(witnesses),
        "newly_permitted": [w for w in witnesses if w["change"] == "deny->permit"],
        "newly_denied": [w for w in witnesses if w["change"] == "permit->deny"],
        "witnesses": witnesses,
        "old_default": "deny",
        "new_default": target.default_action.value,
    }, witnesses)
def invalidate_open_releases(s: Session, policy_id: int,
                             reason: str = "invalidated_by_edit",
                             actor: str = "lab",
                             detail: Optional[dict] = None) -> int:
    """Mark every non-terminal release of a policy as 已替代 (superseded).

    Called when rules / default action / neighbors change: an approval (or
    pending validation, or even an open draft) that froze the old content can
    never silently carry over to edited content — any follow-up work mints a
    brand-new draft instead.
    Returns the number of releases invalidated.
    """
    rows = s.query(dbmod.Release).filter_by(policy_id=policy_id).all()
    n = 0
    for rel in rows:
        if rel.state in OPEN_STATES:
            rel.state = SUPERSEDED
            _add_event(s, rel, "superseded", actor,
                       {"reason": reason, **(detail or {})})
            n += 1
    s.commit()
    return n


# ------------------------------------------------------------- draft
def create_draft(s: Session, db_pol: dbmod.Policy, *,
                 created_by: str = "lab", label: str = "",
                 snapshot: Optional[dbmod.Snapshot] = None,
                 kind: str = "release",
                 rollback_of_id: Optional[int] = None) -> dbmod.Release:
    """Mint a snapshot from the CURRENT policy and wrap it in a draft release.

    Idempotent for open drafts of identical content: the existing draft is
    returned instead of creating a second one.
    """
    from .service import create_snapshot

    if snapshot is None:
        snapshot = create_snapshot(
            s, db_pol,
            label=label or f"release-candidate", created_by=created_by)

    fingerprint = snapshot_fingerprint(snapshot)

    # idempotency: reuse an open draft/validation_failed row of the SAME
    # policy+content (duplicate POST with no intervening edit must not fan
    # out rows), even though each draft mints its own snapshot.
    existing = s.query(dbmod.Release).filter_by(
        policy_id=db_pol.id, kind=kind).order_by(dbmod.Release.id.desc()).first()
    if existing and existing.state in (DRAFT, VALIDATION_FAILED) and \
            snapshot_fingerprint(existing.snapshot) == fingerprint and \
            existing.rollback_of_id == rollback_of_id:
        _add_event(s, existing, "draft_reused", created_by)
        s.commit()
        s.refresh(existing)
        return existing

    rel = dbmod.Release(
        policy_id=db_pol.id, snapshot_id=snapshot.id, kind=kind,
        state=DRAFT,
        version_label=label or f"r{snapshot.version}",
        created_by=created_by,
        rollback_of_id=rollback_of_id,
    )
    s.add(rel)
    s.flush()
    _add_event(s, rel, "created", created_by,
               {"snapshot_id": snapshot.id, "fingerprint": fingerprint,
                "kind": kind})
    s.commit()
    s.refresh(rel)
    return rel


# ------------------------------------------------------------- validation
def validate_release(s: Session, release_id: int, *,
                     probes: Optional[List[str]] = None,
                     nodes: Optional[List[str]] = None,
                     actor: str = "lab") -> dbmod.Release:
    rel = s.get(dbmod.Release, release_id)
    if rel is None:
        raise ValidationError("release not found")
    if rel.state not in (DRAFT, VALIDATION_FAILED):
        raise ReleaseError(
            f"release {release_id} is {rel.state}, only draft/validation_failed "
            "can be validated")

    snap = rel.snapshot
    db_pol = s.get(dbmod.Policy, rel.policy_id)
    fresh = snapshot_fingerprint(snap) == policy_fingerprint(db_pol)
    if rel.kind != "rollback" and not fresh:
        # policy was edited after this draft was minted: old draft is dead,
        # the editor must create a new draft
        rel.state = SUPERSEDED
        _add_event(s, rel, "superseded", actor, {"reason": "stale_at_validation"})
        s.commit()
        raise ReleaseError(
            "policy changed after this draft was created; create a new draft "
            "(rollbacks use POST /api/releases/{id}/rollback)")

    target = engine_policy_from_snapshot(snap)

    # ----- semantic evidence (computed before entering validating so a bad
    # request never strands a draft in validating) -----
    baseline_rel = _active_release(s, rel.policy_id, exclude_id=rel.id)
    baseline_snap = baseline_rel.snapshot if baseline_rel else _latest_other_snapshot(
        s, rel.policy_id, snap.id)
    if baseline_snap is not None:
        try:
            diff_ev = snapshot_diff(s, baseline_snap.id, snap.id)
            witnesses = diff_ev.get("witnesses", [])
        except (ValidationError, PolicyError):
            diff_ev, witnesses = None, []
    else:
        # first ever release: semantic diff against the implicit empty
        # policy baseline (default deny, no rules) — the change a reviewer
        # must approve when going from "nothing installed" to a first config.
        diff_ev, witnesses = _diff_against_empty(target)

    probe_list = list(probes) if probes else default_probes(target, witnesses)
    # parse-validate every probe up front (families must match the snapshot);
    # bad client input is a 422 and must NOT move the draft out of `draft`.
    for pfx in probe_list:
        net = ipaddress.ip_network(pfx, strict=True)
        if net.version != target.family:
            raise ValidationError(
                f"{pfx} is IPv{net.version}, snapshot is IPv{target.family}")

    rel.state = VALIDATING
    _add_event(s, rel, "validation_started", actor)
    s.commit()

    # ----- simulator probe results (ordered) -----
    sim_rows = []
    for i, pfx in enumerate(probe_list):
        hit = target.classify(pfx).to_dict()
        sim_rows.append({
            "order": i, "prefix": pfx,
            "action": hit["final_action"], "seq": hit["matched_seq"],
            "terminal": hit["terminal"],
        })

    # default-deny regression guard: an outsider probe must resolve deny
    # unless the snapshot explicitly defaults to permit
    default_regression = None
    outsider = "192.0.2.255/32" if target.family == 4 else "2001:db8:ffff::/64"
    outsider_hit = target.classify(outsider).to_dict()
    if target.default_action.value == "deny" and outsider_hit["final_action"] != "deny":
        default_regression = f"{outsider} not denied under default-deny"

    # ----- FRR cross-validation on every publish node -----
    nodes = nodes or PUBLISH_NODES
    frr_evidence = {}
    frr_failure = None
    for node in nodes:
        try:
            result = cross_validate(target, probe_list, node=node)
        except FRRUnavailable as e:
            frr_failure = {"node": node, "error": str(e), "kind": "unavailable"}
            break
        # persist a Run row like the standalone cross-validation endpoint
        run = dbmod.Run(
            snapshot_id=snap.id, node=node, status=result["status"],
            detail={"release_id": rel.id,
                    "mismatch_count": result["mismatch_count"],
                    "probes": probe_list,
                    "mismatches": result["mismatches"],
                    "setup_error": result.get("setup_error")})
        s.add(run)
        s.flush()
        frr_evidence[node] = {
            "run_id": run.id,
            "status": result["status"],
            "mismatch_count": result["mismatch_count"],
            "setup_error": result.get("setup_error"),
            "rows": result.get("rows", []),
        }
        if result["status"] != "match":
            frr_failure = {"node": node, "kind": result["status"],
                           "mismatch_count": result["mismatch_count"],
                           "setup_error": result.get("setup_error")}
            break

    evidence = {
        "snapshot_id": snap.id,
        "snapshot_version": snap.version,
        "fingerprint": snapshot_fingerprint(snap),
        "frozen_rules_ordered": snap.payload["rules"],
        "rules_checksum": snapshot_fingerprint(snap),
        "family": snap.payload["family"],
        "default_action": snap.payload["default_action"],
        "neighbors": _neighbors_frozen(s),
        "baseline_snapshot_id": baseline_snap.id if baseline_snap else None,
        "baseline_release_id": baseline_rel.id if baseline_rel else None,
        "semantic_diff": diff_ev,
        "probes": probe_list,
        "probe_results": sim_rows,
        "frr_nodes": frr_evidence,
        "default_deny_guard": {
            "outsider": outsider,
            "action": outsider_hit["final_action"],
            "violation": default_regression,
        },
    }

    if frr_failure or default_regression:
        rel.state = VALIDATION_FAILED
        rel.evidence = evidence
        rel.last_error = {"stage": "frr", **(frr_failure or {}),
                          "default_deny_violation": default_regression}
        _add_event(s, rel, "validation_failed", actor, rel.last_error)
        s.commit()
        s.refresh(rel)
        return rel

    rel.state = PENDING_APPROVAL
    rel.evidence = evidence
    rel.last_error = {}
    _add_event(s, rel, "validation_passed", actor,
               {"nodes": list(frr_evidence), "probe_count": len(probe_list),
                "witness_count": len(witnesses)})
    s.commit()
    s.refresh(rel)
    return rel


# ------------------------------------------------------------- approval
def approve_release(s: Session, release_id: int, *,
                    approved_by: str = "reviewer",
                    comment: str = "") -> dbmod.Release:
    rel = s.get(dbmod.Release, release_id)
    if rel is None:
        raise ValidationError("release not found")
    if rel.state == APPROVED:
        raise ReleaseError(f"release {release_id} already approved")
    if rel.state != PENDING_APPROVAL:
        raise ReleaseError(
            f"release {release_id} is {rel.state}, only pending_approval can be approved")

    snap = rel.snapshot
    db_pol = s.get(dbmod.Policy, rel.policy_id)
    if rel.kind != "rollback" and \
            snapshot_fingerprint(snap) != policy_fingerprint(db_pol):
        rel.state = SUPERSEDED
        _add_event(s, rel, "superseded", approved_by,
                   {"reason": "stale_at_approval"})
        s.commit()
        raise ReleaseError(
            "policy changed between validation and approval; approval refused. "
            "Validate a new draft.")

    rules_checksum = snapshot_fingerprint(snap)
    if not rel.evidence or rel.evidence.get("rules_checksum") != rules_checksum:
        raise ReleaseError("evidence packet missing or does not match snapshot")
    bad_nodes = {n: e["status"] for n, e in rel.evidence.get("frr_nodes", {}).items()
                 if e["status"] != "match"}
    if bad_nodes:
        raise ReleaseError(f"FRR evidence not all green: {bad_nodes}")

    packet = {
        "approved_by": approved_by,
        "comment": comment,
        "rules_checksum": rules_checksum,
        "neighbors_checksum": hashlib.sha256(
            repr(rel.evidence["neighbors"]).encode()).hexdigest(),
        "evidence_fingerprint": hashlib.sha256(
            repr(rel.evidence).encode()).hexdigest(),
        "frozen": {
            "rules": snap.payload["rules"],
            "default_action": snap.payload["default_action"],
            "family": snap.payload["family"],
            "neighbors": rel.evidence["neighbors"],
            "semantic_diff_witnesses":
                (rel.evidence.get("semantic_diff") or {}).get("witnesses", []),
            "probes": rel.evidence["probes"],
            "probe_results": rel.evidence["probe_results"],
            "frr_nodes": {
                n: {"run_id": e["run_id"], "status": e["status"],
                    "mismatch_count": e["mismatch_count"]}
                for n, e in rel.evidence["frr_nodes"].items()
            },
        },
    }
    rel.state = APPROVED
    rel.approved_by = approved_by
    rel.approval = packet
    # only one approval can be publishable at a time: every OTHER open
    # pending/approved release of this policy is superseded by this approval
    # (drafts / validation_failed stay usable as scratch candidates).
    others = s.query(dbmod.Release).filter(
        dbmod.Release.policy_id == rel.policy_id,
        dbmod.Release.id != rel.id,
        dbmod.Release.state.in_([PENDING_APPROVAL, APPROVED])
    ).all()
    for other in others:
        other.state = SUPERSEDED
        _add_event(s, other, "superseded", approved_by,
                   {"reason": "superseded_by_approval",
                    "by_release_id": rel.id})
    _add_event(s, rel, "approved", approved_by,
               {"comment": comment,
                "evidence_fingerprint": packet["evidence_fingerprint"]})
    s.commit()
    s.refresh(rel)
    return rel


# ------------------------------------------------------------- publish
def _active_release(s: Session, policy_id: int,
                    exclude_id: Optional[int] = None) -> Optional[dbmod.Release]:
    q = s.query(dbmod.Release).filter_by(
        policy_id=policy_id, state=SIMULATED_PUBLISHED)
    if exclude_id is not None:
        q = q.filter(dbmod.Release.id != exclude_id)
    return q.order_by(dbmod.Release.id.desc()).first()


def _latest_other_snapshot(s: Session, policy_id: int,
                           snapshot_id: int) -> Optional[dbmod.Snapshot]:
    return s.query(dbmod.Snapshot).filter(
        dbmod.Snapshot.policy_id == policy_id,
        dbmod.Snapshot.id != snapshot_id
    ).order_by(dbmod.Snapshot.version.desc()).first()


def _render_published_config(snap: dbmod.Snapshot) -> str:
    target = engine_policy_from_snapshot(snap)
    return target.to_frr_prefix_list(
        name=publish_plist_name(snap.policy_id))


def publish_release(s: Session, release_id: int, *,
                    nodes: Optional[List[str]] = None,
                    actor: str = "lab",
                    bridge_factory=FRRBridge) -> dbmod.Release:
    """
    Apply the snapshot to every isolated FRR node, verify, then commit DB.

    Ordering is deliberate so database/container state can never diverge:
      1. containers first (install new list under rlabpub{pid}),
      2. verify what FRR shows contains every rendered line,
      3. only then flip the DB row inside a transaction that also supersedes
         the previously active release;
      4. any failure before commit restores the previous active config on the
         nodes already touched and leaves this row `approved` + last_error,
         so the same request can be retried and a later retry can succeed.
    """
    rel0 = s.get(dbmod.Release, release_id)
    if rel0 is None:
        raise ValidationError("release not found")
    with _publish_lock(rel0.policy_id):
        rel = s.get(dbmod.Release, release_id)
        if rel is None:
            raise ValidationError("release not found")
        if rel.state == SIMULATED_PUBLISHED:
            return rel                                   # idempotent no-op
        if rel.state != APPROVED:
            raise ReleaseError(
                f"release {release_id} is {rel.state}, only approved releases "
                "can be published")
        # a newer approved revision may exist (concurrent workflow): only the
        # newest approved release can be promoted; older ones must not win.
        newer = s.query(dbmod.Release).filter(
            dbmod.Release.policy_id == rel.policy_id,
            dbmod.Release.id > rel.id,
            dbmod.Release.state == APPROVED).first()
        if newer is not None:
            raise ReleaseError(
                f"release {release_id} is not the newest approved revision "
                f"(release {newer.id} is newer)")

        snap = rel.snapshot
        target = engine_policy_from_snapshot(snap)
        plname = publish_plist_name(rel.policy_id)
        rendered = _render_published_config(snap)
        checksum = hashlib.sha256(rendered.encode()).hexdigest()
        nodes = nodes or PUBLISH_NODES

        active = _active_release(s, rel.policy_id)
        prev_config = active.published_config if active else ""
        prev_nodes = list(active.published_nodes) if active else []

        applied: List[str] = []
        error: Optional[dict] = None
        for node in nodes:
            try:
                br = bridge_factory(node=node).connect()
                try:
                    # replace atomically from the operator's point of view:
                    # delete old published list, install new, verify.
                    br.remove_named_policy(plname, target.family)
                    br.install_named_policy(
                        plname, target.family, rendered.splitlines())
                    shown = br.show_prefix_list(plname, target.family)
                    missing = [
                        f"seq {r.seq} {r.action.value}"
                        for r in target.rules
                        if f"seq {r.seq} {r.action.value}" not in shown]
                    if missing:
                        raise FRRUnavailable(
                            f"node {node}: post-install verification missing "
                            f"{missing}")
                finally:
                    br.close()
                applied.append(node)
            except FRRUnavailable as e:
                error = {"stage": "apply", "node": node, "error": str(e),
                         "applied_nodes": applied}
                break

        if error is not None:
            # restore previous config on nodes already mutated; best-effort,
            # recorded but never swallowed as success.
            restore = []
            for node in applied:
                try:
                    br = bridge_factory(node=node).connect()
                    try:
                        # restore the previous WINNING config back under the
                        # SAME published name (old and new versions share it
                        # per policy), so the device state matches the DB's
                        # still-active previous release.
                        br.remove_named_policy(plname, target.family)
                        if prev_config:
                            br.install_named_policy(
                                plname, target.family, prev_config.splitlines())
                    finally:
                        br.close()
                    restore.append(node)
                except FRRUnavailable as e2:
                    error.setdefault("restore_errors", {})[node] = str(e2)
            error["restored_nodes"] = restore
            error["previous_release_id"] = active.id if active else None
            # row stays APPROVED: DB claims nothing; retry is legal.
            rel.last_error = error
            _add_event(s, rel, "publish_failed", actor, error)
            s.commit()
            s.refresh(rel)
            return rel

        # ---- containers confirmed: commit the state flip ----
        try:
            rel.state = SIMULATED_PUBLISHED
            rel.published_nodes = nodes
            rel.published_config = rendered
            rel.published_config_checksum = checksum
            rel.last_error = {}
            if active is not None and active.id != rel.id:
                active.state = SUPERSEDED
                _add_event(s, active, "superseded", actor,
                           {"reason": "superseded_by_publish",
                            "by_release_id": rel.id})
            _add_event(s, rel, "simulated_published", actor,
                       {"nodes": nodes, "checksum": checksum,
                        "previous_release_id": active.id if active else None})
            s.commit()
        except IntegrityError:
            # concurrent publish won the partial-unique-index race
            s.rollback()
            winner = _active_release(s, rel.policy_id)
            if winner is not None:
                return winner
            raise

        s.refresh(rel)
        return rel


# ------------------------------------------------------------- rollback
def create_rollback(s: Session, source_release_id: int, *,
                    actor: str = "lab",
                    approved_by_target: Optional[str] = None) -> dbmod.Release:
    """
    Create a NEW release record from a historical (or any) release's
    snapshot. The old row is never modified; the new row is kind=rollback and
    bypasses the 'snapshot must equal live policy' freshness check so an
    older revision can be re-driven through validate -> approve -> publish.
    """
    source = s.get(dbmod.Release, source_release_id)
    if source is None:
        raise ValidationError("release not found")
    snap = source.snapshot
    db_pol = s.get(dbmod.Policy, source.policy_id)

    rel = dbmod.Release(
        policy_id=db_pol.id, snapshot_id=snap.id, kind="rollback",
        state=DRAFT,
        version_label=f"rollback-of-r{source.id}-s{snap.version}",
        created_by=actor,
        rollback_of_id=source.id,
    )
    s.add(rel)
    s.flush()
    _add_event(s, rel, "created", actor,
               {"kind": "rollback", "source_release_id": source.id,
                "snapshot_id": snap.id,
                "snapshot_version": snap.version,
                "snapshot_fingerprint": snapshot_fingerprint(snap)})
    s.commit()
    s.refresh(rel)
    return rel


# ------------------------------------------------------------- serialization
def release_dict(rel: dbmod.Release, include_events: bool = False,
                 s: Optional[Session] = None) -> dict:
    out = {
        "id": rel.id,
        "policy_id": rel.policy_id,
        "snapshot_id": rel.snapshot_id,
        "snapshot_version": rel.snapshot.version if rel.snapshot else None,
        "kind": rel.kind,
        "state": rel.state,
        "state_label": STATE_LABELS.get(rel.state, rel.state),
        "version_label": rel.version_label,
        "created_by": rel.created_by,
        "approved_by": rel.approved_by,
        "evidence": rel.evidence or {},
        "approval": rel.approval or {},
        "last_error": rel.last_error or {},
        "published_nodes": rel.published_nodes or [],
        "published_config": rel.published_config or "",
        "published_config_checksum": rel.published_config_checksum or "",
        "rollback_of_id": rel.rollback_of_id,
        "created_at": rel.created_at.isoformat() if rel.created_at else None,
        "updated_at": rel.updated_at.isoformat() if rel.updated_at else None,
    }
    if include_events:
        sess = s or dbmod.SessionLocal()
        try:
            events = sess.query(dbmod.ReleaseEvent).filter_by(
                release_id=rel.id).order_by(dbmod.ReleaseEvent.id).all()
            out["events"] = [
                {"id": e.id, "at": e.at.isoformat() if e.at else None,
                 "actor": e.actor, "event": e.event, "detail": e.detail or {}}
                for e in events]
        finally:
            if s is None:
                sess.close()
    return out
