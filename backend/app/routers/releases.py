"""
Release pipeline HTTP API.

All transitions are explicit and idempotent where it matters:

  POST   /api/policies/{pid}/releases/draft        mint snapshot -> draft
  POST   /api/releases/{id}/validate               draft/failed -> validating -> ...
  POST   /api/releases/{id}/approve                pending -> approved
  POST   /api/releases/{id}/publish                approved -> simulated_published
  POST   /api/releases/{id}/rollback               historical snapshot -> NEW draft
  GET    /api/releases … /api/policies/{pid}/releases   history
  GET    /api/releases/{id}                        full packet incl. evidence
  GET    /api/releases/{id}/live-config            what the isolated FRR nodes run
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import db as dbmod, release as rl, service
from ..frr_bridge import FRRBridge, FRRUnavailable
from ..schemas import (
    ReleaseApproveIn, ReleaseDraftIn, ReleasePublishIn, ReleaseRollbackIn,
    ReleaseValidateIn,
)
from ..service import ValidationError

router = APIRouter(prefix="/api")


def get_db():
    s = dbmod.SessionLocal()
    try:
        yield s
    finally:
        s.close()


def _get_release(db: Session, rid: int) -> dbmod.Release:
    rel = db.get(dbmod.Release, rid)
    if rel is None:
        raise HTTPException(404, f"release {rid} not found")
    return rel


def _get_policy(db: Session, pid: int) -> dbmod.Policy:
    p = db.get(dbmod.Policy, pid)
    if p is None:
        raise HTTPException(404, f"policy {pid} not found")
    return p


# --------------------------------------------------------------- drafts
@router.post("/policies/{pid}/releases/draft", status_code=201)
def create_draft(pid: int, body: ReleaseDraftIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    try:
        rel = rl.create_draft(db, p, created_by=body.created_by,
                              label=body.label)
    except ValidationError as e:
        raise HTTPException(422, str(e))
    return rl.release_dict(rel, include_events=True, s=db)


@router.get("/policies/{pid}/releases")
def policy_releases(pid: int, db: Session = Depends(get_db)):
    _get_policy(db, pid)
    rows = db.query(dbmod.Release).filter_by(policy_id=pid) \
        .order_by(dbmod.Release.id.desc()).all()
    return [rl.release_dict(r) for r in rows]


@router.get("/policies/{pid}/releases/active")
def policy_active_release(pid: int, db: Session = Depends(get_db)):
    _get_policy(db, pid)
    rel = db.query(dbmod.Release).filter_by(
        policy_id=pid, state=rl.SIMULATED_PUBLISHED).first()
    if rel is None:
        return {"policy_id": pid, "active": None}
    return {"policy_id": pid, "active": rl.release_dict(rel)}


@router.get("/releases")
def list_releases(limit: int = 100, policy_id: Optional[int] = None,
                  state: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(dbmod.Release)
    if policy_id is not None:
        q = q.filter_by(policy_id=policy_id)
    if state:
        q = q.filter_by(state=state)
    rows = q.order_by(dbmod.Release.id.desc()).limit(min(limit, 500)).all()
    return [rl.release_dict(r) for r in rows]


@router.get("/releases/{rid}")
def get_release(rid: int, db: Session = Depends(get_db)):
    return rl.release_dict(_get_release(db, rid), include_events=True, s=db)


# --------------------------------------------------------------- transitions
@router.post("/releases/{rid}/validate")
def validate_release(rid: int, body: ReleaseValidateIn,
                     db: Session = Depends(get_db)):
    rel = _get_release(db, rid)
    try:
        rel = rl.validate_release(db, rid, probes=body.probes, nodes=body.nodes)
    except rl.ReleaseError as e:
        raise HTTPException(409, str(e))
    except ValidationError as e:
        raise HTTPException(422, str(e))
    return rl.release_dict(rel, include_events=True, s=db)


@router.post("/releases/{rid}/approve")
def approve_release(rid: int, body: ReleaseApproveIn,
                    db: Session = Depends(get_db)):
    _get_release(db, rid)
    try:
        rel = rl.approve_release(
            db, rid, approved_by=body.approved_by, comment=body.comment)
    except rl.ReleaseError as e:
        raise HTTPException(409, str(e))
    except ValidationError as e:
        raise HTTPException(422, str(e))
    return rl.release_dict(rel, include_events=True, s=db)


@router.post("/releases/{rid}/publish")
def publish_release(rid: int, body: ReleasePublishIn,
                    db: Session = Depends(get_db)):
    _get_release(db, rid)
    try:
        rel = rl.publish_release(db, rid, nodes=body.nodes)
    except rl.ReleaseError as e:
        raise HTTPException(409, str(e))
    except ValidationError as e:
        raise HTTPException(422, str(e))
    # container failure is a normal retryable outcome, reported as 200 with
    # state=approved + last_error, never as a 5xx that hides retryability.
    return rl.release_dict(rel, include_events=True, s=db)


@router.post("/releases/{rid}/rollback", status_code=201)
def rollback_release(rid: int, body: ReleaseRollbackIn,
                     db: Session = Depends(get_db)):
    _get_release(db, rid)
    try:
        rel = rl.create_rollback(db, rid, actor=body.actor)
    except ValidationError as e:
        raise HTTPException(404, str(e))
    return rl.release_dict(rel, include_events=True, s=db)


# --------------------------------------------------------------- live config
@router.get("/releases/{rid}/live-config")
def release_live_config(rid: int, db: Session = Depends(get_db)):
    """
    Read back the ACTUAL prefix-list currently installed in every isolated
    FRR node for this policy, alongside the release's rendered config and
    checksum — the audit "what is really in the container right now".
    """
    rel = _get_release(db, rid)
    plname = rl.publish_plist_name(rel.policy_id)
    fam = rel.snapshot.payload["family"]
    nodes = {}
    for node in (rel.published_nodes or ["a", "b"]):
        entry = {"reachable": False, "shown": None, "matches_release": None}
        try:
            br = FRRBridge(node=node).connect()
            try:
                shown = br.show_prefix_list(plname, fam)
            finally:
                br.close()
            entry["reachable"] = True
            entry["shown"] = shown
            target = service.engine_policy_from_snapshot(rel.snapshot)
            entry["matches_release"] = all(
                f"seq {r.seq} {r.action.value}" in shown
                for r in target.rules)
        except FRRUnavailable as e:
            entry["error"] = str(e)
        nodes[node] = entry
    return {
        "release_id": rel.id,
        "state": rel.state,
        "plist_name": plname,
        "expected_config": rel.published_config,
        "checksum": rel.published_config_checksum,
        "nodes": nodes,
    }
