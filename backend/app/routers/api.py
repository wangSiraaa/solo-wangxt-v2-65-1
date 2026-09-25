"""HTTP API."""
from __future__ import annotations

import hashlib
import ipaddress

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import db as dbmod, service, workflow
from ..engine import PolicyError
from ..schemas import (
    ApproveIn, ClassifyIn, DiffIn, NeighborIn, PolicyIn, PolicyRulesIn,
    ProbesIn, PublishIn, RollbackIn, ScenarioIn, SnapshotIn, ValidateIn,
)
from ..service import ValidationError
from ..treeview import policy_trie, hit_path, coverage_map
from ..validate import cross_validate_snapshot
from ..frr_bridge import FRRBridge, FRRUnavailable

router = APIRouter(prefix="/api")


def get_db():
    s = dbmod.SessionLocal()
    try:
        yield s
    finally:
        s.close()


def _get_policy(db: Session, pid: int) -> dbmod.Policy:
    p = db.get(dbmod.Policy, pid)
    if p is None:
        raise HTTPException(404, f"policy {pid} not found")
    return p


@router.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------- policies
@router.get("/policies")
def list_policies(db: Session = Depends(get_db)):
    ps = db.query(dbmod.Policy).order_by(dbmod.Policy.name).all()
    return [service.policy_payload(p) for p in ps]


@router.post("/policies", status_code=201)
def create_policy(body: PolicyIn, db: Session = Depends(get_db)):
    if db.query(dbmod.Policy).filter_by(name=body.name).first():
        raise HTTPException(409, f"policy {body.name!r} already exists")
    try:
        ipaddress.ip_network("0.0.0.0/0" if body.family == 4 else "::/0")
    except ValueError:
        raise HTTPException(422, "bad family")
    p = dbmod.Policy(
        name=body.name, family=body.family,
        default_action=body.default_action, description=body.description,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    return service.policy_payload(p)


@router.get("/policies/{pid}")
def get_policy(pid: int, db: Session = Depends(get_db)):
    return service.policy_payload(_get_policy(db, pid))


@router.put("/policies/{pid}")
def update_policy_meta(pid: int, body: PolicyIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    default_changed = p.default_action != body.default_action
    p.default_action = body.default_action
    p.description = body.description
    db.commit()
    db.refresh(p)
    if default_changed:
        workflow.invalidate_open_versions(
            db, p, reason="default action changed after validation/approval")
    return service.policy_payload(p)


@router.delete("/policies/{pid}", status_code=204)
def delete_policy(pid: int, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    db.delete(p)
    db.commit()


@router.put("/policies/{pid}/rules")
def set_rules(pid: int, body: PolicyRulesIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    if body.default_action is not None:
        p.default_action = body.default_action
    try:
        service.replace_rules(db, p, [r.model_dump() for r in body.rules])
    except (ValidationError, PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))
    db.refresh(p)
    return service.policy_payload(p)


@router.get("/policies/{pid}/analyze")
def analyze(pid: int, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    try:
        return service.analyze(db, p)
    except PolicyError as e:
        raise HTTPException(422, str(e))


@router.post("/policies/{pid}/classify")
def classify(pid: int, body: ClassifyIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    ep = service.engine_policy(p)
    try:
        return hit_path(ep, body.prefix)
    except (PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))


@router.post("/policies/{pid}/classify/batch")
def classify_batch(pid: int, body: ProbesIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    ep = service.engine_policy(p)
    out = []
    for i, pfx in enumerate(body.probes):
        try:
            d = ep.classify(pfx).to_dict()
            d["order"] = i
            out.append(d)
        except (PolicyError, ValueError) as e:
            out.append({"order": i, "prefix": pfx, "error": str(e)})
    return {"results": out}


@router.get("/policies/{pid}/trie")
def get_trie(pid: int, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    return policy_trie(service.engine_policy(p))


@router.get("/policies/{pid}/coverage")
def get_coverage(pid: int, depth: int = 8,
                 start: int = 0, count: int = 256,
                 db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    depth = max(0, min(depth, 12 if p.family == 4 else 40))
    count = max(1, min(count, 1024))
    return coverage_map(service.engine_policy(p), depth, (start, count))


# -------------------------------------------------------------- snapshots
@router.get("/policies/{pid}/snapshots")
def list_snapshots(pid: int, db: Session = Depends(get_db)):
    _get_policy(db, pid)
    snaps = db.query(dbmod.Snapshot).filter_by(policy_id=pid) \
        .order_by(dbmod.Snapshot.version.desc()).all()
    return [service.snapshot_dict(s) for s in snaps]


@router.post("/policies/{pid}/snapshots", status_code=201)
def take_snapshot(pid: int, body: SnapshotIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    snap = service.create_snapshot(db, p, label=body.label, created_by=body.created_by)
    return service.snapshot_dict(snap)


@router.get("/snapshots/{sid}")
def get_snapshot(sid: int, db: Session = Depends(get_db)):
    s = db.get(dbmod.Snapshot, sid)
    if s is None:
        raise HTTPException(404, "snapshot not found")
    return service.snapshot_dict(s)


@router.post("/snapshots/diff")
def diff_snapshots(body: DiffIn, db: Session = Depends(get_db)):
    try:
        return service.snapshot_diff(db, body.old_snapshot_id, body.new_snapshot_id)
    except (ValidationError, PolicyError) as e:
        raise HTTPException(422, str(e))


@router.post("/snapshots/{sid}/replay")
def replay(sid: int, body: ProbesIn, db: Session = Depends(get_db)):
    try:
        return service.replay(db, sid, body.probes)
    except ValidationError as e:
        raise HTTPException(404, str(e))
    except (PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))


# ----------------------------------------------------- FRR cross-validation
@router.get("/frr/status")
def frr_status():
    out = {}
    for node in ("a", "b"):
        try:
            ok = FRRBridge(node=node, timeout=4).ping()
        except Exception:
            ok = False
        out[node] = {"reachable": ok}
    return out


@router.post("/snapshots/{sid}/cross-validate")
def cross_validate(sid: int, body: ProbesIn, db: Session = Depends(get_db)):
    s = db.get(dbmod.Snapshot, sid)
    if s is None:
        raise HTTPException(404, "snapshot not found")
    try:
        return cross_validate_snapshot(db, sid, body.probes, node=body.node)
    except FRRUnavailable as e:
        raise HTTPException(503, str(e))
    except (PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))


@router.get("/runs")
def list_runs(limit: int = 50, db: Session = Depends(get_db)):
    runs = db.query(dbmod.Run).order_by(dbmod.Run.created_at.desc()).limit(limit).all()
    return [{
        "id": r.id, "snapshot_id": r.snapshot_id, "node": r.node,
        "status": r.status, "detail": r.detail,
        "created_at": r.created_at.isoformat(),
    } for r in runs]


# ------------------------------------------------- release: validate/approve
def _get_snapshot(db: Session, sid: int) -> dbmod.Snapshot:
    s = db.get(dbmod.Snapshot, sid)
    if s is None:
        raise HTTPException(404, "snapshot not found")
    return s


async def _idempotent(db: Session, request: Request, key: str | None,
                      scope: str, producer):
    """
    Idempotency-Key support for mutating release endpoints.

    * no key                              -> run normally
    * key seen, same request fingerprint  -> replay stored response
    * key seen, different fingerprint     -> 422 (do not rebind a key)
    * new key                             -> run once, persist the response
    """
    if not key:
        return producer()
    body = await request.body()
    fingerprint = hashlib.sha256(
        f"{scope}|{body.decode(errors='replace')}".encode()).hexdigest()
    row = db.get(dbmod.IdempotencyKey, key)
    if row is not None:
        if row.request_hash != fingerprint:
            raise HTTPException(422,
                                "Idempotency-Key reused with a different payload")
        return row.response
    result = producer()
    rec = dbmod.IdempotencyKey(
        key=key, scope=scope, request_hash=fingerprint,
        method_path=scope, response=result)
    db.add(rec)
    try:
        db.commit()
    except IntegrityError:
        # concurrent request with the same key won the insert; replay theirs
        db.rollback()
        winner = db.get(dbmod.IdempotencyKey, key)
        if winner is not None:
            if winner.request_hash != fingerprint:
                raise HTTPException(422,
                                    "Idempotency-Key reused with a different payload")
            return winner.response
        raise
    return result


@router.post("/snapshots/{sid}/validate")
def validate_snapshot(sid: int, body: ValidateIn,
                      db: Session = Depends(get_db)):
    s = _get_snapshot(db, sid)
    try:
        return workflow.validate_snapshot(
            db, sid, probes=body.probes, node=body.node)
    except workflow.WorkflowError as e:
        # state violations are 409; a failed FRR validation is still a
        # terminal validation_failed state -> 422 with evidence in body
        msg = str(e)
        snap = db.get(dbmod.Snapshot, sid)
        if snap is not None and snap.status == "validation_failed":
            raise HTTPException(422, msg)
        raise HTTPException(409, msg)


@router.post("/snapshots/{sid}/approve")
def approve_snapshot(sid: int, body: ApproveIn,
                     db: Session = Depends(get_db)):
    _get_snapshot(db, sid)
    try:
        return workflow.approve_snapshot(
            db, sid, approver=body.approver, comment=body.comment)
    except workflow.WorkflowError as e:
        raise HTTPException(409, str(e))


# ------------------------------------------------- release: publish/rollback
def _release_payload(db: Session, rel: dbmod.Release) -> dict:
    return workflow.release_dict(rel, session=db)


@router.post("/snapshots/{sid}/publish")
async def publish_snapshot(sid: int, body: PublishIn,
                           request: Request,
                           idempotency_key: str | None = Header(default=None),
                           db: Session = Depends(get_db)):
    _get_snapshot(db, sid)

    def _do():
        try:
            rel = workflow.publish_snapshot(
                db, sid, node=body.node, created_by=body.created_by,
                idempotency_key=idempotency_key)
        except workflow.WorkflowError as e:
            raise HTTPException(409, str(e))
        except FRRUnavailable as e:
            raise HTTPException(503, str(e))
        return _release_payload(db, rel)

    return await _idempotent(db, request, idempotency_key,
                             f"publish:{sid}:{body.node}", _do)


@router.get("/policies/{pid}/releases")
def list_releases(pid: int, db: Session = Depends(get_db)):
    _get_policy(db, pid)
    rels = db.query(dbmod.Release).filter_by(policy_id=pid) \
        .order_by(dbmod.Release.id.desc()).all()
    return [_release_payload(db, r) for r in rels]


@router.get("/releases")
def all_releases(limit: int = 100, db: Session = Depends(get_db)):
    rels = db.query(dbmod.Release).order_by(dbmod.Release.id.desc()) \
        .limit(limit).all()
    return [_release_payload(db, r) for r in rels]


@router.get("/releases/{rid}")
def get_release(rid: int, db: Session = Depends(get_db)):
    rel = db.get(dbmod.Release, rid)
    if rel is None:
        raise HTTPException(404, "release not found")
    return _release_payload(db, rel)


@router.post("/releases/{rid}/retry")
def retry_release(rid: int, db: Session = Depends(get_db)):
    rel = db.get(dbmod.Release, rid)
    if rel is None:
        raise HTTPException(404, "release not found")
    try:
        rel = workflow.retry_release(db, rid)
    except workflow.WorkflowError as e:
        # keep 409 for state errors; failed apply -> 422 and row stays failed
        cur = db.get(dbmod.Release, rid)
        if cur is not None and cur.status == "failed":
            raise HTTPException(422, str(e))
        raise HTTPException(409, str(e))
    except FRRUnavailable as e:
        raise HTTPException(503, str(e))
    return _release_payload(db, rel)


@router.post("/snapshots/{sid}/rollback")
async def rollback_to(sid: int, body: RollbackIn,
                      request: Request,
                      idempotency_key: str | None = Header(default=None),
                      db: Session = Depends(get_db)):
    _get_snapshot(db, sid)

    def _do():
        try:
            rel = workflow.rollback(
                db, sid, node=body.node, created_by=body.created_by,
                idempotency_key=idempotency_key)
        except workflow.WorkflowError as e:
            raise HTTPException(409, str(e))
        except FRRUnavailable as e:
            raise HTTPException(503, str(e))
        return _release_payload(db, rel)

    return await _idempotent(db, request, idempotency_key,
                             f"rollback:{sid}:{body.node}", _do)


@router.get("/policies/{pid}/drift")
def policy_drift(pid: int, node: str = "a", db: Session = Depends(get_db)):
    _get_policy(db, pid)
    try:
        return workflow.check_drift(db, pid, node=node)
    except FRRUnavailable as e:
        raise HTTPException(503, str(e))


@router.get("/policies/{pid}/active-release")
def active_release(pid: int, node: str = "a", db: Session = Depends(get_db)):
    _get_policy(db, pid)
    rel = workflow._active_release(db, pid, node)
    return _release_payload(db, rel) if rel else None


# --------------------------------------------------------------- neighbors
@router.get("/neighbors")
def list_neighbors(db: Session = Depends(get_db)):
    ns = db.query(dbmod.Neighbor).order_by(dbmod.Neighbor.name).all()
    return [{"id": n.id, "name": n.name, "ip": n.ip, "family": n.family,
             "asn": n.asn, "inbound_policy": n.inbound_policy,
             "outbound_policy": n.outbound_policy, "description": n.description}
            for n in ns]


@router.post("/neighbors", status_code=201)
def create_neighbor(body: NeighborIn, db: Session = Depends(get_db)):
    try:
        net = ipaddress.ip_network(body.ip, strict=False)
    except ValueError as e:
        raise HTTPException(422, f"bad neighbor ip: {e}")
    if net.version != body.family:
        raise HTTPException(422, f"ip family does not match family={body.family}")
    n = dbmod.Neighbor(**body.model_dump())
    db.add(n)
    db.commit()
    db.refresh(n)
    _invalidate_neighbor_binding(db, body.inbound_policy, body.outbound_policy)
    return {"id": n.id, **body.model_dump()}


def _invalidate_neighbor_binding(db: Session, *policy_names: str | None) -> None:
    """Neighbor bindings are frozen into approval evidence; binding changes
    invalidate open (unpublished) approvals of affected policies."""
    names = {n for n in policy_names if n}
    if not names:
        return
    for p in db.query(dbmod.Policy).filter(dbmod.Policy.name.in_(names)).all():
        workflow.invalidate_open_versions(
            db, p, reason="bound neighbors changed after validation/approval")


@router.put("/neighbors/{nid}")
def update_neighbor(nid: int, body: NeighborIn, db: Session = Depends(get_db)):
    n = db.get(dbmod.Neighbor, nid)
    if n is None:
        raise HTTPException(404, "neighbor not found")
    try:
        net = ipaddress.ip_network(body.ip, strict=False)
    except ValueError as e:
        raise HTTPException(422, f"bad neighbor ip: {e}")
    if net.version != body.family:
        raise HTTPException(422, "ip family does not match family")
    affected = {n.inbound_policy, n.outbound_policy,
                body.inbound_policy, body.outbound_policy}
    for k, v in body.model_dump().items():
        setattr(n, k, v)
    db.commit()
    _invalidate_neighbor_binding(db, *affected)
    return {"id": n.id, **body.model_dump()}


@router.delete("/neighbors/{nid}", status_code=204)
def delete_neighbor(nid: int, db: Session = Depends(get_db)):
    n = db.get(dbmod.Neighbor, nid)
    if n is None:
        raise HTTPException(404, "neighbor not found")
    affected = {n.inbound_policy, n.outbound_policy}
    db.delete(n)
    db.commit()
    _invalidate_neighbor_binding(db, *affected)


# --------------------------------------------------------------- scenarios
@router.get("/scenarios")
def list_scenarios(db: Session = Depends(get_db)):
    return [{"id": s.id, "name": s.name, "description": s.description,
             "from_snapshot_id": s.from_snapshot_id,
             "to_snapshot_id": s.to_snapshot_id, "probes": s.probes,
             "results": s.results, "created_at": s.created_at.isoformat()}
            for s in db.query(dbmod.Scenario).order_by(dbmod.Scenario.id).all()]


@router.post("/scenarios", status_code=201)
def create_scenario(body: ScenarioIn, db: Session = Depends(get_db)):
    if db.query(dbmod.Scenario).filter_by(name=body.name).first():
        raise HTTPException(409, f"scenario {body.name!r} exists")
    results = {}
    if body.from_snapshot_id:
        try:
            results["from"] = service.replay(db, body.from_snapshot_id, body.probes)
        except ValidationError:
            pass
    if body.to_snapshot_id:
        try:
            results["to"] = service.replay(db, body.to_snapshot_id, body.probes)
        except ValidationError:
            pass
    sc = dbmod.Scenario(**body.model_dump(), results=results)
    db.add(sc)
    db.commit()
    db.refresh(sc)
    return {"id": sc.id, "name": sc.name, "results": sc.results}


@router.get("/scenarios/{scid}")
def get_scenario(scid: int, db: Session = Depends(get_db)):
    s = db.get(dbmod.Scenario, scid)
    if s is None:
        raise HTTPException(404, "scenario not found")
    return {"id": s.id, "name": s.name, "description": s.description,
            "from_snapshot_id": s.from_snapshot_id,
            "to_snapshot_id": s.to_snapshot_id, "probes": s.probes,
            "results": s.results}


@router.post("/scenarios/{scid}/replay")
def replay_scenario(scid: int, db: Session = Depends(get_db)):
    """Replay the stored ordered inputs against both snapshots deterministically."""
    s = db.get(dbmod.Scenario, scid)
    if s is None:
        raise HTTPException(404, "scenario not found")
    out = {"probes": s.probes, "from": None, "to": None, "diff": None}
    if s.from_snapshot_id:
        out["from"] = service.replay(db, s.from_snapshot_id, s.probes)
    if s.to_snapshot_id:
        out["to"] = service.replay(db, s.to_snapshot_id, s.probes)
    if s.from_snapshot_id and s.to_snapshot_id:
        out["diff"] = service.snapshot_diff(
            db, s.from_snapshot_id, s.to_snapshot_id)
    s.results = out
    db.commit()
    return out
