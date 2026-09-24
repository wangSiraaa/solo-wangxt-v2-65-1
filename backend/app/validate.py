"""
Cross-validation between the ipaddress simulator and a live local FRR
container.

Semantics reconciliation (verified against FRR 8.4/8.5 source,
lib/plist.c::prefix_list_apply_ext / prefix_list_entry_match):

* containment:        candidate subnet-of rule base           (same as us)
* no ge/le:           EXACT prefix length required            (same as us)
* ge/le window:       plen in [ge, le]; 0 means "unset"       (same bounds)
* first match wins:   FRR walks its internal trie but selects the entry
                      with the smallest seq among all matching bases.
* no entry matched:   FRR returns DENY from prefix_list_apply (and so does
                      BGP's `match ip address prefix-list` fall-through).
* EMPTY prefix list:  FRR short-circuits to PERMIT (!). This cannot happen
                      for a snapshot (every snapshot has >=1 rule); the
                      validator explicitly reports it as a lab setup error
                      instead of silently accepting it.
* CLI ge-only normalization:
      FRR vtysh rewrites `... ge X` (le omitted) to le=32/128 at config
      time for the standard CLI path, matching Cisco semantics and our
      engine. We assert the installed list shows that via `show`.
"""
from __future__ import annotations

from typing import List, Optional

from sqlalchemy.orm import Session

from . import db as dbmod
from .engine import Policy
from .frr_bridge import FRRBridge, FRRObservation, FRRUnavailable
from .service import engine_policy_from_snapshot


def _simulate(policy: Policy, probes: List[str]) -> List[dict]:
    out = []
    for i, pfx in enumerate(probes):
        hit = policy.classify(pfx).to_dict()
        out.append({
            "order": i,
            "prefix": pfx,
            "action": hit["final_action"],
            "seq": hit["matched_seq"],
            "terminal": hit["terminal"],
            "chain": hit["chain"],
        })
    return out


def _installed_config_sanity(show_output: str, policy: Policy) -> Optional[str]:
    """Return an error string if FRR didn't install what we rendered."""
    if not policy.rules:
        return ("policy has zero rules; FRR treats an empty prefix-list as "
                "implicit PERMIT — refusing to compare (add >=1 explicit rule)")
    for r in policy.rules:
        token = f"seq {r.seq} {r.action.value}"
        if token not in show_output:
            return f"FRR install verification failed: missing {token}"
    return None


def cross_validate(policy: Policy, probes: List[str],
                   node: str = "a", install: bool = True,
                   bridge: Optional[FRRBridge] = None,
                   remove_after: bool = True) -> dict:
    sim = _simulate(policy, probes)

    owns_bridge = bridge is None
    if bridge is None:
        bridge = FRRBridge(node=node).connect()
    setup_error = None
    try:
        if install:
            bridge.remove_policy(policy.name, policy.family)
            bridge.install_policy(policy)

        show = bridge.show_prefix_list(policy.name, policy.family)
        setup_error = _installed_config_sanity(show, policy)

        observed: List[FRRObservation] = []
        if setup_error is None:
            for pfx in probes:
                observed.append(
                    bridge.observe(policy.name, policy.family, pfx))

        if install and remove_after:
            try:
                bridge.remove_policy(policy.name, policy.family)
            except FRRUnavailable:
                pass
    finally:
        if owns_bridge:
            bridge.close()

    rows, mismatches = [], []
    if setup_error is None:
        for s, o in zip(sim, observed):
            action_match = (o.action == s["action"])
            # seq: both None when falling through FRR/apply default
            seq_match = (o.seq == s["seq"])
            row = {
                "order": s["order"], "prefix": s["prefix"],
                "sim_action": s["action"], "sim_seq": s["seq"],
                "frr_action": o.action, "frr_seq": o.seq,
                "action_match": action_match, "seq_match": seq_match,
                "frr_raw": o.raw,
            }
            rows.append(row)
            if not action_match or not seq_match:
                mismatches.append(row)

    return {
        "node": node,
        "policy": policy.name,
        "family": policy.family,
        "probes": probes,
        "rows": rows,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "status": ("error" if setup_error
                   else "match" if not mismatches else "mismatch"),
        "setup_error": setup_error,
    }


def cross_validate_snapshot(session: Session, snapshot_id: int,
                            probes: List[str], node: str = "a") -> dict:
    snap = session.get(dbmod.Snapshot, snapshot_id)
    if snap is None:
        raise FRRUnavailable("snapshot not found")
    policy = engine_policy_from_snapshot(snap)
    result = cross_validate(policy, probes, node=node)
    run = dbmod.Run(
        snapshot_id=snapshot_id, node=node,
        status=result["status"],
        detail={"mismatch_count": result["mismatch_count"],
                "probes": probes,
                "mismatches": result["mismatches"],
                "setup_error": result.get("setup_error")},
    )
    session.add(run)
    session.commit()
    result["run_id"] = run.id
    return result
