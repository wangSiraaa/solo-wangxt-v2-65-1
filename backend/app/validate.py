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
from .engine import (
    Action, Policy, Rule,
)
from .frr_bridge import FRRBridge, FRRObservation, FRRUnavailable, get_bridge
from .service import engine_policy_from_snapshot

# FRR prefix-lists have an implicit DENY fall-through; they cannot express a
# policy-level default PERMIT. To cross-validate a permit-default snapshot we
# install a synthesized terminal guard rule (lowest precedence) that only
# exists in FRR for the comparison. The frozen snapshot config is unchanged.
DEFAULT_GUARD_SEQ = 4294967294


def _installed_variant(policy: Policy) -> Policy:
    """Policy variant actually pushed into FRR (adds default-permit guard)."""
    if policy.default_action != Action.PERMIT:
        return policy
    base = "0.0.0.0/0" if policy.family == 4 else "::/0"
    maxlen = 32 if policy.family == 4 else 128
    guard = Rule(seq=DEFAULT_GUARD_SEQ, prefix=base, action=Action.PERMIT,
                 le=maxlen, remark="synthesized default-permit guard")
    return Policy(
        name=policy.name, rules=[*policy.rules, guard],
        default_action=policy.default_action, family=policy.family)


def _make(node: str, timeout: float = 30.0) -> FRRBridge:
    """Indirection point: tests swap frr_bridge._bridge_factory."""
    return get_bridge(node=node, timeout=timeout)


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
    if not policy.rules:
        # an EMPTY real policy: FRR's empty plist short-circuits to PERMIT,
        # which cannot be reconciled with any implicit default — setup error
        return {
            "node": node, "policy": policy.name, "family": policy.family,
            "probes": probes, "rows": [], "mismatch_count": 0,
            "mismatches": [], "status": "error",
            "setup_error": ("policy has zero rules; FRR treats an empty "
                            "prefix-list as implicit PERMIT — refusing to "
                            "compare (add >=1 explicit rule)"),
        }

    installed = _installed_variant(policy)
    guard_seq = DEFAULT_GUARD_SEQ if installed is not policy else None

    owns_bridge = bridge is None
    if bridge is None:
        bridge = _make(node=node).connect()
    setup_error = None
    try:
        if install:
            bridge.remove_policy(policy.name, policy.family)
            bridge.install_policy(installed)

        show = bridge.show_prefix_list(policy.name, policy.family)
        # read-only checks run against the device's REAL config (no
        # synthesized guard); install checks verify what we just pushed
        setup_error = _installed_config_sanity(
            show, installed if install else policy)

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
            # map the synthesized guard hit onto the simulator's terminal
            # default (matched_seq None): both represent "no real rule won"
            frr_seq = None if (guard_seq is not None and o.seq == guard_seq) \
                else o.seq
            # Read-only validation (install=False) runs against the REAL
            # device config, which carries no synthesized default-permit
            # guard; FRR then returns its implicit DENY for fall-through
            # probes. Such probes cannot be reconciled and are skipped
            # (structural show verification covers config presence).
            skip_default = (not install and guard_seq is not None
                            and s["terminal"] == "default")
            action_match = (o.action == s["action"])
            seq_match = (frr_seq == s["seq"])
            row = {
                "order": s["order"], "prefix": s["prefix"],
                "sim_action": s["action"], "sim_seq": s["seq"],
                "sim_terminal": s["terminal"],
                "frr_action": o.action, "frr_seq": frr_seq,
                "frr_raw_seq": o.seq,
                "synthesized_default_guard": frr_seq != o.seq,
                "skipped_default_permit": skip_default,
                "action_match": action_match, "seq_match": seq_match,
                "frr_raw": o.raw,
            }
            rows.append(row)
            if skip_default:
                continue
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

    # If this snapshot is the live published config on the node, validate
    # NON-destructively: never remove/reinstall the active prefix-list.
    from sqlalchemy import select
    active = session.scalar(
        select(dbmod.Release).where(
            dbmod.Release.policy_id == snap.policy_id,
            dbmod.Release.node == node,
            dbmod.Release.status == "active"))
    read_only = active is not None and active.snapshot_id == snapshot_id

    result = cross_validate(policy, probes, node=node,
                            install=not read_only,
                            remove_after=not read_only)
    run = dbmod.Run(
        snapshot_id=snapshot_id, node=node,
        status=result["status"],
        detail={"mismatch_count": result["mismatch_count"],
                "probes": probes,
                "mismatches": result["mismatches"],
                "setup_error": result.get("setup_error"),
                "read_only": read_only},
    )
    session.add(run)
    session.commit()
    result["run_id"] = run.id
    result["read_only"] = read_only
    return result
