"""
Acceptance tests for the reviewable release pipeline.

Covers (mapping to the acceptance criteria in the task):

* validate -> approve -> simulated publish is fully replayable, evidence is
  frozen (rule order, neighbors, default action, semantic diff, probes,
  FRR cross-validation per node);
* editing rules invalidates prior approvals (superseded; approve refused);
* duplicate/concurrent publishes leave exactly ONE active version;
* a container apply failure leaves the DB retryable and container state
  restored, then a retry succeeds — no DB/container divergence;
* rollback creates a NEW release record from a historical snapshot (old
  record untouched), and before/after snapshots, minimal witnesses and
  actual isolated-FRR config can all be reconciled;
* IPv4/IPv6 and default-deny behavior do not regress.

FRR is driven through the in-process stub transport (conftest sets
RLAB_FRR_TRANSPORT=stub), which implements FRR's prefix_list_apply model
and supports explicit failure injection.
"""
import threading

import pytest

from app import db as dbmod
from app.frr_bridge import STUB_FAIL_NEXT, STUB_STATE


# every test starts from an empty DB (client is session-scoped) and empty
# isolated FRR containers
pytestmark = pytest.mark.usefixtures("db")


# --------------------------------------------------------------- helpers
def _policy(client, name, rules, family=4, default="deny"):
    pid = client.post("/api/policies", json={
        "name": name, "family": family, "default_action": default}).json()["id"]
    r = client.put(f"/api/policies/{pid}/rules",
                   json={"rules": rules, "default_action": default})
    assert r.status_code == 200, r.text
    return pid


V1_RULES = [{"seq": 10, "prefix": "192.168.0.0/16", "action": "permit", "le": 24},
            {"seq": 20, "prefix": "10.0.0.0/8", "action": "deny"}]
V2_RULES = [{"seq": 10, "prefix": "192.168.0.0/16", "action": "permit", "le": 23},
            {"seq": 20, "prefix": "10.0.0.0/8", "action": "deny"},
            {"seq": 30, "prefix": "192.168.100.0/24", "action": "deny"}]


def _drive(client, pid, rules=None, expect="approved", probes=None):
    if rules is not None:
        client.put(f"/api/policies/{pid}/rules", json={"rules": rules})
    rid = client.post(f"/api/policies/{pid}/releases/draft",
                      json={"created_by": "tester"}).json()["id"]
    v = client.post(f"/api/releases/{rid}/validate", json={"probes": probes})
    assert v.status_code == 200, v.text
    if expect == "approved":
        assert v.json()["state"] == "pending_approval", v.json()
        a = client.post(f"/api/releases/{rid}/approve",
                        json={"approved_by": "reviewer", "comment": "ok"})
        assert a.status_code == 200, a.text
        assert a.json()["state"] == "approved"
    else:
        assert v.json()["state"] == expect, v.json()
    return rid


# ------------------------------------------------- happy path + evidence
def test_validate_approve_publish_replayable(client):
    pid = _policy(client, "rel-happy", V1_RULES)
    rid = _drive(client, pid)

    rel = client.get(f"/api/releases/{rid}").json()
    ev = rel["evidence"]

    # evidence packet freezes everything the reviewer needs
    assert [r["seq"] for r in ev["frozen_rules_ordered"]] == [10, 20]
    assert ev["default_action"] == "deny"
    assert isinstance(ev["neighbors"], list)
    assert ev["semantic_diff"] is not None          # first release vs prior snap
    assert len(ev["probes"]) == len(ev["probe_results"])
    assert set(ev["frr_nodes"]) == {"a", "b"}
    assert all(e["status"] == "match" for e in ev["frr_nodes"].values())
    # approval freezes a checksummed packet of the same evidence
    assert rel["approval"]["rules_checksum"] == ev["rules_checksum"]
    assert rel["approval"]["approved_by"] == "reviewer"

    # publish only touches the isolated FRR nodes
    pu = client.post(f"/api/releases/{rid}/publish", json={})
    assert pu.status_code == 200
    assert pu.json()["state"] == "simulated_published"

    # replay the exact probes against the frozen snapshot afterwards:
    # the result must match the evidence frozen at validation time
    snap_id = rel["snapshot_id"]
    rep = client.post(f"/api/snapshots/{snap_id}/replay",
                      json={"probes": ev["probes"]}).json()
    for frozen, now in zip(ev["probe_results"], rep["results"]):
        assert frozen["action"] == now["final_action"]
        assert frozen["seq"] == now["matched_seq"]

    # actual isolated container config is verifiable and matches the release
    live = client.get(f"/api/releases/{rid}/live-config").json()
    assert live["plist_name"] == "rlabpub1"
    for node, entry in live["nodes"].items():
        assert entry["reachable"] and entry["matches_release"], node
        assert "seq 10 permit 192.168.0.0/16 le 24" in entry["shown"]


def test_evidence_carries_minimal_witnesses(client):
    # semantic diff evidence must show the over-permit witness:
    # 192.168.100.0/24 flips permit -> deny in v2
    pid = _policy(client, "rel-wit", V1_RULES)
    r1 = _drive(client, pid)
    client.post(f"/api/releases/{r1}/publish", json={})
    r2 = _drive(client, pid, V2_RULES)
    wits = client.get(f"/api/releases/{r2}").json()[
        "evidence"]["semantic_diff"]["witnesses"]
    flipped = {w["prefix"]: w["change"] for w in wits}
    assert flipped.get("192.168.100.0/24") == "permit->deny"


# ------------------------------------------------- edit invalidates approval
def test_rule_edit_invalidates_open_releases(client):
    pid = _policy(client, "rel-edit", V1_RULES)
    rid = _drive(client, pid)                    # approved
    assert client.get(f"/api/releases/{rid}").json()["state"] == "approved"

    client.put(f"/api/policies/{pid}/rules", json={"rules": V2_RULES})
    assert client.get(f"/api/releases/{rid}").json()["state"] == "superseded"

    # cannot approve or publish the dead approval
    assert client.post(f"/api/releases/{rid}/approve",
                       json={"approved_by": "x"}).status_code == 409
    assert client.post(f"/api/releases/{rid}/publish",
                       json={}).status_code == 409

    # pending-approval releases are killed too
    rid2 = client.post(f"/api/policies/{pid}/releases/draft",
                       json={}).json()["id"]
    client.post(f"/api/releases/{rid2}/validate", json={})
    assert client.get(f"/api/releases/{rid2}").json()["state"] == "pending_approval"
    client.put(f"/api/policies/{pid}/rules", json={"rules": V1_RULES})
    assert client.get(f"/api/releases/{rid2}").json()["state"] == "superseded"


def test_stale_draft_cannot_be_validated_after_edit(client):
    pid = _policy(client, "rel-stale", V1_RULES)
    rid = client.post(f"/api/policies/{pid}/releases/draft",
                      json={}).json()["id"]
    client.put(f"/api/policies/{pid}/rules", json={"rules": V2_RULES})
    r = client.post(f"/api/releases/{rid}/validate", json={})
    assert r.status_code == 409
    assert client.get(f"/api/releases/{rid}").json()["state"] == "superseded"


def test_default_action_flip_invalidates(client):
    # default-permit policies are rejected by the default-deny regression
    # guard, so here we verify invalidation starting from an open draft:
    # flipping the default action must kill any in-flight release packet.
    pid = _policy(client, "rel-flip",
                  [{"seq": 10, "prefix": "203.0.113.0/24", "action": "deny"}],
                  default="permit")
    rid = client.post(f"/api/policies/{pid}/releases/draft",
                      json={}).json()["id"]
    assert client.get(f"/api/releases/{rid}").json()["state"] == "draft"
    client.put(f"/api/policies/{pid}/rules", json={
        "rules": [{"seq": 10, "prefix": "203.0.113.0/24", "action": "deny"}],
        "default_action": "deny"})
    assert client.get(f"/api/releases/{rid}").json()["state"] == "superseded"

    # and the guard itself: default-deny snapshot can never validate an
    # outsider as permitted
    rid2 = client.post(f"/api/policies/{pid}/releases/draft",
                       json={}).json()["id"]
    v = client.post(f"/api/releases/{rid2}/validate", json={}).json()
    assert v["state"] == "pending_approval"
    assert v["evidence"]["default_deny_guard"]["violation"] is None


# ------------------------------------------------- concurrency / idempotency
def test_duplicate_and_concurrent_publish_single_active(client):
    pid = _policy(client, "rel-conc", V1_RULES)
    r1 = _drive(client, pid)
    # not published yet: duplicate approve is rejected, state unchanged
    dup = client.post(f"/api/releases/{r1}/approve",
                      json={"approved_by": "again"})
    assert dup.status_code == 409

    # publish r1 once, then duplicate the same publish: idempotent no-op
    client.post(f"/api/releases/{r1}/publish", json={})
    again = client.post(f"/api/releases/{r1}/publish", json={}).json()
    assert again["id"] == r1 and again["state"] == "simulated_published"

    # two approved-but-unpublished revisions racing (simulated by driving
    # r2 and an immediately superseded path is impossible, so the race is
    # duplicate r2 requests against the active r1)
    r2 = _drive(client, pid, V2_RULES)
    results = []
    statuses = []
    barrier = threading.Barrier(4)

    def fire(rid):
        barrier.wait()
        r = client.post(f"/api/releases/{rid}/publish", json={})
        if r.status_code == 200:
            results.append(r.json()["id"])
        statuses.append(r.status_code)

    threads = [threading.Thread(target=fire, args=(r2,)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    active = client.get(f"/api/policies/{pid}/releases/active").json()["active"]
    assert active is not None
    # all duplicate requests resolved to the single winning version r2
    assert active["id"] == r2
    assert set(results) == {r2}
    assert all(s == 200 for s in statuses)
    history = client.get(f"/api/policies/{pid}/releases").json()
    active_rows = [h for h in history if h["state"] == "simulated_published"]
    assert len(active_rows) == 1
    assert [h["state"] for h in history if h["id"] == r1] == ["superseded"]

    # a third distinct approved revision then publishes cleanly, and stale
    # concurrent publishes of r2 after that are rejected
    r3_rules = V2_RULES + [
        {"seq": 40, "prefix": "172.16.0.0/12", "action": "permit", "le": 32}]
    r3 = _drive(client, pid, r3_rules)
    p3 = client.post(f"/api/releases/{r3}/publish", json={}).json()
    assert p3["state"] == "simulated_published"
    stale = client.post(f"/api/releases/{r2}/publish", json={})
    assert stale.status_code == 409
    assert client.get(f"/api/policies/{pid}/releases/active").json()[
        "active"]["id"] == r3


def test_draft_endpoint_idempotent(client):
    pid = _policy(client, "rel-dupdraft", V1_RULES)
    d1 = client.post(f"/api/policies/{pid}/releases/draft", json={}).json()
    d2 = client.post(f"/api/policies/{pid}/releases/draft", json={}).json()
    assert d1["id"] == d2["id"]


def test_state_transitions_enforced(client):
    pid = _policy(client, "rel-trans", V1_RULES)
    rid = client.post(f"/api/policies/{pid}/releases/draft",
                      json={}).json()["id"]
    # cannot approve or publish before validation
    assert client.post(f"/api/releases/{rid}/approve",
                       json={"approved_by": "x"}).status_code == 409
    assert client.post(f"/api/releases/{rid}/publish",
                       json={}).status_code == 409


def test_newer_approval_supersedes_pending_and_approved(client):
    pid = _policy(client, "rel-two", V1_RULES)
    # r1 fully approved
    r1 = _drive(client, pid)
    assert client.get(f"/api/releases/{r1}").json()["state"] == "approved"
    # validate r2 but leave it pending, then validate r3 and approve it
    client.put(f"/api/policies/{pid}/rules", json={"rules": V1_RULES + [
        {"seq": 30, "prefix": "172.16.0.0/12", "action": "deny"}]})
    r2 = client.post(f"/api/policies/{pid}/releases/draft",
                     json={}).json()["id"]
    client.post(f"/api/releases/{r2}/validate", json={})
    assert client.get(f"/api/releases/{r2}").json()["state"] == "pending_approval"

    client.put(f"/api/policies/{pid}/rules", json={"rules": V1_RULES + [
        {"seq": 30, "prefix": "172.16.0.0/12", "action": "permit", "le": 32}]})
    r3 = _drive(client, pid)   # approved
    assert client.get(f"/api/releases/{r3}").json()["state"] == "approved"

    # the prior approved (r1) and pending (r2) are both superseded
    assert client.get(f"/api/releases/{r1}").json()["state"] == "superseded"
    assert client.get(f"/api/releases/{r2}").json()["state"] == "superseded"
    # and cannot publish
    assert client.post(f"/api/releases/{r1}/publish",
                       json={}).status_code == 409
    # only r3 is publishable
    pub = client.post(f"/api/releases/{r3}/publish", json={}).json()
    assert pub["state"] == "simulated_published"


# ------------------------------------------------- FRR failure -> retry
def test_apply_failure_leaves_db_retryable_and_recovers(client):
    pid = _policy(client, "rel-fail", V1_RULES)
    r1 = _drive(client, pid)
    client.post(f"/api/releases/{r1}/publish", json={})
    r2 = _drive(client, pid, V2_RULES)

    # node a applies, node b fails mid-publish
    STUB_FAIL_NEXT["b"] = 1
    failed = client.post(f"/api/releases/{r2}/publish", json={}).json()

    # DB still claims v1 only and still allows retry from v2
    assert failed["state"] == "approved"
    assert failed["last_error"]["node"] == "b"
    assert failed["last_error"]["restored_nodes"] == ["a"]
    active = client.get(f"/api/policies/{pid}/releases/active").json()["active"]
    assert active["id"] == r1

    # containers run v1 on both nodes (v2 residue rolled back)
    live1 = client.get(f"/api/releases/{r1}/live-config").json()
    for node, e in live1["nodes"].items():
        assert e["matches_release"], node
        assert "le 24" in e["shown"] and "seq 30 deny" not in e["shown"]
    for node in ("a", "b"):
        entries = STUB_STATE[node][("rlabpub1", 4)]
        assert entries[0]["le"] == 24 and len(entries) == 2

    # retry -> success, v1 becomes superseded, containers now run v2
    ok = client.post(f"/api/releases/{r2}/publish", json={}).json()
    assert ok["state"] == "simulated_published"
    assert client.get(f"/api/releases/{r1}").json()["state"] == "superseded"
    live2 = client.get(f"/api/releases/{r2}/live-config").json()
    for node, e in live2["nodes"].items():
        assert e["matches_release"]
        assert "seq 30 deny 192.168.100.0/24" in e["shown"]
        assert "le 24" not in e["shown"]


def test_validation_failure_is_retryable(client):
    pid = _policy(client, "rel-valfail", V1_RULES)
    rid = client.post(f"/api/policies/{pid}/releases/draft",
                      json={}).json()["id"]
    STUB_FAIL_NEXT["a"] = 1
    failed = client.post(f"/api/releases/{rid}/validate", json={}).json()
    assert failed["state"] == "validation_failed"
    assert failed["last_error"]["kind"] == "unavailable"

    again = client.post(f"/api/releases/{rid}/validate", json={}).json()
    assert again["state"] == "pending_approval"


# ------------------------------------------------- rollback
def test_rollback_creates_new_release_and_republishes(client):
    pid = _policy(client, "rel-rb", V1_RULES)
    r1 = _drive(client, pid)
    client.post(f"/api/releases/{r1}/publish", json={})
    snap_v1 = client.get(f"/api/releases/{r1}").json()["snapshot_id"]

    r2 = _drive(client, pid, V2_RULES)
    client.post(f"/api/releases/{r2}/publish", json={})
    snap_v2 = client.get(f"/api/releases/{r2}").json()["snapshot_id"]
    assert snap_v1 != snap_v2

    # roll back to the v1 historical snapshot: a NEW record is created
    rb = client.post(f"/api/releases/{r1}/rollback", json={"actor": "sre"}).json()
    assert rb["id"] not in (r1, r2)
    assert rb["kind"] == "rollback"
    assert rb["state"] == "draft"
    assert rb["rollback_of_id"] == r1
    assert rb["snapshot_id"] == snap_v1            # historical snapshot reused

    # old rows are NOT rewritten
    assert client.get(f"/api/releases/{r1}").json()["state"] == "superseded"
    assert client.get(f"/api/releases/{r2}").json()["state"] == "simulated_published"

    v = client.post(f"/api/releases/{rb['id']}/validate", json={}).json()
    assert v["state"] == "pending_approval"        # rollback bypasses staleness
    a = client.post(f"/api/releases/{rb['id']}/approve",
                    json={"approved_by": "sre"}).json()
    assert a["state"] == "approved"
    p = client.post(f"/api/releases/{rb['id']}/publish", json={}).json()
    assert p["state"] == "simulated_published"

    # v2 is now superseded; exactly one active; v1 row still just superseded
    assert client.get(f"/api/releases/{r2}").json()["state"] == "superseded"
    assert client.get(f"/api/releases/{r1}").json()["state"] == "superseded"
    history = client.get(f"/api/policies/{pid}/releases").json()
    assert [h for h in history if h["state"] == "simulated_published"][0]["id"] == rb["id"]

    # actual isolated config matches the v1 content (le 24, no seq 30 guard)
    live = client.get(f"/api/releases/{rb['id']}/live-config").json()
    for node, e in live["nodes"].items():
        assert e["matches_release"], node
        assert "seq 10 permit 192.168.0.0/16 le 24" in e["shown"]
        assert "seq 30 deny" not in e["shown"]

    # before/after snapshots + minimal witnesses remain reconcilable
    diff = client.post("/api/snapshots/diff", json={
        "old_snapshot_id": snap_v2,
        "new_snapshot_id": snap_v1}).json()
    assert diff["witness_count"] >= 1
    assert any(w["prefix"] == "192.168.100.0/24"
               and w["change"] == "deny->permit" for w in diff["witnesses"])


# ------------------------------------------------- v4/v6 + default deny
def test_ipv6_pipeline_and_default_deny(client):
    pid = _policy(client, "rel-v6",
                  [{"seq": 10, "prefix": "2001:db8::/32",
                    "action": "permit", "le": 48}], family=6)
    rid = _drive(client, pid,
                 probes=["2001:db8:2::/48", "2001:dead::/32", "2001:db8:1::/48"])
    ev = client.get(f"/api/releases/{rid}").json()["evidence"]
    assert ev["family"] == 6
    # outsider v6 prefix must be denied (default deny no regression)
    guard = ev["default_deny_guard"]
    assert guard["violation"] is None and guard["action"] == "deny"
    assert all(row["action"] == "deny"
               for row in ev["probe_results"] if row["prefix"] == "2001:dead::/32")
    # FRR agreed on every node
    assert all(n["status"] == "match" for n in ev["frr_nodes"].values())

    client.post(f"/api/releases/{rid}/publish", json={})
    live = client.get(f"/api/releases/{rid}/live-config").json()
    for e in live["nodes"].values():
        assert "ipv6 prefix-list" in e["shown"]
        assert e["matches_release"]


def test_cross_family_probe_rejected_without_losing_draft(client):
    pid = _policy(client, "rel-xprobe", V1_RULES)
    rid = client.post(f"/api/policies/{pid}/releases/draft",
                      json={}).json()["id"]
    r = client.post(f"/api/releases/{rid}/validate",
                    json={"probes": ["2001:db8::/32"]})
    assert r.status_code == 422
    assert client.get(f"/api/releases/{rid}").json()["state"] == "draft"


def test_witness_prefixes_are_actually_replayable(client):
    """Every frozen witness must classify differently on before vs after."""
    pid = _policy(client, "rel-wrep", V1_RULES)
    r1 = _drive(client, pid)
    client.post(f"/api/releases/{r1}/publish", json={})
    r2 = _drive(client, pid, V2_RULES)
    rel2 = client.get(f"/api/releases/{r2}").json()
    s_old, s_new = None, rel2["snapshot_id"]
    # baseline evidence points at the previously active snapshot
    s_old = rel2["evidence"]["baseline_snapshot_id"]
    wits = rel2["evidence"]["semantic_diff"]["witnesses"]
    assert wits
    for w in wits:
        old = client.post(f"/api/snapshots/{s_old}/replay",
                          json={"probes": [w["prefix"]]}).json()["results"][0]
        new = client.post(f"/api/snapshots/{s_new}/replay",
                          json={"probes": [w["prefix"]]}).json()["results"][0]
        assert old["final_action"] != new["final_action"]
        assert {old["final_action"], new["final_action"]} == {"permit", "deny"}
