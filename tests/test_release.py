"""
Acceptance tests for the auditable release pipeline:

draft -> validating -> (validation_failed) -> pending_approval -> approved
      -> simulated_published -> (superseded), plus retryable failure and
append-only rollback.

No docker socket is required: a stateful FakeFRRDevice emulates the isolated
FRR node and the single frr_bridge._bridge_factory is swapped to talk to it.
"""
import ipaddress
import threading
import time
import uuid

import pytest

from app import db as dbmod, workflow
from app.engine import Action, Policy, Rule
from app.frr_bridge import FRRBridge, FRRObservation, FRRUnavailable
from app import validate as validate_mod


# ------------------------------------------------------------- fake device

def frr_apply(rules, family, prefix_text):
    """Port of FRR plist.c prefix_list_apply_ext (same as test_frr)."""
    net = ipaddress.ip_network(prefix_text)
    best = None
    for r in rules:
        if r.family != net.version:
            continue
        if not net.subnet_of(r.net):
            continue
        le = r.le or 0
        ge = r.ge or 0
        if le == 0 and ge == 0:
            if r.net.prefixlen != net.prefixlen:
                continue
        else:
            if le and net.prefixlen > le:
                continue
            if ge and net.prefixlen < ge:
                continue
        if best is None or r.seq < best.seq:
            best = r
    if best is None:
        return "deny", None
    return best.action.value, best.seq


class FakeFRRDevice:
    """Per-node stateful emulation of the isolated FRR container."""

    def __init__(self, fail_next=0, fail_compensate=False):
        self.installed = {}          # (name, family) -> Policy
        self.apply_calls = 0
        self.fail_next = fail_next  # next N installs fail (settable mid-test)
        self.fail_compensate = fail_compensate

    def reset(self):
        self.installed.clear()
        self.apply_calls = 0
        self.fail_next = 0


class DeviceBridge(FRRBridge):
    def __init__(self, device, *a, **kw):
        super().__init__(*a, **kw)
        self.device = device
        self.connected = False

    def connect(self):
        self.connected = True
        return self

    def close(self):
        self.connected = False

    def install_policy(self, policy, vrf=""):
        self.device.apply_calls += 1
        if self.device.fail_next > 0:
            self.device.fail_next -= 1
            raise FRRUnavailable("simulated install failure")
        self.device.installed[(policy.name, policy.family)] = policy
        return ""

    def remove_policy(self, name, family, vrf=""):
        if self.device.fail_compensate:
            raise FRRUnavailable("simulated compensation failure")
        self.device.installed.pop((name, family), None)
        return ""

    def show_prefix_list(self, name, family):
        if (name, family) not in self.device.installed:
            return f"(no) {name}: 0 entries"
        p = self.device.installed[(name, family)]
        lines = [f"ip prefix-list {name}: {len(p.rules)} entries"]
        for r in p.rules:
            ge = f" ge {r.ge}" if r.ge is not None else ""
            le = f" le {r.le}" if r.le is not None else ""
            lines.append(f"   seq {r.seq} {r.action.value} {r.prefix}{ge}{le}")
        return "\n".join(lines)

    def observe(self, name, family, prefix, vrf=""):
        p = self.device.installed[(name, family)]
        action, seq = frr_apply(p.rules, family, prefix)
        if seq is None:
            raw = f"ip prefix list {name} yields DENY for {prefix}, no match found"
        else:
            raw = (f"ip prefix list {name} yields {action.upper()} for "
                   f"{prefix}, matching entry #{seq}")
        return FRRObservation(prefix, action, seq, raw)


@pytest.fixture
def device(monkeypatch):
    import app.frr_bridge as fb
    dev = FakeFRRDevice()
    # both validation and publish bridges must hit the same in-memory device;
    # swap the single factory every module reaches through get_bridge().
    monkeypatch.setattr(fb, "_bridge_factory",
                        lambda node="a", timeout=30.0: DeviceBridge(dev, node=node))
    return dev


# ----------------------------------------------------------------- helpers

def _make_policy(client, name=None, family=4, default="deny", rules=None):
    if name is None:
        # unique per test invocation since the client fixture is session-scoped
        name = f"rel-{uuid.uuid4().hex[:10]}"
    r = client.post("/api/policies", json={
        "name": name, "family": family, "default_action": default})
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    if rules is None:
        rules = [
            {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
            {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 24},
        ]
    r = client.put(f"/api/policies/{pid}/rules",
                   json={"rules": rules, "default_action": default})
    assert r.status_code == 200, r.text
    return pid


def _snapshot(client, pid, label="v1"):
    r = client.post(f"/api/policies/{pid}/snapshots", json={"label": label})
    assert r.status_code == 201, r.text
    return r.json()


def _validate(client, sid, probes=None, node="a"):
    return client.post(f"/api/snapshots/{sid}/validate",
                       json={"probes": probes, "node": node})


def _approve(client, sid, approver="netops-a", comment="ok"):
    return client.post(f"/api/snapshots/{sid}/approve",
                       json={"approver": approver, "comment": comment})


def _publish(client, sid, node="a", key=None):
    headers = {"Idempotency-Key": key} if key else {}
    return client.post(f"/api/snapshots/{sid}/publish",
                       json={"node": node}, headers=headers)


def _active(client, pid, node="a"):
    return client.get(f"/api/policies/{pid}/active-release?node={node}").json()


# ----------------------------------------------------------- 1. happy path

def test_validate_approve_publish_replayable(client, device):
    pid = _make_policy(client)
    snap = _snapshot(client, pid)
    assert snap["status"] == "draft"

    r = _validate(client, snap["id"], probes=[
        "192.168.0.0/16", "192.168.100.0/24", "10.1.2.3/32", "8.8.8.8/32"])
    assert r.status_code == 200, r.text
    ev = r.json()
    assert ev["status"] == "pending_approval"
    assert ev["validation"]["frr"]["status"] == "match"
    assert ev["validation"]["frr"]["mismatch_count"] == 0
    # frozen: rule order, neighbors, default action
    assert ev["validation"]["rule_order"] == [10, 20]
    assert ev["validation"]["default_action"] == "deny"
    assert "neighbors" in ev["validation"]

    r = _approve(client, snap["id"])
    assert r.status_code == 200, r.text
    appr = r.json()
    assert appr["status"] == "approved"
    b = appr["approval"]
    # the approval freezes the full evidence bundle
    for key in ("frozen_rule_order", "frozen_neighbors", "frozen_default_action",
                "frozen_semantic_diff", "frozen_probe_results",
                "frozen_frr_evidence", "frozen_frr_config",
                "frozen_content_hash"):
        assert key in b, key
    assert b["frozen_rule_order"] == [10, 20]
    assert b["frozen_default_action"] == "deny"

    r = _publish(client, snap["id"])
    assert r.status_code == 200, r.text
    rel = r.json()
    assert rel["status"] == "active"
    assert rel["snapshot_id"] == snap["id"]
    assert rel["kind"] == "publish"

    got = client.get(f"/api/snapshots/{snap['id']}").json()
    assert got["status"] == "simulated_published"

    # replayable: probes against the published snapshot still match
    rep = client.post(f"/api/snapshots/{snap['id']}/replay", json={
        "probes": ["192.168.100.0/24", "8.8.8.8/32"]}).json()
    assert [x["final_action"] for x in rep["results"]] == ["permit", "deny"]

    # the isolated device actually holds the applied config
    drift = client.get(f"/api/policies/{pid}/drift").json()
    assert drift["drift"] is False and drift["active_version"] == 1
    assert "seq 10 deny" in drift["device_show"]


# --------------------------------------------------- 2. edit invalidates

def test_rule_change_invalidates_old_approval(client, device):
    pid = _make_policy(client)
    s1 = _snapshot(client, pid, "v1")
    assert _validate(client, s1["id"]).status_code == 200
    assert _approve(client, s1["id"]).status_code == 200

    # edit rules after approval -> old approval must be invalidated
    r = client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 23},
    ]})
    assert r.status_code == 200
    got = client.get(f"/api/snapshots/{s1['id']}").json()
    assert got["status"] == "validation_failed"
    assert got["invalidated_reason"]

    # invalidated snapshot cannot be approved or published
    assert _approve(client, s1["id"]).status_code == 409
    assert _publish(client, s1["id"]).status_code == 409

    # a NEW draft is captured for the edited policy; its evidence is distinct
    s2 = _snapshot(client, pid, "v2")
    assert s2["status"] == "draft"
    assert s2["version"] == 2
    assert s2["content_hash"] != s1["content_hash"]
    assert _validate(client, s2["id"]).status_code == 200
    assert _approve(client, s2["id"]).status_code == 200
    assert _publish(client, s2["id"]).status_code == 200

    # original snapshot immutable and now superseded as a version
    s1again = client.get(f"/api/snapshots/{s1['id']}").json()
    assert s1again["payload"]["rules"][1]["le"] == 24   # old body preserved


def test_default_action_flip_invalidates(client, device):
    pid = _make_policy(client, default="permit")
    s = _snapshot(client, pid)
    assert _validate(client, s["id"]).status_code == 200
    assert _approve(client, s["id"]).status_code == 200
    r = client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 24},
    ], "default_action": "deny"})
    assert r.status_code == 200
    got = client.get(f"/api/snapshots/{s['id']}").json()
    assert got["status"] == "validation_failed"


# ------------------------------------------ 3. duplicate/concurrent publish

def test_duplicate_publish_collapses_to_one_active(client, device):
    pid = _make_policy(client)
    s = _snapshot(client, pid)
    _validate(client, s["id"]); _approve(client, s["id"])
    r1 = _publish(client, s["id"], key="k-1")
    r2 = _publish(client, s["id"], key="k-1")     # same Idempotency-Key
    r3 = _publish(client, s["id"], key="k-other")  # same already-active snap
    assert r1.status_code == 200 and r2.status_code == 200 and r3.status_code == 200
    assert r1.json()["id"] == r2.json()["id"] == r3.json()["id"]
    rels = client.get(f"/api/policies/{pid}/releases").json()
    active = [r for r in rels if r["status"] == "active"]
    assert len(active) == 1


def test_concurrent_publish_only_one_version(client, device, db, monkeypatch):
    import app.frr_bridge as fb

    pid = _make_policy(client)

    # two approved snapshots via the API
    s1 = _snapshot(client, pid, "v1")
    _validate(client, s1["id"]); _approve(client, s1["id"]); _publish(client, s1["id"])
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 23},
    ]})
    s2 = _snapshot(client, pid, "v2")
    _validate(client, s2["id"]); _approve(client, s2["id"])

    # gate the device install so the two publishes overlap while both hold
    # an 'applying' reservation
    import threading as _th
    entered = _th.Event()
    release = _th.Event()
    real_install = DeviceBridge.install_policy

    def gated_install(self, policy, vrf=""):
        entered.set()
        if not release.wait(timeout=5):
            raise FRRUnavailable("gate timeout")
        return real_install(self, policy, vrf=vrf)
    monkeypatch.setattr(DeviceBridge, "install_policy", gated_install)
    # the swapped factory still builds DeviceBridge instances sharing `device`
    monkeypatch.setattr(fb, "_bridge_factory",
                        lambda node="a", timeout=30.0: DeviceBridge(device, node=node))

    results = []

    def worker():
        sess = dbmod.SessionLocal()
        try:
            rel = workflow.publish_snapshot(sess, s2["id"], node="a")
            results.append(("ok", rel.id))
        except workflow.WorkflowError as e:
            results.append(("conflict", str(e)))
        finally:
            sess.close()

    t1 = threading.Thread(target=worker)
    t1.start()
    assert entered.wait(timeout=5)          # t1 is applying on the device
    t2 = threading.Thread(target=worker)    # t2 races the applying slot
    t2.start()
    time.sleep(0.1)
    release.set()
    t1.join(); t2.join()

    statuses = sorted(r[0] for r in results)
    assert statuses == ["conflict", "ok"], results
    s = dbmod.SessionLocal()
    active = [r for r in s.query(dbmod.Release)
              .filter_by(policy_id=pid, node="a", status="active").all()]
    assert len(active) == 1
    assert active[0].snapshot_id == s2["id"]
    applying = [r for r in s.query(dbmod.Release)
                .filter_by(policy_id=pid, node="a", status="applying").all()]
    assert applying == []                  # no stuck in-flight record
    s.close()


# ------------------------------------------- 4. apply failure stays retryable

def test_apply_failure_then_retry_succeeds(client, device, db):
    pid = _make_policy(client)
    s1 = _snapshot(client, pid, "v1")
    _validate(client, s1["id"]); _approve(client, s1["id"]); _publish(client, s1["id"])

    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 23},
    ]})
    s2 = _snapshot(client, pid, "v2")
    _validate(client, s2["id"]); _approve(client, s2["id"])

    device.fail_next = 1   # next install fails, then recovers
    r = _publish(client, s2["id"])
    assert r.status_code == 409

    # DB kept a failed row and the BASELINE stays active (compensated)
    rels = client.get(f"/api/policies/{pid}/releases").json()
    failed = [r for r in rels if r["status"] == "failed"]
    assert len(failed) == 1
    detail = failed[0]["detail"]
    assert "last_error" in detail and detail["compensation_ok"] is True
    assert failed[0]["attempts"] == 1
    assert _active(client, pid)["snapshot_id"] == s1["id"]

    # device is back on baseline (le 24), not a half-applied le 23
    drift = client.get(f"/api/policies/{pid}/drift").json()
    assert drift["active_snapshot_id"] == s1["id"] and drift["drift"] is False

    # retry the SAME failed record: success after recovery
    rid = failed[0]["id"]
    r = client.post(f"/api/releases/{rid}/retry")
    assert r.status_code == 200, r.text
    retried = r.json()
    assert retried["status"] == "active" and retried["attempts"] == 2
    assert retried["id"] == rid
    assert _active(client, pid)["snapshot_id"] == s2["id"]

    # old release became superseded; device holds the new config
    drift = client.get(f"/api/policies/{pid}/drift").json()
    assert drift["drift"] is False and "le 23" in drift["device_show"]


def test_unreachable_container_keeps_failed_retryable(client, monkeypatch):
    # no device fixture: bridges raise FRRUnavailable
    import app.frr_bridge as fb

    def boom(node="a", timeout=30.0):
        b = FRRBridge(node=node)
        b.connect = lambda: (_ for _ in ()).throw(
            FRRUnavailable("container down"))
        return b
    monkeypatch.setattr(fb, "_bridge_factory",
                        lambda node="a", timeout=30.0: boom(node=node))

    pid = _make_policy(client)
    s = _snapshot(client, pid)
    # validation itself fails when FRR is required and unreachable
    r = _validate(client, s["id"])
    assert r.status_code == 422
    got = client.get(f"/api/snapshots/{s['id']}").json()
    assert got["status"] == "validation_failed"
    assert "unavailable" in got["validation"]["frr"]["setup_error"]


# ------------------------------------------------------------- 5. rollback

def test_rollback_appends_new_record_and_restores(client, device):
    pid = _make_policy(client)
    probes = ["192.168.0.0/16", "192.168.100.0/24",
              "192.168.200.0/24", "8.8.8.8/32"]
    s1 = _snapshot(client, pid, "v1")
    _validate(client, s1["id"], probes=probes); _approve(client, s1["id"])
    _publish(client, s1["id"])

    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 23},
        {"seq": 30, "prefix": "192.168.100.0/24", "action": "deny"},
    ]})
    s2 = _snapshot(client, pid, "v2-tight")
    _validate(client, s2["id"]); _approve(client, s2["id"]); _publish(client, s2["id"])
    assert _active(client, pid)["snapshot_id"] == s2["id"]

    # semantic witness 192.168.100.0/24 flips between the two versions
    d = client.post("/api/snapshots/diff", json={
        "old_snapshot_id": s1["id"], "new_snapshot_id": s2["id"]}).json()
    witness = {w["prefix"]: w for w in d["witnesses"]}
    assert witness["192.168.100.0/24"]["change"] == "permit->deny"

    # rollback to the HISTORICAL snapshot -> NEW release record, no rewrite
    r = client.post(f"/api/snapshots/{s1['id']}/rollback", json={"node": "a"})
    assert r.status_code == 200, r.text
    rb = r.json()
    assert rb["kind"] == "rollback" and rb["status"] == "active"
    assert rb["snapshot_id"] == s1["id"]
    assert rb["rolled_back_release_id"] is not None

    rels = client.get(f"/api/policies/{pid}/releases").json()
    kinds = [(r["kind"], r["status"]) for r in rels]
    assert ("rollback", "active") in kinds
    # earlier records retained (superseded), never overwritten
    assert sum(1 for k, st in kinds if k == "publish") == 2
    assert all(any(r["id"] == rid for r in rels)
               for rid in (rb["rolled_back_release_id"],))

    # snapshot states: v1 live again, v2 superseded
    assert client.get(f"/api/snapshots/{s1['id']}").json()["status"] \
        == "simulated_published"
    assert client.get(f"/api/snapshots/{s2['id']}").json()["status"] \
        == "superseded"

    # witness prefix now behaves like v1 again (permit), both by simulation
    # and on the ACTUAL isolated device
    rep = client.post(f"/api/snapshots/{s1['id']}/replay",
                      json={"probes": ["192.168.100.0/24"]}).json()
    assert rep["results"][0]["final_action"] == "permit"
    drift = client.get(f"/api/policies/{pid}/drift").json()
    assert drift["drift"] is False
    assert "le 23" not in drift["device_show"]
    assert "le 24" in drift["device_show"]


def test_rollback_unknown_snapshot_rejected(client, device):
    pid = _make_policy(client)
    s = _snapshot(client, pid)
    _validate(client, s["id"]); _approve(client, s["id"]); _publish(client, s["id"])
    # a snapshot that was never published cannot be a rollback target
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "permit", "le": 32},
    ]})
    s2 = _snapshot(client, pid, "v2")
    r = client.post(f"/api/snapshots/{s2['id']}/rollback", json={"node": "a"})
    assert r.status_code == 409


# --------------------------------------------- 6. v4/v6 + default-deny hold

def test_ipv6_and_default_deny_no_regression_in_pipeline(client, device):
    pid6 = _make_policy(client, name="v6rel", family=6, default="deny", rules=[
        {"seq": 10, "prefix": "2001:db8:1::/48", "action": "deny"},
        {"seq": 20, "prefix": "2001:db8::/32", "action": "permit", "le": 40},
    ])
    s = _snapshot(client, pid6)
    r = _validate(client, s["id"], probes=[
        "2001:db8::/32", "2001:db8::/40", "2001:db8:1::/48",
        "2001:db8:2::/48", "2001:dead::/32"])
    assert r.status_code == 200, r.text
    assert r.json()["validation"]["frr"]["status"] == "match"
    _approve(client, s["id"])
    rel = _publish(client, s["id"]).json()
    assert rel["status"] == "active"

    # actual isolated config is ipv6 and default-deny behavior holds on device
    drift = client.get(f"/api/policies/{pid6}/drift").json()
    assert drift["drift"] is False
    rep = client.post(f"/api/snapshots/{s['id']}/replay", json={
        "probes": ["2001:dead::/32", "2001:db8:2::/48"]}).json()
    assert [x["final_action"] for x in rep["results"]] == ["deny", "deny"]
    assert all(x["terminal"] == "default" for x in rep["results"])


def test_validation_mismatch_fails(client):
    # FRR-required but no bridge wired at all -> validation_failed
    pid = _make_policy(client)
    s = _snapshot(client, pid)
    r = _validate(client, s["id"])
    assert r.status_code == 422
    assert client.get(f"/api/snapshots/{s['id']}").json()["status"] \
        == "validation_failed"
    # retry validation after wiring works
    import app.frr_bridge as fb
    dev = FakeFRRDevice()
    fb._bridge_factory = lambda node="a", timeout=30.0: DeviceBridge(dev, node=node)
    assert _validate(client, s["id"]).status_code == 200


# --------------------------------------------------------- state machine

def test_state_transitions_enforced(client, device):
    pid = _make_policy(client)
    s = _snapshot(client, pid)
    # cannot approve a draft
    assert _approve(client, s["id"]).status_code == 409
    # cannot publish a draft
    assert _publish(client, s["id"]).status_code == 409
    _validate(client, s["id"])
    # cannot validate->validate skip; re-validate allowed, publish still blocked
    assert _publish(client, s["id"]).status_code == 409
    _approve(client, s["id"])
    assert client.post(f"/api/snapshots/{s['id']}/approve",
                       json={"approver": "x"}).status_code == 409
    assert _publish(client, s["id"]).status_code == 200


def test_idempotency_key_reuse_different_payload_rejected(client, device):
    pid = _make_policy(client)
    s = _snapshot(client, pid)
    _validate(client, s["id"]); _approve(client, s["id"])
    h = {"Idempotency-Key": "dup-key"}
    assert client.post(f"/api/snapshots/{s['id']}/publish",
                       json={"node": "a"}, headers=h).status_code == 200
    # same key, different body fingerprint
    r = client.post(f"/api/snapshots/{s['id']}/publish",
                    json={"node": "b", "created_by": "other"}, headers=h)
    assert r.status_code == 422


# ----------------------------------------------- default-permit reconciliation

def test_default_permit_policy_validates_publishes(client, device):
    # policy with implicit default PERMIT and a couple of denies
    pid = _make_policy(client, name=None, default="permit", rules=[
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "203.0.113.0/24", "action": "deny"},
    ])
    s = _snapshot(client, pid, "permit-default")
    probes = ["10.0.0.0/8", "203.0.113.0/24", "192.0.2.1/32", "8.8.8.8/32"]
    r = _validate(client, s["id"], probes=probes)
    assert r.status_code == 200, r.text
    ev = r.json()["validation"]["frr"]
    assert ev["status"] == "match" and ev["mismatch_count"] == 0
    # fall-through probes mapped to synthesized guard and seq-normalized
    outsiders = [row for row in ev["rows"]
                 if row["prefix"] in ("192.0.2.1/32", "8.8.8.8/32")]
    assert outsiders and all(row["frr_seq"] is None for row in outsiders)
    assert any(row["synthesized_default_guard"] for row in ev["rows"])

    assert _approve(client, s["id"]).status_code == 200
    rel = _publish(client, s["id"]).json()
    assert rel["status"] == "active"
    # actual isolated device config has no synthesized guard — only real rules
    drift = client.get(f"/api/policies/{pid}/drift").json()
    assert "4294967294" not in drift["device_show"]
    # simulator semantics on the published snapshot: outsider default permit,
    # exact-rule match deny
    rep = client.post(f"/api/snapshots/{s['id']}/replay",
                      json={"probes": ["8.8.8.8/32", "10.0.0.0/8"]}).json()
    assert [x["final_action"] for x in rep["results"]] == ["permit", "deny"]


def test_cross_validate_active_snapshot_is_non_destructive(client, device):
    pid = _make_policy(client)
    s = _snapshot(client, pid)
    _validate(client, s["id"]); _approve(client, s["id"]); _publish(client, s["id"])

    # legacy cross-validate endpoint against the ACTIVE snapshot must not
    # uninstall the live config (read-only mode)
    r = client.post(f"/api/snapshots/{s['id']}/cross-validate", json={
        "probes": ["192.168.0.0/16", "8.8.8.8/32"], "node": "a"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["read_only"] is True
    drift = client.get(f"/api/policies/{pid}/drift").json()
    assert drift["drift"] is False  # live config survived the check


def test_semantic_diff_frozen_into_approval(client, device):
    pid = _make_policy(client)
    s1 = _snapshot(client, pid, "v1")
    _validate(client, s1["id"]); _approve(client, s1["id"]); _publish(client, s1["id"])
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 23},
    ]})
    s2 = _snapshot(client, pid, "v2")
    r = _validate(client, s2["id"])
    assert r.status_code == 200
    d = r.json()["validation"]["semantic_diff"]
    assert d is not None and d["baseline_snapshot_id"] == s1["id"]
    assert d["witness_count"] >= 1
    r = _approve(client, s2["id"])
    frozen = r.json()["approval"]["frozen_semantic_diff"]
    assert frozen["baseline_version"] == 1
