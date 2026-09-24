"""End-to-end API tests: edit -> snapshot -> diff -> replay."""
import pytest


def _make(client, name, family=4, default="deny"):
    r = client.post("/api/policies", json={
        "name": name, "family": family, "default_action": default})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _rules(client, pid, rules, default=None):
    r = client.put(f"/api/policies/{pid}/rules",
                   json={"rules": rules, "default_action": default})
    assert r.status_code == 200, r.text
    return r.json()


def test_policy_crud_and_validation(client):
    pid = _make(client, "t1")
    p = _rules(client, pid, [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "permit", "le": 24},
    ])
    assert len(p["rules"]) == 1

    r = client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 1, "prefix": "10/8", "action": "permit", "ge": 5, "le": 3},
    ]})
    assert r.status_code == 422
    assert "ge" in r.json()["detail"]


def test_mixed_family_rejected(client):
    pid = _make(client, "v6pol", family=6)
    r = client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "permit"},
    ]})
    assert r.status_code == 422 and "families" in r.json()["detail"]

    _rules(client, pid, [
        {"seq": 10, "prefix": "2001:db8::/32", "action": "permit", "le": 48},
    ])
    r = client.post(f"/api/policies/{pid}/classify", json={"prefix": "10.0.0.0/8"})
    assert r.status_code == 422


def test_shadow_endpoint(client):
    pid = _make(client, "shadow")
    _rules(client, pid, [
        {"seq": 5, "prefix": "172.16.0.0/12", "action": "permit", "le": 32},
        {"seq": 10, "prefix": "172.31.0.0/16", "action": "deny"},
    ])
    a = client.get(f"/api/policies/{pid}/analyze").json()
    assert a["fully_shadowed"] == [10]


def test_hit_chain_endpoint(client):
    pid = _make(client, "chain")
    _rules(client, pid, [
        {"seq": 10, "prefix": "172.31.0.0/16", "action": "deny", "le": 32},
        {"seq": 20, "prefix": "172.16.0.0/12", "action": "permit", "le": 32},
    ])
    h = client.post(f"/api/policies/{pid}/classify",
                    json={"prefix": "172.31.5.0/24"}).json()
    assert h["final_action"] == "deny" and h["matched_seq"] == 10
    assert len(h["trie_path"]) == 25   # /0 ../24
    assert h["chain"][0]["matched"] is True


def test_snapshot_diff_replay(client):
    pid = _make(client, "flip", default="permit")
    _rules(client, pid, [
        {"seq": 10, "prefix": "203.0.113.0/24", "action": "deny"},
    ])
    s1 = client.post(f"/api/policies/{pid}/snapshots",
                     json={"label": "before"}).json()

    client.put(f"/api/policies/{pid}/rules", json={
        "rules": [
            {"seq": 10, "prefix": "203.0.113.0/24", "action": "deny"},
            {"seq": 20, "prefix": "198.51.100.0/24", "action": "permit"},
        ],
        "default_action": "deny",
    })
    s2 = client.post(f"/api/policies/{pid}/snapshots",
                     json={"label": "after"}).json()

    d = client.post("/api/snapshots/diff", json={
        "old_snapshot_id": s1["id"], "new_snapshot_id": s2["id"]}).json()
    assert d["witness_count"] == 1
    assert d["witnesses"][0]["prefix"] == "0.0.0.0/0"
    assert d["witnesses"][0]["change"] == "permit->deny"

    rep = client.post(f"/api/snapshots/{s2['id']}/replay", json={
        "probes": ["104.16.0.0/12", "203.0.113.0/24", "198.51.100.0/24"]}).json()
    assert [r["final_action"] for r in rep["results"]] == \
           ["deny", "deny", "permit"]
    # ordered replay
    assert [r["order"] for r in rep["results"]] == [0, 1, 2]


def test_scenario_persistence_and_replay(client):
    pid = _make(client, "sc")
    _rules(client, pid, [{"seq": 10, "prefix": "10/8", "action": "deny"}])
    s = client.post(f"/api/policies/{pid}/snapshots", json={"label": "v1"}).json()
    r = client.post("/api/scenarios", json={
        "name": "case-1", "from_snapshot_id": s["id"],
        "probes": ["10.0.0.0/8", "11.0.0.0/8"]})
    assert r.status_code == 201
    scid = r.json()["id"]
    out = client.post(f"/api/scenarios/{scid}/replay").json()
    assert [x["final_action"] for x in out["from"]["results"]] == ["deny", "deny"]


def test_batch_error_isolation(client):
    pid = _make(client, "batch")
    _rules(client, pid, [{"seq": 10, "prefix": "10/8", "action": "permit",
                          "le": 32}])
    out = client.post(f"/api/policies/{pid}/classify/batch", json={
        "probes": ["10.1.0.0/16", "junk", "11.0.0.0/8"]}).json()
    assert out["results"][0]["final_action"] == "permit"
    assert "error" in out["results"][1]
    assert out["results"][2]["final_action"] == "deny"


def test_trie_view(client):
    pid = _make(client, "tree")
    _rules(client, pid, [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "permit"},
        {"seq": 20, "prefix": "10.1.0.0/16", "action": "deny"},
    ])
    t = client.get(f"/api/policies/{pid}/trie").json()
    assert t["root"] == "0.0.0.0/0"
    assert "10.0.0.0/8" in t["nodes"]
    assert "10.1.0.0/16" in t["nodes"]
    assert t["nodes"]["10.1.0.0/16"]["rules"][0]["seq"] == 20
