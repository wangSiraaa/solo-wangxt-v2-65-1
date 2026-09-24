"""
Engine semantics: exact prefix, ge/le ranges, first-match, default deny,
v4/v6 isolation; plus the three required worked scenarios at decision level.
"""
import ipaddress

import pytest

from app.engine import (
    Action, Policy, Rule, PolicyError, policy_from_dicts,
)
from app.trie import find_shadowed, minimal_witness_set


# ---------------------------------------------------------------- basics

def test_exact_match():
    p = Policy("p", [Rule(10, "10.0.0.0/8", Action.PERMIT)], Action.DENY)
    assert p.classify("10.0.0.0/8").final_action == Action.PERMIT
    # longer prefix inside the /8 but != /8 -> no match without ge/le
    assert p.classify("10.1.0.0/16").terminal == "default"
    assert p.classify("10.1.2.3/32").final_action == Action.DENY
    # outside
    assert p.classify("11.0.0.0/8").terminal == "default"


def test_ge_le_window():
    p = Policy("p", [
        Rule(10, "192.168.0.0/16", Action.PERMIT, ge=24, le=32),
    ])
    assert p.classify("192.168.0.0/16").terminal == "default"       # too short
    assert p.classify("192.168.0.0/23").terminal == "default"
    assert p.classify("192.168.1.0/24").final_action == Action.PERMIT
    assert p.classify("192.168.1.128/25").final_action == Action.PERMIT
    assert p.classify("192.168.1.1/32").final_action == Action.PERMIT


def test_ge_only_extends_to_maxlen():
    p = Policy("p", [Rule(10, "10.0.0.0/8", Action.PERMIT, ge=9)])
    r = p.rules[0]
    assert r.min_len == 9 and r.max_len == 32       # Cisco normalization
    assert p.classify("10.0.0.0/8").terminal == "default"
    assert p.classify("10.0.0.0/9").final_action == Action.PERMIT
    assert p.classify("10.255.255.255/32").final_action == Action.PERMIT


def test_le_only_without_ge_starts_at_base_len():
    p = Policy("p", [Rule(10, "10.0.0.0/8", Action.PERMIT, le=24)])
    r = p.rules[0]
    assert r.min_len == 8 and r.max_len == 24
    assert p.classify("10.0.0.0/8").final_action == Action.PERMIT
    assert p.classify("10.1.0.0/16").final_action == Action.PERMIT
    assert p.classify("10.1.0.0/25").terminal == "default"


def test_first_match_wins_in_seq_order():
    p = Policy("p", [
        Rule(10, "172.16.0.0/12", Action.PERMIT, le=32),
        Rule(20, "172.31.0.0/16", Action.DENY),
    ])
    # seq 10 wins -> permit even though seq 20 also matches
    assert p.classify("172.31.0.0/16").rule.seq == 10
    # after swap (same lines, seq 5 permit first)
    p2 = Policy("p", [
        Rule(5, "172.16.0.0/12", Action.PERMIT, le=32),
        Rule(10, "172.31.0.0/16", Action.DENY),
    ])
    assert p2.classify("172.31.0.0/16").rule.seq == 5
    assert p2.classify("172.31.0.0/16").final_action == Action.PERMIT


def test_default_deny_and_default_permit():
    deny = Policy("d", [Rule(10, "10/8", Action.PERMIT)], Action.DENY)
    permit = Policy("a", [Rule(10, "10/8", Action.DENY)], Action.PERMIT)
    assert deny.classify("8.8.8.8/32").final_action == Action.DENY
    assert permit.classify("8.8.8.8/32").final_action == Action.PERMIT
    assert deny.classify("8.8.8.8/32").chain[-1].reason.startswith("end of policy")


def test_family_isolation_classify():
    p6 = Policy("v6", [Rule(10, "2001:db8::/32", Action.PERMIT, le=48)])
    assert p6.classify("2001:db8:1::/48").final_action == Action.PERMIT
    with pytest.raises(PolicyError, match="families"):
        p6.classify("10.0.0.0/8")


def test_family_isolation_construction():
    with pytest.raises(PolicyError, match="must not be mixed"):
        Policy("x", [
            Rule(10, "10.0.0.0/8", Action.PERMIT),
            Rule(20, "2001:db8::/32", Action.DENY),
        ])


def test_validation_errors():
    with pytest.raises(PolicyError):
        Rule(10, "10.0.0.0/8", Action.PERMIT, ge=5, le=7)     # ge < base len
    with pytest.raises(PolicyError):
        Rule(10, "10.0.0.0/8", Action.PERMIT, ge=20, le=19)  # ge > le
    with pytest.raises(ValueError):
        Rule(10, "not-a-prefix", Action.PERMIT)
    with pytest.raises(ValueError):
        Rule(10, "10.0.0.1/8", Action.PERMIT)                # host bits set


def test_chain_explains_skips():
    p = Policy("p", [
        Rule(10, "10.0.0.0/8", Action.DENY),
        Rule(20, "192.168.0.0/16", Action.PERMIT, ge=24, le=32),
    ])
    h = p.classify("192.168.0.0/16")
    # seq10: outside containment; seq20: contained but length out of window
    assert h.chain[0].contained is False
    assert h.chain[1].contained and h.chain[1].length_ok is False
    assert h.terminal == "default"


# ---------------------------------------------------------------- shadowing

def test_full_shadow_detected():
    # broad permit at seq 5 makes the later deny unreachable
    p = Policy("p", [
        Rule(5, "172.16.0.0/12", Action.PERMIT, le=32),
        Rule(10, "172.31.0.0/16", Action.DENY),
    ])
    reps = {s.rule.seq: s for s in find_shadowed(p)}
    assert reps[10].fully_shadowed is True
    assert reps[10].witnesses                 # concrete prefixes, nonempty
    for w in reps[10].witnesses:
        h = p.classify(w)
        assert h.rule is not None and h.rule.seq < 10
    # healthy order: narrow deny first
    ok = Policy("ok", [
        Rule(10, "172.31.0.0/16", Action.DENY),
        Rule(20, "172.16.0.0/12", Action.PERMIT, le=32),
    ])
    assert not any(s.fully_shadowed for s in find_shadowed(ok))


def test_window_shadow_vs_exact():
    # broad earlier rule covers the whole /8 in lengths 8..24: both later
    # rules (exact /16 and /16 ge20..24) live inside that region -> shadowed
    p = Policy("p", [
        Rule(10, "10.0.0.0/8", Action.DENY, le=24),
        Rule(20, "10.1.0.0/16", Action.PERMIT),
        Rule(30, "10.2.0.0/16", Action.PERMIT, ge=20, le=24),
    ])
    reps = {s.rule.seq: s for s in find_shadowed(p)}
    assert reps[20].fully_shadowed is True    # exact /16 denied by seq10
    assert reps[30].fully_shadowed is True    # whole window inside seq10 deny
    # and a healthy rule outside seq10's window survives:
    p2 = Policy("p2", [
        Rule(10, "10.0.0.0/8", Action.DENY, le=16),
        Rule(20, "10.2.0.0/16", Action.PERMIT, ge=20, le=24),
    ])
    reps2 = {s.rule.seq: s for s in find_shadowed(p2)}
    assert reps2[20].fully_shadowed is False
    assert p2.classify("10.2.0.0/20").final_action == Action.PERMIT


# ------------------------------------------------------ the three scenarios

def test_scenario_over_permit():
    before = policy_from_dicts("op", [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 24},
    ])
    after = policy_from_dicts("op", [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 23},
        {"seq": 30, "prefix": "192.168.100.0/24", "action": "deny"},
    ])
    # before: the more-specific DC prefix is wrongly permitted
    assert before.classify("192.168.100.0/24").final_action == Action.PERMIT
    # after: it is denied (both by tighter le AND explicit guard first-match)
    assert after.classify("192.168.100.0/24").final_action == Action.DENY
    ws = minimal_witness_set(before, after)
    changed = {w.prefix: w.change for w in ws}
    assert any(c == "permit->deny" for c in changed.values())
    # all witnesses are genuine changes
    for w in ws:
        n = ipaddress.ip_network(w.prefix)
        assert before.classify(str(n)).final_action != \
               after.classify(str(n)).final_action


def test_scenario_reorder():
    before = policy_from_dicts("ro", [
        {"seq": 10, "prefix": "172.31.0.0/16", "action": "deny"},
        {"seq": 20, "prefix": "172.16.0.0/12", "action": "permit", "le": 32},
    ])
    after = policy_from_dicts("ro", [
        {"seq": 5, "prefix": "172.16.0.0/12", "action": "permit", "le": 32},
        {"seq": 10, "prefix": "172.31.0.0/16", "action": "deny"},
    ])
    assert before.classify("172.31.0.0/16").final_action == Action.DENY
    assert after.classify("172.31.0.0/16").final_action == Action.PERMIT
    ws = minimal_witness_set(before, after)
    assert len(ws) >= 1
    w = ws[0]
    assert w.change == "deny->permit"
    # seq20/seq10 becomes fully shadowed after the swap
    assert any(s.fully_shadowed for s in find_shadowed(after))


def test_scenario_default_flip():
    before = Policy("df", [Rule(10, "203.0.113.0/24", Action.DENY)],
                    Action.PERMIT)
    after = policy_from_dicts("df", [
        {"seq": 10, "prefix": "203.0.113.0/24", "action": "deny"},
        {"seq": 20, "prefix": "198.51.100.0/24", "action": "permit"},
    ], default_action="deny")
    # unrelated prefixes flip
    assert before.classify("104.16.0.0/12").final_action == Action.PERMIT
    assert after.classify("104.16.0.0/12").final_action == Action.DENY
    ws = minimal_witness_set(before, after)
    # the broadest possible witness
    assert ws[0].prefix == "0.0.0.0/0"
    assert ws[0].change == "permit->deny"


# ---------------------------------------------------------------- v6

def test_ipv6_ge_le():
    p = policy_from_dicts("v6", [
        # narrow deny must precede the broad permit to be reachable
        {"seq": 5, "prefix": "2001:db8:1::/48", "action": "deny"},
        {"seq": 10, "prefix": "2001:db8::/32", "action": "permit",
         "ge": 40, "le": 48},
    ], family=6)
    assert p.classify("2001:db8::/32").terminal == "default"
    assert p.classify("2001:db8::/40").final_action == Action.PERMIT
    assert p.classify("2001:db8:2::/48").final_action == Action.PERMIT
    assert p.classify("2001:db8:1::/48").final_action == Action.DENY
    assert p.classify("2001:db8:1::/64").terminal == "default"


def test_text_only_change_yields_no_witnesses():
    # identical behavior, only remark text differs
    a = policy_from_dicts("x", [
        {"seq": 10, "prefix": "10/8", "action": "permit", "le": 24,
         "remark": "old note"}])
    b = policy_from_dicts("x", [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "permit", "le": 24,
         "remark": "new note"}])
    assert minimal_witness_set(a, b) == []


def test_frr_rendering():
    p = policy_from_dicts("x", [
        {"seq": 5, "prefix": "172.16.0.0/12", "action": "permit", "le": 32},
        {"seq": 10, "prefix": "172.31.0.0/16", "action": "deny"},
    ])
    out = p.to_frr_prefix_list()
    assert out.splitlines() == [
        "ip prefix-list x seq 5 permit 172.16.0.0/12 le 32",
        "ip prefix-list x seq 10 deny 172.31.0.0/16",
    ]
