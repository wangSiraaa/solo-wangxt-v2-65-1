"""
FRR bridge tests.

Two layers:

1. Parser/conformance tests against CANNED outputs captured from FRR's real
   `debug ip prefix-list ... match` command format (lib/plist.c vty_out):

       ip prefix list P yields PERMIT for 192.168.1.0/24,
           matching entry #20: 192.168.0.0/16 ge 24 le 32
       ip prefix list P yields DENY for 8.8.8.8/32, no match found

2. A full cross_validate() run against a FakeBridge that implements FRR's
   exact prefix_list_apply_ext semantics in Python (ported from plist.c),
   plus randomized consistency checks between our engine and that model.
   When a REAL container is reachable (docker + rpolicy-router-a up), the
   same probes are additionally checked against live FRR — otherwise the
   live checks skip automatically.
"""
import ipaddress
import random

import pytest

from app.engine import Action, Policy, Rule, policy_from_dicts
from app.frr_bridge import FRRBridge, FRRObservation
from app.validate import cross_validate


# ----------------------------------------------------------------- parser

CANNED = {
    "permit": (
        "ip prefix list P yields PERMIT for 192.168.1.0/24, "
        "matching entry #20: 192.168.0.0/16 ge 24 le 32\n"),
    "deny_nomatch": (
        "ip prefix list P yields DENY for 8.8.8.8/32, no match found\n"),
    "deny_rule": (
        "ip prefix list P yields DENY for 172.31.0.0/16, "
        "matching entry #10: 172.31.0.0/16\n"),
}


def test_parse_canned_permit():
    b = FRRBridge.__new__(FRRBridge)
    # bypass __init__; observe only uses regex
    b.vtysh = lambda cmds, allow_warning_rc=False: CANNED["permit"]
    o = b.observe("P", 4, "192.168.1.0/24")
    assert o.action == "permit" and o.seq == 20


def test_parse_canned_deny_no_match():
    b = FRRBridge.__new__(FRRBridge)
    b.vtysh = lambda cmds, allow_warning_rc=False: CANNED["deny_nomatch"]
    o = b.observe("P", 4, "8.8.8.8/32")
    assert o.action == "deny" and o.seq is None


def test_parse_canned_deny_rule():
    b = FRRBridge.__new__(FRRBridge)
    b.vtysh = lambda cmds, allow_warning_rc=False: CANNED["deny_rule"]
    o = b.observe("P", 4, "172.31.0.0/16")
    assert o.action == "deny" and o.seq == 10


# ------------------------------------------------------ FRR behavior model

def frr_apply(rules, family, prefix_text):
    """
    Port of FRR lib/plist.c::prefix_list_apply_ext + prefix_list_entry_match.

    * containment via subnet_of
    * no ge/le  -> exact length
    * ge/le     -> ge <= plen <= le (0 == unset; CLI sets le=max for ge-only)
    * smallest seq among all matching entries
    * no match  -> DENY
    """
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


class FakeFRRBridge(FRRBridge):
    """Records install/remove calls; answers from the FRR behavior port."""
    def __init__(self, policy_provider, *a, **kw):
        super().__init__(*a, **kw)
        self._provider = policy_provider
        self.installed = {}
        self.shown = []

    def connect(self):
        return self

    def close(self):
        pass

    def install_policy(self, policy, vrf=""):
        # FRR CLI normalization of ge-only -> le=maxlen
        self.installed[(policy.name, policy.family)] = policy
        return ""

    def remove_policy(self, name, family, vrf=""):
        self.installed.pop((name, family), None)
        return ""

    def show_prefix_list(self, name, family):
        p = self.installed[(name, family)]
        lines = [f"ip prefix-list {name}: {len(p.rules)} entries"]
        for r in p.rules:
            ge = f" ge {r.ge}" if r.ge is not None else ""
            le = f" le {r.le}" if r.le is not None else ""
            lines.append(f"   seq {r.seq} {r.action.value} {r.prefix}{ge}{le}")
        self.shown.append("\n".join(lines))
        return "\n".join(lines)

    def observe(self, name, family, prefix, vrf=""):
        p = self.installed[(name, family)]
        action, seq = frr_apply(p.rules, family, prefix)
        if seq is None:
            raw = (f"ip prefix list {name} yields DENY for {prefix}, "
                   "no match found")
        else:
            raw = (f"ip prefix list {name} yields {action.upper()} for "
                   f"{prefix}, matching entry #{seq}")
        return FRRObservation(prefix, action, seq, raw)


# ----------------------------------------------------------- cross-validate

def test_cross_validate_matches_frr_model_seed_scenarios():
    scenarios = [
        policy_from_dicts("over-permit", [
            {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
            {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 24},
        ]),
        policy_from_dicts("reorder", [
            {"seq": 5, "prefix": "172.16.0.0/12", "action": "permit", "le": 32},
            {"seq": 10, "prefix": "172.31.0.0/16", "action": "deny"},
        ]),
        Policy("default-flip",
               [Rule(10, "203.0.113.0/24", Action.DENY)], Action.DENY),
    ]
    probes = [
        "192.168.0.0/16", "192.168.100.0/24", "10.1.2.3/32",
        "172.16.0.0/12", "172.31.0.0/16", "172.31.5.0/24", "172.32.0.0/16",
        "203.0.113.0/24", "8.8.8.8/32",
    ]
    for pol in scenarios:
        br = FakeFRRBridge(None, node="a")
        out = cross_validate(pol, probes, bridge=br, remove_after=True)
        assert out["status"] == "match", out["mismatches"]
        assert out["mismatch_count"] == 0
        assert br.installed == {}          # removed after run


def test_cross_validate_randomized_400():
    rng = random.Random(2026)

    def randpol():
        # sample base prefixes WITHOUT replacement (rejection sampling can
        # spin forever once the small candidate pool is exhausted)
        n = rng.randint(1, 7)
        candidates = []
        for d in range(0, 7):
            for i in range(1 << d):
                candidates.append(
                    str(ipaddress.ip_network((i << (32 - d), d))))
        rng.shuffle(candidates)
        rules = []
        for k in range(n):
            base = candidates[k]
            d = ipaddress.ip_network(base).prefixlen
            ge = le = None
            c = rng.random()
            if c < 0.3:
                ge = rng.randint(d + 1, 12)
                if rng.random() < 0.5:
                    le = rng.randint(ge, 12)
            elif c < 0.5:
                le = rng.randint(d + 1, 12)
            rules.append(Rule((k + 1) * 10, base,
                              rng.choice([Action.PERMIT, Action.DENY]),
                              ge=ge, le=le))
        return Policy("r", rules, Action.DENY)

    def probes_for(p):
        # probes: rule bases plus a couple of longer subnets bounded by the
        # rule windows, plus outsiders — kept small on purpose.
        ps = []
        for r in p.rules:
            ps.append(str(r.net))
            d = r.net.prefixlen
            hi = min(d + 2, 12)
            cur = [r.net]
            while cur and cur[0].prefixlen < hi:
                cur = list(cur[0].subnets())
                ps.append(str(cur[0]))
            # one address-length probe if window reaches /32
            if r.max_len >= 20:
                addr = int(r.net.network_address)
                ps.append(str(ipaddress.ip_network((addr, 20))))
        ps += ["8.8.8.8/32", "1.1.1.1/32", "224.0.0.0/4",
               "192.0.2.0/24", "198.51.100.0/24"]
        return list(dict.fromkeys(ps))

    for _ in range(400):
        pol = randpol()
        br = FakeFRRBridge(None)
        out = cross_validate(pol, probes_for(pol), bridge=br)
        assert out["status"] == "match", out["mismatches"][:3]


def test_empty_policy_is_setup_error_not_silent_match():
    br = FakeFRRBridge(None)
    out = cross_validate(Policy("empty", [], Action.DENY, family=4),
                         ["10.0.0.0/8"], bridge=br)
    assert out["status"] == "error"
    assert "zero rules" in out["setup_error"]


# ----------------------------------------------------------- live container

def _docker_available():
    import shutil
    import subprocess
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(
            ["docker", "exec", "rpolicy-router-a", "true"],
            capture_output=True, timeout=5)
        return r.returncode == 0
    except OSError:
        return False


@pytest.mark.skipif(not _docker_available(),
                    reason="FRR container rpolicy-router-a not running "
                           "(docker compose -f frr/docker-compose.yml up -d)")
def test_live_frr_consistency():
    pol = policy_from_dicts("consistency-check", [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit",
         "ge": 24, "le": 32},
        {"seq": 30, "prefix": "172.31.0.0/16", "action": "deny"},
        {"seq": 40, "prefix": "172.16.0.0/12", "action": "permit",
         "le": 32},
    ])
    probes = [
        "10.1.2.3/32", "192.168.0.0/16", "192.168.1.0/24",
        "192.168.1.0/23", "172.31.0.0/16", "172.20.0.0/16",
        "172.32.0.0/16", "8.8.8.8/32",
    ]
    br = FRRBridge(node="a")
    out = cross_validate(pol, probes, bridge=br)
    assert out["status"] == "match", out
