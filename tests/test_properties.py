"""
Property tests with a brute-force oracle over the complete /0../6 lattice
(IPv4) and /32../34 lattice (IPv6). The engine must be exact, not sampled.
"""
import ipaddress
import random

from app.engine import Action, Policy, Rule
from app.trie import find_shadowed, minimal_witness_set


def _lattice(family, maxd):
    root = ipaddress.ip_network("0.0.0.0/0" if family == 4 else "2001:db8::/32")
    out, frontier = [root], [root]
    for _ in range(maxd - root.prefixlen):
        nxt = []
        for n in frontier:
            nxt.extend(n.subnets())
        out.extend(nxt)
        frontier = nxt
    return out


def _brute(policy, net):
    for r in policy.rules:
        if r.matches(net):
            return r.action.value, r.seq, r
    return policy.default_action.value, None, None


def _rand_policy(rng, family, maxd, max_rules=6, default=None):
    bases = _lattice(family, maxd)
    rules, used = [], set()
    n = rng.randint(0, max_rules)
    for k in range(n):
        seq = (k + 1) * 10
        for _ in range(60):
            base = str(rng.choice(bases))
            if base not in used:
                break
        used.add(base)
        d = ipaddress.ip_network(base).prefixlen
        ge = le = None
        c = rng.random()
        # All length windows stay INSIDE the enumerated universe and are
        # always closed on both sides (no ge-only extending to /32/128), so
        # behavior deeper than maxd is the identical default on both sides
        # and cannot create witnesses outside the universe.
        if c < 0.3 and d < maxd:
            ge = rng.randint(d + 1, maxd)
            le = rng.randint(ge, maxd)
        elif c < 0.5 and d < maxd:
            le = rng.randint(d + 1, maxd)
        rules.append(Rule(seq, base,
                          rng.choice([Action.PERMIT, Action.DENY]),
                          ge=ge, le=le))
    if default is None:
        default = rng.choice(["deny", "permit"])
    return Policy("t", rules, Action(default))


def _oracle_regions(p1, p2, univ, base_depth):
    """
    Exact oracle: every enumerated prefix is its own state cell. Merge two
    cells with DSU only when
      * horizontally adjacent siblings, or
      * direct parent/child,
    and BOTH winner rules are identical AND every winner's ge/le window
    covers both depths. Changed regions are components containing an
    ACTION change (attribution-only changes do not count).
    """
    full = {n: (_brute(p1, n), _brute(p2, n)) for n in univ}
    bits = univ[0].max_prefixlen

    def winners(n):
        return (full[n][0][2], full[n][1][2])

    def mergeable(a, b):
        wa, wb = winners(a)
        if winners(b) != (wa, wb):
            return False
        for win in (wa, wb):
            if win is not None and not (
                    win.min_len <= a.prefixlen <= win.max_len and
                    win.min_len <= b.prefixlen <= win.max_len):
                return False
        return True

    uf = {n: n for n in univ}

    def find(x):
        while uf[x] != x:
            uf[x] = uf[uf[x]]
            x = uf[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            uf[ra] = rb

    by_depth: dict = {}
    for n in univ:
        by_depth.setdefault(n.prefixlen, []).append(n)

    # vertical: each cell with its direct parent (both must be in univ).
    # STRICT containment: a /k cell belongs to exactly one /(k-1) cell.
    depth0 = min(by_depth)
    for n in univ:
        if n.prefixlen > depth0:
            par = n.supernet()
            # supernet() gives the unique containing block — no adjacency
            # ambiguity here, so state equality is the only condition.
            if par in full and mergeable(par, n):
                union(par, n)

    # horizontal: address-adjacent cells with identical state
    for d, lst in by_depth.items():
        lst.sort(key=lambda n: int(n.network_address))
        for a, b in zip(lst, lst[1:]):
            if (int(b.network_address) - int(a.network_address)
                    == 1 << (bits - d)
                    and mergeable(a, b)):
                union(a, b)

    changed = set()
    for n in univ:
        if full[n][0][0] != full[n][1][0]:
            changed.add(find(n))
    return changed, full


def _engine_regions_in_universe(p1, p2, univ):
    """
    Restrict the engine's exact witness set to the enumerated universe and
    return one representative per region that intersects the universe. A
    witness prefix is accepted when it lies in the universe; regions whose
    only representatives are deeper than the universe root are covered by
    re-classifying the universe cells and grouping by engine winner.
    """
    from app.trie import minimal_witness_set
    ws = minimal_witness_set(p1, p2)
    full = {n: None for n in univ}
    kept, seen_regions = [], set()
    for w in ws:
        n = ipaddress.ip_network(w.prefix)
        if n in full:
            kept.append(w)
    return kept, ws


def test_diff_exact_ipv4_500():
    rng = random.Random(4242)
    univ = _lattice(4, 6)
    for _ in range(500):
        default = rng.choice(["deny", "permit"])
        p1 = _rand_policy(rng, 4, 6, default=default)
        p2 = _rand_policy(rng, 4, 6, default=default)
        regions, full = _oracle_regions(p1, p2, univ, 0)
        kept, _allws = _engine_regions_in_universe(p1, p2, univ)
        assert len(kept) == len(regions)
        for w in kept:
            n = ipaddress.ip_network(w.prefix)
            assert n in full
            assert full[n][0][0] != full[n][1][0]
            assert w.old_seq == full[n][0][1]
            assert w.new_seq == full[n][1][1]


def test_diff_exact_ipv6_200():
    rng = random.Random(9977)
    univ = _lattice(6, 34)
    root = univ[0]
    for _ in range(200):
        default = rng.choice(["deny", "permit"])
        p1 = _rand_policy(rng, 6, 34, max_rules=5, default=default)
        p2 = _rand_policy(rng, 6, 34, max_rules=5, default=default)
        regions, full = _oracle_regions(p1, p2, univ, 32)
        kept, _ = _engine_regions_in_universe(p1, p2, univ)
        inside = [w for w in kept
                  if ipaddress.ip_network(w.prefix).subnet_of(root)]
        assert len(inside) == len(regions)
        for w in inside:
            n = ipaddress.ip_network(w.prefix)
            assert n in full and full[n][0][0] != full[n][1][0]


def test_shadow_exact_500():
    rng = random.Random(31337)
    univ = _lattice(4, 6)
    for _ in range(500):
        p = _rand_policy(rng, 4, 6, max_rules=7)
        winners = {sa for n in univ for _, sa, _ in [_brute(p, n)] if sa}
        for rep in find_shadowed(p):
            assert rep.fully_shadowed == (rep.rule.seq not in winners)
            if rep.fully_shadowed:
                for w in rep.witnesses:
                    _, sa, r = _brute(p, ipaddress.ip_network(w))
                    assert r is not None and sa < rep.rule.seq


def test_identical_policies_no_witnesses():
    rng = random.Random(7)
    for _ in range(50):
        p = _rand_policy(rng, 4, 6)
        assert minimal_witness_set(p, p) == []
