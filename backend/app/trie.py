"""
Exact trie algorithms for shadow analysis and semantic policy diff.

Prefix space is partitioned into *cells* inside which every rule's match
result is constant.  Partition cuts come from:

  1. base prefix boundaries (containment edges),
  2. ge/le length-range boundaries (min_len / max_len + 1).

Because depths only go to 32 / 128 and rule counts are in the low hundreds,
a binary trie (one node per address bit along inserted bases) plus a length
scan <= 128 is fast enough and stays fully exact — nothing is sampled.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import ipaddress

from .engine import (
    Action, Policy, PolicyError, Rule, ShadowReport, Witness, MAXLEN,
)


@dataclass
class TrieNode:
    depth: int
    net: ipaddress._BaseNetwork
    child0: Optional["TrieNode"] = None
    child1: Optional["TrieNode"] = None
    rules_a: List[Rule] = field(default_factory=list)   # policy A
    rules_b: List[Rule] = field(default_factory=list)   # policy B (diff only)

    def children(self) -> List["TrieNode"]:
        return [c for c in (self.child0, self.child1) if c is not None]


def _root_net(family: int) -> ipaddress._BaseNetwork:
    return ipaddress.ip_network("0.0.0.0/0" if family == 4 else "::/0")


def build_trie(family: int,
               rules_a: List[Rule],
               rules_b: Optional[List[Rule]] = None) -> TrieNode:
    maxlen = MAXLEN[family]
    root = TrieNode(0, _root_net(family))

    def insert(rule: Rule, bucket: str):
        node = root
        net = rule.net
        for depth, bit in enumerate(
                f"{int(net.network_address):0{maxlen}b}"[:net.prefixlen], start=1):
            nxt = node.child0 if bit == "0" else node.child1
            if nxt is None:
                shift = maxlen - depth
                addr_int = (int(net.network_address) >> shift) << shift
                nxt = TrieNode(depth, ipaddress.ip_network((addr_int, depth)))
                if bit == "0":
                    node.child0 = nxt
                else:
                    node.child1 = nxt
            node = nxt
        getattr(node, bucket).append(rule)

    for r in rules_a:
        insert(r, "rules_a")
    for r in (rules_b or []):
        insert(r, "rules_b")
    return root


def _locate(root: TrieNode, net: ipaddress._BaseNetwork) -> TrieNode:
    node = root
    maxlen = net.max_prefixlen
    for bit in f"{int(net.network_address):0{maxlen}b}"[:net.prefixlen]:
        node = node.child0 if bit == "0" else node.child1
    return node


def _winner(depth: int, active: List[Rule]) -> Optional[Rule]:
    """First matching rule among active (active kept in seq order)."""
    for r in active:
        if r.min_len <= depth <= r.max_len:
            return r
    return None


def _gap_block(node: TrieNode, k: int, maxlen: int) -> Optional[ipaddress._BaseNetwork]:
    """
    A /k prefix inside node's subtree but outside every direct-child subtree,
    or None when direct children completely cover node at depth k.
    """
    total = 1 << (k - node.depth)
    node_int = int(node.net.network_address)
    intervals: List[Tuple[int, int]] = []
    for ch in node.children():
        if ch.depth > k:
            continue                                  # /k is child's supernet
        start = (int(ch.net.network_address) - node_int) >> (maxlen - k)
        span = 1 << (k - ch.depth)
        intervals.append((start, start + span))
    intervals.sort()
    cursor = 0
    for start, end in intervals:
        if start > cursor:
            break
        cursor = max(cursor, end)
        if cursor >= total:
            return None
    return ipaddress.ip_network((node_int + (cursor << (maxlen - k)), k))


# ---------------------------------------------------------------------------
# Shadow detection
# ---------------------------------------------------------------------------

def _pairwise_partial_overlaps(rules: List[Rule]) -> dict:
    """Earlier seq numbers whose match region intersects each rule at all."""
    overlaps: dict = {r.seq: set() for r in rules}
    for i, r in enumerate(rules):
        for e in rules[:i]:
            nets_overlap = r.net.subnet_of(e.net) or e.net.subnet_of(r.net)
            lens_overlap = r.min_len <= e.max_len and e.min_len <= r.max_len
            if nets_overlap and lens_overlap:
                overlaps[r.seq].add(e.seq)
    return overlaps


def find_shadowed(policy: Policy, witness_cap: int = 20) -> List[ShadowReport]:
    if policy.family is None:
        return []
    maxlen = MAXLEN[policy.family]
    ordered = policy.rules                      # already seq-sorted
    root = build_trie(policy.family, ordered)
    partial = _pairwise_partial_overlaps(ordered)

    # ---- pass 1: one global walk; a rule is reachable iff it wins a cell --
    reachable: set = set()

    def mark(node: TrieNode, active: List[Rule], depth: int):
        w = _winner(depth, active)
        if w is not None:
            reachable.add(w.seq)

    def dfs_reach(node: TrieNode, active: List[Rule]):
        rules = sorted(active + node.rules_a, key=lambda r: r.seq)
        mark(node, rules, node.depth)
        for k in range(node.depth + 1, maxlen + 1):
            if _gap_block(node, k, maxlen) is None:
                continue
            mark(node, rules, k)
        for ch in node.children():
            dfs_reach(ch, rules)

    dfs_reach(root, [])

    # ---- pass 2: per shadowed rule, sample prefixes of its covered region -
    def covered_samples(rule: Rule) -> List[str]:
        earlier = ordered[:ordered.index(rule)]
        start = _locate(root, rule.net)
        ancestors = sorted(
            (e for e in earlier if e.net.supernet_of(rule.net)),
            key=lambda r: r.seq,
        )
        samples: List[str] = []

        def walk(n: TrieNode, act: List[Rule]):
            if len(samples) >= witness_cap:
                return
            added = [e for e in n.rules_a if e.seq < rule.seq and e not in act]
            act2 = sorted(act + added, key=lambda r: r.seq)

            if rule.min_len <= n.depth <= rule.max_len and _winner(n.depth, act2):
                samples.append(str(n.net))
            if len(samples) >= witness_cap:
                return

            for kk in range(max(n.depth + 1, rule.min_len),
                            min(rule.max_len, maxlen) + 1):
                if _winner(kk, act2) is None:
                    continue                          # uncovered -> bail: rule live
                    # (cannot happen for fully-shadowed; defensive early stop)
                block = _gap_block(n, kk, maxlen)
                if block is not None:
                    samples.append(str(block))
                    if len(samples) >= witness_cap:
                        return
            for ch in n.children():
                walk(ch, act2)

        walk(start, ancestors)
        return samples

    reports: List[ShadowReport] = []
    for rule in ordered:
        shadowed = rule.seq not in reachable
        reports.append(ShadowReport(
            rule=rule,
            fully_shadowed=shadowed,
            partial_shadowed_by=sorted(partial[rule.seq]),
            witnesses=covered_samples(rule) if shadowed else [],
        ))
    return reports


# ---------------------------------------------------------------------------
# Semantic diff: minimal witness prefix set between two policies
# ---------------------------------------------------------------------------

def minimal_witness_set(old: Policy, new: Policy) -> List[Witness]:
    """
    Minimal prefix set that demonstrates every behavior change.

    Method (fully exact, no sampling):

    1. For every depth k = 0..maxlen the address axis [0, 2^k) is tiled by
       SEGMENTS.  A block at depth k is decided either by a trie node cell
       (a rule base sits exactly there) or by the nearest ancestor node's
       GAP region (the part of its subtree outside direct-child subtrees).
       Each segment carries a state signature (old winner seq, new winner
       seq); a segment with different old/new actions is a changed segment.
    2. Segments are merged into maximal uniform regions with a DSU:
         * horizontally: two consecutive /k blocks with the same signature;
         * vertically:   a /k segment contained in the /(k-1) segment with
                         the same signature.
       This deliberately ignores trie nodes whose rules never win anything
       (shadowed bases cannot split a behavior region).
    3. One witness prefix per changed region (its first member block).
    """
    fam = old.family or new.family
    if fam is None:
        return []
    if old.family is not None and new.family is not None and old.family != new.family:
        raise PolicyError("cannot diff IPv4 policy against IPv6 policy")
    maxlen = MAXLEN[fam]

    root = build_trie(family=fam, rules_a=old.rules, rules_b=new.rules)

    def state_at(k: int, act_a, act_b):
        wa = _winner(k, act_a)
        wb = _winner(k, act_b)
        aa = wa.action if wa else old.default_action
        ab = wb.action if wb else new.default_action
        return wa, wb, aa, ab

    # row[k] = segments tiling [0, 2^k); each segment:
    # (start, end, sig, rep_addr, wa, wb, old_action, new_action)
    # start/end are /k block indices; rep_addr is an actual /k address in it.
    rows: List[list] = [[] for _ in range(maxlen + 1)]

    def dfs(node: TrieNode, act_a: List[Rule], act_b: List[Rule]):
        aa_rules = sorted(act_a + node.rules_a, key=lambda r: r.seq)
        bb_rules = sorted(act_b + node.rules_b, key=lambda r: r.seq)
        node_int = int(node.net.network_address)

        # ---- node cell: exactly one /k block ----
        k = node.depth
        wa, wb, aa, ab = state_at(k, aa_rules, bb_rules)
        start_idx = node_int >> (maxlen - k)
        rows[k].append((start_idx, start_idx + 1,
                        (wa and wa.seq, wb and wb.seq),
                        node_int, wa, wb, aa, ab))

        # ---- gap region: for each deeper depth, the blocks of this node's
        # subtree that fall OUTSIDE every direct-child subtree. Active rule
        # sets are constant throughout the gap. ----
        children = node.children()
        for gk in range(k + 1, maxlen + 1):
            scale = 1 << (gk - k)                  # /gk blocks in subtree
            covered: List[Tuple[int, int]] = []
            for ch in children:
                if ch.depth > gk:
                    continue                       # child lies inside one
                    # /gk block; that block is still this node's gap
                # ch.depth == gk: span 1 block; ch.depth < gk: span 2**(..)
                cs = (int(ch.net.network_address) - node_int) >> (maxlen - gk)
                span = 1 << max(0, gk - ch.depth)
                covered.append((cs, cs + span))
            covered.sort()
            gaps: List[Tuple[int, int]] = []
            cur = 0
            for cs, ce in covered:
                if cs > cur:
                    gaps.append((cur, cs))
                cur = max(cur, ce)
            if cur < scale:
                gaps.append((cur, scale))

            wa, wb, aa, ab = state_at(gk, aa_rules, bb_rules)
            sigv = (wa and wa.seq, wb and wb.seq)
            base_idx = node_int >> (maxlen - gk)
            for gs, ge in gaps:
                rep_addr = node_int + (gs << (maxlen - gk))
                rows[gk].append((base_idx + gs, base_idx + ge, sigv,
                                 rep_addr, wa, wb, aa, ab))

        for ch in children:
            dfs(ch, aa_rules, bb_rules)

    dfs(root, [], [])

    # ---- verify every row is an exact tiling, flatten ----
    items: List[list] = []
    for k in range(maxlen + 1):
        row = sorted(rows[k], key=lambda x: x[0])
        cursor = 0
        for segm in row:
            s, e = segm[0], segm[1]
            assert s == cursor, ("tiling gap/overlap", k, s, cursor)
            cursor = e
            items.append([k, *segm, len(items)])
        assert cursor == (1 << k), ("tiling incomplete", k, cursor)

    parent = list(range(len(items)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # items are maximal uniform SEGMENTS; a segment may span many /k blocks.
    # Region connectivity is decided at BLOCK granularity with two exact
    # edges that mirror the binary prefix trie:
    #
    #   vertical : block (k, i)            -> block (k-1, i>>1)
    #   sibling  : block (k, i)            -> block (k, i^1)
    #
    # i^1 is ALWAYS the unique sibling sharing the exact /(k-1) parent, so
    # horizontal connectivity can never wrap around a coarser rule (unlike
    # "any address-adjacent block"). Two blocks join only when their state
    # is identical AND every winner window covers both depths.
    by_depth: Dict[int, List[list]] = {}
    for it in items:
        by_depth.setdefault(it[0], []).append(it)
    for k in by_depth:
        by_depth[k].sort(key=lambda x: x[1])

    def same_state(a, b):
        return a[5] is b[5] and a[6] is b[6]

    def vertically_compatible(a, b):
        if not same_state(a, b):
            return False
        for win in (a[5], a[6]):
            if win is not None and not (
                    win.min_len <= a[0] <= win.max_len and
                    win.min_len <= b[0] <= win.max_len):
                return False
        return True

    import bisect

    # ---- horizontal: two address-adjacent /k segments with identical state
    # are one continuous band (a coarser boundary with NO rule at that depth
    # cannot split them; a rule there would make the states differ) ----
    for k, row in by_depth.items():
        for a, b in zip(row, row[1:]):
            if a[2] == b[1] and same_state(a, b):
                union(a[-1], b[-1])

    # ---- vertical: a /k segment vs the /(k-1) segments covering it.
    # A uniform gap segment may span SEVERAL /(k-1) blocks (a wide ge/le
    # region). It is lifted to the coarser level only when EVERY covering
    # parent segment has the same state and is window-compatible; if even one
    # parent block differs (a coarser rule cuts through), the segment is
    # pinned at depth k and is NOT merged upward — otherwise a deep default
    # band would wrap around that coarser rule. ----
    for k in range(1, maxlen + 1):
        up = by_depth[k - 1]
        up_starts = [u[1] for u in up]
        for it in by_depth[k]:
            ps, pe = it[1] >> 1, ((it[2] - 1) >> 1) + 1
            t = max(0, bisect.bisect_right(up_starts, ps) - 1)
            covering = []
            u = t
            while u < len(up) and up[u][1] < pe:
                if up[u][2] > ps:
                    covering.append(up[u])
                u += 1
            if covering and all(vertically_compatible(p, it) for p in covering):
                for p in covering:
                    union(it[-1], p[-1])

    # ---- choose, per region, the SHALLOWEST changed block (widest prefix
    # that demonstrates the change — most useful single probe) ----
    # item layout: [depth, start, end, sig, rep_addr, wa, wb, aa, ab, id]
    region_rep: Dict[int, list] = {}
    for it in items:
        if it[7] == it[8]:                      # old action == new action
            continue
        r = find(it[-1])
        cur = region_rep.get(r)
        if cur is None or it[0] < cur[0] or (it[0] == cur[0] and it[1] < cur[1]):
            region_rep[r] = it

    witnesses: List[Witness] = []
    for it in region_rep.values():
        k, _s, _e, _sigv, rep_addr, wa, wb, aa, ab, _idx = it
        witnesses.append(Witness(
            prefix=str(ipaddress.ip_network((rep_addr, k))),
            old_action=aa, new_action=ab,
            old_seq=wa and wa.seq, new_seq=wb and wb.seq,
            change=f"{aa.value}->{ab.value}",
        ))
    witnesses.sort(key=lambda w: (int(ipaddress.ip_network(w.prefix).network_address),
                                  ipaddress.ip_network(w.prefix).prefixlen))
    return witnesses
