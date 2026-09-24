"""
Compact prefix-trie views for the React frontend.

Two views:

* policy_trie(policy, probe=None): rule bases as nodes; each node carries
  the ordered list of active rules there and, optionally, the hit chain for
  one probe (hit path highlighted).
* coverage_map(policy, depth): full decision grid at one fixed depth
  (permit/deny/default per block), e.g. depth 8 for IPv4 or 32 for IPv6.
"""
from __future__ import annotations

from typing import List, Optional

import ipaddress

from .engine import Action, Policy, Rule, MAXLEN


def policy_trie(policy: Policy, max_nodes: int = 4000) -> dict:
    maxlen = MAXLEN[policy.family]
    # node key -> data
    nodes: dict = {}

    def ensure(net: ipaddress._BaseNetwork):
        key = str(net)
        d = nodes.get(key)
        if d is None:
            d = {
                "prefix": key,
                "depth": net.prefixlen,
                "rules": [],
                "children": [],
                "has_rule": False,
            }
            nodes[key] = d
        return d

    root = ensure(ipaddress.ip_network("0.0.0.0/0" if policy.family == 4 else "::/0"))

    # insert every rule base and materialize its ancestor chain
    for rule in policy.rules:
        net = rule.net
        chain_nets = [net]
        cur = net
        while cur.prefixlen > 0:
            cur = cur.supernet()
            chain_nets.append(cur)
        chain_nets.reverse()
        prev = root
        for cn in chain_nets:
            n = ensure(cn)
            if n["prefix"] != prev["prefix"] and n["prefix"] not in prev["children"]:
                prev["children"].append(n["prefix"])
            prev = n
        n["has_rule"] = True
        n["rules"].append({
            "seq": rule.seq, "prefix": rule.prefix,
            "action": rule.action.value,
            "ge": rule.ge, "le": rule.le,
            "min_len": rule.min_len, "max_len": rule.max_len,
            "remark": rule.remark,
        })

    # annotate shadow state
    shadows = {s.rule.seq: s for s in policy.shadowed()}
    for n in nodes.values():
        for r in n["rules"]:
            sh = shadows.get(r["seq"])
            r["shadowed"] = bool(sh and sh.fully_shadowed)
            r["partial_shadowed_by"] = sh.partial_shadowed_by if sh else []

    # prune if too big: return sparse root with rule-node paths only
    if len(nodes) > max_nodes:
        keep = set()
        for key, n in nodes.items():
            if n["has_rule"]:
                cur = ipaddress.ip_network(key)
                keep.add(str(cur))
                while cur.prefixlen > 0:
                    cur = cur.supernet()
                    keep.add(str(cur))
        for key in list(nodes):
            if key not in keep:
                del nodes[key]
        for n in nodes.values():
            n["children"] = [c for c in n["children"] if c in keep]
        root = nodes[root["prefix"]]

    return {
        "family": policy.family,
        "maxlen": maxlen,
        "default_action": policy.default_action.value,
        "root": root["prefix"],
        "nodes": nodes,
        "pruned": len(nodes) > max_nodes,
    }


def hit_path(policy: Policy, prefix: str) -> dict:
    hit = policy.classify(prefix)
    # the containment ancestors from root to the candidate
    net = ipaddress.ip_network(prefix)
    path = [str(net.supernet(new_prefix=d)) for d in range(0, net.prefixlen)]
    path.append(str(net))
    d = hit.to_dict()
    d["trie_path"] = path
    return d


def coverage_map(policy: Policy, depth: int,
                 window: Optional[tuple] = None) -> dict:
    """
    Decision for every /depth block, optionally limited to an address window
    (start_int, count_in_blocks). Depth default should be shallow (<= 12 for
    v4, <= 40 for v6) since the grid has 2**depth entries.
    """
    if depth < 0 or depth > MAXLEN[policy.family]:
        raise ValueError("bad depth")
    total = 1 << depth
    start = 0
    count = total
    if window is not None:
        start, count = window
    addr_bits = 32 if policy.family == 4 else 128
    shift = addr_bits - depth
    cells = []
    for i in range(start, min(start + count, total)):
        net = ipaddress.ip_network((i << shift, depth))
        r = policy.classify(str(net))
        cells.append({
            "index": i,
            "prefix": str(net),
            "action": r.final_action.value,
            "seq": r.rule.seq if r.rule else None,
            "terminal": r.terminal,
        })
    return {
        "family": policy.family, "depth": depth,
        "total_blocks": total, "start": start, "count": len(cells),
        "cells": cells,
    }


def regions_summary(policy: Policy) -> dict:
    """Coarse counts of permit/deny/default space at each depth boundary."""
    from .trie import build_trie, _winner, _gap_block
    maxlen = MAXLEN[policy.family]
    root = build_trie(policy.family, policy.rules)
    out = []

    def dfs(node, active):
        rules = sorted(active + node.rules_a, key=lambda r: r.seq)
        for k in range(node.depth, maxlen + 1):
            if k == node.depth:
                w = _winner(k, rules)
                out.append((k, str(node.net), w.seq if w else None,
                           (w.action if w else policy.default_action).value))
            elif _gap_block(node, k, maxlen) is not None:
                w = _winner(k, rules)
                out.append((k, None, w.seq if w else None,
                           (w.action if w else policy.default_action).value))
        for ch in node.children():
            dfs(ch, rules)

    dfs(root, [])
    return {"entries": [{"depth": k, "anchor": a, "seq": s, "action": act}
                        for k, a, s, act in out]}
