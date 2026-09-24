"""
Prefix-list / route-policy evaluation engine.

Semantics (Cisco / FRR `ip prefix-list` style, first-match):

* Every rule is (base_prefix, ge, le) over ONE address family (v4 or v6).
* A candidate prefix P matches rule R iff:
      R.base_prefix network_address == P.network_address & mask(R.base_prefix.prefixlen)
      i.e. P is inside (or equal to) R.base_prefix                      （包含关系）
      and R.effective_min <= P.prefixlen <= R.effective_max            （掩码长度范围）
  effective_min = ge if ge is set else base_prefix.prefixlen
  effective_max = le if le is set else (base_prefix.prefixlen if ge is None else MAXLEN)
* Rules are evaluated in ascending `seq`; the FIRST match wins.
* If no rule matches, the policy `default_action` applies (normally deny).
* IPv4 and IPv6 are NEVER mixed: a candidate of one family cannot match a
  rule of the other.

The module also provides:

* classify(...)            -> hit chain for one candidate prefix
* shadowed_rules(...)      -> rules that can never be hit (covered by earlier rules)
* minimal_witness_set(...) -> smallest set of prefixes that shows every
                              behavior difference between two policies.
                              This is a semantic diff, not a text diff:
                              edits that cannot change forwarding produce no
                              witnesses, and one witness is returned per
                              distinct behavior region.

All enumeration is EXACT: prefix space is cut by rule base prefixes and
length-range boundaries into finite "cells" that are uniform under every
rule; we only enumerate cell representatives, never the whole address space.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple, Dict, Iterable

import ipaddress


class Action(str, Enum):
    PERMIT = "permit"
    DENY = "deny"


MAXLEN = {4: 32, 6: 128}


class PolicyError(ValueError):
    """Raised on malformed rules / mixed address families."""


def _family_of(prefix: str) -> int:
    net = ipaddress.ip_network(prefix, strict=True)
    return net.version


@dataclass(frozen=True)
class Rule:
    seq: int
    prefix: str                       # canonical base prefix, e.g. "10.0.0.0/8"
    action: Action
    ge: Optional[int] = None
    le: Optional[int] = None
    remark: str = ""
    id: Optional[int] = None          # DB id, when persisted

    # ---- derived geometry (filled by Policy) ----
    net: ipaddress._BaseNetwork = field(default=None, compare=False, repr=False)  # type: ignore
    min_len: int = field(default=0, compare=False)
    max_len: int = field(default=0, compare=False)

    def __post_init__(self):
        # accept shorthand where octets are omitted ("10/8" -> "10.0.0.0/8",
        # "2001:db8::/32" already fine), but still reject host bits.
        raw = self.prefix.strip()
        if "/" in raw:
            addr, _, plen = raw.partition("/")
            if ":" not in addr and addr.count(".") < 3:
                octets = addr.split(".") if addr else []
                addr = ".".join(octets + ["0"] * (4 - len(octets)))
                raw = f"{addr}/{plen}"
        net = ipaddress.ip_network(raw, strict=True)
        if str(net) != self.prefix:
            object.__setattr__(self, "prefix", str(net))
        fam = net.version
        base = net.prefixlen
        ge = self.ge
        le = self.le
        if ge is not None and not (base < ge <= MAXLEN[fam]):
            raise PolicyError(
                f"seq {self.seq}: ge must satisfy base-len < ge <= {MAXLEN[fam]}"
            )
        if le is not None and not (base <= le <= MAXLEN[fam]):
            raise PolicyError(
                f"seq {self.seq}: le must satisfy base-len <= le <= {MAXLEN[fam]}"
            )
        if ge is not None and le is not None and ge > le:
            raise PolicyError(f"seq {self.seq}: ge ({ge}) > le ({le})")
        # Cisco: min = ge|base ; max = le|(base if ge unset else MAXLEN)
        min_len = ge if ge is not None else base
        max_len = le if le is not None else (base if ge is None else MAXLEN[fam])
        object.__setattr__(self, "net", net)
        object.__setattr__(self, "min_len", min_len)
        object.__setattr__(self, "max_len", max_len)

    @property
    def family(self) -> int:
        return self.net.version

    def contains(self, cand: ipaddress._BaseNetwork) -> bool:
        """Address containment only (length is checked separately)."""
        if cand.version != self.family:
            return False
        return cand.subnet_of(self.net)

    def length_covers(self, plen: int) -> bool:
        return self.min_len <= plen <= self.max_len

    def matches(self, cand: ipaddress._BaseNetwork) -> bool:
        return self.contains(cand) and self.length_covers(cand.prefixlen)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "seq": self.seq,
            "prefix": self.prefix,
            "action": self.action.value if isinstance(self.action, Action) else self.action,
            "ge": self.ge,
            "le": self.le,
            "remark": self.remark,
        }


def rule_from_dict(d: dict) -> Rule:
    return Rule(
        id=d.get("id"),
        seq=int(d["seq"]),
        prefix=d["prefix"],
        action=Action(d["action"]),
        ge=d.get("ge"),
        le=d.get("le"),
        remark=d.get("remark", ""),
    )


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

@dataclass
class Policy:
    name: str
    rules: List[Rule]
    default_action: Action = Action.DENY
    family: Optional[int] = None      # fixed when rules exist / explicit

    def __post_init__(self):
        self.rules = sorted(self.rules, key=lambda r: r.seq)
        fams = {r.family for r in self.rules}
        if self.family is not None and fams and self.family not in fams:
            raise PolicyError(
                f"policy {self.name!r}: rules address family {fams} != declared {self.family}"
            )
        if len(fams) > 1:
            raise PolicyError(
                f"policy {self.name!r}: IPv4 and IPv6 rules must not be mixed ({fams})"
            )
        if fams:
            self.family = next(iter(fams))
        seqs = [r.seq for r in self.rules]
        if len(seqs) != len(set(seqs)):
            raise PolicyError(f"policy {self.name!r}: duplicate seq numbers")

    # ---- evaluation ------------------------------------------------------

    def classify(self, prefix: str) -> "HitResult":
        cand = ipaddress.ip_network(prefix, strict=True)
        chain = []
        if self.family is not None and cand.version != self.family:
            raise PolicyError(
                f"{prefix} is IPv{cand.version} but policy is IPv{self.family}: "
                "address families must not be mixed"
            )
        for r in self.rules:
            if r.contains(cand):
                hit_len = r.length_covers(cand.prefixlen)
                chain.append(
                    ChainEntry(
                        seq=r.seq, rule_id=r.id, prefix=r.prefix, action=r.action,
                        ge=r.ge, le=r.le, contained=True, length_ok=hit_len,
                        matched=hit_len,
                        reason="match" if hit_len else "containment-only: prefix length out of ge/le window",
                    )
                )
                if hit_len:
                    return HitResult(prefix, cand.prefixlen, cand.version, r,
                                     chain, final_action=r.action, terminal="rule")
            else:
                chain.append(
                    ChainEntry(
                        seq=r.seq, rule_id=r.id, prefix=r.prefix, action=r.action,
                        ge=r.ge, le=r.le, contained=False,
                        length_ok=r.length_covers(cand.prefixlen), matched=False,
                        reason="no-containment: candidate outside base prefix",
                    )
                )
        chain.append(
            ChainEntry(seq=None, rule_id=None, prefix="*", action=self.default_action,
                       ge=None, le=None, contained=True, length_ok=True, matched=True,
                       reason="end of policy: implicit default")
        )
        return HitResult(prefix, cand.prefixlen, cand.version, None,
                         chain, final_action=self.default_action, terminal="default")

    # ---- shadow analysis & semantic diff (see trie.py) -------------------

    def shadowed(self) -> List["ShadowReport"]:
        from .trie import find_shadowed
        return find_shadowed(self)

    def witness_diff(self, other: "Policy") -> List["Witness"]:
        from .trie import minimal_witness_set
        return minimal_witness_set(self, other)

    def to_frr_prefix_list(self) -> str:
        """Render FRR/vtysh ip prefix-list configuration lines."""
        if self.family is None:
            return ""
        ip = "ip" if self.family == 4 else "ipv6"
        lines = []
        for r in self.rules:
            tail = ""
            if r.ge is not None:
                tail += f" ge {r.ge}"
            if r.le is not None:
                tail += f" le {r.le}"
            lines.append(
                f"{ip} prefix-list {self.name} seq {r.seq} {r.action.value} {r.prefix}{tail}"
            )
        return "\n".join(lines)


@dataclass
class ChainEntry:
    seq: Optional[int]
    rule_id: Optional[int]
    prefix: str
    action: Action
    ge: Optional[int]
    le: Optional[int]
    contained: bool
    length_ok: bool
    matched: bool
    reason: str


@dataclass
class HitResult:
    prefix: str
    prefixlen: int
    family: int
    rule: Optional[Rule]
    chain: List[ChainEntry]
    final_action: Action
    terminal: str                 # "rule" | "default"

    def to_dict(self) -> dict:
        return {
            "prefix": self.prefix,
            "prefixlen": self.prefixlen,
            "family": self.family,
            "final_action": self.final_action.value,
            "terminal": self.terminal,
            "matched_seq": self.rule.seq if self.rule else None,
            "matched_rule_id": self.rule.id if self.rule else None,
            "chain": [
                {
                    "seq": e.seq, "rule_id": e.rule_id, "prefix": e.prefix,
                    "action": e.action.value, "ge": e.ge, "le": e.le,
                    "contained": e.contained, "length_ok": e.length_ok,
                    "matched": e.matched, "reason": e.reason,
                }
                for e in self.chain
            ],
        }


@dataclass
class ShadowReport:
    rule: Rule
    fully_shadowed: bool
    partial_shadowed_by: List[int]     # earlier seqs whose ranges overlap
    witnesses: List[str]               # representative prefixes of covered regions

    def to_dict(self) -> dict:
        return {
            "rule": self.rule.to_dict(),
            "fully_shadowed": self.fully_shadowed,
            "partial_shadowed_by": self.partial_shadowed_by,
            "witnesses": self.witnesses,
        }


@dataclass
class Witness:
    prefix: str
    old_action: Action
    new_action: Action
    old_seq: Optional[int]
    new_seq: Optional[int]
    change: str                        # permit->deny / deny->permit

    def to_dict(self) -> dict:
        return {
            "prefix": self.prefix,
            "old_action": self.old_action.value,
            "new_action": self.new_action.value,
            "old_seq": self.old_seq,
            "new_seq": self.new_seq,
            "change": self.change,
        }


def policy_from_dicts(name: str, rules: Iterable[dict],
                      default_action: str = "deny",
                      family: Optional[int] = None) -> Policy:
    return Policy(
        name=name,
        rules=[rule_from_dict(r) for r in rules],
        default_action=Action(default_action),
        family=family,
    )
