"""
Seed the workbench with the three required worked scenarios.

1. OVER-PERMIT  : a too-wide le range admits an internal /24 range intended
                  only as aggregates.
2. REORDER      : two overlapping rules swap seq; the narrower deny is
                  shadowed after the swap.
3. DEFAULT-FLIP : removing the catch-all permit flips the implicit action.

Each scenario stores two snapshots (before/after) plus an ordered probe
list, so it is fully replayable.
"""
from __future__ import annotations

from . import db as dbmod, service


SEEDS = {
    4: {
        "over-permit": {
            "description": "le 24 lets DC more-specifics through (should be le 23)",
            "before": {
                "default_action": "deny",
                "rules": [
                    {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
                    {"seq": 20, "prefix": "192.168.0.0/16",
                     "action": "permit", "le": 24},
                ],
            },
            "after": {
                "default_action": "deny",
                "rules": [
                    {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
                    {"seq": 20, "prefix": "192.168.0.0/16",
                     "action": "permit", "le": 23},
                    # explicit guard: /24 services must stay denied
                    {"seq": 30, "prefix": "192.168.100.0/24", "action": "deny"},
                ],
            },
            "probes": [
                "192.168.0.0/16",
                "192.168.100.0/24",
                "192.168.100.128/25",
                "192.168.200.0/24",
                "192.168.200.0/23",
                "10.1.2.3/32",
                "8.8.8.8/32",
            ],
        },
        "reorder": {
            "description": "broad permit moved BEFORE narrow deny (swap seq)",
            "before": {
                "default_action": "deny",
                "rules": [
                    # narrower deny at seq 10 wins first inside 172.31/16
                    {"seq": 10, "prefix": "172.31.0.0/16", "action": "deny"},
                    {"seq": 20, "prefix": "172.16.0.0/12",
                     "action": "permit", "le": 32},
                ],
            },
            "after": {
                "default_action": "deny",
                "rules": [
                    # same two lines, but broad permit now at seq 5:
                    # first-match -> 172.31/16 deny is fully shadowed
                    {"seq": 5, "prefix": "172.16.0.0/12",
                     "action": "permit", "le": 32},
                    {"seq": 10, "prefix": "172.31.0.0/16", "action": "deny"},
                ],
            },
            "probes": [
                "172.16.0.0/12",
                "172.20.1.0/24",
                "172.31.0.0/16",
                "172.31.5.0/24",
                "172.32.0.0/16",
            ],
        },
        "default-flip": {
            "description": "catch-all permit removed: implicit default -> deny",
            "before": {
                "default_action": "permit",
                "rules": [
                    {"seq": 10, "prefix": "203.0.113.0/24",
                     "action": "deny"},
                ],
            },
            "after": {
                "default_action": "deny",
                "rules": [
                    {"seq": 10, "prefix": "203.0.113.0/24",
                     "action": "deny"},
                    {"seq": 20, "prefix": "198.51.100.0/24",
                     "action": "permit"},
                ],
            },
            "probes": [
                "203.0.113.0/24",
                "203.0.113.7/32",
                "198.51.100.0/24",
                "192.0.2.1/32",
                "104.16.0.0/12",
            ],
        },
    },
    6: {
        "over-permit-v6": {
            "description": "le 48 admits site /48s intended to stay internal",
            "before": {
                "default_action": "deny",
                "rules": [
                    {"seq": 10, "prefix": "2001:db8:1::/48", "action": "deny"},
                    {"seq": 20, "prefix": "2001:db8::/32",
                     "action": "permit", "le": 48},
                ],
            },
            "after": {
                "default_action": "deny",
                "rules": [
                    {"seq": 10, "prefix": "2001:db8:1::/48", "action": "deny"},
                    {"seq": 20, "prefix": "2001:db8::/32",
                     "action": "permit", "le": 40},
                ],
            },
            "probes": [
                "2001:db8::/32",
                "2001:db8::/40",
                "2001:db8:1::/48",
                "2001:db8:2::/48",
                "2001:db8:1:1::/64",
                "2001:dead::/32",
            ],
        },
    },
}

NEIGHBORS = [
    dict(name="edge-r1", ip="10.255.0.1", family=4, asn=64512,
         inbound_policy="over-permit",
         description="local edge, FRR router-a"),
    dict(name="core-r2", ip="10.255.0.2", family=4, asn=64513,
         inbound_policy="reorder",
         description="local core, FRR router-b"),
    dict(name="edge-v6-r1", ip="2001:db8:ffff::1", family=6, asn=64512,
         inbound_policy="over-permit-v6",
         description="local edge IPv6, FRR router-a"),
]


def seed_all() -> None:
    from .migrate import upgrade
    upgrade()
    s = dbmod.SessionLocal()
    try:
        for nb in NEIGHBORS:
            if not s.query(dbmod.Neighbor).filter_by(name=nb["name"]).first():
                s.add(dbmod.Neighbor(**nb))

        for family, scenarios in SEEDS.items():
            for slug, spec in scenarios.items():
                pname = slug
                dbp = s.query(dbmod.Policy).filter_by(name=pname).first()
                if dbp is None:
                    dbp = dbmod.Policy(
                        name=pname, family=family,
                        default_action=spec["before"]["default_action"],
                        description=spec["description"], draft=False)
                    s.add(dbp)
                    s.commit()
                    service.replace_rules(s, dbp, spec["before"]["rules"])
                    snap_before = service.create_snapshot(s, dbp, label="before")

                    dbp.default_action = spec["after"]["default_action"]
                    s.commit()
                    service.replace_rules(s, dbp, spec["after"]["rules"])
                    snap_after = service.create_snapshot(s, dbp, label="after")

                    sc = dbmod.Scenario(
                        name=pname, description=spec["description"],
                        from_snapshot_id=snap_before.id,
                        to_snapshot_id=snap_after.id,
                        probes=spec["probes"],
                    )
                    s.add(sc)
                    s.commit()
    finally:
        s.close()


if __name__ == "__main__":
    seed_all()
    print("seed complete")
