"""
Bridge to the LOCAL FRRouting lab containers (router-a, router-b).

Cross-validation method
-----------------------
No live BGP session is needed: FRR's own prefix-list parser/matcher is the
reference oracle. For each probe we run, inside the container,

    vtysh -c "show ip prefix-list NAME match PREFIX"
    vtysh -c "show ipv6 prefix-list NAME match PREFIX"

which prints FRR's decision (matching seq / allow / deny). The prefix list
itself is installed from a snapshot's rendered config and removed again
after the run.

Transports
----------
* "docker" (default in compose labs): `docker exec rpolicy-router-X vtysh ...`
* "ssh"   : optional, when docker is not reachable from the API process
            (set RLAB_FRR_TRANSPORT=ssh; see config.py for host/port)

The lab network is an internal bridge with no production connectivity.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

import paramiko

from .config import (
    FRR_HOST_A, FRR_HOST_B, FRR_SSH_PORT_A, FRR_SSH_PORT_B,
    FRR_SSH_USER, FRR_SSH_PASSWORD,
)
from .engine import Policy

FRR_TRANSPORT = os.environ.get("RLAB_FRR_TRANSPORT", "docker").lower()


class FRRUnavailable(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# "stub" transport: an in-process stand-in for the isolated FRR containers.
# Used when no docker socket exists (CI, unit/acceptance runs). State is
# process-global per node, so successive bridge instances see the same
# "device". RLAB_STUB_RESET=1 / lab_bridge.reset_stub() clears it.
# STUB_FAIL_NEXT injects N consecutive transport failures on mutating calls,
# which is how acceptance tests simulate a container apply failure followed
# by recovery — production paths never touch this transport.
# ---------------------------------------------------------------------------
STUB_STATE: dict = {}
STUB_FAIL_NEXT: dict = {"a": 0, "b": 0}


def reset_stub() -> None:
    STUB_STATE.clear()
    STUB_FAIL_NEXT["a"] = 0
    STUB_FAIL_NEXT["b"] = 0


def _stub_fail(node: str):
    n = STUB_FAIL_NEXT.get(node, 0)
    if n > 0:
        STUB_FAIL_NEXT[node] = n - 1
        raise FRRUnavailable(f"[stub] simulated FRR failure on router-{node}")


@dataclass
class FRRObservation:
    prefix: str
    action: str           # permit / deny / error
    seq: Optional[int]
    raw: str


NODES = {
    "a": {"docker": "rpolicy-router-a", "host": FRR_HOST_A, "port": FRR_SSH_PORT_A},
    "b": {"docker": "rpolicy-router-b", "host": FRR_HOST_B, "port": FRR_SSH_PORT_B},
}


class FRRBridge:
    def __init__(self, node: str = "a",
                 transport: Optional[str] = None,
                 username: str = FRR_SSH_USER, password: str = FRR_SSH_PASSWORD,
                 timeout: float = 20.0):
        self.node = node
        self.transport = (transport or FRR_TRANSPORT).lower()
        meta = NODES.get(node, NODES["a"])
        self.container = meta["docker"]
        self.host, self.port = meta["host"], meta["port"]
        self.username, self.password = username, password
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None

    # ------------------------------------------------------------- transport
    def connect(self) -> "FRRBridge":
        if self.transport == "stub":
            return self
        if self.transport == "docker":
            if not shutil.which("docker"):
                raise FRRUnavailable(
                    "docker CLI not found; start the API host with docker access "
                    "or set RLAB_FRR_TRANSPORT=ssh"
                )
            try:
                self._docker(["true"])
            except FRRUnavailable:
                raise FRRUnavailable(
                    f"container {self.container!r} not running. "
                    "Start: docker compose -f frr/docker-compose.yml up -d"
                )
        elif self.transport == "ssh":
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=self.host, port=self.port,
                    username=self.username, password=self.password,
                    timeout=self.timeout, allow_agent=False, look_for_keys=False,
                )
            except (OSError, paramiko.SSHException) as e:
                raise FRRUnavailable(
                    f"FRR node '{self.node}' at {self.host}:{self.port} unreachable: {e}") from e
            self._client = client
        else:
            raise FRRUnavailable(f"unknown transport {self.transport!r}")
        return self

    def close(self):
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    def _docker(self, argv: List[str], allow_warning_rc: bool = False) -> str:
        cmd = ["docker", "exec", self.container] + argv
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=self.timeout)
        except subprocess.TimeoutExpired as e:
            raise FRRUnavailable(f"docker exec timeout: {' '.join(argv)}") from e
        except OSError as e:
            raise FRRUnavailable(f"docker exec failed: {e}") from e
        # FRR returns CMD_WARNING (1) for an oracle DENY result
        if p.returncode != 0 and not (allow_warning_rc and p.returncode == 1):
            raise FRRUnavailable(
                f"docker exec rc={p.returncode}: {p.stderr.strip() or p.stdout.strip()}")
        return p.stdout + p.stderr

    def vtysh(self, commands: List[str], allow_warning_rc: bool = False) -> str:
        if self.transport == "stub":
            return _stub_vtysh(self.node, commands)
        if self.transport == "docker":
            args = []
            for c in commands:
                args += ["-c", c]
            return self._docker(["vtysh"] + args, allow_warning_rc=allow_warning_rc)

        # ssh
        assert self._client is not None, "not connected"
        args = " ".join(f"-c {_shell_quote(c)}" for c in commands)
        _stdin, stdout, stderr = self._client.exec_command(
            f"vtysh {args}", timeout=self.timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status()
        # FRR returns CMD_WARNING (1) for a DENY oracle result
        if rc != 0 and not (allow_warning_rc and rc == 1):
            raise FRRUnavailable(f"vtysh rc={rc}: {err.strip() or out.strip()}")
        return out + err

    # ------------------------------------------------------------- provision
    def _plist_commands(self, lines: List[str], vrf: str) -> List[str]:
        cmds = ["configure terminal"]
        if vrf:
            cmds.append(f"vrf {vrf}")
        cmds += lines
        cmds += ["end", "write memory"]
        return cmds

    def install_named_policy(self, plname: str, family: int,
                             lines: List[str], vrf: str = "") -> str:
        """Install explicit already-rendered prefix-list lines as `plname`."""
        return self.vtysh(self._plist_commands(lines, vrf))

    def remove_named_policy(self, plname: str, family: int,
                            vrf: str = "") -> str:
        ip = "ip" if family == 4 else "ipv6"
        cmds = ["configure terminal"]
        if vrf:
            cmds.append(f"vrf {vrf}")
        cmds.append(f"no {ip} prefix-list {plname}")
        cmds += ["end", "write memory"]
        return self.vtysh(cmds)

    def install_policy(self, policy: Policy, vrf: str = "") -> str:
        return self.install_named_policy(
            policy.name, policy.family,
            policy.to_frr_prefix_list().splitlines(), vrf)

    def remove_policy(self, name: str, family: int, vrf: str = "") -> str:
        return self.remove_named_policy(name, family, vrf)

    def show_prefix_list(self, name: str, family: int) -> str:
        ip = "ip" if family == 4 else "ipv6"
        return self.vtysh([f"show {ip} prefix-list {name}"])

    # -------------------------------------------------------------- observe
    # FRR reference oracle (verified against FRR 8.5/8.4 source, plist.c):
    #
    #   debug ip prefix-list WORD match A.B.C.D/M
    #       -> "ip prefix list WORD yields PERMIT|DENY for P,
    #           matching entry #SEQ: P[/M ge X le Y]"  or  "no match found"
    #   (returns vtysh exit code 0 on PERMIT, CMD_WARNING(1) on DENY)
    #
    # Caveat baked into FRR itself: a plist that EXISTS BUT HAS ZERO ENTRIES
    # yields PREFIX_PERMIT. FRR has no implicit deny; that default is a
    # property of the calling route-map/BGP policy. Our snapshots always
    # carry explicit rules; validate.py normalizes the comparison.
    _YIELDS_RE = re.compile(r"yields\s+(PERMIT|DENY)", re.IGNORECASE)
    _SEQ_RE = re.compile(r"matching entry #(\d+)", re.IGNORECASE)

    def observe(self, policy_name: str, family: int, prefix: str,
                vrf: str = "") -> FRRObservation:
        ip = "ip" if family == 4 else "ipv6"
        probe = f"debug {ip} prefix-list {policy_name} match {prefix}"
        cmds = [f"vrf {vrf}", probe] if vrf else [probe]
        # PERMIT -> rc 0, DENY -> CMD_WARNING(1), so do not treat rc!=0 as
        # a transport error: parse both streams.
        raw = self.vtysh(cmds, allow_warning_rc=True)

        m = self._YIELDS_RE.search(raw)
        action = "error"
        if m:
            action = "permit" if m.group(1).lower() == "permit" else "deny"
        seqm = self._SEQ_RE.search(raw)
        return FRRObservation(
            prefix=prefix, action=action,
            seq=int(seqm.group(1)) if seqm else None, raw=raw.strip(),
        )

    def ping(self) -> bool:
        try:
            self.connect()
            out = self.vtysh(["show version"])
            self.close()
            return "FRRouting" in out or "frr" in out.lower()
        except FRRUnavailable:
            return False


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


# ---------------------------------------------------------------------------
# stub transport implementation
# ---------------------------------------------------------------------------
import ipaddress as _ipaddress  # noqa: E402

_PLIST_LINE_RE = re.compile(
    r"^(ip|ipv6) prefix-list (\S+) seq (\d+) (permit|deny) (\S+)"
    r"(?: ge (\d+))?(?: le (\d+))?$")
_NO_PLIST_RE = re.compile(r"^no (ip|ipv6) prefix-list (\S+)$")
_SHOW_PLIST_RE = re.compile(r"^show (ip|ipv6) prefix-list (\S+)$")
_DEBUG_PLIST_RE = re.compile(
    r"^debug (ip|ipv6) prefix-list (\S+) match (\S+)$")


def _stub_store(node: str) -> dict:
    return STUB_STATE.setdefault(node, {})


def _stub_apply(entries: list, family: int, prefix: str):
    """Port of FRR lib/plist.c::prefix_list_apply_ext (same model as tests)."""
    net = _ipaddress.ip_network(prefix)
    maxlen = 32 if family == 4 else 128
    best = None
    for e in entries:
        enet = _ipaddress.ip_network(e["prefix"])
        if enet.version != net.version or not net.subnet_of(enet):
            continue
        ge, le = e["ge"], e["le"]
        if ge is None and le is None:
            if enet.prefixlen != net.prefixlen:
                continue
        else:
            mn = ge if ge is not None else enet.prefixlen
            mx = le if le is not None else (maxlen if ge is not None else enet.prefixlen)
            if not (mn <= net.prefixlen <= mx):
                continue
        if best is None or e["seq"] < best["seq"]:
            best = e
    # FRR fidelity: an existing-but-empty list yields PERMIT.
    if best is None:
        return None
    return best


def _stub_vtysh(node: str, commands: List[str]) -> str:
    store = _stub_store(node)
    out: List[str] = []
    pending_vrf = ""
    for cmd in commands:
        c = cmd.strip()
        if c in ("configure terminal", "end", "write memory", "true"):
            if c == "write memory":
                _stub_fail(node)
            continue
        if c.startswith("vrf "):
            pending_vrf = c.split(" ", 1)[1]
            continue

        m = _PLIST_LINE_RE.match(c)
        if m:
            _stub_fail(node)
            fam = 4 if m.group(1) == "ip" else 6
            name = m.group(2)
            key = (name, fam)
            entries = store.setdefault(key, [])
            entries = [e for e in entries if e["seq"] != int(m.group(3))]
            net = _ipaddress.ip_network(m.group(5), strict=True)
            ge = int(m.group(6)) if m.group(6) else None
            le = int(m.group(7)) if m.group(7) else None
            entries.append({"seq": int(m.group(3)), "action": m.group(4),
                            "prefix": str(net), "ge": ge, "le": le})
            store[key] = sorted(entries, key=lambda e: e["seq"])
            continue

        m = _NO_PLIST_RE.match(c)
        if m:
            _stub_fail(node)
            fam = 4 if m.group(1) == "ip" else 6
            store.pop((m.group(2), fam), None)
            continue

        m = _SHOW_PLIST_RE.match(c)
        if m:
            fam = 4 if m.group(1) == "ip" else 6
            name = m.group(2)
            entries = store.get((name, fam))
            if entries is None:
                continue
            out.append(f"{m.group(1)} prefix-list {name}: {len(entries)} entries")
            for e in entries:
                tail = ""
                if e["ge"] is not None:
                    tail += f" ge {e['ge']}"
                if e["le"] is not None:
                    tail += f" le {e['le']}"
                out.append(f"   seq {e['seq']} {e['action']} {e['prefix']}{tail}")
            continue

        m = _DEBUG_PLIST_RE.match(c)
        if m:
            fam = 4 if m.group(1) == "ip" else 6
            name, pfx = m.group(2), m.group(3)
            entries = store.get((name, fam), [])
            hit = _stub_apply(entries, fam, pfx)
            if hit is None:
                out.append(f"ip prefix list {name} yields DENY for {pfx}, "
                           "no match found")
            else:
                tail = ""
                if hit["ge"] is not None:
                    tail += f" ge {hit['ge']}"
                if hit["le"] is not None:
                    tail += f" le {hit['le']}"
                out.append(
                    f"ip prefix list {name} yields {hit['action'].upper()} "
                    f"for {pfx}, matching entry #{hit['seq']}: "
                    f"{hit['prefix']}{tail}")
            continue

        if c == "show version":
            out.append("FRRouting 8.4.1 (stub-isolated-lab)")
            continue

    return "\n".join(out) + ("\n" if out else "")
