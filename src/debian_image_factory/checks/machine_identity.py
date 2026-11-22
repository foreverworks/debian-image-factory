"""`no-machine-identity` (DESIGN 11): nothing in the image identifies one machine. Pure: it judges the
member list and the few small files `tarball.scan_tarball` read."""

import fnmatch
import posixpath
from collections.abc import Mapping, Sequence
from typing import Final

from .model import NO_MACHINE_IDENTITY, Result, result, split
from .tarball import Member

MACHINE_ID: Final = "/etc/machine-id"
DBUS_MACHINE_ID: Final = "/var/lib/dbus/machine-id"
HOSTNAME: Final = "/etc/hostname"
RESOLV_CONF: Final = "/etc/resolv.conf"
WANTED: Final = frozenset((MACHINE_ID, HOSTNAME))
"""The files whose content `scan_tarball` must keep for this check."""
SSH_HOST_KEYS: Final = "/etc/ssh/ssh_host_*"
RANDOM_SEEDS: Final = ("/var/lib/systemd/random-seed", "/var/lib/urandom/random-seed")
CLOUD_INSTANCE: Final = "/var/lib/cloud/instance"
CLOUD_INSTANCES: Final = "/var/lib/cloud/instances/"

NO_ID: Final = frozenset((b"", b"uninitialized\n"))
"""The contents a machine-id may have in an image: none, or systemd's marker for "set at first boot"."""


def points_at_machine_id(member: Member) -> bool:
    """A symlink to /etc/machine-id (Debian's dbus package makes one) holds no identity of its own."""
    if member.kind != "symlink":
        return False
    target = posixpath.join(posixpath.dirname(member.path), member.target)  # an absolute target wins the join
    return posixpath.normpath(target) == MACHINE_ID


def machine_id_problem(member: Member | None, content: bytes | None) -> str | None:
    if member is None:
        return None
    if member.kind != "file":
        return f"{member.path} is a {member.kind}, not an empty file"
    if content not in NO_ID:
        return f"{member.path} holds an identity"
    return None


def no_machine_identity(members: Sequence[Member], contents: Mapping[str, bytes], key_files: Sequence[str]) -> Result:
    """`key_files` are what `scan_tarball` found holding a private key block or a credential token (the
    token itself is never named: its file, kind and a redacted form are)."""
    by_path = {member.path: member for member in members}
    passed: list[str] = []
    failed: list[str] = []

    machine = machine_id_problem(by_path.get(MACHINE_ID), contents.get(MACHINE_ID))
    ok, bad = split("machine-id-empty-or-uninitialized", [machine] if machine else [])
    passed += ok
    failed += bad

    dbus = by_path.get(DBUS_MACHINE_ID)
    dbus_problem = f"{DBUS_MACHINE_ID} exists and is not a link to {MACHINE_ID}"
    ok, bad = split("no-dbus-machine-id", [dbus_problem] if dbus is not None and not points_at_machine_id(dbus) else [])
    passed += ok
    failed += bad

    host = by_path.get(HOSTNAME)
    host_problem = None
    if host is not None and (host.kind != "file" or contents.get(HOSTNAME, b"") != b""):
        host_problem = f"{HOSTNAME} is not absent or empty"
    ok, bad = split("no-hostname", [host_problem] if host_problem else [])
    passed += ok
    failed += bad

    resolver = by_path.get(RESOLV_CONF)
    resolver_problem = None
    if resolver is not None and resolver.kind != "symlink":
        resolver_problem = f"{RESOLV_CONF} is a {resolver.kind} copied from the build host, not a link"
    ok, bad = split("no-resolver-config", [resolver_problem] if resolver_problem else [])
    passed += ok
    failed += bad

    hosts = sorted(m.path for m in members if m.kind != "dir" and fnmatch.fnmatchcase(m.path, SSH_HOST_KEYS))
    ok, bad = split("no-ssh-host-keys", hosts)
    passed += ok
    failed += bad

    ok, bad = split("no-private-keys", sorted(key_files))
    passed += ok
    failed += bad

    seeds = sorted(m.path for m in members if m.path in RANDOM_SEEDS and m.kind != "dir")
    ok, bad = split("no-random-seed", seeds)
    passed += ok
    failed += bad

    cloud = sorted(
        m.path
        for m in members
        if m.path == CLOUD_INSTANCE or (m.path.startswith(CLOUD_INSTANCES) and m.path != CLOUD_INSTANCES.rstrip("/"))
    )
    ok, bad = split("no-cloud-init-state", cloud)
    passed += ok
    failed += bad
    return result(NO_MACHINE_IDENTITY, passed, failed=failed)
