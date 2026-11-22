"""`two-clones` for core (DESIGN 11): two instances of the artifact share no identity.

The tarball is imported into rootless Docker under a throwaway tag, two containers (no network) read the
identity files, and both are removed afterwards. The comparison is pure; docker is reached through a
`Runner`, so a test can stand in for it.
"""

import base64
import binascii
import contextlib
import subprocess
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final

from .machine_identity import NO_ID
from .model import TWO_CLONES, CheckOutcome, NotRun, Result, result, split

type Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]

READ_SCRIPT: Final = (
    "for f in /etc/machine-id /var/lib/dbus/machine-id /etc/ssh/ssh_host_*_key.pub; do "
    '[ -f "$f" ] && echo "$f $(base64 -w0 "$f")"; done; true'
)
"""Prints `<path> <base64 of the file>` for each identity file the instance has."""

IDENTITY_TESTS: Final[tuple[tuple[str, Callable[[str], bool]], ...]] = (
    ("machine-ids-differ", lambda path: path == "/etc/machine-id"),
    ("dbus-machine-ids-differ", lambda path: path == "/var/lib/dbus/machine-id"),
    ("ssh-host-keys-differ", lambda path: path.startswith("/etc/ssh/ssh_host_")),
)


def parse_readings(output: str) -> dict[str, bytes]:
    """The files READ_SCRIPT printed, by path. A line that is not `<path> <base64>` raises ValueError."""
    found: dict[str, bytes] = {}
    for line in output.splitlines():
        path, _, encoded = line.partition(" ")
        if not path.startswith("/"):
            raise ValueError(f"not a reading: {line!r}")
        try:
            found[path] = base64.b64decode(encoded, validate=True)
        except binascii.Error:
            raise ValueError(f"not a reading: {line!r}") from None
    return found


def shared(first: Mapping[str, bytes], second: Mapping[str, bytes]) -> list[str]:
    """The paths that hold the same identity in both instances. Empty content and systemd's
    `uninitialized` marker are no identity, so two of them are not a clash."""
    return sorted(path for path, value in first.items() if value not in NO_ID and second.get(path) == value)


def compare(first: Mapping[str, bytes], second: Mapping[str, bytes]) -> Result:
    clashes = shared(first, second)
    passed: list[str] = []
    failed: list[str] = []
    for test, selects in IDENTITY_TESTS:
        ok, bad = split(test, [f"{path} is the same in both instances" for path in clashes if selects(path)])
        passed += ok
        failed += bad
    return result(TWO_CLONES, passed, failed=failed)


def run_docker(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False, timeout=900)


def two_clones(artifact: Path, run: Runner = run_docker) -> CheckOutcome:
    """Import `artifact`, run two containers from it, compare what they read, clean up.

    Not run when docker is missing or its daemon unreachable, or the tarball does not import.
    """
    try:
        info = run(["info", "--format", "{{.ServerVersion}}"])
    except (OSError, subprocess.SubprocessError) as error:
        return NotRun(TWO_CLONES, f"docker is not available: {error}")
    if info.returncode != 0:
        return NotRun(TWO_CLONES, f"docker is not usable: {info.stderr.strip() or info.stdout.strip()}")
    tag = f"dif-two-clones-{uuid.uuid4().hex[:12]}:test"
    names = [f"dif-two-clones-{uuid.uuid4().hex[:12]}-{n}" for n in (1, 2)]
    try:
        imported = run(["import", str(artifact), tag])
        if imported.returncode != 0:
            return NotRun(TWO_CLONES, f"docker could not import the tarball: {imported.stderr.strip()}")
        readings: list[dict[str, bytes]] = []
        for name in names:
            ran = run(["run", "--name", name, "--network", "none", tag, "/bin/sh", "-c", READ_SCRIPT])
            if ran.returncode != 0:
                return NotRun(TWO_CLONES, f"an instance did not run: {ran.stderr.strip()}")
            try:
                readings.append(parse_readings(ran.stdout))
            except ValueError as error:
                return NotRun(TWO_CLONES, f"an instance answered something unreadable: {error}")
        return compare(readings[0], readings[1])
    except (OSError, subprocess.SubprocessError) as error:
        return NotRun(TWO_CLONES, f"docker failed: {error}")
    finally:
        for command in (*(["rm", "--force", name] for name in names), ["rmi", "--force", tag]):
            with contextlib.suppress(OSError, subprocess.SubprocessError):  # the check's own answer stands
                run(command)
