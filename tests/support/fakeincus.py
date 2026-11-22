"""A stand-in for the `incus` command line: a function over a small state, for the host checks' tests.

`runner(host)` is a `Runner` (`incus_host.Runner`): it records every call in `host.calls`, answers each command
from the host's settings, keeps the images and instances it was asked to make in `host.images` and
`host.instances` (so a test can see what is left behind), and acts on what an instance was configured with: the
user-data an instance is launched with decides whether its user exists and what its command wrote.
"""

import base64
import hashlib
import json
import re
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from debian_image_factory import fileartifacts
from debian_image_factory.checks import incus_host
from debian_image_factory.checks.incus_host import Runner

NOCLOUD = "DataSourceNoCloud [seed=/var/lib/cloud/seed/nocloud-net][dsmode=net]"


@dataclass(slots=True)
class Host:
    """What the stand-in holds (`images`, `instances`, `calls`) and how it answers (everything else)."""

    missing: bool = False
    """The `incus` command does not exist: every call raises FileNotFoundError."""
    info_returncode: int = 0
    info_error: str = ""
    import_returncode: int = 0
    import_error: str = ""
    printed_fingerprint: str | None = None
    """What `image import` says it computed; None: the real one, from the two files; "": nothing."""
    launch_fails: frozenset[int] = frozenset()
    """Which launches (counted from 1) fail."""
    restart_fails: bool = False
    cloud_init_status: int = 0
    cloud_init_detail: str = NOCLOUD
    honours: tuple[str, ...] = incus_host.CONFIG_KEYS
    """The user-data keys the image's templates read."""
    silent_polls: int = 0
    """How many `list` calls answer with no address before one appears (-1: never)."""
    identities: Sequence[Mapping[str, bytes]] = ()
    """What each instance (in launch order) reads from its identity files; none: every instance has its own."""
    read_returncode: int = 0
    read_output: str | None = None
    """What reading an instance prints instead of its identities, when set."""
    raises: tuple[str, BaseException] | None = None
    """A word in a command, and what the call raises when it has it."""
    delete_raises: bool = False
    calls: list[tuple[str, ...]] = field(default_factory=list)
    images: dict[str, str] = field(default_factory=dict)
    """The images Incus holds, by alias, with their fingerprints."""
    instances: dict[str, dict[str, str]] = field(default_factory=dict)
    """The instances Incus holds, with the configuration each was launched with."""
    launched: list[str] = field(default_factory=list)
    polls: int = 0


def listing(*addresses: tuple[str, str, str]) -> str:
    """`incus list <name> --format json` for one instance with these (family, address, scope) on eth0 and
    the loopback's own addresses: what Incus prints, as far as the checks read it."""
    return json.dumps(
        [
            {
                "name": "instance",
                "status": "Running",
                "state": {
                    "status": "Running",
                    "network": {
                        "lo": {
                            "addresses": [
                                {"family": "inet", "address": "127.0.0.1", "netmask": "8", "scope": "local"},
                                {"family": "inet6", "address": "::1", "netmask": "128", "scope": "local"},
                            ],
                            "type": "loopback",
                        },
                        "eth0": {
                            "addresses": [
                                {"family": family, "address": address, "netmask": "24", "scope": scope}
                                for family, address, scope in addresses
                            ],
                            "type": "broadcast",
                        },
                    },
                },
            }
        ]
    )


def process(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def applied(config: Mapping[str, str], honours: Sequence[str]) -> tuple[bool, str | None]:
    """(whether the user exists, what the command wrote) once cloud-init has read an instance's user-data."""
    for key in honours:
        text = config.get(key)
        if text is not None:
            found = re.search(r"echo (\S+) >", text)
            return f"name: {incus_host.USER}" in text, found.group(1) if found else None
    return False, None


def reading(files: Mapping[str, bytes]) -> str:
    """What the identity script prints for the files an instance has."""
    return "".join(f"{path} {base64.b64encode(content).decode()}\n" for path, content in sorted(files.items()))


def own_identity(name: str) -> dict[str, bytes]:
    """The identity files of an instance that made its own at first boot: nothing is shared with another."""
    digest = hashlib.sha256(name.encode()).hexdigest()
    return {
        "/etc/machine-id": f"{digest[:32]}\n".encode(),
        "/var/lib/dbus/machine-id": f"{digest[32:]}\n".encode(),
        "/etc/hostname": f"{name}\n".encode(),
        "/etc/ssh/ssh_host_ed25519_key.pub": f"ssh-ed25519 {digest}\n".encode(),
    }


def answer_exec(host: Host, name: str, script: str) -> subprocess.CompletedProcess[str]:
    instance = host.instances.get(name)
    if instance is None:
        return process(1, stderr=f"Error: Instance not found: {name}")
    user, marker = applied(instance, host.honours)
    if script.startswith("systemctl is-system-running"):
        return process()
    if script.startswith("cloud-init status"):
        out = f"status: done\nextended_status: done\ndetail: {host.cloud_init_detail}\nerrors: []\n"
        return process(host.cloud_init_status, out if host.cloud_init_detail else "")
    if script.startswith("getent passwd"):
        return process(0 if user else 2)
    if script.startswith("cat "):
        return process(0, marker + "\n") if marker is not None else process(1, stderr="No such file")
    if script == incus_host.READ_SCRIPT:
        if host.read_output is not None:
            return process(host.read_returncode, host.read_output)
        files = host.identities[host.launched.index(name)] if host.identities else own_identity(name)
        return process(host.read_returncode, reading(files), "" if host.read_returncode == 0 else "exec failed")
    return process(127, stderr=f"unexpected script: {script}")


def run(host: Host, args: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    host.calls.append(tuple(args))
    if host.missing:
        raise FileNotFoundError(2, "No such file or directory", "incus")
    if host.raises is not None and host.raises[0] in " ".join(args):
        raise host.raises[1]
    verb, rest = args[0], list(args[1:])
    if verb == "info":
        return process(host.info_returncode, "config: {}\n", host.info_error)
    if verb == "image" and rest[0] == "import":
        alias = rest[rest.index("--alias") + 1]
        if host.import_returncode != 0:
            return process(host.import_returncode, stderr=host.import_error)
        real = fileartifacts.fingerprint_of(Path(rest[1]), Path(rest[2]))
        fingerprint = host.printed_fingerprint if host.printed_fingerprint is not None else real
        host.images[alias] = fingerprint or real
        return process(0, f"Image imported with fingerprint: {fingerprint}\n" if fingerprint else "")
    if verb == "image" and rest[0] == "delete":
        for alias in [alias for alias, fingerprint in host.images.items() if fingerprint == rest[1]]:
            del host.images[alias]
        return process()
    if verb == "launch":
        host.launched.append(rest[1])
        if len(host.launched) in host.launch_fails:
            return process(1, stderr="Error: Failed instance creation: no space left")
        config = {pair.split("=", 1)[0]: pair.split("=", 1)[1] for pair in rest[2:] if "=" in pair}
        host.instances[rest[1]] = config
        return process()
    if verb == "restart":
        return process(1, stderr="Error: instance did not stop") if host.restart_fails else process()
    if verb == "delete":
        if host.delete_raises:
            raise OSError("the incus socket is gone")
        host.instances.pop(rest[-1], None)
        return process()
    if verb == "list":
        host.polls += 1
        silent = host.silent_polls < 0 or host.polls <= host.silent_polls
        return process(0, listing() if silent else listing(("inet", "192.0.2.15", "global")))
    if verb == "exec":
        return answer_exec(host, rest[0], rest[-1])
    return process(2, stderr=f"unexpected command: {verb}")


def runner(host: Host) -> Runner:
    """The stand-in as a `Runner`."""

    def run_incus(args: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
        return run(host, args, timeout)

    return run_incus
