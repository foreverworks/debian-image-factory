"""`incus-boot` and `two-clones` for an Incus image (DESIGN 11), on the Incus host this runs on.

Both run the artifact as Incus runs it: the image is imported from its two files (Incus checks the
fingerprint on import, and the check compares it with the artifact's), instances are launched from it,
and everything this made is deleted afterwards, instances first. Incus is reached through the `incus`
command line, by a `Runner`, so a test can stand in for it; what the answers mean is decided by pure
functions. Where `incus` is missing or its daemon does not answer, both checks are not run, never passed
(DESIGN 9.2: the build stays a candidate until they run).

`incus-boot` launches one instance with `cloud-init.user-data` and one with the older `user.user-data`,
the same cloud-config in both: it creates a user and runs a command that writes a token. For each
instance it proves that cloud-init finished through the NoCloud seed the image's templates filled, that
the user exists, that the command ran, and that Incus reports an IPv4 address; then it restarts the
instance and proves all of it again.

`two-clones` launches two instances with no configuration, waits for their first boot, and reads their
identity: the machine ID, D-Bus's, the SSH host keys and the hostname. Every one of them must differ
between the two, and a first boot must have made a machine ID (and SSH host keys, when the image has
openssh-server): an identity that is absent in both is not a pass.
"""

import contextlib
import json
import subprocess
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .clones import parse_readings, shared
from .machine_identity import NO_ID
from .model import INCUS_BOOT, TWO_CLONES, CheckOutcome, NotRun, Result, result

type Runner = Callable[[Sequence[str], float], subprocess.CompletedProcess[str]]
"""Runs `incus <args>` with a timeout in seconds, capturing text output."""
type Sleep = Callable[[float], None]

USER: Final = "dif-check"
MARKER: Final = "/var/lib/dif-boot-check"
CONFIG_KEYS: Final = ("cloud-init.user-data", "user.user-data")
"""The configuration keys the image's user-data template reads, the current one first (DESIGN 8.1)."""

BOOT_TIMEOUT: Final = 1200.0
"""Seconds a first boot may take, cloud-init's included: generous, since a VM under emulation is slow."""
COMMAND_TIMEOUT: Final = 300.0
ADDRESS_TIMEOUT: Final = 300.0

READ_SCRIPT: Final = (
    "for f in /etc/machine-id /var/lib/dbus/machine-id /etc/hostname /etc/ssh/ssh_host_*_key.pub; do "
    '[ -f "$f" ] && echo "$f $(base64 -w0 "$f")"; done; true'
)
"""Prints `<path> <base64 of the file>` for each identity file an instance has."""

IDENTITIES: Final[tuple[tuple[str, Callable[[str], bool]], ...]] = (
    ("machine-ids-differ", lambda path: path == "/etc/machine-id"),
    ("dbus-machine-ids-differ", lambda path: path == "/var/lib/dbus/machine-id"),
    ("hostnames-differ", lambda path: path == "/etc/hostname"),
    ("ssh-host-keys-differ", lambda path: path.startswith("/etc/ssh/ssh_host_")),
)


def run_incus(args: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["incus", *args], capture_output=True, text=True, check=False, timeout=timeout, stdin=subprocess.DEVNULL
    )


# ---- pure ---------------------------------------------------------------------------------------


def user_data(token: str) -> str:
    """The cloud-config both `incus-boot` instances get: a user, and a command that writes `token`."""
    return (
        "#cloud-config\n"
        "users:\n"
        f"  - name: {USER}\n"
        "    shell: /bin/sh\n"
        "    lock_passwd: true\n"
        "runcmd:\n"
        f"  - [sh, -c, 'echo {token} > {MARKER}']\n"
    )


def imported_fingerprint(output: str) -> str | None:
    """The fingerprint `incus image import` prints (`Image imported with fingerprint: <hex>`)."""
    for line in output.splitlines():
        head, _, tail = line.partition("fingerprint:")
        if tail and "imported" in head.lower():
            return tail.strip()
    return None


def ipv4_addresses(listing: str) -> list[str]:
    """The global IPv4 addresses `incus list <name> --format json` reports for the instance, on any
    interface but the loopback."""
    try:
        instances = json.loads(listing)
    except json.JSONDecodeError:
        return []
    found: list[str] = []
    if not isinstance(instances, list):
        return found
    for instance in instances:
        state = instance.get("state") if isinstance(instance, dict) else None
        network = state.get("network") if isinstance(state, dict) else None
        if not isinstance(network, dict):
            continue
        for name, interface in sorted(network.items()):
            addresses = interface.get("addresses") if isinstance(interface, dict) and name != "lo" else None
            for address in addresses if isinstance(addresses, list) else []:
                if (
                    isinstance(address, dict)
                    and address.get("family") == "inet"
                    and address.get("scope") == "global"
                    and isinstance(address.get("address"), str)
                ):
                    found.append(str(address["address"]))
    return found


def compare_clones(first: Mapping[str, bytes], second: Mapping[str, bytes], *, ssh: bool) -> Result:
    """Every identity differs between the two instances; both have a machine ID their first boot made
    and, when the image has openssh-server, SSH host keys."""
    clashes = shared(first, second)
    passed: list[str] = []
    failed: list[str] = []
    for test, selects in IDENTITIES:
        same = [path for path in clashes if selects(path)]
        if same:
            failed.append(f"{test}: {', '.join(same)} the same in both instances")
        else:
            passed.append(test)
    made = [reading.get("/etc/machine-id", b"") not in NO_ID for reading in (first, second)]
    (passed if all(made) else failed).append(
        "machine-ids-made" if all(made) else "machine-ids-made: an instance has no machine ID after its first boot"
    )
    if ssh:
        keys = [any(path.startswith("/etc/ssh/ssh_host_") for path in reading) for reading in (first, second)]
        (passed if all(keys) else failed).append(
            "ssh-host-keys-made" if all(keys) else "ssh-host-keys-made: an instance has no SSH host keys"
        )
    return result(TWO_CLONES, passed, failed=failed)


@dataclass(frozen=True, slots=True)
class Reading:
    """What one instance answered about its boot (None: the command could not be run)."""

    cloud_init: int | None
    cloud_init_detail: str
    user: bool
    marker: str | None
    addresses: tuple[str, ...]


def boot_tests(prefix: str, token: str, reading: Reading) -> tuple[list[str], list[str], list[str]]:
    """(passed, warned, failed) for one instance's reading. cloud-init's exit 2 means it finished with
    recoverable errors: warned, never passed."""
    passed: list[str] = []
    warned: list[str] = []
    failed: list[str] = []

    def judge(name: str, ok: bool, why: str) -> None:
        (passed if ok else failed).append(name if ok else f"{name}: {why}")

    if reading.cloud_init == 2:
        warned.append(f"{prefix}-cloud-init-done: finished with recoverable errors ({reading.cloud_init_detail})")
    else:
        judge(
            f"{prefix}-cloud-init-done",
            reading.cloud_init == 0,
            f"cloud-init status exited {reading.cloud_init} ({reading.cloud_init_detail})",
        )
    judge(f"{prefix}-nocloud", "NoCloud" in reading.cloud_init_detail, f"datasource: {reading.cloud_init_detail}")
    judge(f"{prefix}-user-created", reading.user, f"no user {USER}")
    judge(f"{prefix}-commands-ran", reading.marker == token, f"{MARKER} holds {reading.marker!r}")
    judge(f"{prefix}-ipv4-reported", bool(reading.addresses), "Incus reports no IPv4 address")
    return passed, warned, failed


# ---- the edge -----------------------------------------------------------------------------------


def incus_problem(run: Runner) -> str | None:
    """Why Incus cannot be used here, or None when its daemon answers."""
    try:
        info = run(["info"], COMMAND_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as error:
        return f"incus is not available: {error}"
    if info.returncode != 0:
        return f"incus is not usable: {info.stderr.strip() or info.stdout.strip()}"
    return None


@dataclass(frozen=True, slots=True)
class Imported:
    alias: str
    fingerprint: str


def import_image(metadata: Path, rootfs: Path, fingerprint: str, run: Runner) -> Imported | str:
    """Import the split image under a throwaway alias; the reason when Incus refuses it or computes
    another fingerprint than the artifact's."""
    alias = f"dif-check-{uuid.uuid4().hex[:12]}"
    done = run(["image", "import", str(metadata), str(rootfs), "--alias", alias], BOOT_TIMEOUT)
    if done.returncode != 0:
        return f"incus image import failed: {done.stderr.strip() or done.stdout.strip()}"
    found = imported_fingerprint(done.stdout + done.stderr)
    if found is not None and found != fingerprint:
        return f"Incus computed the fingerprint {found}, the artifact's is {fingerprint}"
    return Imported(alias, fingerprint)


def forget_image(imported: Imported, run: Runner) -> None:
    with contextlib.suppress(OSError, subprocess.SubprocessError):  # the check's own answer stands
        run(["image", "delete", imported.fingerprint], COMMAND_TIMEOUT)


def launch(alias: str, name: str, config: Mapping[str, str], run: Runner) -> str | None:
    """Launch an instance; the reason when it does not start."""
    args = ["launch", alias, name]
    for key, value in sorted(config.items()):
        args += ["--config", f"{key}={value}"]
    done = run(args, BOOT_TIMEOUT)
    if done.returncode != 0:
        return f"incus launch failed: {done.stderr.strip() or done.stdout.strip()}"
    return None


def remove(names: Sequence[str], run: Runner) -> None:
    for name in names:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            run(["delete", "--force", name], COMMAND_TIMEOUT)


def in_instance(
    name: str, script: str, run: Runner, timeout: float = COMMAND_TIMEOUT
) -> subprocess.CompletedProcess[str]:
    return run(["exec", name, "--", "sh", "-c", script], timeout)


def wait_for_boot(name: str, run: Runner) -> None:
    """Until systemd says the boot ended, whatever it says (a degraded system has booted too)."""
    in_instance(name, "systemctl is-system-running --wait >/dev/null 2>&1; true", run, BOOT_TIMEOUT)


def addresses(name: str, run: Runner, sleep: Sleep) -> tuple[str, ...]:
    """The instance's IPv4 addresses once Incus reports one, or none after ADDRESS_TIMEOUT."""
    deadline = time.monotonic() + ADDRESS_TIMEOUT
    while True:
        listing = run(["list", name, "--format", "json"], COMMAND_TIMEOUT)
        found = ipv4_addresses(listing.stdout) if listing.returncode == 0 else []
        if found or time.monotonic() >= deadline:
            return tuple(found)
        sleep(5.0)


def read_boot(name: str, run: Runner, sleep: Sleep) -> Reading:
    status = in_instance(name, "cloud-init status --wait --long", run, BOOT_TIMEOUT)
    detail = " ".join(
        line.split(":", 1)[1].strip()
        for line in status.stdout.splitlines()
        if line.startswith(("status:", "detail:", "extended_status:"))
    )
    user = in_instance(name, f"getent passwd {USER}", run).returncode == 0
    marker = in_instance(name, f"cat {MARKER}", run)
    return Reading(
        status.returncode,
        detail or status.stderr.strip(),
        user,
        marker.stdout.strip() if marker.returncode == 0 else None,
        addresses(name, run, sleep),
    )


def incus_boot(imported: Imported, run: Runner = run_incus, sleep: Sleep = time.sleep) -> CheckOutcome:
    """DESIGN 11's boot contract, once per user-data key, each instance also after a restart."""
    token = uuid.uuid4().hex
    passed: list[str] = []
    warned: list[str] = []
    failed: list[str] = []
    names = [f"dif-boot-{uuid.uuid4().hex[:8]}-{n}" for n in range(len(CONFIG_KEYS))]
    try:
        for name, key in zip(names, CONFIG_KEYS, strict=True):
            prefix = key.removesuffix(".user-data").replace(".", "-")
            problem = launch(imported.alias, name, {key: user_data(token)}, run)
            if problem is not None:
                return NotRun(INCUS_BOOT, problem)
            for stage in ("first-boot", "after-restart"):
                if stage == "after-restart":
                    restarted = run(["restart", name], BOOT_TIMEOUT)
                    if restarted.returncode != 0:
                        failed.append(f"{prefix}-{stage}-restart: {restarted.stderr.strip()}")
                        continue
                wait_for_boot(name, run)
                ok, warn, bad = boot_tests(f"{prefix}-{stage}", token, read_boot(name, run, sleep))
                passed += ok
                warned += warn
                failed += bad
        return result(INCUS_BOOT, passed, warned, failed)
    except (OSError, subprocess.SubprocessError) as error:
        return NotRun(INCUS_BOOT, f"incus failed: {error}")
    finally:
        remove(names, run)


def two_clones(imported: Imported, *, ssh: bool, run: Runner = run_incus) -> CheckOutcome:
    """Two instances of the image, after their first boot, share no identity."""
    names = [f"dif-clone-{uuid.uuid4().hex[:8]}-{n}" for n in (1, 2)]
    try:
        readings: list[dict[str, bytes]] = []
        for name in names:
            problem = launch(imported.alias, name, {}, run)
            if problem is not None:
                return NotRun(TWO_CLONES, problem)
        for name in names:
            wait_for_boot(name, run)
            read = in_instance(name, READ_SCRIPT, run)
            if read.returncode != 0:
                return NotRun(TWO_CLONES, f"an instance could not be read: {read.stderr.strip()}")
            try:
                readings.append(parse_readings(read.stdout))
            except ValueError as error:
                return NotRun(TWO_CLONES, f"an instance answered something unreadable: {error}")
        return compare_clones(readings[0], readings[1], ssh=ssh)
    except (OSError, subprocess.SubprocessError) as error:
        return NotRun(TWO_CLONES, f"incus failed: {error}")
    finally:
        remove(names, run)
