"""An OCI image under rootless Docker (DESIGN 11): load it from its layout, run it, ask it questions, remove it.

`loaded` puts an image layout into the daemon once and hands the image ID to every check that needs the
container (`oci-run`, `two-clones`, `locked-inputs`); the image is removed afterwards by that ID, never by a
name. Docker is reached through `dockerio.Docker`, so the logic is tested with a stand-in.
"""

import contextlib
import json
import re
import subprocess
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .. import oci
from ..modules import Probe
from . import clones
from .dockerio import DOCKER, Docker
from .model import OCI_RUN, CheckOutcome, NotRun, result, split

RUN_TIMEOUT: Final = 120.0
"""Seconds an image gets to start and exit at end of input."""
PROBE_TIMEOUT: Final = 120.0
"""Seconds a version probe gets."""
TIMED_OUT: Final = 124
"""The exit status a probe that ran out of time is given (`timeout(1)`'s)."""

LOADED_ID: Final = re.compile(r"^Loaded image ID: (sha256:[0-9a-f]{64})$", re.MULTILINE)

USER: Final = "user-as-declared"
ENTRYPOINT: Final = "entrypoint-as-declared"
CMD: Final = "cmd-as-declared"
EXIT: Final = "exits-0"

type ProbeRunner = Callable[[Probe], tuple[int, str]]


@dataclass(frozen=True, slots=True)
class Loaded:
    """An image in the daemon, by the ID `docker load` reported."""

    image: str


def load(layout: Path, docker: Docker) -> Loaded | str:
    """Load the OCI image layout directory; the image, or why it is not there (docker missing or unusable,
    the layout refused, or an answer without an image ID)."""
    problem = clones.docker_problem(docker.run)
    if problem is not None:
        return problem
    try:
        loaded = docker.load(layout)
    except (OSError, subprocess.SubprocessError) as error:
        return f"docker could not load the image layout: {error}"
    if loaded.returncode != 0:
        return f"docker could not load the image layout: {loaded.stderr.strip() or loaded.stdout.strip()}"
    found = LOADED_ID.search(loaded.stdout)
    if found is None:
        return f"docker loaded the image layout but reported no image ID: {loaded.stdout.strip()!r}"
    return Loaded(found.group(1))


@contextlib.contextmanager
def loaded(layout: Path, docker: Docker = DOCKER) -> Iterator[Loaded | str]:
    """The image of `layout` in the daemon while the block runs, or the reason it could not be put there.
    The image is removed on exit by its ID, without `--force`, so a name another image holds stays."""
    found = load(layout, docker)
    try:
        yield found
    finally:
        if isinstance(found, Loaded):
            with contextlib.suppress(OSError, subprocess.SubprocessError):  # the checks' answers stand
                docker.run(["rmi", found.image])


# ---- oci-run ---------------------------------------------------------------------------------------


def strings(value: object) -> tuple[str, ...] | None:
    """A list of strings from `docker inspect` as the image config stores it: null and empty are the same."""
    if not isinstance(value, list) or not value:
        return None
    return tuple(str(item) for item in value)


def declared_problems(
    declared: oci.OciConfig, inspected: Mapping[str, object]
) -> tuple[list[str], list[str], list[str]]:
    """(user, entrypoint, cmd) problems: what docker reports for the loaded image against what its config declares."""
    user = inspected.get("User") or None
    entrypoint, cmd = strings(inspected.get("Entrypoint")), strings(inspected.get("Cmd"))
    found: tuple[list[str], list[str], list[str]] = ([], [], [])
    if user != declared.user:
        found[0].append(f"docker reports user {user!r}, the image declares {declared.user!r}")
    if entrypoint != (declared.entrypoint or None):
        found[1].append(f"docker reports {entrypoint!r}, the image declares {declared.entrypoint!r}")
    if cmd != (declared.cmd or None):
        found[2].append(f"docker reports {cmd!r}, the image declares {declared.cmd!r}")
    return found


def tail(text: str, limit: int = 200) -> str:
    """The end of a process's error output on one line, for a failure message."""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else "..." + flat[-limit:]


def oci_run(
    declared: oci.OciConfig, image: Loaded, docker: Docker = DOCKER, timeout: float = RUN_TIMEOUT
) -> CheckOutcome:
    """The loaded image has the user, entrypoint and cmd its config declares, and running it with no
    arguments, no network and standard input closed exits 0 within `timeout` seconds."""
    name = f"dif-oci-run-{uuid.uuid4().hex[:12]}"
    try:
        inspected = docker.run(["image", "inspect", "--format", "{{json .Config}}", image.image])
        if inspected.returncode != 0:
            return NotRun(OCI_RUN, f"docker could not inspect the loaded image: {inspected.stderr.strip()}")
        try:
            config = json.loads(inspected.stdout)
        except json.JSONDecodeError:
            return NotRun(OCI_RUN, f"docker inspect answered something unreadable: {inspected.stdout[:80]!r}")
        if not isinstance(config, dict):
            return NotRun(OCI_RUN, "docker inspect answered something that is not an object")
        fields = {str(key): value for key, value in config.items()}
        user, entrypoint, cmd = declared_problems(declared, fields)
        exited: list[str] = []
        try:
            ran = docker.run_limited(["run", "--rm", "--name", name, "--network", "none", image.image], timeout)
            if ran.returncode != 0:
                exited.append(f"it exited {ran.returncode}: {tail(ran.stderr)}")
        except subprocess.TimeoutExpired:
            exited.append(f"it did not exit within {timeout:g} seconds")
    except (OSError, subprocess.SubprocessError) as error:
        return NotRun(OCI_RUN, f"docker failed: {error}")
    finally:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            docker.run(["rm", "--force", name])
    passed: list[str] = []
    failed: list[str] = []
    for test, problems in ((USER, user), (ENTRYPOINT, entrypoint), (CMD, cmd), (EXIT, exited)):
        ok, bad = split(test, problems)
        passed += ok
        failed += bad
    return result(OCI_RUN, passed, failed=failed)


# ---- two-clones ------------------------------------------------------------------------------------


def two_clones(image: Loaded, docker: Docker = DOCKER) -> CheckOutcome:
    """Two containers of the loaded image share no machine ID or SSH host key (`clones.two_instances`)."""
    return clones.two_instances(image.image, docker.run)


# ---- locked-inputs ---------------------------------------------------------------------------------


def probe_args(image: str, name: str, argv: Sequence[str]) -> list[str]:
    """`docker run --rm --network none --entrypoint <argv[0]> <image> <argv[1:]>`, named so it can be removed."""
    if not argv:
        raise ValueError("a probe has a command to run")
    return ["run", "--rm", "--name", name, "--network", "none", "--entrypoint", argv[0], image, *argv[1:]]


def run_probe(image_ref: str, docker: Docker = DOCKER, timeout: float = PROBE_TIMEOUT) -> ProbeRunner:
    """The runner `locked-inputs` asks its probes through: each runs in a fresh container of `image_ref` (an
    image the daemon holds, by ID), with no network, and gives (exit status, standard output). A probe that
    runs out of time gives TIMED_OUT and an empty output; docker itself failing raises OSError or
    SubprocessError."""

    def run(probe: Probe) -> tuple[int, str]:
        name = f"dif-probe-{uuid.uuid4().hex[:12]}"
        try:
            ran = docker.run_limited(probe_args(image_ref, name, probe.argv), timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                docker.run(["rm", "--force", name])
            return TIMED_OUT, ""
        return ran.returncode, ran.stdout

    return run
