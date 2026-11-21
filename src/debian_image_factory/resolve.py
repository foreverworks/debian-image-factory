"""Resolving package sets without building (DESIGN 7.2): apt's own solver in a scratch apt root.

The edge that runs `apt-get`. An archive is opened once per plan: each suite's signed indices are
fetched and verified (`archive.fetch_suite`), laid out as a partial mirror, and `apt-get update`
reads that mirror through `file:` sources, verifying it again. Each image is then one or more
`apt-get --simulate install` runs against a dpkg status file holding what its parent installed.

Core is resolved the way mmdebstrap's `apt` variant installs it, in two transactions: first every
`Essential: yes` package of the suite itself, then `apt` and the definition's packages on top.
Recommends are never installed, as in mmdebstrap. Runs as an ordinary user.
"""

import os
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from input_lock import Package

from . import archive, debian, remote

SNAPSHOT_SERVICE: Final = "https://snapshot.debian.org"
DEFAULT_KEYRING: Final = Path("/usr/share/keyrings/debian-archive-keyring.pgp")

INST: Final = re.compile(r"^Inst (?P<name>\S+) (?:\[(?P<old>[^\]]+)\] )?\((?P<version>\S+) .*\[(?P<arch>[^\]]+)\]\)")
STATUS_DROP: Final = frozenset(("Filename", "Size", "MD5sum", "SHA1", "SHA256", "SHA512", "Description-md5"))


class ResolveError(Exception):
    """apt could not resolve a request, or resolved it in a way the factory refuses."""


@dataclass(frozen=True, slots=True)
class Suite:
    archive: str
    """The snapshot.debian.org archive: `debian` or `debian-security`."""
    dist: str


@dataclass(frozen=True, slots=True)
class OpenArchive:
    """One snapshot's verified indices, laid out for apt, and the apt root that reads them."""

    root: Path
    keyring: Path
    arch: str
    stanzas: Mapping[Package, Mapping[str, str]]
    """Every package the indices offer, by (name, version, architecture)."""
    essential: tuple[str, ...]
    """The suite's own `Essential: yes` packages (not those of -updates or -security)."""


@dataclass(frozen=True, slots=True)
class Inst:
    name: str
    version: str
    arch: str
    old: str | None


def suites(suite: str) -> tuple[Suite, ...]:
    """The suites a build snapshot covers: main, updates and security (DESIGN 2.1)."""
    return (Suite("debian", suite), Suite("debian", f"{suite}-updates"), Suite("debian-security", f"{suite}-security"))


def snapshot_base(service: str, archive_name: str, snapshot_id: str) -> str:
    return f"{service.rstrip('/')}/archive/{archive_name}/{snapshot_id}"


def apt_conf(root: Path, arch: str) -> str:
    """A scratch apt root's configuration: nothing is read from the host's /etc/apt."""
    return f"""Dir "{root}";
Dir::State "{root}/state";
Dir::State::Lists "{root}/state/lists";
Dir::State::status "{root}/status";
Dir::Cache "{root}/cache";
Dir::Etc "{root}/etc";
Dir::Etc::SourceList "{root}/sources.list";
Dir::Etc::SourceParts "{root}/etc/sources.list.d";
Dir::Etc::Parts "{root}/etc/apt.conf.d";
Dir::Etc::PreferencesParts "{root}/etc/preferences.d";
Debug::NoLocking "true";
APT::Architecture "{arch}";
APT::Architectures "{arch}";
APT::Install-Recommends "false";
Acquire::Languages "none";
Acquire::Check-Valid-Until "false";
pkgCacheGen::ForceEssential ",";
"""


def apt_env(root: Path) -> dict[str, str]:
    keep = {key: value for key, value in os.environ.items() if not key.startswith(("APT_", "LC_", "LANG"))}
    return {**keep, "APT_CONFIG": str(root / "apt.conf"), "LC_ALL": "C.UTF-8"}


def run_apt(root: Path, *args: str, status: Path | None = None) -> str:
    extra = ["-o", f"Dir::State::status={status}"] if status is not None else []
    done = subprocess.run(
        ["apt-get", "-q", *extra, *args], env=apt_env(root), capture_output=True, text=True, check=False
    )
    if done.returncode != 0:
        raise ResolveError(f"apt-get {' '.join(args)} failed:\n{done.stdout}{done.stderr}".rstrip())
    return done.stdout


def open_archive(
    snapshot_id: str,
    suite: str,
    components: Sequence[str],
    arch: str,
    *,
    keyring: Path,
    cache: Path,
    workdir: Path,
    service: str = SNAPSHOT_SERVICE,
    read: Callable[[str], bytes] = remote.read_url,
) -> OpenArchive:
    """Fetch and verify the snapshot's indices, lay them out under `workdir`, and run apt-get update."""
    indices = [
        archive.fetch_suite(
            snapshot_base(service, one.archive, snapshot_id), one.dist, components, arch, keyring, cache, read
        )
        for one in suites(suite)
    ]
    mirror = archive.lay_out_mirror(indices, workdir / "mirror")
    root = workdir / "apt"
    for directory in (
        "state/lists/partial",
        "cache/archives/partial",
        "etc/sources.list.d",
        "etc/apt.conf.d",
        "etc/preferences.d",
    ):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "status").write_text("")
    (root / "apt.conf").write_text(apt_conf(root, arch))
    (root / "sources.list").write_text(
        "".join(
            f"deb [signed-by={keyring}] file:{mirror / one.archive} {one.dist} {' '.join(components)}\n"
            for one in suites(suite)
        )
    )
    run_apt(root, "update")
    stanzas: dict[Package, Mapping[str, str]] = {}
    essential: list[str] = []
    for index in indices:
        for path, local in index.files:
            if not path.endswith("/Packages"):
                continue
            found = debian.packages_stanzas(local.read_text())
            for stanza in found:
                key = (stanza["Package"], stanza["Version"], stanza["Architecture"])
                stanzas.setdefault(key, stanza)
            if index.dist == suite:
                essential.extend(debian.essential(found, arch))
    return OpenArchive(root, keyring, arch, stanzas, tuple(sorted(set(essential))))


def parse_simulation(output: str) -> list[Inst]:
    """The `Inst` lines of `apt-get --simulate`; a removal is refused (nothing may leave an image)."""
    found: list[Inst] = []
    for line in output.splitlines():
        if line.startswith("Remv "):
            raise ResolveError(f"apt would remove a package: {line}")
        match = INST.match(line)
        if match:
            found.append(Inst(match["name"], match["version"], match["arch"], match["old"]))
        elif line.startswith("Inst "):
            raise ResolveError(f"cannot read apt's line: {line}")
    return found


def status_text(open_archive_: OpenArchive, installed: Sequence[Package]) -> str:
    """A dpkg status file of `installed`, written from the same Packages stanzas apt resolved them from."""
    paragraphs = []
    for package in sorted(installed):
        stanza = open_archive_.stanzas.get(package)
        if stanza is None:
            raise ResolveError(f"{package[0]} {package[1]} ({package[2]}) is not in this snapshot's indices")
        fields = [(key, value) for key, value in stanza.items() if key not in STATUS_DROP]
        fields.insert(1, ("Status", "install ok installed"))
        paragraphs.append("".join(f"{key}: {value}\n" for key, value in fields))
    return "\n".join(paragraphs)


def simulate(
    open_archive_: OpenArchive, installed: Sequence[Package], request: Sequence[str], *, allow_upgrade: bool, label: str
) -> tuple[Package, ...]:
    """The package set after installing `request` on top of `installed`."""
    status = open_archive_.root / f"status-{label}"
    status.write_text(status_text(open_archive_, installed))
    output = run_apt(open_archive_.root, "--simulate", "install", "--", *sorted(set(request)), status=status)
    result = {name: (name, version, arch) for name, version, arch in installed}
    for inst in parse_simulation(output):
        if inst.old is not None and not allow_upgrade:
            raise ResolveError(
                f"{label}: apt would upgrade {inst.name} from {inst.old} to {inst.version}, which its parent "
                "installed: rebuild the parent first (a child never upgrades its parent's packages)"
            )
        result[inst.name] = (inst.name, inst.version, inst.arch)
    return tuple(sorted(result.values()))


def resolve_core(open_archive_: OpenArchive, packages: Sequence[str]) -> tuple[Package, ...]:
    """Core as mmdebstrap's apt variant installs it: the Essential set, then apt and the packages."""
    essential = simulate(open_archive_, (), open_archive_.essential, allow_upgrade=False, label="core-essential")
    return simulate(open_archive_, essential, ["apt", *packages], allow_upgrade=True, label="core")


def resolve_child(
    open_archive_: OpenArchive, parent: Sequence[Package], request: Sequence[str], label: str
) -> tuple[Package, ...]:
    return simulate(open_archive_, parent, request, allow_upgrade=False, label=label)
