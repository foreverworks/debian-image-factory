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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from input_lock import Package

from . import archive, debian, remote, vendordeb
from .debian import Suite as Suite
from .debian import suites as suites

SNAPSHOT_SERVICE: Final = "https://snapshot.debian.org"
DEFAULT_KEYRING: Final = Path("/usr/share/keyrings/debian-archive-keyring.pgp")

INST: Final = re.compile(r"^Inst (?P<name>\S+) (?:\[(?P<old>[^\]]+)\] )?\((?P<version>\S+) .*\[(?P<arch>[^\]]+)\]\)")
STATUS_DROP: Final = frozenset(("Filename", "Size", "MD5sum", "SHA1", "SHA256", "SHA512", "Description-md5"))


class ResolveError(Exception):
    """apt could not resolve a request, or resolved it in a way the factory refuses."""


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
    snapshots: Mapping[str, str] = field(default_factory=dict)
    """The ID each archive was read at, to name in an error."""


@dataclass(frozen=True, slots=True)
class Inst:
    name: str
    version: str
    arch: str
    old: str | None


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
APT::Sandbox::User "root";
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
    snapshot_ids: Mapping[str, str],
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
    """Fetch and verify the snapshots' indices, lay them out under `workdir`, and run apt-get update. Each suite is
    read at the ID of its own archive: `snapshot_ids` has one for every archive."""
    indices = [
        archive.fetch_suite(
            snapshot_base(service, one.archive, snapshot_ids[one.archive]),
            one.dist,
            components,
            arch,
            keyring,
            cache,
            read,
        )
        for one in suites(suite)
    ]
    mirror = archive.lay_out_mirror(indices, workdir / "mirror")
    root = workdir / "apt"
    make_root(
        root,
        arch,
        "".join(
            f"deb [signed-by={keyring}] file:{mirror / one.archive} {one.dist} {' '.join(components)}\n"
            for one in suites(suite)
        ),
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
    return OpenArchive(root, keyring, arch, stanzas, tuple(sorted(set(essential))), dict(snapshot_ids))


def read_at(snapshot_ids: Mapping[str, str]) -> str:
    """The snapshots an error was found at, for its message: `debian 2026... and debian-security 2026...`."""
    return " and ".join(f"{archive} {snapshot_id}" for archive, snapshot_id in snapshot_ids.items())


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


def status_text(
    open_archive_: OpenArchive, installed: Sequence[Package], vendor: Mapping[Package, Mapping[str, str]] | None = None
) -> str:
    """A dpkg status file of `installed`, written from the same Packages stanzas apt resolved them from: the
    snapshot's, or for a vendor .deb an ancestor installs, its verified stanza in `vendor`."""
    paragraphs = []
    for package in sorted(installed):
        stanza = open_archive_.stanzas.get(package) or (vendor or {}).get(package)
        if stanza is None:
            raise ResolveError(
                f"{package[0]} {package[1]} ({package[2]}) is not in the snapshots' indices "
                f"({read_at(open_archive_.snapshots)})"
            )
        fields = [(key, value) for key, value in stanza.items() if key not in STATUS_DROP]
        fields.insert(1, ("Status", "install ok installed"))
        paragraphs.append("".join(f"{key}: {value}\n" for key, value in fields))
    return "\n".join(paragraphs)


def make_root(root: Path, arch: str, sources: str) -> None:
    """A scratch apt root reading `sources` (a sources.list), with an empty status."""
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
    (root / "sources.list").write_text(sources)


def vendor_root(open_archive_: OpenArchive, label: str, stanzas: Sequence[Mapping[str, str]]) -> Path:
    """An apt root for one image alone: the snapshot's sources plus a local flat repository holding the vendor
    stanzas that image installs, so no other image's resolution can see them.

    The flat repository is `[trusted=yes]`: apt has no signature to check there, and needs none, because each
    stanza in it was read from a Packages index its vendor's signed InRelease vouches for, with the stanza's
    sha256 equal to the lock's (`vendordeb.verify`), before it was written here."""
    root = open_archive_.root.parent / f"apt-{label}"
    flat = root / "vendor"
    flat.mkdir(parents=True)
    (flat / "Packages").write_text(vendordeb.stanza_text(stanzas))
    shared = (open_archive_.root / "sources.list").read_text()
    make_root(root, open_archive_.arch, f"{shared}deb [trusted=yes] file:{flat} ./\n")
    run_apt(root, "update")
    return root


def simulate(
    open_archive_: OpenArchive,
    installed: Sequence[Package],
    request: Sequence[str],
    *,
    allow_upgrade: bool,
    label: str,
    root: Path | None = None,
    vendor: Mapping[Package, Mapping[str, str]] | None = None,
) -> tuple[Package, ...]:
    """The package set after installing `request` on top of `installed`, in the archive's apt root or `root`."""
    apt_root = open_archive_.root if root is None else root
    status = open_archive_.root / f"status-{label}"
    status.write_text(status_text(open_archive_, installed, vendor))
    try:
        output = run_apt(apt_root, "--simulate", "install", "--", *sorted(set(request)), status=status)
    except ResolveError as error:
        raise ResolveError(f"{label}: {error}\nthe indices are those of {read_at(open_archive_.snapshots)}") from None
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
    open_archive_: OpenArchive,
    parent: Sequence[Package],
    request: Sequence[str],
    label: str,
    *,
    own: Sequence[Mapping[str, str]] = (),
    vendor: Mapping[Package, Mapping[str, str]] | None = None,
) -> tuple[Package, ...]:
    """A child's set on top of its parent's. `own` are the verified vendor stanzas the child installs: each is
    asked for as `name=version` in the same transaction as `request`, from an apt root of the child's own.
    `vendor` holds the verified stanzas of every vendor .deb an ancestor installs, for the status file."""
    if not own:
        return simulate(open_archive_, parent, request, allow_upgrade=False, label=label, vendor=vendor)
    root = vendor_root(open_archive_, label, own)
    pinned = [f"{stanza['Package']}={stanza['Version']}" for stanza in own]
    return simulate(
        open_archive_, parent, [*request, *pinned], allow_upgrade=False, label=label, root=root, vendor=vendor
    )
