"""`ancestry` (DESIGN 11), pure. For an OCI image: the parent's layers are the image's first layers, by
digest. For a root filesystem (an OS root, an installer's initrd): the parent's files are all there, but
for those the child says it removed. For an Incus image, the parent's files are all in the image.

A core parent is one tarball, which an OCI child carries byte for byte as its first layer, so the layer's
digest is the tarball's sha256. An OCI parent's own layers, in order, are the start of the child's. The
child's manifest also names the parent in `org.opencontainers.image.base.digest`, and that must be the
parent artifact's digest. Digests are sha256 in hex throughout.
"""

import fnmatch
import posixpath
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from .. import oci
from .model import ANCESTRY, CheckOutcome, NotRun, result, split
from .tarball import Member

LAYERS_FIRST = "parent-layers-are-first"
BASE_DIGEST = "base-digest-annotation"
PARENT_FILES = "parent-files-present"
PROVENANCE_PARENT = "provenance-names-parent"

REMOVED_BY_EVERY_BUILD: Final = (
    "/etc/hostname",
    "/etc/resolv.conf",
    "/etc/ssh/ssh_host_*",
    "/var/lib/dbus/machine-id",
    "/var/lib/systemd/random-seed",
    "/var/lib/urandom/random-seed",
    "/var/lib/cloud/instance",
    "/var/lib/cloud/instances",
    "/var/lib/cloud/instances/*",
    "/var/log/*",
    "/var/cache/ldconfig/aux-cache",
    "/var/lib/apt/lists/*",
    "/var/cache/apt/*",
    "/run/*",
    "/tmp/*",
)
"""What every child build removes from its root, whatever its parent held (build/core.py's identity lines
and build/oci.py's cleanup): a parent path that matches is not missing from its child."""


@dataclass(frozen=True, slots=True)
class Parent:
    """The parent artifact as far as it is known here: its digest, and its layers' digests (base first)
    when the artifact is local. A parent known only by the plan's digest has `layers` None."""

    digest: str
    layers: tuple[str, ...] | None


def layer_problems(layers: Sequence[str], parent: Sequence[str]) -> list[str]:
    """How `layers` fail to start with `parent`: the first difference, or that it is shorter."""
    if len(layers) < len(parent):
        return [f"the image has {len(layers)} layers, the parent {len(parent)}"]
    for position, (mine, theirs) in enumerate(zip(layers, parent, strict=False)):
        if mine != theirs:
            return [f"layer {position + 1} is sha256:{mine}, the parent's is sha256:{theirs}"]
    return []


def base_problems(annotations: Mapping[str, str], parent_digest: str) -> list[str]:
    declared = annotations.get(oci.BASE_DIGEST)
    if declared is None:
        return [f"the manifest has no {oci.BASE_DIGEST} annotation"]
    try:
        found = oci.parse_digest(declared)
    except oci.OciError:
        return [f"{oci.BASE_DIGEST} is {declared!r}, which is not a sha256 digest"]
    if found != parent_digest:
        return [f"{oci.BASE_DIGEST} is sha256:{found}, the parent artifact is sha256:{parent_digest}"]
    return []


def ancestry(layers: Sequence[str], annotations: Mapping[str, str], parent: Parent | str) -> CheckOutcome:
    """`layers` are the image's layer digests and `annotations` its manifest's. `parent` is the parent
    artifact, or the reason it is not available here (a missing parent is not run, never passed)."""
    if isinstance(parent, str):
        return NotRun(ANCESTRY, parent)
    if parent.layers is None:
        return NotRun(ANCESTRY, f"the parent sha256:{parent.digest} is not in the output, so its layers are unknown")
    ok_layers, bad_layers = split(LAYERS_FIRST, layer_problems(layers, parent.layers))
    ok_base, bad_base = split(BASE_DIGEST, base_problems(annotations, parent.digest))
    return result(ANCESTRY, [*ok_layers, *ok_base], failed=[*bad_layers, *bad_base])


def parent_files(
    child: Sequence[Member], parent: Sequence[Member], excused: Callable[[str], bool], describe: Callable[[str], str]
) -> tuple[list[str], list[str]]:
    """The one test both root ancestries share: (passed, failed) of `parent-files-present`, every path of
    `parent` is in `child` but for the ones `excused` names. `describe` words a missing path."""
    present = {member.path for member in child}
    missing = sorted(member.path for member in parent if member.path not in present and not excused(member.path))
    return split(PARENT_FILES, [describe(path) for path in missing])


def removed_by_every_build(path: str) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in REMOVED_BY_EVERY_BUILD)


def files_ancestry(
    members: Sequence[Member], parent_members: Sequence[Member], parent_digest: str, named: str | None
) -> CheckOutcome:
    """`members` are the image's, `parent_members` its parent artifact's (digest `parent_digest`), and
    `named` the parent digest the image's provenance names. Every path of the parent is in the image,
    but what every build removes; the provenance names this parent."""
    ok_files, bad_files = parent_files(
        members, parent_members, removed_by_every_build, lambda path: f"{path} is the parent's and not the image's"
    )
    if named == parent_digest:
        ok_named, bad_named = [PROVENANCE_PARENT], []
    else:
        ok_named = []
        bad_named = [f"{PROVENANCE_PARENT}: the provenance names {named or 'no parent'}, the parent is {parent_digest}"]
    return result(ANCESTRY, [*ok_files, *ok_named], failed=[*bad_files, *bad_named])


# ---- root filesystems ------------------------------------------------------------------------------

DPKG_INFO: Final = "/var/lib/dpkg/info/"

CLEANED: Final = (
    "/dev/",
    "/run/",
    "/tmp/",
    "/var/tmp/",
    "/var/log/",
    "/var/cache/apt/",
    "/var/cache/ldconfig/",
    "/var/lib/apt/lists/",
    "/var/lib/dpkg/triggers/",
    "/var/lib/dpkg/updates/",
    "/etc/apt/sources.list.d/",
)
"""Trees whose content a child's build replaces as a matter of course (DESIGN 5.3): device nodes (the booted
system mounts devtmpfs), run and temporary files, logs, apt's and ldconfig's caches and lists, dpkg's
pending triggers and updates, and the apt sources each image renders for itself (`apt_sources`)."""
CLEANED_FILES: Final = frozenset(
    (
        "/etc/apt/sources.list",
        "/etc/hostname",
        "/etc/resolv.conf",
        "/var/lib/dbus/machine-id",
        "/var/lib/systemd/random-seed",
        "/var/lib/urandom/random-seed",
    )
)
"""Files the identity cleanup removes from every image (DESIGN 5.3), and the sources file `apt_sources`
renders."""
SSH_HOST_KEY_PREFIX: Final = "/etc/ssh/ssh_host_"


@dataclass(frozen=True, slots=True)
class ParentRoot:
    """A parent's root filesystem as far as `ancestry` needs it: its digest, every member, and the content of
    its dpkg file lists (`/var/lib/dpkg/info/<package>[:<arch>].list`) by path."""

    digest: str
    members: tuple[Member, ...]
    lists: Mapping[str, bytes]


def is_file_list(path: str) -> bool:
    return path.startswith(DPKG_INFO) and path.endswith(".list") and "/" not in path[len(DPKG_INFO) :]


def package_of(info_path: str) -> str:
    """The package a `/var/lib/dpkg/info/<package>[:<arch>].<suffix>` file belongs to."""
    base = posixpath.basename(info_path)
    return base.rsplit(".", 1)[0].split(":", 1)[0]


def listed_paths(list_text: bytes) -> set[str]:
    """The paths of one dpkg file list (`/.` is the root)."""
    found = set()
    for line in list_text.decode("utf-8", "surrogateescape").splitlines():
        if line.startswith("/"):
            found.add(posixpath.normpath(line))
    return found


def cleaned(path: str) -> bool:
    return (
        path in CLEANED_FILES
        or path.startswith(CLEANED)
        or path.startswith(SSH_HOST_KEY_PREFIX)
        or path + "/" in CLEANED
    )


def removed_by_packages(parent: ParentRoot, installed: Collection[str]) -> set[str]:
    """The parent's paths that belong to packages the child no longer installs: what each one's file list
    names, and the package's own dpkg info files."""
    gone: set[str] = set()
    for path, text in parent.lists.items():
        if package_of(path) not in installed:
            gone |= listed_paths(text)
    gone |= {m.path for m in parent.members if m.path.startswith(DPKG_INFO) and package_of(m.path) not in installed}
    return gone


def root_ancestry(child: Sequence[Member], installed: Collection[str] | str, parent: ParentRoot | str) -> CheckOutcome:
    """Every path of the parent's root is in the child's, but for paths of packages the child no longer
    installs (`installed` is the child's installed package names, from its dpkg status, which `package-set`
    and `sbom-complete` hold to its plan and its records; or why they cannot be read) and the trees every
    build cleans (CLEANED). A parent that is not here is not run, never passed."""
    if isinstance(parent, str):
        return NotRun(ANCESTRY, parent)
    if isinstance(installed, str):
        return result(ANCESTRY, [], failed=[f"dpkg-status-readable: {installed}"])
    removed = removed_by_packages(parent, installed)
    ok, bad = parent_files(
        child,
        parent.members,
        lambda path: path in removed or cleaned(path),
        lambda path: f"{path} is in the parent sha256:{parent.digest[:12]} and not here",
    )
    return result(ANCESTRY, ["dpkg-status-readable", *ok], failed=bad)
