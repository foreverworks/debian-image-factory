"""`ancestry` (DESIGN 11): for an OCI image, the parent's layers are the image's first layers, by digest;
for a kind packed as one root filesystem (Incus), the parent's files are all in the image. Pure.

A core parent is one tarball, which an OCI child carries byte for byte as its first layer, so the layer's
digest is the tarball's sha256. An OCI parent's own layers, in order, are the start of the child's. The
child's manifest also names the parent in `org.opencontainers.image.base.digest`, and that must be the
parent artifact's digest. Digests are sha256 in hex throughout.
"""

import fnmatch
from collections.abc import Mapping, Sequence
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


def files_ancestry(
    members: Sequence[Member], parent_members: Sequence[Member], parent_digest: str, named: str | None
) -> CheckOutcome:
    """`members` are the image's, `parent_members` its parent artifact's (digest `parent_digest`), and
    `named` the parent digest the image's provenance names. Every path of the parent is in the image,
    but what every build removes; the provenance names this parent."""
    held = {member.path for member in members}
    missing = sorted(
        member.path
        for member in parent_members
        if member.path not in held
        and not any(fnmatch.fnmatchcase(member.path, pattern) for pattern in REMOVED_BY_EVERY_BUILD)
    )
    ok_files, bad_files = split(PARENT_FILES, [f"{path} is the parent's and not the image's" for path in missing])
    if named == parent_digest:
        ok_named, bad_named = [PROVENANCE_PARENT], []
    else:
        ok_named = []
        bad_named = [f"{PROVENANCE_PARENT}: the provenance names {named or 'no parent'}, the parent is {parent_digest}"]
    return result(ANCESTRY, [*ok_files, *ok_named], failed=[*bad_files, *bad_named])
