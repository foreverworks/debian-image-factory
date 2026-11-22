"""`ancestry` (DESIGN 11), pure. For an OCI image: the parent's layers are the image's first layers, by
digest. For a root filesystem (an Incus image's squashfs, an OS root, an installer's initrd): the parent's files
are all there, but for those the child's provenance says its build removed.

A core parent is one tarball, which an OCI child carries byte for byte as its first layer, so the layer's
digest is the tarball's sha256. An OCI parent's own layers, in order, are the start of the child's. The
child's manifest also names the parent in `org.opencontainers.image.base.digest`, and that must be the
parent artifact's digest. Digests are sha256 in hex throughout.
"""

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


def names_parent(named: str | None, parent_digest: str) -> tuple[list[str], list[str]]:
    """(passed, failed) of `provenance-names-parent`: the provenance names the parent artifact by digest."""
    if named == parent_digest:
        return [PROVENANCE_PARENT], []
    return [], [f"{PROVENANCE_PARENT}: the provenance names {named or 'no parent'}, the parent is {parent_digest}"]


# ---- root filesystems ------------------------------------------------------------------------------

ROOT: Final = "/"
"""The root directory: always there, and not a member of a layer-style tarball (layer.py writes none)."""


def removed_from_parent(child: Sequence[Member], parent: Sequence[Member]) -> list[str]:
    """The parent's paths the child does not hold, sorted: what the build records it removed (its provenance's
    `removedFromParent`), whether a package's removal, the identity cleanup or a hook took them."""
    present = {member.path for member in child}
    return sorted({member.path for member in parent if member.path != ROOT and member.path not in present})


def root_ancestry(
    child: Sequence[Member],
    parent: Sequence[Member] | str,
    parent_digest: str,
    named: str | None,
    recorded: Collection[str] | str,
) -> CheckOutcome:
    """`ancestry` of a root filesystem built on a parent's: an OS root, an installer kit's root, an Incus
    image's. `parent` is the parent artifact's members (or why they cannot be read), `named` the parent
    digest the child's provenance names, `recorded` the paths its provenance says the build removed from the
    parent (or why they cannot be read). Every path of the parent is in the child but for the recorded ones,
    and the provenance names this parent. A parent that is not here is not run, never passed."""
    if isinstance(parent, str):
        return NotRun(ANCESTRY, parent)
    if isinstance(recorded, str):
        return result(ANCESTRY, [], failed=[f"{PARENT_FILES}: {recorded}"])
    excused = set(recorded)
    ok_files, bad_files = parent_files(
        child,
        parent,
        lambda path: path == ROOT or path in excused,
        lambda path: f"{path} is in the parent sha256:{parent_digest[:12]}, not here and not recorded as removed",
    )
    ok_named, bad_named = names_parent(named, parent_digest)
    return result(ANCESTRY, [*ok_files, *ok_named], failed=[*bad_files, *bad_named])
