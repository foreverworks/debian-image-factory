"""`ancestry` for an OCI image (DESIGN 11): the parent's layers are the image's first layers, by digest. Pure.

A core parent is one tarball, which an OCI child carries byte for byte as its first layer, so the layer's
digest is the tarball's sha256. An OCI parent's own layers, in order, are the start of the child's. The
child's manifest also names the parent in `org.opencontainers.image.base.digest`, and that must be the
parent artifact's digest. Digests are sha256 in hex throughout.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .. import oci
from .model import ANCESTRY, CheckOutcome, NotRun, result, split

LAYERS_FIRST = "parent-layers-are-first"
BASE_DIGEST = "base-digest-annotation"


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
