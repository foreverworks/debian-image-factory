"""Synthetic OCI image layouts and plans for the OCI check tests: layers made with tarfile into gzip, written
with `ocilayout.write_layout` into an output directory under their artifact name."""

import gzip
import hashlib
import json
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from input_lock import Package

from debian_image_factory import oci, ocilayout, published
from tests.support.rootfs import ARCH, BASE, IDENTITY, SNAPSHOT, SUITE, Entry, rootfs

OCI_IDENTITY = "cd" * 32
CHILD_IDENTITY = "ef" * 32

type Layer = Mapping[str, Entry] | bytes
"""A layer given as its entries (see `rootfs`), or as the bytes of a ready gzip tarball (a core artifact)."""


@dataclass(frozen=True, slots=True)
class Built:
    """A layout written into an output directory."""

    path: Path
    digest: str
    """The manifest digest in hex: the image's."""
    layers: tuple[str, ...]
    """The layer digests in hex, base first."""


def write_oci(
    out: Path,
    image: str,
    layers: Sequence[Layer],
    *,
    config: oci.OciConfig = oci.OciConfig(),  # noqa: B008  # a frozen value, safe as a default
    annotations: Mapping[str, str] | None = None,
    identity: str = OCI_IDENTITY,
) -> Built:
    """Write the one-image layout of `layers` (base first) into `out` as `<image>-...-<digest12>.oci`."""
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        blobs: list[tuple[Path, str, int]] = []
        diff_ids: list[str] = []
        for position, layer in enumerate(layers):
            data = layer if isinstance(layer, bytes) else rootfs(layer)
            path = scratch / f"layer-{position}.tar.gz"
            path.write_bytes(data)
            blobs.append((path, hashlib.sha256(data).hexdigest(), len(data)))
            diff_ids.append(hashlib.sha256(gzip.decompress(data)).hexdigest())
        descriptor = ocilayout.write_layout(
            scratch / "image.oci",
            config=oci.image_config(config, diff_ids, ARCH),
            layers=blobs,
            annotations=dict(annotations or {}),
        )
        name = published.artifact_name(image, SUITE, ARCH, identity, descriptor.digest, oci.LAYOUT_EXT)
        (scratch / "image.oci").rename(out / name)
    return Built(out / name, descriptor.digest, tuple(digest for _, digest, _ in blobs))


def entry(
    kind: str,
    *,
    parent: str | None = None,
    identity: str = OCI_IDENTITY,
    checks: Sequence[str] = (),
    packages: Sequence[Package] = BASE,
    artifact: str | None = None,
) -> dict[str, object]:
    """One `images.<name>` of a plan, with every field `planfile.parse_image` requires."""
    found: dict[str, object] = {
        "kind": kind,
        "parent": parent,
        "identity": identity,
        "parent_identity": None,
        "recipe": "r",
        "apt_sources": "snapshot",
        "request": [],
        "packages": [list(package) for package in packages],
        "inputs": {},
        "trust": {},
        "debs": {},
        "modules": [],
        "params": {},
        "checks": list(checks),
        "state": "build" if artifact is None else "reuse",
    }
    if artifact is not None:
        found["artifact"] = artifact
    return found


def plan_json(images: Mapping[str, dict[str, object]], *, snapshot: str = SNAPSHOT) -> str:
    return json.dumps(
        {
            "schema": 1,
            "factory": "test",
            "engine": 1,
            "snapshot": snapshot,
            "baseline": "20261001T000000Z",
            "debian": {"suite": SUITE, "components": ["main"], "architecture": ARCH},
            "params": {},
            "images": dict(images),
        }
    )


__all__ = ["BASE", "CHILD_IDENTITY", "IDENTITY", "OCI_IDENTITY", "Built", "entry", "plan_json", "write_oci"]
