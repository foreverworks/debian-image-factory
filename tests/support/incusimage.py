"""Synthetic Incus artifacts and plans for the Incus tests: a root filesystem from tests/fixtures/squashfs, the
metadata tarball `incus.metadata_tarball` writes, both under their artifact names in an output directory, and
the records file a build leaves beside them."""

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from input_lock import Package
from input_lock.records import PROVENANCE_PREDICATE, ResourceDescriptor, envelope, jsonl, provenance, statement, subject

from debian_image_factory import incus
from debian_image_factory.published import records_name_for
from tests.support import ocimage
from tests.support.rootfs import BASE, IDENTITY, sbom_line

FIXTURES = Path(__file__).parent.parent / "fixtures" / "squashfs"
BASE_IDENTITY = ocimage.OCI_IDENTITY
APP_IDENTITY = ocimage.CHILD_IDENTITY
EPOCH = 1754697600
INCUS_CHECKS = (
    "ancestry",
    "incus-boot",
    "no-build-snapshot",
    "no-machine-identity",
    "package-set",
    "sbom-complete",
    "two-clones",
)


def fixture(name: str) -> bytes:
    """A squashfs image of tests/fixtures/squashfs."""
    return (FIXTURES / f"{name}.sqsh").read_bytes()


@dataclass(frozen=True, slots=True)
class Image:
    """An Incus image written into an output directory."""

    names: incus.Names
    fingerprint: str
    metadata: Path
    rootfs: Path
    records: Path


def metadata_of(image: str, identity: str) -> bytes:
    return incus.metadata_tarball(image=image, suite="trixie", arch="amd64", identity=identity, source_date_epoch=EPOCH)


def write_image(
    out: Path,
    image: str,
    identity: str,
    rootfs: bytes,
    *,
    ancestors: Sequence[tuple[str, str]] = (),
    packages: Sequence[Package] = BASE,
    removed: Sequence[str] | None = (),
) -> Image:
    """The image's two files and its records (provenance naming `ancestors`, nearest first as (image, sha256),
    recording `removed` as the paths its build took from the parent unless None, and an SBOM of `packages`)
    into `out`."""
    meta = metadata_of(image, identity)
    fingerprint = hashlib.sha256(meta + rootfs).hexdigest()
    names = incus.names(image, "trixie", "amd64", identity, fingerprint)
    (out / names.metadata).write_bytes(meta)
    (out / names.rootfs).write_bytes(rootfs)
    dependencies: list[ResourceDescriptor] = [
        {"name": f"{'parent' if position == 0 else 'ancestor'}: {name}", "digest": {"sha256": sha256}}
        for position, (name, sha256) in enumerate(ancestors)
    ]
    build = statement(
        [
            subject(names.image, fingerprint),
            subject(names.metadata, hashlib.sha256(meta).hexdigest()),
            subject(names.rootfs, hashlib.sha256(rootfs).hexdigest()),
        ],
        PROVENANCE_PREDICATE,
        provenance(
            "https://example.com/build-type",
            {"image": image},
            dependencies,
            "https://example.com/builder",
            internal_parameters={"identity": identity}
            | ({} if removed is None else {"removedFromParent": [str(path) for path in removed]}),
            metadata={"finishedOn": "2026-11-21T02:19:41Z"},
        ),
    )
    records = out / records_name_for(fingerprint)
    records.write_text(jsonl([envelope(build)]) + sbom_line(names.image, fingerprint, packages), encoding="utf-8")
    return Image(names, fingerprint, out / names.metadata, out / names.rootfs, records)


def plan_text(
    images: Mapping[str, tuple[str, str | None, str]],
    *,
    packages: Sequence[Package] = BASE,
    checks: Sequence[str] = INCUS_CHECKS,
) -> str:
    """A plan of core and these Incus images, each (identity, parent, kind)."""
    entries: dict[str, dict[str, object]] = {"core": ocimage.entry("core", identity=IDENTITY)}
    for name, (identity, parent, kind) in images.items():
        entries[name] = ocimage.entry(kind, parent=parent, identity=identity, checks=checks, packages=packages)
    return ocimage.plan_json(entries)
