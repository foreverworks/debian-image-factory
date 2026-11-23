"""A small OCI image the way a build leaves it in `out/`, for the registry, publish and verify tests:
a layout directory named as an artifact, and its records beside it (provenance, SBOM and test results
shaped like the factory's own)."""

import gzip
import hashlib
import io
import tarfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from input_lock.records import (
    SPDX_PREDICATE,
    TEST_RESULT_PREDICATE,
    TestOutcome,
    envelope,
    jsonl,
    statement,
    subject,
    test_result,
)

from debian_image_factory import __version__, oci, ocilayout, published, records
from tests.support.definitions import example_lock

IDENTITY: Final = "c3" * 32
SOURCE: Final = records.DefinitionSource("git+https://github.com/example/images", "9a" * 20, "factory.toml")
RECIPE: Final = "34" * 32
BUILDER: Final = "56" * 32
STARTED: Final = "2026-11-21T02:17:05Z"
FINISHED: Final = "2026-11-21T02:19:41Z"


@dataclass(frozen=True, slots=True)
class Built:
    """One image in an output directory: its layout, digest, name and records file."""

    layout: Path
    digest: str
    identity: str
    name: str
    records: Path


def tiny_layer(directory: Path, content: bytes) -> tuple[Path, str, int, str]:
    """A gzip tar layer holding one file: its path, the sha256 and size of the compressed file, and the
    sha256 of the tar (the config's diff ID)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo("hello.txt")
        info.size = len(content)
        info.mtime = 0
        tar.addfile(info, io.BytesIO(content))
    raw = buffer.getvalue()
    packed = gzip.compress(raw, mtime=0)
    path = directory / f"layer-{hashlib.sha256(content).hexdigest()[:8]}.tar.gz"
    path.write_bytes(packed)
    return path, hashlib.sha256(packed).hexdigest(), len(packed), hashlib.sha256(raw).hexdigest()


def result_line(name: str, digest: str, check: str, outcome: TestOutcome = "PASSED") -> str:
    predicate = test_result(outcome, [{"name": check, "uri": f"{records.CHECKS_DOC}#{check}"}])
    return jsonl([envelope(statement([subject(name, digest)], TEST_RESULT_PREDICATE, predicate))])


def make_image(
    out: Path,
    *,
    image: str = "app",
    identity: str = IDENTITY,
    content: bytes = b"hello",
    checks: Sequence[tuple[str, TestOutcome]] = (("package-set", "PASSED"), ("oci-run", "PASSED")),
    entries: Sequence[str] = (),
    provenance_identity: str | None = None,
    finished: str = FINISHED,
) -> Built:
    """Write `out/<name>.oci/` and `out/<manifest digest>.intoto.jsonl`, the way `build` and `test` do."""
    out.mkdir(parents=True, exist_ok=True)
    scratch = out / f".scratch-{hashlib.sha256(content).hexdigest()[:8]}"
    scratch.mkdir()
    layer, layer_digest, layer_size, diff_id = tiny_layer(scratch, content)
    config = oci.image_config(oci.OciConfig(entrypoint=("/bin/sh",)), [diff_id], "amd64")
    annotations = oci.image_annotations(
        identity=identity, base_digest=None, base_name=None, source=SOURCE.uri, revision=SOURCE.revision
    )
    descriptor = ocilayout.write_layout(
        scratch / "layout", config=config, layers=[(layer, layer_digest, layer_size)], annotations=annotations
    )
    name = published.artifact_name(image, "trixie", "amd64", identity, descriptor.digest, oci.LAYOUT_EXT)
    (scratch / "layout").rename(out / name)
    layer.unlink()
    scratch.rmdir()
    lines = records_text(
        name,
        descriptor.digest,
        image=image,
        kind="oci",
        identity=provenance_identity or identity,
        checks=checks,
        entries=entries,
        finished=finished,
    )
    file = out / published.records_name_for(descriptor.digest)
    file.write_text(lines)
    return Built(out / name, descriptor.digest, identity, name, file)


def records_text(
    name: str,
    digest: str,
    *,
    image: str,
    kind: str,
    identity: str,
    checks: Sequence[tuple[str, TestOutcome]],
    entries: Sequence[str] = (),
    finished: str = FINISHED,
) -> str:
    """The records file of one artifact: its provenance, its SBOM, then one test result per check, in order."""
    lock = example_lock()
    provenance = records.provenance_statement(
        subjects=[subject(name, digest)],
        image=image,
        params={},
        definition=SOURCE,
        identity=identity,
        engine=1,
        build_snapshots={"debian": "20261121T004329Z", "debian-security": "20261121T004329Z"},
        architecture="amd64",
        reason=None,
        lock=lock,
        entries=entries,
        recipe_digest=RECIPE,
        in_releases=[],
        builder_image="ghcr.io/example/builder",
        builder_digest=BUILDER,
        ancestors=(),
        builder_id="https://example.com/builder",
        invocation_id=None,
        version=__version__,
        started_on=STARTED,
        finished_on=finished,
    )
    document = records.sbom(
        image=image,
        kind=kind,
        suite="trixie",
        arch="amd64",
        artifact_digest=digest,
        packages=[("libc6", "2.41-12", "amd64")],
        lock=lock,
        entries=entries,
        namespace_base="https://github.com/example/images",
        created="2026-11-21T02:31:12Z",
        version=__version__,
    )
    return "".join(
        [
            records.record_lines([provenance]),
            records.record_lines([statement([subject(name, digest)], SPDX_PREDICATE, document)]),
            *(result_line(name, digest, check, outcome) for check, outcome in checks),
        ]
    )


def make_core_file(
    out: Path,
    *,
    identity: str = IDENTITY,
    checks: Sequence[tuple[str, TestOutcome]] = (),
    content: bytes = b"core rootfs",
    finished: str = FINISHED,
) -> Built:
    """A core tarball in `out/` with its records beside it, as `build` leaves one."""
    out.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(content).hexdigest()
    name = published.artifact_name("core", "trixie", "amd64", identity, digest, "tar.gz")
    (out / name).write_bytes(content)
    file = out / published.records_name_for(digest)
    file.write_text(
        records_text(name, digest, image="core", kind="core", identity=identity, checks=checks, finished=finished)
    )
    return Built(out / name, digest, identity, name, file)
