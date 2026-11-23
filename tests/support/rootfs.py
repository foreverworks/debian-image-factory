"""Synthetic core artifacts for the check tests: root filesystem tarballs, dpkg status texts, plans and
records, built with the standard library and input-lock's own record helpers."""

import gzip
import hashlib
import io
import json
import tarfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import input_lock.records as rec
from input_lock import Package
from input_lock.records import SpdxPackage

from debian_image_factory import published

SNAPSHOT = "20261101T000000Z"
IDENTITY = "ab" * 32
SUITE = "trixie"
ARCH = "amd64"

BASE: tuple[Package, ...] = (
    ("apt", "1.0", "amd64"),
    ("base-files", "1.0", "amd64"),
    ("lib-a", "1.0", "all"),
)


@dataclass(frozen=True, slots=True)
class Link:
    target: str
    hard: bool = False


type Entry = bytes | Link | None
"""A file's content, a link, or None for a directory."""


def status_text(packages: Iterable[Package], extra: str = "") -> bytes:
    paragraphs = [
        f"Package: {n}\nStatus: install ok installed\nVersion: {v}\nArchitecture: {a}\n" for n, v, a in packages
    ]
    return ("\n".join(paragraphs) + extra).encode()


def rootfs(entries: Mapping[str, Entry]) -> bytes:
    """A gzip tarball whose member names start with `./`, as mmdebstrap's do, in the order given."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, entry in entries.items():
            info = tarfile.TarInfo(name)
            info.mtime = 0
            if entry is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            elif isinstance(entry, Link):
                info.type = tarfile.LNKTYPE if entry.hard else tarfile.SYMTYPE
                info.linkname = entry.target
                archive.addfile(info)
            else:
                info.size = len(entry)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(entry))
    return gzip.compress(raw.getvalue(), mtime=0)


def clean_files(packages: Iterable[Package] = BASE) -> dict[str, Entry]:
    """What a good core holds that the checks look at: the dpkg status and an uninitialized machine-id."""
    return {
        "./": None,
        "./etc/": None,
        "./etc/machine-id": b"uninitialized\n",
        "./etc/os-release": b"ID=debian\n",
        "./var/lib/dpkg/status": status_text(packages),
    }


def write_artifact(out: Path, entries: Mapping[str, Entry], identity: str = IDENTITY) -> tuple[Path, str]:
    """Write a core tarball into `out` under its artifact name; return it and its sha256."""
    data = rootfs(entries)
    digest = hashlib.sha256(data).hexdigest()
    path = out / published.artifact_name("core", SUITE, ARCH, identity, digest, "tar.gz")
    path.write_bytes(data)
    return path, digest


def plan_text(
    packages: Sequence[Package] = BASE,
    *,
    snapshot: str = SNAPSHOT,
    baseline: str | None = "20261001T000000Z",
    inputs: Mapping[str, str] | None = None,
    checks: Sequence[str] = ("no-build-snapshot", "no-machine-identity", "package-set", "sbom-complete", "two-clones"),
    extra_images: Mapping[str, object] | None = None,
) -> str:
    core: dict[str, object] = {
        "kind": "core",
        "identity": IDENTITY,
        "packages": [list(p) for p in packages],
        "request": ["apt", "tool-b"],
        "inputs": {name: {"version": version, "sha256": "00"} for name, version in (inputs or {}).items()},
        "checks": list(checks),
    }
    plan = {
        "snapshots": {"debian": snapshot, "debian-security": snapshot},
        "baseline": baseline,
        "debian": {"suite": SUITE, "components": ["main"], "architecture": ARCH},
        "images": {"core": core, **(extra_images or {})},
    }
    return json.dumps(plan)


def provenance_line(
    name: str,
    digest: str,
    parent_digest: str,
    removed: Sequence[str] = (),
    more_subjects: Sequence[tuple[str, str]] = (),
) -> str:
    """One records line: an OS root's or an installer kit's provenance as far as `ancestry` reads it, naming the
    parent core by digest and the parent paths the build removed (`removedFromParent`)."""
    build = rec.statement(
        [rec.subject(name, digest), *(rec.subject(one, sha256) for one, sha256 in more_subjects)],
        rec.PROVENANCE_PREDICATE,
        rec.provenance(
            "https://example.com/build-type",
            {"image": name},
            [{"name": "parent: core", "digest": {"sha256": parent_digest}}],
            "https://example.com/builder",
            internal_parameters={"identity": "0" * 64, "removedFromParent": [str(path) for path in removed]},
            metadata={"finishedOn": "2026-11-21T02:19:41Z"},
        ),
    )
    return rec.jsonl([rec.envelope(build)])


def sbom_line(
    name: str,
    digest: str,
    packages: Iterable[Package],
    inputs: Mapping[str, str] | None = None,
    more_subjects: Sequence[tuple[str, str]] = (),
) -> str:
    """One records line: the SPDX statement of an artifact, as the build writes it (an installer kit's also
    names its kernel and initrd: `more_subjects`)."""
    root: SpdxPackage = {
        "SPDXID": "SPDXRef-Image",
        "name": "core",
        "versionInfo": f"sha256:{digest}",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "primaryPackagePurpose": "CONTAINER",
    }
    locked: list[SpdxPackage] = [
        {
            "SPDXID": f"SPDXRef-Input-{entry}",
            "name": entry,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        }
        for entry, version in (inputs or {}).items()
    ]
    document = rec.spdx_document(
        "core", f"https://example.com/sbom/{digest}", "2026-11-21T00:00:00Z", "Tool: test", root,
        [*rec.deb_packages(packages, SUITE), *locked],
    )  # fmt: skip
    subjects = [rec.subject(name, digest), *(rec.subject(n, d) for n, d in more_subjects)]
    return rec.jsonl([rec.envelope(rec.statement(subjects, rec.SPDX_PREDICATE, document))])
