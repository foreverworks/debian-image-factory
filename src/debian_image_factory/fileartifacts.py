"""The artifacts a directory holds as files (DESIGN 7.4, 8.1): the edge every file target reads them through.

Most kinds are one file whose sha256 names it. An Incus image is two: its metadata tarball, which is the
artifact's name, and its rootfs beside it; their fingerprint names the pair. A rootfs is never an
artifact by itself, and is listed only with its metadata tarball.
"""

import hashlib
import itertools
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import incus
from .published import ArtifactName, Rejected, parse_artifact_name

CHUNK: Final = 1024 * 1024


@dataclass(frozen=True, slots=True)
class FileArtifact:
    """One artifact made of files: `name` is its first file's name, `digest` the hex that names it (a
    file's sha256, an Incus image's fingerprint), `files` every file it is made of, the first one first."""

    name: str
    digest: str
    parts: ArtifactName
    files: tuple[Path, ...]


def chunks(path: Path) -> Iterator[bytes]:
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            yield chunk


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    for chunk in chunks(path):
        digest.update(chunk)
    return digest.hexdigest()


def fingerprint_of(metadata: Path, rootfs: Path) -> str:
    """The Incus fingerprint of a split image on disk."""
    return incus.fingerprint(itertools.chain(chunks(metadata), chunks(rootfs)))


def is_companion(parts: ArtifactName) -> bool:
    """Whether a file is only part of another artifact (an Incus rootfs), never one by itself."""
    return parts.ext == incus.ROOTFS_EXT


def read_artifact(path: Path, parts: ArtifactName) -> FileArtifact | Rejected:
    """The artifact whose first file is `path`, with its digest checked against its name, or why it does
    not count. `path` must not be a companion file."""
    files: tuple[Path, ...] = (path,)
    if parts.ext == incus.METADATA_EXT:
        rootfs = incus.rootfs_of(path.name)
        if rootfs is None or not (path.parent / rootfs).is_file():
            return Rejected(path.name, f"no rootfs {rootfs} beside it")
        files = (path, path.parent / rootfs)
        digest = fingerprint_of(*files)
        what = "Incus fingerprint"
    else:
        digest = sha256_of(path)
        what = "sha256"
    if not digest.startswith(parts.digest12):
        return Rejected(path.name, f"its {what} {digest} does not match the digest in its name")
    return FileArtifact(path.name, digest, parts, files)


def file_artifacts(directory: Path, prefix: str = "") -> tuple[list[FileArtifact], list[Rejected]]:
    """Every file artifact in `directory` whose name starts with `prefix`, by name, and the files named
    like one that do not count, with the reason. Checking a digest reads the files in full."""
    found: list[FileArtifact] = []
    rejected: list[Rejected] = []
    for path in sorted(directory.iterdir()):
        if not path.name.startswith(prefix) or not path.is_file():
            continue
        parts = parse_artifact_name(path.name)
        if parts is None or is_companion(parts):
            continue
        read = read_artifact(path, parts)
        if isinstance(read, Rejected):
            rejected.append(read)
        else:
            found.append(read)
    return found, rejected
