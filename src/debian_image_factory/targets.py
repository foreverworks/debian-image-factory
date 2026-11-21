"""The edge that asks a target what it holds for one identity (DESIGN 7.4). Only `dir://` is read in this release."""

import hashlib
import os
from pathlib import Path

from input_lock.identity import HEX64

from .published import (
    Artifact,
    DirTarget,
    Lookup,
    OciTarget,
    Rejected,
    ReleaseTarget,
    Target,
    artifact_from_records,
    parse_artifact_name,
    records_name_for,
)


def sha256_of(path: Path) -> str:
    """The sha256 of a file, read in full."""
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def lookup(target: Target, image: str, suite: str, arch: str, identity: str) -> Lookup:
    """The artifacts `target` holds for this image and identity that count, and the files that look
    like one but do not (with the reason). Raises NotImplementedError for a target kind not read yet."""
    if not HEX64.fullmatch(identity):
        raise ValueError(f"identity is not 64 lowercase hex characters: {identity!r}")
    match target:
        case DirTarget(path):
            return lookup_dir(Path(path), image, suite, arch, identity)
        case OciTarget():
            scheme = "oci"
        case ReleaseTarget():
            scheme = "github-release"
    raise NotImplementedError(f"{scheme} targets arrive in a later release; this release reads dir:// targets")


def lookup_dir(directory: Path, image: str, suite: str, arch: str, identity: str) -> Lookup:
    """List `directory`, keep the files named for this image, suite, architecture and identity, and
    verify each: its real sha256 must match its name, its records file must exist and be well formed,
    and its provenance must name the image and the full identity. A missing directory holds nothing."""
    prefix = f"{image}-{suite}-{arch}-{identity[:16]}-"
    try:
        names = sorted(name for name in os.listdir(directory) if name.startswith(prefix))
    except FileNotFoundError:
        return Lookup((), ())
    found: list[Artifact] = []
    rejected: list[Rejected] = []
    for name in names:
        parsed = parse_artifact_name(name)
        path = directory / name
        if parsed is None or (parsed.image, parsed.suite, parsed.arch) != (image, suite, arch) or not path.is_file():
            continue
        digest = sha256_of(path)
        if not digest.startswith(parsed.digest12):
            rejected.append(Rejected(name, f"its sha256 {digest} does not match the digest in its name"))
            continue
        records = directory / records_name_for(digest)
        if not records.is_file():
            rejected.append(Rejected(name, f"no records file {records.name} beside it"))
            continue
        try:
            text = records.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            rejected.append(Rejected(name, f"records file {records.name} is not UTF-8"))
            continue
        checked = artifact_from_records(name, digest, image, identity, text)
        if isinstance(checked, Rejected):
            rejected.append(checked)
        else:
            found.append(checked)
    return Lookup(tuple(found), tuple(rejected))
