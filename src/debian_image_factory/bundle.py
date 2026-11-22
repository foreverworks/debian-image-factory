"""Inputs bundles (DESIGN 7.7): everything one image's build reads from the network, in one deterministic tar.

A bundle is a plain tar of three kinds of member: `manifest.json` first, then `plan.json` (the plan the bundle
was made from, byte for byte) and the files of a download cache under `cache/` (the partial mirror and the
locked inputs, laid out exactly as `fetch` lays them out, so unpacking one is making a cache). The manifest
names the image, its identity and the snapshot, and lists every other member with its size and sha256.

Two fetches of one plan write byte-identical bundles: members are sorted, and every header carries the same
time, owner and mode. `unpack` is the reverse and trusts nothing: the manifest must be the first member, every
member must be a regular file the manifest lists, and its bytes must match the manifest's size and sha256.
Pure apart from `write` and `unpack`, which read and write files.
"""

import hashlib
import io
import json
import re
import tarfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, TypedDict

from input_lock.identity import HEX64

from .commands import Failed

SCHEMA: Final = 1
EXTENSION: Final = "inputs.tar"
MANIFEST: Final = "manifest.json"
PLAN: Final = "plan.json"
CACHE: Final = "cache"
"""The member directory that holds the download cache: `cache/mirror/...`, `cache/sha256/...`, `cache/vouched/...`."""
MANIFEST_LIMIT: Final = 1 << 26
"""The most a manifest may weigh, read before anything in it is trusted."""
_SHA256: Final = re.compile("[0-9a-f]{64}")


class ManifestFile(TypedDict):
    path: str
    sha256: str
    size: int


class Manifest(TypedDict):
    schema: int
    image: str
    identity: str
    snapshot: str
    suite: str
    architecture: str
    files: list[ManifestFile]
    """Every member but the manifest itself, sorted by path."""


@dataclass(frozen=True, slots=True)
class Member:
    """One file to put in a bundle: its member name, where it is now, and what it hashes to."""

    path: str
    source: Path
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class Unpacked:
    manifest: Manifest
    plan: bytes
    """The bytes of the bundle's `plan.json`."""
    cache: Path
    """The directory the bundle's `cache/` members were written to."""


def bundle_name(image: str, suite: str, arch: str, identity: str) -> str:
    """`<image>-<suite>-<arch>-<first 16 hex of identity>.inputs.tar`: named by what determines its content.

    The artifact's own digest, which names an artifact, does not exist when `fetch` runs; the image, suite,
    architecture and identity do, and one identity is one set of inputs."""
    if not HEX64.fullmatch(identity):
        raise ValueError(f"identity is not 64 lowercase hex characters: {identity!r}")
    return f"{image}-{suite}-{arch}-{identity[:16]}.{EXTENSION}"


def safe_member(path: str) -> bool:
    """A member name that stays inside the unpack directory: relative, no `..`, no empty or `.` part."""
    parts = PurePosixPath(path).parts
    return bool(parts) and not path.startswith("/") and all(part not in ("", ".", "..") for part in parts)


def hashed(path: str, source: Path) -> Member:
    """The member for the file at `source`: its size and sha256 read from the file now."""
    with source.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    return Member(path, source, digest, source.stat().st_size)


def manifest_bytes(
    *, image: str, identity: str, snapshot: str, suite: str, architecture: str, members: Sequence[Member]
) -> bytes:
    """The manifest's JSON text: sorted keys and members, so equal inputs give equal bytes."""
    files: list[ManifestFile] = [
        {"path": one.path, "sha256": one.sha256, "size": one.size} for one in sorted(members, key=lambda m: m.path)
    ]
    document: Manifest = {
        "schema": SCHEMA,
        "image": image,
        "identity": identity,
        "snapshot": snapshot,
        "suite": suite,
        "architecture": architecture,
        "files": files,
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _header(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mtime = 0
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def write(destination: Path, manifest: bytes, members: Sequence[Member]) -> None:
    """Write the bundle: the manifest, then the members sorted by path, with fixed headers; atomically.

    Raises Failed when a source file is not the size its member says (it changed since it was hashed)."""
    ordered = sorted(members, key=lambda one: one.path)
    names = [one.path for one in ordered]
    if len(set(names)) != len(names) or MANIFEST in names:
        raise ValueError("a bundle's member names must be unique and none may be the manifest")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.part")
    try:
        with tarfile.open(temporary, "w", format=tarfile.PAX_FORMAT) as archive:
            archive.addfile(_header(MANIFEST, len(manifest)), fileobj=io.BytesIO(manifest))
            for one in ordered:
                if one.source.stat().st_size != one.size:
                    raise Failed(f"{one.source}: changed while the bundle was being written")
                with one.source.open("rb") as handle:
                    archive.addfile(_header(one.path, one.size), fileobj=handle)
        temporary.replace(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


# ---- reading --------------------------------------------------------------------------------------------


def _object(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{where} must be an object")
    return {str(key): item for key, item in value.items()}


def _text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where} must be non-empty text")
    return value


def parse_manifest(data: object) -> Manifest:
    """The manifest in `data` (what `json.loads` returned), every field checked; ValueError names the first bad one."""
    document = _object(data, "the manifest")
    if document.get("schema") != SCHEMA:
        raise ValueError(f"the manifest's schema must be {SCHEMA}")
    listed = document.get("files")
    if not isinstance(listed, list):
        raise ValueError("the manifest's files must be a list")
    files: list[ManifestFile] = []
    for index, item in enumerate(listed):
        entry = _object(item, f"files[{index}]")
        path, sha256, size = entry.get("path"), entry.get("sha256"), entry.get("size")
        if not isinstance(path, str) or not safe_member(path) or path == MANIFEST:
            raise ValueError(f"files[{index}].path is not a member name this bundle may hold: {path!r}")
        if path != PLAN and PurePosixPath(path).parts[0] != CACHE:
            raise ValueError(f"files[{index}].path {path!r} is neither {PLAN} nor under {CACHE}/")
        if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
            raise ValueError(f"files[{index}].sha256 must be 64 lowercase hex digits")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError(f"files[{index}].size must be a whole number")
        files.append({"path": path, "sha256": sha256, "size": size})
    names = [one["path"] for one in files]
    if len(set(names)) != len(names):
        raise ValueError("the manifest lists a member twice")
    if PLAN not in names:
        raise ValueError(f"the manifest lists no {PLAN}")
    identity = _text(document.get("identity"), "the manifest's identity")
    if not HEX64.fullmatch(identity):
        raise ValueError("the manifest's identity must be 64 lowercase hex digits")
    return {
        "schema": SCHEMA,
        "image": _text(document.get("image"), "the manifest's image"),
        "identity": identity,
        "snapshot": _text(document.get("snapshot"), "the manifest's snapshot"),
        "suite": _text(document.get("suite"), "the manifest's suite"),
        "architecture": _text(document.get("architecture"), "the manifest's architecture"),
        "files": files,
    }


def unpack(bundle: Path, into: Path) -> Unpacked:
    """Unpack `bundle` into the new directory `into`, checking every member against the manifest.

    `into/plan.json` and `into/cache/...` are written. Raises Failed naming the bundle and the member: a tar that
    is not a bundle, a member the manifest does not list, one whose size or sha256 differs, one that is not a
    regular file, a listed member that is missing."""
    try:
        with tarfile.open(bundle, "r:") as archive:
            return _unpack(archive, bundle, into)
    except OSError as error:
        raise Failed(f"{bundle}: {error.strerror or error}") from None
    except (tarfile.TarError, EOFError) as error:
        raise Failed(f"{bundle}: not an inputs bundle: {error}") from None


def _unpack(archive: tarfile.TarFile, bundle: Path, into: Path) -> Unpacked:
    first = archive.next()
    if first is None or first.name != MANIFEST or not first.isreg() or first.size > MANIFEST_LIMIT:
        raise Failed(f"{bundle}: not an inputs bundle: its first member must be {MANIFEST}")
    handle = archive.extractfile(first)
    assert handle is not None  # a regular file
    try:
        manifest = parse_manifest(json.loads(handle.read().decode("utf-8")))
    except ValueError as error:  # JSON, UTF-8 and the manifest's own checks
        raise Failed(f"{bundle}: {MANIFEST}: {error}") from None
    expected: Mapping[str, ManifestFile] = {one["path"]: one for one in manifest["files"]}
    seen: set[str] = set()
    plan = b""
    while (member := archive.next()) is not None:
        listed = expected.get(member.name)
        if listed is None:
            raise Failed(f"{bundle}: {member.name} is not listed in the manifest")
        if member.name in seen or not member.isreg():
            raise Failed(f"{bundle}: {member.name} is repeated or is not a regular file")
        stream = archive.extractfile(member)
        assert stream is not None  # a regular file
        target = into / member.name
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        size = 0
        with target.open("wb") as written:
            while chunk := stream.read(1 << 20):
                digest.update(chunk)
                size += len(chunk)
                written.write(chunk)
        if size != listed["size"] or digest.hexdigest() != listed["sha256"]:
            raise Failed(f"{bundle}: {member.name} does not match the manifest's size and sha256")
        seen.add(member.name)
        if member.name == PLAN:
            plan = target.read_bytes()
    missing = sorted(set(expected) - seen)
    if missing:
        raise Failed(f"{bundle}: the manifest lists {len(missing)} members the bundle lacks, such as {missing[0]}")
    return Unpacked(manifest, plan, into / CACHE)
