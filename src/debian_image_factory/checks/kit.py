"""An installer kit (DESIGN 8.1): the tarball holding `kit.json`, `vmlinuz` and `initrd.img`, in that order.

`kit_problems` is pure: how the members and kit.json disagree. `read_kit` is the edge that reads the
tarball once for that; `scan_kit` reads the initrd (a gzip newc cpio of the whole root) through
`newc.entries` for the file checks, and searches kit.json and the kernel for the build snapshot too.
"""

import gzip
import hashlib
import json
import tarfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import newc, scanning, tarball
from .tarball import Hit, Keep, Scan, keep_none

KIT_JSON: Final = "kit.json"
VMLINUZ: Final = "vmlinuz"
INITRD: Final = "initrd.img"
MEMBERS: Final = (KIT_JSON, VMLINUZ, INITRD)
FILES: Final = (VMLINUZ, INITRD)
CHUNK: Final = 1024 * 1024
MAX_KIT_JSON: Final = 64 * 1024


@dataclass(frozen=True, slots=True)
class Facts:
    """What a kit tarball holds: its members' names and whether each is a regular file, in order; kit.json's
    bytes; and the sha256 and size of `vmlinuz` and `initrd.img` as they are."""

    members: tuple[tuple[str, bool], ...]
    manifest: bytes | None
    files: Mapping[str, tuple[str, int]]


@dataclass(frozen=True, slots=True)
class Kit:
    kernel: str | None
    """The kernel kit.json names, None when it names none."""
    problems: tuple[str, ...]
    files: Mapping[str, tuple[str, int]]
    """`vmlinuz` and `initrd.img`: (sha256, size) of the bytes the kit holds."""


def canonical(document: object) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def kit_problems(facts: Facts) -> Kit:
    """How the kit is not what DESIGN 8.1 says: exactly the three regular files in order, kit.json canonical
    with schema 1, a kernel, and each file's sha256 and size as listed."""
    problems: list[str] = []
    names = tuple(name for name, _ in facts.members)
    if names != MEMBERS:
        problems.append(f"the kit holds {', '.join(names) or 'nothing'}, not {', '.join(MEMBERS)} in that order")
    problems += [f"{name} is not a regular file" for name, regular in facts.members if not regular]
    if facts.manifest is None:
        return Kit(None, (*problems, f"there is no {KIT_JSON}"), facts.files)
    try:
        document = json.loads(facts.manifest)
    except ValueError as error:
        return Kit(None, (*problems, f"{KIT_JSON} is not JSON: {error}"), facts.files)
    if not isinstance(document, dict):
        return Kit(None, (*problems, f"{KIT_JSON} is not an object"), facts.files)
    if canonical(document) != facts.manifest:
        problems.append(f"{KIT_JSON} is not canonical JSON (sorted keys, no whitespace, one newline)")
    if document.get("schema") != 1:
        problems.append(f"{KIT_JSON} has schema {document.get('schema')!r}, not 1")
    kernel = document.get("kernel")
    if not isinstance(kernel, str) or not kernel:
        problems.append(f"{KIT_JSON} names no kernel")
        kernel = None
    listed = document.get("files")
    listed = listed if isinstance(listed, dict) else {}
    for name in FILES:
        entry, actual = listed.get(name), facts.files.get(name)
        if not isinstance(entry, dict):
            problems.append(f"{KIT_JSON} does not list {name}")
        elif actual is None:
            problems.append(f"{KIT_JSON} lists {name}, which the kit does not hold")
        else:
            if entry.get("sha256") != actual[0]:
                problems.append(f"{KIT_JSON} says {name} has sha256 {entry.get('sha256')}, it has {actual[0]}")
            if entry.get("size") != actual[1]:
                problems.append(f"{KIT_JSON} says {name} is {entry.get('size')} bytes, it is {actual[1]}")
    extra = sorted(set(listed) - set(FILES))
    if extra:
        problems.append(f"{KIT_JSON} lists files the kit format has not: {', '.join(extra)}")
    return Kit(kernel, tuple(problems), facts.files)


def read_kit(path: Path) -> Kit:
    """One pass over the kit tarball: its members, kit.json, the files' digests. Raises tarfile.TarError or
    OSError when it is not a readable tarball."""
    members: list[tuple[str, bool]] = []
    manifest: bytes | None = None
    files: dict[str, tuple[str, int]] = {}
    with tarfile.open(path, mode="r:") as archive:
        for info in archive:
            members.append((info.name, info.isreg()))
            handle = archive.extractfile(info) if info.isreg() else None
            if handle is None:
                continue
            with handle:
                if info.name == KIT_JSON:
                    manifest = handle.read(MAX_KIT_JSON)
                elif info.name in FILES:
                    digest = hashlib.sha256()
                    size = 0
                    while chunk := handle.read(CHUNK):
                        digest.update(chunk)
                        size += len(chunk)
                    files[info.name] = (digest.hexdigest(), size)
    return kit_problems(Facts(tuple(members), manifest, files))


def scan_kit(path: Path, wanted: frozenset[str], needle: str | None, keys: bool, keep: Keep = keep_none) -> Scan:
    """The initrd's root, as `tarball.scan_entries` sees it, plus where the needle is in kit.json or the
    kernel (named `kit.json` and `vmlinuz`, outside the root). Raises tarfile.TarError, newc.NewcError,
    EOFError or OSError (gzip.BadGzipFile among them) when the kit or its initrd cannot be read."""
    extra: list[Hit] = []
    with tarfile.open(path, mode="r:") as archive:
        for name in (KIT_JSON, VMLINUZ):
            handle = archive.extractfile(name) if needle else None
            if handle is not None:
                with handle:
                    if scanning.scan(tarball.chunks_of(handle), needle.encode() if needle else None, False).needle:
                        extra.append(Hit("content", name))
        source = archive.extractfile(INITRD)
        if source is None:
            raise tarfile.TarError(f"the kit has no regular file {INITRD}")
        with source, gzip.GzipFile(fileobj=source, mode="rb") as stream:
            scanned = tarball.scan_entries(newc.entries(stream.read), wanted, needle, keys, keep)
    hits = [*extra, *scanned.needle_hits][: tarball.HITS_LIMIT]
    return Scan(scanned.members, scanned.contents, scanned.key_files, tuple(hits))


def subjects_problems(subjects: Sequence[tuple[str, str]], kit_name: str, kit_digest: str, kit: Kit) -> list[str]:
    """How the records' subjects differ from the kit tarball first, then `vmlinuz` and `initrd.img`, by the
    sha256 of the bytes the kit holds (DESIGN 8.1)."""
    expected = [(kit_name, kit_digest), *((name, kit.files[name][0]) for name in FILES if name in kit.files)]
    found = [digest for _, digest in subjects]
    if found == [digest for _, digest in expected]:
        return []
    shown = ", ".join(f"{name} {digest[:12]}" for name, digest in subjects) or "none"
    return [f"the subjects are {shown}; expected the kit, then vmlinuz, then initrd.img by sha256"]
