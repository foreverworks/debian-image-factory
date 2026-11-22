"""Reading a core root filesystem tarball in one streaming pass: the edge of the file-based checks.

Memory stays bounded: members are read one at a time and file contents in 64 KiB chunks, except the few
small files a check asked for whole (`wanted`), which are read up to MAX_WANTED bytes.
"""

import posixpath
import tarfile
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final, Literal

from . import scanning

CHUNK: Final = 64 * 1024
MAX_WANTED: Final = 32 * 1024 * 1024
HITS_LIMIT: Final = 20

DOC_TREES: Final = ("/usr/share/doc/", "/usr/share/man/", "/usr/share/info/")
COMPRESSED_DOCS: Final = (".gz", ".bz2", ".xz", ".zst")
"""Packages' own documentation, compressed: bytes that no key block or token can be read from, and so not
searched. A plain file in the same trees is searched like any other: a key left in `/usr/share/doc` is a key."""

type Kind = Literal["file", "dir", "symlink", "hardlink", "other"]


@dataclass(frozen=True, slots=True)
class Member:
    path: str
    """Absolute, without a trailing slash: `./etc/machine-id` is `/etc/machine-id`, `./` is `/`."""
    kind: Kind
    target: str = ""
    """The link target of a symlink or hard link, as the archive stores it."""


@dataclass(frozen=True, slots=True)
class Hit:
    where: Literal["path", "link target", "content"]
    path: str


@dataclass(frozen=True, slots=True)
class Scan:
    members: tuple[Member, ...]
    contents: Mapping[str, bytes]
    """The files asked for, by path (absent when the tarball has none, or it is not a regular file)."""
    key_files: tuple[str, ...]
    """Regular files holding a private key block or a credential token, sorted, but for the compressed
    documentation files. A token is named `<path> (<kind>: <redacted>)`, never shown."""
    needle_hits: tuple[Hit, ...]
    """Where the needle was found, in archive order, at most HITS_LIMIT."""


EMPTY: Final = Scan((), {}, (), ())


def normalize(name: str) -> str:
    """A member name as an absolute path in the image: `.`, `./` and `./etc/` are `/` and `/etc`."""
    return posixpath.normpath("/" + name).replace("//", "/", 1)


def kind_of(member: tarfile.TarInfo) -> Kind:
    if member.isreg():
        return "file"
    if member.isdir():
        return "dir"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    return "other"


def chunks_of(handle: IO[bytes]) -> Iterator[bytes]:
    while chunk := handle.read(CHUNK):
        yield chunk


def scan_tarball(path: Path, wanted: frozenset[str], needle: str | None, keys: bool) -> Scan:
    """One pass over a gzip (or plain) tarball.

    `wanted` are the absolute paths whose content is kept; `needle` is searched in every member path, link
    target and regular file's content; `keys` looks for private key blocks in regular files. Raises
    tarfile.TarError, EOFError or OSError when the file cannot be read as a tarball.
    """
    members: list[Member] = []
    contents: dict[str, bytes] = {}
    key_files: list[str] = []
    hits: list[Hit] = []
    needle_bytes = needle.encode() if needle else None

    def hit(where: Literal["path", "link target", "content"], where_path: str) -> None:
        if len(hits) < HITS_LIMIT:
            hits.append(Hit(where, where_path))

    with tarfile.open(path, mode="r|*") as archive:
        for info in archive:
            member = Member(normalize(info.name), kind_of(info), info.linkname if info.issym() or info.islnk() else "")
            members.append(member)
            if needle and needle in info.name:
                hit("path", member.path)
            if needle and needle in member.target:
                hit("link target", member.path)
            if member.kind != "file":
                continue
            handle = archive.extractfile(info)
            if handle is None:
                continue
            with handle:
                stream: Iterable[bytes]
                if member.path in wanted:
                    contents[member.path] = handle.read(MAX_WANTED)
                    stream = [contents[member.path]]
                else:
                    stream = chunks_of(handle)
                search_keys = keys and not (member.path.startswith(DOC_TREES) and member.path.endswith(COMPRESSED_DOCS))
                if needle_bytes is None and not search_keys:
                    continue
                found = scanning.scan(stream, needle_bytes, search_keys)
            if found.needle:
                hit("content", member.path)
            if found.key:
                key_files.append(member.path)
            key_files.extend(f"{member.path} ({token.kind}: {token.redacted})" for token in found.tokens)
    return Scan(tuple(members), contents, tuple(sorted(key_files)), tuple(hits))
