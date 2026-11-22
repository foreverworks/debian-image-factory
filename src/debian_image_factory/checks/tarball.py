"""Reading a core root filesystem tarball in one streaming pass: the edge of the file-based checks.

Memory stays bounded: members are read one at a time and file contents in 64 KiB chunks, except the few
small files a check asked for whole (`wanted`), which are read up to MAX_WANTED bytes.
"""

import posixpath
import tarfile
from collections.abc import Callable, Iterable, Iterator, Mapping
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


type Keep = Callable[[str], bool]
"""Which further paths' contents a scan keeps whole, besides `wanted` (all of a parent's dpkg file lists, say)."""


def keep_none(path: str) -> bool:
    return False


def scan_entries(
    items: Iterable[tuple[str, Member, Iterable[bytes] | None]],
    wanted: frozenset[str],
    needle: str | None,
    keys: bool,
    keep: Keep = keep_none,
) -> Scan:
    """One pass over an archive's members, whatever its format: each item is (the name as stored, the member,
    its data in chunks or None when it has none).

    `wanted` (and what `keep` selects) are the absolute paths whose content is kept; `needle` is searched in
    every stored name, link target and data; `keys` looks for private key blocks and tokens in the data.
    """
    members: list[Member] = []
    contents: dict[str, bytes] = {}
    key_files: list[str] = []
    hits: list[Hit] = []
    needle_bytes = needle.encode() if needle else None

    def hit(where: Literal["path", "link target", "content"], where_path: str) -> None:
        if len(hits) < HITS_LIMIT:
            hits.append(Hit(where, where_path))

    for name, member, data in items:
        members.append(member)
        if needle and needle in name:
            hit("path", member.path)
        if needle and needle in member.target:
            hit("link target", member.path)
        if data is None:
            continue
        stream: Iterable[bytes] = data
        if member.path in wanted or keep(member.path):
            whole = b"".join(bounded(data, MAX_WANTED))
            if member.kind == "file" or whole:
                contents[member.path] = whole
            stream = [whole]
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


def bounded(chunks: Iterable[bytes], limit: int) -> Iterator[bytes]:
    """The first `limit` bytes of `chunks`."""
    left = limit
    for chunk in chunks:
        if left <= 0:
            return
        yield chunk[:left]
        left -= len(chunk)


def tar_items(archive: tarfile.TarFile) -> Iterator[tuple[str, Member, Iterable[bytes] | None]]:
    """The members of an open tarball for `scan_entries`: a regular file's data, nothing for the rest."""
    for info in archive:
        member = Member(normalize(info.name), kind_of(info), info.linkname if info.issym() or info.islnk() else "")
        handle = archive.extractfile(info) if member.kind == "file" else None
        if handle is None:
            yield info.name, member, None
            continue
        with handle:
            yield info.name, member, chunks_of(handle)


def scan_tarball(path: Path, wanted: frozenset[str], needle: str | None, keys: bool, keep: Keep = keep_none) -> Scan:
    """One pass over a gzip (or plain) tarball (`scan_entries` says what is looked for). Raises
    tarfile.TarError, EOFError or OSError when the file cannot be read as a tarball."""
    with tarfile.open(path, mode="r|*") as archive:
        return scan_entries(tar_items(archive), wanted, needle, keys, keep)
