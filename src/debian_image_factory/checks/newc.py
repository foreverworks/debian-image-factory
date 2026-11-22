"""Reading a newc ("070701") cpio archive in one streaming pass: the members of an installer's initrd.

`entries` is the one function the checks read an initrd through (`kit.scan_kit` calls it), so another
reader with the same shape replaces this one there. It yields each member with an iterator over its data,
which must be read (or left) before the next member is asked for; the data the consumer did not read is
skipped. Memory stays bounded: data comes in CHUNK pieces.

A hard link is a regular file whose inode (and device) an earlier member had, with a link count above one:
it is given as a `hardlink` to the first name, as a tarball gives one. Its data, when the archive carries it
there (GNU cpio writes it with the last name), is still yielded, so a search sees it.
"""

import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Final

from .tarball import Kind, Member, normalize

MAGIC: Final = b"070701"
HEADER: Final = 110
"""The magic and thirteen 8-digit hex fields."""
TRAILER: Final = "TRAILER!!!"
CHUNK: Final = 64 * 1024
MAX_NAME: Final = 64 * 1024


type Reader = Callable[[int], bytes]
"""Reads up to that many bytes of the archive (a file's `read`); fewer only at its end."""


class NewcError(ValueError):
    """The bytes are not a newc archive (a bad magic, a short read, a field that is not hex)."""


@dataclass(frozen=True, slots=True)
class Header:
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    mtime: int
    size: int
    devmajor: int
    devminor: int
    rdevmajor: int
    rdevminor: int
    namesize: int


def exactly(read: Reader, size: int) -> bytes:
    data = read(size)
    if len(data) != size:
        raise NewcError(f"the archive ends inside a member ({len(data)} of {size} bytes)")
    return data


def parse_header(raw: bytes) -> Header:
    if raw[:6] != MAGIC:
        raise NewcError(f"not a newc member: the magic is {raw[:6]!r}")
    try:
        fields = [int(raw[6 + 8 * n : 14 + 8 * n], 16) for n in range(13)]
    except ValueError:
        raise NewcError("a newc header field is not hex") from None
    return Header(*fields[:12])


def kind_of(mode: int) -> Kind:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def data_of(read: Reader, left: list[int]) -> Iterator[bytes]:
    """The member's data in chunks; `left` counts what is still unread, for the skip after it."""
    while left[0] > 0:
        chunk = exactly(read, min(CHUNK, left[0]))
        left[0] -= len(chunk)
        yield chunk


def entries(read: Reader) -> Iterator[tuple[str, Member, Iterator[bytes]]]:
    """Each member of the archive `read` gives, up to its trailer: its name as stored, the member, and its data (a
    symlink's target is in the member, not the data). Raises NewcError when the bytes are not a whole newc
    archive."""
    first: dict[tuple[int, int, int], str] = {}
    while True:
        head = parse_header(exactly(read, HEADER))
        if head.namesize < 1 or head.namesize > MAX_NAME:
            raise NewcError(f"a member name of {head.namesize} bytes")
        raw_name = exactly(read, head.namesize)
        exactly(read, -(HEADER + head.namesize) % 4)
        name = raw_name.rstrip(b"\0").decode("utf-8", "surrogateescape")
        if name == TRAILER:
            return
        path = normalize(name)
        kind = kind_of(head.mode)
        target = ""
        if kind == "symlink":
            target = exactly(read, head.size).decode("utf-8", "surrogateescape")
            left = [0]
        else:
            left = [head.size]
        if kind == "file" and head.nlink > 1:
            key = (head.devmajor, head.devminor, head.ino)
            if key in first:
                kind, target = "hardlink", first[key]
            else:
                first[key] = path
        yield name, Member(path, kind, target), data_of(read, left)
        while left[0] > 0:
            left[0] -= len(exactly(read, min(CHUNK, left[0])))
        exactly(read, -head.size % 4)
