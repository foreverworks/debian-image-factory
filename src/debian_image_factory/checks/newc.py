"""Reading a newc ("070701") cpio archive in one streaming pass: the members of an installer's initrd.

`entries` is the one function the checks read an initrd through (`kit.scan_kit` calls it). The format itself
is read by `build.initrd.stream_entries`, the reader the builder's own initrd program uses; this adds what
the checks need on top: each member as `tarball.Member` with its path normalized, and a hard link given as
such. It yields each member with an iterator over its data, which must be read (or left) before the next
member is asked for; the data the consumer did not read is skipped. Memory stays bounded.

A hard link is a regular file whose inode (and device) an earlier member had, with a link count above one:
it is given as a `hardlink` to the first name, as a tarball gives one. Its data, when the archive carries it
there (GNU cpio writes it with the last name), is still yielded, so a search sees it.
"""

import stat
from collections.abc import Iterator

from ..build import initrd
from ..build.initrd import InitrdError as NewcError
from ..build.initrd import Read
from .tarball import Kind, Member, normalize

__all__ = ["NewcError", "Read", "entries"]


def kind_of(mode: int) -> Kind:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def entries(read: Read) -> Iterator[tuple[str, Member, Iterator[bytes]]]:
    """Each member of the archive `read` gives, up to its trailer: its name as stored, the member, and its data (a
    symlink's target is in the member, not the data). Raises NewcError when the bytes are not a whole newc
    archive."""
    first: dict[tuple[int, int, int], str] = {}
    for head, data in initrd.stream_entries(read):
        path = normalize(head.name)
        kind = kind_of(head.mode)
        target = ""
        if kind == "symlink":
            target = b"".join(data).decode("utf-8", "surrogateescape")
            data = iter(())
        if kind == "file" and head.nlink > 1:
            key = (head.devmajor, head.devminor, head.ino)
            if key in first:
                kind, target = "hardlink", first[key]
            else:
                first[key] = path
        yield head.name, Member(path, kind, target), data
