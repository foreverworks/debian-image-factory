"""Reading an Incus image's root filesystem (`*.rootfs.squashfs`) in one pass: the squashfs twin of tarball.py.

It answers the same question with the same types: the members, the files a check asked for whole, the
files holding a key or a token, where the needle was found. Memory stays bounded the same way: file
contents in chunks, but for the few small files in `wanted`, read up to MAX_WANTED bytes.
"""

from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Final, Literal

from .. import squashfs
from ..squashfs import SquashfsError
from . import scanning, tarball
from .scanning import Needle
from .tarball import Hit, Member, Scan

__all__ = ["SquashfsError", "scan_squashfs"]

KINDS: Final[dict[squashfs.Kind, tarball.Kind]] = {
    "file": "file",
    "dir": "dir",
    "symlink": "symlink",
    "char": "other",
    "block": "other",
    "fifo": "other",
    "socket": "other",
}
"""A squashfs hard link is a second path to the same inode, a `file`: there is no `hardlink`."""


def limited(chunks: Iterator[bytes], limit: int) -> bytes:
    """The first `limit` bytes of the chunks, reading no more than that."""
    out = bytearray()
    for chunk in chunks:
        out += chunk[: limit - len(out)]
        if len(out) >= limit:
            break
    return bytes(out)


def scan_squashfs(path: Path, wanted: frozenset[str], needle: Needle, keys: bool) -> Scan:
    """One pass over a squashfs image, the way scan_tarball reads a tarball.

    `wanted` are the absolute paths whose content is kept; `needle` is searched in every path, symlink
    target and regular file's content; `keys` looks for private key blocks and credential tokens in regular
    files. Raises SquashfsError or OSError when the file cannot be read as a squashfs image.
    """
    members: list[Member] = []
    contents: dict[str, bytes] = {}
    key_files: list[str] = []
    hits: list[Hit] = []
    needles = scanning.needles_of(needle)
    needle_bytes = tuple(one.encode() for one in needles)

    def hit(where: Literal["path", "link target", "content"], where_path: str) -> None:
        if len(hits) < tarball.HITS_LIMIT:
            hits.append(Hit(where, where_path))

    with path.open("rb") as handle:
        image = squashfs.open_image(handle)
        for entry in squashfs.walk(image):
            kind = KINDS[entry.kind]
            member = Member(entry.path, kind, entry.target if kind == "symlink" else "")
            members.append(member)
            if any(one in member.path for one in needles):
                hit("path", member.path)
            if any(one in member.target for one in needles):
                hit("link target", member.path)
            if member.kind != "file":
                continue
            stream: Iterable[bytes]
            if member.path in wanted:
                contents[member.path] = limited(squashfs.read_data(image, entry), tarball.MAX_WANTED)
                stream = [contents[member.path]]
            else:
                stream = squashfs.read_data(image, entry)
            doc = member.path.startswith(tarball.DOC_TREES) and member.path.endswith(tarball.COMPRESSED_DOCS)
            search_keys = keys and not doc
            if not needle_bytes and not search_keys:
                continue
            found = scanning.scan(stream, needle_bytes, search_keys)
            if found.needle:
                hit("content", member.path)
            if found.key:
                key_files.append(member.path)
            key_files.extend(f"{member.path} ({token.kind}: {token.redacted})" for token in found.tokens)
    return Scan(tuple(members), contents, tuple(sorted(key_files)), tuple(hits))
