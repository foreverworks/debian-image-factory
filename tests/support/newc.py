"""A small newc ("070701") cpio writer for the tests: synthetic initrds, and the boot test's kit from a real
root (run as a script by the builder's python3: `python3 newc.py ROOT OUT`, gzip -9 with no name and a zero
time). Standard library only, so it runs inside a container that has nothing but python3."""

import gzip
import io
import os
import stat
import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass

TRAILER = "TRAILER!!!"


@dataclass(frozen=True, slots=True)
class Item:
    """One archive member: `name` as stored (`etc/machine-id`, `.` for the root)."""

    name: str
    mode: int
    data: bytes = b""
    ino: int = 0
    nlink: int = 1
    uid: int = 0
    gid: int = 0
    mtime: int = 0
    rdevmajor: int = 0
    rdevminor: int = 0


def pad4(length: int) -> bytes:
    return b"\0" * (-length % 4)


def header(item: Item, ino: int) -> bytes:
    name = item.name.encode() + b"\0"
    fields = (
        ino,
        item.mode,
        item.uid,
        item.gid,
        item.nlink,
        item.mtime,
        len(item.data),
        0,
        0,
        item.rdevmajor,
        item.rdevminor,
        len(name),
        0,
    )
    head = b"070701" + b"".join(b"%08x" % value for value in fields) + name
    return head + pad4(len(head))


def write(out: Callable[[bytes], object], items: Iterable[Item]) -> None:
    """The newc bytes of `items` and the trailer, one member at a time. An item's `ino` 0 is given the next
    number."""
    for number, item in enumerate(items, start=1):
        out(header(item, item.ino or number) + item.data + pad4(len(item.data)))
    out(header(Item(TRAILER, 0), 0))


def archive(items: Iterable[Item]) -> bytes:
    raw = io.BytesIO()
    write(raw.write, items)
    return raw.getvalue()


def file(name: str, data: bytes, mode: int = 0o644) -> Item:
    return Item(name, stat.S_IFREG | mode, data)


def directory(name: str, mode: int = 0o755) -> Item:
    return Item(name, stat.S_IFDIR | mode)


def symlink(name: str, target: str) -> Item:
    return Item(name, stat.S_IFLNK | 0o777, target.encode())


def initrd(items: Iterable[Item]) -> bytes:
    """The gzip of the archive, as an initrd.img is written: level 9, no name, a zero time."""
    return gzip.compress(archive(items), compresslevel=9, mtime=0)


def walk(root: str) -> list[str]:
    """Every path under `root`, relative, sorted, parents first."""
    found: list[str] = []
    for top, dirs, files in os.walk(root):
        dirs.sort()
        for name in [*dirs, *files]:
            found.append(os.path.relpath(os.path.join(top, name), root))
    return sorted(found, key=lambda path: path.split("/"))


def tree_items(root: str) -> Iterator[Item]:
    """A real root as newc items, one file read at a time: numeric owners kept, hard links as newc hard links
    (the data on the first name), device nodes and symlinks kept, and `/init` a link to `/sbin/init`."""
    yield Item(".", stat.S_IFDIR | 0o755)
    if not os.path.lexists(os.path.join(root, "init")):
        yield symlink("init", "/sbin/init")
    seen: dict[tuple[int, int], int] = {}
    for number, relative in enumerate(walk(root), start=2):
        path = os.path.join(root, relative)
        info = os.lstat(path)
        data = b""
        ino = number
        if stat.S_ISLNK(info.st_mode):
            data = os.readlink(path).encode()
        elif stat.S_ISREG(info.st_mode):
            key = (info.st_dev, info.st_ino)
            if info.st_nlink > 1 and key in seen:
                ino = seen[key]
            else:
                seen[key] = number
                with open(path, "rb") as handle:
                    data = handle.read()
        yield Item(
            relative,
            info.st_mode,
            data,
            ino,
            info.st_nlink if stat.S_ISREG(info.st_mode) else 1,
            info.st_uid,
            info.st_gid,
            int(info.st_mtime),
            os.major(info.st_rdev),
            os.minor(info.st_rdev),
        )


def main(argv: Sequence[str]) -> int:
    root, out = argv
    with open(out, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as handle:
        write(handle.write, tree_items(root))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
