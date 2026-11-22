"""Reading a squashfs 4.0 image with the standard library alone: the edge of the file checks of an Incus image.

The reader takes a binary file handle (seekable) and walks the image the way the kernel does: the superblock,
the inode table, the directory table, the fragment table, the id table and the xattr table, all little endian.
Only gzip (zlib) compression is read; any other compressor, a bad magic, another version, a table outside
the file or a block that does not decode raises SquashfsError, never IndexError or struct.error.

Memory stays bounded: metadata is read one 8 KiB block at a time (a few are cached), a file's data one block
at a time, split into CHUNK-sized pieces, and a hole of zeros is never held whole.

Spec: the kernel's fs/squashfs (squashfs_fs.h) and squashfs-tools; the fixtures under tests/fixtures/squashfs
come from mksquashfs 4.6.1.
"""

import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from itertools import pairwise
from typing import IO, Final, Literal

MAGIC: Final = 0x73717368
"""`hsqs`, the first four bytes of an image."""
SUPERBLOCK_SIZE: Final = 96
METADATA_SIZE: Final = 8192
"""A metadata block holds at most this many bytes once decoded."""
UNCOMPRESSED_METADATA: Final = 0x8000
UNCOMPRESSED_BLOCK: Final = 1 << 24
"""The flag in a data block's or a fragment's size word: the bytes are stored as they are."""
SIZE_MASK: Final = UNCOMPRESSED_BLOCK - 1
NONE: Final = 0xFFFFFFFF
"""`no fragment`, `no xattrs`: the 32-bit marker."""
NONE_64: Final = 0xFFFFFFFFFFFFFFFF
CHUNK: Final = 64 * 1024
MAX_DEPTH: Final = 4096
CACHED_BLOCKS: Final = 64
CACHED_FRAGMENTS: Final = 4

GZIP: Final = 1
COMPRESSORS: Final = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}

type Kind = Literal["file", "dir", "symlink", "char", "block", "fifo", "socket"]

DIR, FILE, SYMLINK, BLOCK, CHAR, FIFO, SOCKET = 1, 2, 3, 4, 5, 6, 7
LDIR, LFILE, LSYMLINK, LBLOCK, LCHAR, LFIFO, LSOCKET = 8, 9, 10, 11, 12, 13, 14
KINDS: Final[dict[int, Kind]] = {
    DIR: "dir",
    FILE: "file",
    SYMLINK: "symlink",
    BLOCK: "block",
    CHAR: "char",
    FIFO: "fifo",
    SOCKET: "socket",
}
"""Inode types by their basic number; an extended type (8 to 14) is the basic one plus seven."""

XATTR_PREFIXES: Final = {0: "user.", 1: "trusted.", 2: "security."}
XATTR_OUT_OF_LINE: Final = 0x100


class SquashfsError(ValueError):
    """The bytes are not a squashfs 4.0 image this reader can read."""


@dataclass(frozen=True, slots=True)
class Superblock:
    inode_count: int
    mkfs_time: int
    block_size: int
    fragments: int
    compression: int
    flags: int
    ids: int
    root_inode: int
    bytes_used: int
    id_table: int
    xattr_table: int
    inode_table: int
    directory_table: int
    fragment_table: int
    lookup_table: int


@dataclass(frozen=True, slots=True)
class Blocks:
    """Where a regular file's bytes are: its data blocks, then (when `fragment` is not None) a tail."""

    start: int
    """Absolute offset of the first data block."""
    sizes: tuple[int, ...]
    """The size words of the data blocks: bit 24 set means stored uncompressed, size 0 means a hole."""
    fragment: int | None
    fragment_offset: int


@dataclass(frozen=True, slots=True)
class Listing:
    """A directory's entries: a position in the directory table and the bytes they take there."""

    block: int
    offset: int
    size: int


@dataclass(frozen=True, slots=True)
class Entry:
    path: str
    """Absolute, `/` for the root, no trailing slash."""
    kind: Kind
    mode: int
    """The permission bits, with setuid, setgid and sticky: `mode & 0o7777`."""
    uid: int
    gid: int
    mtime: int
    size: int
    """The content length of a file, the target length of a symlink, 0 for the rest."""
    inode: int
    nlink: int
    target: str = ""
    major: int = 0
    minor: int = 0
    xattrs: tuple[tuple[str, bytes], ...] = ()
    """Name and value, sorted by name; empty when the inode has none."""
    blocks: Blocks | None = None
    listing: Listing | None = None


@dataclass(frozen=True, slots=True, eq=False)
class Image:
    """An opened image: the handle, what its superblock and small tables say, and a few cached blocks."""

    handle: IO[bytes]
    length: int
    superblock: Superblock
    ids: tuple[int, ...]
    fragment_index: tuple[int, ...]
    xattr_index: tuple[int, ...]
    xattr_kv_start: int
    xattr_count: int
    ends: dict[int, int]
    """Where each table ends: the start of the next one, by table start."""
    blocks: dict[int, tuple[bytes, int]] = field(default_factory=dict)
    fragments: dict[int, bytes] = field(default_factory=dict)


@dataclass(slots=True)
class Cursor:
    """A reading position in a metadata table: the block's absolute offset, the offset in its decoded bytes."""

    block: int
    offset: int
    end: int
    """The first absolute offset past the table; a block may not reach it."""


def read_at(handle: IO[bytes], offset: int, size: int, length: int) -> bytes:
    """Exactly `size` bytes at `offset`, or SquashfsError when they are not all inside the image."""
    if offset < 0 or size < 0 or offset + size > length:
        raise SquashfsError(f"{size} bytes at offset {offset} are outside the image ({length} bytes)")
    handle.seek(offset)
    data = handle.read(size)
    if len(data) != size:
        raise SquashfsError(f"truncated image: {size} bytes at offset {offset}, {len(data)} read")
    return data


def inflate(data: bytes, limit: int, what: str) -> bytes:
    """Decode one zlib stream that must end and hold at most `limit` bytes."""
    stream = zlib.decompressobj()
    try:
        out = stream.decompress(data, limit + 1)
    except zlib.error as error:
        raise SquashfsError(f"{what} does not decompress: {error}") from error
    if len(out) > limit:
        raise SquashfsError(f"{what} decompresses to more than {limit} bytes")
    if not stream.eof:
        raise SquashfsError(f"{what} is a truncated compressed stream")
    return out


def data_length(handle: IO[bytes]) -> int:
    return handle.seek(0, 2)


def parse_superblock(raw: bytes) -> Superblock:
    (
        magic,
        inodes,
        mkfs_time,
        block_size,
        fragments,
        compression,
        block_log,
        flags,
        ids,
        major,
        minor,
        root_inode,
        bytes_used,
        id_table,
        xattr_table,
        inode_table,
        directory_table,
        fragment_table,
        lookup_table,
    ) = struct.unpack("<IIIIIHHHHHHQQQQQQQQ", raw)
    if magic != MAGIC:
        raise SquashfsError("not a squashfs image: bad magic")
    if (major, minor) != (4, 0):
        raise SquashfsError(f"unsupported squashfs version {major}.{minor}: only 4.0 is read")
    if compression != GZIP:
        name = COMPRESSORS.get(compression, "unknown")
        raise SquashfsError(f"unsupported squashfs compressor {name} (id {compression}): only gzip is read")
    if not 4096 <= block_size <= 1 << 20 or block_size != 1 << block_log:
        raise SquashfsError(f"bad squashfs block size {block_size} (log {block_log})")
    return Superblock(
        inodes,
        mkfs_time,
        block_size,
        fragments,
        compression,
        flags,
        ids,
        root_inode,
        bytes_used,
        id_table,
        xattr_table,
        inode_table,
        directory_table,
        fragment_table,
        lookup_table,
    )


def metadata_block(handle: IO[bytes], offset: int, end: int, length: int) -> tuple[bytes, int]:
    """One metadata block at `offset`, decoded, and the offset of the block after it."""
    if offset + 2 > end:
        raise SquashfsError(f"metadata block at offset {offset} is outside its table")
    (header,) = struct.unpack("<H", read_at(handle, offset, 2, length))
    size = header & ~UNCOMPRESSED_METADATA
    if size == 0 or size > METADATA_SIZE or offset + 2 + size > end:
        raise SquashfsError(f"bad metadata block of {size} bytes at offset {offset}")
    raw = read_at(handle, offset + 2, size, length)
    if header & UNCOMPRESSED_METADATA:
        return raw, offset + 2 + size
    return inflate(raw, METADATA_SIZE, f"metadata block at offset {offset}"), offset + 2 + size


def block_at(image: Image, offset: int, end: int) -> tuple[bytes, int]:
    cached = image.blocks.get(offset)
    if cached is not None:
        return cached
    block = metadata_block(image.handle, offset, end, image.length)
    if len(image.blocks) >= CACHED_BLOCKS:
        image.blocks.clear()
    image.blocks[offset] = block
    return block


def take(image: Image, cursor: Cursor, size: int) -> bytes:
    """The next `size` bytes of a metadata table, over block boundaries; moves the cursor."""
    out = bytearray()
    while len(out) < size:
        block, following = block_at(image, cursor.block, cursor.end)
        if cursor.offset > len(block):
            raise SquashfsError(f"offset {cursor.offset} is outside the metadata block at {cursor.block}")
        piece = block[cursor.offset : cursor.offset + size - len(out)]
        out += piece
        cursor.offset += len(piece)
        if cursor.offset >= len(block) and len(out) < size:
            cursor.block, cursor.offset = following, 0
    return bytes(out)


def unpack(image: Image, cursor: Cursor, fmt: str) -> tuple[int, ...]:
    return struct.unpack(fmt, take(image, cursor, struct.calcsize(fmt)))


def table_pointers(image_handle: IO[bytes], start: int, count: int, length: int, what: str) -> tuple[int, ...]:
    """The index of a table of metadata blocks: one absolute offset per block."""
    raw = read_at(image_handle, start, 8 * count, length)
    pointers = struct.unpack(f"<{count}Q", raw)
    if any(pointer + 2 > length for pointer in pointers):
        raise SquashfsError(f"the {what} index points outside the image")
    return pointers


def read_table(
    handle: IO[bytes], pointers: tuple[int, ...], count: int, item: int, length: int, what: str
) -> Iterator[bytes]:
    """Each of `count` items of `item` bytes from the metadata blocks `pointers` name (all full but the last)."""
    per_block = METADATA_SIZE // item
    for number, pointer in enumerate(pointers):
        block, _ = metadata_block(handle, pointer, length, length)
        want = min(per_block, count - number * per_block) * item
        if len(block) < want:
            raise SquashfsError(f"the {what} table is short")
        for position in range(0, want, item):
            yield block[position : position + item]


def open_image(handle: IO[bytes]) -> Image:
    """Read the superblock and the small tables (ids, the fragment and xattr indexes) of an image."""
    length = data_length(handle)
    superblock = parse_superblock(read_at(handle, 0, SUPERBLOCK_SIZE, length))
    if superblock.bytes_used > length:
        raise SquashfsError(f"truncated image: {length} bytes, the superblock counts {superblock.bytes_used}")
    for name, start in (
        ("inode", superblock.inode_table),
        ("directory", superblock.directory_table),
        ("id", superblock.id_table),
    ):
        if start >= superblock.bytes_used:
            raise SquashfsError(f"the {name} table starts outside the image")
    if superblock.ids == 0 or superblock.ids > 65536:
        raise SquashfsError(f"bad id count {superblock.ids}")

    starts = {superblock.inode_table, superblock.directory_table, superblock.id_table, superblock.bytes_used}
    if superblock.fragments:
        if superblock.fragment_table >= superblock.bytes_used:
            raise SquashfsError("the fragment table starts outside the image")
        starts.add(superblock.fragment_table)
    if superblock.lookup_table not in (NONE_64, 0) and superblock.lookup_table < superblock.bytes_used:
        starts.add(superblock.lookup_table)

    xattr_index: tuple[int, ...] = ()
    kv_start, xattr_count = 0, 0
    if superblock.xattr_table not in (NONE_64, 0):
        header = read_at(handle, superblock.xattr_table, 16, length)
        kv_start, xattr_count, _unused = struct.unpack("<QII", header)
        blocks = -(-xattr_count // 512)
        xattr_index = table_pointers(handle, superblock.xattr_table + 16, blocks, length, "xattr")
        if kv_start >= superblock.bytes_used:
            raise SquashfsError("the xattr table starts outside the image")
        starts.update((superblock.xattr_table, kv_start))
    ordered = sorted(starts)
    ends = dict(pairwise(ordered))

    id_pointers = table_pointers(handle, superblock.id_table, -(-superblock.ids // 2048), length, "id")
    ids = tuple(
        struct.unpack("<I", item)[0] for item in read_table(handle, id_pointers, superblock.ids, 4, length, "id")
    )
    fragment_index: tuple[int, ...] = ()
    if superblock.fragments:
        fragment_index = table_pointers(
            handle, superblock.fragment_table, -(-superblock.fragments // 512), length, "fragment"
        )
    return Image(handle, length, superblock, ids, fragment_index, xattr_index, kv_start, xattr_count, ends)


def table_cursor(image: Image, start: int, block: int, offset: int) -> Cursor:
    """A cursor at `offset` in the decoded block `block` bytes into the table that begins at `start`."""
    end = image.ends.get(start, image.superblock.bytes_used)
    return Cursor(start + block, offset, end)


def xattrs_of(image: Image, index: int) -> tuple[tuple[str, bytes], ...]:
    if index == NONE:
        return ()
    if index >= image.xattr_count:
        raise SquashfsError(f"xattr index {index} is outside the xattr table")
    handle, length = image.handle, image.length
    pointer = image.xattr_index[index // 512]
    block, _ = metadata_block(handle, pointer, length, length)
    start = index % 512 * 16
    if len(block) < start + 16:
        raise SquashfsError("the xattr id table is short")
    ref, count, _size = struct.unpack("<QII", block[start : start + 16])
    kv_end = image.ends.get(image.xattr_kv_start, image.superblock.bytes_used)
    cursor = Cursor(image.xattr_kv_start + (ref >> 16), ref & 0xFFFF, kv_end)
    found: list[tuple[str, bytes]] = []
    for _ in range(count):
        kind, name_size = unpack(image, cursor, "<HH")
        prefix = XATTR_PREFIXES.get(kind & 0xFF)
        if prefix is None:
            raise SquashfsError(f"unknown xattr prefix {kind & 0xFF}")
        name = prefix + take(image, cursor, name_size).decode("utf-8", "surrogateescape")
        (value_size,) = unpack(image, cursor, "<I")
        value = take(image, cursor, value_size)
        if kind & XATTR_OUT_OF_LINE:
            if value_size != 8:
                raise SquashfsError("a bad out-of-line xattr reference")
            (target,) = struct.unpack("<Q", value)
            far = Cursor(image.xattr_kv_start + (target >> 16), target & 0xFFFF, kv_end)
            (value_size,) = unpack(image, far, "<I")
            value = take(image, far, value_size)
        found.append((name, value))
    return tuple(sorted(found))


def read_inode(image: Image, path: str, block: int, offset: int) -> Entry:
    """The inode at `offset` in the inode table block `block` bytes into the table, as an Entry named `path`."""
    superblock = image.superblock
    cursor = table_cursor(image, superblock.inode_table, block, offset)
    number, mode, uid_index, gid_index, mtime, inode = unpack(image, cursor, "<HHHHII")
    if uid_index >= len(image.ids) or gid_index >= len(image.ids):
        raise SquashfsError(f"{path}: owner index outside the id table")
    base = Entry(path, "file", mode & 0o7777, image.ids[uid_index], image.ids[gid_index], mtime, 0, inode, 1)
    basic = number - 7 if number >= LDIR else number
    kind = KINDS.get(basic)
    if kind is None or number > LSOCKET:
        raise SquashfsError(f"{path}: unknown inode type {number}")
    extended = number >= LDIR
    xattr = NONE

    if basic == DIR:
        if extended:
            nlink, size, start, _parent, _count, offset_in, xattr = unpack(image, cursor, "<IIIIHHI")
        else:
            start, nlink, short, offset_in, _parent = unpack(image, cursor, "<IIHHI")
            size = short
        if size < 3:
            raise SquashfsError(f"{path}: directory size {size} is too small")
        return replace(
            base,
            kind=kind,
            size=0,
            nlink=nlink,
            xattrs=xattrs_of(image, xattr),
            listing=Listing(start, offset_in, size - 3),
        )
    if basic == FILE:
        if extended:
            start, size, _sparse, nlink, fragment, frag_offset, xattr = unpack(image, cursor, "<QQQIIII")
        else:
            start, fragment, frag_offset, size = unpack(image, cursor, "<IIII")
            nlink = 1
        block_size = superblock.block_size
        count = size // block_size if fragment != NONE else -(-size // block_size)
        if count * 4 > image.length:
            raise SquashfsError(f"{path}: a file of {size} bytes cannot fit in the image")
        sizes = struct.unpack(f"<{count}I", take(image, cursor, 4 * count))
        if start + sum(s & SIZE_MASK for s in sizes) > image.length:
            raise SquashfsError(f"{path}: data blocks outside the image")
        if fragment != NONE and not superblock.fragments > fragment:
            raise SquashfsError(f"{path}: fragment {fragment} does not exist")
        return replace(
            base,
            kind=kind,
            size=size,
            nlink=nlink,
            xattrs=xattrs_of(image, xattr),
            blocks=Blocks(start, sizes, None if fragment == NONE else fragment, frag_offset),
        )
    if basic == SYMLINK:
        nlink, size = unpack(image, cursor, "<II")
        target = take(image, cursor, size).decode("utf-8", "surrogateescape")
        if extended:
            (xattr,) = unpack(image, cursor, "<I")
        return replace(
            base,
            kind=kind,
            size=size,
            nlink=nlink,
            xattrs=xattrs_of(image, xattr),
            target=target,
        )
    if basic in (BLOCK, CHAR):
        nlink, rdev = unpack(image, cursor, "<II")
        if extended:
            (xattr,) = unpack(image, cursor, "<I")
        return replace(
            base,
            kind=kind,
            size=0,
            nlink=nlink,
            xattrs=xattrs_of(image, xattr),
            major=rdev >> 8 & 0xFFF,
            minor=rdev & 0xFF | rdev >> 12 & 0xFFF00,
        )
    (nlink,) = unpack(image, cursor, "<I")
    if extended:
        (xattr,) = unpack(image, cursor, "<I")
    return replace(
        base,
        kind=kind,
        size=0,
        nlink=nlink,
        xattrs=xattrs_of(image, xattr),
    )


@dataclass(frozen=True, slots=True)
class Child:
    """A directory entry: a name and where its inode is, as the directory table stores them."""

    name: str
    block: int
    offset: int


def children(image: Image, parent: Entry) -> Iterator[Child]:
    """The entries of a directory in the order the directory table stores them (sorted by name)."""
    listing = parent.listing
    if listing is None:
        raise SquashfsError(f"{parent.path} is not a directory")
    cursor = table_cursor(image, image.superblock.directory_table, listing.block, listing.offset)
    remaining = listing.size
    while remaining > 0:
        if remaining < 12:
            raise SquashfsError(f"{parent.path}: the directory listing is cut short")
        count, start, _inode = unpack(image, cursor, "<III")
        remaining -= 12
        if count > 255:
            raise SquashfsError(f"{parent.path}: a directory header counts {count + 1} entries")
        for _ in range(count + 1):
            offset, _delta, _kind, name_size = unpack(image, cursor, "<HhHH")
            name_bytes = take(image, cursor, name_size + 1)
            remaining -= 8 + name_size + 1
            if remaining < 0:
                raise SquashfsError(f"{parent.path}: the directory listing is cut short")
            if b"/" in name_bytes or b"\0" in name_bytes or name_bytes in (b".", b".."):
                raise SquashfsError(f"{parent.path}: bad entry name {name_bytes!r}")
            yield Child(name_bytes.decode("utf-8", "surrogateescape"), start, offset)


def walk(image: Image) -> Iterator[Entry]:
    """Every entry of the image, the root first, each directory's children right after it, depth first."""
    ref = image.superblock.root_inode
    root = read_inode(image, "/", ref >> 16, ref & 0xFFFF)
    if root.kind != "dir":
        raise SquashfsError("the root inode is not a directory")
    yield root
    seen = {ref}
    stack = [(root.path, children(image, root))]
    while stack:
        parent, pending = stack[-1]
        child = next(pending, None)
        if child is None:
            stack.pop()
            continue
        path = f"{parent.rstrip('/')}/{child.name}"
        entry = read_inode(image, path, child.block, child.offset)
        yield entry
        if entry.kind == "dir":
            key = child.block << 16 | child.offset
            if key in seen:
                raise SquashfsError(f"{path}: a directory reached twice")
            if len(stack) >= MAX_DEPTH:
                raise SquashfsError(f"{path}: directories nested more than {MAX_DEPTH} deep")
            seen.add(key)
            stack.append((path, children(image, entry)))


def entries(handle: IO[bytes]) -> Iterator[Entry]:
    """Every entry of the squashfs image in `handle`, depth first: the root `/` first, children in stored order."""
    return walk(open_image(handle))


def fragment_block(image: Image, number: int) -> bytes:
    if image.superblock.fragments <= number:
        raise SquashfsError(f"fragment {number} does not exist")
    cached = image.fragments.get(number)
    if cached is not None:
        return cached
    block, _ = block_at(image, image.fragment_index[number // 512], image.length)
    position = number % 512 * 16
    if len(block) < position + 16:
        raise SquashfsError("the fragment table is short")
    start, word, _unused = struct.unpack("<QII", block[position : position + 16])
    size = word & SIZE_MASK
    block_size = image.superblock.block_size
    if size == 0 or size > block_size:
        raise SquashfsError(f"fragment {number} has a bad size {size}")
    raw = read_at(image.handle, start, size, image.length)
    data = raw if word & UNCOMPRESSED_BLOCK else inflate(raw, block_size, f"fragment {number}")
    if len(image.fragments) >= CACHED_FRAGMENTS:
        image.fragments.clear()
    image.fragments[number] = data
    return data


def pieces(data: bytes) -> Iterator[bytes]:
    if len(data) <= CHUNK:
        yield data
        return
    for position in range(0, len(data), CHUNK):
        yield data[position : position + CHUNK]


def holes(size: int) -> Iterator[bytes]:
    zeros = bytes(min(size, CHUNK))
    for position in range(0, size, CHUNK):
        yield zeros[: min(CHUNK, size - position)]


def read_data(image: Image, entry: Entry) -> Iterator[bytes]:
    """The bytes of a regular file in chunks of at most CHUNK, one data block held at a time."""
    blocks = entry.blocks
    if entry.kind != "file" or blocks is None:
        raise SquashfsError(f"{entry.path} is not a regular file")
    block_size = image.superblock.block_size
    position, remaining = blocks.start, entry.size
    for word in blocks.sizes:
        want = min(block_size, remaining)
        size = word & SIZE_MASK
        if want == 0 or size > block_size:
            raise SquashfsError(f"{entry.path}: bad block list")
        if size == 0:
            yield from holes(want)
        else:
            raw = read_at(image.handle, position, size, image.length)
            data = raw if word & UNCOMPRESSED_BLOCK else inflate(raw, want, f"{entry.path}: data block")
            if len(data) != want:
                raise SquashfsError(f"{entry.path}: a data block holds {len(data)} bytes, not {want}")
            yield from pieces(data)
        position += size
        remaining -= want
    if remaining:
        if blocks.fragment is None:
            raise SquashfsError(f"{entry.path}: {remaining} bytes are missing from its blocks")
        data = fragment_block(image, blocks.fragment)[blocks.fragment_offset : blocks.fragment_offset + remaining]
        if len(data) != remaining:
            raise SquashfsError(f"{entry.path}: its fragment is too short")
        yield from pieces(data)


def read_file(handle: IO[bytes], entry: Entry) -> Iterator[bytes]:
    """The bytes of the regular file `entry` (from `entries(handle)`), in chunks, never the whole file at once."""
    return read_data(open_image(handle), entry)
