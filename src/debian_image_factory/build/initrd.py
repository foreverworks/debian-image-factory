"""The installer kit writer and the initrd reader: standard library only (DESIGN 5.3, 8.1).

The builder runs this file with its own python3 (`python3 -I initrd.py ...`), copied into the build's work
directory like layer.py, so it imports nothing from the package; the package imports it as
`debian_image_factory.build.initrd` to read an initrd or a kit back. One module holds the format, for
the writer and every reader. Commands:

- `unpack`: an installer parent's `initrd.img`, read from its kit tarball, into an empty root, with owners,
  modes, times and hard links. A device node the kernel will not let a rootless build create is recorded
  in a state file in layer.py's format (absent rows only), so `kit` still writes it. The factory's own
  `/init` link is left out: `kit` adds it again.
- `kit`: the root as the kit: `initrd.img` (below), the image's one kernel `/boot/vmlinuz-<kver>` as
  `vmlinuz`, and `kit.json`, in one uncompressed tar in that order (`kit.json`, `vmlinuz`, `initrd.img`),
  every member mode 0644, owned by 0:0 with no names, time stamped SOURCE_DATE_EPOCH. dpkg's status is
  copied out for the SBOM.

`initrd.img` is the whole root, /boot included, as a newc cpio ("070701"): sorted by path with parents
first, numeric owners, mtimes clamped to SOURCE_DATE_EPOCH, inode numbers assigned in order, hard links
kept as newc hard links (one inode number, the content with the last of them, as GNU cpio writes them),
device nodes, fifos and symbolic links kept, extended attributes dropped (newc has none), and `/init` a
symbolic link to `/sbin/init` (systemd), the first program the kernel runs from an initramfs. It is
compressed with gzip level 9 with no name and a zero time stamp.

Reading: `members(path)` lists an initrd's members (`Member`: name, mode with the file type, owner, link
count, mtime, size, inode, device numbers, link target and, on request, content); `read_kit(path)` checks a
kit tarball's layout and returns its `kit.json`.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tarfile
from collections.abc import Collection, Iterator, Sequence
from dataclasses import dataclass
from typing import BinaryIO, Final

MAGIC: Final = b"070701"
HEADER_SIZE: Final = 110
"""The magic and thirteen 8-digit hexadecimal fields."""
TRAILER: Final = "TRAILER!!!"
INIT: Final = "init"
INIT_TARGET: Final = "/sbin/init"
KIT_MEMBERS: Final = ("kit.json", "vmlinuz", "initrd.img")
"""The kit tarball's members, in their order."""
KIT_SCHEMA: Final = 1
KERNEL_PREFIX: Final = "vmlinuz-"
MAX_SIZE: Final = 0xFFFFFFFF
"""newc's size field has eight hexadecimal digits."""
DPKG_STATUS: Final = "var/lib/dpkg/status"


class InitrdError(Exception):
    """An initrd, a kit or a root this program cannot handle; the message says why."""


@dataclass(frozen=True, slots=True)
class Member:
    """One member of a newc archive, as its header says."""

    name: str
    """Relative to the root, with no `./`; the root itself is `.`."""
    mode: int
    """File type and permission bits (`stat.S_IFMT` splits them)."""
    uid: int
    gid: int
    nlink: int
    mtime: int
    size: int
    """Bytes of content: a symbolic link's target; 0 for every hard link of a group but the last."""
    ino: int
    rdevmajor: int = 0
    rdevminor: int = 0
    link: str = ""
    """A symbolic link's target."""
    data: bytes | None = None
    """The content, when it was asked for."""


@dataclass(frozen=True, slots=True)
class Absent:
    """A device node the build could not create, as layer.py's state records it."""

    kind: str
    """`char` or `block`."""
    mode: int
    uid: int
    gid: int
    mtime: int
    major: int
    minor: int


# ---- names --------------------------------------------------------------------------------------


def clean_name(name: str) -> str:
    """A member name as a path relative to the root (`.` for the root). A `..` is refused."""
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise InitrdError(f"{name!r}: a path with .. in it")
    return "/".join(parts) or "."


def sort_key(path: str) -> tuple[str, ...]:
    """Parents first, then by name, component by component (layer.py's order); the root sorts first."""
    return () if path == "." else tuple(path.split("/"))


# ---- reading ------------------------------------------------------------------------------------


def read_exact(stream: BinaryIO, size: int, what: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise InitrdError(f"the archive ends inside {what}")
    return data


def pad(size: int) -> int:
    return -size % 4


def entries(stream: BinaryIO) -> Iterator[tuple[Member, bytes]]:
    """Every member of the newc archive in `stream` and its content, up to the trailer."""
    while True:
        header = read_exact(stream, HEADER_SIZE, "a header")
        if header[:6] != MAGIC:
            raise InitrdError(f"not a newc header: {header[:6]!r}")
        try:
            fields = [int(header[6 + 8 * index : 14 + 8 * index], 16) for index in range(13)]
        except ValueError:
            raise InitrdError("a header field is not hexadecimal") from None
        ino, mode, uid, gid, nlink, mtime, size, _, _, rdevmajor, rdevminor, namesize, _ = fields
        raw_name = read_exact(stream, namesize, "a name")
        read_exact(stream, pad(HEADER_SIZE + namesize), "a name's padding")
        if not raw_name.endswith(b"\0"):
            raise InitrdError("a name that does not end in NUL")
        name = os.fsdecode(raw_name[:-1])
        if name == TRAILER:
            return
        data = read_exact(stream, size, f"the content of {name}")
        read_exact(stream, pad(size), f"the padding of {name}")
        link = os.fsdecode(data) if stat.S_ISLNK(mode) else ""
        yield Member(clean_name(name), mode, uid, gid, nlink, mtime, size, ino, rdevmajor, rdevminor, link), data


def opened(source: BinaryIO) -> BinaryIO:
    """`source` itself, or its decompressed stream when it starts with gzip's magic."""
    head = source.read(2)
    source.seek(0)
    if head == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=source, mode="rb")  # type: ignore[return-value]  # GzipFile is a binary stream
    return source


def members(path: str, *, contents: bool | Collection[str] = False) -> list[Member]:
    """The members of the initrd at `path` (gzip-compressed or not), in archive order. `contents` asks for
    the content of every member (True) or of the named ones; the others carry `data=None`."""
    with open(path, "rb") as handle:
        return list(read_members(handle, contents=contents))


def read_members(source: BinaryIO, *, contents: bool | Collection[str] = False) -> Iterator[Member]:
    """`members` over an open, seekable binary stream."""
    for member, data in entries(opened(source)):
        wanted = contents if isinstance(contents, bool) else member.name in contents
        yield Member(
            member.name, member.mode, member.uid, member.gid, member.nlink, member.mtime, member.size,
            member.ino, member.rdevmajor, member.rdevminor, member.link, data if wanted else None,
        )  # fmt: skip


def read_kit(path: str) -> dict[str, object]:
    """The `kit.json` of the kit tarball at `path`, after checking the tarball holds exactly the three
    regular files in order and that `vmlinuz` and `initrd.img` are the size and sha256 it names."""
    with tarfile.open(path, mode="r:") as archive:
        found = archive.getmembers()
        if [member.name for member in found] != list(KIT_MEMBERS) or not all(member.isfile() for member in found):
            raise InitrdError(f"{path}: a kit holds the files {list(KIT_MEMBERS)}, not {[m.name for m in found]}")
        handle = archive.extractfile(found[0])
        assert handle is not None  # a regular file always has content
        try:
            kit: object = json.loads(handle.read())
        except ValueError as error:
            raise InitrdError(f"{path}: kit.json is not JSON: {error}") from None
        if not isinstance(kit, dict) or kit.get("schema") != KIT_SCHEMA or not isinstance(kit.get("files"), dict):
            raise InitrdError(f"{path}: kit.json is not a schema {KIT_SCHEMA} kit")
        files: dict[str, object] = kit["files"]
        for member in found[1:]:
            stream = archive.extractfile(member)
            assert stream is not None
            hashed = hashlib.sha256()
            while block := stream.read(1 << 20):
                hashed.update(block)
            digest = hashed.hexdigest()
            if files.get(member.name) != {"sha256": digest, "size": member.size}:
                raise InitrdError(f"{path}: {member.name} is not the file kit.json names")
        return {str(key): value for key, value in kit.items()}


# ---- unpacking ----------------------------------------------------------------------------------


def checked_parent(root: str, path: str) -> None:
    """The directory holding `path` must lie inside the root once its symbolic links are followed."""
    real_root = os.path.realpath(root)
    real = os.path.realpath(os.path.join(root, os.path.dirname(path)))
    if real != real_root and not real.startswith(real_root + "/"):
        raise InitrdError(f"/{path}: its directory leaves the root through a symbolic link")


def set_attributes(path: str, member: Member) -> None:
    os.lchown(path, member.uid, member.gid)
    if not stat.S_ISLNK(member.mode):
        os.chmod(path, stat.S_IMODE(member.mode))
    stamp = member.mtime * 1_000_000_000
    os.utime(path, ns=(stamp, stamp), follow_symlinks=False)


def unpack(root: str, kit: str) -> tuple[dict[str, Absent], list[str]]:
    """The initrd of the kit tarball `kit` into the empty directory `root`. Returns the device nodes that
    could not be created and notes about them."""
    absent: dict[str, Absent] = {}
    notes: list[str] = []
    directories: list[Member] = []
    first_of: dict[int, str] = {}
    before = os.umask(0)
    try:
        with tarfile.open(kit, mode="r:") as archive:
            member_info = archive.getmember("initrd.img")
            source = archive.extractfile(member_info)
            if source is None:
                raise InitrdError(f"{kit}: initrd.img is not a file")
            for member, data in entries(opened(source)):  # type: ignore[arg-type]  # tarfile's reader is a binary stream
                path = member.name
                if path == INIT and stat.S_ISLNK(member.mode) and member.link == INIT_TARGET:
                    continue  # the factory's own: `kit` adds it again
                full = root if path == "." else os.path.join(root, path)
                if path != ".":
                    checked_parent(root, path)
                kind = stat.S_IFMT(member.mode)
                if kind == stat.S_IFDIR:
                    if not os.path.isdir(full):
                        os.mkdir(full, 0o700)
                    directories.append(member)
                    continue
                if os.path.lexists(full):
                    raise InitrdError(f"/{path} is in the initrd twice")
                if kind == stat.S_IFREG:
                    if member.nlink > 1 and member.ino in first_of:
                        os.link(os.path.join(root, first_of[member.ino]), full)
                        if data:  # the content of a group comes with its last link
                            with open(full, "r+b") as target:
                                target.write(data)
                            set_attributes(full, member)
                        continue
                    descriptor = os.open(full, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "wb") as target:
                        target.write(data)
                    if member.nlink > 1:
                        first_of[member.ino] = path
                elif kind == stat.S_IFLNK:
                    os.symlink(member.link, full)
                elif kind == stat.S_IFIFO:
                    os.mkfifo(full)
                elif kind in (stat.S_IFCHR, stat.S_IFBLK):
                    try:
                        os.mknod(full, member.mode, os.makedev(member.rdevmajor, member.rdevminor))
                    except PermissionError as error:
                        numbers = f"{member.rdevmajor}:{member.rdevminor}"
                        notes.append(f"/{path}: device {numbers} not created ({error.strerror})")
                        absent[path] = Absent(
                            "char" if kind == stat.S_IFCHR else "block", stat.S_IMODE(member.mode), member.uid,
                            member.gid, member.mtime, member.rdevmajor, member.rdevminor,
                        )  # fmt: skip
                        continue
                else:
                    raise InitrdError(f"/{path}: a member type this program does not unpack ({member.mode:o})")
                set_attributes(full, member)
        # Directories last, deepest first: creating a child changes its parent's time.
        for member in sorted(directories, key=lambda one: sort_key(one.name), reverse=True):
            set_attributes(root if member.name == "." else os.path.join(root, member.name), member)
    finally:
        os.umask(before)
    return absent, notes


def state_json(absent: dict[str, Absent]) -> str:
    """The absent devices as layer.py's state file holds them (its `state_json` rows)."""
    rows = {
        path: [one.kind, one.mode, one.uid, one.gid, one.mtime, 0, "", "", one.major, one.minor, [], True]
        for path, one in sorted(absent.items(), key=lambda item: sort_key(item[0]))
    }
    return json.dumps(rows, separators=(",", ":"), ensure_ascii=True)


def read_absent(path: str) -> dict[str, Absent]:
    """The absent device nodes of a layer.py state file: its rows whose last value is true. The other
    rows are what the root holds, which `kit` reads from the disk."""
    with open(path, encoding="utf-8") as handle:
        data: object = json.load(handle)
    if not isinstance(data, dict):
        raise InitrdError(f"{path} is not a state file")
    found: dict[str, Absent] = {}
    for name, row in data.items():
        if not isinstance(row, list) or len(row) != 12:
            raise InitrdError(f"the state of {name} is not a row of 12 values")
        if row[11] is not True:
            continue
        kind, mode, uid, gid, mtime, major, minor = row[0], *row[1:5], row[8], row[9]
        numbers = (mode, uid, gid, mtime, major, minor)
        if kind not in ("char", "block") or not all(type(number) is int for number in numbers):
            raise InitrdError(f"the state of {name} is not an absent device")
        found[str(name)] = Absent(kind, mode, uid, gid, mtime, major, minor)
    return found


# ---- writing ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Source:
    """One path of the root to write: its lstat, or the absent device it stands for."""

    path: str
    info: os.stat_result | None
    absent: Absent | None = None


def walk(root: str, absent: dict[str, Absent]) -> list[Source]:
    """Every path of the root, the root itself first, then parents before children in name order, plus
    the absent devices whose directory is still one. A directory on another file system is an error."""
    found: dict[str, Source] = {".": Source(".", os.lstat(root))}
    device = os.lstat(root).st_dev
    pending = [""]
    while pending:
        relative = pending.pop()
        with os.scandir(os.path.join(root, relative) if relative else root) as listing:
            for item in listing:
                path = f"{relative}/{item.name}" if relative else item.name
                info = os.lstat(os.path.join(root, path))
                if info.st_dev != device:
                    raise InitrdError(f"/{path} is on another file system: a mount was left under the root")
                found[path] = Source(path, info)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
    for path, one in absent.items():
        holder = found.get(path.rpartition("/")[0] or ".")
        if path not in found and holder is not None and holder.info is not None and stat.S_ISDIR(holder.info.st_mode):
            found[path] = Source(path, None, one)
    if INIT in found:
        raise InitrdError(f"/{INIT} is already in the root: the kit's initrd makes it a link to {INIT_TARGET}")
    found[INIT] = Source(INIT, None)
    return sorted(found.values(), key=lambda one: sort_key(one.path))


def header(
    name: bytes, *, ino: int, mode: int, uid: int, gid: int, nlink: int, mtime: int, size: int, rdev: tuple[int, int]
) -> bytes:
    if size > MAX_SIZE:
        raise InitrdError(f"/{os.fsdecode(name)}: {size} bytes, more than newc can hold")
    fields = (ino, mode, uid, gid, nlink, mtime, size, 0, 0, rdev[0], rdev[1], len(name) + 1, 0)
    text = MAGIC + b"".join(b"%08x" % field for field in fields) + name + b"\0"
    return text + b"\0" * pad(len(text))


def write_cpio(root: str, sources: Sequence[Source], epoch: int, out: BinaryIO) -> int:
    """The newc archive of `sources` into `out`; returns the number of members (the trailer aside)."""
    groups: dict[tuple[int, int], list[str]] = {}
    for one in sources:
        if one.info is not None and stat.S_ISREG(one.info.st_mode) and one.info.st_nlink > 1:
            groups.setdefault((one.info.st_dev, one.info.st_ino), []).append(one.path)
    inode_of: dict[tuple[int, int], int] = {}
    number = 0
    for one in sources:
        name = b"." if one.path == "." else os.fsencode(one.path)
        data = b""
        rdev = (0, 0)
        nlink = 1
        if one.info is None and one.absent is None:  # the factory's /init
            mode, uid, gid, mtime = stat.S_IFLNK | 0o777, 0, 0, epoch
            data = os.fsencode(INIT_TARGET)
        elif one.info is None:
            assert one.absent is not None
            device = one.absent
            mode = (stat.S_IFCHR if device.kind == "char" else stat.S_IFBLK) | device.mode
            uid, gid, mtime, rdev = device.uid, device.gid, min(device.mtime, epoch), (device.major, device.minor)
        else:
            info = one.info
            mode, uid, gid = info.st_mode, info.st_uid, info.st_gid
            mtime = min(info.st_mtime_ns // 1_000_000_000, epoch)
            if stat.S_ISDIR(mode):
                nlink = 2
            elif stat.S_ISLNK(mode):
                data = os.fsencode(os.readlink(os.path.join(root, one.path)))
            elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                rdev = (os.major(info.st_rdev), os.minor(info.st_rdev))
            elif stat.S_ISSOCK(mode):
                raise InitrdError(f"/{one.path}: a socket, which an image cannot hold")
        key = (one.info.st_dev, one.info.st_ino) if one.info is not None else None
        group = groups.get(key) if key is not None else None
        if group is not None and key is not None:
            if key not in inode_of:
                number += 1
                inode_of[key] = number
            ino, nlink = inode_of[key], len(group)
        else:
            number += 1
            ino = number
        content: str | None = None
        size = len(data)
        if stat.S_ISREG(mode) and (group is None or group[-1] == one.path):
            assert one.info is not None
            content, size = os.path.join(root, one.path), one.info.st_size
        out.write(header(name, ino=ino, mode=mode, uid=uid, gid=gid, nlink=nlink, mtime=mtime, size=size, rdev=rdev))
        if content is not None:
            with open(content, "rb") as handle:
                copied = copy_counted(handle, out)
            if copied != size:
                raise InitrdError(f"/{one.path} changed size while it was read")
        else:
            out.write(data)
        out.write(b"\0" * pad(size))
    out.write(header(TRAILER.encode(), ino=0, mode=0, uid=0, gid=0, nlink=1, mtime=0, size=0, rdev=(0, 0)))
    return len(sources)


def copy_counted(source: BinaryIO, target: BinaryIO) -> int:
    copied = 0
    while block := source.read(1 << 20):
        target.write(block)
        copied += len(block)
    return copied


def write_initrd(root: str, absent: dict[str, Absent], epoch: int, target: str) -> int:
    """`target`: the gzip-compressed newc archive of the root (level 9, no name, zero time stamp)."""
    with (
        open(target, "wb") as raw,
        gzip.GzipFile(filename="", mode="wb", compresslevel=9, mtime=0, fileobj=raw) as writer,
    ):
        return write_cpio(root, walk(root, absent), epoch, writer)  # type: ignore[arg-type]  # GzipFile is a binary stream


def kernel_of(root: str) -> tuple[str, str]:
    """(kernel version, path) of the root's one `/boot/vmlinuz-<kver>`; anything but exactly one fails."""
    boot = os.path.join(root, "boot")
    try:
        names = sorted(name for name in os.listdir(boot) if name.startswith(KERNEL_PREFIX))
    except FileNotFoundError:
        names = []
    if len(names) != 1:
        found = ", ".join(f"/boot/{name}" for name in names) or "none"
        raise InitrdError(f"an installer kit takes exactly one kernel, /boot/vmlinuz-<version>; the root has {found}")
    path = os.path.join(boot, names[0])
    if not os.path.isfile(path) or os.path.islink(path):
        raise InitrdError(f"/boot/{names[0]} is not a regular file")
    return names[0].removeprefix(KERNEL_PREFIX), path


def file_facts(path: str) -> dict[str, object]:
    with open(path, "rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    return {"sha256": digest, "size": os.path.getsize(path)}


def kit_json(image: str, kernel: str, vmlinuz: dict[str, object], initrd: dict[str, object]) -> bytes:
    """Canonical JSON (sorted keys, no whitespace) and a newline."""
    kit = {"schema": KIT_SCHEMA, "image": image, "kernel": kernel, "files": {"vmlinuz": vmlinuz, "initrd.img": initrd}}
    return json.dumps(kit, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def kit_member(name: str, size: int, epoch: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = size, 0o644, epoch
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def kit(root: str, state: str | None, epoch: int, image: str, out: str, status_out: str | None) -> str:
    """Write the kit tarball `out` from the root; returns the kernel version."""
    kernel, vmlinuz = kernel_of(root)
    absent = read_absent(state) if state is not None else {}
    initrd = out + ".initrd.img"
    try:
        write_initrd(root, absent, epoch, initrd)
        described = kit_json(image, kernel, file_facts(vmlinuz), file_facts(initrd))
        with tarfile.open(out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            archive.addfile(kit_member(KIT_MEMBERS[0], len(described), epoch), io.BytesIO(described))
            for name, path in ((KIT_MEMBERS[1], vmlinuz), (KIT_MEMBERS[2], initrd)):
                with open(path, "rb") as handle:
                    archive.addfile(kit_member(name, os.path.getsize(path), epoch), handle)
    finally:
        if os.path.exists(initrd):
            os.unlink(initrd)
    if status_out is not None:
        shutil.copyfile(os.path.join(root, DPKG_STATUS), status_out)
    return kernel


# ---- the command line ---------------------------------------------------------------------------


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="initrd.py")
    commands = parser.add_subparsers(dest="command", required=True)
    unpacking = commands.add_parser("unpack")
    unpacking.add_argument("--root", required=True)
    unpacking.add_argument("--state", required=True)
    unpacking.add_argument("--kit", required=True)
    packing = commands.add_parser("kit")
    packing.add_argument("--root", required=True)
    packing.add_argument("--state")
    packing.add_argument("--epoch", type=int, required=True)
    packing.add_argument("--image", required=True)
    packing.add_argument("--out", required=True)
    packing.add_argument("--status-out")
    arguments = parser.parse_args(list(argv))
    try:
        if arguments.command == "unpack":
            absent, notes = unpack(arguments.root, arguments.kit)
            with open(arguments.state, "w", encoding="utf-8") as handle:
                handle.write(state_json(absent))
            for note in notes:
                print(f"note: {note}")
            print(f"unpacked the initrd of {arguments.kit}")
        else:
            kernel = kit(
                arguments.root, arguments.state, arguments.epoch, arguments.image, arguments.out, arguments.status_out
            )
            print(f"kit for kernel {kernel}")
    except (InitrdError, OSError, tarfile.TarError, EOFError) as error:
        print(f"initrd.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
