"""The OCI layer writer: runs in the builder with the builder's python3, standard library only.

This file is copied into a build's work directory and run there (`python3 -I layer.py ...`), so it
imports nothing from the package. It has two jobs, one per command:

- `unpack`: apply a parent's layers, base first, to an empty directory the way a container runtime
  does (whiteouts, opaque directories, hard links, numeric owners, modes, xattrs, mtimes), then record
  the state of every path in a JSON file.
- `pack`: compare the directory, after the build changed it, with that state and write the one layer
  that turns the parent into the new image: a deterministic tar (PAX, numeric owners, no names, integer
  mtimes) in gzip with no name or time stamp. It also writes the uncompressed tar's sha256 (the layer's
  diff_id) and copies the image's dpkg status out for the SBOM. With `--full` it compares with an empty
  state instead, so the tar holds every path of the root: an `os` image's root filesystem tarball. The
  state's absent device nodes are written too, since the root holds them although this build could not
  create them.

What a path's state holds: its type, permission bits (with setuid, setgid and sticky), owner, mtime
(clamped to SOURCE_DATE_EPOCH, whole seconds), size and sha256 of a file's content, a symbolic link's
target, a device's numbers and every extended attribute. A path whose state differs is in the layer; a
path that is gone gets a whiteout (one for a removed directory, none for its children); a directory is
in the layer only when its own state differs. Device nodes the kernel will not let a rootless build
create are kept in the state as absent, so they are not read as removed. Hard links between paths of
the layer stay hard links.
"""

import argparse
import gzip
import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
from collections.abc import Sequence
from dataclasses import dataclass, replace

WHITEOUT = ".wh."
OPAQUE = ".wh..wh..opq"
XATTR_PREFIX = "SCHILY.xattr."
SKIPPED_XATTRS = ("trusted.overlay.",)
"""Attributes an overlay file system keeps for itself: not part of an image."""


class LayerError(Exception):
    """A layer or a root this program cannot handle; the message says why."""


@dataclass(frozen=True, slots=True)
class Entry:
    """The state of one path (see the module's docstring)."""

    kind: str
    """`dir`, `file`, `symlink`, `char`, `block` or `fifo`."""
    mode: int
    uid: int
    gid: int
    mtime: int
    size: int = 0
    sha256: str = ""
    link: str = ""
    major: int = 0
    minor: int = 0
    xattrs: tuple[tuple[str, str], ...] = ()
    """(name, value in hex), sorted by name."""
    absent: bool = False
    """A device node that could not be created here: recorded, never compared with the disk."""


@dataclass(frozen=True, slots=True)
class Scan:
    entries: dict[str, Entry]
    links: dict[str, tuple[int, int]]
    """For regular files with more than one link: (device, inode), to find the paths that share one."""


# ---- names --------------------------------------------------------------------------------------


def clean_name(name: str) -> str:
    """A tar member name as a path relative to the root: no `./`, no leading or doubled slash. A `..`
    is refused: no layer needs one and a crafted layer could leave the root with it."""
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise LayerError(f"{name!r}: a path with .. in it")
    return "/".join(parts)


def sort_key(path: str) -> tuple[str, ...]:
    return tuple(path.split("/"))


# ---- scanning a root ----------------------------------------------------------------------------


def xattrs_of(path: str) -> tuple[tuple[str, str], ...]:
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError:
        return ()
    found: list[tuple[str, str]] = []
    for name in sorted(names):
        if name.startswith(SKIPPED_XATTRS):
            continue
        try:
            found.append((name, os.getxattr(path, name, follow_symlinks=False).hex()))
        except OSError:
            continue  # gone between the two calls, or not readable: not part of the image
    return tuple(found)


def sha256_of(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def entry_of(path: str, info: os.stat_result, epoch: int) -> Entry:
    """The state of `path`, whose lstat is `info`."""
    mode = stat.S_IMODE(info.st_mode)
    uid, gid, mtime = info.st_uid, info.st_gid, min(info.st_mtime_ns // 1_000_000_000, epoch)
    attributes = xattrs_of(path)
    if stat.S_ISDIR(info.st_mode):
        return Entry("dir", mode, uid, gid, mtime, xattrs=attributes)
    if stat.S_ISLNK(info.st_mode):
        return Entry("symlink", 0o777, uid, gid, mtime, link=os.readlink(path), xattrs=attributes)
    if stat.S_ISREG(info.st_mode):
        return Entry("file", mode, uid, gid, mtime, size=info.st_size, sha256=sha256_of(path), xattrs=attributes)
    if stat.S_ISFIFO(info.st_mode):
        return Entry("fifo", mode, uid, gid, mtime, xattrs=attributes)
    if stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
        kind = "char" if stat.S_ISCHR(info.st_mode) else "block"
        major, minor = os.major(info.st_rdev), os.minor(info.st_rdev)
        return Entry(kind, mode, uid, gid, mtime, major=major, minor=minor, xattrs=attributes)
    raise LayerError(f"{path}: a file type an image cannot hold (a socket?)")


def scan(root: str, epoch: int) -> Scan:
    """The state of every path under `root`, keyed by path relative to it. A directory on another
    file system (a mount left behind) is an error: its contents would end up in the layer."""
    entries: dict[str, Entry] = {}
    links: dict[str, tuple[int, int]] = {}
    device = os.lstat(root).st_dev
    pending = [""]
    while pending:
        relative = pending.pop()
        with os.scandir(os.path.join(root, relative) if relative else root) as listing:
            for item in listing:
                path = f"{relative}/{item.name}" if relative else item.name
                full = os.path.join(root, path)
                info = os.lstat(full)
                if info.st_dev != device:
                    raise LayerError(f"/{path} is on another file system: a mount was left under the root")
                entries[path] = entry_of(full, info, epoch)
                if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                    links[path] = (info.st_dev, info.st_ino)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
    return Scan(entries, links)


# ---- the state file -----------------------------------------------------------------------------


def state_json(entries: dict[str, Entry]) -> str:
    rows = {
        path: [
            one.kind,
            one.mode,
            one.uid,
            one.gid,
            one.mtime,
            one.size,
            one.sha256,
            one.link,
            one.major,
            one.minor,
            [list(pair) for pair in one.xattrs],
            one.absent,
        ]
        for path, one in sorted(entries.items(), key=lambda item: sort_key(item[0]))
    }
    return json.dumps(rows, separators=(",", ":"), ensure_ascii=True)


def parse_row(path: str, row: object) -> Entry:
    if not isinstance(row, list) or len(row) != 12:
        raise LayerError(f"the state of {path} is not a row of 12 values")
    kind, mode, uid, gid, mtime, size, digest, link, major, minor, attributes, absent = row
    numbers = (mode, uid, gid, mtime, size, major, minor)
    if (
        not isinstance(kind, str)
        or not isinstance(digest, str)
        or not isinstance(link, str)
        or not isinstance(attributes, list)
        or not isinstance(absent, bool)
        or not all(isinstance(number, int) and not isinstance(number, bool) for number in numbers)
    ):
        raise LayerError(f"the state of {path} has a field of the wrong type")
    pairs: list[tuple[str, str]] = []
    for pair in attributes:
        if not (isinstance(pair, list) and len(pair) == 2 and all(isinstance(part, str) for part in pair)):
            raise LayerError(f"the state of {path} has a malformed attribute")
        pairs.append((str(pair[0]), str(pair[1])))
    return Entry(kind, mode, uid, gid, mtime, size, digest, link, major, minor, tuple(pairs), absent)


def read_state(path: str) -> dict[str, Entry]:
    with open(path, encoding="utf-8") as handle:
        data: object = json.load(handle)
    if not isinstance(data, dict):
        raise LayerError(f"{path} is not a state file")
    return {str(name): parse_row(str(name), row) for name, row in data.items()}


# ---- unpacking layers ---------------------------------------------------------------------------


def remove_path(path: str) -> None:
    """Delete a file, a link or a whole directory tree, if there is one."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def checked_parent(root: str, path: str, verified: set[str]) -> None:
    """The directory holding `path` must lie inside the root once its symbolic links are followed.
    `verified` caches the directories found inside; whoever creates a symbolic link empties it, since
    the link may replace a directory a cached path goes through."""
    parent = os.path.dirname(path)
    if parent in verified:
        return
    real_root = os.path.realpath(root)
    real = os.path.realpath(os.path.join(root, parent)) if parent else real_root
    if real != real_root and not real.startswith(real_root + "/"):
        raise LayerError(f"/{path}: its directory leaves the root through a symbolic link")
    verified.add(parent)


def set_attributes(path: str, member: tarfile.TarInfo, notes: list[str]) -> None:
    """Owner, then permission bits (a chown clears setuid), then xattrs. An attribute the kernel refuses
    is noted and left out: the state is read back from the disk, so the layer stays consistent."""
    os.lchown(path, member.uid, member.gid)
    if not member.issym():
        os.chmod(path, member.mode & 0o7777)
    for key, value in sorted(member.pax_headers.items()):
        if not key.startswith(XATTR_PREFIX):
            continue
        name = key.removeprefix(XATTR_PREFIX)
        try:
            os.setxattr(path, name, value.encode("utf-8", "surrogateescape"), follow_symlinks=False)
        except OSError as error:
            notes.append(f"{path}: xattr {name} not set ({error.strerror})")


def set_time(path: str, member: tarfile.TarInfo) -> None:
    stamp = int(member.mtime) * 1_000_000_000
    os.utime(path, ns=(stamp, stamp), follow_symlinks=False)


def apply_deletions(root: str, names: Sequence[str], verified: set[str]) -> None:
    """The whiteouts and opaque directories of one layer, applied before it adds anything, so that what
    the layer itself holds is never hidden by its own markers."""
    for name in names:
        checked_parent(root, name, verified)
        directory, _, base = name.rpartition("/")
        if base == OPAQUE:
            target = os.path.join(root, directory) if directory else root
            if os.path.isdir(target) and not os.path.islink(target):
                for child in os.listdir(target):
                    remove_path(os.path.join(target, child))
        else:
            gone = base.removeprefix(WHITEOUT)
            if not gone:
                raise LayerError(f"/{name}: a whiteout that names no file")
            remove_path(os.path.join(root, directory, gone))


def hidden_by(markers: Sequence[str], path: str) -> bool:
    """Whether a layer's whiteouts and opaque markers remove or empty `path`."""
    for name in markers:
        directory, _, base = name.rpartition("/")
        if base == OPAQUE:
            if path.startswith(directory + "/" if directory else ""):
                return True
        else:
            gone = f"{directory}/{base.removeprefix(WHITEOUT)}" if directory else base.removeprefix(WHITEOUT)
            if path == gone or path.startswith(gone + "/"):
                return True
    return False


def unpack_layer(root: str, layer: str, skipped: dict[str, Entry], notes: list[str], verified: set[str]) -> None:
    with tarfile.open(layer, mode="r:*", encoding="utf-8") as archive:
        members = [member for member in archive if clean_name(member.name)]
        names = [clean_name(member.name) for member in members]
        markers = [name for name in names if os.path.basename(name).startswith(WHITEOUT)]
        apply_deletions(root, markers, verified)
        for path in [path for path in skipped if hidden_by(markers, path)]:
            del skipped[path]
        directories: list[tuple[str, tarfile.TarInfo]] = []
        for member in members:
            path = clean_name(member.name)
            if os.path.basename(path).startswith(WHITEOUT):
                continue
            checked_parent(root, path, verified)
            full = os.path.join(root, path)
            skipped.pop(path, None)
            if member.isdir():
                if not os.path.isdir(full) or os.path.islink(full):
                    remove_path(full)
                    os.mkdir(full, 0o700)
                directories.append((path, member))
                verified.discard(path)
                continue
            remove_path(full)
            if member.isreg():
                source = archive.extractfile(member)
                if source is None:
                    raise LayerError(f"/{path}: its content cannot be read")
                descriptor = os.open(full, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as target:
                    shutil.copyfileobj(source, target, 1 << 20)
            elif member.issym():
                os.symlink(member.linkname, full)
                verified.clear()  # it may stand where a checked directory was
            elif member.islnk():
                first = clean_name(member.linkname)
                checked_parent(root, first, verified)
                os.link(os.path.join(root, first), full, follow_symlinks=False)
                continue
            elif member.isfifo():
                os.mkfifo(full)
            elif member.ischr() or member.isblk():
                kind = stat.S_IFCHR if member.ischr() else stat.S_IFBLK
                try:
                    os.mknod(full, kind | (member.mode & 0o7777), os.makedev(member.devmajor, member.devminor))
                except PermissionError as error:
                    notes.append(f"/{path}: device {member.devmajor}:{member.devminor} not created ({error.strerror})")
                    skipped[path] = Entry(
                        "char" if member.ischr() else "block", member.mode & 0o7777, member.uid, member.gid,
                        int(member.mtime), major=member.devmajor, minor=member.devminor, absent=True,
                    )  # fmt: skip
                    continue
            else:
                raise LayerError(f"/{path}: a member type this program does not unpack ({member.type!r})")
            set_attributes(full, member, notes)
            set_time(full, member)
        # Directories last, deepest first: creating a child changes its parent's time, and a mode without
        # write permission would stop the children being created.
        for path, member in sorted(directories, key=lambda item: sort_key(item[0]), reverse=True):
            full = os.path.join(root, path)
            set_attributes(full, member, notes)
            set_time(full, member)


def unpack(root: str, layers: Sequence[str], epoch: int) -> tuple[dict[str, Entry], list[str]]:
    skipped: dict[str, Entry] = {}
    notes: list[str] = []
    verified: set[str] = set()
    before = os.umask(0)  # modes are set explicitly, exactly as the layer says
    try:
        for layer in layers:
            unpack_layer(root, layer, skipped, notes, verified)
    finally:
        os.umask(before)
    entries = scan(root, epoch).entries
    for path, entry in skipped.items():
        if path not in entries:
            entries[path] = replace(entry, mtime=min(entry.mtime, epoch))
    return entries, notes


# ---- the new layer ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Change:
    path: str
    whiteout: bool


def changes(old: dict[str, Entry], new: dict[str, Entry]) -> list[Change]:
    """What the layer holds, in tar order: every new or different path, and a whiteout for each removed
    path whose parent still is a directory."""
    found = [Change(path, False) for path, one in new.items() if old.get(path) != one]
    gone = {path for path, one in old.items() if path not in new and not one.absent}
    for path in gone:
        parent = path.rpartition("/")[0]
        if parent in gone:
            continue  # its directory is removed as a whole
        if parent and (parent not in new or new[parent].kind != "dir"):
            continue  # the parent became something else: that entry replaces everything below it
        found.append(Change(path, True))
    return sorted(found, key=lambda one: (sort_key(one.path), one.whiteout))


def member_for(path: str, one: Entry) -> tarfile.TarInfo:
    info = tarfile.TarInfo(path)
    info.uid, info.gid, info.uname, info.gname = one.uid, one.gid, "", ""
    info.mode, info.mtime = one.mode, one.mtime
    if one.kind == "dir":
        info.type = tarfile.DIRTYPE
    elif one.kind == "file":
        info.type, info.size = tarfile.REGTYPE, one.size
    elif one.kind == "symlink":
        info.type, info.linkname = tarfile.SYMTYPE, one.link
    elif one.kind == "fifo":
        info.type = tarfile.FIFOTYPE
    else:
        info.type = tarfile.CHRTYPE if one.kind == "char" else tarfile.BLKTYPE
        info.devmajor, info.devminor = one.major, one.minor
    info.pax_headers = {
        XATTR_PREFIX + name: bytes.fromhex(value).decode("utf-8", "surrogateescape") for name, value in one.xattrs
    }
    return info


def write_tar(root: str, found: Sequence[Change], new: Scan, epoch: int, target: str) -> None:
    first_of: dict[tuple[int, int], str] = {}
    with tarfile.open(target, mode="w", format=tarfile.PAX_FORMAT, encoding="utf-8") as archive:
        for change in found:
            if change.whiteout:
                directory, _, base = change.path.rpartition("/")
                info = tarfile.TarInfo(f"{directory}/{WHITEOUT}{base}" if directory else f"{WHITEOUT}{base}")
                info.mode, info.mtime, info.uid, info.gid, info.uname, info.gname = 0o644, epoch, 0, 0, "", ""
                archive.addfile(info)
                continue
            one = new.entries[change.path]
            info = member_for(change.path, one)
            shared = new.links.get(change.path)
            if one.kind == "file" and shared is not None and shared in first_of:
                info.type, info.linkname, info.size = tarfile.LNKTYPE, first_of[shared], 0
                archive.addfile(info)
            elif one.kind == "file":
                if shared is not None:
                    first_of[shared] = change.path
                with open(os.path.join(root, change.path), "rb") as handle:
                    archive.addfile(info, handle)
            else:
                archive.addfile(info)


def gzip_file(source: str, target: str) -> None:
    """gzip, level 9, with no file name and a zero time stamp in the header: the same tar, the same bytes."""
    with (
        open(source, "rb") as reader,
        open(target, "wb") as raw,
        gzip.GzipFile(filename="", mode="wb", compresslevel=9, mtime=0, fileobj=raw) as writer,
    ):
        shutil.copyfileobj(reader, writer, 1 << 20)


def with_absent(new: Scan, state: dict[str, Entry]) -> Scan:
    """`new` plus the state's absent device nodes that are still not on the disk and whose directory still
    is one: what the root holds, as a full tarball writes it."""
    entries = dict(new.entries)
    for path, one in state.items():
        if not one.absent or path in entries:
            continue
        parent = path.rpartition("/")[0]
        holder = entries.get(parent)
        if not parent or (holder is not None and holder.kind == "dir"):
            entries[path] = one
    return Scan(entries, new.links)


def pack(
    root: str, state: str, epoch: int, out: str, diff_id: str | None, status_out: str | None, *, full: bool = False
) -> int:
    """Write the layer; returns the number of entries in it (nothing is written when there are none).
    `full` writes every path of the root (an empty parent state), the state's absent devices included."""
    old = read_state(state)
    new = scan(root, epoch)
    if full:
        new, old = with_absent(new, old), {}
    found = changes(old, new.entries)
    if status_out is not None:
        shutil.copyfile(os.path.join(root, "var/lib/dpkg/status"), status_out)
    if not found:
        return 0
    plain = out + ".tar"
    write_tar(root, found, new, epoch, plain)
    if diff_id is not None:
        with open(diff_id, "w", encoding="ascii") as handle:
            handle.write(sha256_of(plain) + "\n")
    gzip_file(plain, out)
    os.unlink(plain)
    return len(found)


# ---- the command line ---------------------------------------------------------------------------


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="layer.py")
    commands = parser.add_subparsers(dest="command", required=True)
    unpacking = commands.add_parser("unpack")
    unpacking.add_argument("--root", required=True)
    unpacking.add_argument("--state", required=True)
    unpacking.add_argument("--epoch", type=int, required=True)
    unpacking.add_argument("layers", nargs="*")
    packing = commands.add_parser("pack")
    packing.add_argument("--root", required=True)
    packing.add_argument("--state", required=True)
    packing.add_argument("--epoch", type=int, required=True)
    packing.add_argument("--out", required=True)
    packing.add_argument("--diff-id")
    packing.add_argument("--status-out")
    packing.add_argument("--full", action="store_true", help="every path of the root, not the change")
    arguments = parser.parse_args(list(argv))
    try:
        if arguments.command == "unpack":
            entries, notes = unpack(arguments.root, arguments.layers, arguments.epoch)
            with open(arguments.state, "w", encoding="utf-8") as handle:
                handle.write(state_json(entries))
            for note in notes:
                print(f"note: {note}")
            print(f"unpacked {len(arguments.layers)} layers, {len(entries)} paths")
        else:
            count = pack(
                arguments.root,
                arguments.state,
                arguments.epoch,
                arguments.out,
                arguments.diff_id,
                arguments.status_out,
                full=arguments.full,
            )
            if arguments.full:
                print(f"root of {count} entries")
            else:
                print(f"layer of {count} entries" if count else "no layer: nothing changed")
    except (LayerError, OSError, tarfile.TarError) as error:
        print(f"layer.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
