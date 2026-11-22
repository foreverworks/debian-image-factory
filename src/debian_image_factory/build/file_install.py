"""Place a locked download in an image root: the `builtin:file` module's install step.

    python3 file_install.py ROOT SOURCE PATH SOURCE_DATE_EPOCH --mode MODE
    python3 file_install.py ROOT SOURCE PATH SOURCE_DATE_EPOCH --unpack STRIP_COMPONENTS

This file is copied into the build's work directory and run by the builder's python3, so it uses the
standard library only and imports nothing from the factory (like node_install.py). `tarfile` reads a
`.tar`, `.tar.gz` or `.tar.xz` here, outside the chroot: the image may have no tar, gzip or xz.

What it does (DESIGN 6.4):

- `--mode`: SOURCE is copied to ROOT/PATH with MODE (octal, no setuid, setgid or sticky bit), replacing a
  file or link that is there;
- `--unpack`: SOURCE is a tarball unpacked into the directory ROOT/PATH with STRIP_COMPONENTS leading parts of
  every member name dropped (a member left with no name is skipped). A member name that is absolute, holds
  `..`, or is empty is refused, as is anything but a regular file, directory, symlink or hard link (so no
  device or fifo); a link whose target is not inside PATH is refused;
- either way: every missing parent directory is created 0755; everything written is owned by root:root (when
  run as root) with the member's permission bits and no setuid, setgid or sticky bit; every modification time
  is the older of the member's and SOURCE_DATE_EPOCH (a placed file's is SOURCE_DATE_EPOCH); a directory that
  exists already keeps its mode, and every directory this changes gets its time back, so the bytes depend on
  the inputs alone;
- a path below ROOT that is a symlink is never followed: the build must not write outside the image.
"""

import os
import posixpath
import shutil
import sys
import tarfile
from collections.abc import Sequence
from pathlib import Path
from typing import IO, Final

CHUNK: Final = 1 << 20
PERMISSIONS: Final = 0o777
"""The bits kept of a member's mode: never setuid, setgid or sticky."""


class InstallError(Exception):
    """The download or the target is not one this step will write."""


def member_parts(name: str, strip: int) -> tuple[str, ...]:
    """A member's path below the directory, as parts, with `strip` leading parts dropped; () when none is left.

    Raises InstallError for an absolute name, a `..` part or an empty one."""
    if name.startswith("/"):
        raise InstallError(f"{name}: absolute member name")
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise InstallError(f"{name}: member name goes up with ..")
    if not parts:
        raise InstallError(f"{name!r}: empty member name")
    return tuple(parts[strip:])


def inside(path: str, directory: str) -> bool:
    return path == directory or path.startswith(directory.rstrip("/") + "/")


def link_target_problem(parts: tuple[str, ...], target: str, directory: str) -> str | None:
    """Why a symlink at `parts` (below the directory) may not point at `target`; None when it may."""
    if target == "":
        return "empty link target"
    here = posixpath.join(directory, *parts[:-1])
    resolved = posixpath.normpath(target if target.startswith("/") else posixpath.join(here, target))
    if not inside(resolved, directory):
        return f"link target {target!r} leaves {directory}"
    return None


def check_writable(root: Path, relative: str) -> None:
    """Every existing component of `relative` below `root` is a real directory: no symlink is followed."""
    current = root
    for part in relative.split("/"):
        if not part:
            continue
        current = current / part
        if current.is_symlink():
            raise InstallError(f"/{relative}: {part} is a symlink in the image, which is never followed")
        if not current.exists():
            return
        if not current.is_dir():
            raise InstallError(f"/{relative}: {part} is not a directory")


def own(path: Path) -> None:
    """root:root, when this runs as root (the builder's user; an ordinary user cannot give files away)."""
    if os.geteuid() == 0:
        os.lchown(path, 0, 0)


def make_dir(root: Path, relative: str, stamps: dict[Path, int], epoch: int) -> Path:
    """`relative` below `root` as a directory, with every missing level created (0755, root, epoch).

    A directory that exists is recorded so its time is put back after the build changes it."""
    check_writable(root, relative)
    current = root
    for part in relative.split("/"):
        if not part:
            continue
        current = current / part
        if not current.exists():
            current.mkdir()
            current.chmod(0o755)
            own(current)
            stamps[current] = epoch
        elif current not in stamps:
            stamps[current] = min(int(current.lstat().st_mtime), epoch)
    return current


def replace_target(path: Path) -> None:
    """Make room for a file or link at `path`: whatever is there, except a directory, goes."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        raise InstallError(f"{path}: a directory is in the way")


def write_file(target: Path, source: IO[bytes], mode: int) -> None:
    """`source` (a binary file object) at `target`, a new file never reached through a symlink."""
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        shutil.copyfileobj(source, handle, CHUNK)
    own(target)
    target.chmod(mode & PERMISSIONS)


def restore(stamps: dict[Path, int], modes: dict[Path, int]) -> None:
    for path, mode in modes.items():
        path.chmod(mode)
    for path in sorted(stamps, key=lambda item: len(item.parts), reverse=True):
        os.utime(path, (stamps[path], stamps[path]), follow_symlinks=False)


def place(root: Path, source: Path, path: str, epoch: int, mode: int) -> int:
    """Copy `source` to `root`/`path` with `mode`; returns 1, the files written."""
    stamps: dict[Path, int] = {}
    relative = path.lstrip("/")
    parent, _, name = relative.rpartition("/")
    if not name:
        raise InstallError(f"{path}: not a file path")
    make_dir(root, parent, stamps, epoch)
    target = root / relative
    replace_target(target)
    with source.open("rb") as handle:
        write_file(target, handle, mode)
    os.utime(target, (epoch, epoch), follow_symlinks=False)
    restore(stamps, {})
    return 1


def unpack(root: Path, tarball: Path, path: str, epoch: int, strip: int) -> int:
    """Unpack `tarball` into the directory `root`/`path`; returns how many members were written."""
    stamps: dict[Path, int] = {}
    modes: dict[Path, int] = {}
    base = path.lstrip("/")
    written = 0
    make_dir(root, base, stamps, epoch)
    with tarfile.open(tarball, mode="r:*") as archive:
        for member in archive:
            parts = member_parts(member.name, strip)
            if not parts:
                continue
            relative = f"{base}/{'/'.join(parts)}"
            target = root / relative
            mtime = min(max(int(member.mtime), 0), epoch)
            if member.isdir():
                made = not target.exists()
                make_dir(root, relative, stamps, epoch)
                stamps[target] = mtime
                if made:
                    modes[target] = member.mode & PERMISSIONS
                written += 1
                continue
            make_dir(root, relative.rsplit("/", 1)[0], stamps, epoch)
            replace_target(target)
            if member.isreg():
                source = archive.extractfile(member)
                if source is None:
                    raise InstallError(f"{member.name}: cannot be read")
                with source:
                    write_file(target, source, member.mode)
            elif member.issym():
                problem = link_target_problem(parts, member.linkname, path)
                if problem is not None:
                    raise InstallError(f"{member.name}: {problem}")
                os.symlink(member.linkname, target)
                own(target)
            elif member.islnk():
                linked = member_parts(member.linkname, strip)
                if not linked:
                    raise InstallError(f"{member.name}: hard link to a member that is stripped away")
                os.link(root / base / "/".join(linked), target, follow_symlinks=False)
                written += 1
                continue  # the same inode as its target, whose time is already set
            else:
                raise InstallError(f"{member.name}: only files, directories and links are unpacked")
            os.utime(target, (mtime, mtime), follow_symlinks=False)
            written += 1
    restore(stamps, modes)
    return written


def usage() -> int:
    print(
        "usage: file_install.py ROOT SOURCE PATH SOURCE_DATE_EPOCH (--mode MODE | --unpack STRIP_COMPONENTS)",
        file=sys.stderr,
    )
    return 2


def main(argv: Sequence[str]) -> int:
    if len(argv) != 6 or not argv[3].isdigit() or argv[4] not in ("--mode", "--unpack"):
        return usage()
    root, source, path, epoch, how, value = Path(argv[0]), Path(argv[1]), argv[2], int(argv[3]), argv[4], argv[5]
    if not (path.startswith("/") and posixpath.normpath(path) == path and path != "/"):
        print(f"file_install: path {path!r} is not an absolute normalised path", file=sys.stderr)
        return 2
    try:
        if how == "--mode":
            if not (len(value) == 4 and value.startswith("0") and all(c in "01234567" for c in value)):
                print(f"file_install: mode {value!r} is not an octal string such as 0644", file=sys.stderr)
                return 2
            count = place(root, source, path, epoch, int(value, 8))
        else:
            if not value.isdigit():
                return usage()
            count = unpack(root, source, path, epoch, int(value))
    except (InstallError, tarfile.TarError, OSError, EOFError) as error:
        print(f"file_install: {error}", file=sys.stderr)
        return 1
    print(f"file_install: {count} {'member' if how == '--unpack' else 'file'}s into {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
