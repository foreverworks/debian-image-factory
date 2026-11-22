"""Unpack a nodejs.org release tarball into an image root: the `builtin:node-tarball` module's install step.

    python3 node_install.py ROOT TARBALL PREFIX SOURCE_DATE_EPOCH

This file is copied into the build's work directory and run by the builder's python3, so it uses the
standard library only and imports nothing from the factory. The builder has no `xz-utils` and the image
has no python: `tarfile` reads the `.tar.xz` here, outside the chroot.

What it does (DESIGN 6.4):

- the tarball's top directory (`node-v26.13.1-linux-x64/`) is stripped and the rest goes below
  `ROOT/PREFIX`; the top-level `CHANGELOG.md` and `README.md` are skipped, `LICENSE` is kept;
- a member name that is absolute, holds `..`, or is empty is refused, as is anything but a regular file,
  directory, symlink or hard link; a link whose target is not inside PREFIX is refused;
- everything is owned by root:root (when run as root) with the tarball's permission bits and no
  setuid, setgid or sticky bit; every modification time is the older of the member's and SOURCE_DATE_EPOCH;
  a directory that exists already keeps its mode, and every directory this changes gets its time back,
  so the bytes depend on the inputs alone;
- a path below ROOT that is a symlink is never followed: the build must not write outside the image;
- when PREFIX is not `/usr/local`, `/usr/local/bin/{node,npm,npx}` link to `PREFIX/bin/<name>`.
"""

import os
import posixpath
import shutil
import sys
import tarfile
from collections.abc import Sequence
from pathlib import Path
from typing import Final

SKIPPED: Final = frozenset(("CHANGELOG.md", "README.md"))
"""Top-level files of the tarball that are not part of what runs."""

LINKED: Final = ("node", "npm", "npx")
LINK_DIR: Final = "/usr/local/bin"
DEFAULT_PREFIX: Final = "/usr/local"
CHUNK: Final = 1 << 20


class InstallError(Exception):
    """The tarball or the target is not one this step will write."""


def stripped(name: str) -> tuple[str, ...]:
    """A member's path below the top directory, as parts; () for the top directory itself.

    Raises InstallError for an absolute name, a `..` part or an empty one."""
    if name.startswith("/"):
        raise InstallError(f"{name}: absolute member name")
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise InstallError(f"{name}: member name goes up with ..")
    if not parts:
        raise InstallError(f"{name!r}: empty member name")
    return tuple(parts[1:])


def inside(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def link_target_problem(parts: tuple[str, ...], target: str, prefix: str) -> str | None:
    """Why a symlink at `parts` (below the prefix) may not point at `target`; None when it may."""
    if target == "":
        return "empty link target"
    here = posixpath.join(prefix, *parts[:-1])
    resolved = posixpath.normpath(target if target.startswith("/") else posixpath.join(here, target))
    if not inside(resolved, prefix):
        return f"link target {target!r} leaves {prefix}"
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


def install(root: Path, tarball: Path, prefix: str, epoch: int) -> int:
    """Unpack `tarball` into `root`/`prefix`, then add the links; returns how many members were written."""
    stamps: dict[Path, int] = {}
    modes: dict[Path, int] = {}
    base = prefix.lstrip("/")
    written = 0
    make_dir(root, base, stamps, epoch)
    with tarfile.open(tarball, mode="r:*") as archive:
        for member in archive:
            parts = stripped(member.name)
            if not parts or (len(parts) == 1 and member.isfile() and parts[0] in SKIPPED):
                continue
            relative = f"{base}/{'/'.join(parts)}"
            target = root / relative
            mtime = min(max(int(member.mtime), 0), epoch)
            if member.isdir():
                made = not (root / relative).exists()
                make_dir(root, relative, stamps, epoch)
                stamps[target] = mtime
                if made:
                    modes[target] = member.mode & 0o777
            else:
                make_dir(root, relative.rsplit("/", 1)[0], stamps, epoch)
                replace_target(target)
                if member.isreg():
                    source = archive.extractfile(member)
                    if source is None:
                        raise InstallError(f"{member.name}: cannot be read")
                    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with source, os.fdopen(descriptor, "wb") as handle:
                        shutil.copyfileobj(source, handle, CHUNK)
                    own(target)
                    target.chmod(member.mode & 0o777)
                elif member.issym():
                    problem = link_target_problem(parts, member.linkname, prefix)
                    if problem is not None:
                        raise InstallError(f"{member.name}: {problem}")
                    os.symlink(member.linkname, target)
                    own(target)
                elif member.islnk():
                    linked = stripped(member.linkname)
                    if not linked:
                        raise InstallError(f"{member.name}: hard link to the top directory")
                    os.link(root / base / "/".join(linked), target, follow_symlinks=False)
                else:
                    raise InstallError(f"{member.name}: only files, directories and links are installed")
                os.utime(target, (mtime, mtime), follow_symlinks=False)
            written += 1
    if prefix != DEFAULT_PREFIX:
        link_dir = make_dir(root, LINK_DIR.lstrip("/"), stamps, epoch)
        for name in LINKED:
            link = link_dir / name
            replace_target(link)
            os.symlink(f"{prefix}/bin/{name}", link)
            own(link)
            os.utime(link, (epoch, epoch), follow_symlinks=False)
    for path, mode in modes.items():
        path.chmod(mode)
    for path in sorted(stamps, key=lambda item: len(item.parts), reverse=True):
        os.utime(path, (stamps[path], stamps[path]), follow_symlinks=False)
    return written


def main(argv: Sequence[str]) -> int:
    if len(argv) != 4 or not argv[3].isdigit():
        print("usage: node_install.py ROOT TARBALL PREFIX SOURCE_DATE_EPOCH", file=sys.stderr)
        return 2
    root, tarball, prefix, epoch = Path(argv[0]), Path(argv[1]), argv[2], int(argv[3])
    if not (prefix.startswith("/") and posixpath.normpath(prefix) == prefix and prefix != "/"):
        print(f"node_install: prefix {prefix!r} is not an absolute normalised path", file=sys.stderr)
        return 2
    try:
        count = install(root, tarball, prefix, epoch)
    except (InstallError, tarfile.TarError, OSError, EOFError) as error:
        print(f"node_install: {error}", file=sys.stderr)
        return 1
    print(f"node_install: {count} members into {prefix}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
