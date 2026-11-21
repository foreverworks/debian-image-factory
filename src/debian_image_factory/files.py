"""The file edge: reading the hooks, module scripts and file trees a definition references.

Modes are normalised to what git keeps, executable or not (`0755` or `0644`, directories `0755`),
so a checkout's umask never changes an identity. A file that needs another mode or an owner gets it
from a hook.
"""

import hashlib
import stat
from pathlib import Path

from .definition import Definition
from .identity import FileFact


def mode_of(info: int) -> str:
    if stat.S_ISDIR(info):
        return "0755"
    return "0755" if info & 0o111 else "0644"


def fact(path: Path, script: bool) -> FileFact:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return FileFact(None, "0777", link=str(path.readlink()))
    if stat.S_ISDIR(info.st_mode):
        return FileFact(None, mode_of(info.st_mode), directory=True)
    content = path.read_bytes()
    return FileFact(
        hashlib.sha256(content).hexdigest(),
        mode_of(info.st_mode),
        text=content.decode("utf-8", errors="replace") if script else "",
    )


def read_files(root: Path, definition: Definition) -> tuple[dict[str, FileFact], list[str]]:
    """Every file the definition references, relative to its directory, and the problems found
    (a missing file, a hook that is not a regular file, a file tree that is not a directory)."""
    found: dict[str, FileFact] = {}
    problems: list[str] = []
    scripts = {module.use for module in definition.modules.values() if not module.use.startswith("builtin:")}
    for image in definition.images.values():
        scripts.update(image.hooks)
    for relative in sorted(scripts):
        path = root / relative
        if not path.is_file() or path.is_symlink():
            problems.append(f"{relative}: a hook or module script must be a regular file")
            continue
        found[relative] = fact(path, script=True)
    trees = sorted({image.files for image in definition.images.values() if image.files is not None})
    for relative in trees:
        top = root / relative
        if not top.is_dir() or top.is_symlink():
            problems.append(f"{relative}: a file tree must be a directory")
            continue
        found[relative] = fact(top, script=False)
        for path in sorted(top.rglob("*")):
            found[path.relative_to(root).as_posix()] = fact(path, script=False)
    return found, problems
