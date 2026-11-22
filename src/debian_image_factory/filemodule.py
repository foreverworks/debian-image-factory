"""The `builtin:file` module's pure parts (DESIGN 6.4): its table, and which of its lock entries an image places.
No files, no network.

A file module places one locked download at the absolute `path` its table names: copied there with `mode`
(`0644` by default), or, with `unpack = true`, a `.tar`, `.tar.gz` or `.tar.xz` unpacked into the directory
`path`, with `strip_components` leading parts of every member name dropped. An image that uses the module has
exactly one of its entries to place; a keyring the entry's `signed_by` names is a trust root and is not placed.
"""

import posixpath
import re
from collections.abc import Mapping
from typing import Final
from urllib.parse import urlsplit

MODULE: Final = "builtin:file"
"""The `use` value of the module."""

KEYS: Final = frozenset(("use", "enabled_by", "path", "mode", "unpack", "strip_components"))
"""What a file module's table may hold."""

DEFAULT_MODE: Final = "0644"

MODE: Final = re.compile(r"0[0-7]{3}")
"""A file's mode: four octal digits with no setuid, setgid or sticky bit."""

UNPACK_SUFFIXES: Final = (".tar", ".tar.gz", ".tar.xz")
"""What `unpack` reads, told by the rendered url."""

PATH_PART: Final = re.compile(r"[A-Za-z0-9._+-]+")
"""A path is written into a shell line and a path inside the image: its parts are plain."""


# ---- the module's table ---------------------------------------------------------------------


def path_problem(value: object) -> str | None:
    """What is wrong with a `path` value: an absolute, normalised path of plain parts, not `/` itself."""
    if not isinstance(value, str):
        return "must be a string"
    if not value.startswith("/") or posixpath.normpath(value) != value or value == "/":
        return "must be an absolute normalised path below /, such as /usr/local/bin/tool or /opt/tool"
    if not all(PATH_PART.fullmatch(part) and part not in (".", "..") for part in value.split("/")[1:]):
        return "may hold only letters, digits and . _ + - in each part"
    return None


def table_problems(table: Mapping[str, object]) -> list[str]:
    """Every problem of a file module's table, as `key: reason` (the caller prefixes the module)."""
    found = [f"unknown key {key!r}: this module takes {sorted(KEYS - {'use'})}" for key in sorted(set(table) - KEYS)]
    if "path" not in table:
        found.append("path is required: where the file goes in the image (or the directory it unpacks into)")
    else:
        problem = path_problem(table["path"])
        if problem is not None:
            found.append(f"path {problem}")
    unpack = table.get("unpack", False)
    if not isinstance(unpack, bool):
        found.append("unpack must be true or false")
        unpack = False
    if "mode" in table:
        mode = table["mode"]
        if unpack:
            found.append("mode is for a file placed as it is: an unpacked tarball keeps its members' modes")
        elif not (isinstance(mode, str) and MODE.fullmatch(mode)):
            found.append('mode must be an octal string such as "0644" or "0755" (no setuid, setgid or sticky bit)')
    if "strip_components" in table:
        strip = table["strip_components"]
        if not unpack:
            found.append("strip_components needs unpack = true")
        elif not (isinstance(strip, int) and not isinstance(strip, bool) and strip >= 0):
            found.append("strip_components must be a whole number, 0 or more")
    return found


def path_of(table: Mapping[str, object]) -> str:
    path = table.get("path")
    return path if isinstance(path, str) else ""


def mode_of(table: Mapping[str, object]) -> str:
    mode = table.get("mode", DEFAULT_MODE)
    return mode if isinstance(mode, str) else DEFAULT_MODE


def unpacks(table: Mapping[str, object]) -> bool:
    return table.get("unpack") is True


def strip_of(table: Mapping[str, object]) -> int:
    strip = table.get("strip_components", 0)
    return strip if isinstance(strip, int) and not isinstance(strip, bool) else 0


# ---- the entry it places ------------------------------------------------------------------------


def is_archive(url: str) -> bool:
    """A rendered url naming a tarball `unpack` reads."""
    return urlsplit(url).path.endswith(UNPACK_SUFFIXES)


def placed_problems(urls: Mapping[str, str], unpack: bool) -> list[str]:
    """What is wrong with one image's entries of a file module (entry name to rendered url, keyrings left out):
    not exactly one, or, with `unpack`, one whose url is not a tarball it reads."""
    if len(urls) != 1:
        return [f"places exactly one lock entry per image, found {sorted(urls)}"]
    ((name, url),) = urls.items()
    if unpack and not is_archive(url):
        return [f"entry {name} is unpacked, so its url must end in one of {list(UNPACK_SUFFIXES)}"]
    return []
