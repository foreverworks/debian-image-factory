"""The `builtin:node-tarball` module's pure parts (DESIGN 6.4): its table, and which of its lock entries is the
release. No files, no network.

An image that uses the module has exactly one release tarball among the module's entries, told by its rendered
url ending in `.tar.xz` or `.tar.gz`. The entry must carry `signed_by` and `sums_url` (input-lock's trust
fields): `fetch` verifies Node's signed `SHASUMS256.txt.asc` through them, as it does for any entry that has them.
"""

import posixpath
import re
from collections.abc import Mapping
from typing import Final
from urllib.parse import urlsplit

MODULE: Final = "builtin:node-tarball"
"""The `use` value of the module."""

KEYS: Final = frozenset(("use", "enabled_by", "prefix"))
"""What a node-tarball module's table may hold."""

DEFAULT_PREFIX: Final = "/usr/local"

TARBALL_SUFFIXES: Final = (".tar.xz", ".tar.gz")

PREFIX_PART: Final = re.compile(r"[A-Za-z0-9._+-]+")
"""A prefix is written into a shell line and a path inside the image: its parts are plain."""


# ---- the module's table ---------------------------------------------------------------------


def prefix_of(table: Mapping[str, object]) -> str:
    """The install prefix a (validated) module table names, `/usr/local` when it names none."""
    prefix = table.get("prefix", DEFAULT_PREFIX)
    return prefix if isinstance(prefix, str) else DEFAULT_PREFIX


def prefix_problem(value: object) -> str | None:
    """What is wrong with a `prefix` value: an absolute, normalised path of plain parts, not `/` itself."""
    if not isinstance(value, str):
        return "must be a string"
    if not value.startswith("/") or posixpath.normpath(value) != value or value == "/":
        return "must be an absolute normalised path below /, such as /usr/local or /opt/node"
    if not all(PREFIX_PART.fullmatch(part) and part not in (".", "..") for part in value.split("/")[1:]):
        return "may hold only letters, digits and . _ + - in each part"
    return None


def table_problems(table: Mapping[str, object]) -> list[str]:
    """Every problem of a node-tarball module's table, as `key: reason` (the caller prefixes the module)."""
    found = [f"unknown key {key!r}: this module takes {sorted(KEYS - {'use'})}" for key in sorted(set(table) - KEYS)]
    if "prefix" in table:
        problem = prefix_problem(table["prefix"])
        if problem is not None:
            found.append(f"prefix {problem}")
    return found


# ---- the release tarball ------------------------------------------------------------------------


def is_tarball(url: str) -> bool:
    """A rendered url naming a release tarball."""
    return urlsplit(url).path.endswith(TARBALL_SUFFIXES)


def tarball_problems(urls: Mapping[str, str], signed: Mapping[str, bool]) -> list[str]:
    """What is wrong with one image's node-tarball entries (entry name to rendered url): not exactly one
    release tarball, or a tarball without `signed_by` and `sums_url` (`signed` says which entries have both)."""
    tarballs = sorted(name for name, url in urls.items() if is_tarball(url))
    if len(tarballs) != 1:
        return [f"needs exactly one release tarball (url ending {list(TARBALL_SUFFIXES)}), found {tarballs}"]
    if not signed.get(tarballs[0], False):
        return [
            f"entry {tarballs[0]} needs signed_by (the release keyring entry) and sums_url "
            "(the signed SHASUMS256.txt.asc), so that fetch verifies the release against Node's signature"
        ]
    return []
