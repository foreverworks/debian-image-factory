"""Debian's text formats, pure: deb822 paragraphs, Release files, Packages stanzas.

Nothing here reads a file or the network. The archive edge (`archive.py`) feeds it text it has already
verified.
"""

import re
from dataclasses import dataclass
from typing import Final

_SHA256: Final = re.compile(r"[0-9a-f]{64}")
_FIELD_NAME: Final = re.compile(r"[^\s:#][^\s:]*")


def parse_deb822(text: str) -> list[dict[str, str]]:
    """The paragraphs of a deb822 document, each a mapping of field name to value.

    Field names keep their case. A value is the text after the colon on the first line, stripped,
    followed by every continuation line verbatim (leading whitespace kept), each preceded by a newline.
    Comment lines (starting with `#`) are skipped and blank lines end a paragraph. A field repeated in
    one paragraph (compared without case, as Debian does) raises ValueError, as does a line that is
    neither a field, a continuation nor a comment.
    """
    paragraphs: list[dict[str, str]] = []
    current: dict[str, str] = {}
    seen: set[str] = set()
    last: str | None = None
    for number, line in enumerate(text.split("\n"), start=1):
        if line.strip() == "":
            if current:
                paragraphs.append(current)
            current, seen, last = {}, set(), None
        elif line.startswith("#"):
            continue
        elif line[0] in " \t":
            if last is None:
                raise ValueError(f"line {number}: continuation line without a field: {line!r}")
            current[last] += "\n" + line
        else:
            name, colon, value = line.partition(":")
            if not colon or not _FIELD_NAME.fullmatch(name):
                raise ValueError(f"line {number}: not a field: {line!r}")
            if name.lower() in seen:
                raise ValueError(f"line {number}: field {name!r} repeated in one paragraph")
            seen.add(name.lower())
            current[name] = value.strip()
            last = name
    if current:
        paragraphs.append(current)
    return paragraphs


def field(paragraph: dict[str, str], name: str) -> str | None:
    """The value of field `name`, compared without case, or None."""
    for key, value in paragraph.items():
        if key.lower() == name.lower():
            return value
    return None


def release_paragraph(release_text: str) -> dict[str, str]:
    """The one paragraph of a Release file. ValueError unless the text holds exactly one."""
    paragraphs = parse_deb822(release_text)
    if len(paragraphs) != 1:
        raise ValueError(f"a Release file holds one paragraph, this one holds {len(paragraphs)}")
    return paragraphs[0]


def release_files(release_text: str) -> dict[str, tuple[str, int]]:
    """Path (relative to the dist directory) -> (sha256, size) from the SHA256 field of a Release file."""
    value = field(release_paragraph(release_text), "SHA256")
    if value is None:
        raise ValueError("the Release file has no SHA256 field")
    files: dict[str, tuple[str, int]] = {}
    for line in value.split("\n"):
        if line.strip() == "":
            continue
        parts = line.split()
        if len(parts) != 3 or not _SHA256.fullmatch(parts[0]) or not parts[1].isascii() or not parts[1].isdigit():
            raise ValueError(f"bad SHA256 line in Release: {line!r}")
        if parts[2] in files:
            raise ValueError(f"Release lists {parts[2]!r} twice")
        files[parts[2]] = (parts[0], int(parts[1]))
    return files


def acquire_by_hash(release_text: str) -> bool:
    """Whether the Release file says `Acquire-By-Hash: yes`."""
    value = field(release_paragraph(release_text), "Acquire-By-Hash")
    return value is not None and value.lower() == "yes"


def by_hash_path(dist_path: str, path: str, sha256: str) -> str:
    """Where an archive serves a file listed in Release by its hash.

    `dist_path` is the dist directory (`dists/trixie`), `path` the file's path in Release
    (`main/binary-amd64/Packages.xz`). The result is `dists/trixie/main/binary-amd64/by-hash/SHA256/<hex>`.
    """
    if not _SHA256.fullmatch(sha256):
        raise ValueError(f"not a sha256: {sha256!r}")
    directory, slash, _name = path.rpartition("/")
    prefix = f"{dist_path.rstrip('/')}/{directory}/" if slash else f"{dist_path.rstrip('/')}/"
    return f"{prefix}by-hash/SHA256/{sha256}"


def packages_stanzas(text: str) -> list[dict[str, str]]:
    """The stanzas of a Packages file (paragraphs, so a repeated field is an error)."""
    return parse_deb822(text)


def essential(stanzas: list[dict[str, str]], arch: str) -> list[str]:
    """Names of the `Essential: yes` packages built for `arch` or for all, in file order."""
    names: list[str] = []
    for stanza in stanzas:
        flag = field(stanza, "Essential")
        if flag is None or flag.lower() != "yes":
            continue
        package = field(stanza, "Package")
        if package is None:
            raise ValueError("a Packages stanza has no Package field")
        if field(stanza, "Architecture") in (arch, "all"):
            names.append(package)
    return names


def installed_packages(status_text: str) -> list[tuple[str, str, str]]:
    """(name, version, architecture) of every package a dpkg status file says is installed, sorted.

    Only paragraphs whose `Status` ends in `installed` (`install ok installed`, `hold ok installed`)
    count; config-files, half-installed and not-installed entries do not.
    """
    found: set[tuple[str, str, str]] = set()
    for paragraph in parse_deb822(status_text):
        status = field(paragraph, "Status")
        if status is None or status.split()[-1:] != ["installed"]:
            continue
        name, version, arch = field(paragraph, "Package"), field(paragraph, "Version"), field(paragraph, "Architecture")
        if not (name and version and arch):
            raise ValueError(f"a status paragraph lacks Package, Version or Architecture: {paragraph!r}")
        found.add((name, version, arch))
    return sorted(found)


@dataclass(frozen=True, slots=True)
class Suite:
    archive: str
    """The snapshot.debian.org archive: `debian` or `debian-security`."""
    dist: str


def suites(suite: str) -> tuple[Suite, ...]:
    """The suites a build snapshot covers: main, updates and security (DESIGN section 2, goal 1)."""
    return (Suite("debian", suite), Suite("debian", f"{suite}-updates"), Suite("debian-security", f"{suite}-security"))
