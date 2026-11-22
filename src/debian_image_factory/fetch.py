"""The `fetch` stage (DESIGN 5.3, 7.7): everything a plan names, downloaded, verified and laid out for the build.

`fetch plan.json` reads the plan alone. It re-reads the plan's snapshot indices (verified against the
archive keyring, as `plan` did), finds every package of every image in them, downloads each pool file
into the content-addressed cache checking its size and sha256 against the signed index, and lays out the
partial mirror (`mirror_dir`) the build reads through `file:` sources: the signed `InRelease` and indices
as `plan` laid them out, plus the pool files, hard-linked from the cache. Every locked input an image
installs is downloaded the same way, checked against the lock's checksums and stored in the cache by
sha256 (`input_path` says where).

A file that does not match is refused, naming its URL, and never tried from another source: a mirror or
cache is a performance layer, never an authority (7.7). Reads go through `Sources.read`, so tests and
`--mirror` use the same code as snapshot.debian.org.
"""

import filecmp
import hashlib
import os
import re
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, TextIO

from input_lock import Package, Value

from . import archive, debian, resolve
from .commands import Failed, Sources, Usage
from .planfile import Plan, read_plan

CHECKSUMS: Final = (("sha256", 64, hashlib.sha256), ("sha512", 128, hashlib.sha512), ("sha1", 40, hashlib.sha1))
"""Field name, hex length and constructor of the checksums a locked input may carry."""


@dataclass(frozen=True, slots=True)
class LockedInput:
    """One locked input as the plan carries it: where it is read and what it must hash to."""

    name: str
    url: str
    sha256: str
    checksums: tuple[tuple[str, str], ...]
    """(algorithm, hex digest) for every checksum the entry carries, sha256 first."""


@dataclass(frozen=True, slots=True)
class FetchPlan:
    """What `fetch` reads of a plan.json: the snapshot, where to look, and everything to fetch."""

    snapshot: str
    suite: str
    components: tuple[str, ...]
    architecture: str
    packages: tuple[Package, ...]
    """The union of every image's resolved set, sorted."""
    inputs: tuple[LockedInput, ...]
    """Every locked input of every image, once each, sorted."""


@dataclass(frozen=True, slots=True)
class PoolFile:
    """One package's file as the signed indices describe it."""

    sha256: str
    size: int
    locations: tuple[tuple[str, str, str], ...]
    """(archive name, archive base URL, Filename), sorted: where the file is, and where the mirror lays it."""


# ---- reading plan.json --------------------------------------------------------------------------


def locked_input(image: str, name: str, fields: Mapping[str, Value]) -> LockedInput:
    """One image's locked input, checked for what fetch needs of it; Failed naming the field."""
    where = f"images.{image}.inputs.{name}"
    url = fields.get("url")
    if not isinstance(url, str) or not url:
        raise Failed(f"plan: {where}.url is missing: nothing says where to read it")
    if not url.startswith("https://"):
        raise Failed(f"plan: {where}.url must be an https:// URL, not {url!r}")
    checksums: list[tuple[str, str]] = []
    for algorithm, length, _constructor in CHECKSUMS:
        if algorithm not in fields:
            continue
        digest = fields[algorithm]
        if not isinstance(digest, str) or not re.fullmatch(f"[0-9a-f]{{{length}}}", digest):
            raise Failed(f"plan: {where}.{algorithm} must be {length} lowercase hex digits")
        checksums.append((algorithm, digest))
    if not checksums or checksums[0][0] != "sha256":
        raise Failed(f"plan: {where}.sha256 is missing: `lock checksums` adds a sha256 to an entry that has none")
    return LockedInput(name, url, checksums[0][1], tuple(checksums))


def fetch_plan(plan: Plan) -> FetchPlan:
    """What fetch needs of a plan: the union of every image's packages and locked inputs."""
    packages: set[Package] = set()
    inputs: set[LockedInput] = set()
    for image, entry in sorted(plan["images"].items()):
        packages.update(entry["packages"])
        inputs.update(locked_input(image, name, fields) for name, fields in sorted(entry["inputs"].items()))
    debian_ = plan["debian"]
    return FetchPlan(
        plan["snapshot"],
        debian_["suite"],
        debian_["components"],
        debian_["architecture"],
        tuple(sorted(packages)),
        tuple(sorted(inputs, key=lambda item: (item.name, item.url, item.checksums))),
    )


# ---- finding packages in the signed indices -----------------------------------------------------


def _safe_filename(filename: str) -> bool:
    path = PurePosixPath(filename)
    return not path.is_absolute() and ".." not in path.parts and "." not in path.parts and bool(path.parts)


def pool_files(
    indices: Sequence[archive.SuiteIndex], wanted: Sequence[Package]
) -> tuple[dict[Package, PoolFile], list[str]]:
    """Where each wanted package's file is, and every problem: a package no index lists, a stanza without
    its file fields, two stanzas of one package that disagree on the sha256.

    Suites of one archive (`trixie` and `trixie-updates`) often list the same file; any listing will do.
    A package listed by both archives is laid out in both, so apt finds it wherever it chooses to read it.
    """
    wanted_set = set(wanted)
    found: dict[Package, tuple[str, int, set[tuple[str, str, str]]]] = {}
    problems: list[str] = []
    unusable: set[Package] = set()
    for index in indices:
        archive_ = archive.archive_name(index.base_url)
        for path, local in index.files:
            if not path.endswith("/Packages"):
                continue
            for stanza in debian.packages_stanzas(local.read_text(encoding="utf-8")):
                key = (stanza.get("Package", ""), stanza.get("Version", ""), stanza.get("Architecture", ""))
                if key not in wanted_set:
                    continue
                filename = stanza.get("Filename", "")
                sha256 = stanza.get("SHA256", "")
                size = stanza.get("Size", "")
                label = f"{key[0]} {key[1]} ({key[2]})"
                if not (_safe_filename(filename) and re.fullmatch("[0-9a-f]{64}", sha256) and size.isdigit()):
                    problems.append(f"{label}: the index of {index.dist} gives no usable Filename, Size and SHA256")
                    unusable.add(key)
                    continue
                earlier = found.get(key)
                if earlier is not None and earlier[0] != sha256:
                    problems.append(f"{label}: the indices disagree on its sha256 ({earlier[0]} and {sha256})")
                    continue
                locations = earlier[2] if earlier is not None else set()
                locations.add((archive_, index.base_url, filename))
                found[key] = (sha256, int(size), locations)
    problems.extend(
        f"{name} {version} ({arch}): not in the indices of any suite of the snapshot"
        for name, version, arch in wanted
        if (name, version, arch) not in found and (name, version, arch) not in unusable
    )
    return {key: PoolFile(sha, size, tuple(sorted(where))) for key, (sha, size, where) in found.items()}, problems


# ---- downloading ----------------------------------------------------------------------------------


def _digest(algorithm: str, data: bytes) -> str:
    return {name: constructor for name, _length, constructor in CHECKSUMS}[algorithm](data).hexdigest()


def download_pool_file(package: Package, pool: PoolFile, sources: Sources) -> bool:
    """Make sure the cache holds the package's file; True when it was downloaded, False when it was there.

    Raises Failed naming the URL when it cannot be read or is not the size and sha256 the index gives.
    """
    present = archive.cached(sources.cache, pool.sha256)
    if present is not None and present.stat().st_size == pool.size:
        return False
    _archive, base_url, filename = pool.locations[0]
    url = f"{base_url}/{filename}"
    try:
        data = sources.read(url)
    except (OSError, ValueError) as error:
        raise Failed(f"{url}: cannot be read: {error}") from None
    if len(data) != pool.size or hashlib.sha256(data).hexdigest() != pool.sha256:
        raise Failed(
            f"{url}: does not match the signed index for {package[0]} {package[1]} "
            f"(expected {pool.size} bytes, sha256 {pool.sha256})"
        )
    archive.store(sources.cache, data)
    return True


def verified_input(item: LockedInput, data: bytes) -> None:
    """Failed naming the URL unless `data` carries every checksum the lock gives."""
    for algorithm, expected in item.checksums:
        if _digest(algorithm, data) != expected:
            raise Failed(f"{item.url}: does not match the lock's {algorithm} for {item.name} ({expected})")


def download_input(item: LockedInput, sources: Sources) -> bool:
    """Make sure the cache holds the locked input, by sha256; True when it was downloaded."""
    present = archive.cached(sources.cache, item.sha256)
    if present is not None:
        verified_input(item, present.read_bytes())
        return False
    try:
        data = sources.read(item.url)
    except (OSError, ValueError) as error:
        raise Failed(f"{item.url}: cannot be read: {error}") from None
    verified_input(item, data)
    archive.store(sources.cache, data)
    return True


def input_path(cache: Path, fields: Mapping[str, object]) -> Path:
    """The cached file of a locked input, from its `build_fields`; the build copies it into the container.

    Raises Failed when `fetch` has not stored it (or the file in the cache no longer hashes to its name).
    """
    sha256 = fields.get("sha256")
    if not isinstance(sha256, str) or not re.fullmatch("[0-9a-f]{64}", sha256):
        raise Failed("a locked input needs a sha256 to be found in the cache: `lock checksums` adds one")
    path = archive.cached(cache, sha256)
    if path is None:
        raise Failed(f"input {fields.get('url', sha256)} is not in the cache {cache}: run `fetch` first")
    return path


# ---- the partial mirror -----------------------------------------------------------------------------


def mirror_dir(cache: Path, snapshot: str) -> Path:
    """Where the partial mirror of a snapshot lives: `<cache>/mirror/<snapshot>`, read by the build as `file:`."""
    return cache / "mirror" / snapshot


def place(source: Path, target: Path) -> None:
    """Put `source` at `target` as a hard link (a copy across devices), replacing what is there.

    A file already identical is left alone. Never a symlink: the build bind-mounts the mirror into a container.
    """
    if target.is_file() and not target.is_symlink() and (target.samefile(source) or filecmp.cmp(source, target, False)):
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=target.parent, prefix=".tmp-")
    os.close(fd)
    temp = Path(name)
    try:
        temp.unlink()
        try:
            os.link(source, temp)
        except OSError:
            shutil.copyfile(source, temp)
        os.replace(temp, target)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def lay_out_pool(mirror: Path, cache: Path, files: Mapping[Package, PoolFile]) -> int:
    """Every pool file at `<mirror>/<archive>/<Filename>`, linked from the cache; how many files that is."""
    placed = 0
    for pool in files.values():
        source = archive.cache_path(cache, pool.sha256)
        for archive_, _base_url, filename in pool.locations:
            place(source, mirror / archive_ / filename)
            placed += 1
    return placed


# ---- the command --------------------------------------------------------------------------------------


def load_plan(path: Path) -> FetchPlan:
    try:
        return fetch_plan(read_plan(path))
    except OSError as error:
        raise Failed(f"{path}: {error.strerror or error}") from None
    except ValueError as error:
        raise Failed(f"{path}: {error}") from None


def open_indices(plan: FetchPlan, sources: Sources) -> list[archive.SuiteIndex]:
    try:
        return [
            archive.fetch_suite(
                resolve.snapshot_base(sources.service, one.archive, plan.snapshot),
                one.dist,
                plan.components,
                plan.architecture,
                sources.keyring,
                sources.cache,
                sources.read,
            )
            for one in resolve.suites(plan.suite)
        ]
    except (archive.ArchiveError, OSError, ValueError) as error:
        raise Failed(str(error)) from None


def fetch_command(plan_path: Path, sources: Sources, *, bundle: bool, out: TextIO) -> int:
    """`fetch`: indices, pool files, locked inputs and the partial mirror. Returns the exit status (0)."""
    if bundle:
        raise Usage("inputs bundles arrive in a later release (milestone M6)")
    plan = load_plan(plan_path)
    indices = open_indices(plan, sources)
    try:
        found, problems = pool_files(indices, plan.packages)
    except ValueError as error:
        raise Failed(f"a Packages index is malformed: {error}") from None
    if problems:
        raise Failed("\n".join(problems))
    fetched = reused = 0
    for package, pool in sorted(found.items()):
        try:
            if download_pool_file(package, pool, sources):
                fetched += 1
            else:
                reused += 1
        except Failed as error:
            problems.append(str(error))
    inputs_fetched = inputs_reused = 0
    for item in plan.inputs:
        try:
            if download_input(item, sources):
                inputs_fetched += 1
            else:
                inputs_reused += 1
        except Failed as error:
            problems.append(str(error))
    if problems:
        raise Failed("\n".join(problems))
    mirror = mirror_dir(sources.cache, plan.snapshot)
    try:
        archive.lay_out_mirror(indices, mirror)
        lay_out_pool(mirror, sources.cache, found)
    except (archive.ArchiveError, OSError) as error:
        raise Failed(f"cannot lay out the mirror {mirror}: {error}") from None
    print(f"suites: {len(indices)} verified at snapshot {plan.snapshot}", file=out)
    print(f"packages: {fetched} fetched, {reused} already cached ({len(found)} in all)", file=out)
    print(f"inputs: {inputs_fetched} fetched, {inputs_reused} already cached ({len(plan.inputs)} in all)", file=out)
    print(f"mirror: {mirror}", file=out)
    return 0
