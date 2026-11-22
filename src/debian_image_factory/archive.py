"""Reading a Debian archive snapshot's signed indices (DESIGN 7.2 and 7.7).

The edge of the archive code: it downloads, verifies with `gpgv` and writes files. Everything it
parses goes through the pure functions in `debian.py`. What a mirror or cache returns is trusted only
after the signature on `InRelease` and the hashes in it have checked out.
"""

import gzip
import hashlib
import lzma
import os
import subprocess
import tempfile
import zlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from debian_image_factory import debian, remote


class ArchiveError(Exception):
    """An index could not be read, or what was read did not verify."""


@dataclass(frozen=True, slots=True)
class SuiteIndex:
    """One suite's verified indices: the signed `InRelease` and the files it vouches for."""

    base_url: str
    dist: str
    release: bytes
    """The `InRelease` bytes, signature included."""
    files: tuple[tuple[str, Path], ...]
    """Release path (relative to the dist directory) -> verified local file, sorted by path."""


def archive_name(base_url: str) -> str:
    """The path component after `archive/`: `debian` for `https://host/archive/debian/20261121T004329Z`."""
    parts = urlparse(base_url).path.split("/")
    if "archive" not in parts[:-1]:
        raise ArchiveError(f"{base_url!r} has no archive/<name>/ component")
    return parts[parts.index("archive") + 1]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cache_path(cache: Path, sha256: str) -> Path:
    """Where the content-addressed cache keeps the file with this hash."""
    return cache / "sha256" / sha256[:2] / sha256


def cached(cache: Path, sha256: str) -> Path | None:
    """The cached file with this hash when it is present and still hashes to it."""
    path = cache_path(cache, sha256)
    if path.is_file() and _sha256(path.read_bytes()) == sha256:
        return path
    return None


def store(cache: Path, data: bytes) -> Path:
    """Put `data` in the cache (atomically) and return its path."""
    sha256 = _sha256(data)
    path = cache_path(cache, sha256)
    if cached(cache, sha256) is None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.replace(temp, path)
        except BaseException:
            Path(temp).unlink(missing_ok=True)
            raise
    return path


def verify_in_release(in_release: bytes, keyring: Path, source: str) -> str:
    """The signed text of a clear-signed `InRelease`, after `gpgv --keyring <keyring>` accepts it.

    Raises ArchiveError with gpgv's own message when the signature does not verify.
    """
    with tempfile.TemporaryDirectory(prefix="dif-gpgv-") as scratch:
        signed = Path(scratch) / "InRelease"
        text = Path(scratch) / "Release"
        signed.write_bytes(in_release)
        result = subprocess.run(
            ["gpgv", "--homedir", scratch, "--keyring", str(keyring.resolve()), "--output", str(text), str(signed)],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", "replace").strip()
            raise ArchiveError(f"InRelease from {source} failed signature verification: {message}")
        return text.read_text(encoding="utf-8")


def _decompressor(suffix: str) -> Callable[[bytes], bytes]:
    return {".xz": lzma.decompress, ".gz": gzip.decompress}.get(suffix, bytes)


def _fetch_listed(
    base_url: str,
    dist: str,
    path: str,
    sha256: str,
    size: int,
    by_hash: bool,
    cache: Path,
    read: Callable[[str], bytes],
) -> Path | None:
    """The verified, cached file for a Release entry, or None when the archive does not serve it.

    A file served but not matching Release is an ArchiveError, never a reason to try another form.
    """
    present = cached(cache, sha256)
    if present is not None and present.stat().st_size == size:
        return present
    urls = [f"{base_url}/dists/{dist}/{path}"]
    if by_hash:
        urls.insert(0, f"{base_url}/{debian.by_hash_path(f'dists/{dist}', path, sha256)}")
    for url in urls:
        try:
            data = read(url)
        except OSError:
            continue
        if len(data) != size or _sha256(data) != sha256:
            raise ArchiveError(f"{url} does not match Release (expected {size} bytes, sha256 {sha256})")
        return store(cache, data)
    return None


def _fetch_index(
    base_url: str,
    dist: str,
    component: str,
    arch: str,
    listed: dict[str, tuple[str, int]],
    by_hash: bool,
    cache: Path,
    read: Callable[[str], bytes],
) -> list[tuple[str, Path]]:
    stem = f"{component}/binary-{arch}/Packages"
    for suffix in (".xz", ".gz", ""):
        entry = listed.get(stem + suffix)
        if entry is None:
            continue
        fetched = _fetch_listed(base_url, dist, stem + suffix, entry[0], entry[1], by_hash, cache, read)
        if fetched is None:
            continue
        if not suffix:
            return [(stem, fetched)]
        try:
            plain = _decompressor(suffix)(fetched.read_bytes())
        except (lzma.LZMAError, OSError, EOFError, zlib.error) as error:
            raise ArchiveError(f"{stem + suffix} of {base_url} does not decompress: {error}") from error
        plain_listed = listed.get(stem)
        if plain_listed is not None and (len(plain) != plain_listed[1] or _sha256(plain) != plain_listed[0]):
            raise ArchiveError(f"{stem} (decompressed from {stem + suffix}) does not match Release")
        return [(stem + suffix, fetched), (stem, store(cache, plain))]
    raise ArchiveError(f"{base_url}/dists/{dist}: no Packages index for {component}/{arch} could be read")


def fetch_suite(
    base_url: str,
    dist: str,
    components: Sequence[str],
    arch: str,
    keyring: Path,
    cache: Path,
    read: Callable[[str], bytes] = remote.read_url,
) -> SuiteIndex:
    """Download and verify one suite's `InRelease` and the `Packages` index of each component.

    The signature is checked with `gpgv --keyring <keyring>` and refused on failure. Each index is
    read as `Packages.xz`, else `.gz`, else uncompressed (by hash when Release says
    `Acquire-By-Hash: yes`), checked against the size and sha256 in Release, decompressed, and its
    decompressed form checked against Release too when listed. Files live in the content-addressed
    cache `<cache>/sha256/<aa>/<hex>` and are reused when present and matching.
    """
    base_url = base_url.rstrip("/")
    in_release = read(f"{base_url}/dists/{dist}/InRelease")
    release_text = verify_in_release(in_release, keyring, f"{base_url}/dists/{dist}")
    try:
        listed = debian.release_files(release_text)
        by_hash = debian.acquire_by_hash(release_text)
    except ValueError as error:
        raise ArchiveError(f"Release of {base_url}/dists/{dist} is malformed: {error}") from error
    files: dict[str, Path] = {}
    for component in components:
        files.update(_fetch_index(base_url, dist, component, arch, listed, by_hash, cache, read))
    return SuiteIndex(base_url, dist, in_release, tuple(sorted(files.items())))


def _publish(target: Path, data: bytes) -> None:
    """Write `data` to `target` so no reader ever sees a partial file (temp file in the same directory, then rename)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=target.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(temp, target)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def lay_out_mirror(indices: Sequence[SuiteIndex], dest: Path) -> Path:
    """Write a partial mirror apt can read through `file:` sources, and return `dest`.

    For each suite: `dest/<archive-name>/dists/<dist>/InRelease` and every index file at its Release
    path, compressed as fetched and uncompressed (apt's `file:` method reads the plain paths, never
    by-hash ones). apt verifies the signature and the hashes itself. A source line is
    `deb [signed-by=<keyring>] file:<dest>/<archive-name> <dist> <component>`.

    Several processes or threads may lay out the same `dest` at once (it is shared by snapshot): every
    file is published by an atomic rename, so a concurrent writer or reader sees a whole file or none,
    never a half-written one, and files with the same name always carry the same verified bytes.
    """
    for index in indices:
        dist_dir = dest / archive_name(index.base_url) / "dists" / index.dist
        in_release = dist_dir / "InRelease"
        if in_release.exists() and in_release.read_bytes() != index.release:
            raise ArchiveError(f"two different InRelease files for {dist_dir}")
        _publish(in_release, index.release)
        for path, local in index.files:
            _publish(dist_dir / path, local.read_bytes())
    return dest
