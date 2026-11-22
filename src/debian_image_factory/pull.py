"""`verify --pull` for file targets (DESIGN 9.1): an artifact of a `github-release://` release or a `dir://`
directory is downloaded, with its records, to a scratch directory, and the ordinary file verify runs there.

A target is reduced to what verify needs of it: the names of the files it holds and a way to copy one. The
artifact is named by its file name or by its digest (the sha256, or an Incus image's fingerprint, in full hex,
optionally `sha256:`-prefixed); the digest is found through the 12 hex every artifact name carries.
"""

import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from input_lock.identity import HEX64

from . import commands, fileartifacts, github, incus, published


@dataclass(frozen=True, slots=True)
class Source:
    """A file target as `verify` reads it: its label, the names of every file it holds, and a function
    that writes one of them (by name) to a destination path."""

    label: str
    names: tuple[str, ...]
    fetch: Callable[[str, Path], None]


@dataclass(frozen=True, slots=True)
class Pulled:
    """An artifact in the scratch directory: its (first) file, its digest as computed from the bytes, and
    what is wrong already (it is not the digest that was asked for)."""

    path: Path
    digest: str
    problems: tuple[str, ...]


def dir_source(directory: Path) -> Source:
    """The files of a directory. Raises Failed when it is not one."""
    try:
        names = tuple(sorted(one.name for one in directory.iterdir() if one.is_file()))
    except OSError as error:
        raise commands.Failed(f"dir://{directory}: {error.strerror or error}") from None

    def fetch(name: str, destination: Path) -> None:
        shutil.copyfile(directory / name, destination)

    return Source(f"dir://{directory}", names, fetch)


def release_source(client: github.Client) -> Source:
    """The assets of the release the client names. Raises Failed when the tag has no release or GitHub
    cannot be read."""
    try:
        release = github.release_by_tag(client)
        if release is None:
            raise commands.Failed(f"{client.name}: no such release")
        assets = {one["name"]: one for one in github.list_assets(client, release)}
    except github.GitHubError as error:
        raise commands.Failed(str(error)) from None  # it names the release already

    def fetch(name: str, destination: Path) -> None:
        github.download_asset(client, assets[name], destination)

    return Source(client.name, tuple(sorted(assets)), fetch)


def artifact_name_for(source: Source, wanted: str) -> str:
    """The file name of the artifact `wanted` names: a file name the target holds, or a digest in full hex.
    A rootfs file names its Incus image's metadata file. Raises Failed when nothing, or more than one thing,
    is meant."""
    digest = wanted.removeprefix("sha256:")
    if HEX64.fullmatch(digest):
        found = [
            name
            for name in source.names
            if (parts := published.parse_artifact_name(name)) is not None
            and not fileartifacts.is_companion(parts)
            and digest.startswith(parts.digest12)
        ]
        if not found:
            raise commands.Failed(f"{source.label}: no artifact whose name carries the digest {digest[:12]}")
        if len(found) > 1:
            raise commands.Failed(
                f"{source.label}: {len(found)} artifacts carry the digest {digest[:12]}, name one: {', '.join(found)}"
            )
        return found[0]
    parts = published.parse_artifact_name(wanted)
    if parts is None:
        raise commands.Failed(f"{wanted!r} is neither an artifact file name nor a sha256 in 64 hex characters")
    if parts.ext == incus.ROOTFS_EXT:
        wanted = wanted.removesuffix(incus.ROOTFS_EXT) + incus.METADATA_EXT
    if wanted not in source.names:
        raise commands.Failed(f"{source.label}: no artifact named {wanted}")
    return wanted


def files_of(name: str) -> tuple[str, ...]:
    """The files an artifact is made of: itself, and for an Incus image its rootfs."""
    rootfs = incus.rootfs_of(name)
    return (name,) if rootfs is None else (name, rootfs)


def pull_artifact(source: Source, wanted: str, scratch: Path) -> Pulled:
    """Download the artifact `wanted` and its records into `scratch` (an existing, empty directory). Raises
    Failed when it is not there or a download fails."""
    name = artifact_name_for(source, wanted)
    held = frozenset(source.names)
    try:
        for file in files_of(name):
            if file not in held:
                raise commands.Failed(f"{source.label}: {name} has no companion file {file}")
            source.fetch(file, scratch / file)
        path = scratch / name
        rootfs = incus.rootfs_of(name)
        digest = (
            fileartifacts.sha256_of(path) if rootfs is None else fileartifacts.fingerprint_of(path, scratch / rootfs)
        )
        records = published.records_name_for(digest)
        if records in held:
            source.fetch(records, scratch / records)
    except OSError as error:
        raise commands.Failed(f"{source.label}: {name}: {error.strerror or error}") from None
    asked = wanted.removeprefix("sha256:")
    problems: Sequence[str] = (
        (f"{name}: its digest is {digest}, not the {asked} that was asked for",)
        if HEX64.fullmatch(asked) and asked != digest
        else ()
    )
    return Pulled(path, digest, tuple(problems))
