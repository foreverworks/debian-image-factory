"""The artifact an OCI image is built on, found and read (DESIGN 5.3, 8.2). An edge: it reads files.

A child's parent is built earlier in the same run, or it is already somewhere: in the build's output
directory, in a `dir://` target given as `--parents`, or in a registry (`pull`). Every candidate is
checked against its own name and, when the plan names the parent's digest, against that digest, so a
child is never built on bytes other than the ones its identity was computed from.
"""

import gzip
import hashlib
import tarfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from input_lock.identity import HEX64

from .. import commands, oci, ocilayout, planfile, published

CORE_EXTENSION: Final = "tar.gz"
EXTENSIONS: Final[Mapping[str, str]] = {"core": CORE_EXTENSION, "oci": oci.LAYOUT_EXT}
"""The extension of each artifact kind a child can be built on."""
DPKG_STATUS: Final = "var/lib/dpkg/status"

type Finder = Callable[[str], Path | None]
"""Where an artifact is, by its file or directory name; None when nowhere."""
type Pull = Callable[[published.OciTarget, str, Path], Path]
"""Fetch the image with this manifest digest (hex) from a registry into a directory, as an OCI image
layout, and return the layout's path."""


@dataclass(frozen=True, slots=True)
class ParentArtifact:
    """An artifact an image descends from."""

    image: str
    kind: str
    """`core` or `oci`."""
    name: str
    """The artifact's file or directory name."""
    digest: str
    """sha256 in hex: of a core tarball, or of an OCI image's manifest."""
    path: Path | None
    """Where it is; None for an ancestor only known by the name and digest its child's annotations give."""


@dataclass(frozen=True, slots=True)
class Base:
    """What an OCI child starts from: its parent's layers and config."""

    layers: tuple[tuple[Path, str, int], ...]
    """(path, sha256 of the file, size), base first: the shape `ocilayout.write_layout` takes."""
    diff_ids: tuple[str, ...]
    """sha256 of each layer uncompressed, in hex."""
    config: oci.OciConfig | None
    """What the parent runs as; None when the parent is core, which has no config."""


# ---- reading artifacts --------------------------------------------------------------------------


def sha256_of(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def gunzip_sha256(path: Path) -> str:
    """sha256 of the file once decompressed; the whole stream is read, so a truncated file fails."""
    digest = hashlib.sha256()
    try:
        with gzip.open(path, "rb") as handle:
            while block := handle.read(1 << 20):
                digest.update(block)
    except (OSError, EOFError) as error:
        raise commands.Failed(f"{path.name}: not a complete gzip stream: {error}") from None
    return digest.hexdigest()


def name_parts(name: str, kind: str) -> published.ArtifactName:
    parts = published.parse_artifact_name(name)
    if parts is None or parts.ext != EXTENSIONS[kind]:
        raise commands.Failed(f"{name} is not the name of a {kind} artifact")
    return parts


def describe_core(path: Path) -> ParentArtifact:
    """A core tarball, its digest read from its bytes and checked against the digest its name carries."""
    parts = name_parts(path.name, "core")
    digest = sha256_of(path)
    if not digest.startswith(parts.digest12):
        raise commands.Failed(f"{path.name}: its sha256 is {digest}, which its name does not say")
    return ParentArtifact(parts.image, "core", path.name, digest, path)


def describe_layout(path: Path, *, check_layers: bool) -> ParentArtifact:
    """An OCI image layout: its manifest digest, read back through `ocilayout` (which checks every
    blob it returns), checked against the digest its name carries."""
    parts = name_parts(path.name, "oci")
    try:
        layout = ocilayout.read_layout(path, check_layers=check_layers)
    except (oci.OciError, OSError) as error:
        raise commands.Failed(f"{path.name}: {error}") from None
    if not layout.descriptor.digest.startswith(parts.digest12):
        raise commands.Failed(f"{path.name}: its manifest is {layout.descriptor.digest}, which its name does not say")
    return ParentArtifact(parts.image, "oci", path.name, layout.descriptor.digest, path)


def describe(path: Path, kind: str, *, check_layers: bool = True) -> ParentArtifact:
    return describe_core(path) if kind == "core" else describe_layout(path, check_layers=check_layers)


def base_of(parent: ParentArtifact) -> Base:
    """The layers and config a child starts from. A core tarball is its own single layer."""
    if parent.path is None:
        raise commands.Failed(f"{parent.name} is only known by name: its layers are needed to build on it")
    if parent.kind == "core":
        size = parent.path.stat().st_size
        return Base(((parent.path, parent.digest, size),), (gunzip_sha256(parent.path),), None)
    try:
        layout = ocilayout.read_layout(parent.path, check_layers=False)
    except (oci.OciError, OSError) as error:
        raise commands.Failed(f"{parent.name}: {error}") from None
    layers = tuple(
        (path, described.digest, described.size)
        for path, described in zip(layout.layers, layout.manifest.layers, strict=True)
    )
    return Base(layers, layout.diff_ids, layout.config)


def dpkg_status(layers: Sequence[Path]) -> str:
    """dpkg's status of an image made of `layers`: the last layer that holds the file has the final one."""
    for layer in reversed(layers):
        with tarfile.open(layer, mode="r:*") as archive:
            for member in archive:
                if member.name.removeprefix("./") == DPKG_STATUS and member.isfile():
                    handle = archive.extractfile(member)
                    if handle is not None:
                        return handle.read().decode("utf-8")
    raise commands.Failed(f"no layer holds {DPKG_STATUS}")


# ---- finding the parent -------------------------------------------------------------------------


def in_directory(
    directory: Path, image: str, kind: str, suite: str, arch: str, identity: str, digest: str | None
) -> list[ParentArtifact]:
    """The artifacts of this image and identity in `directory`: the one named by `digest`, or, when the
    plan names none, every one there. Each is read and checked."""
    extension = EXTENSIONS[kind]
    if digest is not None:
        path = directory / published.artifact_name(image, suite, arch, identity, digest, extension)
        if not path.exists():
            return []
        found = describe(path, kind)
        if found.digest != digest:
            raise commands.Failed(f"{path}: its digest is {found.digest}, not {digest}")
        return [found]
    prefix = f"{image}-{suite}-{arch}-{identity[:16]}-"
    try:
        names = sorted(name for name in (entry.name for entry in directory.iterdir()) if name.startswith(prefix))
    except FileNotFoundError:
        return []
    return [
        describe(directory / name, kind)
        for name in names
        if (parts := published.parse_artifact_name(name)) is not None
        and (parts.image, parts.suite, parts.arch, parts.ext) == (image, suite, arch, extension)
    ]


def named_digest(entry: planfile.ImageEntry) -> str | None:
    """The digest the plan names for an image it says to reuse or wait for."""
    artifact = entry.get("artifact")
    if artifact is None:
        return None
    if not isinstance(artifact, str) or not HEX64.fullmatch(artifact):
        raise commands.Failed(f"the plan's artifact {artifact!r} is not a sha256 in hex")
    return artifact


def locate_parent(
    child: str,
    parent: str,
    entry: planfile.ImageEntry,
    *,
    suite: str,
    arch: str,
    built: Mapping[str, ParentArtifact],
    out_dir: Path,
    directories: Sequence[Path],
    registries: Sequence[published.OciTarget],
    pull: Pull,
    scratch: Path,
) -> ParentArtifact:
    """The artifact of `child`'s parent: built earlier in this run, else in `out_dir`, else in a `dir://`
    parent target, else pulled from an `oci://` one. Fails naming where it looked."""
    if parent in built:
        return built[parent]
    kind = entry["kind"]
    if kind not in EXTENSIONS:
        raise commands.Failed(f"images.{child}: its parent {parent} is a {kind} image, which no OCI image is built on")
    digest = named_digest(entry)
    searched: list[str] = []
    for directory in (out_dir, *directories):
        found = in_directory(directory, parent, kind, suite, arch, entry["identity"], digest)
        if len(found) > 1:
            names = ", ".join(one.name for one in found)
            raise commands.Failed(f"images.{child}: {directory} holds several builds of {parent} ({names}); name one")
        if found:
            return found[0]
        searched.append(str(directory))
    if digest is not None and kind == "oci":
        name = published.artifact_name(parent, suite, arch, entry["identity"], digest, "oci")
        for number, registry in enumerate(registries):
            where = f"oci://{registry.registry}/{registry.repository}"
            try:  # each target in turn (DESIGN 9.1): one that lacks the image, or fails, is not the last word
                pulled = describe_layout(pull(registry, digest, scratch / str(number) / name), check_layers=True)
            except commands.Failed as error:
                searched.append(f"{where} ({error})")
                continue
            if pulled.digest != digest:
                raise commands.Failed(f"{where}: pulled {pulled.digest}, not {digest}")
            return pulled
    wanted = f"digest {digest}" if digest is not None else f"identity {entry['identity'][:16]}"
    raise commands.Failed(
        f"images.{child}: its parent {parent} ({wanted}) is not built in this run and was not found in "
        f"{', '.join(searched)}: build it (--image {parent}) or point --parents at where it is"
    )


def lineage(parent: ParentArtifact, find: Finder) -> tuple[ParentArtifact, ...]:
    """`parent` and every ancestor above it up to core, nearest first, from each image's own annotations
    (the base digest and name its manifest carries). `find` says where an ancestor's layout is, by its
    artifact name; core needs none, since it has no ancestors of its own."""
    chain = [parent]
    current = parent
    while current.kind == "oci":
        if current.path is None:
            raise commands.Failed(f"{current.name}: its layout is needed to list the images below it")
        try:
            annotations = ocilayout.read_layout(current.path, check_layers=False).manifest.annotations
            base_digest = oci.parse_digest(annotations.get(oci.BASE_DIGEST))
        except (oci.OciError, OSError) as error:
            raise commands.Failed(f"{current.name}: it does not say what it is built on ({error})") from None
        base_name = annotations.get(oci.BASE_NAME, "")
        parts = published.parse_artifact_name(base_name)
        if parts is None:
            raise commands.Failed(f"{current.name}: its base name {base_name!r} is not an artifact name")
        if parts.ext == CORE_EXTENSION:
            current = ParentArtifact(parts.image, "core", base_name, base_digest, None)
        elif parts.ext == oci.LAYOUT_EXT:
            path = find(base_name)
            if path is None:
                raise commands.Failed(
                    f"{current.name} is built on {base_name}, which is not in the build's output or in --parents: "
                    "its annotations are needed to list the images below it"
                )
            current = describe_layout(path, check_layers=False)
            if current.digest != base_digest:
                raise commands.Failed(
                    f"{path}: its manifest is {current.digest}, but {chain[-1].name} says {base_digest}"
                )
        else:
            raise commands.Failed(f"{current.name}: its base {base_name} is neither a core tarball nor an OCI image")
        chain.append(current)
    return tuple(chain)
