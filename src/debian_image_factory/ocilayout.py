"""The OCI image layout on disk (image-spec `image-layout.md`): write one, read one back. An edge.

A layout here holds exactly one image: `oci-layout`, `index.json` naming one manifest, and
`blobs/sha256/<hex>` for the manifest, its config and its layers. Reading checks every blob it
returns against its digest, so nothing downstream sees bytes that do not match their name.
"""

import hashlib
import json
import os
import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import oci

LAYOUT_FILE: Final = b'{"imageLayoutVersion":"1.0.0"}'


@dataclass(frozen=True, slots=True)
class Layout:
    """One image read from a layout: its manifest's descriptor and bytes, parsed manifest and config,
    and the path of each layer blob, base first."""

    path: Path
    descriptor: oci.Descriptor
    manifest_bytes: bytes
    manifest: oci.Manifest
    config_bytes: bytes
    config: oci.OciConfig
    diff_ids: tuple[str, ...]
    layers: tuple[Path, ...]


def blob_path(layout: Path, digest: str) -> Path:
    oci.digest_text(digest)
    return layout / "blobs" / "sha256" / digest


def file_sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def write_blob(layout: Path, data: bytes) -> str:
    digest = oci.sha256_hex(data)
    path = blob_path(layout, digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.is_file():
        path.write_bytes(data)
    return digest


def add_blob_file(layout: Path, source: Path, digest: str) -> None:
    """Place the file `source`, whose sha256 the caller computed as `digest`, as a blob: hard-linked
    when it can be, copied otherwise. The digest is checked again."""
    if file_sha256(source) != digest:
        raise oci.OciError(f"{source}: its sha256 is not {digest}")
    path = blob_path(layout, digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        return
    try:
        os.link(source, path)
    except OSError:
        shutil.copyfile(source, path)


def write_layout(
    layout: Path, *, config: bytes, layers: Sequence[tuple[Path, str, int]], annotations: dict[str, str]
) -> oci.Descriptor:
    """Write a one-image layout at `layout` (which must not exist yet) from the config bytes and the
    layer files `(path, sha256 of the compressed file, size)`, base first. Returns the manifest's
    descriptor; its digest is the image's."""
    if layout.exists():
        raise FileExistsError(f"{layout} already exists")
    layout.mkdir(parents=True)
    config_descriptor = oci.Descriptor(oci.CONFIG, write_blob(layout, config), len(config))
    layer_descriptors: list[oci.Descriptor] = []
    for path, digest, size in layers:
        add_blob_file(layout, path, digest)
        layer_descriptors.append(oci.Descriptor(oci.LAYER_GZIP, digest, size))
    manifest = oci.image_manifest(config_descriptor, layer_descriptors, annotations)
    descriptor = oci.Descriptor(oci.MANIFEST, write_blob(layout, manifest), len(manifest))
    write_index(layout, descriptor)
    return descriptor


def write_index(layout: Path, descriptor: oci.Descriptor) -> None:
    """Make the directory `layout`, whose blobs are all in place, a layout holding the one image whose
    manifest is `descriptor`: write `oci-layout` and `index.json`."""
    (layout / "oci-layout").write_bytes(LAYOUT_FILE)
    (layout / "index.json").write_bytes(oci.index([descriptor]))


def read_blob(layout: Path, descriptor: oci.Descriptor) -> bytes:
    data = blob_path(layout, descriptor.digest).read_bytes()
    if len(data) != descriptor.size or oci.sha256_hex(data) != descriptor.digest:
        raise oci.OciError(f"{layout}: blob {descriptor.digest} does not match its descriptor")
    return data


def read_layout(layout: Path, *, check_layers: bool = True) -> Layout:
    """The one image a layout holds, every blob checked against its digest (layers too, unless
    `check_layers` is false, for a caller that hashes them itself as it reads them)."""
    try:
        if json.loads((layout / "oci-layout").read_bytes()).get("imageLayoutVersion") != "1.0.0":
            raise oci.OciError(f"{layout}: oci-layout is not version 1.0.0")
    except (OSError, ValueError, AttributeError) as error:
        raise oci.OciError(f"{layout}: not an OCI image layout ({error})") from None
    manifests = oci.parse_index((layout / "index.json").read_bytes())
    if len(manifests) != 1 or manifests[0].media_type != oci.MANIFEST:
        raise oci.OciError(f"{layout}: index.json must name exactly one image manifest")
    descriptor = manifests[0]
    manifest_bytes = read_blob(layout, descriptor)
    manifest = oci.parse_manifest(manifest_bytes)
    config_bytes = read_blob(layout, manifest.config)
    config, diff_ids = oci.parse_config(config_bytes)
    if len(diff_ids) != len(manifest.layers):
        raise oci.OciError(f"{layout}: {len(manifest.layers)} layers but {len(diff_ids)} diff_ids")
    paths: list[Path] = []
    for layer in manifest.layers:
        path = blob_path(layout, layer.digest)
        if check_layers and (path.stat().st_size != layer.size or file_sha256(path) != layer.digest):
            raise oci.OciError(f"{layout}: layer {layer.digest} does not match its descriptor")
        paths.append(path)
    return Layout(layout, descriptor, manifest_bytes, manifest, config_bytes, config, diff_ids, tuple(paths))
