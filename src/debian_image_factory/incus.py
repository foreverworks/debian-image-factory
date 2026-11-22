"""An Incus image as the factory writes it (DESIGN 8.1): a split image, a metadata tarball and a squashfs
root filesystem, named by their Incus fingerprint. Pure: bytes and text in, bytes and text out.

The metadata tarball holds `metadata.yaml` and the factory's own NoCloud templates (DESIGN 15, decision
19), written from Incus's image format documentation: on `create` and `copy` Incus renders them into the
instance's root, so cloud-init finds a NoCloud seed with the instance's own data and its name, and an
image carries no hostname of its own. The user-data, vendor-data and network-config templates read the
`cloud-init.*` configuration keys and fall back to the older `user.*` ones, which some tooling still sets.

The fingerprint of a split image is the sha256 of the metadata tarball's bytes followed by the rootfs's
(Incus computes it the same way on import), so it is a sha256 and names the image in records like any
other digest: the provenance's subjects are the image under its fingerprint and both files under their own.
"""

import gzip
import hashlib
import io
import json
import tarfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final

from .published import artifact_name, parse_artifact_name

METADATA_EXT: Final = "incus.tar.gz"
"""The extension of the metadata tarball (metadata.yaml and templates)."""
ROOTFS_EXT: Final = "rootfs.squashfs"
"""The extension of the root filesystem, a squashfs with its gzip compressor."""

ARCHITECTURES: Final[Mapping[str, str]] = {"amd64": "x86_64", "arm64": "aarch64"}
"""Debian's architecture names as Incus's metadata.yaml names them."""

SUITE_NAMES: Final[Mapping[str, str]] = {"trixie": "Debian 13 (trixie)"}
"""How a description names a suite; a suite not listed is named as it is."""

SEED: Final = "/var/lib/cloud/seed/nocloud-net"
"""Where cloud-init's NoCloud datasource reads its seed inside an instance."""

DEFAULT_USER_DATA: Final = "#cloud-config\n{}\n"
DEFAULT_NETWORK: Final = "version: 2\nethernets:\n  eth0:\n    dhcp4: true\n    dhcp6: true\n"
"""What an instance's network is without configuration: its first interface, Incus's `eth0`, on DHCP."""


def _from_config(key: str) -> str:
    """A template body that prints the instance's `cloud-init.<key>`, else its `user.<key>`, else the
    template's `default` property. pongo2's `config_get` returns its default when the key is unset."""
    modern = f'config_get("cloud-init.{key}", "")'
    older = f'config_get("user.{key}", properties.default)'
    return f'{{% if {modern} != "" %}}{{{{ {modern} }}}}{{% else %}}{{{{ {older} }}}}{{% endif %}}\n'


TEMPLATES: Final[Mapping[str, str]] = {
    "cloud-init-meta.tpl": "instance-id: {{ instance.name }}\nlocal-hostname: {{ instance.name }}\n",
    "cloud-init-user.tpl": _from_config("user-data"),
    "cloud-init-vendor.tpl": _from_config("vendor-data"),
    "cloud-init-network.tpl": _from_config("network-config"),
    "hostname.tpl": "{{ instance.name }}\n",
    "hosts.tpl": (
        "127.0.0.1\tlocalhost\n"
        "127.0.1.1\t{{ instance.name }}\n"
        "\n"
        "::1\tlocalhost ip6-localhost ip6-loopback\n"
        "ff02::1\tip6-allnodes\n"
        "ff02::2\tip6-allrouters\n"
    ),
}
"""The template files, by name, as `templates/<name>` in the metadata tarball. The meta-data's instance-id
is the instance's name, so a copy (which Incus gives a new name) is a new instance to cloud-init."""

RENDERED: Final[tuple[tuple[str, str, str | None], ...]] = (
    (f"{SEED}/meta-data", "cloud-init-meta.tpl", None),
    (f"{SEED}/user-data", "cloud-init-user.tpl", DEFAULT_USER_DATA),
    (f"{SEED}/vendor-data", "cloud-init-vendor.tpl", DEFAULT_USER_DATA),
    (f"{SEED}/network-config", "cloud-init-network.tpl", DEFAULT_NETWORK),
    ("/etc/hostname", "hostname.tpl", None),
    ("/etc/hosts", "hosts.tpl", None),
)
"""(path in the instance, template, its `default` property) for every file Incus renders on create and copy."""


def description(suite: str, image: str) -> str:
    return f"{SUITE_NAMES.get(suite, suite)} {image}"


def _quoted(text: str) -> str:
    """A YAML double-quoted scalar. JSON's string syntax is a subset of YAML's double-quoted style."""
    return json.dumps(text, ensure_ascii=True)


def metadata_yaml(*, image: str, suite: str, arch: str, identity: str, source_date_epoch: int) -> str:
    """The image's metadata.yaml (DESIGN 8.1). `creation_date` is source_date_epoch, never the build
    time; `serial` is the identity's first 16 hex, so the same inputs give the same file."""
    if arch not in ARCHITECTURES:
        raise ValueError(f"no Incus architecture name for {arch!r}")
    lines = [
        f"architecture: {ARCHITECTURES[arch]}",
        f"creation_date: {int(source_date_epoch)}",
        "properties:",
        "  os: debian",
        f"  release: {_quoted(suite)}",
        f"  variant: {_quoted(image)}",
        f"  serial: {_quoted(identity[:16])}",
        f"  description: {_quoted(description(suite, image))}",
        "templates:",
    ]
    for path, template, default in RENDERED:
        lines += [f"  {path}:", "    when: [create, copy]", f"    template: {template}"]
        if default is not None:
            lines += ["    properties:", f"      default: {_quoted(default)}"]
    return "\n".join(lines) + "\n"


def metadata_tarball(*, image: str, suite: str, arch: str, identity: str, source_date_epoch: int) -> bytes:
    """The metadata tarball: metadata.yaml, then the templates in name order, owned by root, 0644,
    every time stamp source_date_epoch, gzip with no name and a zero time stamp: the same inputs give
    the same bytes."""
    epoch = int(source_date_epoch)
    yaml = metadata_yaml(image=image, suite=suite, arch=arch, identity=identity, source_date_epoch=epoch)
    entries: list[tuple[str, bytes | None]] = [
        ("metadata.yaml", yaml.encode()),
        ("templates", None),
        *((f"templates/{name}", TEMPLATES[name].encode()) for name in sorted(TEMPLATES)),
    ]
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.mtime = epoch
            if data is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(info)
            else:
                info.mode, info.size = 0o644, len(data)
                archive.addfile(info, io.BytesIO(data))
    packed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=packed, compresslevel=9, mtime=0) as handle:
        handle.write(raw.getvalue())
    return packed.getvalue()


def fingerprint(chunks: Iterable[bytes]) -> str:
    """The Incus fingerprint of a split image: the sha256 of the metadata tarball's bytes followed by the
    rootfs's, given in that order as chunks."""
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class Names:
    """The file names of one Incus image: its metadata tarball, its rootfs, and the name its records give
    the image as a whole (the common stem, which carries the fingerprint's first 12 hex)."""

    image: str
    metadata: str
    rootfs: str


def names(image: str, suite: str, arch: str, identity: str, fingerprint_: str) -> Names:
    """`<image>-<suite>-<arch>-<identity16>-<fingerprint12>` with `.incus.tar.gz` and `.rootfs.squashfs`."""
    metadata = artifact_name(image, suite, arch, identity, fingerprint_, METADATA_EXT)
    stem = metadata.removesuffix(f".{METADATA_EXT}")
    return Names(stem, metadata, f"{stem}.{ROOTFS_EXT}")


def rootfs_of(metadata_name: str) -> str | None:
    """The rootfs file name that goes with a metadata tarball's name, or None when it is not one."""
    parsed = parse_artifact_name(metadata_name)
    if parsed is None or parsed.ext != METADATA_EXT:
        return None
    return metadata_name.removesuffix(METADATA_EXT) + ROOTFS_EXT
