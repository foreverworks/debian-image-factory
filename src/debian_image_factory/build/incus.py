"""What an Incus image's build runs in the builder (DESIGN 5.3, 8.1), as text. Pure.

The builder sees `/mirror` (read-only) and `/factory`, this build's work directory, as for core, and has
no network. The work directory holds the parent's root filesystem (`parent.tar.gz`, core's tarball, or
`parent.squashfs`, an Incus parent's rootfs), the device nodes it holds (`devices.pseudo`, `devices.list`),
the layer program, and what every child build reads: the keyring, the file tree, the hooks with their
inputs and build.env. `build.sh` then:

1. unpacks the parent's root into `/factory/root`. Device nodes cannot be made in a user namespace
   (rootless Docker), so they are left out here and put back in step 5 from the parent's own listing;
2. enters the root with proc, a minimal /dev and the mirror mounted, and installs the kind's packages and
   the image's own with the image's apt, as an OCI child does (build/oci.py), then the file tree, the
   modules and the hooks;
3. cleans up as every child does: apt's lists and caches, logs, every machine identity;
4. makes it a system that boots in Incus: `/etc/machine-id` is `uninitialized` and SSH host keys are
   made at first boot (the boot lines every kind that boots shares), systemd-networkd brings up the
   network cloud-init writes, and cloud-init reads only the NoCloud seed the image's templates fill;
5. packs the root as a squashfs with its gzip compressor: owners, modes and extended attributes as they
   are, every time stamp clamped to SOURCE_DATE_EPOCH, the parent's device nodes added from their listing, and
   the same inputs give the same bytes.

The metadata tarball is written outside the builder (`incus.metadata_tarball`), from the plan alone.
"""

import shlex
from collections.abc import Sequence
from typing import Final

from . import core
from . import oci as child

ROOT: Final = child.ROOT
PARENT_TARBALL: Final = f"{core.WORK}/parent.tar.gz"
PARENT_SQUASHFS: Final = f"{core.WORK}/parent.squashfs"
DEVICES_PSEUDO: Final = f"{core.WORK}/devices.pseudo"
"""mksquashfs pseudo definitions of the parent's device nodes: `<path> <c|b> <mode> <uid> <gid> <major> <minor>`."""
DEVICES_LIST: Final = f"{core.WORK}/devices.list"
"""The parent's device node paths, one per line, relative to the root: what unsquashfs leaves out."""
STATE: Final = f"{core.WORK}/parent.state.json"
ROOTFS: Final = f"{core.WORK}/rootfs.squashfs"
STATUS: Final = f"{core.WORK}/dpkg-status"

CLOUD_CONFIG: Final = "etc/cloud/cloud.cfg.d/90-factory-nocloud.cfg"
CLOUD_CONFIG_TEXT: Final = (
    "# Written by debian-image-factory: an Incus image's data comes from the NoCloud seed its templates\n"
    "# fill on create and copy (/var/lib/cloud/seed/nocloud-net), and from nowhere else.\n"
    "datasource_list: [NoCloud, None]\n"
)
NETWORKD_UNIT: Final = "systemd-networkd.service"

SQUASHFS_OPTIONS: Final = ("-comp", "gzip", "-noappend", "-no-progress", "-xattrs", "-quiet")
"""mksquashfs's gzip compressor, as Incus and every reader expect; a new file each time; extended
attributes kept. The exported SOURCE_DATE_EPOCH sets the file system's time stamp and clamps every file's
(mksquashfs refuses it together with `-mkfs-time` or `-all-time`)."""


def unpack_lines(parent: str, source_date_epoch: int) -> list[str]:
    """The parent's root into `$root`: core's tarball through the layer program (which skips the device
    nodes it cannot make), an Incus parent's squashfs through unsquashfs without its device nodes."""
    lines = ["# the parent's root filesystem, without its device nodes (they return when the root is packed)"]
    if parent == "core":
        return [
            *lines,
            'mkdir -p "$root"',
            f'python3 -I {child.LAYER_PROGRAM} unpack --root "$root" --state {STATE} --epoch {int(source_date_epoch)}'
            f" {PARENT_TARBALL}",
        ]
    if parent == "incus":
        return [
            *lines,
            f'unsquashfs -no-progress -quiet -exclude-file {DEVICES_LIST} -d "$root" {PARENT_SQUASHFS}',
        ]
    raise ValueError(f"an Incus image is built on core or on an Incus image, not on {parent!r}")


def setup_lines(*, networkd: bool) -> list[str]:
    """What makes the root an Incus instance's: cloud-init reads the NoCloud seed only, and
    systemd-networkd, when the image has it, brings up the network cloud-init renders for it."""
    lines = [
        "# cloud-init reads the NoCloud seed the image's templates fill, and nothing else",
        f'mkdir -p "$root/{CLOUD_CONFIG.rsplit("/", 1)[0]}"',
        f"printf '%s' {shlex.quote(CLOUD_CONFIG_TEXT)} > \"$root/{CLOUD_CONFIG}\"",
        f'chmod 0644 "$root/{CLOUD_CONFIG}"',
    ]
    if networkd:
        lines += [
            "# systemd-networkd brings up what cloud-init's network configuration says",
            f'if [ -e "$root/usr/lib/systemd/system/{NETWORKD_UNIT}" ]; then',
            f'    chroot "$root" systemctl enable {NETWORKD_UNIT}',
            "fi",
        ]
    return lines


def pack_lines(source_date_epoch: int, owner: str | None) -> list[str]:
    """The root as a squashfs, and dpkg's status beside it for the SBOM."""
    del source_date_epoch  # exported at the top of the script, which is how mksquashfs reads it
    options = " ".join(SQUASHFS_OPTIONS)
    lines = [
        "# dpkg's status of the finished root, for the SBOM",
        f'cp "$root/var/lib/dpkg/status" {STATUS}',
        "# the root as a squashfs: every time stamp clamped to SOURCE_DATE_EPOCH, the parent's device nodes added back",
        f'mksquashfs "$root" {ROOTFS} {options} -pf {DEVICES_PSEUDO}',
    ]
    if owner is not None:
        lines += [f"chown {shlex.quote(owner)} {ROOTFS} {STATUS}"]
    return lines


def build_script(
    *,
    parent: str,
    request: Sequence[str],
    source_date_epoch: int,
    owner: str | None,
    files: bool,
    module_lines: Sequence[str],
    hooks: Sequence[str],
    boot_lines: Sequence[str],
) -> str:
    """The builder's entry point for one Incus image. `parent` is the parent's kind (`core` or `incus`);
    `request` what apt installs (the kind's packages and the image's own); `module_lines` what the
    switched-on builtin modules run with the root as `$root`; `hooks` the scripts run in the chroot after
    them; `boot_lines` what every kind that boots writes into its root (DESIGN 5.3); `owner` (`uid:gid`)
    hands the outputs back where the container's root is the host's."""
    cleanup_trap = [
        "cleanup() {",
        "    status=$?",
        *(f"    {line}" for line in child.unmount_lines(mirror=bool(request), quiet=True)),
        f'    rm -rf --one-file-system "$root" {child.ASIDE}',
        '    exit "$status"',
        "}",
        "trap cleanup EXIT",
    ]
    lines = [
        "set -eu",
        f"export SOURCE_DATE_EPOCH={int(source_date_epoch)}",
        *child.ENVIRONMENT,
        "umask 022",
        f'root="{ROOT}"',
        *cleanup_trap,
        *unpack_lines(parent, source_date_epoch),
        *child.mount_lines(),
    ]
    if request:
        lines += [*child.apt_setup_lines(), *child.install_lines(request)]
    if files:
        lines += core.files_lines()
    lines += list(module_lines)
    if hooks:
        lines += [
            *core.hook_lines(hooks),
            *(f'rm -rf "$root{core.HOOK_DIR}/{name}"' for name in ("hooks", "inputs", "build.env")),
        ]
    if request:
        lines += child.apt_cleanup_lines()
    lines += [
        *setup_lines(networkd=True),
        *child.trace_lines(),
        *core.identity_lines(),
        *boot_lines,
        *child.unmount_lines(mirror=bool(request)),
        *child.run_cleanup_lines(),
        *pack_lines(source_date_epoch, owner),
        "",
    ]
    return "\n".join(lines)


def device_pseudo(path: str, kind: str, mode: int, uid: int, gid: int, major: int, minor: int) -> str:
    """One mksquashfs pseudo definition of a device node; `path` is absolute in the image."""
    if kind not in ("char", "block"):
        raise ValueError(f"{path}: {kind} is not a device node")
    if any(char.isspace() for char in path):
        raise ValueError(f"{path}: a device node path with white space cannot be written as a pseudo definition")
    letter = "c" if kind == "char" else "b"
    return f"{path} {letter} {mode & 0o7777:o} {uid} {gid} {major} {minor}\n"
