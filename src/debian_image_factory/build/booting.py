"""What an installer or os image's build runs in the builder (DESIGN 5.3, 8.1), as text. Pure.

Both kinds build exactly like an OCI child (`oci.child_lines`): the parent's filesystem is unpacked into
`/factory/root`, the image's packages, file tree, modules and hooks go in with the image's own apt from
the mirror, then the build's traces and every machine identity are removed. Then they differ from OCI in
three ways:

- the parent's filesystem is one file. A core or os parent is its root filesystem tarball, unpacked by
  layer.py as a single layer; an installer parent is its kit, whose `initrd.img` initrd.py unpacks.
- the image carries its own apt sources (`apt_sources`: live, or pinned to the baseline snapshot), written
  where core writes them and replacing whatever the parent had; the build snapshot never appears there.
- the root ends as a booting root (`boot.boot_lines`) and is packed whole: an os image as one root
  filesystem tarball (`layer.py pack --full`), an installer as its kit (`initrd.py kit`).

A kernel package's postinst (initramfs-tools writing `/boot/initrd.img-<kver>`) runs in the chroot with
proc and the minimal /dev that `oci.mount_lines` gives it.
"""

import shlex
from collections.abc import Sequence
from typing import Final

from . import boot, core, oci

INITRD_PROGRAM: Final = f"{core.WORK}/initrd.py"
PARENT_KIT: Final = f"{core.WORK}/parent.tar"
"""An installer parent's kit, whose initrd is the child's starting root."""
ROOTFS: Final = f"{core.WORK}/os.tar.gz"
"""What an os build leaves in the work directory: the whole root filesystem."""
KIT: Final = f"{core.WORK}/kit.tar"
"""What an installer build leaves in the work directory: the kit."""
KINDS: Final = ("installer", "os")


def unpack_kit_lines() -> list[str]:
    """An installer parent's initrd as the root, with the device nodes this build cannot create recorded."""
    return [
        "# the parent installer's initrd, unpacked, and the device nodes it holds that cannot be created here",
        'mkdir -p "$root"',
        f'python3 -I {INITRD_PROGRAM} unpack --root "$root" --state {oci.STATE} --kit {PARENT_KIT}',
    ]


def handed_back(outputs: Sequence[str], owner: str | None) -> list[str]:
    """Hand `outputs` to the invoking user where the container's root is the host's."""
    if owner is None:
        return []
    return [
        f"for output in {' '.join(outputs)}; do",
        f'    if [ -e "$output" ]; then chown {shlex.quote(owner)} "$output"; fi',
        "done",
    ]


def os_pack_lines(source_date_epoch: int, owner: str | None) -> list[str]:
    """The whole root as the os image's tarball: what layer.py writes for a child layer, applied to every
    path (an empty parent state)."""
    return [
        "# the whole root filesystem, every path, as one tarball",
        f'python3 -I {oci.LAYER_PROGRAM} pack --full --root "$root" --state {oci.STATE}'
        f" --epoch {int(source_date_epoch)} --out {ROOTFS} --status-out {oci.STATUS}",
        *handed_back((ROOTFS, oci.STATUS), owner),
    ]


def installer_pack_lines(image: str, source_date_epoch: int, owner: str | None) -> list[str]:
    """The root as the installer's kit: kit.json, the kernel and the whole root as an initrd."""
    return [
        "# the kit: kit.json, the image's kernel and the whole root as its initrd",
        f'python3 -I {INITRD_PROGRAM} kit --root "$root" --state {oci.STATE} --epoch {int(source_date_epoch)}'
        f" --image {shlex.quote(image)} --out {KIT} --status-out {oci.STATUS}",
        *handed_back((KIT, oci.STATUS), owner),
    ]


def build_script(
    *,
    kind: str,
    image: str,
    parent_kind: str,
    request: Sequence[str],
    source_date_epoch: int,
    owner: str | None,
    files: bool,
    module_lines: Sequence[str],
    hooks: Sequence[str],
    debs: Sequence[str] = (),
) -> str:
    """The builder's entry point for one installer or os image built on a `parent_kind` parent (core, or
    one of its own kind). The arguments are `oci.build_script`'s (`debs`: the builder paths of the
    image's vendor .deb files); `image` names the kit's image."""
    if kind not in KINDS:
        raise ValueError(f"{kind!r} is not a kind this script builds ({', '.join(KINDS)})")
    if parent_kind not in ("core", kind):
        raise ValueError(f"an {kind} image is built on core or another {kind} image, not on {parent_kind}")
    unpack = unpack_kit_lines() if parent_kind == "installer" else oci.unpack_lines(1, source_date_epoch)
    pack = (
        os_pack_lines(source_date_epoch, owner)
        if kind == "os"
        else installer_pack_lines(image, source_date_epoch, owner)
    )
    lines = [
        *oci.prologue_lines(source_date_epoch, mirror=bool(request or debs)),
        *unpack,
        *oci.child_lines(
            request=request,
            files=files,
            module_lines=module_lines,
            hooks=hooks,
            debs=debs,
            sources=core.sources_lines(),
            finish=boot.boot_lines(),
        ),
        *pack,
        "",
    ]
    return "\n".join(lines)
