"""A small bootable OS root and an installer kit for the boot checks' integration test, in the artifact
formats the factory writes (DESIGN 8.1), built with mmdebstrap in the builder image at the builder's
snapshot: core's package set plus a kernel, GRUB for UEFI, systemd and openssh-server, with the boot kinds'
`uninitialized` machine-id (trixie's own sshd-keygen.service makes the host keys at first boot).

This is a test fixture, not the factory's installer or OS build: it makes boots to check without the rest
of the pipeline. Needs docker, the builder image (`scripts/builder build`) and network access to
snapshot.debian.org.
"""

import hashlib
import io
import json
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from debian_image_factory import published, tools

SUPPORT: Final = Path(__file__).resolve().parent
IDENTITY: Final = "cd" * 32
SUITE: Final = "trixie"
ARCH: Final = "amd64"
EPOCH: Final = 1754697600

PACKAGES: Final = (
    "ca-certificates",
    "tzdata",
    "locales",
    "linux-image-amd64",
    "grub-efi-amd64",
    "systemd-sysv",
    "openssh-server",
)

SCRIPT: Final = r"""
set -eu
root=/scratch/root
mkdir -p /scratch
mmdebstrap --mode=root --variant=apt --format=directory --components=main \
  --include="$PACKAGES" \
  --aptopt='Acquire::Check-Valid-Until "false"' \
  trixie "$root" "deb http://snapshot.debian.org/archive/debian/$SNAPSHOT/ trixie main"
printf 'uninitialized\n' > "$root/etc/machine-id"
rm -f "$root"/etc/ssh/ssh_host_* "$root/var/lib/dbus/machine-id" "$root/etc/hostname" \
  "$root/etc/resolv.conf" "$root/var/lib/systemd/random-seed"
rm -rf "$root"/var/lib/apt/lists/* "$root"/var/cache/apt/*
kernels=$(cd "$root/boot" && ls vmlinuz-*)
kver=${kernels#vmlinuz-}
printf '%s\n' "$kver" > /out/kver
cp "$root/boot/vmlinuz-$kver" /out/vmlinuz
python3 /support/newc.py "$root" /out/initrd.img
tar --sort=name --numeric-owner --format=pax --pax-option=delete=atime,delete=ctime \
  --mtime="@$EPOCH" --clamp-mtime -C "$root" -cf - . | gzip -9n > /out/os.tar.gz
"""


@dataclass(frozen=True, slots=True)
class Built:
    os_root: Path
    os_digest: str
    kit: Path
    kit_digest: str
    kernel: str


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def kit_bytes(kernel: str, vmlinuz: bytes, initrd: bytes) -> bytes:
    """The kit tarball (DESIGN 8.1): `kit.json`, `vmlinuz`, `initrd.img`, mode 0644, root, the epoch."""
    files = {
        name: {"sha256": sha256(data), "size": len(data)}
        for name, data in (("vmlinuz", vmlinuz), ("initrd.img", initrd))
    }
    manifest = (
        json.dumps(
            {"schema": 1, "image": "installer", "kernel": kernel, "files": files}, sort_keys=True, separators=(",", ":")
        ).encode()
        + b"\n"
    )
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in (("kit.json", manifest), ("vmlinuz", vmlinuz), ("initrd.img", initrd)):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o644, EPOCH
            archive.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def build(out: Path, builder: str = tools.BUILDER_IMAGE) -> Built:
    """Build both into `out` under their artifact names (the scratch files beside them are removed)."""
    subprocess.run(
        [
            "docker", "run", "--rm", "--privileged",
            "-e", f"PACKAGES={','.join(PACKAGES)}",
            "-e", f"SNAPSHOT={tools.BUILDER_SNAPSHOT}",
            "-e", f"EPOCH={EPOCH}",
            "-v", f"{out}:/out",
            "-v", f"{SUPPORT / 'newc.py'}:/support/newc.py:ro",
            builder, "bash", "-c", SCRIPT,
        ],
        check=True,
        stdin=subprocess.DEVNULL,
    )  # fmt: skip
    kernel = (out / "kver").read_text().strip()
    root_bytes = (out / "os.tar.gz").read_bytes()
    os_digest = sha256(root_bytes)
    os_root = out / published.artifact_name("os", SUITE, ARCH, IDENTITY, os_digest, "tar.gz")
    (out / "os.tar.gz").rename(os_root)
    kit = kit_bytes(kernel, (out / "vmlinuz").read_bytes(), (out / "initrd.img").read_bytes())
    kit_digest = sha256(kit)
    kit_path = out / published.artifact_name("installer", SUITE, ARCH, IDENTITY, kit_digest, "tar")
    kit_path.write_bytes(kit)
    for scratch in ("kver", "vmlinuz", "initrd.img"):
        (out / scratch).unlink()
    return Built(os_root, os_digest, kit_path, kit_digest, kernel)
