"""The boot checks' edge: QEMU in the boot checks' container image, under docker (DESIGN 12).

One container run boots an artifact as many times as the checks need (two for `two-clones`, whose first
boot `installer-boot` or `os-boot` also judges), all at once. KVM is used when /dev/kvm opens here (it is
passed in with `--device`), TCG otherwise, with a longer time limit. The container gets no network. Its
inputs and the serial logs live in a scratch directory beside the artifact (docker mounts host paths, and
the artifact's own directory is one docker sees); the unpacked root and the disk images stay inside the
container and go with it.
"""

import contextlib
import math
import os
import posixpath
import shutil
import subprocess
import tarfile
import tempfile
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .. import tools
from . import vm
from .dockerio import LimitedRunner, run_docker_limited
from .kit import INITRD, VMLINUZ

CHUNK: Final = 1024 * 1024
BLOCK: Final = 4096
UNPREPARED: Final = 3
"""The exit status of the OS script when the root cannot be made bootable (no GRUB for UEFI in it)."""


def kvm_usable() -> bool:
    """Whether /dev/kvm opens for reading and writing here."""
    try:
        handle = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    except OSError:
        return False
    os.close(handle)
    return True


@dataclass(frozen=True, slots=True)
class Vm:
    """What the boot checks reach outside the process through, and their time limits (seconds per boot)."""

    image: str = tools.VM_IMAGE
    run: LimitedRunner = run_docker_limited
    kvm: Callable[[], bool] = kvm_usable
    kvm_timeout_s: int = 600
    tcg_timeout_s: int = 2400
    prepare_timeout_s: int = 1800
    """Unpacking the root, GRUB, and the filesystem images, before the OS boots."""


VM: Final = Vm()


@dataclass(frozen=True, slots=True)
class Unready:
    """The boots did not happen: why, and whether the artifact is the cause (a root that cannot be made
    bootable) or this machine is (no docker, no boot image)."""

    reason: str
    artifact_fault: bool = False


@dataclass(frozen=True, slots=True)
class RootFacts:
    """What laying an OS root onto a disk needs to know of its tarball."""

    content_bytes: int
    """Every member rounded up to its 4 KiB blocks."""
    files: int
    kernels: tuple[str, ...]
    """The versions of `/boot/vmlinuz-*`."""


def root_facts(path: Path) -> RootFacts:
    """One pass over the OS tarball's member headers. Raises tarfile.TarError or OSError when it cannot be read."""
    content = files = 0
    kernels: list[str] = []
    with tarfile.open(path, mode="r|*") as archive:
        for info in archive:
            files += 1
            content += math.ceil(info.size / BLOCK) * BLOCK if info.isreg() else BLOCK
            name = posixpath.normpath("/" + info.name)
            if posixpath.dirname(name) == "/boot" and posixpath.basename(name).startswith("vmlinuz-"):
                kernels.append(posixpath.basename(name).removeprefix("vmlinuz-"))
    return RootFacts(content, files, tuple(sorted(kernels)))


def problem_with(machine: Vm) -> str | None:
    """Why the boot image cannot be run here, or None."""
    try:
        found = machine.run(["image", "inspect", "--format", "{{.Id}}", machine.image], 60)
    except (OSError, subprocess.SubprocessError) as error:
        return f"docker is not available: {error}"
    if found.returncode != 0:
        how = f"docker pull {machine.image}" if "@sha256:" in machine.image else "scripts/builder vm builds it"
        return f"the boot image {machine.image} is not here ({how}): {found.stderr.strip()}"
    return None


def last_lines(text: str, lines: int = 6) -> str:
    return " | ".join(line.strip() for line in text.strip().splitlines()[-lines:] if line.strip())


def run_boots(
    machine: Vm, work: Path, mounts: Sequence[str], script: str, count: int, timeout_s: int, kvm: bool
) -> list[vm.Boot] | Unready:
    """Run `script` in the boot image with `work` as vm.WORK; read each boot's exit status and serial log."""
    name = f"dif-boot-{uuid.uuid4().hex[:12]}"
    (work / "run.sh").write_text(script)
    args = [
        "run", "--rm", "--name", name, "--network", "none",
        *(["--device", "/dev/kvm"] if kvm else []),
        "-v", f"{work}:{vm.WORK}",
        *mounts,
        machine.image, "bash", f"{vm.WORK}/run.sh",
    ]  # fmt: skip
    limit = machine.prepare_timeout_s + timeout_s + 120
    try:
        ran = machine.run(args, limit)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            machine.run(["rm", "--force", name], 60)
        ran = None
    except (OSError, subprocess.SubprocessError) as error:
        return Unready(f"docker failed: {error}")
    if ran is not None and ran.returncode != 0 and not (work / "exit-1").exists():
        output = last_lines(ran.stderr or ran.stdout)
        return Unready(f"the boot did not start (exit {ran.returncode}): {output}", ran.returncode == UNPREPARED)
    boots: list[vm.Boot] = []
    for n in range(1, count + 1):
        status_file, log, port = work / f"exit-{n}", work / f"serial-{n}.log", work / f"report-{n}.log"
        status = int(status_file.read_text().strip() or "-1") if status_file.exists() else None
        serial = log.read_bytes().decode("utf-8", "replace") if log.exists() else ""
        report = port.read_bytes().decode("utf-8", "replace") if port.exists() else ""
        boots.append(vm.boot_of(status, serial, timeout_s, report))
    return boots


def work_dir(beside: Path) -> Path:
    """A scratch directory beside the artifact, with the credentials the guest reads."""
    work = Path(tempfile.mkdtemp(prefix=".boot-", dir=beside.parent))
    for file_name, content in vm.credential_files():
        (work / file_name).write_text(content)
    return work


def remove(work: Path) -> None:
    """The scratch directory and what the container wrote there (files only, so its owner may unlink them
    even when a rootful docker made them)."""
    shutil.rmtree(work, ignore_errors=True)


def accel_and_limit(machine: Vm) -> tuple[bool, vm.Accel, int]:
    kvm = machine.kvm()
    return kvm, "kvm" if kvm else "tcg", machine.kvm_timeout_s if kvm else machine.tcg_timeout_s


def boot_installer(kit: Path, count: int, machine: Vm = VM) -> list[vm.Boot] | Unready:
    """Boot the kit `count` times at once from its own kernel and initrd."""
    problem = problem_with(machine)
    if problem is not None:
        return Unready(problem)
    work = work_dir(kit)
    try:
        with tarfile.open(kit, mode="r:") as archive:
            for member in (VMLINUZ, INITRD):
                source = archive.extractfile(member)
                if source is None:
                    return Unready(f"the kit has no regular file {member}", True)
                with source, (work / member).open("wb") as target:
                    shutil.copyfileobj(source, target, CHUNK)
        kvm, accel, limit = accel_and_limit(machine)
        size = (work / INITRD).stat().st_size
        script = vm.installer_script(vm.Machine(accel, vm.installer_memory_mib(size)), count, limit)
        return run_boots(machine, work, [], script, count, limit, kvm)
    except (KeyError, tarfile.TarError) as error:
        return Unready(f"the kit cannot be read: {error}", True)
    finally:
        remove(work)


def boot_os(root: Path, facts: RootFacts, count: int, machine: Vm = VM) -> list[vm.Boot] | Unready:
    """Lay the OS root onto a scratch GPT disk (ESP with the OS's own standalone GRUB, ext4 root) and boot
    a copy of it `count` times at once by UEFI."""
    if len(facts.kernels) != 1:
        return Unready(f"/boot holds {len(facts.kernels)} kernels, not one", True)
    problem = problem_with(machine)
    if problem is not None:
        return Unready(problem)
    work = work_dir(root)
    try:
        layout = vm.disk_layout(vm.root_mib(facts.content_bytes, facts.files))
        (work / "grub.cfg").write_text(vm.grub_cfg(facts.kernels[0]))
        (work / "layout.sfdisk").write_text(layout.sfdisk)
        kvm, accel, limit = accel_and_limit(machine)
        script = vm.os_script(vm.Machine(accel, vm.OS_MEMORY_MIB), layout, count, limit)
        mounts = ["-v", f"{root.resolve()}:{vm.ARTIFACT}/root.tar.gz:ro"]
        return run_boots(machine, work, mounts, script, count, limit, kvm)
    finally:
        remove(work)
