"""The boot checks' harness, pure (DESIGN 11, 12): `installer-boot`, `os-boot` and `two-clones` for the
installer and OS kinds.

QEMU boots the exact artifact inside the boot checks' container image (`builder/vm.Dockerfile`); the
harness never changes the artifact. The guest reports through two systemd credentials passed as SMBIOS
type 11 OEM strings: an extra unit, `factory-report.service`, that waits for the boot to finish and writes
one `FACTORY-REPORT` line to a second serial port, apart from the console, before powering off, and a drop-in that makes
`multi-user.target` want it. Everything here is text and argument lists: the QEMU command lines, the
credentials, the OS disk's GPT layout and embedded grub.cfg, the script the container runs, and the
reading of the serial log into results. `vmrun` runs it.
"""

import base64
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Literal

from .model import INSTALLER_BOOT, OS_BOOT, TWO_CLONES, Result, result, split

REPORT_UNIT_NAME: Final = "factory-report.service"
REPORT_MARKER: Final = "FACTORY-REPORT"
ROOT_LABEL: Final = "factory-root"
SERIAL: Final = "/dev/ttyS1"
"""The report's own port, apart from the console (ttyS0). On the console the kernel prints through the same
UART, straight past the tty's transmit buffer, so a message printed while the report drains lands in the
middle of the report line; and the guest can power off before the buffer is empty."""

MIB: Final = 1024 * 1024
SECTOR: Final = 512
ESP_MIB: Final = 64
"""The scratch disk's EFI system partition: room for one standalone GRUB image, and FAT32's minimum."""

REPORT_SCRIPT: Final = (
    "state=$(systemctl is-system-running --wait); "
    "kernel=$(uname -r); "
    "machine=$(cat /etc/machine-id 2>/dev/null || echo none); "
    "if ls /etc/ssh/ssh_host_*_key.pub >/dev/null 2>&1; "
    "then ssh=$(cat /etc/ssh/ssh_host_*_key.pub | sort | sha256sum | cut -d ' ' -f 1); "
    "else ssh=none; fi; "
    f"{{ echo; echo {REPORT_MARKER} kernel=$kernel machine-id=$machine ssh=$ssh state=${{state:-unknown}}; }} "
    f"> {SERIAL}; "
    "systemctl --no-block poweroff"
)
"""What the report unit runs: wait until the boot is over (`running`, or `degraded` when a unit failed), then
one line with the running kernel, the machine ID, the sha256 of the sorted SSH host public keys (`none`
without any) and the state, on the serial port, and power off."""


def unit_quoted(script: str) -> str:
    """`script` as one double-quoted argument of an `Exec` line: `$` and `%` doubled, so systemd expands
    neither its environment nor its specifiers. The script holds no double quote and no backslash."""
    if '"' in script or "\\" in script:
        raise ValueError("the report script must hold no double quote and no backslash")
    return '"' + script.replace("%", "%%").replace("$", "$$") + '"'


REPORT_UNIT: Final = f"""[Unit]
Description=Report this boot to the factory's boot check

[Service]
Type=simple
ExecStart=/bin/sh -c {unit_quoted(REPORT_SCRIPT)}
"""
"""`Type=simple`, not oneshot: a oneshot's start job would keep the boot from finishing, and the script waits
for exactly that."""

TARGET_DROPIN: Final = f"""[Unit]
Wants={REPORT_UNIT_NAME}
"""

CREDENTIALS: Final = (
    (f"systemd.extra-unit.{REPORT_UNIT_NAME}", REPORT_UNIT),
    ("systemd.unit-dropin.multi-user.target", TARGET_DROPIN),
)
"""The two systemd credentials (systemd.system-credentials(7)), by name and value."""


def smbios_string(name: str, value: str) -> str:
    """One SMBIOS type 11 OEM string carrying a systemd credential, its value in base64 (the `binary`
    form), so no comma, newline or quote of the unit text meets QEMU's option parser."""
    return f"io.systemd.credential.binary:{name}={base64.b64encode(value.encode()).decode()}"


def credential_files() -> list[tuple[str, str]]:
    """(file name, content) for each credential: QEMU reads each OEM string from its file (`path=`)."""
    return [(f"credential-{n}.txt", smbios_string(name, value)) for n, (name, value) in enumerate(CREDENTIALS, 1)]


# ---- QEMU ----------------------------------------------------------------------------------------------


type Accel = Literal["kvm", "tcg"]


@dataclass(frozen=True, slots=True)
class Machine:
    accel: Accel
    memory_mib: int
    cpus: int = 2


OVMF_CODE: Final = "/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS: Final = "/usr/share/OVMF/OVMF_VARS_4M.fd"


def common_args(machine: Machine, serial: str, report: str, credentials: Sequence[str]) -> list[str]:
    accel = (
        ["-accel", "kvm", "-cpu", "host"] if machine.accel == "kvm" else ["-accel", "tcg,thread=multi", "-cpu", "max"]
    )
    args = [
        "qemu-system-x86_64",
        "-machine", "q35",
        *accel,
        "-m", str(machine.memory_mib),
        "-smp", str(machine.cpus),
        "-nodefaults",
        "-no-user-config",
        "-display", "none",
        "-no-reboot",
        "-nic", "none",
        "-serial", f"file:{serial}",
        "-serial", f"file:{report}",
    ]  # fmt: skip
    for path in credentials:
        args += ["-smbios", f"type=11,path={path}"]
    return args


def installer_args(
    machine: Machine, vmlinuz: str, initrd: str, serial: str, report: str, credentials: Sequence[str]
) -> list[str]:
    """The kit booted from RAM: its kernel, its initrd as the whole system, the console on the serial port."""
    return [
        *common_args(machine, serial, report, credentials),
        "-kernel", vmlinuz,
        "-initrd", initrd,
        "-append", "console=ttyS0",
    ]  # fmt: skip


def os_args(
    machine: Machine, disk: str, varstore: str, serial: str, report: str, credentials: Sequence[str]
) -> list[str]:
    """The scratch disk booted by OVMF (UEFI), from its EFI system partition's `EFI/BOOT/BOOTX64.EFI`."""
    return [
        *common_args(machine, serial, report, credentials),
        "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={OVMF_CODE}",
        "-drive", f"if=pflash,format=raw,unit=1,file={varstore}",
        "-drive", f"file={disk},format=raw,if=virtio",
    ]  # fmt: skip


def installer_memory_mib(initrd_size: int) -> int:
    """Room for the compressed initrd, the system it unpacks into RAM (gzip of a root is about a third of
    it) and the system running."""
    return 1024 + math.ceil(initrd_size * 5 / MIB)


OS_MEMORY_MIB: Final = 1536


# ---- the OS disk ---------------------------------------------------------------------------------------


def grub_cfg(kernel: str) -> str:
    """The config the standalone GRUB image embeds: find the root by its label, boot the OS's own kernel and
    initramfs with the root by label and the console on the serial port. The root is mounted read-write
    from the start (`rw`): an OS root has no fstab entry for itself, so nothing would remount it, and first
    boot must be able to write its machine ID and host keys."""
    return f"""set timeout=0
insmod part_gpt
insmod ext2
insmod search_label
search --no-floppy --label --set=root {ROOT_LABEL}
linux /boot/vmlinuz-{kernel} root=LABEL={ROOT_LABEL} rw console=ttyS0
initrd /boot/initrd.img-{kernel}
boot
"""


@dataclass(frozen=True, slots=True)
class Layout:
    """The scratch disk: its GPT as `sfdisk` reads it, where each filesystem image goes (in MiB from the
    start) and the disk's whole size."""

    sfdisk: str
    esp_start_mib: int
    root_start_mib: int
    root_mib: int
    total_mib: int


ESP_TYPE: Final = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
LINUX_ROOT_X86_64: Final = "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"


def root_mib(content_bytes: int, files: int) -> int:
    """An ext4 root for the unpacked tree: every file rounded up to its 4 KiB blocks (`content_bytes` is
    that sum), a quarter more for metadata, and 512 MiB for what the first boots write."""
    return math.ceil((content_bytes + files * 256) * 1.25 / MIB) + 512


def disk_layout(root_size_mib: int) -> Layout:
    """A GPT disk: 1 MiB for the table, the ESP, the root, 1 MiB for the backup table."""
    sectors = MIB // SECTOR
    esp_start, root_start = 1, 1 + ESP_MIB
    text = (
        "label: gpt\n"
        "unit: sectors\n"
        f"sector-size: {SECTOR}\n"
        "\n"
        f'start={esp_start * sectors}, size={ESP_MIB * sectors}, type={ESP_TYPE}, name="EFI system"\n'
        f'start={root_start * sectors}, size={root_size_mib * sectors}, type={LINUX_ROOT_X86_64}, name="{ROOT_LABEL}"\n'
    )
    return Layout(text, esp_start, root_start, root_size_mib, root_start + root_size_mib + 1)


# ---- the scripts the container runs --------------------------------------------------------------------

WORK: Final = "/work"
"""The host's scratch directory in the container: the inputs the harness wrote and the serial logs."""
ARTIFACT: Final = "/artifact"
"""The artifact, mounted read-only."""
SCRATCH: Final = "/scratch"
"""Inside the container's own filesystem: the unpacked root and the disk images, gone with the container."""


def serial_log(n: int) -> str:
    return f"{WORK}/serial-{n}.log"


def report_log(n: int) -> str:
    return f"{WORK}/report-{n}.log"


def boots_script(commands: Sequence[Sequence[str]], timeout_s: int) -> str:
    """Start every boot at once, each under `timeout`, and wait for all; each one's exit status goes to
    `exit-<n>` (124 when it ran out of time)."""
    lines = []
    for n, command in enumerate(commands, 1):
        quoted = " ".join(shell_quote(part) for part in command)
        lines.append(f"( timeout --kill-after=10 {timeout_s} {quoted}; echo $? > {WORK}/exit-{n} ) &")
    lines.append("wait")
    return "\n".join(lines) + "\n"


def shell_quote(text: str) -> str:
    return text if re.fullmatch(r"[A-Za-z0-9_./:=,+@-]+", text) else "'" + text.replace("'", "'\\''") + "'"


def installer_script(machine: Machine, count: int, timeout_s: int) -> str:
    """Boot the kit (its two files in WORK) `count` times at once."""
    credentials = [f"{WORK}/{name}" for name, _ in credential_files()]
    commands = [
        installer_args(machine, f"{WORK}/vmlinuz", f"{WORK}/initrd.img", serial_log(n), report_log(n), credentials)
        for n in range(1, count + 1)
    ]
    return "set -eu\n" + boots_script(commands, timeout_s)


def os_script(machine: Machine, layout: Layout, count: int, timeout_s: int) -> str:
    """Lay the root (ARTIFACT/root.tar.gz) onto a scratch disk and boot a copy of it `count` times at once.

    The root is unpacked without device nodes, which a user namespace cannot make and the booted system
    gets from devtmpfs. GRUB is the OS's own: `grub-mkstandalone` runs in a chroot of the unpacked root and
    its output and the config it read are removed before the ext4 image is made from the tree."""
    credentials = [f"{WORK}/{name}" for name, _ in credential_files()]
    root = f"{SCRATCH}/root"
    prepare = f"""set -eu
mkdir -p {root}
tar -xpzf {ARTIFACT}/root.tar.gz -C {root} --numeric-owner --xattrs --xattrs-include='*' \\
    --anchored --exclude='dev/*' --exclude='./dev/*'
test -x {root}/usr/bin/grub-mkstandalone || {{ echo "the OS has no grub-mkstandalone" >&2; exit 3; }}
test -d {root}/usr/lib/grub/x86_64-efi || {{ echo "the OS has no GRUB for x86_64-efi" >&2; exit 3; }}
cp {WORK}/grub.cfg {root}/tmp/factory-grub.cfg
chroot {root} grub-mkstandalone -O x86_64-efi -o /tmp/factory-bootx64.efi boot/grub/grub.cfg=/tmp/factory-grub.cfg
mv {root}/tmp/factory-bootx64.efi {SCRATCH}/bootx64.efi
rm -f {root}/tmp/factory-grub.cfg
truncate -s {ESP_MIB}M {SCRATCH}/esp.img
mkfs.vfat -F 32 -n FACTORY-ESP {SCRATCH}/esp.img >/dev/null
mmd -i {SCRATCH}/esp.img ::/EFI ::/EFI/BOOT
mcopy -i {SCRATCH}/esp.img {SCRATCH}/bootx64.efi ::/EFI/BOOT/BOOTX64.EFI
mkfs.ext4 -q -F -L {ROOT_LABEL} -d {root} {SCRATCH}/root.img {layout.root_mib}M
rm -rf {root}
truncate -s {layout.total_mib}M {SCRATCH}/disk.img
sfdisk -q {SCRATCH}/disk.img < {WORK}/layout.sfdisk
dd if={SCRATCH}/esp.img of={SCRATCH}/disk.img bs=1M seek={layout.esp_start_mib} conv=notrunc,sparse status=none
dd if={SCRATCH}/root.img of={SCRATCH}/disk.img bs=1M seek={layout.root_start_mib} conv=notrunc,sparse status=none
rm -f {SCRATCH}/esp.img {SCRATCH}/root.img
"""
    copies = "".join(
        f"cp --sparse=always {SCRATCH}/disk.img {SCRATCH}/disk-{n}.img\ncp {OVMF_VARS} {SCRATCH}/vars-{n}.fd\n"
        for n in range(1, count + 1)
    )
    commands = [
        os_args(machine, f"{SCRATCH}/disk-{n}.img", f"{SCRATCH}/vars-{n}.fd", serial_log(n), report_log(n), credentials)
        for n in range(1, count + 1)
    ]
    return prepare + copies + f"rm -f {SCRATCH}/disk.img\n" + boots_script(commands, timeout_s)


# ---- reading what came back ---------------------------------------------------------------------------

REPORT_LINE: Final = re.compile(
    rf"{REPORT_MARKER} kernel=(?P<kernel>\S+) machine-id=(?P<machine_id>\S*) ssh=(?P<ssh>\S+) state=(?P<state>\S*)"
)
ESCAPES: Final = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|[\x00-\x08\x0b-\x1f\x7f]")
TAIL_LINES: Final = 8
TAIL_WIDTH: Final = 160


@dataclass(frozen=True, slots=True)
class Report:
    kernel: str
    machine_id: str
    ssh: str
    """The sha256 of the sorted host public keys, or `none`."""
    state: str


@dataclass(frozen=True, slots=True)
class Boot:
    """One boot: its report, or what went wrong (no report in time, QEMU failing), and its serial log."""

    report: Report | None
    problem: str | None
    serial: str


def parse_report(serial: str) -> Report | None:
    """The last report line on the serial log, or None."""
    found = list(REPORT_LINE.finditer(serial))
    if not found:
        return None
    last = found[-1]
    return Report(last["kernel"], last["machine_id"], last["ssh"], last["state"])


def tail(serial: str, lines: int = TAIL_LINES) -> str:
    """The last non-empty lines of a serial log, control characters and colour codes removed, each cut to
    TAIL_WIDTH, joined with ` | `: enough to see where a boot stopped, small enough for a record."""
    kept = [ESCAPES.sub("", line).strip() for line in serial.replace("\r", "\n").splitlines()]
    kept = [line[:TAIL_WIDTH] for line in kept if line]
    return " | ".join(kept[-lines:]) if kept else "(the serial log is empty)"


def boot_of(exit_status: int | None, serial: str, timeout_s: int, report_port: str = "") -> Boot:
    """A boot from QEMU's exit status (None when it never ran), its console log and what the guest wrote to
    the report port. The report is on the port; one on the console counts too."""
    report = parse_report(report_port) or parse_report(serial)
    if report is not None:
        return Boot(report, None, serial)
    if exit_status == 124 or exit_status == 137:
        problem = f"no {REPORT_MARKER} line within {timeout_s} s"
    elif exit_status is None:
        problem = "QEMU did not run"
    elif exit_status == 0:
        problem = f"QEMU exited 0 (the guest powered off) without a {REPORT_MARKER} line"
    else:
        problem = f"QEMU exited {exit_status} without a {REPORT_MARKER} line"
    written = next((text for text in (report_port, serial) if REPORT_MARKER in text), "")
    if written:
        partial = tail(written[written.index(REPORT_MARKER) :], 1)
        problem += f"; a {REPORT_MARKER} was written but is not whole: {partial}"
    elif exit_status == 0:
        problem += "; the report port was empty" if not report_port.strip() else "; the report port held none"
    return Boot(None, problem, serial)


def log_name(artifact_name: str, n: int) -> str:
    """Where a boot's serial log is kept, beside the artifact, when a check on it failed."""
    return f"{artifact_name}.boot-{n}.serial.log"


def unreported(test: str, boot: Boot, artifact_name: str, n: int) -> str:
    return f"{test}: boot {n}: {boot.problem}; serial log {log_name(artifact_name, n)}, ending: {tail(boot.serial)}"


REPORTED: Final = "report-arrived"
NO_IDENTITY: Final = ("", "uninitialized", "none")


def installer_boot(kit_kernel: str | None, kit_problems: Sequence[str], boot: Boot, artifact_name: str) -> Result:
    """`installer-boot`: the kit is what its kit.json says, it boots from RAM to the report, and the running
    kernel is the one kit.json names."""
    ok_kit, bad_kit = split("kit-json-matches-files", list(kit_problems))
    if boot.report is None:
        return result(INSTALLER_BOOT, ok_kit, failed=[*bad_kit, unreported(REPORTED, boot, artifact_name, 1)])
    running = boot.report.kernel
    kernel_problems = [] if running == kit_kernel else [f"the running kernel is {running}, kit.json names {kit_kernel}"]
    ok_kernel, bad_kernel = split("running-kernel-is-the-kit-kernel", kernel_problems)
    return result(INSTALLER_BOOT, [*ok_kit, REPORTED, *ok_kernel], failed=[*bad_kit, *bad_kernel])


def os_boot(installed_kernel: str | Sequence[str], wants_ssh: bool, boot: Boot, artifact_name: str) -> Result:
    """`os-boot`: the root laid onto a disk boots by UEFI to multi-user (`degraded` is a warning), the running
    kernel is the one in /boot, first boot made a machine ID and, with openssh-server, SSH host keys.
    `installed_kernel` is the kernel version in /boot, or the `/boot/vmlinuz-*` found when not exactly one."""
    if boot.report is None:
        return result(OS_BOOT, [], failed=[unreported(REPORTED, boot, artifact_name, 1)])
    report = boot.report
    passed, warned, failed = [REPORTED], [], []
    if report.state == "running":
        passed.append("system-running")
    elif report.state == "degraded":
        warned.append("system-running: the system is degraded (a unit failed)")
    else:
        failed.append(f"system-running: the system is {report.state}")
    if isinstance(installed_kernel, str):
        kernel = [] if report.kernel == installed_kernel else [f"running {report.kernel}, /boot has {installed_kernel}"]
    else:
        kernel = [f"/boot holds {len(installed_kernel)} kernels, not one: {', '.join(installed_kernel) or 'none'}"]
    ok, bad = split("running-kernel-is-installed-kernel", kernel)
    passed, failed = [*passed, *ok], [*failed, *bad]
    machine = [] if report.machine_id not in NO_IDENTITY else [f"/etc/machine-id is {report.machine_id or 'empty'}"]
    ok, bad = split("first-boot-made-machine-id", machine)
    passed, failed = [*passed, *ok], [*failed, *bad]
    if wants_ssh:
        ok, bad = split("first-boot-made-ssh-host-keys", ["there are no SSH host keys"] if report.ssh == "none" else [])
        passed, failed = [*passed, *ok], [*failed, *bad]
    return result(OS_BOOT, passed, warned, failed)


def two_clones(boots: Sequence[Boot], artifact_name: str) -> Result:
    """`two-clones` for a boot kind: two boots of the same artifact made different machine IDs and SSH host
    keys (where there are any)."""
    missing = [
        unreported("both-instances-reported", boot, artifact_name, n)
        for n, boot in enumerate(boots, 1)
        if boot.report is None
    ]
    reports = [boot.report for boot in boots if boot.report is not None]
    if missing or len(reports) < 2:
        return result(TWO_CLONES, [], failed=missing or ["both-instances-reported: fewer than two boots"])
    first, second = reports[0], reports[1]
    if first.machine_id in NO_IDENTITY and second.machine_id in NO_IDENTITY:
        id_problems = ["neither instance has a machine ID after its first boot"]
    elif first.machine_id == second.machine_id:
        id_problems = ["/etc/machine-id is the same in both instances"]
    else:
        id_problems = []
    ok_id, bad_id = split("machine-ids-differ", id_problems)
    same_ssh = first.ssh == second.ssh and first.ssh != "none"
    ok_ssh, bad_ssh = split(
        "ssh-host-keys-differ", ["the SSH host keys are the same in both instances"] if same_ssh else []
    )
    return result(TWO_CLONES, ["both-instances-reported", *ok_id, *ok_ssh], failed=[*bad_id, *bad_ssh])
