"""The boot checks' harness, pure parts: credentials, QEMU arguments, the OS disk, and serial logs read into
`installer-boot`, `os-boot` and `two-clones` results."""

import base64
import re
import unittest

from debian_image_factory.checks import vm

KERNEL = "6.12.0-1-amd64"


def report(kernel: str = KERNEL, machine: str = "a" * 32, ssh: str = "b" * 64, state: str = "running") -> str:
    line = f"FACTORY-REPORT kernel={kernel} machine-id={machine} ssh={ssh} state={state}"
    return f"[  9.1] noise\r\n{line}\r\n[ 9.2] reboot\n"


def boot(serial: str, status: int | None = 0) -> vm.Boot:
    return vm.boot_of(status, serial, 600)


class CredentialsTest(unittest.TestCase):
    def test_each_credential_is_an_oem_string_with_its_value_in_base64(self) -> None:
        files = vm.credential_files()
        self.assertEqual(len(files), 2)
        decoded = {}
        for _, text in files:
            prefix, _, encoded = text.partition("=")
            self.assertTrue(prefix.startswith("io.systemd.credential.binary:"))
            decoded[prefix.removeprefix("io.systemd.credential.binary:")] = base64.b64decode(encoded).decode()
        self.assertEqual(
            set(decoded), {"systemd.extra-unit.factory-report.service", "systemd.unit-dropin.multi-user.target"}
        )
        self.assertIn("Wants=factory-report.service", decoded["systemd.unit-dropin.multi-user.target"])
        self.assertIn("Type=simple", decoded["systemd.extra-unit.factory-report.service"])

    def test_the_unit_escapes_the_shell_for_systemd(self) -> None:
        line = next(line for line in vm.REPORT_UNIT.splitlines() if line.startswith("ExecStart="))
        self.assertNotRegex(line, r"(?<!\$)\$(?!\$)")  # every $ is doubled
        unescaped = line.removeprefix('ExecStart=/bin/sh -c "').removesuffix('"').replace("$$", "$")
        self.assertEqual(unescaped, vm.REPORT_SCRIPT)
        self.assertIn("> /dev/ttyS0", vm.REPORT_SCRIPT)
        with self.assertRaises(ValueError):
            vm.unit_quoted('echo "x"')


class QemuTest(unittest.TestCase):
    def test_installer_boots_its_kernel_and_initrd_with_the_serial_console(self) -> None:
        args = vm.installer_args(vm.Machine("tcg", 2048), "/w/vmlinuz", "/w/initrd.img", "/w/serial-1.log", ["/w/c1"])
        joined = " ".join(args)
        self.assertIn("-kernel /w/vmlinuz -initrd /w/initrd.img -append console=ttyS0", joined)
        self.assertIn("-accel tcg,thread=multi", joined)
        self.assertIn("-smbios type=11,path=/w/c1", joined)
        self.assertIn("-nic none", joined)
        self.assertIn("-serial file:/w/serial-1.log", joined)

    def test_os_boots_by_ovmf_from_its_disk_and_kvm_uses_the_host_cpu(self) -> None:
        joined = " ".join(vm.os_args(vm.Machine("kvm", 1536), "/s/disk.img", "/s/vars.fd", "/w/serial.log", []))
        self.assertIn("-accel kvm -cpu host", joined)
        self.assertIn(f"readonly=on,file={vm.OVMF_CODE}", joined)
        self.assertIn("file=/s/vars.fd", joined)
        self.assertIn("file=/s/disk.img,format=raw,if=virtio", joined)

    def test_boots_run_at_once_each_under_its_own_time_limit(self) -> None:
        script = vm.installer_script(vm.Machine("tcg", 2048), 2, 900)
        self.assertEqual(script.count("timeout --kill-after=10 900 qemu-system-x86_64"), 2)
        self.assertIn("serial-2.log", script)
        self.assertTrue(script.rstrip().endswith("wait"))


class DiskTest(unittest.TestCase):
    def test_grub_boots_the_installed_kernel_with_the_root_by_label(self) -> None:
        cfg = vm.grub_cfg(KERNEL)
        self.assertIn(f"linux /boot/vmlinuz-{KERNEL} root=LABEL=factory-root rw console=ttyS0", cfg)
        self.assertIn(f"initrd /boot/initrd.img-{KERNEL}", cfg)
        self.assertIn("search --no-floppy --label --set=root factory-root", cfg)

    def test_the_layout_is_an_esp_then_the_root_aligned_to_mib(self) -> None:
        layout = vm.disk_layout(1000)
        starts = [int(n) for n in re.findall(r"start=(\d+)", layout.sfdisk)]
        sizes = [int(n) for n in re.findall(r"size=(\d+)", layout.sfdisk)]
        self.assertEqual(starts, [2048, 2048 * (1 + vm.ESP_MIB)])
        self.assertEqual(sizes, [2048 * vm.ESP_MIB, 2048 * 1000])
        self.assertIn(vm.ESP_TYPE, layout.sfdisk)
        self.assertEqual(layout.total_mib, 1 + vm.ESP_MIB + 1000 + 1)
        self.assertEqual((layout.esp_start_mib, layout.root_start_mib), (1, 1 + vm.ESP_MIB))

    def test_the_root_has_room_for_its_files_and_first_boots(self) -> None:
        self.assertGreater(vm.root_mib(400 * vm.MIB, 15000), 400 + 512)

    def test_the_os_script_makes_grub_in_the_root_and_the_ext4_from_the_tree(self) -> None:
        script = vm.os_script(vm.Machine("tcg", 1536), vm.disk_layout(900), 2, 1200)
        self.assertIn("chroot /scratch/root grub-mkstandalone -O x86_64-efi", script)
        self.assertIn("mkfs.ext4 -q -F -L factory-root -d /scratch/root /scratch/root.img 900M", script)
        self.assertIn("mcopy -i /scratch/esp.img /scratch/bootx64.efi ::/EFI/BOOT/BOOTX64.EFI", script)
        self.assertEqual(script.count("qemu-system-x86_64"), 2)


class ReportTest(unittest.TestCase):
    def test_the_last_report_line_is_read(self) -> None:
        found = vm.parse_report(report() + report(machine="c" * 32))
        self.assertEqual(found, vm.Report(KERNEL, "c" * 32, "b" * 64, "running"))
        self.assertIsNone(vm.parse_report("[ 1.0] Linux version\n"))

    def test_a_missing_report_says_why_and_ends_with_the_serial_tail(self) -> None:
        late = boot("line one\n\x1b[0;32mline two\x1b[0m\n", 124)
        self.assertEqual(late.problem, "no FACTORY-REPORT line within 600 s")
        self.assertEqual(vm.tail(late.serial), "line one | line two")
        self.assertEqual(boot("", 1).problem, "QEMU exited 1 without a FACTORY-REPORT line")

    def test_installer_boot_passes_when_the_kit_kernel_runs(self) -> None:
        passed = vm.installer_boot(KERNEL, (), boot(report()), "kit.tar")
        self.assertEqual(passed.outcome, "PASSED")
        other = vm.installer_boot(KERNEL, (), boot(report(kernel="6.1.0-9-amd64")), "kit.tar")
        self.assertEqual(other.outcome, "FAILED")
        self.assertIn("kit.json names " + KERNEL, other.failed[0])
        silent = vm.installer_boot(KERNEL, (), boot("panic\n", 124), "kit.tar")
        self.assertIn("serial log kit.tar.boot-1.serial.log, ending: panic", silent.failed[0])
        broken = vm.installer_boot(KERNEL, ("kit.json says vmlinuz is 1 bytes",), boot(report()), "kit.tar")
        self.assertEqual(broken.failed, ("kit-json-matches-files: kit.json says vmlinuz is 1 bytes",))

    def test_os_boot_judges_state_kernel_machine_id_and_keys(self) -> None:
        self.assertEqual(vm.os_boot(KERNEL, True, boot(report()), "os.tar.gz").outcome, "PASSED")
        degraded = vm.os_boot(KERNEL, True, boot(report(state="degraded")), "os.tar.gz")
        self.assertEqual(degraded.outcome, "WARNED")
        failed = vm.os_boot(KERNEL, True, boot(report(machine="uninitialized", ssh="none")), "os.tar.gz")
        self.assertEqual(
            [line.split(":")[0] for line in failed.failed],
            ["first-boot-made-machine-id", "first-boot-made-ssh-host-keys"],
        )
        self.assertEqual(vm.os_boot(KERNEL, False, boot(report(ssh="none")), "os.tar.gz").outcome, "PASSED")
        two = vm.os_boot((KERNEL, "6.1.0-9-amd64"), False, boot(report()), "os.tar.gz")
        self.assertIn("2 kernels", two.failed[0])

    def test_two_clones_needs_two_reports_with_different_identities(self) -> None:
        one, other = boot(report()), boot(report(machine="c" * 32, ssh="d" * 64))
        self.assertEqual(vm.two_clones([one, other], "a").outcome, "PASSED")
        same = vm.two_clones([one, boot(report())], "a")
        self.assertEqual([line.split(":")[0] for line in same.failed], ["machine-ids-differ", "ssh-host-keys-differ"])
        keyless = vm.two_clones([boot(report(ssh="none")), boot(report(machine="c" * 32, ssh="none"))], "a")
        self.assertEqual(keyless.outcome, "PASSED")
        lost = vm.two_clones([one, boot("", 124)], "a")
        self.assertIn("boot 2", lost.failed[0])


if __name__ == "__main__":
    unittest.main()
