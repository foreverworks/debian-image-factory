"""scripts/incus-vm: the pure parts (arguments, user-data, the QEMU and docker command lines, the console parser)."""

import base64
import importlib.machinery
import importlib.util
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "incus-vm"


def load() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("incus_vm", str(SCRIPT))
    spec = importlib.util.spec_from_loader("incus_vm", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


vm = load()
NONCE = "0123456789abcdef"


class ParseArgsTest(unittest.TestCase):
    def test_defaults_and_command(self) -> None:
        options = vm.parse_args(["--", "sh", "-c", "incus version"], 16)
        self.assertEqual(options.command, ("sh", "-c", "incus version"))
        self.assertIsNone(options.snapshot)
        self.assertEqual((options.memory, options.cpus, options.timeout_minutes), (2048, 4, 60.0))
        self.assertFalse(options.inner)

    def test_cpus_default_follows_a_small_host(self) -> None:
        self.assertEqual(vm.parse_args(["--", "true"], 2).cpus, 2)

    def test_options_before_the_separator_only(self) -> None:
        options = vm.parse_args(
            ["--snapshot", "20261110T000000Z", "--share", "/a/b:work", "--share", "/c:repo", "--memory", "4096",
             "--cpus", "3", "--timeout", "5", "--", "ls", "--share", "x"],
            8,
        )  # fmt: skip
        self.assertEqual(options.snapshot, "20261110T000000Z")
        self.assertEqual([(s.path, s.name) for s in options.shares], [("/a/b", "work"), ("/c", "repo")])
        self.assertEqual((options.memory, options.cpus, options.timeout_minutes), (4096, 3, 5.0))
        self.assertEqual(options.command, ("ls", "--share", "x"))

    def test_rejects_a_missing_command(self) -> None:
        for argv in ([], ["--memory", "1024"], ["--"]):
            with self.assertRaises(vm.UsageError, msg=str(argv)):
                vm.parse_args(argv, 4)

    def test_rejects_bad_values(self) -> None:
        bad = [
            ["--snapshot", "latest", "--", "true"],
            ["--share", "nocolon", "--", "true"],
            ["--share", "/a:bad/name", "--", "true"],
            ["--share", "/a,b:x", "--", "true"],
            ["--share", "/a:x", "--share", "/b:x", "--", "true"],
            ["--memory", "10", "--", "true"],
            ["--timeout", "0", "--", "true"],
            ["--bogus", "--", "true"],
            ["--memory", "many", "--", "true"],
        ]
        for argv in bad:
            with self.assertRaises(vm.UsageError, msg=str(argv)):
                vm.parse_args(argv, 4)


class AptSourcesTest(unittest.TestCase):
    def test_live_mirrors(self) -> None:
        text = vm.apt_sources(None)
        self.assertIn("URIs: http://deb.debian.org/debian\n", text)
        self.assertIn("URIs: http://deb.debian.org/debian-security\n", text)
        self.assertNotIn("snapshot", text)

    def test_snapshot_archives_for_the_three_suites(self) -> None:
        text = vm.apt_sources("20261110T000000Z")
        self.assertIn("URIs: https://snapshot.debian.org/archive/debian/20261110T000000Z/\n", text)
        self.assertIn("URIs: https://snapshot.debian.org/archive/debian-security/20261110T000000Z/\n", text)
        self.assertIn("Suites: trixie trixie-updates\n", text)
        self.assertIn("Suites: trixie-security\n", text)


class GuestScriptTest(unittest.TestCase):
    def check_syntax(self, script: str) -> None:
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)

    def test_prepare_installs_only_incus_and_its_bridge_helper_and_initialises_it(self) -> None:
        script = vm.guest_script(NONCE, "prepare", None, [], ["ignored"])
        self.check_syntax(script)
        self.assertIn("apt-get install -y -q --no-install-recommends incus dnsmasq-base\n", script)
        self.assertIn("incus admin init --minimal\n", script)
        self.assertIn(f"INCUS-VM-START {NONCE}", script)
        self.assertIn(f"INCUS-VM-EXIT {NONCE} %d", script)
        self.assertNotIn("ignored", script)

    def test_prepare_at_a_snapshot_turns_the_valid_until_check_off(self) -> None:
        script = vm.guest_script(NONCE, "prepare", "20261110T000000Z", [], [])
        self.assertIn("SNAPSHOT=20261110T000000Z\n", script)
        self.assertIn("snapshot.debian.org/archive/debian-security/20261110T000000Z/", script)
        self.assertIn("Acquire::Check-Valid-Until", script)

    def test_run_mounts_each_share_and_quotes_the_command(self) -> None:
        command = ["sh", "-c", "echo 'a b' > /mnt/work/x; $HOME"]
        script = vm.guest_script(NONCE, "run", None, ["work", "repo"], command)
        self.check_syntax(script)
        self.assertIn("mkdir -p /mnt/work && mount -t virtiofs work /mnt/work", script)
        self.assertIn("mkdir -p /mnt/repo && mount -t virtiofs repo /mnt/repo", script)
        self.assertIn(f"( body {shlex.join(command)} )\n", script)
        self.assertIn("/dev/ttyS1", script)
        self.assertTrue(script.endswith("systemctl poweroff\n"))

    def test_run_command_survives_the_guest_shell(self) -> None:
        # The quoted words come back as the same argv when a shell parses the line.
        command = ["printf", "%s|", "a b", "it's", '"q"', "$x", ""]
        line = f"( body {shlex.join(command)} )"
        self.assertEqual(shlex.split(line.removeprefix("( body ").removesuffix(" )")), command)

    def test_run_without_shares_still_a_valid_script(self) -> None:
        self.check_syntax(vm.guest_script(NONCE, "run", None, [], ["true"]))


class UserDataTest(unittest.TestCase):
    def test_cloud_config_carries_the_script_and_runs_it(self) -> None:
        shares = [vm.Share("/a", "work")]
        data = vm.user_data(NONCE, "run", None, shares, ["true"])
        self.assertTrue(data.startswith("#cloud-config\n"))
        self.assertIn("encoding: b64", data)
        self.assertIn("runcmd:\n  - [/usr/local/sbin/incus-vm-run]\n", data)
        encoded = next(line for line in data.splitlines() if "content:" in line).split(": ", 1)[1]
        script = base64.b64decode(encoded).decode()
        self.assertEqual(script, vm.guest_script(NONCE, "run", None, ["work"], ["true"]))

    def test_each_boot_is_a_new_instance(self) -> None:
        self.assertNotEqual(vm.meta_data("a-prepare"), vm.meta_data("a-run"))
        self.assertIn("instance-id: incus-vm-a-run\n", vm.meta_data("a-run"))

    def test_seed_iso_is_labelled_cidata(self) -> None:
        command = vm.seed_iso_command(Path("/w/seed.iso"), Path("/w/seed"))
        self.assertEqual(command[command.index("-volid") + 1], "cidata")
        self.assertEqual(command[-2:], ["/w/seed/user-data", "/w/seed/meta-data"])


class QemuCommandTest(unittest.TestCase):
    def build(self, accel: str, shares: list[object] | None = None) -> list[str]:
        command: list[str] = vm.qemu_command(
            Path("/w/run.qcow2"), Path("/w/seed.iso"), Path("/w/console.log"), shares or [], Path("/w"), 2048, 4, accel
        )
        return command

    def test_kvm(self) -> None:
        command = self.build("kvm")
        self.assertEqual(command[command.index("-accel") + 1], "kvm")
        self.assertEqual(command[command.index("-cpu") + 1], "host")

    def test_tcg(self) -> None:
        command = self.build("tcg")
        self.assertEqual(command[command.index("-accel") + 1], "tcg,thread=multi")
        self.assertEqual(command[command.index("-cpu") + 1], "max")

    def test_serial_ports_console_to_a_file_and_the_command_to_stdout(self) -> None:
        command = self.build("tcg")
        self.assertIn("file:/w/console.log", command)
        self.assertIn("stdio,id=cmdout,signal=off", command)
        self.assertIn("isa-serial,chardev=cmdout,iobase=0x2f8,irq=3", command)
        self.assertIn("-no-reboot", command)

    def test_resources_and_disks(self) -> None:
        command = self.build("tcg")
        self.assertEqual(command[command.index("-m") + 1], "2048")
        self.assertEqual(command[command.index("-smp") + 1], "4")
        self.assertIn("file=/w/run.qcow2,if=virtio,format=qcow2", command)
        self.assertIn("file=/w/seed.iso,if=virtio,format=raw,readonly=on", command)

    def test_memory_is_a_shared_memfd_for_virtiofs(self) -> None:
        command = self.build("tcg")
        self.assertIn("q35,memory-backend=mem0", command)
        self.assertIn("memory-backend-memfd,id=mem0,size=2048M,share=on", command)

    def test_one_virtiofs_device_per_share(self) -> None:
        command = self.build("tcg", [vm.Share("/shares/work", "work"), vm.Share("/shares/repo", "repo")])
        self.assertEqual(
            [command[i + 1] for i, word in enumerate(command) if word == "-chardev" and "socket" in command[i + 1]],
            ["socket,id=fs0,path=/w/virtiofsd-work.sock", "socket,id=fs1,path=/w/virtiofsd-repo.sock"],
        )
        self.assertIn("vhost-user-fs-pci,chardev=fs0,tag=work", command)
        self.assertIn("vhost-user-fs-pci,chardev=fs1,tag=repo", command)
        self.assertNotIn("-virtfs", command)

    def test_virtiofsd_serves_the_share_without_a_sandbox(self) -> None:
        command = vm.virtiofsd_command(vm.Share("/shares/work", "work"), Path("/w/virtiofsd-work.sock"))
        self.assertIn("--socket-path=/w/virtiofsd-work.sock", command)
        self.assertIn("--shared-dir=/shares/work", command)
        self.assertIn("--sandbox=none", command)


class DockerCommandTest(unittest.TestCase):
    options = vm.Options(
        command=("sh", "-c", "incus version"),
        snapshot="20261110T000000Z",
        shares=(vm.Share("/home/u/work", "work"),),
        memory=3000,
        cpus=2,
        timeout_minutes=5.0,
    )

    def command(self, accel: str, user_args: list[str]) -> list[str]:
        command: list[str] = vm.docker_run_command(
            self.options, "tag:1", Path("/r/scripts/incus-vm"), Path("/c"), accel, user_args
        )
        return command

    def test_tcg_has_no_device(self) -> None:
        command = self.command("tcg", [])
        self.assertNotIn("--device", command)
        self.assertIn("--privileged", command)

    def test_kvm_passes_the_device(self) -> None:
        command = self.command("kvm", [])
        self.assertEqual(command[command.index("--device") + 1], "/dev/kvm")

    def test_mounts_and_inner_arguments_round_trip(self) -> None:
        command = self.command("tcg", [])
        mounts = [command[i + 1] for i, word in enumerate(command) if word == "--mount"]
        self.assertEqual(
            mounts,
            [
                "type=bind,src=/r/scripts/incus-vm,dst=/opt/incus-vm,readonly",
                "type=bind,src=/c,dst=/cache",
                "type=bind,src=/home/u/work,dst=/shares/work",
            ],
        )
        tag_at = command.index("tag:1")
        self.assertEqual(command[tag_at + 1 : tag_at + 3], ["python3", "/opt/incus-vm"])
        inner = vm.parse_args(command[tag_at + 3 :], 16)
        self.assertTrue(inner.inner)
        self.assertEqual(inner.accel, "tcg")
        self.assertEqual(inner.command, self.options.command)
        self.assertEqual(inner.snapshot, self.options.snapshot)
        self.assertEqual([(s.path, s.name) for s in inner.shares], [("/shares/work", "work")])
        self.assertEqual((inner.memory, inner.cpus, inner.timeout_minutes), (3000, 2, 5.0))

    def test_user_args(self) -> None:
        self.assertEqual(vm.docker_user_args(True, 1000, 1000, 108), [])
        self.assertEqual(vm.docker_user_args(False, 1000, 1001, None), ["--user", "1000:1001"])
        self.assertEqual(
            vm.docker_user_args(False, 1000, 1001, 108), ["--user", "1000:1001", "--group-add", "108"]
        )  # fmt: skip

    def test_harness_image_is_pinned_and_tagged_by_content(self) -> None:
        dockerfile = vm.harness_dockerfile()
        self.assertRegex(dockerfile, r"^FROM debian:trixie@sha256:[0-9a-f]{64}\n")
        for package in ("qemu-system-x86", "qemu-utils", "virtiofsd", "xorriso"):
            self.assertIn(package, dockerfile)
        self.assertEqual(vm.harness_tag(dockerfile), vm.harness_tag(vm.harness_dockerfile()))
        self.assertNotEqual(vm.harness_tag(dockerfile), vm.harness_tag(dockerfile + "\n"))


class ConsoleTest(unittest.TestCase):
    def test_start_and_exit_status(self) -> None:
        text = f"boot noise\r\nINCUS-VM-START {NONCE}\r\nINCUS-VM-EXIT {NONCE} 3\r\n"
        self.assertEqual(vm.parse_console(text, NONCE), vm.Outcome(True, 3))

    def test_never_started(self) -> None:
        self.assertEqual(vm.parse_console("login:\n", NONCE), vm.Outcome(False, None))

    def test_started_but_never_finished(self) -> None:
        self.assertEqual(vm.parse_console(f"INCUS-VM-START {NONCE}\n", NONCE), vm.Outcome(True, None))

    def test_a_marker_after_other_console_text(self) -> None:
        text = f"incus-vm login: INCUS-VM-EXIT {NONCE} 7\n[ 3.1] x INCUS-VM-START {NONCE}\n"
        self.assertEqual(vm.parse_console(text, NONCE), vm.Outcome(True, 7))

    def test_another_runs_marker_is_ignored(self) -> None:
        text = "INCUS-VM-START ffff\nINCUS-VM-EXIT ffff 0\n"
        self.assertEqual(vm.parse_console(text, NONCE), vm.Outcome(False, None))

    def test_tail_keeps_the_last_lines(self) -> None:
        self.assertEqual(vm.tail("\n".join(str(i) for i in range(100)), NONCE, 3), "97\n98\n99")

    def test_tail_stops_at_the_exit_marker(self) -> None:
        text = f"a\nb\nINCUS-VM-EXIT {NONCE} 100\nshutdown 1\nshutdown 2\n"
        self.assertEqual(vm.tail(text, NONCE, 2), f"b\nINCUS-VM-EXIT {NONCE} 100")


class ChecksumTest(unittest.TestCase):
    def test_finds_the_image_line(self) -> None:
        text = f"{'a' * 128}  other.qcow2\n{'b' * 128}  wanted.qcow2\n"
        self.assertEqual(vm.parse_sha512sums(text, "wanted.qcow2"), "b" * 128)
        with self.assertRaises(KeyError):
            vm.parse_sha512sums(text, "missing.qcow2")

    def test_the_pinned_image_name_and_directory_agree(self) -> None:
        self.assertIn(vm.CLOUD_BUILD, vm.CLOUD_URL)
        self.assertIn(vm.CLOUD_BUILD, vm.CLOUD_IMAGE)

    def test_cache_key_names_the_snapshot_and_digests_every_input(self) -> None:
        key = vm.cache_key("ab" * 64, "20261110T000000Z", "20261122", "text")
        self.assertRegex(key, r"^20261110T000000Z-[0-9a-f]{16}$")
        self.assertEqual(key, vm.cache_key("ab" * 64, "20261110T000000Z", "20261122", "text"))
        later = vm.cache_key("ab" * 64, "20261110T000000Z", "20270101", "text")
        self.assertEqual(key, later, "a snapshot ignores the day")
        for changed in (
            vm.cache_key("ac" * 64, "20261110T000000Z", "20261122", "text"),
            vm.cache_key("ab" * 64, "20261111T000000Z", "20261122", "text"),
            vm.cache_key("ab" * 64, "20261110T000000Z", "20261122", "other text"),
        ):
            self.assertNotEqual(changed, key)

    def test_without_a_snapshot_the_key_holds_the_day(self) -> None:
        today = vm.cache_key("ab" * 64, None, "20261122", "text")
        self.assertRegex(today, r"^20261122-[0-9a-f]{16}$")
        self.assertNotEqual(today, vm.cache_key("ab" * 64, None, "20261123", "text"))

    def test_the_prepare_inputs_hold_the_script_the_sources_and_the_packages(self) -> None:
        inputs = vm.prepare_inputs("20261110T000000Z")
        script = vm.guest_script("0" * 16, "prepare", "20261110T000000Z", [], [])
        self.assertIn(base64.b64encode(script.encode()).decode(), inputs)
        self.assertIn("incus dnsmasq-base", script)
        self.assertIn("snapshot.debian.org/archive/debian/20261110T000000Z/", script)
        self.assertIn(f"disk={vm.DISK_SIZE}", inputs)
        self.assertNotEqual(inputs, vm.prepare_inputs(None))
        self.assertNotEqual(inputs, vm.prepare_inputs("20261111T000000Z"))

    def test_a_change_to_the_prepare_script_the_sources_or_the_packages_changes_the_key(self) -> None:
        def key() -> str:
            return str(vm.cache_key("ab" * 64, "20261110T000000Z", "20261122", vm.prepare_inputs("20261110T000000Z")))

        before = key()
        for name, value in (
            ("PREPARE_STEPS", vm.PREPARE_STEPS + "true\n"),
            ("INCUS_PACKAGES", (*vm.INCUS_PACKAGES, "jq")),
            ("DISK_SIZE", "12G"),
        ):
            with mock.patch.object(vm, name, value):
                self.assertNotEqual(key(), before, name)
        real = vm.apt_sources
        with mock.patch.object(vm, "apt_sources", lambda snapshot: real(snapshot) + "# changed\n"):
            self.assertNotEqual(key(), before, "apt sources text")
        self.assertEqual(key(), before)


class ShareDirectoryTest(unittest.TestCase):
    def test_a_missing_share_directory_is_a_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            options = vm.Options(command=("true",), shares=(vm.Share(f"{scratch}/missing", "x"),))
            with self.assertRaises(vm.UsageError):
                vm.outside(options)


if __name__ == "__main__":
    unittest.main()
