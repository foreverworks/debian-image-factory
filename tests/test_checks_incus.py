"""The Incus checks: the pure parts of `incus-boot` and `two-clones`, the edge that drives Incus (through a
stand-in for the `incus` command), `ancestry` by files, and `test` on an output directory that holds Incus
images made from a squashfs fixture."""

import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest import mock

import input_lock.records as rec

from debian_image_factory import records
from debian_image_factory.checks import ancestry, command, incus_host
from debian_image_factory.checks.model import INCUS_BOOT, TWO_CLONES, CheckOutcome, NotRun, Result
from debian_image_factory.checks.tarball import Member
from debian_image_factory.commands import Sources
from debian_image_factory.planfile import Plan, parse_plan
from tests.support import incusimage
from tests.support.fakeincus import NOCLOUD, Host, listing, runner
from tests.support.incusimage import APP_IDENTITY, BASE_IDENTITY, Image, write_image
from tests.support.rootfs import BASE, SNAPSHOT

TOKEN = "0123456789abcdef"
FINGERPRINT = "ab" * 32
KEYS = ("cloud-init", "user")
STAGES = ("first-boot", "after-restart")
MACHINE = "/etc/machine-id"
DBUS = "/var/lib/dbus/machine-id"
HOSTNAME = "/etc/hostname"
SSH_KEY = "/etc/ssh/ssh_host_ed25519_key.pub"


def good(first: str = "1", second: str = "2") -> tuple[dict[str, bytes], dict[str, bytes]]:
    """The identity files of two instances that made their own."""

    def files(one: str) -> dict[str, bytes]:
        return {
            MACHINE: f"machine-{one}\n".encode(),
            DBUS: f"dbus-{one}\n".encode(),
            HOSTNAME: f"host-{one}\n".encode(),
            SSH_KEY: f"ssh-ed25519 key-{one}\n".encode(),
        }

    return files(first), files(second)


def ran(outcome: CheckOutcome) -> Result:
    assert isinstance(outcome, Result), outcome
    return outcome


def not_run(outcome: CheckOutcome) -> NotRun:
    assert isinstance(outcome, NotRun), outcome
    return outcome


def boot_names(*tests: str) -> list[str]:
    return [f"{key}-{stage}-{test}" for key in KEYS for stage in STAGES for test in tests]


ALL_BOOT_TESTS = ("cloud-init-done", "nocloud", "user-created", "commands-ran", "ipv4-reported")


class Clock:
    """A clock that only the sleeps move, so that waiting out ADDRESS_TIMEOUT takes no time."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def monotonic(self) -> float:
        return self.now


# ---- the pure parts ---------------------------------------------------------------------------------


class UserDataTest(unittest.TestCase):
    def test_it_creates_a_user_and_runs_a_command_that_writes_the_token(self) -> None:
        text = incus_host.user_data(TOKEN)
        self.assertTrue(text.startswith("#cloud-config\n"))
        self.assertIn("  - name: dif-check\n", text)
        self.assertIn("    lock_passwd: true\n", text)
        self.assertIn(f"  - [sh, -c, 'echo {TOKEN} > /var/lib/dif-boot-check']\n", text)

    def test_the_text_is_the_same_for_the_same_token_and_differs_for_another(self) -> None:
        self.assertEqual(incus_host.user_data("a"), incus_host.user_data("a"))
        self.assertNotEqual(incus_host.user_data("a"), incus_host.user_data("b"))


class ImportedFingerprintTest(unittest.TestCase):
    def test_the_fingerprint_follows_the_colon(self) -> None:
        self.assertEqual(
            incus_host.imported_fingerprint(f"Image imported with fingerprint: {FINGERPRINT}\n"), FINGERPRINT
        )

    def test_other_lines_around_it_are_skipped(self) -> None:
        text = f"Importing image: 100%\nImage imported with fingerprint: {FINGERPRINT}\n"
        self.assertEqual(incus_host.imported_fingerprint(text), FINGERPRINT)

    def test_the_word_imported_is_matched_whatever_its_case(self) -> None:
        self.assertEqual(
            incus_host.imported_fingerprint(f"IMAGE IMPORTED WITH fingerprint: {FINGERPRINT}"), FINGERPRINT
        )

    def test_a_line_that_is_not_the_import_message_is_not_one(self) -> None:
        for text in ("", "fingerprint: abc\n", "Image imported with fingerprint:\n", "Image imported\n"):
            self.assertIsNone(incus_host.imported_fingerprint(text), text)


class Ipv4AddressesTest(unittest.TestCase):
    REALISTIC = json.dumps(
        [
            {
                "architecture": "x86_64",
                "config": {"image.os": "Debian"},
                "name": "dif-boot-1",
                "status": "Running",
                "state": {
                    "status": "Running",
                    "network": {
                        "eth0": {
                            "addresses": [
                                {"family": "inet", "address": "192.0.2.15", "netmask": "24", "scope": "global"},
                                {"family": "inet6", "address": "2001:db8::15", "netmask": "64", "scope": "global"},
                                {
                                    "family": "inet6",
                                    "address": "fe80::1",
                                    "netmask": "64",
                                    "scope": "link",
                                },  # push-guard: allow
                            ],
                            "type": "broadcast",
                        },
                        "lo": {
                            "addresses": [
                                {"family": "inet", "address": "127.0.0.1", "netmask": "8", "scope": "local"},
                                {"family": "inet6", "address": "::1", "netmask": "128", "scope": "local"},
                            ],
                            "type": "loopback",
                        },
                    },
                },
            }
        ]
    )

    def test_only_the_global_ipv4_address_is_reported(self) -> None:
        self.assertEqual(incus_host.ipv4_addresses(self.REALISTIC), ["192.0.2.15"])

    def test_the_loopback_is_ignored_even_with_a_global_address(self) -> None:
        text = json.dumps(
            [
                {
                    "state": {
                        "network": {
                            "lo": {"addresses": [{"family": "inet", "address": "203.0.113.9", "scope": "global"}]}
                        }
                    }
                }
            ]
        )
        self.assertEqual(incus_host.ipv4_addresses(text), [])

    def test_a_link_local_or_local_ipv4_address_is_not_global(self) -> None:
        text = listing(("inet", "198.51.100.3", "link"), ("inet", "198.51.100.4", "local"))
        self.assertEqual(incus_host.ipv4_addresses(text), [])

    def test_interfaces_are_read_in_name_order(self) -> None:
        text = json.dumps(
            [
                {
                    "state": {
                        "network": {
                            "eth1": {"addresses": [{"family": "inet", "address": "192.0.2.21", "scope": "global"}]},
                            "eth0": {"addresses": [{"family": "inet", "address": "192.0.2.20", "scope": "global"}]},
                        }
                    }
                }
            ]
        )
        self.assertEqual(incus_host.ipv4_addresses(text), ["192.0.2.20", "192.0.2.21"])

    def test_an_instance_that_is_stopped_has_no_network(self) -> None:
        text = json.dumps([{"name": "x", "status": "Stopped", "state": {"status": "Stopped", "network": None}}])
        self.assertEqual(incus_host.ipv4_addresses(text), [])

    def test_what_is_not_the_expected_shape_gives_no_address(self) -> None:
        shapes = [
            "",
            "not json",
            "{}",
            '"text"',
            "[]",
            "[1, null, []]",
            '[{"state": null}]',
            '[{"state": {"network": []}}]',
            '[{"state": {"network": {"eth0": []}}}]',
            '[{"state": {"network": {"eth0": {"addresses": "x"}}}}]',
            '[{"state": {"network": {"eth0": {"addresses": [null, 3, {}]}}}}]',
            '[{"state": {"network": {"eth0": {"addresses": [{"family": "inet", "scope": "global"}]}}}}]',
            '[{"state": {"network": {"eth0": {"addresses": [{"family": "inet", "address": 5, "scope": "global"}]}}}}]',
        ]
        for text in shapes:
            self.assertEqual(incus_host.ipv4_addresses(text), [], text)


class CompareClonesTest(unittest.TestCase):
    ALL_PASSED = (
        "machine-ids-differ",
        "dbus-machine-ids-differ",
        "hostnames-differ",
        "ssh-host-keys-differ",
        "machine-ids-made",
        "ssh-host-keys-made",
    )

    def test_two_instances_that_share_nothing_pass_every_test(self) -> None:
        first, second = good()
        got = incus_host.compare_clones(first, second, ssh=True)
        self.assertEqual((got.check, got.outcome, got.passed, got.failed), (TWO_CLONES, "PASSED", self.ALL_PASSED, ()))

    def test_without_openssh_no_host_keys_are_asked_for(self) -> None:
        first, second = good()
        for files in (first, second):
            del files[SSH_KEY]
        got = incus_host.compare_clones(first, second, ssh=False)
        self.assertEqual(got.outcome, "PASSED")
        self.assertNotIn("ssh-host-keys-made", got.passed)
        self.assertEqual(
            incus_host.compare_clones(first, second, ssh=True).failed,
            ("ssh-host-keys-made: an instance has no SSH host keys",),
        )

    def test_each_shared_identity_fails_its_own_test_and_names_the_path(self) -> None:
        cases = {
            MACHINE: "machine-ids-differ",
            DBUS: "dbus-machine-ids-differ",
            HOSTNAME: "hostnames-differ",
            SSH_KEY: "ssh-host-keys-differ",
        }
        for path, test in cases.items():
            first, second = good()
            second[path] = first[path]
            got = incus_host.compare_clones(first, second, ssh=True)
            self.assertEqual(got.outcome, "FAILED", path)
            self.assertEqual(got.failed, (f"{test}: {path} the same in both instances",))
            self.assertNotIn(test, got.passed)
            self.assertEqual(len(got.passed), 5)

    def test_every_ssh_host_key_that_is_shared_is_named(self) -> None:
        first, second = good()
        for name in ("rsa", "ecdsa"):
            first[f"/etc/ssh/ssh_host_{name}_key.pub"] = second[f"/etc/ssh/ssh_host_{name}_key.pub"] = b"shared\n"
        got = incus_host.compare_clones(first, second, ssh=True)
        self.assertEqual(
            got.failed,
            (
                "ssh-host-keys-differ: /etc/ssh/ssh_host_ecdsa_key.pub, /etc/ssh/ssh_host_rsa_key.pub "
                "the same in both instances",
            ),
        )

    def test_an_absent_machine_id_is_not_a_pass(self) -> None:
        first, second = good()
        del first[MACHINE]
        got = incus_host.compare_clones(first, second, ssh=True)
        self.assertEqual(got.failed, ("machine-ids-made: an instance has no machine ID after its first boot",))
        self.assertIn("machine-ids-differ", got.passed)

    def test_two_uninitialized_or_empty_machine_ids_are_no_clash_but_no_identity_either(self) -> None:
        for value in (b"uninitialized\n", b""):
            first, second = good()
            first[MACHINE] = second[MACHINE] = value
            got = incus_host.compare_clones(first, second, ssh=True)
            self.assertIn("machine-ids-differ", got.passed, value)
            self.assertEqual(got.failed, ("machine-ids-made: an instance has no machine ID after its first boot",))

    def test_one_instance_that_never_made_its_machine_id_fails_even_if_the_other_did(self) -> None:
        first, second = good()
        second[MACHINE] = b"uninitialized\n"
        self.assertEqual(incus_host.compare_clones(first, second, ssh=True).outcome, "FAILED")

    def test_one_instance_without_host_keys_fails_when_the_image_has_openssh(self) -> None:
        first, second = good()
        del second[SSH_KEY]
        got = incus_host.compare_clones(first, second, ssh=True)
        self.assertEqual(got.failed, ("ssh-host-keys-made: an instance has no SSH host keys",))

    def test_failures_add_up(self) -> None:
        first, second = good()
        second[MACHINE], second[HOSTNAME] = first[MACHINE], first[HOSTNAME]
        got = incus_host.compare_clones(first, second, ssh=True)
        self.assertEqual(len(got.failed), 2)
        self.assertEqual(len(got.passed), 4)


class BootWaitScriptTest(unittest.TestCase):
    """The script runs in the instance; here under sh, with systemctl and cloud-init stubs on PATH."""

    def wait(self, script: str, states: Sequence[str], *, cloud_init: bool = True) -> list[str]:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            calls = root / "calls"
            (root / "states").write_text("".join(f"{state}\n" for state in states))
            stubs = {
                # each call without --wait answers the next state, and the last one from then on
                "systemctl": f"""echo "systemctl $*" >> {calls}
[ "$2" = --wait ] && {{ echo offline; exit 1; }}
state=$(head -n1 {root}/states)
[ "$(wc -l < {root}/states)" -gt 1 ] && sed -i 1d {root}/states
echo "$state"
""",
                "cloud-init": f'echo "cloud-init $*" >> {calls}\n',
            }
            bin_dir = root / "bin"
            bin_dir.mkdir()
            for name, body in stubs.items():
                if name == "cloud-init" and not cloud_init:
                    continue
                stub = bin_dir / name
                stub.write_text("#!/bin/sh\n" + body)
                stub.chmod(0o755)
            # only the stubs and the tools the script and the stubs use, so a cloud-init on this host is not found
            for tool in ("grep", "head", "sed", "wc", "sleep"):
                found = shutil.which(tool)
                assert found is not None, tool
                (bin_dir / tool).symlink_to(found)
            env = {"PATH": str(bin_dir)}
            subprocess.run([shutil.which("sh") or "/bin/sh", "-c", script], env=env, check=True, timeout=30)
            return calls.read_text().splitlines()

    def test_an_offline_answer_is_asked_again_until_the_boot_finished_then_cloud_init_is_awaited(self) -> None:
        calls = self.wait(incus_host.CLONE_WAIT_SCRIPT, ["offline", "starting", "degraded"])
        self.assertEqual(
            calls,
            [
                "systemctl is-system-running --wait",
                "systemctl is-system-running",
                "systemctl is-system-running",
                "systemctl is-system-running",
                "cloud-init status --wait",
            ],
        )

    def test_without_cloud_init_the_wait_ends_with_systemd(self) -> None:
        calls = self.wait(incus_host.CLONE_WAIT_SCRIPT, ["running"], cloud_init=False)
        self.assertEqual(calls[-1], "systemctl is-system-running")

    def test_incus_boot_waits_for_systemd_only(self) -> None:
        calls = self.wait(incus_host.SYSTEMD_WAIT_SCRIPT, ["offline", "running"])
        self.assertNotIn("cloud-init status --wait", calls)
        self.assertEqual(calls.count("systemctl is-system-running"), 2)


class BootTestsTest(unittest.TestCase):
    def reading(self, **changes: object) -> incus_host.Reading:
        fields: dict[str, object] = {
            "cloud_init": 0,
            "cloud_init_detail": f"done {NOCLOUD}",
            "user": True,
            "marker": TOKEN,
            "addresses": ("192.0.2.15",),
        }
        fields.update(changes)
        return incus_host.Reading(**fields)  # type: ignore[arg-type]  # the keywords are the class's own, built as a dict

    def test_a_good_boot_passes_all_five(self) -> None:
        passed, warned, failed = incus_host.boot_tests("user-first-boot", TOKEN, self.reading())
        self.assertEqual(passed, [f"user-first-boot-{test}" for test in ALL_BOOT_TESTS])
        self.assertEqual((warned, failed), ([], []))

    def test_cloud_init_exit_2_is_a_warning_and_never_a_pass(self) -> None:
        passed, warned, failed = incus_host.boot_tests(
            "p", TOKEN, self.reading(cloud_init=2, cloud_init_detail="x NoCloud")
        )
        self.assertEqual(warned, ["p-cloud-init-done: finished with recoverable errors (x NoCloud)"])
        self.assertNotIn("p-cloud-init-done", passed)
        self.assertEqual(failed, [])
        self.assertEqual(len(passed), 4)

    def test_any_other_cloud_init_exit_fails(self) -> None:
        for status in (1, 3, 255, None):
            _, warned, failed = incus_host.boot_tests("p", TOKEN, self.reading(cloud_init=status))
            self.assertEqual(warned, [])
            self.assertEqual(failed, [f"p-cloud-init-done: cloud-init status exited {status} (done {NOCLOUD})"])

    def test_another_datasource_than_nocloud_fails(self) -> None:
        _, _, failed = incus_host.boot_tests("p", TOKEN, self.reading(cloud_init_detail="done DataSourceNone"))
        self.assertEqual(failed, ["p-nocloud: datasource: done DataSourceNone"])

    def test_a_missing_user_and_a_command_that_did_not_run_fail_apart(self) -> None:
        _, _, failed = incus_host.boot_tests("p", TOKEN, self.reading(user=False, marker=None))
        self.assertEqual(
            failed,
            ["p-user-created: no user dif-check", "p-commands-ran: /var/lib/dif-boot-check holds None"],
        )

    def test_a_marker_with_another_token_is_not_the_command_having_run(self) -> None:
        _, _, failed = incus_host.boot_tests("p", TOKEN, self.reading(marker="stale"))
        self.assertEqual(failed, ["p-commands-ran: /var/lib/dif-boot-check holds 'stale'"])

    def test_no_address_fails(self) -> None:
        _, _, failed = incus_host.boot_tests("p", TOKEN, self.reading(addresses=()))
        self.assertEqual(failed, ["p-ipv4-reported: Incus reports no IPv4 address"])


# ---- the edge ---------------------------------------------------------------------------------------


class Scratch(unittest.TestCase):
    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory(prefix="checks-incus-test-")
        self.addCleanup(scratch.cleanup)
        self.dir = Path(scratch.name)
        self.host = Host()
        self.incus = runner(self.host)
        self.clock = Clock()
        patch = mock.patch("debian_image_factory.checks.incus_host.time.monotonic", self.clock.monotonic)
        patch.start()
        self.addCleanup(patch.stop)

    def verbs(self) -> list[str]:
        return [call[0] for call in self.host.calls]

    def deleted(self) -> list[str]:
        return [call[-1] for call in self.host.calls if call[:2] == ("delete", "--force")]

    def clean(self) -> None:
        self.assertEqual(self.host.instances, {})
        self.assertEqual(self.host.images, {})


class IncusProblemTest(Scratch):
    def test_a_daemon_that_answers_is_no_problem(self) -> None:
        self.assertIsNone(incus_host.incus_problem(self.incus))
        self.assertEqual(self.host.calls, [("info",)])

    def test_a_daemon_that_does_not_answer_is_named_with_its_error(self) -> None:
        self.host.info_returncode, self.host.info_error = 1, "Error: unix socket not found\n"
        self.assertEqual(incus_host.incus_problem(self.incus), "incus is not usable: Error: unix socket not found")

    def test_a_missing_command_is_not_available(self) -> None:
        self.host.missing = True
        problem = incus_host.incus_problem(self.incus)
        assert problem is not None
        self.assertTrue(problem.startswith("incus is not available: "))

    def test_a_command_that_hangs_is_not_available(self) -> None:
        self.host.raises = ("info", subprocess.TimeoutExpired("incus", 300))
        problem = incus_host.incus_problem(self.incus)
        assert problem is not None
        self.assertTrue(problem.startswith("incus is not available: "))


class ImportImageTest(Scratch):
    def files(self) -> tuple[Path, Path, str]:
        meta, root = self.dir / "image.incus.tar.gz", self.dir / "image.rootfs.squashfs"
        meta.write_bytes(b"metadata")
        root.write_bytes(b"rootfs")
        return meta, root, hashlib.sha256(b"metadatarootfs").hexdigest()

    def test_an_image_whose_fingerprint_is_the_artifacts_is_imported_under_a_throwaway_alias(self) -> None:
        meta, root, fingerprint = self.files()
        got = incus_host.import_image(meta, root, fingerprint, self.incus)
        assert isinstance(got, incus_host.Imported)
        self.assertEqual(got.fingerprint, fingerprint)
        self.assertRegex(got.alias, r"^dif-check-[0-9a-f]{12}$")
        self.assertEqual(self.host.calls, [("image", "import", str(meta), str(root), "--alias", got.alias)])
        self.assertEqual(self.host.images, {got.alias: fingerprint})

    def test_each_import_has_its_own_alias(self) -> None:
        meta, root, fingerprint = self.files()
        aliases: set[str] = set()
        for _ in range(3):
            got = incus_host.import_image(meta, root, fingerprint, self.incus)
            assert isinstance(got, incus_host.Imported)
            aliases.add(got.alias)
        self.assertEqual(len(aliases), 3)

    def test_a_refused_import_gives_the_reason(self) -> None:
        meta, root, fingerprint = self.files()
        self.host.import_returncode, self.host.import_error = 1, "Error: Failed to import: invalid metadata\n"
        self.assertEqual(
            incus_host.import_image(meta, root, fingerprint, self.incus),
            "incus image import failed: Error: Failed to import: invalid metadata",
        )
        self.clean()

    def test_another_fingerprint_than_the_artifacts_is_refused_and_leaves_nothing_behind(self) -> None:
        meta, root, fingerprint = self.files()
        other = "ee" * 32
        self.host.printed_fingerprint = other
        self.assertEqual(
            incus_host.import_image(meta, root, fingerprint, self.incus),
            f"Incus computed the fingerprint {other}, the artifact's is {fingerprint}",
        )
        self.assertEqual(self.host.images, {}, "the image Incus did import is not left in its store")

    def test_an_import_that_prints_no_fingerprint_is_taken_as_the_artifacts(self) -> None:
        meta, root, fingerprint = self.files()
        self.host.printed_fingerprint = ""
        got = incus_host.import_image(meta, root, fingerprint, self.incus)
        assert isinstance(got, incus_host.Imported)
        self.assertEqual(got.fingerprint, fingerprint)


class IncusBootTest(Scratch):
    def setUp(self) -> None:
        super().setUp()
        self.imported = incus_host.Imported("dif-check-aaaaaaaaaaaa", FINGERPRINT)
        self.host.images[self.imported.alias] = FINGERPRINT

    def boot(self) -> CheckOutcome:
        return incus_host.incus_boot(self.imported, self.incus, self.clock.sleep)

    def test_every_instance_passes_every_test_before_and_after_a_restart(self) -> None:
        got = ran(self.boot())
        self.assertEqual((got.check, got.outcome, got.warned, got.failed), (INCUS_BOOT, "PASSED", (), ()))
        self.assertEqual(list(got.passed), boot_names(*ALL_BOOT_TESTS))
        self.assertEqual(self.clock.slept, [])

    def test_one_instance_is_launched_per_user_data_key_with_the_same_cloud_config(self) -> None:
        self.boot()
        launches = [call for call in self.host.calls if call[0] == "launch"]
        self.assertEqual(len(launches), 2)
        self.assertEqual([call[1] for call in launches], [self.imported.alias] * 2)
        configs = []
        for call in launches:
            self.assertEqual(call[3], "--config")
            key, _, text = call[4].partition("=")
            configs.append((key, text))
        self.assertEqual([key for key, _ in configs], ["cloud-init.user-data", "user.user-data"])
        self.assertEqual(configs[0][1], configs[1][1])
        self.assertIn("name: dif-check", configs[0][1])

    def test_each_instance_is_restarted_once_between_its_two_readings(self) -> None:
        self.boot()
        self.assertEqual(self.verbs().count("restart"), 2)
        first = self.verbs().index("launch")
        self.assertEqual(self.verbs()[first : first + 3], ["launch", "exec", "exec"])

    def test_the_instances_are_deleted_after_a_pass_and_the_image_is_left_to_the_caller(self) -> None:
        self.boot()
        self.assertEqual(self.host.instances, {})
        self.assertEqual(len(self.deleted()), 2)
        self.assertEqual(self.host.images, {self.imported.alias: FINGERPRINT})

    def test_cloud_init_finishing_with_recoverable_errors_is_a_warning(self) -> None:
        self.host.cloud_init_status = 2
        got = ran(self.boot())
        self.assertEqual(got.outcome, "WARNED")
        self.assertEqual(len(got.warned), 4)
        self.assertTrue(all("finished with recoverable errors" in one for one in got.warned))
        self.assertNotIn("cloud-init-first-boot-cloud-init-done", got.passed)
        self.assertEqual(got.failed, ())

    def test_cloud_init_failing_fails_every_reading(self) -> None:
        self.host.cloud_init_status = 1
        got = ran(self.boot())
        self.assertEqual(got.outcome, "FAILED")
        self.assertEqual(len(got.failed), 4)
        self.assertTrue(got.failed[0].startswith("cloud-init-first-boot-cloud-init-done: cloud-init status exited 1"))

    def test_another_datasource_than_nocloud_fails(self) -> None:
        self.host.cloud_init_detail = "DataSourceNone"
        got = ran(self.boot())
        self.assertEqual([one.split(":")[0] for one in got.failed], boot_names("nocloud"))

    def test_a_key_the_image_does_not_read_fails_only_that_instances_user_and_command(self) -> None:
        self.host.honours = ("cloud-init.user-data",)
        got = ran(self.boot())
        self.assertEqual(
            sorted(one.split(":")[0] for one in got.failed),
            sorted(f"user-{stage}-{test}" for stage in STAGES for test in ("user-created", "commands-ran")),
        )
        self.assertIn("cloud-init-first-boot-user-created", got.passed)

    def test_an_instance_that_never_gets_an_address_fails_after_the_wait(self) -> None:
        self.host.silent_polls = -1
        got = ran(self.boot())
        self.assertEqual([one.split(":")[0] for one in got.failed], boot_names("ipv4-reported"))
        self.assertEqual(set(self.clock.slept), {5.0})
        self.assertEqual(len(self.clock.slept), 60 * 4)

    def test_an_address_that_comes_late_is_waited_for(self) -> None:
        self.host.silent_polls = 2
        got = ran(self.boot())
        self.assertEqual(got.outcome, "PASSED")
        self.assertEqual(self.clock.slept, [5.0, 5.0])

    def test_a_restart_that_fails_is_a_failure_and_the_rest_goes_on(self) -> None:
        self.host.restart_fails = True
        got = ran(self.boot())
        self.assertEqual(
            list(got.failed),
            [
                "cloud-init-after-restart-restart: Error: instance did not stop",
                "user-after-restart-restart: Error: instance did not stop",
            ],
        )
        self.assertEqual(list(got.passed), [n for n in boot_names(*ALL_BOOT_TESTS) if "first-boot" in n])

    def test_an_instance_that_does_not_launch_is_not_run_and_both_names_are_deleted(self) -> None:
        self.host.launch_fails = frozenset({1})
        got = not_run(self.boot())
        self.assertEqual(got, NotRun(INCUS_BOOT, "incus launch failed: Error: Failed instance creation: no space left"))
        self.assertEqual(self.verbs().count("launch"), 1)
        self.assertEqual(len(self.deleted()), 2)
        self.assertEqual(self.host.instances, {})

    def test_a_second_instance_that_does_not_launch_deletes_the_first_too(self) -> None:
        self.host.launch_fails = frozenset({2})
        got = not_run(self.boot())
        self.assertEqual(got.check, INCUS_BOOT)
        self.assertIn("incus launch failed", got.reason)
        self.assertEqual(len(self.host.launched), 2)
        self.assertEqual(self.host.instances, {})
        self.assertEqual(len(self.deleted()), 2)

    def test_a_missing_incus_is_not_run_and_never_passed(self) -> None:
        self.host.missing = True
        got = not_run(self.boot())
        self.assertEqual(got.check, INCUS_BOOT)
        self.assertTrue(got.reason.startswith("incus failed: "))

    def test_a_boot_that_never_ends_fails_at_once_without_reading_it_and_the_instances_are_deleted(self) -> None:
        self.host.raises = ("systemctl is-system-running", subprocess.TimeoutExpired("incus", 1200))
        got = ran(self.boot())
        self.assertEqual(got.outcome, "FAILED")
        self.assertEqual(got.passed, ())
        self.assertEqual(
            [line.split(":")[0] for line in got.failed],
            ["cloud-init-first-boot-boot-finished"],
        )
        self.assertEqual(self.host.instances, {})

    def test_a_cloud_init_that_never_finishes_fails_and_the_instances_are_deleted(self) -> None:
        self.host.raises = ("cloud-init status", subprocess.TimeoutExpired("incus", 1200))
        got = ran(self.boot())
        self.assertEqual(got.outcome, "FAILED")
        self.assertIn("cloud-init did not finish within 1200 s", " ".join(got.failed))
        self.assertEqual(self.host.instances, {})
        self.assertEqual(len(self.deleted()), 2)

    def test_an_unexpected_error_still_deletes_the_instances(self) -> None:
        self.host.raises = ("getent passwd", RuntimeError("boom"))
        with self.assertRaisesRegex(RuntimeError, "boom"):
            self.boot()
        self.assertEqual(self.host.instances, {})

    def test_a_delete_that_fails_does_not_change_the_answer(self) -> None:
        self.host.delete_raises = True
        got = ran(self.boot())
        self.assertEqual(got.outcome, "PASSED")
        self.assertEqual(len(self.deleted()), 2, "every instance is still tried")


class TwoClonesTest(Scratch):
    def setUp(self) -> None:
        super().setUp()
        self.imported = incus_host.Imported("dif-check-aaaaaaaaaaaa", FINGERPRINT)

    def clones(self, *, ssh: bool = True) -> CheckOutcome:
        return incus_host.two_clones(self.imported, ssh=ssh, run=self.incus)

    def test_two_instances_that_made_their_own_identity_pass(self) -> None:
        got = ran(self.clones())
        self.assertEqual((got.check, got.outcome, got.failed), (TWO_CLONES, "PASSED", ()))
        self.assertEqual(got.passed, CompareClonesTest.ALL_PASSED)

    def test_two_instances_are_launched_with_no_configuration_and_deleted(self) -> None:
        self.clones()
        launches = [call for call in self.host.calls if call[0] == "launch"]
        self.assertEqual([call[:2] for call in launches], [("launch", self.imported.alias)] * 2)
        self.assertEqual([len(call) for call in launches], [3, 3])
        self.assertEqual(self.host.instances, {})
        self.assertEqual(len(self.deleted()), 2)

    def test_a_shared_machine_id_fails(self) -> None:
        first, second = good()
        second[MACHINE] = first[MACHINE]
        self.host.identities = [first, second]
        got = ran(self.clones())
        self.assertEqual(got.outcome, "FAILED")
        self.assertEqual(got.failed, (f"machine-ids-differ: {MACHINE} the same in both instances",))

    def test_instances_that_made_no_machine_id_fail(self) -> None:
        first, second = good()
        first[MACHINE] = second[MACHINE] = b"uninitialized\n"
        self.host.identities = [first, second]
        got = ran(self.clones())
        self.assertEqual(got.failed, ("machine-ids-made: an instance has no machine ID after its first boot",))

    def test_host_keys_are_asked_for_only_when_the_image_has_openssh(self) -> None:
        first, second = good()
        del first[SSH_KEY], second[SSH_KEY]
        self.host.identities = [first, second]
        self.assertEqual(ran(self.clones(ssh=False)).outcome, "PASSED")
        self.host.identities = [first, second]
        self.host.launched.clear()
        self.assertEqual(ran(self.clones(ssh=True)).failed, ("ssh-host-keys-made: an instance has no SSH host keys",))

    def test_an_instance_that_does_not_launch_is_not_run_and_both_are_deleted(self) -> None:
        for number in (1, 2):
            self.host.launch_fails = frozenset({number})
            self.host.launched.clear()
            self.host.calls.clear()
            got = not_run(self.clones())
            self.assertEqual(got.check, TWO_CLONES)
            self.assertIn("incus launch failed", got.reason)
            self.assertEqual(self.host.instances, {})
            self.assertEqual(len(self.deleted()), 2)

    def test_an_instance_that_cannot_be_read_is_not_run(self) -> None:
        self.host.read_returncode = 1
        got = not_run(self.clones())
        self.assertEqual(got.reason, "an instance could not be read: exec failed")
        self.assertEqual(self.host.instances, {})

    def test_an_answer_that_is_not_readable_is_not_run(self) -> None:
        self.host.read_output = "this is not a reading\n"
        got = not_run(self.clones())
        self.assertTrue(got.reason.startswith("an instance answered something unreadable: "))
        self.assertEqual(self.host.instances, {})

    def test_a_missing_incus_or_a_hang_is_not_run_and_never_passed(self) -> None:
        self.host.raises = ("systemctl", subprocess.TimeoutExpired("incus", 1200))
        got = not_run(self.clones())
        self.assertTrue(got.reason.startswith("incus failed: "))
        self.assertEqual(self.host.instances, {})
        self.host.missing = True
        self.assertTrue(not_run(self.clones()).reason.startswith("incus failed: "))

    def test_an_unexpected_error_still_deletes_the_instances(self) -> None:
        self.host.raises = ("systemctl", RuntimeError("boom"))
        with self.assertRaisesRegex(RuntimeError, "boom"):
            self.clones()
        self.assertEqual(self.host.instances, {})


# ---- ancestry by files ------------------------------------------------------------------------------


def files(*paths: str) -> list[Member]:
    return [Member(path, "file", "") for path in paths]


PARENT = "11" * 32
OTHER = "22" * 32


class FilesAncestryTest(unittest.TestCase):
    def test_an_image_that_holds_every_parent_file_and_names_the_parent_passes(self) -> None:
        got = ran(ancestry.files_ancestry(files("/etc/a", "/etc/b", "/new"), files("/etc/a", "/etc/b"), PARENT, PARENT))
        self.assertEqual((got.check, got.outcome), ("ancestry", "PASSED"))
        self.assertEqual(got.passed, ("parent-files-present", "provenance-names-parent"))

    def test_a_parent_file_the_image_lacks_fails_and_is_named(self) -> None:
        got = ran(ancestry.files_ancestry(files("/etc/a"), files("/etc/a", "/etc/b", "/usr/c"), PARENT, PARENT))
        self.assertEqual(got.outcome, "FAILED")
        self.assertEqual(
            got.failed,
            (
                "parent-files-present: /etc/b is the parent's and not the image's",
                "parent-files-present: /usr/c is the parent's and not the image's",
            ),
        )
        self.assertEqual(got.passed, ("provenance-names-parent",))

    def test_a_long_list_of_missing_files_is_cut_and_counted(self) -> None:
        parent = files(*(f"/data/{number:03d}" for number in range(40)))
        got = ran(ancestry.files_ancestry([], parent, PARENT, PARENT))
        self.assertEqual(len(got.failed), 26)
        self.assertEqual(got.failed[-1], "parent-files-present: and 15 more")

    def test_what_every_build_removes_is_not_missing(self) -> None:
        removed = [
            "/etc/hostname",
            "/etc/resolv.conf",
            "/etc/ssh/ssh_host_ed25519_key",
            "/etc/ssh/ssh_host_rsa_key.pub",
            "/var/lib/dbus/machine-id",
            "/var/lib/systemd/random-seed",
            "/var/lib/urandom/random-seed",
            "/var/lib/cloud/instance",
            "/var/lib/cloud/instances",
            "/var/lib/cloud/instances/i-1/user-data.txt",
            "/var/log/dpkg.log",
            "/var/log/apt/term.log",
            "/var/cache/ldconfig/aux-cache",
            "/var/lib/apt/lists/deb.example_dists_Release",
            "/var/cache/apt/pkgcache.bin",
            "/run/lock",
            "/tmp/scratch",
        ]
        got = ran(ancestry.files_ancestry(files("/etc/a"), files("/etc/a", *removed), PARENT, PARENT))
        self.assertEqual(got.outcome, "PASSED", got.failed)

    def test_what_looks_like_a_removed_path_but_is_not_one_is_missing(self) -> None:
        paths = [
            "/etc/hostname.d",
            "/var/lib/cloud/data",
            "/etc/ssh/sshd_config",
            "/var/lib/apt/extended_states",
            "/var/cache/debconf/config.dat",
        ]
        got = ran(ancestry.files_ancestry([], files(*paths), PARENT, PARENT))
        self.assertEqual(len(got.failed), len(paths), got.failed)

    def test_a_provenance_that_names_another_parent_or_none_fails(self) -> None:
        for named, text in ((OTHER, OTHER), (None, "no parent")):
            got = ran(ancestry.files_ancestry(files("/a"), files("/a"), PARENT, named))
            self.assertEqual(got.outcome, "FAILED")
            self.assertEqual(
                got.failed,
                (f"provenance-names-parent: the provenance names {text}, the parent is {PARENT}",),
            )
            self.assertEqual(got.passed, ("parent-files-present",))

    def test_both_failing_at_once_lists_both(self) -> None:
        got = ran(ancestry.files_ancestry([], files("/a"), PARENT, None))
        self.assertEqual(len(got.failed), 2)
        self.assertEqual(got.passed, ())

    def test_no_parent_files_at_all_is_fine(self) -> None:
        self.assertEqual(ran(ancestry.files_ancestry(files("/a"), [], PARENT, PARENT)).outcome, "PASSED")


# ---- test on an output directory --------------------------------------------------------------------


CORE_DIGEST = "5c" * 32


class Out:
    """An output directory: an Incus image on core and an Incus image on that, and the plan."""

    def __init__(self, root: Path, *, packages: Sequence[tuple[str, str, str]] = BASE) -> None:
        self.root = root
        self.packages = packages
        self.root_fs = incusimage.fixture("incus-root")
        self.base = write_image(
            root, "incus-base", BASE_IDENTITY, self.root_fs, ancestors=[("core", CORE_DIGEST)], packages=packages
        )
        self.app = write_image(
            root,
            "incus-app",
            APP_IDENTITY,
            self.root_fs,
            ancestors=[("incus-base", self.base.fingerprint), ("core", CORE_DIGEST)],
            packages=packages,
        )
        self.write_plan(packages=packages)

    def write_plan(
        self, *, packages: Sequence[tuple[str, str, str]] = BASE, checks: Sequence[str] = incusimage.INCUS_CHECKS
    ) -> None:
        (self.root / "plan.json").write_text(
            incusimage.plan_text(
                {"incus-base": (BASE_IDENTITY, "core", "incus"), "incus-app": (APP_IDENTITY, "incus-base", "incus")},
                packages=packages,
                checks=checks,
            )
        )

    def plan(self) -> Plan:
        return parse_plan(json.loads((self.root / "plan.json").read_text()))

    def run(self, host: Host, requested: Sequence[str] = ()) -> tuple[int, str]:
        out = io.StringIO()
        effects = command.Effects(incus=runner(host))
        status = command.test_command(self.root, requested, Sources(), out, effects)
        return status, out.getvalue()

    def results(self, image: Image) -> dict[str, str]:
        found: dict[str, str] = {}
        for one in records.decode_statements(image.records.read_text()):
            predicate = one["predicate"]
            if one.get("predicateType") == rec.TEST_RESULT_PREDICATE and isinstance(predicate, dict):
                found[str(predicate["configuration"][0]["name"])] = str(predicate["result"])
        return found

    def subjects_of_results(self, image: Image) -> list[object]:
        return [
            one["subject"]
            for one in records.decode_statements(image.records.read_text())
            if one.get("predicateType") == rec.TEST_RESULT_PREDICATE
        ]


class Base(unittest.TestCase):
    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory(prefix="checks-incus-out-")
        self.addCleanup(scratch.cleanup)
        self.out = Out(Path(scratch.name))
        self.host = Host()
        patch = mock.patch("debian_image_factory.checks.incus_host.time.monotonic", Clock().monotonic)
        patch.start()
        self.addCleanup(patch.stop)


class DiscoveryTest(Base):
    def found(self) -> tuple[list[command.Found], list[str]]:
        return command.find_artifacts(self.out.root, self.out.plan())

    def test_an_incus_pair_is_found_once_by_its_fingerprint_and_its_rootfs_is_not_skipped(self) -> None:
        found, skipped = self.found()
        self.assertEqual(skipped, [])
        self.assertEqual(
            [(one.image, one.path.name, one.digest, one.layout) for one in found],
            [
                ("incus-app", self.out.app.names.metadata, self.out.app.fingerprint, None),
                ("incus-base", self.out.base.names.metadata, self.out.base.fingerprint, None),
            ],
        )

    def test_a_missing_rootfs_skips_the_image_with_the_reason(self) -> None:
        self.out.app.rootfs.unlink()
        found, skipped = self.found()
        self.assertEqual([one.image for one in found], ["incus-base"])
        self.assertEqual(
            skipped, [f"skipped {self.out.app.names.metadata}: no rootfs {self.out.app.names.rootfs} beside it"]
        )

    def test_a_rootfs_without_its_metadata_tarball_is_neither_found_nor_skipped(self) -> None:
        self.out.app.metadata.unlink()
        found, skipped = self.found()
        self.assertEqual([one.image for one in found], ["incus-base"])
        self.assertEqual(skipped, [])

    def test_a_rootfs_that_is_not_the_one_the_name_says_is_skipped(self) -> None:
        self.out.app.rootfs.write_bytes(incusimage.fixture("scan"))
        found, skipped = self.found()
        self.assertEqual([one.image for one in found], ["incus-base"])
        self.assertEqual(len(skipped), 1)
        self.assertIn("does not match the digest in its name", skipped[0])

    def test_an_image_that_is_not_of_the_incus_kind_in_the_plan_is_skipped(self) -> None:
        text = (self.out.root / "plan.json").read_text().replace('"kind": "incus"', '"kind": "oci"')
        found, skipped = command.find_artifacts(self.out.root, parse_plan(json.loads(text)))
        self.assertEqual(found, [])
        self.assertEqual(len(skipped), 2)
        self.assertIn("is of kind oci, not incus", skipped[0])

    def test_an_image_the_plan_does_not_know_is_skipped(self) -> None:
        text = (self.out.root / "plan.json").read_text().replace(APP_IDENTITY, "99" * 32)
        found, skipped = command.find_artifacts(self.out.root, parse_plan(json.loads(text)))
        self.assertEqual([one.image for one in found], ["incus-base"])
        self.assertIn("no image of the plan has this name and identity", skipped[0])


class ParentNamedTest(Base):
    def named(self, image: Image) -> str | None:
        return command.parent_named(image.records.read_text(), image.fingerprint)

    def test_the_first_ancestor_of_the_provenance_is_the_parent(self) -> None:
        self.assertEqual(self.named(self.out.app), self.out.base.fingerprint)
        self.assertEqual(self.named(self.out.base), CORE_DIGEST)

    def test_no_records_or_unreadable_records_name_no_parent(self) -> None:
        self.assertIsNone(command.parent_named(None, self.out.app.fingerprint))
        self.assertIsNone(command.parent_named("not json\n", self.out.app.fingerprint))

    def test_records_about_another_digest_name_no_parent(self) -> None:
        self.assertIsNone(command.parent_named(self.out.app.records.read_text(), "00" * 32))

    def test_a_provenance_without_ancestors_names_no_parent(self) -> None:
        bare = write_image(self.out.root, "incus-bare", BASE_IDENTITY, incusimage.fixture("scan"))
        self.assertIsNone(self.named(bare))

    def test_two_provenance_records_that_agree_name_their_parent(self) -> None:
        text = self.out.app.records.read_text()
        named = command.parent_named(text + text.splitlines(keepends=True)[0], self.out.app.fingerprint)
        self.assertEqual(named, self.out.base.fingerprint)

    def test_the_provenance_is_found_by_any_of_its_three_subjects(self) -> None:
        meta = hashlib.sha256(self.out.app.metadata.read_bytes()).hexdigest()
        self.assertEqual(command.parent_named(self.out.app.records.read_text(), meta), self.out.base.fingerprint)


class FileParentTest(Base):
    def others(self) -> list[command.Found]:
        return command.find_artifacts(self.out.root, self.out.plan())[0]

    def one(self, image: str) -> command.Found:
        return next(one for one in self.others() if one.image == image)

    def test_the_parent_is_the_one_artifact_of_the_parent_image(self) -> None:
        got = command.file_parent(self.one("incus-app"), self.out.plan(), self.others())
        assert isinstance(got, command.Found)
        self.assertEqual((got.image, got.digest), ("incus-base", self.out.base.fingerprint))

    def test_a_parent_that_is_not_in_the_output_is_named_as_missing(self) -> None:
        got = command.file_parent(self.one("incus-base"), self.out.plan(), self.others())
        self.assertEqual(got, "the parent core is not in the output, so its files cannot be compared")

    def test_an_image_without_a_parent_has_none(self) -> None:
        text = (self.out.root / "plan.json").read_text().replace('"parent": "incus-base"', '"parent": null')
        plan = parse_plan(json.loads(text))
        self.assertEqual(command.file_parent(self.one("incus-app"), plan, self.others()), "the image has no parent")

    def test_two_builds_of_the_parent_are_not_chosen_between(self) -> None:
        write_image(self.out.root, "incus-base", BASE_IDENTITY, incusimage.fixture("scan"))
        got = command.file_parent(self.one("incus-app"), self.out.plan(), self.others())
        self.assertEqual(got, "the output holds 2 builds of the parent incus-base")


class RunTest(Base):
    def test_a_good_pair_passes_every_check_that_runs_here_and_each_is_recorded_for_its_fingerprint(self) -> None:
        status, printed = self.out.run(self.host)
        self.assertEqual(status, 0, printed)
        app = self.out.results(self.out.app)
        self.assertEqual(app, dict.fromkeys(incusimage.INCUS_CHECKS, "PASSED"))
        base = self.out.results(self.out.base)
        self.assertEqual(base, {name: "PASSED" for name in incusimage.INCUS_CHECKS if name != "ancestry"})
        for subjects in self.out.subjects_of_results(self.out.app):
            self.assertEqual(
                subjects, [{"name": self.out.app.names.metadata, "digest": {"sha256": self.out.app.fingerprint}}]
            )

    def test_the_parent_not_in_the_output_is_listed_as_not_run_and_writes_no_record(self) -> None:
        _, printed = self.out.run(self.host)
        self.assertIn("incus-base: ancestry not run: the parent core is not in the output", printed)
        self.assertNotIn("ancestry", self.out.results(self.out.base))

    def test_the_image_is_imported_once_and_deleted_after_the_instances_for_each_image(self) -> None:
        self.out.run(self.host)
        verbs = [call[:2] for call in self.host.calls if call[0] in ("image", "delete")]
        self.assertEqual(verbs.count(("image", "import")), 2)
        self.assertEqual(verbs.count(("image", "delete")), 2)
        self.assertEqual(self.host.images, {})
        self.assertEqual(self.host.instances, {})
        calls = self.host.calls
        for start in (index for index, call in enumerate(calls) if call[:2] == ("image", "import")):
            end = next(index for index in range(start, len(calls)) if calls[index][:2] == ("image", "delete"))
            instances = [call for call in calls[start:end] if call[0] == "launch"]
            deletes = [call for call in calls[start:end] if call[:2] == ("delete", "--force")]
            self.assertEqual((len(instances), len(deletes)), (4, 4))

    def test_the_image_is_imported_from_the_pair_with_its_own_fingerprint(self) -> None:
        self.out.run(self.host, ["two-clones"])
        imports = [call for call in self.host.calls if call[:2] == ("image", "import")]
        self.assertEqual(
            sorted(call[2:4] for call in imports),
            sorted([(str(image.metadata), str(image.rootfs)) for image in (self.out.app, self.out.base)]),
        )

    def test_no_incus_is_reached_when_no_check_needs_it(self) -> None:
        status, _ = self.out.run(self.host, ["package-set", "sbom-complete", "no-machine-identity", "ancestry"])
        self.assertEqual(status, 0)
        self.assertEqual(self.host.calls, [])

    def test_a_missing_incus_leaves_the_hosted_checks_not_run_and_the_rest_run(self) -> None:
        self.host.missing = True
        status, printed = self.out.run(self.host)
        self.assertEqual(status, 0, printed)
        self.assertEqual(
            self.out.results(self.out.app),
            {name: "PASSED" for name in incusimage.INCUS_CHECKS if name not in ("incus-boot", "two-clones")},
        )
        for check in ("incus-boot", "two-clones"):
            self.assertIn(f"incus-app: {check} not run: incus is not available: ", printed)
            self.assertNotIn(check, self.out.results(self.out.app))
        self.assertEqual(self.host.calls, [("info",)] * 2, "one question per image, no import")

    def test_a_daemon_that_does_not_answer_leaves_them_not_run(self) -> None:
        self.host.info_returncode, self.host.info_error = 1, "Error: daemon not running"
        status, printed = self.out.run(self.host)
        self.assertEqual(status, 0)
        self.assertIn("incus-app: incus-boot not run: incus is not usable: Error: daemon not running", printed)

    def test_a_refused_import_leaves_them_not_run(self) -> None:
        self.host.import_returncode, self.host.import_error = 1, "Error: invalid image"
        status, printed = self.out.run(self.host)
        self.assertEqual(status, 0)
        self.assertIn("incus-app: two-clones not run: incus image import failed: Error: invalid image", printed)
        self.assertEqual(self.host.instances, {})

    def test_a_fingerprint_incus_computes_differently_leaves_them_not_run_and_the_image_deleted(self) -> None:
        self.host.printed_fingerprint = "ee" * 32
        status, printed = self.out.run(self.host)
        self.assertEqual(status, 0)
        self.assertIn(f"incus-boot not run: Incus computed the fingerprint {'ee' * 32}", printed)
        self.assertEqual(self.host.images, {})
        self.assertEqual(self.host.instances, {})

    def test_a_launch_that_fails_is_not_run_and_nothing_is_left(self) -> None:
        self.host.launch_fails = frozenset({1, 2, 3, 4, 5, 6, 7, 8})
        status, printed = self.out.run(self.host)
        self.assertEqual(status, 0)
        self.assertIn("incus-app: incus-boot not run: incus launch failed", printed)
        self.assertIn("incus-app: two-clones not run: incus launch failed", printed)
        self.assertEqual(self.host.images, {})
        self.assertEqual(self.host.instances, {})
        self.assertNotIn("incus-boot", self.out.results(self.out.app))

    def test_an_unexpected_error_in_a_step_still_deletes_the_instances_and_the_image(self) -> None:
        self.host.raises = ("cloud-init status", RuntimeError("boom"))
        with self.assertRaisesRegex(RuntimeError, "boom"):
            self.out.run(self.host)
        self.assertEqual(self.host.instances, {})
        self.assertEqual(self.host.images, {})

    def test_a_failing_image_delete_does_not_change_the_checks_answers(self) -> None:
        self.host.raises = ("image delete", OSError("the incus socket is gone"))
        status, printed = self.out.run(self.host)
        self.assertEqual(status, 0, printed)
        self.assertEqual(self.out.results(self.out.app)["incus-boot"], "PASSED")

    def test_a_failing_hosted_check_fails_the_command(self) -> None:
        self.host.cloud_init_status = 1
        status, printed = self.out.run(self.host)
        self.assertEqual(status, 1)
        self.assertEqual(self.out.results(self.out.app)["incus-boot"], "FAILED")
        self.assertIn("incus-app: incus-boot FAILED: ", printed)

    def test_a_warning_is_recorded_as_warned_and_does_not_fail_the_command(self) -> None:
        self.host.cloud_init_status = 2
        status, _ = self.out.run(self.host)
        self.assertEqual(status, 0)
        self.assertEqual(self.out.results(self.out.app)["incus-boot"], "WARNED")

    def test_two_clones_asks_for_host_keys_only_when_the_image_installs_openssh(self) -> None:
        keyless = [{MACHINE: b"x\n", HOSTNAME: b"a\n"}, {MACHINE: b"y\n", HOSTNAME: b"b\n"}] * 2
        self.out.write_plan(packages=(*BASE, ("openssh-server", "1.0", "amd64")))
        self.out.run(Host(identities=keyless), ["two-clones"])
        self.assertEqual(self.out.results(self.out.app)["two-clones"], "FAILED")
        self.out.write_plan()
        self.out.run(Host(identities=keyless), ["two-clones"])
        self.assertEqual(self.out.results(self.out.app)["two-clones"], "PASSED")  # the last record wins


class AncestryRunTest(Base):
    def test_a_child_that_lacks_a_file_of_its_parent_fails_naming_it(self) -> None:
        child = write_image(
            self.out.root,
            "incus-app",
            APP_IDENTITY,
            incusimage.fixture("scan"),  # a different tree: none of the parent's files
            ancestors=[("incus-base", self.out.base.fingerprint)],
        )
        self.out.app.metadata.unlink()
        self.out.app.rootfs.unlink()
        status, printed = self.out.run(self.host, ["ancestry"])
        self.assertEqual(status, 1, printed)
        self.assertIn("parent-files-present: /var/lib/dpkg/status is the parent's and not the image's", printed)
        self.assertEqual(self.out.results(child)["ancestry"], "FAILED")

    def test_a_provenance_that_names_another_parent_fails(self) -> None:
        # the same pair again, with a provenance that names another digest for its parent
        again = write_image(
            self.out.root, "incus-app", APP_IDENTITY, self.out.root_fs, ancestors=[("incus-base", "77" * 32)]
        )
        self.assertEqual(again.fingerprint, self.out.app.fingerprint)
        status, printed = self.out.run(self.host, ["ancestry"])
        self.assertEqual(status, 1, printed)
        self.assertIn(
            f"provenance-names-parent: the provenance names {'77' * 32}, the parent is {self.out.base.fingerprint}",
            printed,
        )

    def test_a_provenance_that_names_no_parent_fails(self) -> None:
        write_image(self.out.root, "incus-app", APP_IDENTITY, self.out.root_fs)
        status, printed = self.out.run(self.host, ["ancestry"])
        self.assertEqual(status, 1, printed)
        self.assertIn("the provenance names no parent", printed)


class RecordsTest(Base):
    def test_a_check_that_ran_is_appended_to_the_records_file_and_the_others_stay(self) -> None:
        before = self.out.app.records.read_text()
        self.out.run(self.host, ["package-set"])
        after = self.out.app.records.read_text()
        self.assertTrue(after.startswith(before))
        self.assertEqual(self.out.results(self.out.app), {"package-set": "PASSED"})

    def test_the_package_set_of_an_image_the_plan_does_not_say_fails(self) -> None:
        self.out.write_plan(packages=(*BASE, ("extra", "1.0", "amd64")))
        status, _ = self.out.run(self.host, ["package-set"])
        self.assertEqual(status, 1)
        self.assertEqual(self.out.results(self.out.app), {"package-set": "FAILED"})

    def test_a_build_snapshot_left_in_the_root_filesystem_fails_the_image(self) -> None:
        text = (self.out.root / "plan.json").read_text().replace(SNAPSHOT, "20261121T004329Z")  # scan.sqsh holds it
        (self.out.root / "plan.json").write_text(text)
        scan = write_image(self.out.root, "incus-app", APP_IDENTITY, incusimage.fixture("scan"))
        self.out.app.metadata.unlink()
        self.out.app.rootfs.unlink()
        status, printed = self.out.run(self.host, ["no-build-snapshot"])
        self.assertEqual(status, 1, printed)
        self.assertEqual(self.out.results(scan), {"no-build-snapshot": "FAILED"})
        self.assertEqual(self.out.results(self.out.base), {"no-build-snapshot": "PASSED"})


if __name__ == "__main__":
    unittest.main()
