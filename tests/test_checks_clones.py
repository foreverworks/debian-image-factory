"""`two-clones`: the comparison, and the docker edge with a stand-in for docker."""

import base64
import subprocess
import unittest
from collections.abc import Sequence
from pathlib import Path

from debian_image_factory.checks import clones
from debian_image_factory.checks.model import NotRun, Result

MACHINE = "/etc/machine-id"
DBUS = "/var/lib/dbus/machine-id"
HOSTKEY = "/etc/ssh/ssh_host_ed25519_key.pub"


def reading(files: dict[str, bytes]) -> str:
    return "".join(f"{path} {base64.b64encode(value).decode()}\n" for path, value in files.items())


class ParseTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        files = {MACHINE: b"abc\n", HOSTKEY: b"ssh-ed25519 AAAA host\n", DBUS: b""}
        self.assertEqual(clones.parse_readings(reading(files)), files)
        self.assertEqual(clones.parse_readings(""), {})

    def test_garbage_is_refused(self) -> None:
        for text in ("no path here\n", "/etc/x !!!notbase64\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                clones.parse_readings(text)


class CompareTest(unittest.TestCase):
    def test_nothing_present_passes(self) -> None:
        found = clones.compare({}, {})
        self.assertEqual(found.outcome, "PASSED")
        self.assertEqual(found.passed, ("machine-ids-differ", "dbus-machine-ids-differ", "ssh-host-keys-differ"))

    def test_empty_and_uninitialized_are_no_identity(self) -> None:
        for value in (b"", b"uninitialized\n"):
            with self.subTest(value=value):
                self.assertEqual(clones.compare({MACHINE: value}, {MACHINE: value}).outcome, "PASSED")

    def test_values_that_differ_pass(self) -> None:
        self.assertEqual(clones.compare({MACHINE: b"aaa\n", HOSTKEY: b"k1"}, {MACHINE: b"bbb\n", HOSTKEY: b"k2"}).outcome, "PASSED")

    def test_a_value_present_and_equal_fails_only_its_test(self) -> None:
        found = clones.compare({MACHINE: b"aaa\n", DBUS: b"x", HOSTKEY: b"k1"}, {MACHINE: b"aaa\n", DBUS: b"y", HOSTKEY: b"k2"})
        self.assertEqual(found.outcome, "FAILED")
        self.assertEqual(found.passed, ("dbus-machine-ids-differ", "ssh-host-keys-differ"))
        self.assertEqual(found.failed, (f"machine-ids-differ: {MACHINE} is the same in both instances",))

    def test_a_shared_host_key_fails(self) -> None:
        found = clones.compare({HOSTKEY: b"k"}, {HOSTKEY: b"k", MACHINE: b"z"})
        self.assertEqual([name.split(":")[0] for name in found.failed], ["ssh-host-keys-differ"])


class Docker:
    """Records the docker commands and answers them: `outputs` are what the two containers print."""

    def __init__(
        self, outputs: Sequence[str] = ("", ""), failing: str | None = None, missing: bool = False
    ) -> None:
        self.commands: list[list[str]] = []
        self.outputs = list(outputs)
        self.failing = failing
        self.missing = missing

    def __call__(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if self.missing:
            raise FileNotFoundError("docker")
        self.commands.append(list(args))
        if args[0] == self.failing:
            return subprocess.CompletedProcess(args, 1, "", f"{args[0]} refused")
        out = self.outputs.pop(0) if args[0] == "run" else ""
        return subprocess.CompletedProcess(args, 0, out, "")

    def verbs(self) -> list[str]:
        return [command[0] for command in self.commands]


class EdgeTest(unittest.TestCase):
    path = Path("/out/core.tar.gz")

    def test_two_instances_that_differ(self) -> None:
        docker = Docker([reading({MACHINE: b"a\n"}), reading({MACHINE: b"b\n"})])
        found = clones.two_clones(self.path, docker)
        self.assertIsInstance(found, Result)
        assert isinstance(found, Result)
        self.assertEqual(found.outcome, "PASSED")
        self.assertEqual(docker.verbs(), ["info", "import", "run", "run", "rm", "rm", "rmi"])
        runs = [c for c in docker.commands if c[0] == "run"]
        self.assertTrue(all("--network" in c and c[c.index("--network") + 1] == "none" for c in runs))
        self.assertNotEqual(runs[0][2], runs[1][2])

    def test_two_instances_that_share_an_identity_fail_and_are_still_cleaned_up(self) -> None:
        docker = Docker([reading({MACHINE: b"same\n"})] * 2)
        found = clones.two_clones(self.path, docker)
        assert isinstance(found, Result)
        self.assertEqual(found.outcome, "FAILED")
        self.assertEqual(docker.verbs()[-3:], ["rm", "rm", "rmi"])

    def test_no_docker_is_not_run(self) -> None:
        found = clones.two_clones(self.path, Docker(missing=True))
        self.assertIsInstance(found, NotRun)
        assert isinstance(found, NotRun)
        self.assertEqual(found.check, "two-clones")
        self.assertIn("not available", found.reason)

    def test_an_unreachable_daemon_is_not_run_and_nothing_is_imported(self) -> None:
        docker = Docker(failing="info")
        found = clones.two_clones(self.path, docker)
        self.assertIsInstance(found, NotRun)
        self.assertEqual(docker.verbs(), ["info"])

    def test_an_import_that_fails_is_not_run_and_cleans_up(self) -> None:
        docker = Docker(failing="import")
        found = clones.two_clones(self.path, docker)
        self.assertIsInstance(found, NotRun)
        self.assertEqual(docker.verbs()[-1], "rmi")

    def test_an_instance_that_does_not_run_or_answers_nonsense_is_not_run(self) -> None:
        self.assertIsInstance(clones.two_clones(self.path, Docker(failing="run")), NotRun)
        self.assertIsInstance(clones.two_clones(self.path, Docker(["nonsense\n", ""])), NotRun)
