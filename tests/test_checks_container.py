"""The docker-backed OCI checks against a stand-in for docker: load, `oci-run`, `two-clones`, the probe runner."""

import subprocess
import unittest
from pathlib import Path

from debian_image_factory import oci
from debian_image_factory.checks import container
from debian_image_factory.checks.dockerio import Docker
from debian_image_factory.checks.model import NotRun, Result
from debian_image_factory.modules import Probe
from tests.support.fakedocker import IMAGE_ID, FakeDocker, reading

LAYOUT = Path("/out/image.oci")
IMAGE = container.Loaded(IMAGE_ID)
DECLARED = oci.OciConfig("0:0", None, ("/bin/sh", "-c", "exit 0"))
MACHINE = "/etc/machine-id"


def result_of(found: object) -> Result:
    assert isinstance(found, Result), found
    return found


class LoadTest(unittest.TestCase):
    def test_the_layout_is_loaded_once_and_the_image_removed_by_its_id(self) -> None:
        fake = FakeDocker()
        with container.loaded(LAYOUT, fake.docker()) as image:
            self.assertEqual(image, IMAGE)
        self.assertEqual(fake.loaded, [LAYOUT])
        self.assertEqual(fake.commands[-1], ["rmi", IMAGE_ID])

    def test_an_image_that_is_not_loaded_is_not_removed(self) -> None:
        for fake in (
            FakeDocker(failing="load"),
            FakeDocker(failing="info"),
            FakeDocker(missing=True),
            FakeDocker(load_output="Loaded image: x:y\n"),
        ):
            with self.subTest(failing=fake.failing), container.loaded(LAYOUT, fake.docker()) as image:
                self.assertIsInstance(image, str)
            self.assertNotIn("rmi", fake.verbs())

    def test_the_reasons_say_what_docker_said(self) -> None:
        with container.loaded(LAYOUT, FakeDocker(failing="load").docker()) as image:
            self.assertEqual(image, "docker could not load the image layout: load refused")
        with container.loaded(LAYOUT, FakeDocker(missing=True).docker()) as image:
            self.assertIn("docker is not available", str(image))

    def test_the_image_is_removed_when_the_block_raises(self) -> None:
        fake = FakeDocker()
        with self.assertRaises(RuntimeError), container.loaded(LAYOUT, fake.docker()):
            raise RuntimeError("boom")
        self.assertEqual(fake.commands[-1], ["rmi", IMAGE_ID])


class OciRunTest(unittest.TestCase):
    def test_a_matching_image_that_exits_0_passes_every_test(self) -> None:
        fake = FakeDocker()
        found = result_of(container.oci_run(DECLARED, IMAGE, fake.docker()))
        self.assertEqual(found.outcome, "PASSED")
        self.assertEqual(found.passed, ("user-as-declared", "entrypoint-as-declared", "cmd-as-declared", "exits-0"))
        run = next(c for c in fake.commands if c[0] == "run")
        self.assertEqual(run[run.index("--network") + 1], "none")
        self.assertEqual(run[-1], IMAGE_ID)
        self.assertIn("--rm", run)
        self.assertEqual(fake.commands[-1][:2], ["rm", "--force"])

    def test_a_cmd_that_exits_1_fails_only_the_exit_test(self) -> None:
        found = result_of(container.oci_run(DECLARED, IMAGE, FakeDocker(exit_code=1).docker()))
        self.assertEqual(found.outcome, "FAILED")
        self.assertEqual(found.passed, ("user-as-declared", "entrypoint-as-declared", "cmd-as-declared"))
        self.assertEqual(found.failed, ("exits-0: it exited 1: boom",))

    def test_an_image_that_does_not_exit_in_time_fails(self) -> None:
        fake = FakeDocker(timeout_on_run=True)
        found = result_of(container.oci_run(DECLARED, IMAGE, fake.docker(), timeout=5))
        self.assertEqual(found.failed, ("exits-0: it did not exit within 5 seconds",))
        self.assertEqual(fake.commands[-1][:2], ["rm", "--force"])

    def test_a_config_docker_reports_differently_fails_its_own_test(self) -> None:
        fake = FakeDocker(config={"User": "1000", "Entrypoint": ["/x"], "Cmd": ["a"]})
        found = result_of(container.oci_run(DECLARED, IMAGE, fake.docker()))
        self.assertEqual(
            [item.split(":")[0] for item in found.failed],
            ["user-as-declared", "entrypoint-as-declared", "cmd-as-declared"],
        )
        self.assertEqual(found.passed, ("exits-0",))

    def test_unset_is_unset_whichever_way_docker_says_it(self) -> None:
        configs: list[dict[str, object]] = [{}, {"User": "", "Entrypoint": None, "Cmd": []}]
        for config in configs:
            with self.subTest(config=config):
                found = result_of(container.oci_run(oci.OciConfig(), IMAGE, FakeDocker(config=config).docker()))
                self.assertEqual(found.outcome, "PASSED")

    def test_an_entrypoint_and_a_cmd_are_compared_in_order(self) -> None:
        declared = oci.OciConfig("node", ("docker-entrypoint.sh",), ("node",))
        same = FakeDocker(config={"User": "node", "Entrypoint": ["docker-entrypoint.sh"], "Cmd": ["node"]})
        self.assertEqual(result_of(container.oci_run(declared, IMAGE, same.docker())).outcome, "PASSED")
        swapped = FakeDocker(config={"User": "node", "Entrypoint": ["node"], "Cmd": ["docker-entrypoint.sh"]})
        self.assertEqual(result_of(container.oci_run(declared, IMAGE, swapped.docker())).outcome, "FAILED")

    def test_docker_failing_is_not_run(self) -> None:
        for failing in ("image",):
            found = container.oci_run(DECLARED, IMAGE, FakeDocker(failing=failing).docker())
            self.assertIsInstance(found, NotRun)

    def test_garbage_from_inspect_is_not_run(self) -> None:
        fake = FakeDocker()
        docker = Docker(
            run=lambda args: subprocess.CompletedProcess(args, 0, "not json", ""),
            run_limited=fake.run_limited,
            load=fake.load,
        )
        self.assertIsInstance(container.oci_run(DECLARED, IMAGE, docker), NotRun)


class TwoClonesTest(unittest.TestCase):
    def test_instances_that_differ_pass_and_the_image_is_not_removed(self) -> None:
        fake = FakeDocker(identities=[reading({MACHINE: b"a\n"}), reading({MACHINE: b"b\n"})])
        found = result_of(container.two_clones(IMAGE, fake.docker()))
        self.assertEqual(found.outcome, "PASSED")
        runs = [c for c in fake.commands if c[0] == "run"]
        self.assertEqual(len(runs), 2)
        for command in runs:
            self.assertEqual(command[command.index("--entrypoint") + 1], "/bin/sh")
            self.assertIn(IMAGE_ID, command)
        self.assertNotIn("rmi", fake.verbs())

    def test_a_shared_machine_id_fails(self) -> None:
        fake = FakeDocker(identities=[reading({MACHINE: b"same\n"})] * 2)
        self.assertEqual(result_of(container.two_clones(IMAGE, fake.docker())).outcome, "FAILED")
        self.assertEqual(fake.verbs()[-2:], ["rm", "rm"])


class ProbeTest(unittest.TestCase):
    def test_a_probe_runs_in_a_container_with_its_command_as_the_entrypoint(self) -> None:
        fake = FakeDocker(probes={"/usr/local/bin/node": (0, "v26.1.0\n")})
        run = container.run_probe(IMAGE_ID, fake.docker())
        self.assertEqual(run(Probe("node", ("/usr/local/bin/node", "--version"), "v26.1.0")), (0, "v26.1.0\n"))
        command = fake.commands[-1]
        self.assertEqual(command[:2], ["run", "--rm"])
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertEqual(command[command.index("--entrypoint") + 1 :], ["/usr/local/bin/node", IMAGE_ID, "--version"])

    def test_a_missing_program_reports_docker_s_status(self) -> None:
        run = container.run_probe(IMAGE_ID, FakeDocker().docker())
        self.assertEqual(run(Probe("x", ("/nope",), "1")), (127, ""))

    def test_a_probe_that_runs_out_of_time_reports_124_and_is_removed(self) -> None:
        fake = FakeDocker(timeout_on_run=True)
        self.assertEqual(container.run_probe(IMAGE_ID, fake.docker())(Probe("x", ("/slow",), "1")), (124, ""))
        self.assertEqual(fake.commands[-1][:2], ["rm", "--force"])

    def test_a_probe_without_a_command_is_a_bug(self) -> None:
        with self.assertRaises(ValueError):
            container.run_probe(IMAGE_ID, FakeDocker().docker())(Probe("x", (), "1"))


if __name__ == "__main__":
    unittest.main()
