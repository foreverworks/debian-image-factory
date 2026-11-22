"""The container checks of an OCI image against real rootless docker, with no builder.

The image is a one-layer OCI layout whose layer is the root filesystem of the official `busybox:stable`
image (`docker create` and `docker export`), with a declared user and cmd. `oci-run`, `two-clones` and the
`locked-inputs` probe runner then run on it for real, and so does `test` over an output directory.
Needs rootless docker and, once, network access to pull busybox.
"""

import gzip
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from debian_image_factory import oci, records
from debian_image_factory.checks import command, container
from debian_image_factory.checks.dockerio import DOCKER
from debian_image_factory.checks.model import Result
from debian_image_factory.commands import Sources
from debian_image_factory.modules import Probe
from tests.support import ocimage

BUSYBOX = "busybox:stable"


def docker(*args: str, stdout: int | None = subprocess.PIPE) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["docker", *args], check=True, stdout=stdout, stderr=subprocess.PIPE)


def busybox_layer() -> bytes:
    """The gzip tarball of busybox's root filesystem."""
    docker("pull", "--quiet", BUSYBOX)
    created = docker("create", BUSYBOX).stdout.decode().strip()
    try:
        return gzip.compress(docker("export", created).stdout, mtime=0)
    finally:
        docker("rm", created)


def image_ids() -> set[str]:
    return set(docker("image", "ls", "--all", "--quiet", "--no-trunc").stdout.decode().split())


def image_id(layout: Path) -> str:
    """The ID docker gives the layout's image once loaded: the digest of its config blob. The tests below
    look for their own image only, so another class loading an image into the same daemon at the same time
    is not mistaken for a leak."""
    index = json.loads((layout / "index.json").read_text())
    manifest = json.loads(
        (layout / "blobs" / "sha256" / index["manifests"][0]["digest"].removeprefix("sha256:")).read_text()
    )
    return str(manifest["config"]["digest"])


def cmd(*words: str) -> oci.OciConfig:
    return oci.OciConfig("0:0", None, words)


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class OciChecksTest(unittest.TestCase):
    layer: bytes

    @classmethod
    def setUpClass(cls) -> None:
        cls.layer = busybox_layer()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)

    def built(self, config: oci.OciConfig) -> ocimage.Built:
        built = ocimage.write_oci(self.out, "app", [self.layer], config=config)
        leaked = image_id(built.path)
        self.addCleanup(lambda: self.assertNotIn(leaked, image_ids(), "the check left its image behind"))
        return built

    def test_a_declared_image_that_exits_0_passes_oci_run_and_is_removed_by_its_id(self) -> None:
        built = self.built(cmd("/bin/sh", "-c", "exit 0"))
        with container.loaded(built.path) as image:
            assert isinstance(image, container.Loaded), image
            found = container.oci_run(oci.OciConfig("0:0", None, ("/bin/sh", "-c", "exit 0")), image)
        assert isinstance(found, Result), found
        self.assertEqual(found.outcome, "PASSED", found.failed)
        self.assertEqual(found.passed, ("user-as-declared", "entrypoint-as-declared", "cmd-as-declared", "exits-0"))

    def test_a_cmd_that_exits_1_fails(self) -> None:
        built = self.built(cmd("/bin/sh", "-c", "exit 1"))
        with container.loaded(built.path) as image:
            assert isinstance(image, container.Loaded), image
            found = container.oci_run(cmd("/bin/sh", "-c", "exit 1"), image)
        assert isinstance(found, Result), found
        self.assertEqual(found.outcome, "FAILED")
        self.assertEqual(found.passed, ("user-as-declared", "entrypoint-as-declared", "cmd-as-declared"))
        self.assertTrue(found.failed[0].startswith("exits-0: it exited 1"), found.failed)

    def test_a_declaration_the_loaded_image_does_not_have_fails_its_test(self) -> None:
        built = self.built(cmd("/bin/sh", "-c", "exit 0"))
        with container.loaded(built.path) as image:
            assert isinstance(image, container.Loaded), image
            found = container.oci_run(oci.OciConfig("0:0", ("/bin/true",), ("/bin/sh", "-c", "exit 0")), image)
        assert isinstance(found, Result), found
        self.assertEqual([item.split(":")[0] for item in found.failed], ["entrypoint-as-declared"])

    def test_an_image_that_does_not_exit_is_failed_and_its_container_removed(self) -> None:
        built = self.built(cmd("/bin/sleep", "60"))
        with container.loaded(built.path) as image:
            assert isinstance(image, container.Loaded), image
            found = container.oci_run(cmd("/bin/sleep", "60"), image, DOCKER, timeout=3)
            names = (
                docker("ps", "--all", "--quiet", "--filter", "name=dif-oci-run-", "--filter", f"ancestor={image.image}")
                .stdout.decode()
                .split()
            )
        assert isinstance(found, Result), found
        self.assertEqual(found.failed, ("exits-0: it did not exit within 3 seconds",))
        self.assertEqual(names, [])

    def test_two_containers_of_the_image_share_no_identity(self) -> None:
        built = self.built(cmd("/bin/sh", "-c", "exit 0"))
        with container.loaded(built.path) as image:
            assert isinstance(image, container.Loaded), image
            found = container.two_clones(image)
        assert isinstance(found, Result), found
        self.assertEqual(found.outcome, "PASSED", found.failed)

    def test_the_probe_runner_runs_a_command_in_a_container_with_no_network(self) -> None:
        built = self.built(cmd("/bin/sh", "-c", "exit 0"))
        with container.loaded(built.path) as image:
            assert isinstance(image, container.Loaded), image
            run = container.run_probe(image.image)
            self.assertEqual(run(Probe("echo", ("/bin/echo", "v1.2.3"), "v1.2.3")), (0, "v1.2.3\n"))
            self.assertEqual(run(Probe("sh", ("/bin/sh", "-c", "echo out; exit 3"), "x")), (3, "out\n"))
            self.assertEqual(
                run(Probe("net", ("/bin/sh", "-c", "wget -q -T 3 -O- http://192.0.2.1/ || exit 9"), "x"))[0], 9
            )
            self.assertNotEqual(run(Probe("none", ("/nonexistent",), "x"))[0], 0)

    def test_test_runs_oci_run_and_two_clones_on_an_output_directory_and_records_them(self) -> None:
        built = self.built(cmd("/bin/sh", "-c", "exit 0"))
        entries = {"app": ocimage.entry("oci", parent="core", checks=("oci-run", "two-clones"))}
        entries["core"] = ocimage.entry("core")
        (self.out / "plan.json").write_text(ocimage.plan_json(entries))
        printed = io.StringIO()
        status = command.test_command(self.out, [], Sources(), printed)
        self.assertEqual(status, 0, printed.getvalue())
        text = (self.out / f"{built.digest}.intoto.jsonl").read_text()
        statements = records.decode_statements(text)
        self.assertEqual(len(statements), 2)
        for statement in statements:
            self.assertEqual(statement["subject"], [{"name": built.path.name, "digest": {"sha256": built.digest}}])
        self.assertIn("app: oci-run PASSED", printed.getvalue())
        self.assertIn("app: two-clones PASSED", printed.getvalue())

    def test_the_layout_loads_as_an_image_docker_can_describe(self) -> None:
        built = self.built(cmd("/bin/sh", "-c", "exit 0"))
        with container.loaded(built.path) as image:
            assert isinstance(image, container.Loaded), image
            inspected = json.loads(docker("image", "inspect", image.image).stdout)
        self.assertEqual(inspected[0]["Config"]["User"], "0:0")


if __name__ == "__main__":
    unittest.main()
