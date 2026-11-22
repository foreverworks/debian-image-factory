"""A parallel build gives the same artifacts, digests and records as a serial one (DESIGN 9.1).

The example plan's core, oci-base, node-26 and incus-base are built twice from one fetch: `--jobs 1`, one image
after another, and `--jobs 4`, with oci-base and incus-base (both on core) building side by side. Needs docker,
the builder image (`scripts/builder build`) and network access to snapshot.debian.org.

What it checks: the two output directories hold the same files by name (the names carry the digests); every
artifact, layout and record is the same bytes, the records but for the build's own timestamps; the parallel
run's output starts every line with an image's name, starts the two siblings before either ends and the child
after its parent ends; no work directory is left behind.
"""

import hashlib
import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from debian_image_factory import records
from tests.support import builder_images

from .test_core_build import ROOT, factory, files
from .test_oci_build import build

IMAGES = ("core", "oci-base", "node-26", "incus-base")
TIMES = {"startedOn", "finishedOn", "created"}
"""The build's own clock: the only fields of a record that differ between two builds of the same inputs."""


def tree(root: Path) -> dict[str, str]:
    """Every file under `root` (a layout directory included) by relative path, with its sha256. The logs and
    the plan copy are left out: a log names its own run, the plan is the input."""
    found: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_file() and not relative.endswith(".build.log") and not relative.endswith(".jsonl"):
            found[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return found


def without_times(value: object) -> object:
    if isinstance(value, dict):
        return {key: without_times(one) for key, one in value.items() if key not in TIMES}
    if isinstance(value, list):
        return [without_times(one) for one in value]
    return value


def statements(root: Path) -> dict[str, object]:
    return {
        path.name: without_times(records.decode_statements(path.read_text())) for path in sorted(root.glob("*.jsonl"))
    }


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class ParallelBuildTest(unittest.TestCase):
    work: Path
    scratch: tempfile.TemporaryDirectory[str]
    serial_output: str
    parallel_output: str

    @classmethod
    def setUpClass(cls) -> None:
        tag = builder_images.image()
        (ROOT / "dist").mkdir(exist_ok=True)
        cls.scratch = tempfile.TemporaryDirectory(prefix="integration-parallel-", dir=ROOT / "dist")
        cls.work = Path(cls.scratch.name)
        plan = cls.work / "plan.json"
        factory("plan", *files(), "--out", str(plan))
        factory("fetch", str(plan))
        chosen = [argument for image in IMAGES for argument in ("--image", image)]
        common = ["--builder-image", tag, *files(), *chosen]
        cls.serial_output = build(str(plan), "--out", str(cls.work / "serial"), "--jobs", "1", *common)
        cls.parallel_output = build(str(plan), "--out", str(cls.work / "parallel"), "--jobs", "4", *common)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.scratch.cleanup()

    def test_both_builds_hold_the_same_files(self) -> None:
        serial, parallel = tree(self.work / "serial"), tree(self.work / "parallel")
        self.assertEqual(sorted(serial), sorted(parallel))
        self.assertGreater(len(serial), len(IMAGES))

    def test_every_artifact_and_layout_is_the_same_bytes(self) -> None:
        self.assertEqual(tree(self.work / "serial"), tree(self.work / "parallel"))

    def test_the_records_are_the_same_but_for_the_clock(self) -> None:
        serial, parallel = statements(self.work / "serial"), statements(self.work / "parallel")
        self.assertEqual(len(serial), len(IMAGES))
        self.assertEqual(serial, parallel)

    def test_the_parallel_output_names_the_image_on_every_line(self) -> None:
        lines = self.parallel_output.splitlines()
        self.assertEqual(lines[0], "building 4 images, 4 at a time: --jobs 4")
        for line in lines[1:]:
            self.assertRegex(line, rf"^({'|'.join(map(re.escape, IMAGES))}): ")

    def test_the_siblings_start_together_and_the_child_waits_for_its_parent(self) -> None:
        lines = self.parallel_output.splitlines()

        def where(prefix: str) -> int:
            return next(number for number, line in enumerate(lines) if line.startswith(prefix))

        started = {image: where(f"{image}: building") for image in IMAGES}
        finished = {image: where(f"{image}: {image}-trixie-") for image in IMAGES}
        siblings = ("oci-base", "incus-base")
        self.assertLess(finished["core"], min(started[one] for one in siblings))
        self.assertLess(max(started[one] for one in siblings), min(finished[one] for one in siblings))
        self.assertLess(finished["oci-base"], started["node-26"])

    def test_the_serial_output_builds_one_image_at_a_time(self) -> None:
        lines = self.serial_output.splitlines()[1:]
        starts, ends = lines[0::2], lines[1::2]
        self.assertEqual(len(starts), len(IMAGES))
        for start, end in zip(starts, ends, strict=True):
            image = start.removesuffix(": building")
            self.assertTrue(end.startswith(f"{image}: {image}-trixie-"), (start, end))

    def test_no_work_directory_is_left_behind(self) -> None:
        for out in ("serial", "parallel"):
            self.assertEqual(list((self.work / out).glob(".work-*")), [], out)

    def test_the_plan_copy_is_the_same_plan(self) -> None:
        self.assertEqual(
            json.loads((self.work / "serial" / "plan.json").read_text()),
            json.loads((self.work / "parallel" / "plan.json").read_text()),
        )
