"""The nightly path for real: the Action's own shell steps (action.yml, through tests/support/action.py) on the
nightly workflow's definition, against snapshot.debian.org and rootless Docker, with the .pyz built from this
checkout. The first night plans at the newest completed snapshot, fetches, builds core and an Incus base in the
builder, tests, and publishes to a `dir://` target; the second night, the same inputs a moment later, plans
against that target, reads `changed=false`, and fetches, builds, tests and publishes nothing.

Needs docker, the builder image (the Action builds it with scripts/builder) and network access.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from debian_image_factory import published
from tests.support import action

ROOT = action.ROOT
NIGHTLY = ROOT / ".github" / "nightly"


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class NightlyActionTest(unittest.TestCase):
    work: Path
    scratch: tempfile.TemporaryDirectory[str]
    target: Path
    first: action.Result
    second: action.Result

    @classmethod
    def night(cls, name: str, pyz: Path) -> action.Result:
        return action.run_action(
            {
                "definition": str(NIGHTLY / "factory.toml"),
                "lock": str(NIGHTLY / "lock.json"),
                "snapshot": "latest",
                "against": f"dir://{cls.target}",
                "publish": "true",
                "pyz": str(pyz),
            },
            scratch=cls.work / name,
            cwd=cls.work,
            env={"XDG_CACHE_HOME": str(cls.work / "cache")},
        )

    @classmethod
    def setUpClass(cls) -> None:
        # Under dist/, not /tmp: the docker daemon mounts the build directory from its own view of the host.
        (ROOT / "dist").mkdir(exist_ok=True)
        cls.scratch = tempfile.TemporaryDirectory(prefix="integration-action-", dir=ROOT / "dist")
        cls.work = Path(cls.scratch.name)
        cls.target = cls.work / "target"
        built = subprocess.run(
            [str(ROOT / "scripts" / "build-pyz"), str(cls.work / "pyz")], check=True, capture_output=True, text=True
        )
        pyz = Path(built.stdout.strip().splitlines()[-1])
        cls.first = cls.night("first", pyz)
        cls.second = cls.night("second", pyz)

    @classmethod
    def tearDownClass(cls) -> None:
        # docker leaves files this user cannot delete: remove the build directories from inside a container
        subprocess.run(
            ["docker", "run", "--rm", "-v", f"{cls.work}:/w", "debian:trixie", "rm", "-rf", "/w/first", "/w/second"],
            check=False,
            capture_output=True,
        )
        shutil.rmtree(cls.work, ignore_errors=True)
        cls.scratch.cleanup()

    def test_the_first_night_builds_tests_and_publishes_both_images(self) -> None:
        self.assertTrue(self.first.ok, self.first.log)
        self.assertEqual(self.first.outputs["summary"]["changed"], "true")
        self.assertEqual(self.first.outputs["summary"]["images"], "core,incus-base")
        for step in ("fetch", "build", "test", "publish"):
            self.assertIn(step, self.first.outputs, step)
        names = sorted(path.name for path in self.target.iterdir())
        for image in ("core", "incus-base"):
            self.assertTrue(any(published.parse_artifact_name(n) and n.startswith(f"{image}-") for n in names), image)

    def test_the_first_night_names_what_it_built(self) -> None:
        artifacts = json.loads(self.first.outputs["artifacts"]["json"])
        self.assertEqual(sorted(artifacts), ["core", "incus-base"])
        for image, digest in artifacts.items():
            self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$", image)
            self.assertTrue((self.target / published.records_name_for(digest.removeprefix("sha256:"))).is_file(), image)

    def test_the_second_night_builds_nothing(self) -> None:
        self.assertTrue(self.second.ok, self.second.log)
        self.assertEqual(self.second.outputs["summary"], {"changed": "false", "images": "", "vm": "false"})
        for step in ("fetch", "build", "test", "publish"):
            self.assertNotIn(step, self.second.outputs, f"{step} ran on a night with nothing to build")

    def test_the_second_night_finds_what_the_first_published(self) -> None:
        plan = json.loads(Path(self.second.outputs["plan"]["path"]).read_text(encoding="utf-8"))
        states = {name: entry["state"] for name, entry in plan["images"].items()}
        # core passed every check; the Incus base waits for the checks that need an Incus host
        self.assertEqual(states["core"], "reuse")
        self.assertIn(states["incus-base"], ("reuse", "wait"))
        self.assertEqual(self.second.outputs["artifacts"]["json"], self.first.outputs["artifacts"]["json"])
