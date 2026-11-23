"""The resolver spike (DESIGN 7.2): the plan's core package set equals a real mmdebstrap build's.

It plans the example definition at the example lock's snapshots, builds core for real with
mmdebstrap in the builder image at the same two snapshots (one per archive), and compares the plan's set with the built
root's dpkg status. It also plans inside the builder image and requires the same plan bytes, so
identities do not depend on the machine. Needs docker and network access to snapshot.debian.org.
"""

import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from debian_image_factory import cli
from tests.support import builder_images

ROOT = Path(__file__).resolve().parent.parent.parent
EXAMPLES = ROOT / "examples"


def run(*argv: str) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout.strip()


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class SpikeTest(unittest.TestCase):
    plan_text: str
    tag: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.tag = builder_images.image()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "plan.json"
            status = cli.main(
                [
                    "plan",
                    *("--lock", str(EXAMPLES / "lock.json"), "--definition", str(EXAMPLES / "factory.toml")),
                    *("--out", str(out)),
                ]
            )
            assert status == 0, "plan failed"
            cls.plan_text = out.read_text()

    def test_core_equals_a_real_mmdebstrap_build(self) -> None:
        plan: object = json.loads(self.plan_text)
        assert isinstance(plan, dict)
        core = plan["images"]["core"]
        snapshots = plan["snapshots"]
        assert isinstance(snapshots, dict)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "core.json"
            run(
                str(ROOT / "scripts" / "spike-core"),
                *("--debian", snapshots["debian"], "--debian-security", snapshots["debian-security"]),
                *("--out", str(out), "--tag", self.tag),
                *core["request"],
            )
            built: object = json.loads(out.read_text())
        assert isinstance(built, list)
        planned = {tuple(row) for row in core["packages"]}
        real = {tuple(row) for row in built}
        self.assertEqual(sorted(planned - real), [], "planned but not installed")
        self.assertEqual(sorted(real - planned), [], "installed but not planned")

    def test_the_builder_plans_the_same_bytes(self) -> None:
        inside = subprocess.run(
            [
                *("docker", "run", "--rm", "--network", "host", "-v", f"{ROOT}:/repo:ro", "-w", "/repo/examples"),
                *("-e", "PYTHONPATH=/repo/src:/repo/.vendor", self.tag),
                *("python3", "-m", "debian_image_factory", "plan", "--cache", "/tmp/cache"),
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertEqual(inside, self.plan_text)

    def test_a_second_plan_gives_the_same_bytes(self) -> None:
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "again.json"
            cli.main(
                [
                    "plan",
                    *("--lock", str(EXAMPLES / "lock.json"), "--definition", str(EXAMPLES / "factory.toml")),
                    *("--out", str(target)),
                ]
            )
            out.write(target.read_text())
        self.assertEqual(out.getvalue(), self.plan_text)


if __name__ == "__main__":
    unittest.main()
