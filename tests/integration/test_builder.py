"""Builds the builder image and runs the spike. Needs docker and network access to snapshot.debian.org."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from debian_image_factory.tools import builder_tools, parse_tools

ROOT = Path(__file__).resolve().parent.parent.parent
BUILDER = str(ROOT / "scripts" / "builder")
SPIKE = str(ROOT / "scripts" / "spike-core")


def lock_snapshot() -> str:
    data: object = json.loads((ROOT / "lock.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    snapshot = data["debian_snapshot"]
    assert isinstance(snapshot, str)
    return snapshot


def run(*argv: str) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout.strip()


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class BuilderTest(unittest.TestCase):
    tag: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.tag = run(BUILDER, "build")

    def test_tool_versions_equal_tools_json(self) -> None:
        built = parse_tools(json.loads(run(BUILDER, "tools", "--tag", self.tag)))
        self.assertEqual(built, builder_tools())

    def test_spike_core_resolves_the_requested_packages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "core.json"
            run(
                SPIKE,
                *("--snapshot", lock_snapshot(), "--out", str(out), "--tag", self.tag),
                *("ca-certificates", "tzdata", "locales"),
            )
            rows: object = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue((Path(tmp) / "core.json.log").is_file())
        self.assertIsInstance(rows, list)
        assert isinstance(rows, list)
        self.assertEqual(rows, sorted(rows))
        names = {row[0] for row in rows}
        self.assertLessEqual({"apt", "dpkg", "ca-certificates", "tzdata", "locales"}, names)
        for row in rows:
            self.assertEqual(len(row), 3)


if __name__ == "__main__":
    unittest.main()
