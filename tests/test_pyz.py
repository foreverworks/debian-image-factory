import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "scripts" / "build-pyz"


def build(out: Path) -> Path:
    done = subprocess.run([str(BUILD), str(out)], capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise AssertionError(f"build-pyz failed: {done.stderr}")
    return Path(done.stdout.strip().splitlines()[-1])


class PyzTest(unittest.TestCase):
    def test_runs_and_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            first = build(Path(raw) / "one")
            second = build(Path(raw) / "two")
            done = subprocess.run(
                [sys.executable, str(first), "--version"], capture_output=True, text=True, check=False
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertTrue(done.stdout.startswith("debian-image-factory "), done.stdout)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first.name, f"debian-image-factory-{done.stdout.split()[1]}.pyz")
            lines = first.with_name(first.name + ".sha256").read_text().split()
            self.assertEqual(lines[1], first.name)
            self.assertEqual(lines[0], second.with_name(second.name + ".sha256").read_text().split()[0])

    def test_bundles_both_packages(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            names = set(zipfile.ZipFile(build(Path(raw))).namelist())
        self.assertIn("debian_image_factory/cli.py", names)
        self.assertIn("input_lock/__init__.py", names)
        self.assertIn("__main__.py", names)
        self.assertFalse([n for n in names if "__pycache__" in n])


if __name__ == "__main__":
    unittest.main()
