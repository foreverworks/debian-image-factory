import subprocess
import tempfile
import unittest
from pathlib import Path

from debian_image_factory.build import boot


class BootLinesTests(unittest.TestCase):
    def test_the_machine_id_waits_for_the_first_boot(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "etc").mkdir()
            (root / "etc" / "machine-id").write_text("")
            script = "\n".join(["set -eu", f'root="{root}"', *boot.boot_lines()])
            subprocess.run(["sh", "-c", script], check=True)
            self.assertEqual((root / "etc" / "machine-id").read_text(), "uninitialized\n")
            self.assertEqual((root / "etc" / "machine-id").stat().st_mode & 0o777, 0o444)

    def test_an_image_without_a_machine_id_file_gets_one(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "etc").mkdir()
            script = "\n".join(["set -eu", f'root="{root}"', *boot.boot_lines()])
            subprocess.run(["sh", "-c", script], check=True)
            self.assertEqual((root / "etc" / "machine-id").read_text(), "uninitialized\n")


if __name__ == "__main__":
    unittest.main()
