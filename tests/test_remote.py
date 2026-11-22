"""The one function that reads a URL: its schemes and its size cap."""

import tempfile
import unittest
from pathlib import Path

from debian_image_factory import remote


class ReadUrlTests(unittest.TestCase):
    def test_a_file_url_is_read_whole_up_to_the_limit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dif-remote-") as scratch:
            (Path(scratch) / "x").write_bytes(b"abcd")
            self.assertEqual(remote.read_url(f"file://{scratch}/x", limit=4), b"abcd")

    def test_an_answer_longer_than_the_limit_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dif-remote-") as scratch:
            (Path(scratch) / "x").write_bytes(b"abcde")
            with self.assertRaisesRegex(OSError, "more than 4 bytes"):
                remote.read_url(f"file://{scratch}/x", limit=4)

    def test_other_schemes_are_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "only"):
            remote.read_url("ftp://example.com/x")


if __name__ == "__main__":
    unittest.main()
