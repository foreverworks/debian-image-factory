"""`no-build-snapshot`: PASSED, FAILED and WARNED when it cannot tell."""

import unittest

from debian_image_factory.checks import snapshot
from debian_image_factory.checks.tarball import Hit

SNAPSHOT = "20261121T004329Z"
BASELINE = "20261001T000000Z"


class NoBuildSnapshotTest(unittest.TestCase):
    def test_no_hits_passes(self) -> None:
        found = snapshot.no_build_snapshot(SNAPSHOT, BASELINE, [])
        self.assertEqual((found.check, found.outcome), ("no-build-snapshot", "PASSED"))
        self.assertEqual(found.passed, ("build-snapshot-absent",))

    def test_no_baseline_at_all_passes(self) -> None:
        self.assertEqual(snapshot.no_build_snapshot(SNAPSHOT, None, []).outcome, "PASSED")

    def test_each_kind_of_hit_fails_and_is_named(self) -> None:
        hits = [Hit("path", "/a"), Hit("link target", "/b"), Hit("content", "/etc/apt/sources.list")]
        found = snapshot.no_build_snapshot(SNAPSHOT, BASELINE, hits)
        self.assertEqual(found.outcome, "FAILED")
        self.assertEqual(found.passed, ())
        self.assertEqual(len(found.failed), 3)
        self.assertIn(f"{SNAPSHOT} is in a link target of /b", found.failed[1])

    def test_the_baseline_equal_to_the_build_snapshot_warns_and_says_why(self) -> None:
        for hits in ([], [Hit("content", "/etc/apt/sources.list")]):
            with self.subTest(hits=hits):
                found = snapshot.no_build_snapshot(SNAPSHOT, SNAPSHOT, hits)
                self.assertEqual(found.outcome, "WARNED")
                self.assertEqual((found.passed, found.failed), ((), ()))
                self.assertIn("cannot be told apart", found.warned[0])
                self.assertIn(SNAPSHOT, found.warned[0])
