"""`no-build-snapshot`: PASSED, FAILED and WARNED when it cannot tell, for one build snapshot or two."""

import unittest

from debian_image_factory.checks import snapshot
from debian_image_factory.checks.tarball import Hit

SNAPSHOT = "20261121T004329Z"
SECURITY = "20261123T141315Z"
BASELINE = "20261001T000000Z"
BOTH = {"debian": SNAPSHOT, "debian-security": SNAPSHOT}
APART = {"debian": SNAPSHOT, "debian-security": SECURITY}


class NoBuildSnapshotTest(unittest.TestCase):
    def test_no_hits_passes(self) -> None:
        found = snapshot.no_build_snapshot(BOTH, BASELINE, [])
        self.assertEqual((found.check, found.outcome), ("no-build-snapshot", "PASSED"))
        self.assertEqual(found.passed, ("build-snapshot-absent",))

    def test_no_baseline_at_all_passes(self) -> None:
        self.assertEqual(snapshot.no_build_snapshot(BOTH, None, []).outcome, "PASSED")

    def test_each_kind_of_hit_fails_and_is_named(self) -> None:
        hits = [Hit("path", "/a"), Hit("link target", "/b"), Hit("content", "/etc/apt/sources.list")]
        found = snapshot.no_build_snapshot(BOTH, BASELINE, hits)
        self.assertEqual(found.outcome, "FAILED")
        self.assertEqual(found.passed, ())
        self.assertEqual(len(found.failed), 3)
        self.assertIn(f"{SNAPSHOT} is in a link target of /b", found.failed[1])

    def test_the_baseline_equal_to_the_build_snapshot_warns_and_says_why(self) -> None:
        for hits in ([], [Hit("content", "/etc/apt/sources.list")]):
            with self.subTest(hits=hits):
                found = snapshot.no_build_snapshot(BOTH, SNAPSHOT, hits)
                self.assertEqual(found.outcome, "WARNED")
                self.assertEqual((found.passed, found.failed), ((), ()))
                self.assertIn("cannot be told apart", found.warned[0])
                self.assertIn(SNAPSHOT, found.warned[0])


class TwoSnapshotsTest(unittest.TestCase):
    def test_both_ids_are_searched_and_named(self) -> None:
        self.assertEqual(snapshot.searched(APART, BASELINE), (SNAPSHOT, SECURITY))
        found = snapshot.no_build_snapshot(APART, BASELINE, [Hit("content", "/x")])
        self.assertEqual(found.outcome, "FAILED")
        self.assertIn(f"{SNAPSHOT} or {SECURITY} is in a content of /x", found.failed[0])

    def test_both_archives_at_one_id_make_one_needle(self) -> None:
        self.assertEqual(snapshot.searched(BOTH, BASELINE), (SNAPSHOT,))

    def test_an_id_the_baseline_shares_only_warns_for_that_id_and_the_other_is_still_searched(self) -> None:
        self.assertEqual(snapshot.searched(APART, SNAPSHOT), (SECURITY,))
        clean = snapshot.no_build_snapshot(APART, SNAPSHOT, [])
        self.assertEqual((clean.outcome, clean.passed), ("WARNED", ("build-snapshot-absent",)))
        self.assertIn(
            f"the baseline {SNAPSHOT} is the build snapshot of debian, so a match cannot be told apart", clean.warned[0]
        )
        hit = snapshot.no_build_snapshot(APART, SNAPSHOT, [Hit("path", "/x")])
        self.assertEqual(hit.outcome, "FAILED")
        self.assertIn(f"{SECURITY} is in a path of /x", hit.failed[0])
        self.assertNotIn(SNAPSHOT, hit.failed[0])
        self.assertEqual(len(hit.warned), 1)

    def test_the_security_id_equal_to_the_baseline_leaves_debian_searched(self) -> None:
        self.assertEqual(snapshot.searched(APART, SECURITY), (SNAPSHOT,))
        found = snapshot.no_build_snapshot(APART, SECURITY, [])
        self.assertIn("of debian-security", found.warned[0])

    def test_both_ids_equal_to_the_baseline_search_nothing_and_warn_once(self) -> None:
        self.assertEqual(snapshot.searched(APART, None), (SNAPSHOT, SECURITY))
        found = snapshot.no_build_snapshot(BOTH, SNAPSHOT, [Hit("path", "/x")])
        self.assertEqual((found.outcome, len(found.warned), found.failed), ("WARNED", 1, ()))
