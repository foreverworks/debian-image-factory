"""Retention (DESIGN 9.1, 11, 12): what `prune` keeps and deletes, as a pure function of the builds, their
results and the pins."""

import itertools
import unittest
from collections.abc import Mapping, Sequence

from input_lock.records import TestOutcome

from debian_image_factory import retention
from debian_image_factory.published import Artifact
from debian_image_factory.retention import Verdict

CHECKS = ("package-set", "oci-run")
PASSED: Mapping[str, TestOutcome] = {"package-set": "PASSED", "oci-run": "PASSED"}
WARNED: Mapping[str, TestOutcome] = {"package-set": "PASSED", "oci-run": "WARNED"}
PENDING: Mapping[str, TestOutcome] = {"package-set": "PASSED"}
BAD: Mapping[str, TestOutcome] = {"package-set": "PASSED", "oci-run": "FAILED"}
BAD_AND_PENDING: Mapping[str, TestOutcome] = {"package-set": "FAILED"}


def required(image: str, locked: bool) -> Sequence[str] | None:
    if image == "gone":
        return None
    return (*CHECKS, "locked-inputs") if locked else CHECKS


def build(
    digit: int,
    results: Mapping[str, TestOutcome] = PASSED,
    *,
    day: int | None = None,
    image: str = "app",
    locked: bool = False,
) -> Artifact:
    """A build whose digest is its number repeated; `day` is its finish time (the number by default)."""
    finished = f"2026-11-{day if day is not None else digit:02d}T02:00:00Z"
    return Artifact(image, "ab" * 32, f"{digit:02x}" * 32, f"{image}-{digit}", finished, results, locked)


def digest(digit: int) -> str:
    return f"{digit:02x}" * 32


def kept(verdicts: Sequence[Verdict]) -> list[str]:
    return [one.artifact.name for one in verdicts if one.keep]


def deleted(verdicts: Sequence[Verdict]) -> list[str]:
    return [one.artifact.name for one in verdicts if not one.keep]


def run(
    artifacts: Sequence[Artifact], pins: Sequence[str] = (), good: int = 5, candidates: int = 1
) -> tuple[Verdict, ...]:
    return retention.retain(artifacts, required, pins, good, candidates)


class GoodBuildsTest(unittest.TestCase):
    def test_the_newest_five_good_builds_stay_by_default(self) -> None:
        found = run([build(n) for n in range(1, 9)])
        self.assertEqual(kept(found), ["app-8", "app-7", "app-6", "app-5", "app-4"])
        self.assertEqual(deleted(found), ["app-3", "app-2", "app-1"])

    def test_fewer_builds_than_the_limit_all_stay(self) -> None:
        self.assertEqual(deleted(run([build(1), build(2)])), [])

    def test_a_warned_check_counts_as_passing(self) -> None:
        self.assertEqual({one.standing for one in run([build(1, WARNED)])}, {"good"})

    def test_the_limit_is_the_number_asked_for(self) -> None:
        found = run([build(n) for n in range(1, 5)], good=2)
        self.assertEqual(kept(found), ["app-4", "app-3"])

    def test_zero_keeps_no_good_build(self) -> None:
        self.assertEqual(kept(run([build(1), build(2)], good=0, candidates=0)), [])

    def test_newest_is_by_finish_time_not_by_digest_or_listing_order(self) -> None:
        old, new = build(9, day=1), build(1, day=20)
        for listing in ([old, new], [new, old]):
            self.assertEqual(kept(run(listing, good=1)), ["app-1"])

    def test_a_tie_in_time_goes_to_the_smallest_digest(self) -> None:
        for listing in itertools.permutations([build(3, day=5), build(2, day=5), build(9, day=5)]):
            self.assertEqual(kept(run(listing, good=1)), ["app-2"])

    def test_a_build_without_a_time_is_older_than_any_with_one(self) -> None:
        untimed = Artifact("app", "ab" * 32, digest(1), "app-1", None, PASSED)
        self.assertEqual(kept(run([untimed, build(2, day=3)], good=1)), ["app-2"])

    def test_a_negative_limit_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            run([build(1)], good=-1)
        with self.assertRaises(ValueError):
            run([build(1)], candidates=-1)


class CandidatesTest(unittest.TestCase):
    def test_the_newest_candidate_stays_by_default(self) -> None:
        # one older build passed oci-run, so the check is in force for the later ones
        found = run([build(9, day=1), build(1, PENDING, day=2), build(2, PENDING, day=3), build(3, PENDING, day=4)])
        self.assertEqual((kept(found), deleted(found)), (["app-3", "app-9"], ["app-2", "app-1"]))
        self.assertEqual({one.standing for one in found if one.artifact.name != "app-9"}, {"candidate"})

    def test_candidates_and_good_builds_have_their_own_limits(self) -> None:
        found = run([build(1), build(2), build(3, PENDING), build(4, PENDING)], good=1, candidates=1)
        self.assertEqual((kept(found), deleted(found)), (["app-4", "app-2"], ["app-3", "app-1"]))

    def test_a_build_with_no_results_at_all_is_a_candidate(self) -> None:
        self.assertEqual(run([build(1, {})])[0].standing, "candidate")

    def test_a_failed_build_whose_other_checks_have_no_result_is_still_a_candidate(self) -> None:
        found = run([build(1, BAD_AND_PENDING)])
        self.assertEqual((found[0].standing, found[0].keep), ("candidate", True))

    def test_such_a_build_leaves_through_the_candidate_limit_like_any_other(self) -> None:
        found = run([build(1, BAD_AND_PENDING), build(2, BAD_AND_PENDING)])
        self.assertEqual((kept(found), deleted(found)), (["app-2"], ["app-1"]))

    def test_the_last_result_of_a_check_decides_so_a_later_pass_is_good(self) -> None:
        self.assertEqual(run([build(1, {"package-set": "PASSED", "oci-run": "PASSED"})])[0].standing, "good")


class NewCheckTest(unittest.TestCase):
    """A check added to the definition after builds were made does not demote them (DESIGN 11)."""

    def required_with(self, extra: str) -> retention.RequiredChecks:
        return lambda image, locked: (*CHECKS, extra)

    def test_adding_a_required_check_keeps_every_good_build(self) -> None:
        builds = [build(n) for n in range(1, 6)]
        found = retention.retain(builds, self.required_with("scan"), [], 5, 1)
        self.assertEqual(deleted(found), [])
        self.assertEqual([one.standing for one in found], ["candidate", "good", "good", "good", "good"])

    def test_the_same_with_the_strict_rule_would_have_deleted_most_of_them(self) -> None:
        builds = [build(n) for n in range(1, 6)]
        strict = [retention.standing_of(one, self.required_with("scan")) for one in builds]
        self.assertEqual(strict, ["candidate"] * 5)

    def test_older_builds_stay_good_once_the_new_check_has_run_on_a_newer_one(self) -> None:
        required = self.required_with("scan")
        tested = build(6, {**PASSED, "scan": "PASSED"})
        found = retention.retain([*(build(n) for n in range(1, 6)), tested], required, [], 5, 1)
        self.assertEqual(deleted(found), ["app-1"])  # the sixth good build, as without the new check
        self.assertEqual({one.standing for one in found}, {"good"})

    def test_a_failed_new_check_still_fails_a_build_it_ran_on(self) -> None:
        required = self.required_with("scan")
        found = retention.retain([build(1), build(2, {**PASSED, "scan": "FAILED"})], required, [], 5, 1)
        self.assertEqual([(one.artifact.name, one.standing) for one in found], [("app-2", "failed"), ("app-1", "good")])

    def test_a_build_newer_than_the_first_result_of_a_check_is_held_to_it(self) -> None:
        required = self.required_with("scan")
        first = build(1, {**PASSED, "scan": "PASSED"}, day=2)
        later = build(2, day=3)
        self.assertEqual(retention.retain([first, later], required, [], 5, 1)[0].standing, "candidate")

    def test_a_build_with_no_result_for_any_required_check_is_never_helped(self) -> None:
        found = retention.retain([build(1, {}), build(2)], self.required_with("scan"), [], 5, 1)
        self.assertEqual(
            {one.artifact.name: one.standing for one in found}, {"app-1": "candidate", "app-2": "candidate"}
        )

    def test_a_check_nobody_has_run_is_not_held_against_older_builds_but_is_against_the_newest(self) -> None:
        found = run([build(1), build(2), build(3, PENDING)], good=5, candidates=1)
        self.assertEqual([(one.artifact.name, one.standing) for one in found][0], ("app-3", "candidate"))
        self.assertEqual({one.standing for one in found[1:]}, {"good"})


class FailedBuildsTest(unittest.TestCase):
    def test_a_failed_build_whose_checks_have_ended_is_deleted(self) -> None:
        found = run([build(1, BAD)])
        self.assertEqual((found[0].keep, found[0].standing), (False, "failed"))
        self.assertIn("failed", found[0].reason)

    def test_failed_builds_are_deleted_however_few_there_are(self) -> None:
        self.assertEqual(kept(run([build(n, BAD) for n in range(1, 4)], good=9, candidates=9)), [])

    def test_a_run_of_failed_nights_never_pushes_out_a_good_build(self) -> None:
        good = [build(n) for n in range(1, 6)]
        failed = [build(n, BAD, day=n - 9) for n in range(10, 30)]
        candidates = [build(n, PENDING, day=n - 9) for n in range(30, 40)]
        found = run([*failed, *candidates, *good])
        self.assertEqual(
            sorted(name for name in kept(found) if name in {g.name for g in good}), sorted(g.name for g in good)
        )
        self.assertEqual(len(kept(found)), 6)  # the five good builds and the newest candidate

    def test_a_good_build_is_kept_whatever_follows_it(self) -> None:
        found = run([build(1), build(2, BAD, day=9), build(3, BAD, day=10)], good=1)
        self.assertEqual((kept(found), deleted(found)), (["app-1"], ["app-3", "app-2"]))


class PinsTest(unittest.TestCase):
    def test_a_pinned_digest_is_never_deleted_whatever_its_standing(self) -> None:
        for results in (PASSED, PENDING, BAD):
            with self.subTest(results=dict(results)):
                found = run([build(1, results, day=1), build(2), build(3)], pins=[digest(1)], good=1, candidates=0)
                self.assertIn("app-1", kept(found))
                self.assertEqual(next(one for one in found if one.artifact.name == "app-1").reason[:6], "pinned")

    def test_a_pin_does_not_use_up_a_place_in_the_limit(self) -> None:
        found = run([build(1), build(2), build(3)], pins=[digest(1)], good=1)
        self.assertEqual(kept(found), ["app-3", "app-1"])
        self.assertEqual(deleted(found), ["app-2"])

    def test_a_pin_names_an_artifact_in_any_image(self) -> None:
        found = run([build(1, BAD, image="a"), build(2, BAD, image="b")], pins=[digest(2)])
        self.assertEqual((kept(found), deleted(found)), (["b-2"], ["a-1"]))

    def test_a_pin_that_matches_nothing_changes_nothing(self) -> None:
        self.assertEqual(kept(run([build(1)], pins=[digest(7)])), ["app-1"])


class BoundTest(unittest.TestCase):
    def test_at_most_keep_good_plus_keep_candidates_per_image_plus_pins(self) -> None:
        mixes = [PASSED, PENDING, BAD, BAD_AND_PENDING, {}]
        artifacts = [
            build(n, mixes[n % len(mixes)], day=(n * 7) % 28 + 1, image=("a" if n % 2 else "b")) for n in range(1, 60)
        ]
        pins = [digest(5), digest(6), digest(7)]
        for good, candidates in ((0, 0), (1, 1), (5, 1), (3, 0), (2, 4)):
            with self.subTest(good=good, candidates=candidates):
                found = run(artifacts, pins=pins, good=good, candidates=candidates)
                self.assertEqual(len(found), len(artifacts))
                for image in ("a", "b"):
                    mine = [one for one in found if one.artifact.image == image and one.keep]
                    pinned = [one for one in mine if one.artifact.digest in pins]
                    self.assertLessEqual(len(mine) - len(pinned), good + candidates)

    def test_every_artifact_gets_exactly_one_verdict(self) -> None:
        artifacts = [build(n, PASSED if n % 2 else BAD, image="a" if n % 3 else "b") for n in range(1, 20)]
        self.assertEqual(sorted(one.artifact.name for one in run(artifacts)), sorted(one.name for one in artifacts))


class ImagesTest(unittest.TestCase):
    def test_each_image_is_counted_on_its_own(self) -> None:
        found = run([build(1, image="a"), build(2, image="a"), build(3, image="b"), build(4, image="b")], good=1)
        self.assertEqual(kept(found), ["a-2", "b-4"])

    def test_an_image_the_definition_does_not_name_is_kept(self) -> None:
        found = run([build(1, BAD, image="gone"), build(2, BAD, image="gone")])
        self.assertEqual((kept(found), {one.standing for one in found}), (["gone-2", "gone-1"], {"unknown"}))
        self.assertIn("not in the definition", found[0].reason)

    def test_locked_inputs_join_the_required_checks_of_a_build_that_lists_them(self) -> None:
        self.assertEqual(run([build(1, locked=False)])[0].standing, "good")
        self.assertEqual(run([build(1, locked=True)])[0].standing, "candidate")
        results: Mapping[str, TestOutcome] = {**PASSED, "locked-inputs": "PASSED"}
        self.assertEqual(run([build(1, results, locked=True)])[0].standing, "good")

    def test_the_verdicts_come_by_image_then_newest_first(self) -> None:
        found = run([build(1, image="b"), build(2, image="a"), build(3, image="b"), build(4, image="a")])
        self.assertEqual([one.artifact.name for one in found], ["a-4", "a-2", "b-3", "b-1"])

    def test_nothing_published_nothing_to_do(self) -> None:
        self.assertEqual(run([]), ())


if __name__ == "__main__":
    unittest.main()
