import json
import unittest
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import ClassVar

from debian_image_factory import listings, snapshots

FIXTURES = Path(__file__).parent / "fixtures" / "listings"
ARCHIVES = ("debian", "debian-security")


def answer(archive: str, ids: list[object]) -> dict[str, object]:
    return {"_comment": "foo", "result": {archive: ids}}


class ParseListingTests(unittest.TestCase):
    def test_fixture_listings_parse(self) -> None:
        for archive in ARCHIVES:
            data = json.loads((FIXTURES / f"{archive}.json").read_text())
            ids = snapshots.parse_listing(data, archive)
            self.assertGreater(len(ids), 50)
            self.assertEqual(list(ids), sorted(set(ids)))

    def test_empty_listing_is_valid(self) -> None:
        self.assertEqual(snapshots.parse_listing(answer("debian", []), "debian"), ())

    def test_rejects_wrong_shapes(self) -> None:
        cases: list[tuple[object, str]] = [
            ([], "expected a JSON object"),
            ({}, "no 'result' object"),
            ({"result": []}, "no 'result' object"),
            ({"result": {"debian-security": []}}, "no list for 'debian'"),
            ({"result": {"debian": "20260101T000000Z"}}, "no list for 'debian'"),
            (answer("debian", [20260101000000]), "entry 0 is not a string"),
        ]
        for data, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                snapshots.parse_listing(data, "debian")

    def test_rejects_bad_ids(self) -> None:
        for bad in [
            "2026-01-01",
            "20260101T000000",
            "20260101t000000z",
            "20261301T000000Z",
            "20260230T000000Z",
            "20260101T246000Z",
            "20260101T000060Z",
            " 20260101T000000Z",
            "20260101T000000Z\n",
            "\uff120260101T000000Z",  # a fullwidth digit,
        ]:
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "not a snapshot ID"):
                snapshots.parse_listing(answer("debian", ["20250101T000000Z", bad]), "debian")

    def test_rejects_unsorted_and_duplicates(self) -> None:
        for ids in (["20260102T000000Z", "20260101T000000Z"], ["20260101T000000Z", "20260101T000000Z"]):
            with self.subTest(ids=ids), self.assertRaisesRegex(ValueError, "strictly ascending"):
                snapshots.parse_listing(answer("debian", list(ids)), "debian")


class RecordedListingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.listings = listings.load_listings(FIXTURES)

    def test_load_listings_reads_every_archive(self) -> None:
        self.assertEqual(sorted(self.listings), sorted(ARCHIVES))

    def test_fetch_listings_uses_the_service_url(self) -> None:
        seen: list[str] = []

        def read(url: str) -> bytes:
            seen.append(url)
            archive = url.rsplit("=", 1)[1]
            return (FIXTURES / f"{archive}.json").read_bytes()

        fetched = listings.fetch_listings(ARCHIVES, base="https://snapshots.example.com/", read=read)
        self.assertEqual(fetched, self.listings)
        self.assertEqual(seen, [f"https://snapshots.example.com/mr/timestamp/?archive={a}" for a in ARCHIVES])

    def test_fetch_listings_rejects_junk(self) -> None:
        with self.assertRaisesRegex(ValueError, "not JSON"):
            listings.fetch_listings(["debian"], read=lambda url: b"<html>")
        with self.assertRaisesRegex(ValueError, "no 'result' object"):
            listings.fetch_listings(["debian"], read=lambda url: b"{}")

    def test_trim_keeps_the_shape_and_the_later_ids(self) -> None:
        data = json.loads((FIXTURES / "debian.json").read_text())
        cut = "20261110T000000Z"
        out = listings.trim(data, "debian", cut)
        kept = snapshots.parse_listing(out, "debian")
        self.assertEqual(set(out), {"_comment", "result"})
        self.assertTrue(kept)
        self.assertTrue(all(value >= cut for value in kept))
        self.assertEqual(kept, tuple(v for v in self.listings["debian"] if v >= cut))

    def test_fixture_facts(self) -> None:
        # The recorded listings end at different times: debian-security stops hours before debian.
        self.assertLess(self.listings["debian-security"][-1], self.listings["debian"][-1])
        self.assertTrue(self.listings["debian"][0].startswith("20261101"))


class FixtureChoiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.listings = listings.load_listings(FIXTURES)
        self.horizon = min(ids[-1] for ids in self.listings.values())

    def test_latest_completed_on_the_fixtures(self) -> None:
        found = snapshots.latest_completed(self.listings)
        assert found is not None
        self.assertLess(found, self.horizon)
        every = {value for ids in self.listings.values() for value in ids if value < self.horizon}
        self.assertEqual(found, max(every))
        self.assertTrue(snapshots.completed(found, self.listings))
        self.assertEqual(snapshots.problems(found, self.listings), [])

    def test_the_horizon_and_later_are_not_completed(self) -> None:
        self.assertFalse(snapshots.completed(self.horizon, self.listings))
        newest = self.listings["debian"][-1]
        self.assertFalse(snapshots.completed(newest, self.listings))

    def test_just_before_the_horizon_is_completed(self) -> None:
        moment = datetime.strptime(self.horizon, "%Y%m%dT%H%M%SZ") - timedelta(seconds=1)
        before = moment.strftime("%Y%m%dT%H%M%SZ")
        self.assertTrue(snapshots.completed(before, self.listings))

    def test_serving_a_time_between_listed_ids(self) -> None:
        serves = snapshots.serving("20261115T120000Z", self.listings)
        self.assertEqual(sorted(serves), sorted(ARCHIVES))
        for archive, value in serves.items():
            assert value is not None
            self.assertLessEqual(value, "20261115T120000Z")
            later = [v for v in self.listings[archive] if value < v <= "20261115T120000Z"]
            self.assertEqual(later, [])

    def test_problem_names_the_archive_that_is_behind(self) -> None:
        mid = "20261121T100000Z"  # after debian-security's newest, before debian's
        found = snapshots.problems(mid, self.listings)
        self.assertEqual(len(found), 1)
        self.assertIn("archive debian-security lists no snapshot after it", found[0])
        newest_debian = self.listings["debian"][-1]  # later than every debian-security snapshot too
        found = snapshots.problems(newest_debian, self.listings)
        self.assertEqual(len(found), 2)
        self.assertTrue(all("not completed" in line for line in found))


A = ["20260101T000000Z", "20260102T000000Z", "20260103T000000Z"]
B = ["20260101T120000Z", "20260102T120000Z", "20260103T120000Z"]


class ServedTests(unittest.TestCase):
    def test_equal_to_a_listed_id_serves_it(self) -> None:
        self.assertEqual(snapshots.served("20260102T000000Z", A), "20260102T000000Z")

    def test_between_serves_the_earlier(self) -> None:
        self.assertEqual(snapshots.served("20260102T235959Z", A), "20260102T000000Z")

    def test_after_the_last_serves_the_last(self) -> None:
        self.assertEqual(snapshots.served("20270101T000000Z", A), "20260103T000000Z")

    def test_earlier_than_the_first_serves_nothing(self) -> None:
        self.assertIsNone(snapshots.served("20251231T235959Z", A))

    def test_empty_listing_and_bad_id_serve_nothing(self) -> None:
        self.assertIsNone(snapshots.served("20260102T000000Z", []))
        self.assertIsNone(snapshots.served("tomorrow", A))


class CompletedTests(unittest.TestCase):
    def test_strictly_later_snapshot_in_every_archive(self) -> None:
        both = {"a": A, "b": B}
        self.assertTrue(snapshots.completed("20260102T000000Z", both))
        self.assertTrue(snapshots.completed("20260103T000000Z", both) is False)

    def test_an_id_equal_to_an_archives_newest_is_not_completed(self) -> None:
        self.assertFalse(snapshots.completed("20260103T000000Z", {"a": A}))
        self.assertTrue(snapshots.completed("20260102T235959Z", {"a": A}))

    def test_an_id_before_an_archives_first_snapshot_is_completed_but_serves_nothing(self) -> None:
        both = {"a": A, "b": B}
        self.assertTrue(snapshots.completed("20260101T000000Z", both))
        self.assertTrue(snapshots.completed("20251201T000000Z", both))
        self.assertIsNone(snapshots.serving("20260101T060000Z", both)["b"])
        found = snapshots.problems("20260101T060000Z", both)
        self.assertEqual(len(found), 1)
        self.assertIn("archive b serves nothing", found[0])
        self.assertIn(B[0], found[0])

    def test_no_archives_and_empty_listings_are_never_completed(self) -> None:
        self.assertFalse(snapshots.completed("20260102T000000Z", {}))
        self.assertFalse(snapshots.completed("20260102T000000Z", {"a": A, "b": []}))

    def test_bad_id_is_not_completed(self) -> None:
        self.assertFalse(snapshots.completed("2026-01-02", {"a": A}))


class LatestCompletedTests(unittest.TestCase):
    def test_newest_listed_before_every_archives_newest(self) -> None:
        # newest of a is 01-03T00:00, of b 01-03T12:00: the horizon is a's newest, so 01-02T12:00 (b's) wins.
        self.assertEqual(snapshots.latest_completed({"a": A, "b": B}), "20260102T120000Z")

    def test_one_archive_only_steps_back_one_snapshot(self) -> None:
        self.assertEqual(snapshots.latest_completed({"a": A}), "20260102T000000Z")

    def test_equal_newest_timestamps_exclude_that_timestamp(self) -> None:
        a = ["20260101T000000Z", "20260105T000000Z"]
        b = ["20260102T000000Z", "20260105T000000Z"]
        self.assertEqual(snapshots.latest_completed({"a": a, "b": b}), "20260102T000000Z")

    def test_the_result_is_completed_and_the_next_listed_one_is_not(self) -> None:
        both = {"a": A, "b": B}
        found = snapshots.latest_completed(both)
        assert found is not None
        self.assertTrue(snapshots.completed(found, both))
        later = sorted(v for ids in both.values() for v in ids if v > found)
        self.assertTrue(later)
        self.assertFalse(snapshots.completed(later[0], both))

    def test_none_when_nothing_is_earlier(self) -> None:
        self.assertIsNone(snapshots.latest_completed({"a": ["20260101T000000Z"]}))
        self.assertIsNone(snapshots.latest_completed({"a": A, "b": ["20260103T000000Z"]}))

    def test_none_when_an_archive_serves_nothing_at_the_candidate(self) -> None:
        late = ["20260301T000000Z", "20260302T000000Z"]
        self.assertIsNone(snapshots.latest_completed({"a": A, "b": late}))

    def test_none_for_no_archives_or_an_empty_listing(self) -> None:
        self.assertIsNone(snapshots.latest_completed({}))
        self.assertIsNone(snapshots.latest_completed({"a": A, "b": []}))


class ProblemsAndResolveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.both = {"a": A, "b": B}

    def test_bad_format(self) -> None:
        found = snapshots.problems("latest", self.both)
        self.assertEqual(len(found), 1)
        self.assertIn("not a snapshot ID", found[0])

    def test_not_completed_names_the_archive_whose_newest_is_not_later(self) -> None:
        found = snapshots.problems("20260103T060000Z", self.both)
        self.assertEqual(len(found), 1)
        self.assertIn("archive a ", found[0])
        self.assertIn("20260103T000000Z", found[0])

    def test_several_problems_are_listed_separately(self) -> None:
        found = snapshots.problems("20260101T060000Z", {"a": A, "b": ["20260102T120000Z"]})
        self.assertEqual(len(found), 1)
        found = snapshots.problems("20260101T120000Z", {"a": A, "b": ["20260101T120000Z", "20260102T000000Z"]})
        self.assertEqual(found, [])
        found = snapshots.problems("20260101T060000Z", {"a": ["20260102T000000Z"], "b": []})
        self.assertEqual(len(found), 2)

    def test_empty_inputs(self) -> None:
        self.assertEqual(len(snapshots.problems("20260102T000000Z", {})), 1)
        self.assertIn("lists no snapshots", snapshots.problems("20260102T000000Z", {"a": []})[0])

    def test_serving_reports_each_archive(self) -> None:
        self.assertEqual(
            snapshots.serving("20260102T060000Z", self.both),
            {"a": "20260102T000000Z", "b": "20260101T120000Z"},
        )

    def test_resolve_a_bare_id_gives_what_each_archive_serves(self) -> None:
        self.assertEqual(
            snapshots.resolve("lock", self.both, "20260102T060000Z"), {"a": "20260102T000000Z", "b": "20260101T120000Z"}
        )
        self.assertEqual(
            snapshots.resolve("20260102T060000Z", self.both, "x"), {"a": "20260102T000000Z", "b": "20260101T120000Z"}
        )

    def test_resolve_latest_is_the_newest_listed_id_of_each_archive(self) -> None:
        self.assertEqual(
            snapshots.resolve("latest", self.both, "20260101T000000Z"),
            {"a": "20260103T000000Z", "b": "20260103T120000Z"},
        )
        with self.assertRaisesRegex(ValueError, "archive b lists no snapshots"):
            snapshots.resolve("latest", {"a": A, "b": []}, "20260101T000000Z")
        with self.assertRaisesRegex(ValueError, "no archive is in use"):
            snapshots.resolve("latest", {}, "20260101T000000Z")

    def test_resolve_refuses_what_cannot_be_used(self) -> None:
        with self.assertRaisesRegex(ValueError, "lock's snapshot ID 20260103T000000Z cannot be used.*not completed"):
            snapshots.resolve("lock", self.both, "20260103T000000Z")
        with self.assertRaisesRegex(ValueError, "the lock pins no snapshot"):
            snapshots.resolve("lock", self.both, None)


class ExactTests(unittest.TestCase):
    """An exact ID per archive: usable when that archive's own listing holds it, whatever the other lists."""

    def setUp(self) -> None:
        self.both = {"a": A, "b": B}

    def test_a_listed_id_is_usable_without_a_later_one(self) -> None:
        newest = {"a": "20260103T000000Z", "b": "20260103T120000Z"}
        self.assertEqual(snapshots.exact_problems(newest, self.both), {"a": [], "b": []})
        self.assertEqual(snapshots.resolve(newest, self.both, None), newest)

    def test_each_archive_may_be_at_a_different_time(self) -> None:
        mixed = {"a": "20260101T000000Z", "b": "20260103T120000Z"}
        self.assertEqual(snapshots.resolve(mixed, self.both, None), mixed)
        self.assertEqual(snapshots.resolve("lock", self.both, mixed), mixed)

    def test_an_id_the_archive_does_not_list_is_refused_never_replaced(self) -> None:
        found = snapshots.exact_problems({"a": "20260102T060000Z", "b": "20260101T120000Z"}, self.both)
        self.assertEqual(found["b"], [])
        self.assertEqual(
            found["a"],
            ["20260102T060000Z is not listed by archive a (the nearest listed one before it is 20260102T000000Z)"],
        )
        with self.assertRaisesRegex(
            ValueError, "the lock's snapshots cannot be used: a: 20260102T060000Z is not listed"
        ):
            snapshots.resolve("lock", self.both, {"a": "20260102T060000Z", "b": "20260101T120000Z"})

    def test_an_id_listed_by_the_other_archive_only_is_not_enough(self) -> None:
        found = snapshots.exact_problems({"a": "20260101T120000Z", "b": "20260101T120000Z"}, self.both)
        self.assertIn("20260101T120000Z is not listed by archive a", found["a"][0])
        self.assertEqual(found["b"], [])

    def test_where_the_id_lies_is_said(self) -> None:
        later = snapshots.exact_problems({"a": "20260104T000000Z", "b": B[0]}, self.both)["a"][0]
        self.assertIn("its newest is 20260103T000000Z", later)
        earlier = snapshots.exact_problems({"a": "20251231T000000Z", "b": B[0]}, self.both)["a"][0]
        self.assertIn("its first is 20260101T000000Z", earlier)
        empty = snapshots.exact_problems({"a": A[0], "b": B[0]}, {"a": [], "b": B})["a"][0]
        self.assertIn("lists nothing at all", empty)

    def test_missing_extra_and_malformed_archives_are_named(self) -> None:
        found = snapshots.exact_problems({"a": "soon", "c": A[0]}, self.both)
        self.assertIn("'soon' is not a snapshot ID", found["a"][0])
        self.assertEqual(found["b"], ["no snapshot is pinned for archive b"])
        self.assertIn("c is not an archive this build reads", found["c"][0])

    def test_listed_is_exact_membership(self) -> None:
        self.assertTrue(snapshots.listed(A[1], A))
        self.assertFalse(snapshots.listed("20260102T000001Z", A))
        self.assertFalse(snapshots.listed(A[0], []))


class ChoiceTests(unittest.TestCase):
    def test_the_words_a_bare_id_and_pairs(self) -> None:
        self.assertEqual(snapshots.parse_choice("lock"), "lock")
        self.assertEqual(snapshots.parse_choice("latest"), "latest")
        self.assertEqual(snapshots.parse_choice("20260102T000000Z"), "20260102T000000Z")
        self.assertEqual(
            snapshots.parse_choice("debian-security=20260103T000000Z,debian=20260101T000000Z"),
            {"debian": "20260101T000000Z", "debian-security": "20260103T000000Z"},
        )

    def test_a_missing_unknown_repeated_or_malformed_archive_is_a_usage_problem(self) -> None:
        for text, message in (
            ("debian=20260101T000000Z", "debian-security is missing"),
            ("debian=20260101T000000Z,other=20260101T000000Z", "'other' is not an archive"),
            ("debian=20260101T000000Z,debian=20260102T000000Z", "named twice"),
            ("debian=20260101T000000Z,debian-security=soon", "'soon' is not a snapshot ID"),
            ("debian-security", "is not lock, latest"),
            ("", "is not lock, latest"),
        ):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, message):
                snapshots.parse_choice(text)

    def test_ids_for_lock_snapshot_may_name_some_archives(self) -> None:
        self.assertEqual(snapshots.parse_ids(["20260102T000000Z"]), "20260102T000000Z")
        self.assertEqual(snapshots.parse_ids(["debian=20260102T000000Z"]), {"debian": "20260102T000000Z"})
        self.assertEqual(
            snapshots.parse_ids(["debian=20260101T000000Z", "debian-security=20260102T000000Z"]),
            {"debian": "20260101T000000Z", "debian-security": "20260102T000000Z"},
        )
        with self.assertRaisesRegex(ValueError, "a bare snapshot ID covers both archives"):
            snapshots.parse_ids(["20260102T000000Z", "debian=20260101T000000Z"])
        with self.assertRaisesRegex(ValueError, "is not archive=ID"):
            snapshots.parse_ids(["soon"])

    def test_named_is_what_a_narrow_read_can_confirm(self) -> None:
        self.assertEqual(snapshots.named("latest"), {})
        self.assertEqual(snapshots.named("20260101T000000Z"), {})
        self.assertEqual(snapshots.named({"a": "x"}), {"a": "x"})

    def test_the_stem_joins_the_ids_in_archive_order(self) -> None:
        self.assertEqual(
            snapshots.stem({"debian-security": "20260103T000000Z", "debian": "20260101T000000Z"}),
            "20260101T000000Z_20260103T000000Z",
        )


class NarrowReadTests(unittest.TestCase):
    """The service caches a listing for ten minutes: an ID newer than its newest is asked for alone."""

    LISTED: ClassVar[dict[str, tuple[str, ...]]] = {"debian": tuple(A), "debian-security": tuple(B)}

    def answering(self, text: str) -> tuple[list[str], Callable[[str], bytes]]:
        asked: list[str] = []

        def read(url: str) -> bytes:
            asked.append(url)
            return text.encode()

        return asked, read

    def test_a_listed_answer_adds_the_id(self) -> None:
        new = "20260104T000000Z"
        asked, read = self.answering(json.dumps({"result": {"debian": [new]}}))
        found = listings.confirm(self.LISTED, {"debian": new}, base="https://s.example/", read=read)
        self.assertEqual(found["debian"], (*A, new))
        self.assertEqual(found["debian-security"], tuple(B))
        self.assertEqual(asked, [f"https://s.example/mr/timestamp/?archive=debian&after={new}&before={new}"])

    def test_an_empty_answer_leaves_the_listing_and_the_id_stays_unlisted(self) -> None:
        new = "20260104T000000Z"
        _, read = self.answering('{"result": {}}')
        found = listings.confirm(self.LISTED, {"debian": new}, read=read)
        self.assertEqual(found, self.LISTED)
        self.assertIn(
            "is not listed by archive debian",
            snapshots.exact_problems({"debian": new, "debian-security": B[0]}, found)["debian"][0],
        )

    def test_ids_that_the_listing_can_decide_need_no_read(self) -> None:
        asked, read = self.answering("{}")
        named = {
            "debian": A[1],
            "debian-security": "20260102T000000Z",
        }  # listed, and not listed but older than the newest
        self.assertEqual(listings.confirm(self.LISTED, named, read=read), self.LISTED)
        self.assertEqual(asked, [])
        self.assertEqual(listings.confirm(self.LISTED, {"debian": "soon"}, read=read), self.LISTED)
        self.assertEqual(asked, [])

    def test_an_archive_with_an_empty_listing_asks_too(self) -> None:
        asked, read = self.answering(json.dumps({"result": {"debian": [A[0]]}}))
        found = listings.confirm({"debian": ()}, {"debian": A[0]}, read=read)
        self.assertEqual(found["debian"], (A[0],))
        self.assertEqual(len(asked), 1)

    def test_answers_of_the_wrong_shape_are_errors(self) -> None:
        new = "20260104T000000Z"
        for text, message in (
            ("<html>", "not JSON"),
            ("[]", "no 'result' object"),
            (json.dumps({"result": {"debian-security": [new]}}), "names \\['debian-security'\\]"),
            ('{"result": {"debian": ["2026"]}}', "not a snapshot ID"),
        ):
            with self.subTest(text=text):
                _, read = self.answering(text)
                with self.assertRaisesRegex(ValueError, message):
                    listings.confirm(self.LISTED, {"debian": new}, read=read)

    def test_a_failed_read_is_an_oserror(self) -> None:
        def read(url: str) -> bytes:
            raise OSError("connection refused")

        with self.assertRaises(OSError):
            listings.confirm(self.LISTED, {"debian": "20260104T000000Z"}, read=read)


if __name__ == "__main__":
    unittest.main()
