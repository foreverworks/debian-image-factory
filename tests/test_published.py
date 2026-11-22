import base64
import json
import unittest
from datetime import UTC, datetime

from input_lock.records import (
    PROVENANCE_PREDICATE,
    SPDX_PREDICATE,
    TEST_RESULT_PREDICATE,
    envelope,
    jsonl,
    provenance,
    statement,
    subject,
    test_result,
)

from debian_image_factory.published import (
    Artifact,
    DirTarget,
    OciTarget,
    RecordsError,
    Rejected,
    ReleaseTarget,
    artifact_from_records,
    artifact_name,
    decide,
    described_artifact,
    format_target,
    future_notes,
    last_results,
    parse_artifact_name,
    parse_envelope,
    parse_envelopes,
    parse_target,
    partial_name,
    partial_of,
    sort_newest_first,
)
from debian_image_factory.published import (
    records_digest as published_records_digest,
)

IDENTITY = "ab" * 32
OTHER = "cd" * 32
DIGEST = "12" * 32
NAME = artifact_name("node-26", "trixie", "amd64", IDENTITY, DIGEST, "tar.gz")


def prov(identity: str = IDENTITY, image: str = "node-26", digest: str = DIGEST, finished: str | None = None) -> str:
    metadata = {"finishedOn": finished} if finished else {}
    predicate = provenance(
        "https://example.com/build-type",
        {"image": image},
        [],
        "https://example.com/builder",
        internal_parameters={"identity": identity},
        metadata=metadata,  # type: ignore[arg-type]  # a test passes a plain dict where the TypedDict is declared
    )
    return jsonl([envelope(statement([subject(NAME, digest)], PROVENANCE_PREDICATE, predicate))])


def check(name: str, result: str, digest: str = DIGEST, finished: str | None = None, run: str = "r") -> str:
    entries: list[dict[str, object]] = [{"name": name}]
    if finished is not None:
        entries.append({"name": "run", "annotations": {"runId": run, "startedOn": finished, "finishedOn": finished}})
    predicate = test_result(result, entries)  # type: ignore[arg-type]  # a test names any outcome; annotations are in-toto's
    return jsonl([envelope(statement([subject(NAME, digest)], TEST_RESULT_PREDICATE, predicate))])


def art(digest: str, results: dict[str, str], finished: str | None = None) -> Artifact:
    return Artifact("node-26", IDENTITY, digest, f"file-{digest[:2]}", finished, results)  # type: ignore[arg-type]  # test outcomes


def parsed(records: str) -> Artifact | Rejected:
    return artifact_from_records(NAME, DIGEST, "node-26", IDENTITY, records)


class DecideTest(unittest.TestCase):
    def test_reuse_when_every_required_check_passes(self) -> None:
        one = art("aa" * 32, {"a": "PASSED", "b": "WARNED", "extra": "FAILED"})
        self.assertEqual(decide([one], ["a", "b"]).state, "reuse")
        self.assertEqual(decide([one], ["a", "b"]).artifact, one.digest)

    def test_reuse_with_no_required_checks(self) -> None:
        self.assertEqual(decide([art("aa" * 32, {})], []).state, "reuse")

    def test_reuse_picks_newest_finish_time_across_offsets(self) -> None:
        old = art("11" * 32, {"a": "PASSED"}, "2026-11-21T10:00:00Z")
        new = art("ff" * 32, {"a": "PASSED"}, "2026-11-21T12:00:00+03:00")  # 09:00 UTC, older than 10:00Z
        newer = art("99" * 32, {"a": "PASSED"}, "2026-11-21T11:30:00Z")
        self.assertEqual(decide([old, new], ["a"]).artifact, old.digest)
        self.assertEqual(decide([new, newer, old], ["a"]).artifact, newer.digest)

    def test_reuse_tie_goes_to_smallest_digest_in_any_order(self) -> None:
        a = art("22" * 32, {"a": "PASSED"}, "2026-11-21T10:00:00Z")
        b = art("11" * 32, {"a": "PASSED"}, "2026-11-21T10:00:00Z")
        self.assertEqual(decide([a, b], ["a"]).artifact, b.digest)
        self.assertEqual(decide([b, a], ["a"]).artifact, b.digest)

    def test_artifact_without_time_is_older_than_one_with(self) -> None:
        none = art("00" * 32, {"a": "PASSED"})
        timed = art("ff" * 32, {"a": "PASSED"}, "2026-01-01T00:00:00Z")
        self.assertEqual(decide([none, timed], ["a"]).artifact, timed.digest)
        self.assertEqual(decide([timed, none], ["a"]).artifact, timed.digest)

    def test_reuse_beats_a_newer_candidate(self) -> None:
        good = art("11" * 32, {"a": "PASSED"}, "2026-11-21T10:00:00Z")
        pending = art("00" * 32, {}, "2026-11-22T10:00:00Z")
        self.assertEqual(decide([pending, good], ["a"]), decide([good], ["a"]))

    def test_wait_lists_missing_checks_sorted(self) -> None:
        one = art("aa" * 32, {"b": "PASSED"})
        got = decide([one], ["z", "b", "a"])
        self.assertEqual((got.state, got.artifact, got.waiting_for, got.failed), ("wait", one.digest, ("a", "z"), ()))

    def test_wait_picks_newest_candidate_and_its_own_missing_checks(self) -> None:
        old = art("11" * 32, {}, "2026-11-21T10:00:00Z")
        new = art("22" * 32, {"a": "PASSED"}, "2026-11-21T11:00:00Z")
        got = decide([old, new], ["a", "b"])
        self.assertEqual((got.artifact, got.waiting_for), (new.digest, ("b",)))

    def test_failed_artifact_is_skipped_for_a_candidate(self) -> None:
        failed = art("11" * 32, {"a": "FAILED"})
        pending = art("22" * 32, {})
        got = decide([failed, pending], ["a"])
        self.assertEqual((got.state, got.artifact, got.waiting_for), ("wait", pending.digest, ("a",)))

    def test_build_when_nothing_exists(self) -> None:
        self.assertEqual(decide([], ["a"]), decide([], []))
        self.assertEqual(decide([], ["a"]).state, "build")
        self.assertIsNone(decide([], ["a"]).artifact)

    def test_build_reports_failed_required_checks_only(self) -> None:
        one = art("11" * 32, {"b": "FAILED", "a": "PASSED", "other": "FAILED"})
        two = art("22" * 32, {"c": "FAILED"})
        got = decide([one, two], ["a", "b", "c"])
        self.assertEqual((got.state, got.failed, got.waiting_for), ("build", ("b", "c"), ()))

    def test_failed_beats_missing_on_the_same_artifact(self) -> None:
        got = decide([art("11" * 32, {"a": "FAILED"})], ["a", "b"])
        self.assertEqual((got.state, got.failed), ("build", ("a",)))


class ParseRecordsTest(unittest.TestCase):
    def test_provenance_and_results_make_an_artifact(self) -> None:
        got = parsed(prov(finished="2026-11-21T02:19:41Z") + check("a", "PASSED") + check("b", "WARNED"))
        self.assertEqual(
            got, Artifact("node-26", IDENTITY, DIGEST, NAME, "2026-11-21T02:19:41Z", {"a": "PASSED", "b": "WARNED"})
        )

    def test_provenance_alone_is_a_candidate_without_time(self) -> None:
        got = parsed(prov())
        self.assertIsInstance(got, Artifact)
        assert isinstance(got, Artifact)
        self.assertEqual((got.finished_on, dict(got.results)), (None, {}))

    def test_last_result_in_file_order_wins(self) -> None:
        self.assertEqual(self.result(["FAILED", "PASSED"]), "PASSED")
        self.assertEqual(self.result(["PASSED", "FAILED"]), "FAILED")
        self.assertEqual(self.result(["PASSED", "FAILED", "WARNED"]), "WARNED")

    def result(self, outcomes: list[str]) -> str:
        got = parsed(prov() + "".join(check("a", outcome) for outcome in outcomes))
        assert isinstance(got, Artifact)
        return got.results["a"]

    def test_the_run_that_finished_last_wins_whatever_the_file_order(self) -> None:
        later = check("a", "PASSED", finished="2026-11-21T03:00:00.5Z", run="two")
        earlier = check("a", "FAILED", finished="2026-11-21T02:00:00Z", run="one")
        for text in (earlier + later, later + earlier):
            got = parsed(prov() + text)
            assert isinstance(got, Artifact)
            self.assertEqual(got.results["a"], "PASSED")

    def test_times_are_compared_as_instants_not_as_text(self) -> None:
        east = check("a", "FAILED", finished="2026-11-21T10:00:00+03:00", run="one")  # 07:00Z
        west = check("a", "PASSED", finished="2026-11-21T08:00:00Z", run="two")
        got = parsed(prov() + west + east)
        assert isinstance(got, Artifact)
        self.assertEqual(got.results["a"], "PASSED")

    def test_a_result_without_a_time_is_older_than_one_with_a_time(self) -> None:
        got = parsed(prov() + check("a", "PASSED", finished="2026-11-21T02:00:00Z") + check("a", "FAILED"))
        assert isinstance(got, Artifact)
        self.assertEqual(got.results["a"], "PASSED")

    def test_file_order_breaks_a_tie_of_times(self) -> None:
        one = check("a", "FAILED", finished="2026-11-21T02:00:00Z", run="one")
        two = check("a", "PASSED", finished="2026-11-21T02:00:00Z", run="two")
        got = parsed(prov() + one + two)
        assert isinstance(got, Artifact)
        self.assertEqual(got.results["a"], "PASSED")
        got = parsed(prov() + two + one)
        assert isinstance(got, Artifact)
        self.assertEqual(got.results["a"], "FAILED")

    def test_a_result_stamped_in_the_future_does_not_count_and_is_named(self) -> None:
        now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
        real = check("a", "FAILED", finished="2026-11-22T02:00:00Z", run="one")
        forged = check("a", "PASSED", finished="2099-01-01T00:00:00Z", run="two")
        got = artifact_from_records(NAME, DIGEST, "node-26", IDENTITY, prov() + real + forged, now)
        assert isinstance(got, Artifact)
        self.assertEqual(dict(got.results), {"a": "FAILED"})
        self.assertEqual(got.future_results, (("a", "2099-01-01T00:00:00Z"),))
        (note,) = future_notes([got])
        self.assertEqual(note.name, got.name)
        self.assertIn("finished in the future", note.reason)

    def test_a_check_with_only_a_future_result_has_none(self) -> None:
        now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
        got = artifact_from_records(
            NAME, DIGEST, "node-26", IDENTITY, prov() + check("a", "PASSED", finished="2099-01-01T00:00:00Z"), now
        )
        assert isinstance(got, Artifact)
        self.assertEqual(dict(got.results), {})
        self.assertEqual(decide([got], ["a"]).state, "wait")

    def test_a_small_allowance_covers_clocks_that_differ(self) -> None:
        now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
        inside = check("a", "PASSED", finished="2026-11-22T12:04:59Z")
        outside = check("b", "PASSED", finished="2026-11-22T12:05:01Z")
        got = artifact_from_records(NAME, DIGEST, "node-26", IDENTITY, prov() + inside + outside, now)
        assert isinstance(got, Artifact)
        self.assertEqual(dict(got.results), {"a": "PASSED"})
        self.assertEqual([check_ for check_, _ in got.future_results], ["b"])

    def test_last_results_without_a_now_counts_everything(self) -> None:
        records = parse_envelopes(check("a", "PASSED", finished="2099-01-01T00:00:00Z"))
        self.assertEqual(last_results(records), {"a": "PASSED"})
        self.assertEqual(last_results(records, datetime(2026, 11, 22, tzinfo=UTC)), {})

    def test_each_check_has_its_own_last_result(self) -> None:
        text = (
            check("a", "PASSED", finished="2026-11-21T05:00:00Z")
            + check("b", "FAILED", finished="2026-11-21T01:00:00Z")
            + check("b", "PASSED", finished="2026-11-21T02:00:00Z")
            + check("a", "FAILED", finished="2026-11-21T04:00:00Z")
        )
        got = parsed(prov() + text)
        assert isinstance(got, Artifact)
        self.assertEqual(dict(got.results), {"a": "PASSED", "b": "PASSED"})

    def test_the_run_entry_is_read(self) -> None:
        claim = parse_envelope(check("a", "PASSED", finished="2026-11-21T02:00:00Z", run="r1")).check
        assert claim is not None
        self.assertEqual((claim.run, claim.finished_on), ("r1", "2026-11-21T02:00:00Z"))
        legacy = parse_envelope(check("a", "PASSED")).check
        assert legacy is not None
        self.assertEqual((legacy.run, legacy.finished_on), (None, None))

    def test_a_run_entry_that_is_malformed_is_refused(self) -> None:
        for bad in ({"name": "run"}, {"name": "run", "annotations": {"runId": "x", "finishedOn": "yesterday"}}):
            predicate = test_result("PASSED", [{"name": "a"}, bad])  # type: ignore[list-item]  # a malformed entry
            line = jsonl([envelope(statement([subject(NAME, DIGEST)], TEST_RESULT_PREDICATE, predicate))])
            with self.assertRaises(RecordsError):
                parse_envelope(line)

    def test_failed_then_passed_makes_the_check_pass(self) -> None:
        got = parsed(prov() + check("a", "FAILED") + check("a", "PASSED"))
        assert isinstance(got, Artifact)
        self.assertEqual(decide([got], ["a"]).state, "reuse")

    def test_latest_finish_time_of_several_provenance_records(self) -> None:
        got = parsed(prov(finished="2026-11-21T10:00:00Z") + prov(finished="2026-11-21T12:00:00+03:00"))
        assert isinstance(got, Artifact)
        self.assertEqual(got.finished_on, "2026-11-21T10:00:00Z")

    def test_records_about_another_digest_are_ignored(self) -> None:
        got = parsed(prov() + check("a", "FAILED", digest="34" * 32))
        assert isinstance(got, Artifact)
        self.assertEqual(dict(got.results), {})

    def test_other_predicates_only_have_to_be_well_formed(self) -> None:
        sbom = jsonl([envelope(statement([subject(NAME, DIGEST)], SPDX_PREDICATE, {}))])  # type: ignore[arg-type]  # SPDX stub
        self.assertIsInstance(parsed(prov() + sbom), Artifact)

    def test_provenance_naming_another_identity_is_ignored(self) -> None:
        got = parsed(prov(identity=OTHER))
        self.assertIsInstance(got, Rejected)
        assert isinstance(got, Rejected)
        self.assertIn(OTHER, got.reason)

    def test_provenance_naming_another_image_is_ignored(self) -> None:
        got = parsed(prov(image="core"))
        self.assertIsInstance(got, Rejected)

    def test_one_wrong_provenance_among_right_ones_rejects(self) -> None:
        self.assertIsInstance(parsed(prov() + prov(identity=OTHER)), Rejected)

    def test_no_provenance_about_this_digest_is_rejected(self) -> None:
        self.assertIsInstance(parsed(prov(digest="34" * 32)), Rejected)
        self.assertIsInstance(parsed(check("a", "PASSED")), Rejected)
        self.assertIsInstance(parsed(""), Rejected)

    def test_malformed_lines_reject_the_artifact_with_the_line_number(self) -> None:
        for bad in ("not json\n", "[]\n", '{"payloadType":"x","payload":"e30=","signatures":[]}\n'):
            got = parsed(prov() + bad)
            self.assertIsInstance(got, Rejected, bad)
            assert isinstance(got, Rejected)
            self.assertIn("line 2", got.reason)
            self.assertIn("malformed", got.reason)

    def test_bad_payloads_and_fields_are_malformed(self) -> None:
        def line(payload: bytes, kind: str = "application/vnd.in-toto+json") -> str:
            body = {"payloadType": kind, "payload": base64.b64encode(payload).decode(), "signatures": []}
            return json.dumps(body) + "\n"

        good = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "x", "digest": {"sha256": DIGEST}}],
            "predicateType": TEST_RESULT_PREDICATE,
            "predicate": {"result": "PASSED", "configuration": [{"name": "a"}]},
        }

        def variant(**change: object) -> str:
            return line(json.dumps({**good, **change}).encode())

        cases = [
            line(b"not json"),
            line(b"\xff\xfe"),
            line(json.dumps(good).encode(), kind="text/plain"),
            variant(_type="other"),
            variant(subject=[]),
            variant(subject=[{"digest": {"sha256": "short"}}]),
            variant(predicate={"result": "MAYBE", "configuration": [{"name": "a"}]}),
            variant(predicate={"result": "PASSED", "configuration": []}),
            variant(predicate={"result": "PASSED", "configuration": [{}]}),
            variant(predicateType=PROVENANCE_PREDICATE, predicate={"buildDefinition": {"externalParameters": {}}}),
            variant(
                predicateType=PROVENANCE_PREDICATE,
                predicate={
                    "buildDefinition": {"externalParameters": {"image": "a"}, "internalParameters": {"identity": "xyz"}}
                },
            ),
            variant(
                predicateType=PROVENANCE_PREDICATE,
                predicate={
                    "buildDefinition": {
                        "externalParameters": {"image": "a"},
                        "internalParameters": {"identity": IDENTITY},
                    },
                    "runDetails": {"metadata": {"finishedOn": "yesterday"}},
                },
            ),
        ]
        self.assertEqual(len(parse_envelopes(variant())), 1)
        for case in cases:
            with self.assertRaises(RecordsError, msg=case):
                parse_envelopes(case)
            self.assertIsInstance(parsed(prov() + case), Rejected)

    def test_blank_lines_are_skipped(self) -> None:
        self.assertEqual(len(parse_envelopes("\n" + prov() + "\n\n")), 1)


class DescribedArtifactTest(unittest.TestCase):
    """An artifact read from its records alone, the image and identity being the provenance's (what `prune` lists)."""

    def test_the_image_and_the_identity_are_the_provenances(self) -> None:
        found = described_artifact(
            NAME, DIGEST, prov(finished="2026-11-21T02:00:00Z") + check("a", "PASSED"), IDENTITY[:16]
        )
        self.assertEqual(
            found, Artifact("node-26", IDENTITY, DIGEST, NAME, "2026-11-21T02:00:00Z", {"a": "PASSED"}, False)
        )

    def test_a_full_identity_works_as_the_prefix(self) -> None:
        self.assertIsInstance(described_artifact(NAME, DIGEST, prov(), IDENTITY), Artifact)

    def test_an_identity_that_does_not_start_with_the_prefix_is_rejected(self) -> None:
        found = described_artifact(NAME, DIGEST, prov(OTHER), IDENTITY[:16])
        assert isinstance(found, Rejected)
        self.assertIn(f"provenance names identity {OTHER}", found.reason)

    def test_provenance_that_disagrees_with_itself_is_rejected(self) -> None:
        found = described_artifact(NAME, DIGEST, prov() + prov(image="other"), IDENTITY[:16])
        assert isinstance(found, Rejected)
        self.assertIn("different images or identities", found.reason)

    def test_no_provenance_and_malformed_records_are_rejected(self) -> None:
        for records, reason in (
            ("", "no provenance record"),
            (check("a", "PASSED"), "no provenance record"),
            ("x\n", "malformed"),
        ):
            found = described_artifact(NAME, DIGEST, records, IDENTITY[:16])
            assert isinstance(found, Rejected)
            self.assertIn(reason, found.reason)

    def test_records_about_another_digest_are_not_about_this_one(self) -> None:
        self.assertIsInstance(described_artifact(NAME, "34" * 32, prov(), IDENTITY[:16]), Rejected)


class OrderTest(unittest.TestCase):
    def test_newest_first_by_time_then_smallest_digest_with_untimed_last(self) -> None:
        one = art("22" * 32, {}, "2026-11-21T10:00:00Z")
        two = art("11" * 32, {}, "2026-11-21T10:00:00Z")
        three = art("33" * 32, {}, "2026-11-22T10:00:00Z")
        untimed = art("00" * 32, {})
        self.assertEqual(sort_newest_first([untimed, one, three, two]), [three, two, one, untimed])


class PartialNameTest(unittest.TestCase):
    def test_a_partial_name_is_never_an_artifact_or_a_records_file(self) -> None:
        partial = partial_name(NAME, "0123456789abcdef")
        self.assertEqual(partial, f"{NAME}.partial-0123456789abcdef")
        self.assertIsNone(parse_artifact_name(partial))
        self.assertEqual(partial_of(partial), NAME)
        records = partial_name(f"{DIGEST}.intoto.jsonl", "0123456789abcdef")
        self.assertIsNone(published_records_digest(records))
        self.assertEqual(partial_of(records), f"{DIGEST}.intoto.jsonl")

    def test_other_names_are_not_partial(self) -> None:
        for name in (NAME, f"{NAME}.partial", f"{NAME}.partial-xyz", f"{NAME}.partial-0123456789abcde", ""):
            self.assertIsNone(partial_of(name))

    def test_a_token_is_16_hex(self) -> None:
        with self.assertRaises(ValueError):
            partial_name(NAME, "short")


class FormatTargetTest(unittest.TestCase):
    def test_a_target_reads_back_as_it_was_written(self) -> None:
        for text in ("dir:///srv/out", "oci://localhost:5000/team/app", "github-release://example/images@v1.2"):
            self.assertEqual(format_target(parse_target(text)), text)


class LockedInputsTest(unittest.TestCase):
    """Whether a build lists locked inputs (dependencies with a name and a uri besides lock.json)."""

    def locked(self, dependencies: object) -> bool:
        records = AncestorsTest.provenance_with(dependencies)
        found = artifact_from_records(NAME, DIGEST, "node-26", IDENTITY, records)
        assert isinstance(found, Artifact)
        return found.has_locked_inputs

    def test_a_dependency_with_a_name_and_a_uri_is_a_locked_input(self) -> None:
        self.assertTrue(self.locked([{"name": "node", "uri": "https://example.com/node.tar.gz"}]))

    def test_lock_json_and_other_dependencies_are_not(self) -> None:
        self.assertFalse(self.locked([{"name": "lock.json", "uri": "x", "digest": {"sha256": "11" * 32}}]))
        self.assertFalse(self.locked([{"name": "parent: core", "digest": {"sha256": "11" * 32}}, "text", 3]))
        self.assertFalse(self.locked([]))
        self.assertFalse(self.locked(None))


class AncestorsTest(unittest.TestCase):
    """The images a build descends from, read from its provenance's resolved dependencies."""

    @staticmethod
    def provenance_with(dependencies: object) -> str:
        """A records file of one provenance statement whose resolved dependencies are `dependencies`."""
        statement_ = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": NAME, "digest": {"sha256": DIGEST}}],
            "predicateType": PROVENANCE_PREDICATE,
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {"image": "node-26"},
                    "internalParameters": {"identity": IDENTITY},
                    "resolvedDependencies": dependencies,
                },
                "runDetails": {"builder": {"id": "https://example.com/builder"}, "metadata": {}},
            },
        }
        body = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(statement_).encode()).decode(),
            "signatures": [],
        }
        return json.dumps(body) + "\n"

    def ancestors(self, dependencies: object) -> tuple[tuple[str, str], ...]:
        (record,) = parse_envelopes(self.provenance_with(dependencies))
        assert record.build is not None
        return record.build.ancestors

    def test_the_parent_then_each_ancestor_are_kept_in_order(self) -> None:
        got = self.ancestors(
            [
                {"name": "parent: incus-app", "digest": {"sha256": "11" * 32}},
                {"name": "ancestor: incus-base", "digest": {"sha256": "22" * 32}},
                {"name": "ancestor: core", "digest": {"sha256": "33" * 32}},
            ]
        )
        self.assertEqual(got, (("incus-app", "11" * 32), ("incus-base", "22" * 32), ("core", "33" * 32)))

    def test_the_order_of_the_file_is_the_order_returned_not_a_sorted_one(self) -> None:
        got = self.ancestors(
            [
                {"name": "parent: zzz", "digest": {"sha256": "ff" * 32}},
                {"name": "ancestor: aaa", "digest": {"sha256": "00" * 32}},
            ]
        )
        self.assertEqual([name for name, _ in got], ["zzz", "aaa"])

    def test_other_dependencies_are_ignored_whatever_their_shape(self) -> None:
        got = self.ancestors(
            [
                {"uri": "git+https://example.com/images@" + "9a" * 20, "digest": {"gitCommit": "9a" * 20}},
                {"name": "lock.json", "digest": {"sha256": "44" * 32}},
                {"name": "recipe of node-26", "digest": {"sha256": "not checked"}},
                {"name": "parent:no-space", "digest": {"sha256": "bad"}},
                {"name": 7},
                "text",
                None,
                {"name": "parent: core", "digest": {"sha256": "55" * 32}},
            ]
        )
        self.assertEqual(got, (("core", "55" * 32),))

    def test_a_name_with_a_colon_in_the_image_is_kept_whole(self) -> None:
        got = self.ancestors([{"name": "parent: a: b", "digest": {"sha256": "66" * 32}}])
        self.assertEqual(got, (("a: b", "66" * 32),))

    def test_no_dependencies_or_not_a_list_mean_no_ancestors(self) -> None:
        values: list[object] = [[], None, {}, "parent: core", 3]
        for value in values:
            self.assertEqual(self.ancestors(value), (), repr(value))

    def test_an_ancestor_with_a_malformed_digest_is_a_malformed_record(self) -> None:
        bad: list[object] = [
            {"name": "parent: core"},
            {"name": "parent: core", "digest": "55" * 32},
            {"name": "parent: core", "digest": {"sha256": "short"}},
            {"name": "parent: core", "digest": {"sha256": "AB" * 32}},
            {"name": "ancestor: core", "digest": {"sha256": 5}},
            {"name": "ancestor: core", "digest": {"sha512": "55" * 32}},
        ]
        for dependency in bad:
            with self.assertRaisesRegex(RecordsError, "has no sha256 digest"):
                self.ancestors([{"name": "parent: ok", "digest": {"sha256": "11" * 32}}, dependency])


class NamesTest(unittest.TestCase):
    def test_artifact_name_has_the_designed_shape(self) -> None:
        self.assertEqual(NAME, f"node-26-trixie-amd64-{IDENTITY[:16]}-{DIGEST[:12]}.tar.gz")

    def test_round_trip(self) -> None:
        for image, ext in (("core", "tar.gz"), ("node-26", "tar"), ("incus-base", "incus.tar.gz"), ("a.b", "squashfs")):
            name = artifact_name(image, "trixie", "arm64", IDENTITY, DIGEST, ext)
            got = parse_artifact_name(name)
            assert got is not None
            self.assertEqual(
                (got.image, got.suite, got.arch, got.identity16, got.digest12, got.ext),
                (image, "trixie", "arm64", IDENTITY[:16], DIGEST[:12], ext),
            )

    def test_not_a_name(self) -> None:
        for name in ("core.tar.gz", f"{DIGEST}.intoto.jsonl", "core-trixie-amd64-xyz-123.tar", ""):
            self.assertIsNone(parse_artifact_name(name))

    def test_bad_parts_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            artifact_name("core", "trixie", "amd64", "short", DIGEST, "tar")
        with self.assertRaises(ValueError):
            artifact_name("core", "tri-xie", "amd64", IDENTITY, DIGEST, "tar")
        with self.assertRaises(ValueError):
            artifact_name("Core", "trixie", "amd64", IDENTITY, DIGEST, "tar")


class TargetTest(unittest.TestCase):
    def test_targets(self) -> None:
        self.assertEqual(parse_target("dir:///srv/out"), DirTarget("/srv/out"))
        self.assertEqual(parse_target("dir://out/images"), DirTarget("out/images"))
        self.assertEqual(parse_target("oci://ghcr.io/example/images"), OciTarget("ghcr.io", "example/images"))
        self.assertEqual(parse_target("oci://localhost:5000/core"), OciTarget("localhost:5000", "core"))
        self.assertEqual(
            parse_target("github-release://example/images@v1.2"), ReleaseTarget("example", "images", "v1.2")
        )

    def test_bad_targets(self) -> None:
        for text in (
            "",
            "out",
            "dir://",
            "ftp://x/y",
            "oci://ghcr.io",
            "oci://ghcr.io/",
            "oci://ghcr.io/Example/Images",
            "oci:///repo",
            "oci://bad host/repo",
            "github-release://example/images",
            "github-release://example@v1",
            "github-release://example/images@",
            "github-release://example/images@a b",
            "github-release://-bad/images@v1",
            "github-release://example/../@v1",
        ):
            with self.assertRaises(ValueError, msg=text):
                parse_target(text)


if __name__ == "__main__":
    unittest.main()
