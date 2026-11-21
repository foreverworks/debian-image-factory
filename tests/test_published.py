import base64
import json
import unittest

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
    parse_artifact_name,
    parse_envelopes,
    parse_target,
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


def check(name: str, result: str, digest: str = DIGEST) -> str:
    predicate = test_result(result, [{"name": name}])  # type: ignore[arg-type]  # a test names any outcome
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
