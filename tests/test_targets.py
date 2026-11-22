import hashlib
import tempfile
import unittest
from pathlib import Path

from input_lock.records import (
    PROVENANCE_PREDICATE,
    TEST_RESULT_PREDICATE,
    envelope,
    jsonl,
    provenance,
    statement,
    subject,
    test_result,
)

from debian_image_factory.published import (
    DirTarget,
    artifact_name,
    decide,
    records_name_for,
)
from debian_image_factory.targets import lookup

IDENTITY = "ab" * 32
OTHER = "cd" * 32


def write_artifact(
    directory: Path,
    content: bytes,
    image: str = "node-26",
    identity: str = IDENTITY,
    named_identity: str = IDENTITY,
    results: dict[str, str] | None = None,
    records: bool = True,
    finished: str = "2026-11-21T02:19:41Z",
) -> tuple[str, str]:
    digest = hashlib.sha256(content).hexdigest()
    name = artifact_name(image, "trixie", "amd64", named_identity, digest, "tar.gz")
    (directory / name).write_bytes(content)
    if records:
        envelopes = [
            envelope(
                statement(
                    [subject(name, digest)],
                    PROVENANCE_PREDICATE,
                    provenance(
                        "https://example.com/build-type",
                        {"image": image},
                        [],
                        "https://example.com/builder",
                        internal_parameters={"identity": identity},
                        metadata={"finishedOn": finished},
                    ),
                )
            )
        ]
        for check, outcome in (results or {}).items():
            predicate = test_result(outcome, [{"name": check}])  # type: ignore[arg-type]  # a test names any outcome
            envelopes.append(envelope(statement([subject(name, digest)], TEST_RESULT_PREDICATE, predicate)))
        (directory / records_name_for(digest)).write_text(jsonl(envelopes), encoding="utf-8")
    return name, digest


class DirLookupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def find(self) -> tuple[list[str], list[str]]:
        got = lookup(DirTarget(str(self.dir)), "node-26", "trixie", "amd64", IDENTITY)
        return [a.name for a in got.artifacts], [r.name for r in got.rejected]

    def test_a_good_artifact_is_found_with_its_results(self) -> None:
        name, digest = write_artifact(self.dir, b"one", results={"a": "PASSED", "b": "WARNED"})
        got = lookup(DirTarget(str(self.dir)), "node-26", "trixie", "amd64", IDENTITY)
        self.assertEqual(got.rejected, ())
        (one,) = got.artifacts
        self.assertEqual((one.name, one.digest, one.image, one.identity), (name, digest, "node-26", IDENTITY))
        self.assertEqual(dict(one.results), {"a": "PASSED", "b": "WARNED"})
        self.assertEqual(one.finished_on, "2026-11-21T02:19:41Z")
        self.assertEqual(decide(got.artifacts, ["a", "b"]).state, "reuse")
        self.assertEqual(decide(got.artifacts, ["a", "b", "c"]).state, "wait")

    def test_other_images_identities_and_foreign_files_are_not_listed(self) -> None:
        name, _ = write_artifact(self.dir, b"one")
        write_artifact(self.dir, b"two", image="core")
        write_artifact(self.dir, b"three", identity=OTHER, named_identity=OTHER)
        (self.dir / "notes.txt").write_text("hello")
        (self.dir / "node-26-trixie-amd64-readme").mkdir()
        self.assertEqual(self.find(), ([name], []))

    def test_two_artifacts_of_one_identity_are_both_found_sorted(self) -> None:
        a, _ = write_artifact(self.dir, b"one")
        b, _ = write_artifact(self.dir, b"two")
        self.assertEqual(self.find(), (sorted([a, b]), []))

    def test_missing_directory_holds_nothing(self) -> None:
        got = lookup(DirTarget(str(self.dir / "absent")), "node-26", "trixie", "amd64", IDENTITY)
        self.assertEqual((got.artifacts, got.rejected), ((), ()))

    def test_provenance_naming_another_identity_is_ignored_with_a_reason(self) -> None:
        name, _ = write_artifact(self.dir, b"one", identity=OTHER, named_identity=IDENTITY)
        got = lookup(DirTarget(str(self.dir)), "node-26", "trixie", "amd64", IDENTITY)
        self.assertEqual(got.artifacts, ())
        (rejected,) = got.rejected
        self.assertEqual(rejected.name, name)
        self.assertIn(OTHER, rejected.reason)

    def test_provenance_naming_another_image_is_ignored(self) -> None:
        write_artifact(self.dir, b"one", image="node-26")
        name, _ = write_artifact(self.dir, b"two")
        # rewrite the second artifact's records so its provenance names a different image
        digest = hashlib.sha256(b"two").hexdigest()
        other = jsonl(
            [
                envelope(
                    statement(
                        [subject(name, digest)],
                        PROVENANCE_PREDICATE,
                        provenance(
                            "https://example.com/b",
                            {"image": "core"},
                            [],
                            "https://example.com/x",
                            internal_parameters={"identity": IDENTITY},
                        ),
                    )
                )
            ]
        )
        (self.dir / records_name_for(digest)).write_text(other)
        found, rejected = self.find()
        self.assertEqual(rejected, [name])
        self.assertEqual(len(found), 1)

    def test_file_whose_sha256_does_not_match_its_name_is_ignored(self) -> None:
        name, _ = write_artifact(self.dir, b"one")
        (self.dir / name).write_bytes(b"tampered")
        got = lookup(DirTarget(str(self.dir)), "node-26", "trixie", "amd64", IDENTITY)
        self.assertEqual(got.artifacts, ())
        self.assertIn("does not match", got.rejected[0].reason)

    def test_records_about_another_digest_than_the_files_are_ignored(self) -> None:
        # the name is right for the file, but the records file only vouches for a different digest
        name, digest = write_artifact(self.dir, b"one", records=False)
        other_digest = hashlib.sha256(b"elsewhere").hexdigest()
        text = jsonl(
            [
                envelope(
                    statement(
                        [subject(name, other_digest)],
                        PROVENANCE_PREDICATE,
                        provenance(
                            "https://example.com/b",
                            {"image": "node-26"},
                            [],
                            "https://example.com/x",
                            internal_parameters={"identity": IDENTITY},
                        ),
                    )
                )
            ]
        )
        (self.dir / records_name_for(digest)).write_text(text)
        got = lookup(DirTarget(str(self.dir)), "node-26", "trixie", "amd64", IDENTITY)
        self.assertEqual(got.artifacts, ())
        self.assertIn("no provenance", got.rejected[0].reason)

    def test_missing_records_file_is_ignored_with_a_reason(self) -> None:
        name, digest = write_artifact(self.dir, b"one", records=False)
        got = lookup(DirTarget(str(self.dir)), "node-26", "trixie", "amd64", IDENTITY)
        self.assertEqual(got.artifacts, ())
        self.assertEqual(got.rejected[0].name, name)
        self.assertIn(records_name_for(digest), got.rejected[0].reason)

    def test_malformed_records_line_is_reported_not_raised(self) -> None:
        name, digest = write_artifact(self.dir, b"one", results={"a": "PASSED"})
        path = self.dir / records_name_for(digest)
        path.write_text(path.read_text() + "this is not an envelope\n")
        got = lookup(DirTarget(str(self.dir)), "node-26", "trixie", "amd64", IDENTITY)
        self.assertEqual(got.artifacts, ())
        self.assertEqual(got.rejected[0].name, name)
        self.assertIn("line 3", got.rejected[0].reason)

    def test_records_that_are_not_utf8_are_reported(self) -> None:
        name, digest = write_artifact(self.dir, b"one")
        (self.dir / records_name_for(digest)).write_bytes(b"\xff\xfe\n")
        got = lookup(DirTarget(str(self.dir)), "node-26", "trixie", "amd64", IDENTITY)
        self.assertEqual((got.artifacts, got.rejected[0].name), ((), name))

    def test_a_bad_identity_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            lookup(DirTarget(str(self.dir)), "node-26", "trixie", "amd64", "abc")


if __name__ == "__main__":
    unittest.main()
