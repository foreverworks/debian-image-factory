"""`byte-equal` (DESIGN 11): the digest of a build against another build of the same image."""

import io
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

from debian_image_factory import published, records
from debian_image_factory.checks import byte_equal, command
from debian_image_factory.checks.model import BYTE_EQUAL, NotRun, Result
from debian_image_factory.commands import Sources, Usage
from tests.support.ocimage import entry, plan_json
from tests.support.rootfs import ARCH, IDENTITY, SUITE, Entry, clean_files, write_artifact

SAME = "ab" * 32
OTHER = "cd" * 32


def name_of(
    image: str = "core", identity: str = IDENTITY, digest: str = SAME, ext: str = "tar.gz"
) -> published.ArtifactName:
    parsed = published.parse_artifact_name(published.artifact_name(image, SUITE, ARCH, identity, digest, ext))
    assert parsed is not None
    return parsed


class CompareTest(unittest.TestCase):
    def test_equal_digests_pass(self) -> None:
        outcome = byte_equal.compare(SAME, [(Path("a/x.tar.gz"), SAME), (Path("b/x.tar.gz"), SAME)])
        self.assertEqual(outcome, Result(BYTE_EQUAL, "PASSED", ("same-digest",), (), ()))

    def test_a_different_digest_warns_and_never_fails(self) -> None:
        outcome = byte_equal.compare(SAME, [(Path("a/x.tar.gz"), SAME), (Path("b/y.tar.gz"), OTHER)])
        assert isinstance(outcome, Result)
        self.assertEqual((outcome.outcome, outcome.failed, outcome.passed), ("WARNED", (), ()))
        self.assertIn(f"y.tar.gz is {OTHER}", outcome.warned[0])
        self.assertNotIn("x.tar.gz", outcome.warned[0])

    def test_without_a_twin_it_is_not_run(self) -> None:
        outcome = byte_equal.compare(SAME, [])
        assert isinstance(outcome, NotRun)
        self.assertIn("--twin", outcome.reason)

    def test_two_builds_are_the_same_image_by_name_up_to_the_digest(self) -> None:
        self.assertTrue(byte_equal.same_build(name_of(), name_of(digest=OTHER)))
        self.assertFalse(byte_equal.same_build(name_of(), name_of(identity="12" * 32)))
        self.assertFalse(byte_equal.same_build(name_of(), name_of(image="os")))
        self.assertFalse(byte_equal.same_build(name_of(), name_of(ext="tar")))


class TestCommandTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "out"
        self.out.mkdir()
        self.path, self.digest = write_artifact(self.out, clean_files())
        (self.out / "plan.json").write_text(
            plan_json({"core": entry("core", identity=IDENTITY, checks=("byte-equal",))})
        )

    def twin(self, name: str, files: Mapping[str, Entry] | None = None) -> Path:
        directory = self.root / name
        directory.mkdir()
        write_artifact(directory, files if files is not None else clean_files())
        return directory

    def run_test(self, *twins: Path, requested: tuple[str, ...] = ()) -> tuple[int, str]:
        out = io.StringIO()
        effects = command.Effects(twins=twins)
        status = command.test_command(self.out, requested, Sources(), out, effects)
        return status, out.getvalue()

    def test_a_twin_with_the_same_bytes_passes_and_is_attested(self) -> None:
        status, text = self.run_test(self.twin("again"))
        self.assertEqual((status, text.strip()), (0, "core: byte-equal PASSED"))
        self.assertEqual(
            len(records.decode_statements((self.out / published.records_name_for(self.digest)).read_text())), 1
        )

    def test_a_twin_with_other_bytes_warns_and_the_exit_status_stays_zero(self) -> None:
        files = clean_files()
        files["./usr/"] = None
        files["./usr/bin/"] = None
        files["./usr/bin/extra"] = b"x"
        status, text = self.run_test(self.twin("again", files))
        self.assertEqual(status, 0)
        self.assertIn("core: byte-equal WARNED: same-digest: this build is " + self.digest, text)

    def test_without_a_twin_it_is_not_run_and_writes_no_record(self) -> None:
        before = (self.out / published.records_name_for(self.digest)).exists()
        status, text = self.run_test()
        self.assertEqual(status, 0)
        self.assertIn("core: byte-equal not run: no second build", text)
        self.assertEqual((self.out / published.records_name_for(self.digest)).exists(), before)

    def test_the_artifact_itself_is_not_its_own_twin(self) -> None:
        _, text = self.run_test(self.out)
        self.assertIn("not run", text)

    def test_it_is_a_check_test_knows_for_every_kind(self) -> None:
        status, text = self.run_test(self.twin("again"), requested=("byte-equal",))
        self.assertEqual((status, text.strip()), (0, "core: byte-equal PASSED"))
        with self.assertRaises(Usage):
            command.test_command(self.out, ["byte-equals"], Sources(), io.StringIO())


if __name__ == "__main__":
    unittest.main()
