"""`verify --pull` for file targets: an artifact of a release or a directory is downloaded with its records and
verified as a local file (DESIGN 9.1), against the fake GitHub API of tests/support."""

import io
import tempfile
import unittest
from pathlib import Path

from debian_image_factory import commands, github, pull, verify
from tests.support import fake_github
from tests.support.oci_fixtures import make_core_file
from tests.test_publish_release import ADDRESS, TARGET, ReleaseCase, make_incus
from tests.test_verify import DEFINITION, VerifyBase


class DirSourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()

    def pulled(self, wanted: str) -> pull.Pulled:
        return pull.pull_artifact(pull.dir_source(self.root / "out"), wanted, self.scratch)

    def test_an_artifact_is_copied_with_its_records_by_name_and_by_digest(self) -> None:
        core = make_core_file(self.root / "out")
        for wanted in (core.name, core.digest, f"sha256:{core.digest}"):
            with self.subTest(wanted):
                for old in self.scratch.iterdir():
                    old.unlink()
                got = self.pulled(wanted)
                self.assertEqual((got.path.name, got.digest, got.problems), (core.name, core.digest, ()))
                self.assertEqual(sorted(p.name for p in self.scratch.iterdir()), sorted([core.name, core.records.name]))

    def test_an_incus_image_is_copied_with_its_rootfs_and_named_by_either_file_or_its_fingerprint(self) -> None:
        names, fingerprint = make_incus(self.root / "out")
        for wanted in (names.metadata, names.rootfs, fingerprint):
            with self.subTest(wanted):
                for old in self.scratch.iterdir():
                    old.unlink()
                got = self.pulled(wanted)
                self.assertEqual((got.path.name, got.digest), (names.metadata, fingerprint))
                self.assertEqual(
                    sorted(p.name for p in self.scratch.iterdir()),
                    sorted([names.metadata, names.rootfs, f"{fingerprint}.intoto.jsonl"]),
                )

    def test_what_is_not_there_is_named(self) -> None:
        core = make_core_file(self.root / "out")
        with self.assertRaisesRegex(commands.Failed, "no artifact named"):
            self.pulled(core.name.replace("core", "other"))
        with self.assertRaisesRegex(commands.Failed, "no artifact whose name carries the digest 000000000000"):
            self.pulled("0" * 64)
        with self.assertRaisesRegex(commands.Failed, "neither an artifact file name nor a sha256"):
            self.pulled("whatever")
        with self.assertRaisesRegex(commands.Failed, "does not exist|No such file"):
            pull.dir_source(self.root / "missing")

    def test_a_digest_that_is_not_the_files_is_a_problem(self) -> None:
        core = make_core_file(self.root / "out")
        core.layout.write_bytes(b"changed")  # the name still carries the old digest
        digest = core.digest
        got = self.pulled(digest)
        self.assertNotEqual(got.digest, digest)
        self.assertIn("not the", got.problems[0])


class VerifyDirTest(VerifyBase):
    def run_pull(self, ref: str, wanted: str | None) -> str:
        said = io.StringIO()
        self.assertEqual(
            verify.verify_command(ref, False, None, self.definition, said, pull_wanted=True, artifact=wanted), 0
        )
        return said.getvalue()

    def test_a_core_tarball_of_a_directory_verifies_by_name_and_by_digest(self) -> None:
        core = make_core_file(self.root / "out", checks=[("package-set", "PASSED")])
        for wanted in (core.name, core.digest):
            said = self.run_pull(f"dir://{self.root / 'out'}", wanted)
            self.assertIn(f"{core.name} in dir://{self.root / 'out'}: verified", said)
            self.assertIn("checks: package-set PASSED", said)

    def test_a_file_that_changed_is_named_against_its_own_digest(self) -> None:
        core = make_core_file(self.root / "out")
        core.layout.write_bytes(b"changed")
        with self.assertRaises(commands.Failed) as caught:
            verify.verify_command(
                f"dir://{self.root / 'out'}",
                False,
                None,
                self.definition,
                io.StringIO(),
                pull_wanted=True,
                artifact=core.name,
            )
        found = str(caught.exception)
        self.assertIn("which its name does not carry", found)
        self.assertIn("no records file", found)

    def test_a_directory_ref_needs_pull_and_an_artifact(self) -> None:
        make_core_file(self.root / "out")
        ref = f"dir://{self.root / 'out'}"
        for pull_wanted, artifact in ((False, None), (True, None), (False, "x")):
            with self.assertRaisesRegex(commands.Usage, "--pull --artifact"):
                verify.verify_command(
                    ref, False, None, self.definition, io.StringIO(), pull_wanted=pull_wanted, artifact=artifact
                )
        with self.assertRaisesRegex(commands.Usage, "--artifact goes with"):
            verify.verify_command(str(self.root / "out"), False, None, self.definition, io.StringIO(), artifact="x")
        with self.assertRaisesRegex(commands.Usage, "already local"):
            verify.verify_command(str(self.root / "out"), False, None, self.definition, io.StringIO(), pull_wanted=True)


class VerifyReleaseTest(ReleaseCase):
    def setUp(self) -> None:
        super().setUp()
        self.definition = self.root / "factory.toml"
        self.definition.write_text(DEFINITION)

    def run_pull(self, wanted: str, tag_ref: str = ADDRESS) -> str:
        said = io.StringIO()
        self.assertEqual(
            verify.verify_command(tag_ref, False, None, self.definition, said, pull_wanted=True, artifact=wanted), 0
        )
        return said.getvalue()

    def test_a_release_artifact_verifies_by_name_and_by_digest(self) -> None:
        core = make_core_file(self.out, checks=[("package-set", "PASSED")])
        self.publish()
        for wanted in (core.name, core.digest):
            said = self.run_pull(wanted)
            self.assertIn(f"{core.name} in {ADDRESS}: verified", said)

    def test_an_asset_changed_after_publishing_is_named(self) -> None:
        core = make_core_file(self.out)
        self.publish()
        self.stored(core.name).data = b"swapped"
        with self.assertRaises(commands.Failed) as caught:
            verify.verify_command(
                ADDRESS, False, None, self.definition, io.StringIO(), pull_wanted=True, artifact=core.name
            )
        self.assertIn("which its name does not carry", str(caught.exception))

    def test_a_missing_release_or_artifact_is_a_failure(self) -> None:
        with self.assertRaisesRegex(commands.Failed, f"{ADDRESS}: no such release"):
            self.run_pull("x-trixie-amd64-0000000000000000-000000000000.tar.gz")
        core = make_core_file(self.out)
        self.publish()
        with self.assertRaisesRegex(commands.Failed, "no artifact named"):
            self.run_pull(core.name.replace("core", "other"))

    def test_the_release_is_read_with_the_clients_own_listing(self) -> None:
        core = make_core_file(self.out)
        self.publish()
        source = pull.release_source(github.connect(TARGET))
        self.assertEqual(source.names, tuple(sorted([core.name, core.records.name])))
        self.assertEqual(fake_github.OWNER in source.label, True)

    def test_an_incus_image_is_pulled_with_both_files(self) -> None:
        names, fingerprint = make_incus(self.out)
        self.publish()
        with tempfile.TemporaryDirectory() as scratch:
            got = pull.pull_artifact(pull.release_source(github.connect(TARGET)), fingerprint, Path(scratch))
            self.assertEqual((got.path.name, got.digest), (names.metadata, fingerprint))
            self.assertEqual(
                sorted(p.name for p in Path(scratch).iterdir()),
                sorted([names.metadata, names.rootfs, f"{fingerprint}.intoto.jsonl"]),
            )


if __name__ == "__main__":
    unittest.main()
