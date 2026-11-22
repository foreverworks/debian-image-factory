"""`github-release://` targets: publishing files to a release and reading them back (DESIGN 7.4, 9.1), against a
fake GitHub API in a thread. No test here reaches a real one."""

import hashlib
import io
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path

from input_lock.records import PROVENANCE_PREDICATE, envelope, jsonl, provenance, statement, subject

from debian_image_factory import commands, incus, publish, published, targets
from tests.support import fake_github
from tests.support.fake_github import OWNER, REPO, Fake, Stored
from tests.support.oci_fixtures import IDENTITY, make_core_file, make_image, records_text, result_line

TARGET = published.ReleaseTarget(OWNER, REPO, "v1")
ADDRESS = f"github-release://{OWNER}/{REPO}@v1"
OTHER = "d4" * 32


def make_incus(
    out: Path, *, metadata: bytes = b"metadata tarball", rootfs: bytes = b"squashfs", image: str = "incus-base"
) -> tuple[incus.Names, str]:
    """An Incus image in `out/` with its records: provenance whose subjects are the image under its
    fingerprint and both files under their own sha256, as a build writes it."""
    out.mkdir(parents=True, exist_ok=True)
    fingerprint = incus.fingerprint([metadata, rootfs])
    names = incus.names(image, "trixie", "amd64", IDENTITY, fingerprint)
    (out / names.metadata).write_bytes(metadata)
    (out / names.rootfs).write_bytes(rootfs)
    subjects = [
        subject(names.image, fingerprint),
        subject(names.metadata, hashlib.sha256(metadata).hexdigest()),
        subject(names.rootfs, hashlib.sha256(rootfs).hexdigest()),
    ]
    predicate = provenance(
        "https://example.com/build-type",
        {"image": image},
        [],
        "https://example.com/builder",
        internal_parameters={"identity": IDENTITY},
        metadata={"finishedOn": "2026-11-21T02:19:41Z"},
    )
    text = jsonl([envelope(statement(subjects, PROVENANCE_PREDICATE, predicate))])
    (out / published.records_name_for(fingerprint)).write_text(text)
    return names, fingerprint


class ReleaseCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "out"
        self.fake = Fake()
        stack = ExitStack()
        self.addCleanup(stack.close)
        api = stack.enter_context(fake_github.running(self.fake))
        stack.enter_context(fake_github.environment(api))

    def publish(self, out: Path | None = None) -> str:
        said = io.StringIO()
        self.assertEqual(publish.publish_command(out or self.out, [ADDRESS], "none", said), 0)
        return said.getvalue()

    def assets(self) -> dict[str, bytes]:
        return self.fake.assets("v1")

    def lookup(self, identity: str = IDENTITY, image: str = "core") -> published.Lookup:
        return targets.lookup(TARGET, image, "trixie", "amd64", identity)

    def stored(self, name: str) -> Stored:
        return next(one for one in self.fake.releases["v1"].assets if one.name == name)

    def uploads(self) -> int:
        return len([line for line in self.fake.log if line.startswith("POST /upload")])


class PublishTest(ReleaseCase):
    def test_a_core_tarball_goes_to_a_release_that_is_created(self) -> None:
        core = make_core_file(self.out)
        said = self.publish()
        self.assertIn(f"{ADDRESS}: release created", said)
        self.assertIn(f"{ADDRESS}: {core.name} uploaded, 2 record lines added", said)
        self.assertEqual(
            self.assets(), {core.name: core.layout.read_bytes(), core.records.name: core.records.read_bytes()}
        )
        found = self.lookup()
        self.assertEqual((found.rejected, [one.digest for one in found.artifacts]), ((), [core.digest]))
        self.assertEqual(found.artifacts[0].name, core.name)

    def test_an_incus_image_uploads_both_files_and_its_records_under_the_fingerprint(self) -> None:
        names, fingerprint = make_incus(self.out)
        said = self.publish()
        self.assertIn(f"{ADDRESS}: {names.metadata} uploaded, 1 record lines added", said)
        self.assertEqual(
            sorted(self.assets()), sorted([names.metadata, names.rootfs, published.records_name_for(fingerprint)])
        )
        found = self.lookup(image="incus-base")
        self.assertEqual(found.rejected, ())
        self.assertEqual([(one.name, one.digest) for one in found.artifacts], [(names.metadata, fingerprint)])

    def test_publishing_again_uploads_nothing_and_adds_no_record_line(self) -> None:
        core = make_core_file(self.out)
        self.publish()
        before, uploads = dict(self.assets()), self.uploads()
        said = self.publish()
        self.assertIn(f"{core.name} already there, 0 record lines added", said)
        self.assertNotIn("release created", said)
        self.assertEqual((self.assets(), self.uploads()), (before, uploads))
        self.assertEqual(len([line for line in self.fake.log if line.startswith("DELETE")]), 0)
        self.assertEqual(len(self.assets()[core.records.name].splitlines()), 2)

    def test_an_incus_image_published_again_is_already_there(self) -> None:
        names, _ = make_incus(self.out)
        self.publish()
        uploads = self.uploads()
        self.assertIn(f"{names.metadata} already there, 0 record lines added", self.publish())
        self.assertEqual(self.uploads(), uploads)

    def test_new_records_are_merged_and_the_records_asset_is_replaced(self) -> None:
        core = make_core_file(self.out)
        self.publish()
        held = self.assets()[core.records.name]
        extra = result_line(core.name, core.digest, "package-set", "PASSED")
        core.records.write_text(core.records.read_text() + extra)
        said = self.publish()
        self.assertIn("already there, 1 record lines added", said)
        self.assertEqual(self.assets()[core.records.name], held + extra.encode())
        self.assertEqual(len([line for line in self.fake.log if line.startswith("DELETE")]), 1)
        self.assertEqual(self.lookup().artifacts[0].results, {"package-set": "PASSED"})

    def test_a_line_someone_else_added_is_kept(self) -> None:
        core = make_core_file(self.out)
        self.publish()
        self.stored(core.records.name).data += b"a line from another publisher\n"
        self.publish()
        self.assertTrue(self.assets()[core.records.name].endswith(b"a line from another publisher\n"))

    def test_an_asset_that_holds_other_bytes_is_refused_and_nothing_is_written(self) -> None:
        core = make_core_file(self.out)
        names, _ = make_incus(self.out)
        release = fake_github.Release(fake_github.new_id(self.fake), "v1")
        release.assets.append(Stored(fake_github.new_id(self.fake), names.rootfs, b"someone else's squashfs"))
        self.fake.releases["v1"] = release
        with self.assertRaises(commands.Failed) as caught:
            self.publish()
        text = str(caught.exception)
        theirs = hashlib.sha256(b"someone else's squashfs").hexdigest()
        self.assertIn(f"the asset {names.rootfs} holds sha256 {theirs}", text)
        self.assertIn(f"is sha256 {hashlib.sha256(b'squashfs').hexdigest()}", text)
        self.assertIn("nothing was overwritten", text)
        self.assertEqual(self.assets(), {names.rootfs: b"someone else's squashfs"})
        self.assertEqual(self.uploads(), 0)
        self.assertNotIn(core.name, self.assets())

    def test_an_asset_whose_digest_github_does_not_state_is_compared_by_its_bytes(self) -> None:
        core = make_core_file(self.out)
        self.publish()
        self.fake.hide_digest.update(self.assets())
        uploads = self.uploads()
        self.assertIn("already there, 0 record lines added", self.publish())
        self.assertEqual(self.uploads(), uploads)
        self.stored(core.name).data = b"tampered"
        with self.assertRaisesRegex(commands.Failed, "nothing was overwritten"):
            self.publish()

    def test_an_oci_layout_is_not_published_here_and_the_files_are(self) -> None:
        make_image(self.out)
        core = make_core_file(self.out)
        said = self.publish()
        self.assertRegex(said, r"@v1: app-.*\.oci not published here, OCI images publish to oci:// targets")
        self.assertEqual(sorted(self.assets()), sorted([core.name, core.records.name]))

    def test_an_output_of_oci_images_only_fails_before_anything_is_written(self) -> None:
        make_image(self.out)
        with self.assertRaisesRegex(commands.Failed, "holds OCI images only .*a github-release:// target takes files"):
            self.publish()
        self.assertEqual((self.fake.log, self.fake.releases), ([], {}))

    def test_an_anonymous_publisher_is_told_so(self) -> None:
        make_core_file(self.out)
        with (
            fake_github.environment(f"http://127.0.0.1:{self.fake.port}", token=None),
            self.assertRaisesRegex(commands.Failed, "anonymous"),
        ):
            self.publish()
        self.assertEqual(self.fake.releases, {})

    def test_a_file_that_does_not_match_its_name_is_refused(self) -> None:
        core = make_core_file(self.out)
        core.layout.write_bytes(b"tampered")
        with self.assertRaisesRegex(commands.Failed, "does not match the digest in its name"):
            self.publish()
        self.assertEqual(self.fake.log, [])

    def test_the_token_is_never_in_what_a_failure_says(self) -> None:
        make_core_file(self.out)
        self.fake.fail_once.extend(["POST /upload"] * 4)
        with self.assertRaises(commands.Failed) as caught:
            self.publish()
        self.assertIn("HTTP 503", str(caught.exception))
        self.assertNotIn(fake_github.TOKEN, str(caught.exception))


class LookupTest(ReleaseCase):
    def test_a_tag_without_a_release_holds_nothing(self) -> None:
        self.assertEqual(self.lookup(), published.Lookup((), ()))

    def test_results_come_from_the_records_and_other_files_are_left_alone(self) -> None:
        core = make_core_file(self.out, checks=[("package-set", "PASSED"), ("oci-run", "FAILED")])
        other = self.root / "other"
        other.mkdir()
        content = b"another core"
        digest = hashlib.sha256(content).hexdigest()
        name = published.artifact_name("core", "trixie", "amd64", OTHER, digest, "tar.gz")
        (other / name).write_bytes(content)
        (other / published.records_name_for(digest)).write_text(
            records_text(name, digest, image="core", kind="core", identity=OTHER, checks=())
        )
        (self.out / "plan.json").write_text("{}")
        self.publish()
        self.publish(other)
        found = self.lookup()
        self.assertEqual((found.rejected, [one.digest for one in found.artifacts]), ((), [core.digest]))
        self.assertEqual(found.artifacts[0].results, {"package-set": "PASSED", "oci-run": "FAILED"})
        self.assertEqual(self.lookup(OTHER).artifacts[0].identity, OTHER)

    def test_other_images_in_the_release_are_not_this_ones(self) -> None:
        make_core_file(self.out)
        self.publish()
        self.assertEqual(self.lookup(image="app"), published.Lookup((), ()))

    def test_a_listing_of_several_pages_and_assets_without_digests_still_reads(self) -> None:
        core = make_core_file(self.out)
        _, fingerprint = make_incus(self.out)
        self.publish()
        self.fake.page_size = 1
        self.fake.hide_digest.update(self.assets())
        self.assertEqual([one.digest for one in self.lookup().artifacts], [core.digest])
        self.assertEqual([one.digest for one in self.lookup(image="incus-base").artifacts], [fingerprint])

    def test_an_artifact_without_a_records_asset_is_rejected(self) -> None:
        core = make_core_file(self.out)
        self.publish()
        self.fake.releases["v1"].assets.remove(self.stored(core.records.name))
        found = self.lookup()
        self.assertEqual(found.artifacts, ())
        self.assertEqual(
            [(one.name, one.reason) for one in found.rejected],
            [(core.name, f"no records asset {core.records.name} beside it")],
        )

    def test_records_that_name_another_identity_are_rejected(self) -> None:
        core = make_core_file(self.out)
        core.records.write_text(
            records_text(core.name, core.digest, image="core", kind="core", identity=OTHER, checks=())
        )
        self.publish()
        found = self.lookup()
        self.assertEqual(found.artifacts, ())
        self.assertIn(f"provenance names identity {OTHER}, not {IDENTITY}", found.rejected[0].reason)

    def test_records_about_another_image_are_rejected(self) -> None:
        core = make_core_file(self.out)
        core.records.write_text(
            records_text(core.name, core.digest, image="app", kind="core", identity=IDENTITY, checks=())
        )
        self.publish()
        self.assertIn("provenance names image 'app', not 'core'", self.lookup().rejected[0].reason)

    def test_bytes_that_do_not_match_the_name_are_rejected_with_or_without_a_stated_digest(self) -> None:
        core = make_core_file(self.out)
        self.publish()
        for hidden in (False, True):
            with self.subTest(hidden=hidden):
                self.fake.hide_digest.clear()
                if hidden:
                    self.fake.hide_digest.add(core.name)
                self.stored(core.name).data = b"tampered" if hidden else b"tampered too"
                found = self.lookup()
                self.assertEqual(found.artifacts, ())
                self.assertIn("does not match the digest in its name", found.rejected[0].reason)

    def test_an_incus_image_without_its_rootfs_is_rejected(self) -> None:
        names, _ = make_incus(self.out)
        self.publish()
        self.fake.releases["v1"].assets.remove(self.stored(names.rootfs))
        found = self.lookup(image="incus-base")
        self.assertEqual(found.artifacts, ())
        self.assertEqual(
            [(one.name, one.reason) for one in found.rejected],
            [(names.metadata, f"no rootfs {names.rootfs} asset beside it")],
        )

    def test_an_incus_image_whose_records_do_not_cover_both_files_is_rejected(self) -> None:
        names, fingerprint = make_incus(self.out)
        self.publish()
        self.stored(names.rootfs).data = b"another squashfs"
        found = self.lookup(image="incus-base")
        self.assertEqual(found.artifacts, ())
        self.assertIn(
            f"no records asset starting {fingerprint[:12]} lists the sha256 of both of its files",
            found.rejected[0].reason,
        )

    def test_an_incus_image_without_a_records_asset_is_rejected(self) -> None:
        names, fingerprint = make_incus(self.out)
        self.publish()
        self.fake.releases["v1"].assets.remove(self.stored(published.records_name_for(fingerprint)))
        found = self.lookup(image="incus-base")
        self.assertEqual(found.artifacts, ())
        self.assertEqual(found.rejected[0].name, names.metadata)

    def test_records_that_are_not_text_or_not_records_are_rejected(self) -> None:
        core = make_core_file(self.out)
        self.publish()
        for data, reason in ((b"\xff\xfe\n", "is not UTF-8"), (b"not json\n", "records file is malformed")):
            with self.subTest(reason=reason):
                self.stored(core.records.name).data = data
                found = self.lookup()
                self.assertEqual(found.artifacts, ())
                self.assertIn(reason, found.rejected[0].reason)

    def test_a_bad_identity_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.lookup("abc")


if __name__ == "__main__":
    unittest.main()
