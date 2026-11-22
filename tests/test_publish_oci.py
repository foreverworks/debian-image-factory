"""Publishing to an `oci://` target and looking it up again, on a registry that lists referrers (the
API, `OCI-Subject`) and on one that does not (the tag schema): what is pushed, what is skipped the
second time, what a lookup accepts and rejects, and what `push_layout` does for any layout."""

import io
import tempfile
import unittest
from pathlib import Path
from typing import Final

from debian_image_factory import cli, commands, oci, ocilayout, publish, published, registry, targets
from debian_image_factory.published import OciTarget
from tests.support import fake_registry
from tests.support.fake_registry import Fake
from tests.support.oci_fixtures import IDENTITY, make_core_file, make_image, result_line, tiny_layer

OTHER: Final = "d4" * 32


def api() -> Fake:
    return Fake()


def tag_schema() -> Fake:
    return Fake(referrers_api=False, subject_header=False)


MODES: Final = (("api", api), ("tag", tag_schema))


def tags_of(fake: Fake) -> list[str]:
    return sorted(fake.tags)


class PublishOciTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def publish(self, name: str, out: Path | None = None) -> str:
        said = io.StringIO()
        status = publish.publish_command(out or self.root / "out", [f"oci://{name}/team/app"], "none", said)
        self.assertEqual(status, 0)
        return said.getvalue()

    def referrer_count(self, fake: Fake, digest: str) -> int:
        return len(fake_registry.referrers_of(fake, f"sha256:{digest}"))

    def test_an_image_its_tag_and_every_record_are_pushed(self) -> None:
        for mode, make in MODES:
            with self.subTest(mode):
                fake = make()
                built = make_image(self.root / mode)
                with fake_registry.running(fake) as name:
                    said = self.publish(name, self.root / mode)
                    self.assertEqual(said, f"oci://{name}/team/app: {built.name} pushed, 4 records added\n")
                    self.assertEqual(fake.tags[oci.identity_tag(IDENTITY)], f"sha256:{built.digest}")
                    if mode == "api":
                        self.assertEqual(self.referrer_count(fake, built.digest), 4)
                        self.assertNotIn(oci.referrers_tag(built.digest), fake.tags)
                    else:
                        index = oci.parse_index(fake.manifests[fake.tags[oci.referrers_tag(built.digest)]])
                        self.assertEqual(len(index), 4)

    def test_publishing_again_pushes_nothing_and_attaches_nothing(self) -> None:
        for mode, make in MODES:
            with self.subTest(mode):
                fake = make()
                built = make_image(self.root / mode)
                with fake_registry.running(fake) as name:
                    self.publish(name, self.root / mode)
                    held = (dict(fake.manifests), dict(fake.tags))
                    fake.log.clear()
                    said = self.publish(name, self.root / mode)
                    self.assertIn("already there, 0 records added", said)
                    self.assertEqual((fake.manifests, fake.tags), held)
                    self.assertEqual([line for line in fake.log if not line.startswith(("GET", "HEAD"))], [])
                    if mode == "tag":
                        index = oci.parse_index(fake.manifests[fake.tags[oci.referrers_tag(built.digest)]])
                        self.assertEqual(len(index), 4)

    def test_a_record_added_later_is_the_only_one_attached(self) -> None:
        for mode, make in MODES:
            with self.subTest(mode):
                fake = make()
                built = make_image(self.root / mode)
                with fake_registry.running(fake) as name:
                    self.publish(name, self.root / mode)
                    built.records.write_text(
                        built.records.read_text() + result_line(built.name, built.digest, "no-machine-identity")
                    )
                    said = self.publish(name, self.root / mode)
                    self.assertIn("already there, 1 records added", said)
                    self.assertEqual(
                        len(
                            registry.referrers_of(registry.connect(OciTarget(name, "team/app")), built.digest).attached
                        ),
                        5,
                    )

    def test_what_was_published_is_found_by_its_identity_with_its_results(self) -> None:
        for mode, make in MODES:
            with self.subTest(mode):
                fake = make()
                built = make_image(self.root / mode)
                with fake_registry.running(fake) as name:
                    self.publish(name, self.root / mode)
                    found = targets.lookup(OciTarget(name, "team/app"), "app", "trixie", "amd64", IDENTITY)
                    self.assertEqual(found.rejected, ())
                    (artifact,) = found.artifacts
                    self.assertEqual(
                        (artifact.image, artifact.identity, artifact.digest, artifact.name),
                        ("app", IDENTITY, built.digest, f"oci://{name}/team/app@sha256:{built.digest}"),
                    )
                    self.assertEqual(dict(artifact.results), {"package-set": "PASSED", "oci-run": "PASSED"})
                    self.assertEqual(artifact.finished_on, "2026-11-21T02:19:41Z")
                    self.assertEqual(
                        targets.lookup(OciTarget(name, "team/app"), "app", "trixie", "amd64", OTHER),
                        published.Lookup((), ()),
                    )

    def test_a_lookup_in_a_registry_that_has_nothing_finds_nothing(self) -> None:
        with fake_registry.running(Fake()) as name:
            self.assertEqual(
                targets.lookup(OciTarget(name, "team/app"), "app", "trixie", "amd64", IDENTITY),
                published.Lookup((), ()),
            )

    def test_a_tag_whose_manifest_carries_another_identity_is_rejected(self) -> None:
        fake = Fake()
        built = make_image(self.root / "out", identity=OTHER)
        with fake_registry.running(fake) as name:
            self.publish(name)
            fake.tags[oci.identity_tag(IDENTITY)] = f"sha256:{built.digest}"  # someone moved the tag
            found = targets.lookup(OciTarget(name, "team/app"), "app", "trixie", "amd64", IDENTITY)
            self.assertEqual(found.artifacts, ())
            self.assertIn("identity annotation", found.rejected[0].reason)

    def test_a_tag_that_names_an_index_is_rejected(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            client = registry.connect(OciTarget(name, "team/app"))
            registry.put_manifest(client, oci.identity_tag(IDENTITY), oci.index([]), oci.INDEX)
            found = targets.lookup(OciTarget(name, "team/app"), "app", "trixie", "amd64", IDENTITY)
            self.assertEqual(found.artifacts, ())
            self.assertIn("not an OCI image manifest", found.rejected[0].reason)

    def test_records_that_do_not_check_are_rejected_with_the_reason(self) -> None:
        fake = Fake()
        built = make_image(self.root / "out")
        with fake_registry.running(fake) as name:
            self.publish(name)
            for one in registry.referrers_of(registry.connect(OciTarget(name, "team/app")), built.digest).attached:
                fake.broken_blobs.add(f"sha256:{one.envelope.digest}")
            found = targets.lookup(OciTarget(name, "team/app"), "app", "trixie", "amd64", IDENTITY)
            self.assertEqual(found.artifacts, ())
            reasons = [one.reason for one in found.rejected]
            self.assertEqual(sum("does not match its digest" in reason for reason in reasons), 4)
            self.assertIn("no provenance record is about this file's sha256", reasons)

    def test_one_unreadable_record_is_reported_and_the_rest_count(self) -> None:
        fake = Fake()
        built = make_image(self.root / "out")
        with fake_registry.running(fake) as name:
            self.publish(name)
            client = registry.connect(OciTarget(name, "team/app"))
            attached = registry.referrers_of(client, built.digest).attached
            envelopes, _ = registry.fetch_envelopes(client, attached)
            for one, data in zip(attached, envelopes, strict=True):
                record = published.parse_envelope(data.decode())
                if record.check is not None and record.check.check == "oci-run":
                    fake.broken_blobs.add(f"sha256:{one.envelope.digest}")
            found = targets.lookup(OciTarget(name, "team/app"), "app", "trixie", "amd64", IDENTITY)
            self.assertEqual(len(found.rejected), 1)
            self.assertIn("does not match its digest", found.rejected[0].reason)
            self.assertEqual(dict(found.artifacts[0].results), {"package-set": "PASSED"})

    def test_a_dead_registry_is_a_failure_not_a_traceback(self) -> None:
        make_image(self.root / "out")
        with self.assertRaisesRegex(commands.Failed, "oci://127.0.0.1:9/team/app: .*"):
            publish.publish_command(self.root / "out", ["oci://127.0.0.1:9/team/app"], "none", io.StringIO())

    def test_a_registry_that_refuses_the_push_says_so(self) -> None:
        fake = Fake(auth="basic")
        make_image(self.root / "out")
        with fake_registry.running(fake) as name, self.assertRaisesRegex(commands.Failed, "HTTP 401"):
            publish.publish_command(
                self.root / "out",
                [f"oci://{name}/team/app"],
                "none",
                io.StringIO(),
                connect=lambda target: registry.connect(target, credentials=lambda _: None),
            )


class TargetsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_files_go_to_dir_and_images_go_to_oci_and_each_says_what_it_left(self) -> None:
        make_image(self.root / "out")
        core = make_core_file(self.root / "out")
        fake = Fake()
        with fake_registry.running(fake) as name:
            said = io.StringIO()
            publish.publish_command(
                self.root / "out", [f"oci://{name}/team/app", f"dir://{self.root / 'dir'}"], "none", said
            )
            lines = said.getvalue().splitlines()
            self.assertIn(f"{name}/team/app: {core.name} not published here, files publish to dir://", lines)
            self.assertTrue(any("not published here, OCI images publish to oci:// targets" in line for line in lines))
            self.assertTrue((self.root / "dir" / core.name).is_file())
            self.assertEqual(len([p for p in (self.root / "dir").iterdir() if p.suffix == ".oci"]), 0)
            self.assertIn(oci.identity_tag(IDENTITY), fake.tags)

    def test_a_dir_target_alone_refuses_an_image(self) -> None:
        make_image(self.root / "out")
        with self.assertRaisesRegex(commands.Failed, "holds OCI images only .*they publish to oci:// targets"):
            publish.publish_command(self.root / "out", [f"dir://{self.root / 'dir'}"], "none", io.StringIO())
        self.assertFalse((self.root / "dir").exists())
        self.assertEqual(cli.main(["publish", str(self.root / "out"), "--to", f"dir://{self.root / 'dir'}"]), 1)

    def test_an_oci_target_alone_refuses_a_core_tarball(self) -> None:
        make_core_file(self.root / "out")
        with self.assertRaisesRegex(commands.Failed, "holds files only .*oci:// targets take OCI images"):
            publish.publish_command(self.root / "out", ["oci://127.0.0.1:9/team/app"], "none", io.StringIO())

    def test_a_release_target_is_still_a_later_release(self) -> None:
        make_image(self.root / "out")
        with self.assertRaisesRegex(commands.Usage, "github-release:// targets arrive in a later release"):
            publish.publish_command(self.root / "out", ["github-release://example/images@v1"], "none", io.StringIO())

    def test_every_target_is_checked_before_anything_is_written(self) -> None:
        make_core_file(self.root / "out")
        with self.assertRaises(commands.Failed):
            publish.publish_command(
                self.root / "out", [f"dir://{self.root / 'dir'}", "oci://127.0.0.1:9/team/app"], "none", io.StringIO()
            )
        self.assertFalse((self.root / "dir").exists())

    def test_plan_reads_oci_targets_and_still_refuses_releases(self) -> None:
        self.assertEqual(
            commands.parse_targets(["oci://127.0.0.1:5000/team/app"]), [OciTarget("127.0.0.1:5000", "team/app")]
        )
        self.assertEqual(commands.parse_targets(["oci://[::1]:5000/team/app"]), [OciTarget("[::1]:5000", "team/app")])
        with self.assertRaisesRegex(commands.Usage, "github-release targets arrive in a later release"):
            commands.parse_targets(["github-release://example/images@v1"])


class RefusalsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def push(self) -> None:
        publish.publish_command(self.root / "out", ["oci://127.0.0.1:9/team/app"], "none", io.StringIO())

    def test_a_layout_that_was_changed_is_refused_before_anything_is_pushed(self) -> None:
        built = make_image(self.root / "out")
        layer = ocilayout.read_layout(built.layout).layers[0]
        layer.write_bytes(layer.read_bytes() + b"x")
        with self.assertRaisesRegex(commands.Failed, "does not match its descriptor"):
            self.push()

    def test_an_image_without_records_is_refused(self) -> None:
        built = make_image(self.root / "out")
        built.records.unlink()
        with self.assertRaisesRegex(commands.Failed, "no records file"):
            self.push()

    def test_a_provenance_that_names_another_identity_than_the_manifest_is_refused(self) -> None:
        make_image(self.root / "out", provenance_identity=OTHER)
        with self.assertRaisesRegex(commands.Failed, f"provenance names identity {OTHER}"):
            self.push()

    def test_a_record_about_another_artifact_is_refused(self) -> None:
        built = make_image(self.root / "out")
        elsewhere = make_image(self.root / "else", content=b"other", identity=OTHER)
        built.records.write_text(built.records.read_text() + elsewhere.records.read_text().splitlines()[2] + "\n")
        with self.assertRaisesRegex(commands.Failed, "record 5 is not about this image"):
            self.push()

    def test_a_layout_whose_name_lies_is_refused(self) -> None:
        built = make_image(self.root / "out")
        lying = built.layout.with_name(built.name.replace(built.digest[:12], "0" * 12))
        built.layout.rename(lying)
        with self.assertRaisesRegex(commands.Failed, "does not match the digest in its name"):
            self.push()


class PushLayoutTest(unittest.TestCase):
    """`push_layout` takes any single-image layout: the builder image of a later release goes through it."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def layout(self, name: str, content: bytes, annotations: dict[str, str] | None = None) -> ocilayout.Layout:
        layer, digest, size, diff_id = tiny_layer(self.root, content)
        config = oci.image_config(oci.OciConfig(user=name), [diff_id], "amd64")
        path = self.root / name
        ocilayout.write_layout(path, config=config, layers=[(layer, digest, size)], annotations=annotations or {})
        return ocilayout.read_layout(path)

    def test_a_layout_with_no_factory_annotations_and_no_records_is_pushed_under_the_tags_given(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            client = registry.connect(OciTarget(name, "tools/builder"))
            found = self.layout("plain", b"one")
            report = publish.push_layout(client, found, ["v1", "latest"], [])
            self.assertEqual(
                report, publish.PushReport(found.descriptor.digest, "pushed", 2, 0, 0, "api")
            )  # the config and the layer
            self.assertEqual(sorted(fake.tags), ["latest", "v1"])
            self.assertEqual(set(fake.tags.values()), {f"sha256:{found.descriptor.digest}"})
            again = publish.push_layout(client, found, ["v1", "latest"], [])
            self.assertEqual((again.state, again.blobs_pushed), ("already there", 0))

    def test_blobs_the_registry_has_are_not_sent_again(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            client = registry.connect(OciTarget(name, "tools/builder"))
            first = self.layout("a", b"shared")
            second = self.layout("b", b"shared")  # the same layer, another config
            publish.push_layout(client, first, [], [])
            report = publish.push_layout(client, second, [], [])
            self.assertEqual(report.blobs_pushed, 1)  # its config only
            self.assertEqual(len(fake.blobs), 3)

    def test_a_tag_that_named_another_image_is_moved(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            client = registry.connect(OciTarget(name, "tools/builder"))
            first, second = self.layout("a", b"one"), self.layout("b", b"two")
            publish.push_layout(client, first, ["v1"], [])
            report = publish.push_layout(client, second, ["v1"], [])
            self.assertEqual(report.state, "pushed")
            self.assertEqual(fake.tags["v1"], f"sha256:{second.descriptor.digest}")

    def test_the_empty_config_blob_of_the_referrers_goes_up_once(self) -> None:
        fake = Fake()
        built = make_image(self.root / "out")
        with fake_registry.running(fake) as name:
            client = registry.connect(OciTarget(name, "tools/builder"))
            lines = [line for line in built.records.read_bytes().split(b"\n") if line]
            report = publish.push_layout(client, ocilayout.read_layout(built.layout), [], lines)
            self.assertEqual(report.blobs_pushed, 2 + 4 + 1)  # config and layer, four envelopes, one empty config
            self.assertEqual(report.records_added, 4)

    def test_the_same_record_twice_in_one_push_is_attached_once(self) -> None:
        fake = Fake(referrers_api=False, subject_header=False)
        built = make_image(self.root / "out")
        with fake_registry.running(fake) as name:
            client = registry.connect(OciTarget(name, "tools/builder"))
            line = built.records.read_bytes().split(b"\n")[0]
            report = publish.push_layout(client, ocilayout.read_layout(built.layout), [], [line, line])
            self.assertEqual((report.records_added, report.records_present), (1, 1))

    def test_the_tag_schema_keeps_what_others_attached_and_adds_to_the_end(self) -> None:
        fake = Fake(referrers_api=False, subject_header=False)
        built = make_image(self.root / "out", checks=())
        with fake_registry.running(fake) as name:
            client = registry.connect(OciTarget(name, "tools/builder"))
            layout = ocilayout.read_layout(built.layout)
            publish.push_layout(client, layout, [], [])
            foreign = b'{"payload":"e30=","payloadType":"application/vnd.in-toto+json","signatures":[]}'
            data, blob = oci.referrer_manifest(foreign, "https://example.com/x", layout.descriptor)
            registry.put_blob(client, blob.digest, blob.size, foreign)
            registry.put_blob(client, oci.EMPTY_DIGEST, 2, oci.EMPTY_BLOB)
            registry.put_manifest(client, f"sha256:{oci.sha256_hex(data)}", data, oci.MANIFEST)
            registry.put_manifest(
                client,
                oci.referrers_tag(layout.descriptor.digest),
                oci.merged_referrers(None, oci.referrer_descriptor(data)),
                oci.INDEX,
            )
            lines = [line for line in built.records.read_bytes().split(b"\n") if line]
            publish.push_layout(client, layout, [], lines)
            listed = oci.parse_index(fake.manifests[fake.tags[oci.referrers_tag(layout.descriptor.digest)]])
            self.assertEqual(len(listed), 3)
            self.assertEqual(listed[0].digest, oci.sha256_hex(data))  # theirs first, ours after in file order
            self.assertEqual(
                [one.annotations[oci.PREDICATE_TYPE] for one in listed[1:]],
                [
                    "https://slsa.dev/provenance/v1",
                    "https://spdx.dev/Document/v2.3",
                ],
            )

    def test_a_record_that_is_not_an_envelope_is_refused(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            client = registry.connect(OciTarget(name, "tools/builder"))
            with self.assertRaisesRegex(oci.OciError, "not a DSSE envelope"):
                publish.push_layout(client, self.layout("x", b"x"), [], [b"not json"])


if __name__ == "__main__":
    unittest.main()
