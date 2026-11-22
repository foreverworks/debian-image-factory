"""OCI values (`oci`) and the image layout on disk (`ocilayout`): canonical bytes, the config merge
rules, parse round trips and refusals, referrer manifests in the shape of DESIGN 8.2, the tag-schema
index update, and a layout that is written, read back and refuses a changed byte."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Final

from input_lock import JsonValue

from debian_image_factory import oci, ocilayout
from tests.support.oci_fixtures import IDENTITY, make_image, tiny_layer

DIGEST: Final = "ab" * 32
EMPTY_CONFIG_DIGEST: Final = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"


def table(**values: JsonValue) -> dict[str, JsonValue]:
    return dict(values)


class CanonicalTest(unittest.TestCase):
    def test_keys_are_sorted_and_nothing_is_padded(self) -> None:
        self.assertEqual(
            oci.canonical({"b": [1, 2], "a": {"d": 1, "c": "é"}}), '{"a":{"c":"é","d":1},"b":[1,2]}'.encode()
        )

    def test_the_same_values_in_another_order_give_the_same_bytes(self) -> None:
        self.assertEqual(oci.canonical({"x": 1, "y": 2}), oci.canonical({"y": 2, "x": 1}))

    def test_the_empty_blob_has_the_digest_the_image_spec_gives_it(self) -> None:
        self.assertEqual(oci.EMPTY_BLOB, b"{}")
        self.assertEqual(oci.EMPTY_DIGEST, hashlib.sha256(b"{}").hexdigest())
        self.assertEqual(f"sha256:{oci.EMPTY_DIGEST}", EMPTY_CONFIG_DIGEST)


class DigestAndTagTest(unittest.TestCase):
    def test_digests_are_sha256_in_lowercase_hex_only(self) -> None:
        self.assertEqual(oci.parse_digest(f"sha256:{DIGEST}"), DIGEST)
        self.assertEqual(oci.digest_text(DIGEST), f"sha256:{DIGEST}")
        for bad in (DIGEST, f"sha512:{DIGEST}", f"sha256:{DIGEST.upper()}", "sha256:abc", None, 7):
            with self.subTest(bad=bad), self.assertRaises(oci.OciError):
                oci.parse_digest(bad)
        with self.assertRaises(oci.OciError):
            oci.digest_text("abc")

    def test_the_identity_tag_is_73_characters(self) -> None:
        self.assertEqual(oci.identity_tag(IDENTITY), f"identity-{IDENTITY}")
        self.assertEqual(len(oci.identity_tag(IDENTITY)), 73)
        with self.assertRaises(oci.OciError):
            oci.identity_tag(IDENTITY[:-1])

    def test_the_referrers_tag_is_the_tag_schemas(self) -> None:
        self.assertEqual(oci.referrers_tag(DIGEST), f"sha256-{DIGEST}")
        with self.assertRaises(oci.OciError):
            oci.referrers_tag(f"sha256:{DIGEST}")

    def test_architectures(self) -> None:
        self.assertEqual([oci.oci_architecture(a) for a in ("amd64", "arm64", "armhf")], ["amd64", "arm64", "arm"])
        with self.assertRaises(oci.OciError):
            oci.oci_architecture("m68k")


class ConfigMergeTest(unittest.TestCase):
    def test_a_child_of_core_starts_empty(self) -> None:
        found = oci.merged_config(
            None, table(user="app", workdir="/srv", env={"B": "2", "A": "1"}, labels={"z": "1", "a": "2"})
        )
        self.assertEqual(found.user, "app")
        self.assertEqual(found.workdir, "/srv")
        self.assertEqual(found.env, (("B", "2"), ("A", "1")))
        self.assertEqual(found.labels, (("a", "2"), ("z", "1")))

    def test_env_and_labels_merge_key_by_key_and_the_rest_replaces(self) -> None:
        parent = oci.merged_config(
            None, table(user="root", workdir="/", cmd=["a"], env={"A": "1", "B": "2"}, labels={"k": "old", "p": "p"})
        )
        child = oci.merged_config(parent, table(user="app", env={"B": "3", "C": "4"}, labels={"k": "new"}))
        self.assertEqual(child.user, "app")
        self.assertEqual(child.workdir, "/")
        self.assertEqual(child.cmd, ("a",))
        self.assertEqual(child.env, (("A", "1"), ("B", "3"), ("C", "4")))  # a replaced value keeps its place
        self.assertEqual(child.labels, (("k", "new"), ("p", "p")))

    def test_an_entrypoint_without_cmd_clears_the_inherited_cmd(self) -> None:
        parent = oci.merged_config(None, table(entrypoint=["/old"], cmd=["--serve"]))
        cleared = oci.merged_config(parent, table(entrypoint=["/new"]))
        self.assertEqual((cleared.entrypoint, cleared.cmd), (("/new",), None))
        kept = oci.merged_config(parent, table(entrypoint=["/new"], cmd=["--x"]))
        self.assertEqual((kept.entrypoint, kept.cmd), (("/new",), ("--x",)))

    def test_a_cmd_alone_keeps_the_inherited_entrypoint(self) -> None:
        parent = oci.merged_config(None, table(entrypoint=["/old"], cmd=["--serve"]))
        found = oci.merged_config(parent, table(cmd=["--other"]))
        self.assertEqual((found.entrypoint, found.cmd), (("/old",), ("--other",)))

    def test_an_empty_table_changes_nothing(self) -> None:
        parent = oci.merged_config(None, table(user="u", env={"A": "1"}))
        self.assertEqual(oci.merged_config(parent, {}), parent)

    def test_refusals(self) -> None:
        for bad in (
            table(color="red"),
            table(user=3),
            table(cmd="a"),
            table(cmd=[1]),
            table(env=["A=1"]),
            table(env={"A": 1}),
        ):
            with self.subTest(bad=bad), self.assertRaises(oci.OciError):
                oci.merged_config(None, bad)

    def test_the_config_json_holds_only_what_is_set(self) -> None:
        self.assertEqual(oci.config_json(oci.OciConfig()), {})
        found = oci.config_json(
            oci.merged_config(
                None, table(user="u", entrypoint=["/x"], cmd=["c"], env={"A": "1"}, workdir="/w", labels={"l": "v"})
            )
        )
        self.assertEqual(
            found,
            {"User": "u", "Entrypoint": ["/x"], "Cmd": ["c"], "Env": ["A=1"], "WorkingDir": "/w", "Labels": {"l": "v"}},
        )


class ImageConfigTest(unittest.TestCase):
    def test_a_config_carries_no_build_time_and_round_trips(self) -> None:
        config = oci.merged_config(None, table(user="u", entrypoint=["/x"], env={"A": "1=2"}, labels={"l": "v"}))
        data = oci.image_config(config, [DIGEST, "cd" * 32], "arm64")
        value = json.loads(data)
        self.assertEqual(set(value), {"architecture", "os", "config", "rootfs"})  # no created, no history
        self.assertEqual((value["architecture"], value["os"]), ("arm64", "linux"))
        self.assertEqual(value["rootfs"], {"type": "layers", "diff_ids": [f"sha256:{DIGEST}", f"sha256:{'cd' * 32}"]})
        self.assertEqual(data, oci.canonical(value))
        parsed, diff_ids = oci.parse_config(data)
        self.assertEqual(parsed, config)
        self.assertEqual(diff_ids, (DIGEST, "cd" * 32))

    def test_a_config_written_elsewhere_still_reads(self) -> None:
        data = json.dumps(
            {"created": "2020-01-01T00:00:00Z", "history": [], "config": {"ExposedPorts": {"80/tcp": {}}, "Cmd": ["x"]},
             "rootfs": {"type": "layers", "diff_ids": [f"sha256:{DIGEST}"]}}
        ).encode()  # fmt: skip
        parsed, diff_ids = oci.parse_config(data)
        self.assertEqual((parsed.cmd, diff_ids), (("x",), (DIGEST,)))

    def test_refusals(self) -> None:
        for bad in (b"nope", b"[]", b"{}", b'{"rootfs":{"type":"layers","diff_ids":["sha256:abc"]}}',
                    b'{"rootfs":{"type":"layers","diff_ids":[]},"config":{"Cmd":"x"}}',
                    b'{"rootfs":{"type":"layers","diff_ids":[]},"config":{"User":3}}'):  # fmt: skip
            with self.subTest(bad=bad), self.assertRaises(oci.OciError):
                oci.parse_config(bad)


class ManifestTest(unittest.TestCase):
    def test_an_image_manifest_round_trips(self) -> None:
        config = oci.descriptor_of(oci.CONFIG, b"{}x")
        layers = [oci.Descriptor(oci.LAYER_GZIP, DIGEST, 10), oci.Descriptor(oci.LAYER_GZIP, "cd" * 32, 20)]
        annotations = oci.image_annotations(
            identity=IDENTITY,
            base_digest=DIGEST,
            base_name="core",
            source="git+https://example.com/x",
            revision="1" * 40,
        )
        data = oci.image_manifest(config, layers, annotations)
        self.assertEqual(data, oci.canonical(json.loads(data)))
        parsed = oci.parse_manifest(data)
        self.assertEqual((parsed.config, parsed.layers), (config, tuple(layers)))
        self.assertEqual(parsed.annotations[oci.IDENTITY], IDENTITY)
        self.assertEqual(parsed.annotations[oci.BASE_DIGEST], f"sha256:{DIGEST}")
        self.assertIsNone(parsed.subject)
        self.assertEqual(
            oci.parse_manifest(oci.image_manifest(config, [], {oci.IDENTITY: IDENTITY})).annotations,
            {oci.IDENTITY: IDENTITY},
        )

    def test_annotations_leave_out_what_is_unknown(self) -> None:
        self.assertEqual(
            oci.image_annotations(identity=IDENTITY, base_digest=None, base_name=None, source=None, revision=None),
            {oci.IDENTITY: IDENTITY},
        )

    def test_refusals(self) -> None:
        good = json.loads(oci.image_manifest(oci.descriptor_of(oci.CONFIG, b"c"), [], {}))
        cases: list[bytes] = [b"nope", b"[]", json.dumps({**good, "schemaVersion": 1}).encode()]
        cases.append(json.dumps({**good, "mediaType": oci.INDEX}).encode())
        cases.append(json.dumps({**good, "mediaType": "application/vnd.docker.distribution.manifest.v2+json"}).encode())
        cases.append(json.dumps({**good, "layers": "x"}).encode())
        cases.append(json.dumps({**good, "layers": [{"mediaType": "x", "digest": "sha256:zz", "size": 1}]}).encode())
        cases.append(
            json.dumps({**good, "layers": [{"mediaType": "x", "digest": f"sha256:{DIGEST}", "size": -1}]}).encode()
        )
        cases.append(json.dumps({**good, "annotations": {"a": 1}}).encode())
        cases.append(json.dumps({**good, "artifactType": 3}).encode())
        for bad in cases:
            with self.subTest(bad=bad[:60]), self.assertRaises(oci.OciError):
                oci.parse_manifest(bad)


class ReferrerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = b'{"payload":"e30=","payloadType":"application/vnd.in-toto+json","signatures":[]}'
        self.subject = oci.Descriptor(oci.MANIFEST, DIGEST, 1043)
        self.predicate = "https://slsa.dev/provenance/v1"

    def test_the_referrer_manifest_has_the_shape_of_design_8_2(self) -> None:
        data, blob = oci.referrer_manifest(self.envelope, self.predicate, self.subject)
        self.assertEqual(
            json.loads(data),
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": "application/vnd.in-toto+json",
                "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": EMPTY_CONFIG_DIGEST, "size": 2},
                "layers": [
                    {
                        "mediaType": "application/vnd.dsse.envelope.v1+json",
                        "digest": f"sha256:{hashlib.sha256(self.envelope).hexdigest()}",
                        "size": len(self.envelope),
                        "annotations": {"in-toto.io/predicate-type": self.predicate},
                    }
                ],
                "subject": {"mediaType": oci.MANIFEST, "digest": f"sha256:{DIGEST}", "size": 1043},
            },
        )
        self.assertEqual(data, oci.canonical(json.loads(data)))
        self.assertEqual(
            (blob.media_type, blob.digest, blob.size),
            (oci.DSSE_ENVELOPE, oci.sha256_hex(self.envelope), len(self.envelope)),
        )

    def test_the_same_record_always_gives_the_same_manifest(self) -> None:
        self.assertEqual(
            oci.referrer_manifest(self.envelope, self.predicate, self.subject),
            oci.referrer_manifest(self.envelope, self.predicate, self.subject),
        )

    def test_a_referrer_is_listed_by_digest_size_artifact_type_and_predicate(self) -> None:
        data, _ = oci.referrer_manifest(self.envelope, self.predicate, self.subject)
        listed = oci.referrer_descriptor(data)
        self.assertEqual(
            (listed.media_type, listed.digest, listed.size, listed.artifact_type, dict(listed.annotations)),
            (oci.MANIFEST, oci.sha256_hex(data), len(data), oci.IN_TOTO_ARTIFACT, {oci.PREDICATE_TYPE: self.predicate}),
        )

    def test_an_artifact_manifest_round_trips_its_subject_and_type(self) -> None:
        data, _ = oci.referrer_manifest(self.envelope, self.predicate, self.subject)
        parsed = oci.parse_manifest(data)
        self.assertEqual(parsed.artifact_type, oci.IN_TOTO_ARTIFACT)
        self.assertEqual(parsed.subject, self.subject)
        self.assertEqual(parsed.config.media_type, oci.EMPTY)


class IndexTest(unittest.TestCase):
    def descriptors(self) -> list[oci.Descriptor]:
        return [
            oci.Descriptor(oci.MANIFEST, c * 64, 100 + n, {oci.PREDICATE_TYPE: "p"}, oci.IN_TOTO_ARTIFACT)
            for n, c in enumerate("abc")
        ]

    def test_an_index_round_trips_in_order(self) -> None:
        listed = self.descriptors()
        data = oci.index(listed)
        self.assertEqual(data, oci.canonical(json.loads(data)))
        self.assertEqual(list(oci.parse_index(data)), listed)

    def test_merged_referrers_starts_an_index_when_there_is_none(self) -> None:
        one = self.descriptors()[0]
        self.assertEqual(oci.parse_index(oci.merged_referrers(None, one)), (one,))

    def test_merged_referrers_appends_in_order_and_never_lists_one_twice(self) -> None:
        first, second, third = self.descriptors()
        held = oci.merged_referrers(oci.merged_referrers(None, first), second)
        self.assertEqual(oci.merged_referrers(held, first), held)  # already listed: unchanged bytes
        self.assertEqual(oci.parse_index(oci.merged_referrers(held, third)), (first, second, third))

    def test_refusals(self) -> None:
        for bad in (
            b"x",
            b"[]",
            b'{"schemaVersion":1}',
            b'{"schemaVersion":2,"mediaType":"x","manifests":[]}',
            b'{"schemaVersion":2}',
        ):
            with self.subTest(bad=bad), self.assertRaises(oci.OciError):
                oci.parse_index(bad)
        self.assertEqual(oci.parse_index(b'{"schemaVersion":2,"manifests":[]}'), ())  # a missing mediaType is allowed


class LayoutTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def written(self) -> tuple[Path, oci.Descriptor, bytes]:
        layer, digest, size, diff_id = tiny_layer(self.root, b"content")
        config = oci.image_config(oci.OciConfig(), [diff_id], "amd64")
        path = self.root / "layout"
        descriptor = ocilayout.write_layout(
            path, config=config, layers=[(layer, digest, size)], annotations={oci.IDENTITY: IDENTITY}
        )
        return path, descriptor, config

    def test_a_layout_is_written_and_read_back(self) -> None:
        path, descriptor, config = self.written()
        self.assertEqual(sorted(p.name for p in path.iterdir()), ["blobs", "index.json", "oci-layout"])
        self.assertEqual((path / "oci-layout").read_bytes(), b'{"imageLayoutVersion":"1.0.0"}')
        found = ocilayout.read_layout(path)
        self.assertEqual(found.descriptor, descriptor)
        self.assertEqual(found.config_bytes, config)
        self.assertEqual(found.manifest.annotations, {oci.IDENTITY: IDENTITY})
        self.assertEqual(len(found.layers), 1)
        self.assertEqual(found.layers[0], ocilayout.blob_path(path, found.manifest.layers[0].digest))
        self.assertEqual(oci.sha256_hex(found.manifest_bytes), descriptor.digest)

    def test_a_layout_is_not_written_over_another(self) -> None:
        path, _, _ = self.written()
        with self.assertRaises(FileExistsError):
            ocilayout.write_layout(path, config=b"{}", layers=[], annotations={})

    def test_every_blob_is_checked_when_read(self) -> None:
        for which in ("manifest", "config", "layer"):
            with self.subTest(which):
                path, descriptor, _ = self.written()
                found = ocilayout.read_layout(path)
                blob = {
                    "manifest": ocilayout.blob_path(path, descriptor.digest),
                    "config": ocilayout.blob_path(path, found.manifest.config.digest),
                    "layer": found.layers[0],
                }[which]
                blob.write_bytes(blob.read_bytes() + b"x")
                with self.assertRaisesRegex(oci.OciError, "does not match its descriptor"):
                    ocilayout.read_layout(path)
                # tear down for the next case
                for child in sorted(path.rglob("*"), reverse=True):
                    child.rmdir() if child.is_dir() else child.unlink()
                path.rmdir()

    def test_layers_can_be_left_for_the_caller_to_hash(self) -> None:
        path, _, _ = self.written()
        layer = ocilayout.read_layout(path).layers[0]
        layer.write_bytes(b"changed")
        self.assertEqual(len(ocilayout.read_layout(path, check_layers=False).layers), 1)
        with self.assertRaises(oci.OciError):
            ocilayout.read_layout(path)

    def test_a_directory_that_is_not_one_image_layout_is_refused(self) -> None:
        path, descriptor, _ = self.written()
        (path / "index.json").write_bytes(oci.index([descriptor, descriptor]))
        with self.assertRaisesRegex(oci.OciError, "exactly one image manifest"):
            ocilayout.read_layout(path)
        (path / "oci-layout").write_bytes(b'{"imageLayoutVersion":"2.0.0"}')
        with self.assertRaisesRegex(oci.OciError, "version 1.0.0"):
            ocilayout.read_layout(path)
        with self.assertRaisesRegex(oci.OciError, "not an OCI image layout"):
            ocilayout.read_layout(self.root / "missing")

    def test_a_config_whose_diff_ids_do_not_match_the_layers_is_refused(self) -> None:
        layer, digest, size, _ = tiny_layer(self.root, b"content")
        path = self.root / "bad"
        ocilayout.write_layout(
            path, config=oci.image_config(oci.OciConfig(), [], "amd64"), layers=[(layer, digest, size)], annotations={}
        )
        with self.assertRaisesRegex(oci.OciError, "1 layers but 0 diff_ids"):
            ocilayout.read_layout(path)

    def test_a_layer_file_with_the_wrong_digest_is_not_added(self) -> None:
        layer, _, size, _ = tiny_layer(self.root, b"content")
        with self.assertRaisesRegex(oci.OciError, "its sha256 is not"):
            ocilayout.write_layout(self.root / "x", config=b"{}", layers=[(layer, DIGEST, size)], annotations={})

    def test_a_build_output_layout_reads(self) -> None:
        built = make_image(self.root / "out")
        self.assertEqual(ocilayout.read_layout(built.layout).descriptor.digest, built.digest)


if __name__ == "__main__":
    unittest.main()
