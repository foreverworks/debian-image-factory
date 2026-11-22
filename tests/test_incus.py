import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from input_lock.records import PROVENANCE_PREDICATE, envelope, jsonl, provenance, statement, subject

from debian_image_factory import fileartifacts, incus
from debian_image_factory.published import DirTarget, Rejected, records_name_for
from debian_image_factory.targets import lookup

IDENTITY = "ab" * 32
EPOCH = 1754697600


def tarball() -> bytes:
    return incus.metadata_tarball(
        image="incus-base", suite="trixie", arch="amd64", identity=IDENTITY, source_date_epoch=EPOCH
    )


def write_image(directory: Path, rootfs: bytes = b"hsqs-root", image: str = "incus-base") -> incus.Names:
    meta = incus.metadata_tarball(image=image, suite="trixie", arch="amd64", identity=IDENTITY, source_date_epoch=EPOCH)
    fingerprint = hashlib.sha256(meta + rootfs).hexdigest()
    names = incus.names(image, "trixie", "amd64", IDENTITY, fingerprint)
    (directory / names.metadata).write_bytes(meta)
    (directory / names.rootfs).write_bytes(rootfs)
    record = statement(
        [
            subject(names.image, fingerprint),
            subject(names.metadata, hashlib.sha256(meta).hexdigest()),
            subject(names.rootfs, hashlib.sha256(rootfs).hexdigest()),
        ],
        PROVENANCE_PREDICATE,
        provenance(
            "https://example.com/build-type",
            {"image": image},
            [],
            "https://example.com/builder",
            internal_parameters={"identity": IDENTITY},
            metadata={"finishedOn": "2026-11-21T02:19:41Z"},
        ),
    )
    (directory / records_name_for(fingerprint)).write_text(jsonl([envelope(record)]), encoding="utf-8")
    return names


class MetadataTest(unittest.TestCase):
    def test_metadata_yaml_names_the_image_without_a_build_time(self) -> None:
        text = incus.metadata_yaml(
            image="incus-base", suite="trixie", arch="amd64", identity=IDENTITY, source_date_epoch=EPOCH
        )
        self.assertIn("architecture: x86_64\n", text)
        self.assertIn(f"creation_date: {EPOCH}\n", text)
        self.assertIn('  serial: "abababababababab"\n', text)
        self.assertIn('  description: "Debian 13 (trixie) incus-base"\n', text)
        for path, template, _ in incus.RENDERED:
            self.assertIn(f"  {path}:\n    when: [create, copy]\n    template: {template}\n", text)
        self.assertIn('      default: "#cloud-config\\n{}\\n"\n', text)

    def test_an_unknown_architecture_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            incus.metadata_yaml(image="x", suite="trixie", arch="mips", identity=IDENTITY, source_date_epoch=EPOCH)

    def test_the_tarball_is_the_same_bytes_every_time(self) -> None:
        self.assertEqual(tarball(), tarball())
        self.assertEqual(tarball()[4:8], b"\0\0\0\0")  # gzip's time stamp

    def test_the_tarball_holds_the_metadata_and_every_template(self) -> None:
        with tarfile.open(fileobj=io.BytesIO(tarball()), mode="r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            self.assertEqual(
                names, ["metadata.yaml", "templates", *(f"templates/{n}" for n in sorted(incus.TEMPLATES))]
            )
            self.assertTrue(all(m.mtime == EPOCH and m.uid == 0 and m.gid == 0 for m in members))
            handle = archive.extractfile("templates/cloud-init-user.tpl")
            assert handle is not None
            body = handle.read().decode()
        self.assertIn('config_get("cloud-init.user-data", "")', body)
        self.assertIn('config_get("user.user-data", properties.default)', body)
        self.assertEqual(set(incus.TEMPLATES), {template for _, template, _ in incus.RENDERED})

    def test_the_fingerprint_is_the_sha256_of_both_files_in_order(self) -> None:
        self.assertEqual(incus.fingerprint([b"meta", b"root"]), hashlib.sha256(b"metaroot").hexdigest())

    def test_names_share_a_stem(self) -> None:
        names = incus.names("incus-base", "trixie", "amd64", IDENTITY, "cd" * 32)
        self.assertEqual(names.image, "incus-base-trixie-amd64-abababababababab-cdcdcdcdcdcd")
        self.assertEqual(names.metadata, names.image + ".incus.tar.gz")
        self.assertEqual(names.rootfs, names.image + ".rootfs.squashfs")
        self.assertEqual(incus.rootfs_of(names.metadata), names.rootfs)
        self.assertIsNone(incus.rootfs_of(names.rootfs))


class FileArtifactsTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def test_an_incus_image_is_one_artifact_of_two_files(self) -> None:
        names = write_image(self.dir)
        found, rejected = fileartifacts.file_artifacts(self.dir)
        self.assertEqual(rejected, [])
        self.assertEqual(
            [(one.name, [p.name for p in one.files]) for one in found],
            [(names.metadata, [names.metadata, names.rootfs])],
        )
        meta = (self.dir / names.metadata).read_bytes()
        self.assertEqual(found[0].digest, hashlib.sha256(meta + b"hsqs-root").hexdigest())

    def test_a_missing_or_changed_rootfs_is_rejected(self) -> None:
        names = write_image(self.dir)
        (self.dir / names.rootfs).write_bytes(b"other")
        _, rejected = fileartifacts.file_artifacts(self.dir)
        self.assertEqual([one.name for one in rejected], [names.metadata])
        self.assertIn("Incus fingerprint", rejected[0].reason)
        (self.dir / names.rootfs).unlink()
        _, rejected = fileartifacts.file_artifacts(self.dir)
        self.assertEqual(rejected, [Rejected(names.metadata, f"no rootfs {names.rootfs} beside it")])

    def test_a_dir_target_finds_an_incus_image_by_its_fingerprint(self) -> None:
        names = write_image(self.dir)
        got = lookup(DirTarget(str(self.dir)), "incus-base", "trixie", "amd64", IDENTITY)
        self.assertEqual(got.rejected, ())
        self.assertEqual([one.name for one in got.artifacts], [names.metadata])


if __name__ == "__main__":
    unittest.main()
