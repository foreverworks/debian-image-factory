"""An installer kit's checks that read files: the newc reader, kit.json against the kit's members, the
initrd scan, and the kit's SBOM subjects."""

import gzip
import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from debian_image_factory.checks import kit, newc
from debian_image_factory.checks.tarball import Member
from tests.support import newc as writer

EPOCH = 1754697600
KERNEL = "6.12.0-1-amd64"


def kit_bytes(
    vmlinuz: bytes = b"kernel",
    initrd: bytes | None = None,
    *,
    manifest: bytes | None = None,
    order: tuple[str, ...] = kit.MEMBERS,
) -> bytes:
    initrd = (
        initrd
        if initrd is not None
        else writer.initrd([writer.directory("."), writer.file("etc/os-release", b"ID=debian\n")])
    )
    files = {
        name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        for name, data in (("vmlinuz", vmlinuz), ("initrd.img", initrd))
    }
    document = {"schema": 1, "image": "installer", "kernel": KERNEL, "files": files}
    text = manifest if manifest is not None else kit.canonical(document)
    contents = {"kit.json": text, "vmlinuz": vmlinuz, "initrd.img": initrd}
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in order:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(contents[name]), 0o644, EPOCH
            archive.addfile(info, io.BytesIO(contents[name]))
    return raw.getvalue()


class NewcTest(unittest.TestCase):
    def read(self, items: list[writer.Item]) -> list[tuple[str, Member, bytes]]:
        stream = io.BytesIO(writer.archive(items))
        return [(name, member, b"".join(data)) for name, member, data in newc.entries(stream.read)]

    def test_members_come_back_with_their_kinds_targets_and_data(self) -> None:
        found = self.read(
            [
                writer.directory("."),
                writer.symlink("init", "/sbin/init"),
                writer.directory("etc"),
                writer.file("etc/machine-id", b"uninitialized\n"),
            ]
        )
        self.assertEqual(
            [(member.path, member.kind, member.target, data) for _, member, data in found],
            [
                ("/", "dir", "", b""),
                ("/init", "symlink", "/sbin/init", b""),
                ("/etc", "dir", "", b""),
                ("/etc/machine-id", "file", "", b"uninitialized\n"),
            ],
        )

    def test_a_second_name_of_an_inode_is_a_hard_link_to_the_first(self) -> None:
        mode = 0o100644
        found = self.read(
            [writer.Item("bin/a", mode, b"same", ino=7, nlink=2), writer.Item("bin/b", mode, b"", ino=7, nlink=2)]
        )
        self.assertEqual([m.kind for _, m, _ in found], ["file", "hardlink"])
        self.assertEqual(found[1][1].target, "/bin/a")

    def test_unread_data_is_skipped(self) -> None:
        stream = io.BytesIO(writer.archive([writer.file("a", b"x" * 100_000), writer.file("b", b"y")]))
        paths = [member.path for _, member, _ in newc.entries(stream.read)]
        self.assertEqual(paths, ["/a", "/b"])

    def test_a_truncated_archive_or_a_bad_magic_is_refused(self) -> None:
        data = writer.archive([writer.file("a", b"abc")])
        with self.assertRaises(newc.NewcError):
            list(newc.entries(io.BytesIO(data[:120]).read))
        with self.assertRaises(newc.NewcError):
            list(newc.entries(io.BytesIO(b"070702" + data[6:]).read))


class KitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, data: bytes) -> Path:
        path = Path(self.tmp.name) / "installer.tar"
        path.write_bytes(data)
        return path

    def test_a_good_kit_has_no_problems_and_names_its_kernel(self) -> None:
        read = kit.read_kit(self.write(kit_bytes()))
        self.assertEqual((read.kernel, read.problems), (KERNEL, ()))
        self.assertEqual(read.files["vmlinuz"], (hashlib.sha256(b"kernel").hexdigest(), 6))

    def test_a_file_that_differs_from_kit_json_is_named(self) -> None:
        initrd = writer.initrd([writer.directory(".")])
        document = {
            "schema": 1,
            "image": "installer",
            "kernel": KERNEL,
            "files": {
                "vmlinuz": {"sha256": "00" * 32, "size": 6},
                "initrd.img": {"sha256": hashlib.sha256(initrd).hexdigest(), "size": 1},
            },
        }
        read = kit.read_kit(self.write(kit_bytes(initrd=initrd, manifest=kit.canonical(document))))
        self.assertEqual(len(read.problems), 2)
        self.assertIn("vmlinuz has sha256 " + "00" * 32, read.problems[0])
        self.assertIn(f"initrd.img is 1 bytes, it is {len(initrd)}", read.problems[1])

    def test_members_out_of_order_and_a_kit_json_that_is_not_canonical_are_named(self) -> None:
        read = kit.read_kit(self.write(kit_bytes(order=("vmlinuz", "kit.json", "initrd.img"))))
        self.assertIn("not kit.json, vmlinuz, initrd.img in that order", read.problems[0])
        spaced = kit.read_kit(self.write(kit_bytes(manifest=b'{"schema": 1}\n')))
        self.assertTrue(any("not canonical" in problem for problem in spaced.problems))
        self.assertIsNone(spaced.kernel)

    def test_the_initrd_is_scanned_and_kit_json_searched_for_the_snapshot(self) -> None:
        initrd = writer.initrd(
            [
                writer.directory("."),
                writer.directory("etc"),
                writer.file("etc/machine-id", b"uninitialized\n"),
                writer.file(
                    "etc/apt/sources.list",
                    b"deb http://snapshot.debian.org/archive/debian/20261101T000000Z/ trixie main\n",
                ),
            ]
        )
        path = self.write(kit_bytes(initrd=initrd))
        scanned = kit.scan_kit(path, frozenset({"/etc/machine-id"}), "20261101T000000Z", True)
        self.assertEqual(scanned.contents, {"/etc/machine-id": b"uninitialized\n"})
        self.assertEqual([(hit.where, hit.path) for hit in scanned.needle_hits], [("content", "/etc/apt/sources.list")])
        self.assertIn("/etc", [member.path for member in scanned.members])

    def test_a_kit_whose_initrd_is_not_gzip_newc_cannot_be_scanned(self) -> None:
        path = self.write(kit_bytes(initrd=gzip.compress(b"not an archive")))
        with self.assertRaises(newc.NewcError):
            kit.scan_kit(path, frozenset(), None, False)

    def test_the_subjects_are_the_kit_then_its_kernel_and_initrd(self) -> None:
        read = kit.read_kit(self.write(kit_bytes()))
        vmlinuz, initrd = read.files["vmlinuz"][0], read.files["initrd.img"][0]
        good = [("installer.tar", "aa" * 32), ("vmlinuz", vmlinuz), ("initrd.img", initrd)]
        self.assertEqual(kit.subjects_problems(good, "installer.tar", "aa" * 32, read), [])
        swapped = [good[0], good[2], good[1]]
        self.assertEqual(len(kit.subjects_problems(swapped, "installer.tar", "aa" * 32, read)), 1)
        self.assertEqual(len(kit.subjects_problems(good[:1], "installer.tar", "aa" * 32, read)), 1)


if __name__ == "__main__":
    unittest.main()
