"""The squashfs reader and the scan of an Incus image's root filesystem, against images made by mksquashfs.

The images under tests/fixtures/squashfs come from scripts/make-squashfs-fixtures (squashfs-tools 4.6.1 as
Debian 13 ships it); each has a .json listing made from the source tree it was built from, so the reader is
compared with a view that never went through squashfs.
"""

import hashlib
import io
import json
import random
import struct
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from debian_image_factory import squashfs
from debian_image_factory.checks import squashfs_scan, tarball
from debian_image_factory.checks.tarball import Hit, Member
from debian_image_factory.squashfs import Entry, SquashfsError

FIXTURES = Path(__file__).parent / "fixtures" / "squashfs"
LISTED = ("tree-gzip", "tree-uncompressed", "bigblock", "bigdir", "xattrs", "xattrs-added", "scan")
NEEDLE = "20261121T004329Z"
KEY_FILES = ("/root/id", "/srv/key", "/usr/share/doc/ssh/example")


@dataclass(frozen=True, slots=True)
class Expected:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    mtime: int
    size: int
    nlink: int
    target: str
    major: int
    minor: int
    group: int | None
    sha256: str | None
    xattrs: list[list[str]]


def expected(name: str) -> list[Expected]:
    return [Expected(**item) for item in json.loads((FIXTURES / f"{name}.json").read_text())]


def image(name: str) -> bytes:
    return (FIXTURES / f"{name}.sqsh").read_bytes()


def listing(data: bytes) -> list[Entry]:
    return list(squashfs.entries(io.BytesIO(data)))


def content(data: bytes, entry: Entry) -> bytes:
    return b"".join(squashfs.read_file(io.BytesIO(data), entry))


def sha256(data: bytes, entry: Entry) -> str:
    digest = hashlib.sha256()
    for chunk in squashfs.read_file(io.BytesIO(data), entry):
        digest.update(chunk)
    return digest.hexdigest()


def patched(data: bytes, offset: int, fmt: str, value: int) -> bytes:
    return data[:offset] + struct.pack(fmt, value) + data[offset + struct.calcsize(fmt) :]


class ListingTest(unittest.TestCase):
    def test_every_fixture_lists_as_its_source_tree_did(self) -> None:
        for name in LISTED:
            with self.subTest(name):
                data = image(name)
                found = listing(data)
                want = expected(name)
                self.assertEqual([e.path for e in found], [w.path for w in want])
                for entry, wanted in zip(found, want, strict=True):
                    self.assertEqual(
                        (
                            entry.kind,
                            entry.mode,
                            entry.uid,
                            entry.gid,
                            entry.mtime,
                            entry.size,
                            entry.nlink,
                            entry.target,
                            entry.major,
                            entry.minor,
                            [[key, value.hex()] for key, value in entry.xattrs],
                        ),
                        (
                            wanted.kind,
                            wanted.mode,
                            wanted.uid,
                            wanted.gid,
                            wanted.mtime,
                            wanted.size,
                            wanted.nlink,
                            wanted.target,
                            wanted.major,
                            wanted.minor,
                            wanted.xattrs,
                        ),
                        entry.path,
                    )
                    if entry.kind == "file":
                        self.assertEqual(sha256(data, entry), wanted.sha256, entry.path)

    def test_the_root_comes_first_and_paths_are_absolute(self) -> None:
        found = listing(image("tree-gzip"))
        self.assertEqual(found[0].path, "/")
        self.assertEqual(found[0].kind, "dir")
        self.assertTrue(all(e.path.startswith("/") and (e.path == "/" or not e.path.endswith("/")) for e in found))
        paths = [e.path for e in found]
        self.assertLess(paths.index("/data"), paths.index("/data/block-exact.bin"))
        self.assertLess(paths.index("/data/with space"), paths.index("/dev"))

    def test_the_stored_order_is_depth_first_by_name(self) -> None:
        keys = [tuple(p.encode().split(b"/")[1:]) for p in (e.path for e in listing(image("bigdir")))]
        self.assertEqual(keys, sorted(keys))

    def test_hard_links_are_files_sharing_an_inode(self) -> None:
        for name in ("tree-gzip", "tree-uncompressed", "scan"):
            with self.subTest(name):
                inodes: dict[int, set[int]] = {}
                for entry, wanted in zip(listing(image(name)), expected(name), strict=True):
                    if wanted.group is not None:
                        self.assertEqual(entry.kind, "file")
                        self.assertGreater(entry.nlink, 1)
                        inodes.setdefault(wanted.group, set()).add(entry.inode)
                self.assertTrue(inodes)
                self.assertTrue(all(len(found) == 1 for found in inodes.values()))
                self.assertEqual(len({next(iter(found)) for found in inodes.values()}), len(inodes))

    def test_every_kind_is_found(self) -> None:
        kinds = {e.kind for e in listing(image("tree-gzip"))}
        self.assertEqual(kinds, {"file", "dir", "symlink", "char", "block", "fifo", "socket"})
        by_path = {e.path: e for e in listing(image("tree-gzip"))}
        self.assertEqual((by_path["/dev/wide"].major, by_path["/dev/wide"].minor), (259, 300))
        self.assertEqual(by_path["/link/relative"].target, "../data/text.txt")
        self.assertEqual(by_path["/owned/setuid"].mode, 0o4755)
        self.assertEqual(by_path["/owned/sticky"].mode, 0o1777)
        self.assertEqual((by_path["/owned/user-file"].uid, by_path["/owned/user-file"].gid), (1000, 2000))

    def test_xattrs_are_sorted_pairs_with_every_prefix_and_shared_values(self) -> None:
        by_path = {e.path: e for e in listing(image("xattrs"))}
        self.assertEqual(
            by_path["/f2"].xattrs,
            (("user.a", b"same-value"), ("user.b", b"same-value"), ("user.bin", b"\x00\xff\x10")),
        )
        self.assertEqual(by_path["/dir"].xattrs, (("user.dir", b"dirvalue"),))
        self.assertEqual(by_path["/f1"].xattrs, by_path["/f4"].xattrs)
        self.assertEqual(by_path["/dir/inside"].xattrs, ())
        added = {e.path: e for e in listing(image("xattrs-added"))}
        names = [name for name, _ in added["/dir/file"].xattrs]
        self.assertEqual(names, ["security.fixture", "trusted.fixture", "user.fixture"])

    def test_the_fixtures_cover_what_the_reader_must_handle(self) -> None:
        tree = listing(image("tree-gzip"))
        blocks = [e.blocks for e in tree if e.blocks is not None]
        words = [word for b in blocks for word in b.sizes]
        self.assertTrue(any(word & squashfs.UNCOMPRESSED_BLOCK for word in words), "a stored block")
        self.assertTrue(any(word and not word & squashfs.UNCOMPRESSED_BLOCK for word in words), "a gzip block")
        self.assertTrue(any(word == 0 for word in words), "a hole")
        self.assertTrue(any(b.fragment is not None for b in blocks), "a fragment")
        self.assertTrue(any(b.fragment is not None and b.sizes for b in blocks), "a tail after whole blocks")
        self.assertTrue(any(e.size == 4096 and e.blocks and e.blocks.fragment is None for e in tree), "one block")
        many = [e for e in listing(image("bigdir")) if e.listing is not None]
        self.assertTrue(any(e.listing and e.listing.size > squashfs.METADATA_SIZE for e in many))
        self.assertGreater(len([e for e in listing(image("bigdir")) if e.path.startswith("/entries/")]), 256)


class ContentTest(unittest.TestCase):
    def test_chunks_are_bounded_and_add_up(self) -> None:
        data = image("bigblock")
        by_path = {e.path: e for e in listing(data)}
        for path, size in (("/zeros.bin", 393221), ("/one-block.bin", 131072), ("/with-tail.bin", 150000)):
            chunks = list(squashfs.read_file(io.BytesIO(data), by_path[path]))
            self.assertEqual(sum(map(len, chunks)), size, path)
            self.assertLessEqual(max(map(len, chunks)), squashfs.CHUNK, path)
        zeros = b"".join(squashfs.read_file(io.BytesIO(data), by_path["/zeros.bin"]))
        self.assertEqual(zeros, bytes(393221))

    def test_reading_is_lazy(self) -> None:
        data = image("bigblock")
        entry = {e.path: e for e in listing(data)}["/zeros.bin"]
        chunks = squashfs.read_file(io.BytesIO(data), entry)
        self.assertEqual(len(next(chunks)), squashfs.CHUNK)

    def test_an_empty_file_has_no_chunks(self) -> None:
        by_path = {e.path: e for e in listing(image("tree-gzip"))}
        self.assertEqual(content(image("tree-gzip"), by_path["/data/empty"]), b"")
        self.assertEqual(content(image("tree-gzip"), by_path["/etc/machine-id"]), b"")

    def test_only_a_regular_file_has_content(self) -> None:
        data = image("tree-gzip")
        entry = {e.path: e for e in listing(data)}["/data"]
        with self.assertRaises(SquashfsError):
            content(data, entry)

    def test_small_files_share_a_fragment_and_still_read(self) -> None:
        data = image("tree-gzip")
        by_path = {e.path: e for e in listing(data)}
        self.assertEqual(content(data, by_path["/data/tiny-3"]), b"tiny file number 3\n")
        self.assertEqual(content(data, by_path["/data/tiny-1-hard"]), b"tiny file number 1\n")


class MalformedTest(unittest.TestCase):
    def refused(self, data: bytes, *words: str) -> None:
        with self.assertRaises(SquashfsError) as caught:
            listing(data)
        for word in words:
            self.assertIn(word, str(caught.exception))

    def test_it_is_a_value_error(self) -> None:
        self.assertTrue(issubclass(SquashfsError, ValueError))

    def test_not_an_image(self) -> None:
        self.refused(b"", "outside the image")
        self.refused(b"not a squashfs image at all" * 10, "magic")
        self.refused(b"hsqs", "outside the image")

    def test_bad_magic(self) -> None:
        self.refused(b"sqsh" + image("tree-gzip")[4:], "magic")

    def test_another_version(self) -> None:
        data = image("tree-gzip")
        self.refused(patched(data, 28, "<H", 3), "version 3.0")
        self.refused(patched(data, 30, "<H", 1), "version 4.1")

    def test_other_compressors_are_refused_by_name(self) -> None:
        data = image("tree-gzip")
        for number, name in ((2, "lzma"), (3, "lzo"), (4, "xz"), (5, "lz4"), (6, "zstd"), (9, "unknown")):
            with self.subTest(name):
                self.refused(patched(data, 20, "<H", number), name, "gzip")

    def test_a_bad_block_size(self) -> None:
        self.refused(patched(image("tree-gzip"), 12, "<I", 5000), "block size")

    def test_a_truncated_image_is_refused_wherever_it_is_cut(self) -> None:
        for name in ("tree-gzip", "bigdir", "xattrs"):
            data = image(name)
            (used,) = struct.unpack_from("<Q", data, 40)
            for cut in sorted({0, 1, 95, 96, 97, used // 2, used - 1, *range(100, used, 331)}):
                with self.subTest(name=name, cut=cut):
                    self.refused(data[:cut])

    def test_tables_pointing_outside_the_file(self) -> None:
        data = image("tree-gzip")
        for offset in (48, 56, 64, 72, 80):  # id, xattr, inode, directory and fragment tables
            with self.subTest(offset=offset):
                self.refused(patched(data, offset, "<Q", len(data) + 4096))

    def test_a_root_inode_outside_the_table(self) -> None:
        self.refused(patched(image("tree-gzip"), 32, "<Q", 0xFFFFFF << 16))

    def test_damaged_images_fail_cleanly_or_read(self) -> None:
        generator = random.Random(7)
        for name in ("tree-gzip", "tree-uncompressed", "bigdir", "xattrs", "scan"):
            data = image(name)
            (used,) = struct.unpack_from("<Q", data, 40)
            for _ in range(250):
                broken = bytearray(data)
                for _ in range(generator.choice((1, 1, 2, 8))):
                    broken[generator.randrange(used)] = generator.randrange(256)
                try:
                    handle = io.BytesIO(bytes(broken))
                    for entry in squashfs.entries(handle):
                        if entry.kind == "file":
                            for _chunk in squashfs.read_file(handle, entry):
                                pass
                except SquashfsError:
                    pass


class ScanTest(unittest.TestCase):
    def scan(
        self, wanted: frozenset[str] = frozenset(), needle: str | None = None, keys: bool = False, name: str = "scan"
    ) -> tarball.Scan:
        return squashfs_scan.scan_squashfs(FIXTURES / f"{name}.sqsh", wanted, needle, keys)

    def test_members_are_typed_like_a_tarballs(self) -> None:
        members = {m.path: m for m in self.scan().members}
        self.assertEqual(members["/"], Member("/", "dir"))
        self.assertEqual(members["/etc/alias"], Member("/etc/alias", "symlink", "hostname"))
        self.assertEqual(members["/etc/notes-hard"], Member("/etc/notes-hard", "file"))
        self.assertEqual({members[p].kind for p in ("/dev/fifo", "/dev/null", "/dev/loop0", "/dev/socket")}, {"other"})
        self.assertNotIn("hardlink", {m.kind for m in members.values()})
        paths = [m.path for m in self.scan().members]
        self.assertEqual(paths, [e.path for e in listing(image("scan"))])

    def test_wanted_contents_are_kept_whole_and_others_are_not(self) -> None:
        found = self.scan(wanted=frozenset(("/etc/machine-id", "/etc/alias", "/etc/missing", "/etc")))
        self.assertEqual(found.contents, {"/etc/machine-id": b"uninitialized\n"})

    def test_a_wanted_file_is_cut_at_the_limit(self) -> None:
        found = self.scan(wanted=frozenset(("/big/clean",)))
        self.assertEqual(len(found.contents["/big/clean"]), 200000)
        self.assertEqual(found.contents["/big/clean"][5:10], b"other")

    def test_private_keys_are_found_in_plain_files_but_not_in_compressed_documentation(self) -> None:
        self.assertEqual(self.scan(keys=True).key_files, KEY_FILES)

    def test_keys_are_not_searched_when_not_asked_for(self) -> None:
        self.assertEqual(self.scan().key_files, ())

    def test_needle_in_a_path_a_link_target_and_content(self) -> None:
        found = self.scan(needle=NEEDLE)
        self.assertEqual(
            found.needle_hits,
            (
                Hit("content", "/big/block-boundary"),
                Hit("content", "/big/chunk-boundary"),
                Hit("content", "/etc/apt/sources"),
                Hit("link target", "/etc/link"),
                Hit("path", f"/var/{NEEDLE}"),
                Hit("path", f"/var/{NEEDLE}/x"),
            ),
        )

    def test_needle_across_the_chunk_and_the_block_boundaries(self) -> None:
        paths = {hit.path for hit in self.scan(needle=NEEDLE).needle_hits}
        self.assertIn("/big/chunk-boundary", paths)
        self.assertIn("/big/block-boundary", paths)
        self.assertNotIn("/big/clean", paths)

    def test_needle_in_a_wanted_file(self) -> None:
        found = self.scan(wanted=frozenset(("/etc/apt/sources",)), needle=NEEDLE)
        self.assertIn(Hit("content", "/etc/apt/sources"), found.needle_hits)
        self.assertEqual(found.contents, {"/etc/apt/sources": f"deb file:/{NEEDLE}\n".encode()})

    def test_hits_are_limited(self) -> None:
        found = self.scan(needle="/", name="bigdir")
        self.assertEqual(len(found.needle_hits), tarball.HITS_LIMIT)

    def test_a_file_that_is_not_an_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rootfs.squashfs"
            path.write_bytes(b"not a squashfs image at all" * 8)
            with self.assertRaises(SquashfsError):
                squashfs_scan.scan_squashfs(path, frozenset(), None, False)
            path.write_bytes(image("scan")[:1500])
            with self.assertRaises(SquashfsError):
                squashfs_scan.scan_squashfs(path, frozenset(), NEEDLE, True)
            with self.assertRaises(OSError):
                squashfs_scan.scan_squashfs(Path(tmp) / "missing", frozenset(), None, False)

    def test_another_compressor_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rootfs.squashfs"
            path.write_bytes(patched(image("scan"), 20, "<H", 4))
            with self.assertRaisesRegex(SquashfsError, "xz"):
                squashfs_scan.scan_squashfs(path, frozenset(), None, False)


if __name__ == "__main__":
    unittest.main()
