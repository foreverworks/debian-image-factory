"""Layers merged into one filesystem: whiteouts, opaque directories, replaced directories, hidden secrets."""

import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

from debian_image_factory.checks import layers, tarball
from debian_image_factory.checks.tarball import Member
from tests.support.rootfs import Entry, Link, rootfs

KEY = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n"
NEEDLE = "20261121T004329Z"


def scan(
    stack: Sequence[Mapping[str, Entry]],
    wanted: frozenset[str] = frozenset(),
    needle: str | None = None,
    keys: bool = False,
) -> tarball.Scan:
    with tempfile.TemporaryDirectory() as tmp:
        paths: list[Path] = []
        for position, entries in enumerate(stack):
            paths.append(Path(tmp) / f"{position}.tar.gz")
            paths[-1].write_bytes(rootfs(entries))
        return layers.scan_image(paths, wanted, needle, keys)


def paths_of(found: tarball.Scan) -> list[str]:
    return sorted(member.path for member in found.members)


class WhiteoutTest(unittest.TestCase):
    def test_a_later_layer_adds_and_replaces(self) -> None:
        found = scan([{"./etc/": None, "./etc/a": b"1"}, {"./etc/b": b"2", "./etc/a": b"3"}], frozenset(("/etc/a",)))
        self.assertEqual(paths_of(found), ["/etc", "/etc/a", "/etc/b"])
        self.assertEqual(found.contents, {"/etc/a": b"3"})

    def test_a_whiteout_removes_the_file_and_is_not_itself_a_member(self) -> None:
        found = scan(
            [{"./etc/": None, "./etc/hostname": b"box"}, {"./etc/.wh.hostname": b""}], frozenset(("/etc/hostname",))
        )
        self.assertEqual(paths_of(found), ["/etc"])
        self.assertEqual(found.contents, {})

    def test_a_whiteout_removes_a_directory_with_everything_in_it(self) -> None:
        base = {
            "./var/": None,
            "./var/lib/": None,
            "./var/lib/apt/": None,
            "./var/lib/apt/lists/": None,
            "./var/lib/apt/lists/x": b"1",
            "./var/log": b"",
        }
        found = scan([base, {"./var/lib/.wh.apt": b""}])
        self.assertEqual(paths_of(found), ["/var", "/var/lib", "/var/log"])

    def test_a_whiteout_does_not_touch_a_sibling_with_the_same_prefix(self) -> None:
        found = scan([{"./d/": None, "./d/ab": b"", "./d/abc": b""}, {"./d/.wh.ab": b""}])
        self.assertEqual(paths_of(found), ["/d", "/d/abc"])

    def test_an_opaque_directory_empties_the_layers_below_and_keeps_its_own_entries(self) -> None:
        lower = {"./data/": None, "./data/old": b"1", "./data/sub/": None, "./data/sub/old": b"2", "./keep": b""}
        upper = {"./data/": None, "./data/.wh..wh..opq": b"", "./data/new": b"3"}
        self.assertEqual(paths_of(scan([lower, upper])), ["/data", "/data/new", "/keep"])

    def test_a_whiteout_in_a_layer_hides_only_lower_layers(self) -> None:
        found = scan([{"./a": b"1"}, {"./a": b"2", "./.wh.a": b""}])
        self.assertEqual(paths_of(found), ["/a"])

    def test_the_spec_s_reserved_names_are_not_files(self) -> None:
        found = scan([{"./a": b"1", "./.wh..wh.plnk": b""}])
        self.assertEqual(paths_of(found), ["/a"])

    def test_a_file_replaces_a_directory_and_what_it_held(self) -> None:
        found = scan([{"./x/": None, "./x/y": b"1"}, {"./x": b"now a file"}])
        self.assertEqual(found.members, (Member("/x", "file"),))

    def test_a_directory_replaces_a_file_and_a_link_replaces_content(self) -> None:
        wanted = frozenset(("/a", "/b"))
        found = scan([{"./a": b"1", "./b": b"2"}, {"./a/": None, "./b": Link("a")}], wanted)
        self.assertEqual(sorted((m.path, m.kind) for m in found.members), [("/a", "dir"), ("/b", "symlink")])
        self.assertEqual(found.contents, {})

    def test_the_content_comes_from_the_layer_that_wins_and_goes_with_a_whiteout(self) -> None:
        wanted = frozenset(("/etc/machine-id",))
        layer = {"./etc/": None, "./etc/machine-id": b"abc\n"}
        self.assertEqual(scan([layer, {"./etc/machine-id": b""}], wanted).contents, {"/etc/machine-id": b""})
        self.assertEqual(scan([layer, {"./etc/.wh.machine-id": b""}], wanted).contents, {})
        self.assertEqual(
            scan([layer, {"./etc/.wh.machine-id": b""}, {"./etc/machine-id": b"z"}], wanted).contents,
            {"/etc/machine-id": b"z"},
        )

    def test_names_are_normalised_like_core(self) -> None:
        self.assertEqual(paths_of(scan([{"./": None, "./a": b""}])), ["/", "/a"])


class HiddenTest(unittest.TestCase):
    def test_a_key_a_later_layer_deletes_is_still_found(self) -> None:
        found = scan([{"./root/": None, "./root/id": KEY}, {"./root/.wh.id": b""}], keys=True)
        self.assertEqual(paths_of(found), ["/root"])
        self.assertEqual(found.key_files, ("/root/id",))

    def test_keys_of_every_layer_are_listed_once_and_sorted(self) -> None:
        found = scan([{"./b": KEY, "./a": KEY}, {"./b": KEY}], keys=True)
        self.assertEqual(found.key_files, ("/a", "/b"))

    def test_documentation_trees_are_still_skipped(self) -> None:
        self.assertEqual(scan([{"./usr/share/doc/x/example": KEY}], keys=True).key_files, ())

    def test_the_needle_in_a_deleted_file_is_still_a_hit_and_hits_are_in_layer_order(self) -> None:
        found = scan([{"./a": NEEDLE.encode()}, {"./.wh.a": b"", "./b": NEEDLE.encode()}], needle=NEEDLE)
        self.assertEqual([hit.path for hit in found.needle_hits], ["/a", "/b"])

    def test_no_keys_asked_none_looked_for(self) -> None:
        self.assertEqual(scan([{"./a": KEY}]).key_files, ())


class StreamTest(unittest.TestCase):
    def test_layers_are_read_one_at_a_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "1.tar.gz"
            first.write_bytes(rootfs({"./a": b"1"}))
            missing = Path(tmp) / "2.tar.gz"
            iterator = layers.scan_layers([first, missing], frozenset(), None, False)
            self.assertEqual([m.path for m in next(iterator).members], ["/a"])
            with self.assertRaises(OSError):
                next(iterator)


if __name__ == "__main__":
    unittest.main()
