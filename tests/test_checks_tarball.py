"""Reading a root filesystem tarball in a streaming pass."""

import tarfile
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

from debian_image_factory.checks import tarball
from debian_image_factory.checks.tarball import Hit, Member
from tests.support.rootfs import Entry, Link, rootfs

NEEDLE = "20261121T004329Z"
KEY = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n"


class ScanTest(unittest.TestCase):
    def scan(
        self,
        entries: Mapping[str, Entry],
        wanted: frozenset[str] = frozenset(),
        needle: str | tuple[str, ...] | None = None,
        keys: bool = False,
    ) -> tarball.Scan:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "core.tar.gz"
            path.write_bytes(rootfs(entries))
            return tarball.scan_tarball(path, wanted, needle, keys)

    def test_members_are_absolute_and_typed(self) -> None:
        found = self.scan(
            {
                "./": None,
                "./etc/": None,
                "./etc/a": b"x",
                "./bin/sh": Link("dash"),
                "./etc/b": Link("./etc/a", hard=True),
            }
        )
        self.assertEqual(
            found.members,
            (
                Member("/", "dir"),
                Member("/etc", "dir"),
                Member("/etc/a", "file"),
                Member("/bin/sh", "symlink", "dash"),
                Member("/etc/b", "hardlink", "./etc/a"),
            ),
        )

    def test_several_needles_are_each_searched_in_paths_targets_and_content(self) -> None:
        other = "20261123T141315Z"
        found = self.scan(
            {
                f"./a/{NEEDLE}": b"x",
                "./b": Link(f"/x/{other}"),
                "./c": f"see {other} here".encode(),
                "./d": b"nothing",
            },
            needle=(NEEDLE, other),
        )
        self.assertEqual(
            [(hit.where, hit.path) for hit in found.needle_hits],
            [("path", f"/a/{NEEDLE}"), ("link target", "/b"), ("content", "/c")],
        )

    def test_one_of_two_needles_absent_finds_the_other_only(self) -> None:
        found = self.scan({"./c": f"see {NEEDLE} here".encode()}, needle=("20261123T141315Z", NEEDLE))
        self.assertEqual([hit.path for hit in found.needle_hits], ["/c"])
        self.assertEqual(self.scan({"./c": b"none"}, needle=(NEEDLE, "20261123T141315Z")).needle_hits, ())

    def test_wanted_contents_are_kept_whole_and_others_are_not(self) -> None:
        found = self.scan(
            {"./etc/a": b"one", "./etc/b": b"two", "./etc/c": Link("a")}, wanted=frozenset(("/etc/a", "/etc/c"))
        )
        self.assertEqual(found.contents, {"/etc/a": b"one"})

    def test_private_keys_are_found_in_plain_files_wherever_they_are(self) -> None:
        found = self.scan(
            {
                "./root/id": KEY,
                "./etc/notes": b"no key here",
                "./usr/share/doc/ssh/example": KEY,
                "./usr/share/man/man1/ssh.1": KEY,
                "./usr/share/info/ssh.info": KEY,
                "./srv/key": b"text\n" + KEY,
            },
            keys=True,
        )
        self.assertEqual(
            found.key_files,
            (
                "/root/id",
                "/srv/key",
                "/usr/share/doc/ssh/example",
                "/usr/share/info/ssh.info",
                "/usr/share/man/man1/ssh.1",
            ),
        )

    def test_only_compressed_documentation_is_exempt(self) -> None:
        exempt = {
            f"./usr/share/{tree}/pkg/file{suffix}": KEY
            for tree in ("doc", "man", "info")
            for suffix in (".gz", ".bz2", ".xz", ".zst")
        }
        self.assertEqual(self.scan(exempt, keys=True).key_files, ())
        near = {
            "./usr/share/doc/pkg/file.gz.txt": KEY,
            "./usr/share/docs/pkg/file.gz": KEY,
            "./usr/share/doc/x.GZ": KEY,
        }
        self.assertEqual(
            self.scan(near, keys=True).key_files,
            ("/usr/share/doc/pkg/file.gz.txt", "/usr/share/doc/x.GZ", "/usr/share/docs/pkg/file.gz"),
        )

    def test_tokens_are_named_by_file_and_kind_with_a_redacted_form(self) -> None:
        token = b"gh" + b"p_" + b"aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5"
        found = self.scan(
            {
                "./root/.netrc": b"password " + token + b"\n",
                "./usr/share/doc/x/notes": token,
                "./usr/share/doc/x.gz": token,
            },
            keys=True,
        )
        self.assertEqual(
            found.key_files,
            (
                "/root/.netrc (GitHub token: ghp_…(40 characters))",
                "/usr/share/doc/x/notes (GitHub token: ghp_…(40 characters))",
            ),
        )
        self.assertNotIn(token.decode()[5:], " ".join(found.key_files))

    def test_a_key_and_a_token_in_one_file_are_two_entries(self) -> None:
        token = b"npm" + b"_" + b"aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5"
        found = self.scan({"./root/both": KEY + token}, keys=True)
        self.assertEqual(len(found.key_files), 2)

    def test_keys_are_not_searched_when_not_asked_for(self) -> None:
        self.assertEqual(self.scan({"./root/id": KEY}).key_files, ())

    def test_needle_in_a_path_a_link_target_and_content(self) -> None:
        found = self.scan(
            {
                f"./var/{NEEDLE}/x": b"",
                "./etc/link": Link(f"/mnt/{NEEDLE}"),
                "./etc/hard": Link(f"./{NEEDLE}", hard=True),
                "./etc/apt/sources": f"deb file:/{NEEDLE}\n".encode(),
                "./etc/clean": b"nothing",
            },
            needle=NEEDLE,
        )
        self.assertEqual(
            found.needle_hits,
            (
                Hit("path", f"/var/{NEEDLE}/x"),
                Hit("link target", "/etc/link"),
                Hit("link target", "/etc/hard"),
                Hit("content", "/etc/apt/sources"),
            ),
        )

    def test_needle_across_the_64_kib_read_boundary(self) -> None:
        data = b"a" * (tarball.CHUNK - 7) + NEEDLE.encode() + b"b" * 50
        found = self.scan({"./big": data, "./small": b"x"}, needle=NEEDLE)
        self.assertEqual(found.needle_hits, (Hit("content", "/big"),))

    def test_needle_in_a_wanted_file_and_in_a_long_path(self) -> None:
        found = self.scan({"./etc/a": b"x " + NEEDLE.encode()}, wanted=frozenset(("/etc/a",)), needle=NEEDLE)
        self.assertEqual(found.needle_hits, (Hit("content", "/etc/a"),))
        long = "./" + "d/" * 80 + NEEDLE
        self.assertEqual(self.scan({long: b""}, needle=NEEDLE).needle_hits[0].where, "path")

    def test_hits_are_limited(self) -> None:
        found = self.scan({f"./{NEEDLE}{n}": b"" for n in range(50)}, needle=NEEDLE)
        self.assertEqual(len(found.needle_hits), tarball.HITS_LIMIT)

    def test_a_file_that_is_not_a_tarball(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "core.tar.gz"
            path.write_bytes(b"not a tarball at all")
            with self.assertRaises((tarfile.TarError, EOFError, OSError)):
                tarball.scan_tarball(path, frozenset(), None, False)
