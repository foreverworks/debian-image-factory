"""The layer writer (build/layer.py) on small trees, as an ordinary user: unpacking a parent's layers with
their whiteouts, recording its state, and writing the one layer that turns it into the changed tree."""

import gzip
import hashlib
import io
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from debian_image_factory.build import layer

EPOCH = 1754697600
UID, GID = os.getuid(), os.getgid()


def info(name: str, kind: bytes = tarfile.REGTYPE, mode: int = 0o644, mtime: int = EPOCH - 1000) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.type, member.mode, member.mtime, member.uid, member.gid = kind, mode, mtime, UID, GID
    return member


def write_layer(path: Path, members: list[tuple[tarfile.TarInfo, bytes]]) -> None:
    with tarfile.open(path, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for member, data in members:
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data) if data else None)


def directory(name: str, mode: int = 0o755) -> tuple[tarfile.TarInfo, bytes]:
    return info(name, tarfile.DIRTYPE, mode), b""


def regular(name: str, data: bytes, mode: int = 0o644) -> tuple[tarfile.TarInfo, bytes]:
    return info(name, mode=mode), data


def symlink(name: str, target: str) -> tuple[tarfile.TarInfo, bytes]:
    member = info(name, tarfile.SYMTYPE, 0o777)
    member.linkname = target
    return member, b""


def hardlink(name: str, target: str) -> tuple[tarfile.TarInfo, bytes]:
    member = info(name, tarfile.LNKTYPE)
    member.linkname = target
    return member, b""


def tar_members(path: Path) -> list[tarfile.TarInfo]:
    with tarfile.open(path, mode="r:gz") as archive:
        return archive.getmembers()


class Fixture(unittest.TestCase):
    """A scratch directory with a parent unpacked into `root` and its state in `state`."""

    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="layer-test-")
        self.addCleanup(self.scratch.cleanup)
        self.dir = Path(self.scratch.name)
        self.root = self.dir / "root"
        self.root.mkdir()
        self.state = self.dir / "state.json"

    def unpack(self, *layers: Path, root: Path | None = None) -> dict[str, layer.Entry]:
        entries, _ = layer.unpack(str(root or self.root), [str(one) for one in layers], EPOCH)
        return entries

    def parent(self, members: list[tuple[tarfile.TarInfo, bytes]]) -> Path:
        path = self.dir / "parent.tar.gz"
        write_layer(path, members)
        self.state.write_text(layer.state_json(self.unpack(path)))
        return path

    def pack(self, name: str = "layer") -> tuple[Path, Path, int]:
        out, diff_id = self.dir / f"{name}.tar.gz", self.dir / f"{name}.diff_id"
        count = layer.pack(str(self.root), str(self.state), EPOCH, str(out), str(diff_id), None)
        return out, diff_id, count


class UnpackTest(Fixture):
    def test_unpacks_files_links_modes_and_times(self) -> None:
        self.parent(
            [
                directory("etc", 0o750),
                regular("etc/passwd", b"root\n", 0o640),
                regular("bin-tool", b"#!/bin/sh\n", 0o755),
                symlink("etc/alias", "passwd"),
                hardlink("etc/passwd-copy", "etc/passwd"),
            ]
        )
        self.assertEqual((self.root / "etc/passwd").read_bytes(), b"root\n")
        self.assertEqual(stat.S_IMODE((self.root / "etc").stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((self.root / "bin-tool").stat().st_mode), 0o755)
        self.assertEqual(os.readlink(self.root / "etc/alias"), "passwd")
        self.assertEqual((self.root / "etc/passwd").stat().st_ino, (self.root / "etc/passwd-copy").stat().st_ino)
        self.assertEqual(int((self.root / "etc/passwd").stat().st_mtime), EPOCH - 1000)
        self.assertEqual(int((self.root / "etc").stat().st_mtime), EPOCH - 1000, "a directory's time is set last")

    def test_a_later_layer_replaces_whiteouts_and_empties(self) -> None:
        first = self.dir / "first.tar.gz"
        write_layer(
            first,
            [
                directory("a"),
                regular("a/keep", b"1"),
                regular("a/gone", b"2"),
                directory("opaque"),
                regular("opaque/old", b"3"),
                directory("tree"),
                regular("tree/leaf", b"4"),
                regular("file", b"before"),
            ],
        )
        second = self.dir / "second.tar.gz"
        write_layer(
            second,
            [
                regular("a/.wh.gone", b""),
                regular("opaque/new", b"5"),
                regular("opaque/.wh..wh..opq", b""),
                regular(".wh.tree", b""),
                regular("file", b"after"),
            ],
        )
        entries = self.unpack(first, second)
        self.assertEqual(sorted(entries), ["a", "a/keep", "file", "opaque", "opaque/new"])
        self.assertEqual((self.root / "file").read_bytes(), b"after")

    def test_a_device_node_the_kernel_refuses_stays_in_the_state_as_absent(self) -> None:
        device = info("dev-null", tarfile.CHRTYPE, 0o666)
        device.devmajor, device.devminor = 1, 3
        self.parent([(device, b"")])
        entries = layer.read_state(str(self.dir / "state.json"))
        if (self.root / "dev-null").exists():
            self.assertFalse(entries["dev-null"].absent)  # running as root: the node was made
        else:
            self.assertTrue(entries["dev-null"].absent)
            self.assertEqual((entries["dev-null"].major, entries["dev-null"].minor), (1, 3))
            self.assertEqual(self.pack()[2], 0, "an absent device is not a removed one")

    def test_a_layer_cannot_leave_the_root(self) -> None:
        escape = self.dir / "escape.tar.gz"
        write_layer(escape, [(info("../outside"), b"x")])
        with self.assertRaisesRegex(layer.LayerError, r"\.\."):
            self.unpack(escape)
        sneaky = self.dir / "sneaky.tar.gz"
        write_layer(sneaky, [symlink("lib", "/etc"), regular("lib/passwd", b"x")])
        other = self.dir / "other"
        other.mkdir()
        with self.assertRaisesRegex(layer.LayerError, "leaves the root"):
            self.unpack(sneaky, root=other)

    def test_xattrs_are_restored_when_the_file_system_takes_them(self) -> None:
        probe = self.dir / "probe"
        probe.write_bytes(b"")
        try:
            os.setxattr(probe, "user.x", b"1")
        except OSError:
            self.skipTest("this file system keeps no user xattrs")
        member = info("tagged")
        member.pax_headers = {layer.XATTR_PREFIX + "user.factory": "yes"}
        self.parent([(member, b"x")])
        self.assertEqual(os.getxattr(self.root / "tagged", "user.factory"), b"yes")


class StateTest(Fixture):
    def test_the_state_file_round_trips(self) -> None:
        entries = self.unpack_one()
        self.assertEqual(layer.read_state(str(self.state)), entries)

    def unpack_one(self) -> dict[str, layer.Entry]:
        self.parent([directory("d"), regular("d/f", b"data"), symlink("d/l", "f")])
        entries = layer.scan(str(self.root), EPOCH).entries
        self.assertEqual(entries["d/f"].sha256, hashlib.sha256(b"data").hexdigest())
        self.assertEqual(entries["d/l"].link, "f")
        return entries

    def test_mtimes_later_than_the_epoch_are_clamped(self) -> None:
        self.parent([regular("f", b"x")])
        os.utime(self.root / "f", (EPOCH + 5000, EPOCH + 5000))
        self.assertEqual(layer.scan(str(self.root), EPOCH).entries["f"].mtime, EPOCH)

    def test_a_malformed_state_file_is_refused(self) -> None:
        self.state.write_text('{"f": [1, 2]}')
        with self.assertRaisesRegex(layer.LayerError, "row of 12"):
            layer.read_state(str(self.state))


class PackTest(Fixture):
    def changed(self) -> list[tarfile.TarInfo]:
        out, _, count = self.pack()
        self.assertGreater(count, 0)
        return tar_members(out)

    def setUp(self) -> None:
        super().setUp()
        self.parent(
            [
                directory("etc"),
                regular("etc/os-release", b"ID=debian\n"),
                regular("etc/removed", b"bye\n"),
                directory("var"),
                directory("var/lib"),
                regular("var/lib/status", b"old\n"),
                directory("usr"),
                directory("usr/share"),
                regular("usr/share/a", b"a"),
                regular("usr/share/b", b"b"),
                directory("untouched"),
                regular("untouched/f", b"f"),
            ]
        )

    def test_nothing_changed_writes_no_layer(self) -> None:
        out, diff_id, count = self.pack()
        self.assertEqual(count, 0)
        self.assertFalse(out.exists() or diff_id.exists())

    def test_new_changed_and_removed_paths_in_tar_order(self) -> None:
        (self.root / "etc/os-release").write_bytes(b"ID=debian\nVERSION_ID=13\n")
        os.utime(self.root / "etc/os-release", (EPOCH - 10, EPOCH - 10))
        (self.root / "etc/removed").unlink()
        os.symlink("os-release", self.root / "etc/os-release.link")
        (self.root / "usr/share/new").write_bytes(b"new")
        for name in ("usr/share/a", "usr/share/b"):
            os.unlink(self.root / name)
        members = self.changed()
        names = [member.name for member in members]
        self.assertEqual(
            names,
            [
                "etc",
                "etc/os-release",
                "etc/os-release.link",
                "etc/.wh.removed",
                "usr/share",
                "usr/share/.wh.a",
                "usr/share/.wh.b",
                "usr/share/new",
            ],
        )
        by_name = {member.name: member for member in members}
        self.assertEqual(by_name["etc/os-release"].size, len(b"ID=debian\nVERSION_ID=13\n"))
        self.assertEqual(by_name["etc/os-release"].mtime, EPOCH - 10)
        self.assertEqual(by_name["usr/share/new"].mtime, EPOCH, "a new file's time is clamped to the epoch")
        self.assertTrue(by_name["etc/os-release.link"].issym())
        self.assertEqual(by_name["etc/os-release.link"].linkname, "os-release")
        self.assertTrue(by_name["etc/.wh.removed"].isreg())
        self.assertEqual(by_name["etc/.wh.removed"].size, 0)

    def test_a_removed_directory_gets_one_whiteout_and_no_children(self) -> None:
        for name in ("untouched/f", "untouched"):
            path = self.root / name
            path.rmdir() if path.is_dir() else path.unlink()
        self.assertEqual([member.name for member in self.changed()], [".wh.untouched"])

    def test_a_directory_is_in_the_layer_only_when_its_own_state_changed(self) -> None:
        (self.root / "var/lib/status").write_bytes(b"new\n")
        os.utime(self.root / "var/lib/status", (EPOCH - 5, EPOCH - 5))
        self.assertEqual([member.name for member in self.changed()], ["var/lib/status"])
        os.chmod(self.root / "untouched", 0o700)
        names = [member.name for member in tar_members(self.pack("again")[0])]
        self.assertEqual(names, ["untouched", "var/lib/status"])

    def test_a_new_directory_comes_before_its_children(self) -> None:
        (self.root / "opt/x").mkdir(parents=True)
        (self.root / "opt/x/f").write_bytes(b"1")
        (self.root / "opt/y").write_bytes(b"2")
        self.assertEqual([member.name for member in self.changed()], ["opt", "opt/x", "opt/x/f", "opt/y"])

    def test_paths_that_share_an_inode_stay_hard_links(self) -> None:
        (self.root / "opt").mkdir()
        (self.root / "opt/one").write_bytes(b"shared")
        os.link(self.root / "opt/one", self.root / "opt/two")
        os.link(self.root / "opt/one", self.root / "opt/three")
        members = {member.name: member for member in self.changed()}
        self.assertTrue(members["opt/one"].isreg())
        self.assertEqual(members["opt/one"].size, len(b"shared"))
        for name in ("opt/two", "opt/three"):
            self.assertTrue(members[name].islnk())
            self.assertEqual(members[name].linkname, "opt/one")
            self.assertEqual(members[name].size, 0)

    def test_a_new_link_to_an_unchanged_file_is_a_copy(self) -> None:
        os.link(self.root / "usr/share/a", self.root / "usr/share/a2")
        members = {member.name: member for member in self.changed()}
        self.assertEqual(list(members), ["usr/share", "usr/share/a2"])
        self.assertTrue(members["usr/share/a2"].isreg())

    def test_the_tar_is_pax_with_numeric_owners_and_no_names_or_extra_times(self) -> None:
        (self.root / "new").write_bytes(b"x")
        out, _, _ = self.pack()
        with gzip.open(out) as handle:
            raw = handle.read()
        self.assertEqual(raw[257:263], b"ustar\x00", "a ustar header")
        self.assertNotIn(b"atime", raw)
        self.assertNotIn(b"ctime", raw)
        (member,) = tar_members(out)
        self.assertEqual((member.uname, member.gname), ("", ""))
        self.assertEqual((member.uid, member.gid), (UID, GID))
        self.assertEqual(member.pax_headers, {})

    def test_gzip_header_has_no_name_and_no_time(self) -> None:
        (self.root / "new").write_bytes(b"x")
        out, _, _ = self.pack()
        header = out.read_bytes()[:10]
        # magic, deflate, no flags (no FNAME), mtime 0, level 9 (XFL 2), the OS byte Python writes
        self.assertEqual(header[:8], b"\x1f\x8b\x08\x00\x00\x00\x00\x00")
        self.assertEqual(header[8], 2)

    def test_diff_id_is_the_sha256_of_the_uncompressed_tar(self) -> None:
        (self.root / "new").write_bytes(b"x")
        out, diff_id, _ = self.pack()
        with gzip.open(out) as handle:
            self.assertEqual(diff_id.read_text().strip(), hashlib.sha256(handle.read()).hexdigest())

    def test_two_runs_write_the_same_bytes(self) -> None:
        (self.root / "new").write_bytes(b"x")
        os.symlink("new", self.root / "alias")
        first, _, _ = self.pack("one")
        second, _, _ = self.pack("two")
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_the_layer_applied_to_the_parent_gives_the_changed_tree(self) -> None:
        (self.root / "etc/os-release").write_bytes(b"ID=debian\nVERSION_ID=13\n")
        (self.root / "etc/removed").unlink()
        (self.root / "opt/deep").mkdir(parents=True)
        (self.root / "opt/deep/f").write_bytes(b"1")
        os.link(self.root / "opt/deep/f", self.root / "opt/deep/g")
        os.symlink("deep/f", self.root / "opt/link")
        for name in ("untouched/f", "untouched"):
            path = self.root / name
            path.rmdir() if path.is_dir() else path.unlink()
        out, _, _ = self.pack()
        rebuilt = self.dir / "rebuilt"
        rebuilt.mkdir()
        entries = self.unpack(self.dir / "parent.tar.gz", out, root=rebuilt)
        self.assertEqual(entries, layer.scan(str(self.root), EPOCH).entries)

    def test_a_status_file_is_copied_out_even_when_nothing_else_changed(self) -> None:
        (self.root / "var/lib/dpkg").mkdir(parents=True)
        (self.root / "var/lib/dpkg/status").write_bytes(b"Package: a\n")
        copy = self.dir / "status"
        out = self.dir / "layer.tar.gz"
        layer.pack(str(self.root), str(self.state), EPOCH, str(out), str(self.dir / "d"), str(copy))
        self.assertEqual(copy.read_bytes(), b"Package: a\n")

    def test_a_removed_name_that_became_a_directory_needs_no_whiteouts_below_it(self) -> None:
        (self.root / "etc/removed").unlink()
        (self.root / "etc/removed").mkdir()
        (self.root / "etc/removed/inner").write_bytes(b"1")
        names = [member.name for member in self.changed()]
        self.assertEqual(names, ["etc", "etc/removed", "etc/removed/inner"])

    def test_a_directory_replaced_by_a_file_replaces_everything_below_it(self) -> None:
        for name in ("untouched/f", "untouched"):
            path = self.root / name
            path.rmdir() if path.is_dir() else path.unlink()
        (self.root / "untouched").write_bytes(b"now a file")
        members = {member.name: member for member in self.changed()}
        self.assertEqual(list(members), ["untouched"])
        self.assertTrue(members["untouched"].isreg())

    def test_a_mount_left_under_the_root_is_an_error(self) -> None:
        real_lstat = os.lstat

        def other_device(path: str) -> os.stat_result:
            real = real_lstat(path)
            if path.endswith("/untouched"):
                fields = list(real)
                fields[2] = real.st_dev + 1  # st_dev
                return os.stat_result(fields)
            return real

        with (
            mock.patch.object(os, "lstat", new=other_device),
            self.assertRaisesRegex(layer.LayerError, "another file system"),
        ):
            layer.scan(str(self.root), EPOCH)


class CommandLineTest(Fixture):
    def test_unpack_then_pack_through_the_program_itself(self) -> None:
        first = self.dir / "first.tar.gz"
        write_layer(first, [directory("d"), regular("d/f", b"1")])
        program = Path(layer.__file__)

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, "-I", str(program), *args], capture_output=True, text=True, check=False
            )

        done = run("unpack", "--root", str(self.root), "--state", str(self.state), "--epoch", str(EPOCH), str(first))
        self.assertEqual(done.returncode, 0, done.stderr)
        (self.root / "d/g").write_bytes(b"2")
        out = self.dir / "layer.tar.gz"
        done = run(
            "pack", "--root", str(self.root), "--state", str(self.state), "--epoch", str(EPOCH),
            "--out", str(out), "--diff-id", str(self.dir / "diff"),
        )  # fmt: skip
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual([member.name for member in tar_members(out)], ["d", "d/g"])
        broken = run("pack", "--root", str(self.root), "--state", str(self.dir / "missing"), "--epoch", "1",
                     "--out", str(out), "--diff-id", str(self.dir / "diff"))  # fmt: skip
        self.assertEqual(broken.returncode, 1)


if __name__ == "__main__":
    unittest.main()
