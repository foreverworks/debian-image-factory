"""The kit writer and initrd reader (build/initrd.py) on small trees, as an ordinary user: the newc archive
byte for byte (order, inodes, hard links, symbolic links, devices, time stamps, /init), kit.json and the kit
tarball, reading both back, and unpacking an installer parent's initrd into a root."""

import gzip
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from debian_image_factory.build import initrd, layer

EPOCH = 1754697600
LATER = EPOCH + 86400
KERNEL = "6.12.99+deb13-amd64"


def make_root(root: Path) -> None:
    """A small root: a kernel, a hard-linked pair, a symbolic link, an empty directory, a fifo and dpkg's
    status, with time stamps after SOURCE_DATE_EPOCH."""
    for folder in ("boot", "usr/bin", "usr/sbin", "var/lib/dpkg", "empty"):
        (root / folder).mkdir(parents=True, exist_ok=True)
    (root / "boot" / f"vmlinuz-{KERNEL}").write_bytes(b"a kernel\n")
    (root / "usr" / "bin" / "perl").write_bytes(b"perl\n")
    os.link(root / "usr" / "bin" / "perl", root / "usr" / "bin" / "perl5.40")
    (root / "usr" / "bin" / "tool").write_bytes(b"#!/bin/sh\n")
    (root / "usr" / "bin" / "tool").chmod(0o755)
    (root / "usr" / "sbin" / "init").symlink_to("../lib/systemd/systemd")
    (root / "sbin").symlink_to("usr/sbin")
    os.mkfifo(root / "usr" / "fifo")
    (root / "var" / "lib" / "dpkg" / "status").write_bytes(b"Package: base-files\n")
    for path in [root, *root.rglob("*")]:
        os.utime(path, (LATER, LATER), follow_symlinks=False)


def gunzip(path: Path) -> bytes:
    return gzip.decompress(path.read_bytes())


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory(prefix="initrd-test-")
        self.addCleanup(scratch.cleanup)
        self.dir = Path(scratch.name)
        self.root = self.dir / "root"
        self.root.mkdir()
        make_root(self.root)

    def write(
        self, root: Path | None = None, name: str = "initrd.img", absent: dict[str, initrd.Absent] | None = None
    ) -> Path:
        target = self.dir / name
        initrd.write_initrd(str(root or self.root), absent or {}, EPOCH, str(target))
        return target

    def by_name(self, path: Path, contents: bool = True) -> dict[str, initrd.Member]:
        return {member.name: member for member in initrd.members(str(path), contents=contents)}


class WriterTest(Fixture):
    def test_members_are_sorted_parents_first_with_the_root_first_and_init_added(self) -> None:
        names = [member.name for member in initrd.members(str(self.write()))]
        self.assertEqual(
            names,
            [
                ".", "boot", f"boot/vmlinuz-{KERNEL}", "empty", "init", "sbin", "usr", "usr/bin",
                "usr/bin/perl", "usr/bin/perl5.40", "usr/bin/tool", "usr/fifo", "usr/sbin", "usr/sbin/init",
                "var", "var/lib", "var/lib/dpkg", "var/lib/dpkg/status",
            ],
        )  # fmt: skip

    def test_init_is_a_link_to_systemd_owned_by_root(self) -> None:
        init = self.by_name(self.write())["init"]
        self.assertEqual((stat.S_IFMT(init.mode), stat.S_IMODE(init.mode)), (stat.S_IFLNK, 0o777))
        self.assertEqual(
            (init.link, init.data, init.uid, init.gid, init.mtime), ("/sbin/init", b"/sbin/init", 0, 0, EPOCH)
        )

    def test_a_root_that_has_its_own_init_is_refused(self) -> None:
        (self.root / "init").write_text("#!/bin/sh\n")
        with self.assertRaisesRegex(initrd.InitrdError, "/init is already in the root"):
            self.write()

    def test_inode_numbers_follow_the_order_and_hard_links_share_one_with_the_content_last(self) -> None:
        members = initrd.members(str(self.write()), contents=True)
        by_name = {member.name: member for member in members}
        first, second = by_name["usr/bin/perl"], by_name["usr/bin/perl5.40"]
        self.assertEqual((first.ino, first.nlink, first.size, first.data), (second.ino, 2, 0, b""))
        self.assertEqual((second.nlink, second.size, second.data), (2, 5, b"perl\n"))
        unique = []
        for member in members:
            if member.ino not in unique:
                unique.append(member.ino)
        self.assertEqual(unique, list(range(1, len(unique) + 1)))
        self.assertEqual(by_name["usr/bin/tool"].nlink, 1)

    def test_modes_owners_and_clamped_times(self) -> None:
        by_name = self.by_name(self.write())
        self.assertEqual(by_name["usr/bin/tool"].mode, stat.S_IFREG | 0o755)
        self.assertEqual(stat.S_IFMT(by_name["usr/fifo"].mode), stat.S_IFIFO)
        self.assertEqual(stat.S_IFMT(by_name["empty"].mode), stat.S_IFDIR)
        self.assertEqual(by_name["sbin"].link, "usr/sbin")
        self.assertEqual({member.mtime for member in by_name.values()}, {EPOCH})
        self.assertEqual({(member.uid, member.gid) for name, member in by_name.items() if name != "init"}, {
            (os.getuid(), os.getgid())
        })  # fmt: skip
        early = EPOCH - 1000
        os.utime(self.root / "usr" / "bin" / "tool", (early, early))
        self.assertEqual(self.by_name(self.write(name="again.img"))["usr/bin/tool"].mtime, early)

    def test_an_absent_device_from_the_state_is_written_as_a_device_node(self) -> None:
        (self.root / "dev").mkdir()
        null = initrd.Absent("char", 0o666, 0, 0, LATER, 1, 3)
        disk = initrd.Absent("block", 0o660, 0, 6, EPOCH - 5, 8, 0)
        gone = initrd.Absent("char", 0o600, 0, 0, EPOCH, 5, 1)
        by_name = self.by_name(self.write(absent={"dev/null": null, "dev/sda": disk, "nowhere/console": gone}))
        self.assertEqual(
            (by_name["dev/null"].mode, by_name["dev/null"].rdevmajor, by_name["dev/null"].rdevminor),
            (stat.S_IFCHR | 0o666, 1, 3),
        )
        self.assertEqual(by_name["dev/null"].mtime, EPOCH)
        self.assertEqual(
            (by_name["dev/sda"].mode, by_name["dev/sda"].gid, by_name["dev/sda"].mtime),
            (stat.S_IFBLK | 0o660, 6, EPOCH - 5),
        )
        self.assertNotIn("nowhere/console", by_name, "a device whose directory is gone is not written")

    def test_the_same_tree_gives_the_same_bytes_whatever_its_inodes_and_later_times(self) -> None:
        first = self.write(name="first.img")
        other = self.dir / "other"
        other.mkdir()
        (other / "pad").write_text("shifts the inode numbers\n")
        copy = other / "root"
        copy.mkdir()
        make_root(copy)
        os.utime(copy / "usr" / "bin" / "tool", (LATER + 99, LATER + 99))
        second = self.write(copy, name="second.img")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first.read_bytes(), self.write(name="third.img").read_bytes())

    def test_the_archive_is_newc_in_gzip_with_no_name_and_no_time(self) -> None:
        path = self.write()
        raw = path.read_bytes()
        self.assertEqual(raw[:4], b"\x1f\x8b\x08\x00", "gzip, no name flag")
        self.assertEqual(raw[4:8], b"\0\0\0\0", "a zero time stamp")
        plain = gzip.decompress(raw)
        self.assertEqual(plain[:6], b"070701")
        self.assertIn(b"TRAILER!!!\0", plain[-128:])
        self.assertEqual(len(plain) % 4, 0)
        # the reader takes an uncompressed archive as well
        (self.dir / "plain.cpio").write_bytes(plain)
        self.assertEqual(
            [one.name for one in initrd.members(str(self.dir / "plain.cpio"))],
            [one.name for one in initrd.members(str(path))],
        )

    def test_gnu_cpio_reads_the_archive(self) -> None:
        if subprocess.run(["sh", "-c", "command -v cpio"], capture_output=True, check=False).returncode != 0:
            self.skipTest("no cpio here")
        listing = subprocess.run(
            ["cpio", "-it", "--quiet"], input=gunzip(self.write()), capture_output=True, check=True
        ).stdout.decode()
        self.assertEqual(listing.splitlines()[:3], [".", "boot", f"boot/vmlinuz-{KERNEL}"])
        self.assertIn("usr/bin/perl5.40", listing.splitlines())

    def test_contents_are_read_only_for_the_names_asked(self) -> None:
        members = initrd.members(str(self.write()), contents=["var/lib/dpkg/status"])
        with_data = {member.name: member.data for member in members if member.data is not None}
        self.assertEqual(with_data, {"var/lib/dpkg/status": b"Package: base-files\n"})

    def test_a_truncated_or_foreign_archive_is_refused(self) -> None:
        plain = gunzip(self.write())
        for name, data in (("short", plain[:200]), ("odc", b"070707" + plain[6:])):
            (self.dir / name).write_bytes(data)
            with self.subTest(name=name), self.assertRaises(initrd.InitrdError):
                initrd.members(str(self.dir / name))


class KitTest(Fixture):
    def kit(self, root: Path | None = None, name: str = "kit.tar", state: str | None = None) -> Path:
        out = self.dir / name
        kernel = initrd.kit(str(root or self.root), state, EPOCH, "installer", str(out), str(self.dir / "status"))
        self.assertEqual(kernel, KERNEL)
        return out

    def test_the_kit_holds_kit_json_vmlinuz_and_initrd_in_order_as_root_at_the_epoch(self) -> None:
        kit = self.kit()
        with tarfile.open(kit, mode="r:") as archive:
            members = archive.getmembers()
            data = {member.name: archive.extractfile(member).read() for member in members}  # type: ignore[union-attr]  # regular files
        self.assertEqual([member.name for member in members], ["kit.json", "vmlinuz", "initrd.img"])
        for member in members:
            self.assertEqual(
                (member.type, member.mode, member.uid, member.gid, member.uname, member.gname, member.mtime),
                (tarfile.REGTYPE, 0o644, 0, 0, "", "", EPOCH),
            )
        self.assertEqual(data["vmlinuz"], b"a kernel\n")
        expected = {
            "files": {
                "initrd.img": {
                    "sha256": hashlib.sha256(data["initrd.img"]).hexdigest(),
                    "size": len(data["initrd.img"]),
                },
                "vmlinuz": {"sha256": hashlib.sha256(b"a kernel\n").hexdigest(), "size": 9},
            },
            "image": "installer",
            "kernel": KERNEL,
            "schema": 1,
        }
        self.assertEqual(data["kit.json"], json.dumps(expected, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        self.assertEqual(initrd.read_kit(str(kit)), expected)
        self.assertEqual((self.dir / "status").read_bytes(), b"Package: base-files\n")
        self.assertEqual(sorted(path.name for path in self.dir.iterdir()), ["kit.tar", "root", "status"])

    def test_the_kit_is_byte_reproducible(self) -> None:
        self.assertEqual(self.kit(name="a.tar").read_bytes(), self.kit(name="b.tar").read_bytes())

    def test_the_initrd_holds_boot_too(self) -> None:
        with tarfile.open(self.kit(), mode="r:") as archive:
            (self.dir / "initrd.img").write_bytes(archive.extractfile("initrd.img").read())  # type: ignore[union-attr]  # a regular file
        self.assertIn(f"boot/vmlinuz-{KERNEL}", self.by_name(self.dir / "initrd.img"))

    def test_exactly_one_kernel(self) -> None:
        (self.root / "boot" / "vmlinuz-6.13-amd64").write_bytes(b"another\n")
        with self.assertRaisesRegex(
            initrd.InitrdError, r"exactly one kernel.*/boot/vmlinuz-6\.12.*/boot/vmlinuz-6\.13"
        ):
            self.kit()
        for path in (self.root / "boot").iterdir():
            path.unlink()
        with self.assertRaisesRegex(initrd.InitrdError, "the root has none"):
            self.kit()

    def test_a_kit_whose_files_are_not_what_kit_json_names_is_refused(self) -> None:
        kit = self.kit()
        with tarfile.open(kit, mode="r:") as archive:
            members = [(member, archive.extractfile(member).read()) for member in archive.getmembers()]  # type: ignore[union-attr]  # regular files
        cases = {
            "order": [members[1], members[0], members[2]],
            "missing": members[:2],
            "tampered": [members[0], members[1], (members[2][0], members[2][1][:-1] + b"x")],
        }
        for name, chosen in cases.items():
            target = self.dir / f"{name}.tar"
            with tarfile.open(target, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for member, data in chosen:
                    archive.addfile(member, io.BytesIO(data))
            with self.subTest(name=name), self.assertRaises(initrd.InitrdError):
                initrd.read_kit(str(target))

    def test_the_absent_devices_of_a_layer_state_reach_the_initrd(self) -> None:
        (self.root / "dev").mkdir()
        os.utime(self.root / "dev", (LATER, LATER))
        entries = layer.scan(str(self.root), EPOCH).entries
        entries["dev/console"] = layer.Entry("char", 0o600, 0, 0, EPOCH, major=5, minor=1, absent=True)
        state = self.dir / "state.json"
        state.write_text(layer.state_json(entries))
        self.assertEqual(
            initrd.read_absent(str(state)), {"dev/console": initrd.Absent("char", 0o600, 0, 0, EPOCH, 5, 1)}
        )
        kit = self.kit(state=str(state))
        with tarfile.open(kit, mode="r:") as archive:
            (self.dir / "initrd.img").write_bytes(archive.extractfile("initrd.img").read())  # type: ignore[union-attr]  # a regular file
        console = self.by_name(self.dir / "initrd.img")["dev/console"]
        self.assertEqual((console.mode, console.rdevmajor, console.rdevminor), (stat.S_IFCHR | 0o600, 5, 1))


class UnpackTest(Fixture):
    def test_unpacking_a_kit_and_packing_it_again_gives_the_same_initrd(self) -> None:
        kit = self.dir / "kit.tar"
        initrd.kit(str(self.root), None, EPOCH, "installer", str(kit), None)
        child = self.dir / "child"
        child.mkdir()
        absent, notes = initrd.unpack(str(child), str(kit))
        self.assertEqual((absent, notes), ({}, []))
        self.assertFalse((child / "init").exists() or (child / "init").is_symlink(), "the factory's /init is left out")
        self.assertEqual(
            os.stat(child / "usr" / "bin" / "perl").st_ino, os.stat(child / "usr" / "bin" / "perl5.40").st_ino
        )
        self.assertEqual((child / "usr" / "bin" / "perl5.40").read_bytes(), b"perl\n")
        self.assertEqual(os.readlink(child / "sbin"), "usr/sbin")
        self.assertEqual(stat.S_IMODE(os.stat(child / "usr" / "bin" / "tool").st_mode), 0o755)
        self.assertEqual(int(os.stat(child / "usr" / "bin").st_mtime), EPOCH)
        again = self.dir / "again.tar"
        initrd.kit(str(child), None, EPOCH, "installer", str(again), None)
        self.assertEqual(again.read_bytes(), kit.read_bytes())

    def test_a_device_this_user_cannot_create_is_recorded_as_absent(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root creates device nodes")
        (self.root / "dev").mkdir()
        kit = self.dir / "kit.tar"
        console = initrd.Absent("char", 0o600, 0, 0, EPOCH, 5, 1)
        target = self.dir / "initrd.img"
        initrd.write_initrd(str(self.root), {"dev/console": console}, EPOCH, str(target))
        with tarfile.open(kit, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            archive.add(target, arcname="initrd.img")
        child = self.dir / "child"
        child.mkdir()
        absent, notes = initrd.unpack(str(child), str(kit))
        self.assertEqual(absent, {"dev/console": console})
        self.assertEqual(len(notes), 1)
        state = self.dir / "state.json"
        state.write_text(initrd.state_json(absent))
        self.assertEqual(initrd.read_absent(str(state)), absent)
        self.assertEqual(layer.read_state(str(state))["dev/console"].absent, True, "layer.py reads the same rows")

    def test_a_member_that_leaves_the_root_is_refused(self) -> None:
        (self.root / "escape").symlink_to("/tmp")
        (self.root / "escape-dir").mkdir()
        target = self.dir / "initrd.img"
        initrd.write_initrd(str(self.root), {}, EPOCH, str(target))
        data = gunzip(target).replace(b"escape-dir", b"escape/dir")  # same length: the archive stays valid
        target.write_bytes(gzip.compress(data))
        kit = self.dir / "kit.tar"
        with tarfile.open(kit, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            archive.add(target, arcname="initrd.img")
        child = self.dir / "child"
        child.mkdir()
        with self.assertRaisesRegex(initrd.InitrdError, "leaves the root"):
            initrd.unpack(str(child), str(kit))


class CommandLineTest(Fixture):
    def run_program(self, *argv: str) -> subprocess.CompletedProcess[str]:
        program = Path(initrd.__file__)
        return subprocess.run([sys.executable, "-I", str(program), *argv], capture_output=True, text=True, check=False)

    def test_the_program_runs_with_the_standard_library_alone(self) -> None:
        kit = self.dir / "kit.tar"
        done = self.run_program(
            "kit", "--root", str(self.root), "--epoch", str(EPOCH), "--image", "installer", "--out", str(kit),
            "--status-out", str(self.dir / "status"),
        )  # fmt: skip
        self.assertEqual((done.returncode, done.stdout.strip()), (0, f"kit for kernel {KERNEL}"), done.stderr)
        child = self.dir / "child"
        child.mkdir()
        done = self.run_program("unpack", "--root", str(child), "--state", str(self.dir / "s.json"), "--kit", str(kit))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads((self.dir / "s.json").read_text()), {})

    def test_a_failure_is_one_line_and_a_non_zero_exit(self) -> None:
        (self.root / "init").write_text("")
        done = self.run_program(
            "kit", "--root", str(self.root), "--epoch", "1", "--image", "i", "--out", str(self.dir / "k")
        )
        self.assertEqual(done.returncode, 1)
        self.assertTrue(done.stderr.startswith("initrd.py: /init is already in the root"), done.stderr)


if __name__ == "__main__":
    unittest.main()
