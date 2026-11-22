"""The file module's install script, run on small files and synthetic tarballs into a temporary root as an
ordinary user: a placed file, an unpacked tarball, the same bytes from the same inputs, and every member it
refuses."""

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

from debian_image_factory import modules
from debian_image_factory.build import file_install

EPOCH = 1754697600


def member(
    name: str,
    kind: bytes = tarfile.REGTYPE,
    data: bytes = b"",
    mode: int = 0o644,
    link: str = "",
    mtime: int = EPOCH + 1000,
) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = mode
    info.mtime = mtime
    info.size = len(data) if kind == tarfile.REGTYPE else 0
    info.linkname = link
    info.uid = info.gid = 1234
    info.uname = info.gname = "builder"
    return info, data


def release() -> list[tuple[tarfile.TarInfo, bytes]]:
    return [
        member("tool-3.1/", tarfile.DIRTYPE, mode=0o755),
        member("tool-3.1/bin/", tarfile.DIRTYPE, mode=0o755),
        member("tool-3.1/bin/tool", data=b"#!tool\n", mode=0o4755),
        member("tool-3.1/bin/t", tarfile.SYMTYPE, link="tool", mode=0o777),
        member("tool-3.1/lib/libt.so", data=b"lib", mode=0o2755, mtime=100),
        member("tool-3.1/lib/libt.so.1", tarfile.LNKTYPE, link="tool-3.1/lib/libt.so"),
        member("tool-3.1/share/", tarfile.DIRTYPE, mode=0o1777, mtime=50),
    ]


def pack(path: Path, members: list[tuple[tarfile.TarInfo, bytes]], mode: str = "w:gz") -> Path:
    with tarfile.open(path, mode) as archive:  # type: ignore[call-overload]  # mode is a str of the open modes
        for info, data in members:
            archive.addfile(info, io.BytesIO(data) if info.type == tarfile.REGTYPE else None)
    return path


def listing(root: Path) -> list[tuple[str, int, int, str]]:
    """Every path below `root`: mode, time, and its bytes' sha256 or its link target."""
    found = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if path.is_symlink():
            what = "-> " + os.readlink(path)
        elif path.is_file():
            what = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            what = "dir"
        found.append((str(path.relative_to(root)), info.st_mode, int(info.st_mtime), what))
    return found


class InstallCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dif-file-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.root = self.tmp / "root"
        self.root.mkdir()

    def tarball(self, members: list[tuple[tarfile.TarInfo, bytes]] | None = None, mode: str = "w:gz") -> Path:
        return pack(self.tmp / "tool.tar", release() if members is None else members, mode)

    def unpack(self, tarball: Path, path: str = "/opt/tool", strip: int = 1) -> int:
        return file_install.unpack(self.root, tarball, path, EPOCH, strip)

    def mode(self, path: str) -> int:
        return stat.S_IMODE((self.root / path).lstat().st_mode)

    def mtime(self, path: str) -> int:
        return int((self.root / path).lstat().st_mtime)


class PlaceTest(InstallCase):
    def source(self, data: bytes = b"#!binary\n") -> Path:
        path = self.tmp / "tool"
        path.write_bytes(data)
        os.utime(path, (EPOCH + 99, EPOCH + 99))
        return path

    def test_the_file_lands_with_its_mode_and_the_epoch_as_its_time(self) -> None:
        self.assertEqual(file_install.place(self.root, self.source(), "/usr/local/bin/tool", EPOCH, 0o755), 1)
        self.assertEqual((self.root / "usr/local/bin/tool").read_bytes(), b"#!binary\n")
        self.assertEqual((self.mode("usr/local/bin/tool"), self.mtime("usr/local/bin/tool")), (0o755, EPOCH))

    def test_missing_parents_are_made_0755_at_the_epoch_and_existing_ones_keep_theirs(self) -> None:
        (self.root / "usr").mkdir()
        (self.root / "usr").chmod(0o750)
        os.utime(self.root / "usr", (30, 30))
        file_install.place(self.root, self.source(), "/usr/local/bin/tool", EPOCH, 0o644)
        self.assertEqual((self.mode("usr/local"), self.mtime("usr/local")), (0o755, EPOCH))
        self.assertEqual((self.mode("usr"), self.mtime("usr")), (0o750, 30))

    def test_a_file_that_is_there_is_replaced(self) -> None:
        (self.root / "etc").mkdir()
        (self.root / "etc/tool.conf").write_text("old")
        file_install.place(self.root, self.source(b"new"), "/etc/tool.conf", EPOCH, 0o644)
        self.assertEqual((self.root / "etc/tool.conf").read_bytes(), b"new")

    def test_a_symlink_on_the_way_is_never_followed(self) -> None:
        outside = self.tmp / "outside"
        outside.mkdir()
        (self.root / "opt").symlink_to(outside)
        with self.assertRaisesRegex(file_install.InstallError, "symlink in the image"):
            file_install.place(self.root, self.source(), "/opt/tool", EPOCH, 0o644)
        self.assertEqual(list(outside.iterdir()), [])

    def test_a_directory_in_the_way_is_refused(self) -> None:
        (self.root / "opt/tool").mkdir(parents=True)
        with self.assertRaisesRegex(file_install.InstallError, "a directory is in the way"):
            file_install.place(self.root, self.source(), "/opt/tool", EPOCH, 0o644)


class UnpackTest(InstallCase):
    def test_the_stripped_tree_lands_in_the_directory(self) -> None:
        self.assertEqual(self.unpack(self.tarball()), 6)
        self.assertEqual((self.root / "opt/tool/bin/tool").read_bytes(), b"#!tool\n")
        self.assertEqual(os.readlink(self.root / "opt/tool/bin/t"), "tool")
        self.assertTrue((self.root / "opt/tool/lib/libt.so").samefile(self.root / "opt/tool/lib/libt.so.1"))
        self.assertFalse((self.root / "opt/tool/tool-3.1").exists())

    def test_without_strip_the_top_directory_stays(self) -> None:
        self.unpack(self.tarball(), strip=0)
        self.assertTrue((self.root / "opt/tool/tool-3.1/bin/tool").is_file())

    def test_modes_lose_setuid_setgid_and_sticky(self) -> None:
        self.unpack(self.tarball())
        self.assertEqual(self.mode("opt/tool/bin/tool"), 0o755)
        self.assertEqual(self.mode("opt/tool/lib/libt.so"), 0o755)
        self.assertEqual(self.mode("opt/tool/share"), 0o777)
        self.assertEqual(self.mode("opt/tool/lib"), 0o755, "a directory the tarball does not list")

    def test_times_are_clamped_to_source_date_epoch(self) -> None:
        self.unpack(self.tarball())
        self.assertEqual(self.mtime("opt/tool/bin/tool"), EPOCH, "newer than the epoch")
        self.assertEqual(self.mtime("opt/tool/lib/libt.so"), 100, "older than the epoch stays")
        self.assertEqual(self.mtime("opt/tool/share"), 50)
        self.assertEqual(self.mtime("opt/tool"), EPOCH)
        self.assertEqual(self.mtime("opt"), EPOCH)

    def test_xz_and_plain_tarballs_work_too(self) -> None:
        for mode in ("w:xz", "w"):
            with self.subTest(mode=mode):
                self.unpack(self.tarball(mode=mode), path=f"/opt/{mode[-2:]}")
                self.assertTrue((self.root / f"opt/{mode[-2:]}/bin/tool").is_file())

    def test_two_runs_give_the_same_tree_byte_for_byte(self) -> None:
        first, second = self.tmp / "first", self.tmp / "second"
        for root in (first, second):
            root.mkdir()
            file_install.unpack(root, self.tarball(), "/opt/tool", EPOCH, 1)
        self.assertEqual(listing(first), listing(second))
        self.assertGreater(len(listing(first)), 6)

    def test_ownership_is_root_only_when_run_as_root(self) -> None:
        self.unpack(self.tarball())
        expected = 0 if os.geteuid() == 0 else os.geteuid()
        self.assertEqual((self.root / "opt/tool/bin/tool").stat().st_uid, expected)


class RefusalTest(InstallCase):
    def refused(self, members: list[tuple[tarfile.TarInfo, bytes]], pattern: str, strip: int = 0) -> None:
        with self.assertRaisesRegex(file_install.InstallError, pattern):
            self.unpack(self.tarball(members), strip=strip)
        self.assertEqual([path.name for path in self.tmp.iterdir() if path.name not in ("root", "tool.tar")], [])

    def test_an_absolute_name(self) -> None:
        self.refused([member("/etc/passwd", data=b"x")], "absolute member name")

    def test_a_name_that_goes_up(self) -> None:
        self.refused([member("a/../../etc/passwd", data=b"x")], r"goes up with \.\.")

    def test_an_empty_name(self) -> None:
        self.refused([member("./", tarfile.DIRTYPE)], "empty member name")

    def test_a_fifo_and_a_device(self) -> None:
        self.refused([member("fifo", tarfile.FIFOTYPE)], "only files, directories and links")
        self.refused([member("null", tarfile.CHRTYPE)], "only files, directories and links")

    def test_a_symlink_that_leaves_the_directory(self) -> None:
        self.refused([member("escape", tarfile.SYMTYPE, link="../../etc/passwd")], "leaves /opt/tool")
        self.refused([member("abs", tarfile.SYMTYPE, link="/etc/passwd")], "leaves /opt/tool")

    def test_a_hard_link_to_a_stripped_member(self) -> None:
        self.refused([member("top/x", data=b"x"), member("top/y", tarfile.LNKTYPE, link="top")], "stripped away", 1)

    def test_a_symlink_in_the_image_is_never_followed(self) -> None:
        outside = self.tmp / "elsewhere"
        outside.mkdir()
        (self.root / "opt").symlink_to(outside)
        with self.assertRaisesRegex(file_install.InstallError, "symlink in the image"):
            self.unpack(self.tarball())
        self.assertEqual(list(outside.iterdir()), [])


class ScriptTest(InstallCase):
    def run_script(self, *argv: str) -> subprocess.CompletedProcess[str]:
        script = self.tmp / "file_install.py"
        script.write_text(modules.helper_text(modules.FILE_INSTALL))
        return subprocess.run([sys.executable, "-I", str(script), *argv], capture_output=True, text=True, check=False)

    def test_it_runs_on_its_own_with_python_isolated(self) -> None:
        done = self.run_script(str(self.root), str(self.tarball()), "/opt/tool", str(EPOCH), "--unpack", "1")
        self.assertEqual((done.returncode, done.stdout), (0, "file_install: 6 members into /opt/tool\n"), done.stderr)
        source = self.tmp / "conf"
        source.write_text("x")
        done = self.run_script(str(self.root), str(source), "/etc/tool.conf", str(EPOCH), "--mode", "0600")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.mode("etc/tool.conf"), 0o600)

    def test_bad_arguments_are_usage_errors(self) -> None:
        for argv in (
            ("r", "s", "/p", "x", "--mode", "0644"),
            ("r", "s", "relative", str(EPOCH), "--mode", "0644"),
            ("r", "s", "/p", str(EPOCH), "--mode", "4755"),
            ("r", "s", "/p", str(EPOCH), "--unpack", "-1"),
            ("r", "s", "/p", str(EPOCH), "--copy", "0644"),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(self.run_script(*argv).returncode, 2)

    def test_a_refusal_is_exit_1(self) -> None:
        bad = pack(self.tmp / "bad.tar", [member("/etc/passwd", data=b"x")])
        done = self.run_script(str(self.root), str(bad), "/opt/tool", str(EPOCH), "--unpack", "0")
        self.assertEqual(done.returncode, 1)
        self.assertIn("absolute member name", done.stderr)
