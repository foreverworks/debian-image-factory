"""The node-tarball install script, run on small synthetic tarballs into a temporary root as an ordinary user."""

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
from debian_image_factory.build import node_install

EPOCH = 1754697600
TOP = "node-v26.13.1-linux-x64"


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
        member(f"{TOP}/", tarfile.DIRTYPE, mode=0o755),
        member(f"{TOP}/CHANGELOG.md", data=b"changes"),
        member(f"{TOP}/README.md", data=b"read me"),
        member(f"{TOP}/LICENSE", data=b"the licence", mtime=100),
        member(f"{TOP}/bin/", tarfile.DIRTYPE, mode=0o755),
        member(f"{TOP}/bin/node", data=b"#!node\n", mode=0o4755),
        member(f"{TOP}/bin/npm", tarfile.SYMTYPE, link="../lib/node_modules/npm/bin/npm-cli.js", mode=0o777),
        member(f"{TOP}/lib/node_modules/npm/bin/npm-cli.js", data=b"cli", mode=0o2755),
        member(f"{TOP}/lib/node_modules/npm/README.md", data=b"npm's own readme"),
        member(f"{TOP}/share/doc/", tarfile.DIRTYPE, mode=0o700, mtime=50),
    ]


def pack(path: Path, members: list[tuple[tarfile.TarInfo, bytes]], mode: str = "w:xz") -> Path:
    with tarfile.open(path, mode) as archive:  # type: ignore[call-overload]  # mode is a str of the open modes
        for info, data in members:
            archive.addfile(info, io.BytesIO(data) if info.type == tarfile.REGTYPE else None)
    return path


class InstallCase(unittest.TestCase):
    _tmp: tempfile.TemporaryDirectory[str]
    tmp: Path

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dif-node-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.root = self.tmp / "root"
        self.root.mkdir()

    def tarball(self, members: list[tuple[tarfile.TarInfo, bytes]] | None = None, mode: str = "w:xz") -> Path:
        return pack(self.tmp / "node.tar", release() if members is None else members, mode)

    def install(self, tarball: Path, prefix: str = "/usr/local") -> int:
        return node_install.install(self.root, tarball, prefix, EPOCH)

    def mode(self, path: str) -> int:
        return stat.S_IMODE((self.root / path).lstat().st_mode)

    def mtime(self, path: str) -> int:
        return int((self.root / path).lstat().st_mtime)


class UnpackTest(InstallCase):
    def test_the_top_directory_is_stripped_and_the_tree_lands_in_the_prefix(self) -> None:
        self.install(self.tarball())
        self.assertEqual((self.root / "usr/local/bin/node").read_bytes(), b"#!node\n")
        self.assertEqual((self.root / "usr/local/lib/node_modules/npm/bin/npm-cli.js").read_bytes(), b"cli")
        self.assertFalse((self.root / "usr/local" / TOP).exists())

    def test_changelog_and_readme_are_skipped_and_license_is_kept(self) -> None:
        self.install(self.tarball())
        self.assertFalse((self.root / "usr/local/CHANGELOG.md").exists())
        self.assertFalse((self.root / "usr/local/README.md").exists())
        self.assertEqual((self.root / "usr/local/LICENSE").read_bytes(), b"the licence")
        self.assertTrue((self.root / "usr/local/lib/node_modules/npm/README.md").is_file(), "only the top level")

    def test_modes_are_the_tarballs_without_setuid_or_setgid(self) -> None:
        self.install(self.tarball())
        self.assertEqual(self.mode("usr/local/bin/node"), 0o755)
        self.assertEqual(self.mode("usr/local/lib/node_modules/npm/bin/npm-cli.js"), 0o755)
        self.assertEqual(self.mode("usr/local/LICENSE"), 0o644)
        self.assertEqual(self.mode("usr/local/share/doc"), 0o700)
        self.assertEqual(self.mode("usr/local/lib"), 0o755, "a directory the tarball does not list")

    def test_times_are_clamped_to_source_date_epoch(self) -> None:
        self.install(self.tarball())
        self.assertEqual(self.mtime("usr/local/bin/node"), EPOCH, "newer than the epoch")
        self.assertEqual(self.mtime("usr/local/LICENSE"), 100, "older than the epoch stays")
        self.assertEqual(self.mtime("usr/local/share/doc"), 50)
        self.assertEqual(self.mtime("usr/local/lib/node_modules"), EPOCH)
        self.assertEqual(self.mtime("usr/local/bin/npm"), EPOCH)
        self.assertEqual(self.mtime("usr/local"), EPOCH)

    def test_a_symlink_is_kept_as_a_symlink(self) -> None:
        self.install(self.tarball())
        self.assertEqual(os.readlink(self.root / "usr/local/bin/npm"), "../lib/node_modules/npm/bin/npm-cli.js")

    def test_ownership_is_root_only_when_run_as_root(self) -> None:
        self.install(self.tarball())
        if os.geteuid() != 0:
            self.assertEqual((self.root / "usr/local/bin/node").stat().st_uid, os.geteuid())
        else:
            self.assertEqual((self.root / "usr/local/bin/node").stat().st_uid, 0)

    def test_gzip_tarballs_work_too(self) -> None:
        self.install(self.tarball(mode="w:gz"))
        self.assertTrue((self.root / "usr/local/bin/node").is_file())

    def test_the_count_is_what_was_written(self) -> None:
        self.assertEqual(self.install(self.tarball()), 7)

    def test_two_runs_give_the_same_tree(self) -> None:
        def listing(root: Path) -> list[tuple[str, int, int]]:
            return sorted(
                (str(p.relative_to(root)), stat.S_IMODE(p.lstat().st_mode), int(p.lstat().st_mtime))
                for p in root.rglob("*")
            )

        first = self.tmp / "first"
        second = self.tmp / "second"
        for root in (first, second):
            (root / "usr/local/bin").mkdir(parents=True)
            node_install.install(root, self.tarball(), "/usr/local", EPOCH)
            self.assertIsNotNone(listing(root))
        self.assertEqual(listing(first), listing(second))

    def test_an_existing_directory_keeps_its_mode_and_gets_its_time_back(self) -> None:
        bin_dir = self.root / "usr/local/bin"
        bin_dir.mkdir(parents=True)
        bin_dir.chmod(0o750)
        os.utime(bin_dir, (30, 30))
        self.install(self.tarball())
        self.assertEqual(self.mode("usr/local/bin"), 0o750)
        self.assertEqual(self.mtime("usr/local/bin"), EPOCH, "the tarball lists bin/, and its time is the clamped one")
        other = self.root / "usr/local/etc"
        other.mkdir()
        os.utime(other, (30, 30))
        self.install(self.tarball())
        self.assertEqual(self.mtime("usr/local/etc"), 30, "untouched")

    def test_a_file_that_is_there_is_replaced(self) -> None:
        (self.root / "usr/local/bin").mkdir(parents=True)
        (self.root / "usr/local/bin/node").write_text("old")
        self.install(self.tarball())
        self.assertEqual((self.root / "usr/local/bin/node").read_bytes(), b"#!node\n")


class OtherPrefixTest(InstallCase):
    def test_links_in_usr_local_bin_point_at_the_prefix(self) -> None:
        self.install(self.tarball(), "/opt/node-26")
        self.assertTrue((self.root / "opt/node-26/bin/node").is_file())
        for name in ("node", "npm", "npx"):
            self.assertEqual(os.readlink(self.root / "usr/local/bin" / name), f"/opt/node-26/bin/{name}")
        self.assertEqual(self.mtime("usr/local/bin/node"), EPOCH)
        self.assertEqual(self.mtime("usr/local/bin"), EPOCH)

    def test_the_default_prefix_adds_no_links(self) -> None:
        self.install(self.tarball())
        self.assertFalse((self.root / "usr/local/bin/npx").exists(), "the tarball here has no npx and none is added")

    def test_existing_links_are_replaced_and_siblings_kept(self) -> None:
        bin_dir = self.root / "usr/local/bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "node").write_text("old")
        (bin_dir / "other").write_text("mine")
        self.install(self.tarball(), "/opt/n")
        self.assertEqual(os.readlink(bin_dir / "node"), "/opt/n/bin/node")
        self.assertEqual((bin_dir / "other").read_text(), "mine")


class RefusalTest(InstallCase):
    def refused(self, members: list[tuple[tarfile.TarInfo, bytes]], pattern: str, prefix: str = "/usr/local") -> None:
        with self.assertRaisesRegex(node_install.InstallError, pattern):
            self.install(self.tarball(members), prefix)

    def test_an_absolute_name(self) -> None:
        self.refused([member("/etc/passwd", data=b"x")], "absolute member name")

    def test_a_name_with_dot_dot(self) -> None:
        self.refused([member(f"{TOP}/../../etc/x", data=b"x")], "goes up with ..")
        self.refused([member("../x", data=b"x")], "goes up with ..")

    def test_a_symlink_out_of_the_prefix(self) -> None:
        self.refused([member(f"{TOP}/bin/x", tarfile.SYMTYPE, link="../../../etc/passwd")], "leaves /usr/local")
        self.refused([member(f"{TOP}/x", tarfile.SYMTYPE, link="/etc/shadow")], "leaves /usr/local")
        self.refused([member(f"{TOP}/x", tarfile.SYMTYPE, link="..")], "leaves /usr/local")

    def test_a_symlink_that_stays_inside_is_fine(self) -> None:
        pack(self.tmp / "ok.tar", [member(f"{TOP}/a/x", tarfile.SYMTYPE, link="../b/y")])
        self.install(self.tmp / "ok.tar")
        self.assertEqual(os.readlink(self.root / "usr/local/a/x"), "../b/y")
        pack(self.tmp / "abs.tar", [member(f"{TOP}/z", tarfile.SYMTYPE, link="/usr/local/lib/q")])
        self.install(self.tmp / "abs.tar")

    def test_links_are_judged_against_the_prefix_not_the_root(self) -> None:
        self.refused([member(f"{TOP}/x", tarfile.SYMTYPE, link="/usr/local/lib/q")], "leaves /opt/n", prefix="/opt/n")

    def test_a_hard_link_is_made_inside_the_prefix(self) -> None:
        self.install(
            self.tarball(
                [
                    member(f"{TOP}/bin/node", data=b"n"),
                    member(f"{TOP}/bin/node2", tarfile.LNKTYPE, link=f"{TOP}/bin/node"),
                ]
            )
        )
        self.assertEqual((self.root / "usr/local/bin/node2").read_bytes(), b"n")
        self.assertEqual((self.root / "usr/local/bin/node").stat().st_nlink, 2)

    def test_a_hard_link_to_outside_is_refused(self) -> None:
        self.refused([member(f"{TOP}/bin/x", tarfile.LNKTYPE, link="../../etc/passwd")], "goes up with ..")
        self.refused([member(f"{TOP}/bin/x", tarfile.LNKTYPE, link="/etc/passwd")], "absolute member name")

    def test_devices_and_fifos(self) -> None:
        self.refused([member(f"{TOP}/dev", tarfile.CHRTYPE)], "only files, directories and links")
        self.refused([member(f"{TOP}/pipe", tarfile.FIFOTYPE)], "only files, directories and links")

    def test_a_symlink_in_the_image_is_never_followed(self) -> None:
        outside = self.tmp / "outside"
        outside.mkdir()
        (self.root / "usr/local").mkdir(parents=True)
        (self.root / "usr/local/lib").symlink_to(outside)
        with self.assertRaisesRegex(node_install.InstallError, "is a symlink in the image"):
            self.install(self.tarball())
        self.assertEqual(list(outside.iterdir()), [])

    def test_a_directory_in_the_way_of_a_file(self) -> None:
        (self.root / "usr/local/bin/node").mkdir(parents=True)
        with self.assertRaisesRegex(node_install.InstallError, "a directory is in the way"):
            self.install(self.tarball())


class CommandLineTest(InstallCase):
    def run_script(self, *args: str) -> subprocess.CompletedProcess[str]:
        script = self.tmp / "node_install.py"
        script.write_text(modules.node_install_text())
        return subprocess.run([sys.executable, "-I", str(script), *args], capture_output=True, text=True, check=False)

    def test_the_text_the_build_stages_runs_as_a_script(self) -> None:
        done = self.run_script(str(self.root), str(self.tarball()), "/usr/local", str(EPOCH))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("7 members into /usr/local", done.stdout)
        self.assertTrue((self.root / "usr/local/bin/node").is_file())

    def test_a_refusal_is_an_exit_status_and_a_message(self) -> None:
        bad = self.tarball([member("/etc/passwd", data=b"x")])
        done = self.run_script(str(self.root), str(bad), "/usr/local", str(EPOCH))
        self.assertEqual(done.returncode, 1)
        self.assertIn("node_install: /etc/passwd: absolute member name", done.stderr)

    def test_a_tarball_that_is_not_one(self) -> None:
        junk = self.tmp / "junk.tar.xz"
        junk.write_bytes(b"not a tarball")
        done = self.run_script(str(self.root), str(junk), "/usr/local", str(EPOCH))
        self.assertEqual(done.returncode, 1)
        self.assertIn("node_install:", done.stderr)

    def test_usage(self) -> None:
        self.assertEqual(self.run_script("only", "two").returncode, 2)
        self.assertEqual(self.run_script(str(self.root), "t", "/usr/local", "soon").returncode, 2)
        self.assertEqual(self.run_script(str(self.root), "t", "usr/local", "1").returncode, 2)
        self.assertEqual(self.run_script(str(self.root), "t", "/usr/local/", "1").returncode, 2)


if __name__ == "__main__":
    unittest.main()
