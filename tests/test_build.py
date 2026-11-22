"""The core build's pure parts: what runs in the builder, the image's apt sources, the hook
environment, the file tree tar, and what the build edge derives without docker."""

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from debian_image_factory import tools
from debian_image_factory.build import core, run
from debian_image_factory.identity import FileFact

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = "20261121T004329Z"


class SourcesTest(unittest.TestCase):
    def test_build_sources_read_the_mounted_mirror_one_suite_per_line_and_name_no_snapshot(self) -> None:
        options = "[signed-by=/factory/keyring.pgp check-valid-until=no]"
        self.assertEqual(
            core.build_sources("trixie", ["main", "contrib"]),
            f"deb {options} copy:///mirror/debian trixie main contrib\n"
            f"deb {options} copy:///mirror/debian trixie-updates main contrib\n"
            f"deb {options} copy:///mirror/debian-security trixie-security main contrib\n",
        )

    def test_live_sources_point_at_debian_and_carry_no_snapshot(self) -> None:
        text = core.image_sources("live", "trixie", ["main"], "20261108T000000Z")
        self.assertIn("URIs: http://deb.debian.org/debian\nSuites: trixie trixie-updates\n", text)
        self.assertIn("URIs: http://security.debian.org/debian-security\nSuites: trixie-security\n", text)
        self.assertNotIn("Snapshot", text)
        self.assertNotIn("20261108T000000Z", text)

    def test_baseline_pins_every_suite(self) -> None:
        text = core.image_sources("baseline", "trixie", ["main"], "20261108T000000Z")
        self.assertEqual(text.count("Snapshot: 20261108T000000Z"), 2)

    def test_baseline_except_security_leaves_security_live(self) -> None:
        text = core.image_sources("baseline-except-security", "trixie", ["main"], "20261108T000000Z")
        debian, security = text.split("\n\n")
        self.assertIn("Snapshot: 20261108T000000Z", debian)
        self.assertNotIn("Snapshot", security)

    def test_baseline_without_one_and_unknown_modes_are_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "needs the baseline"):
            core.image_sources("baseline", "trixie", ["main"], None)
        with self.assertRaisesRegex(ValueError, "not live"):
            core.image_sources("nightly", "trixie", ["main"], None)


class ScriptsTest(unittest.TestCase):
    def test_build_script_runs_mmdebstrap_offline_and_gzips_without_name_or_time(self) -> None:
        text = core.build_script(
            suite="trixie", request=["tzdata", "apt", "ca-certificates"], source_date_epoch=1754697600, owner=None
        )
        self.assertIn("export SOURCE_DATE_EPOCH=1754697600\n", text)
        self.assertIn("--mode=root --variant=apt --format=tar --include=apt,ca-certificates,tzdata", text)
        self.assertIn("gzip -n -9 < /factory/rootfs.tar > /factory/rootfs.tar.gz", text)
        self.assertNotIn("chown", text)
        self.assertIn("chown 1000:1000 /factory/rootfs.tar.gz", core.build_script(
            suite="trixie", request=["apt"], source_date_epoch=1, owner="1000:1000"
        ))  # fmt: skip

    def test_customize_script_replaces_sources_and_removes_identity(self) -> None:
        text = core.customize_script(files=False, hooks=())
        self.assertIn('find "$root/etc/apt/sources.list.d" -mindepth 1 -delete', text)
        self.assertIn("install -m 0644 /factory/debian.sources", text)
        for path in ("etc/hostname", "etc/resolv.conf", "var/lib/dbus/machine-id", "var/lib/systemd/random-seed"):
            self.assertIn(f'rm -f "$root/{path}"', text)
        self.assertIn('rm -f "$root"/etc/ssh/ssh_host_*', text)
        self.assertIn('if [ -e "$root/etc/machine-id" ]; then : > "$root/etc/machine-id"; fi', text)
        self.assertNotIn("files.tar", text)
        self.assertNotIn("chroot", text)

    def test_hooks_run_in_order_in_the_chroot_and_leave_nothing_behind(self) -> None:
        text = core.customize_script(files=True, hooks=("hooks/b.sh", "hooks/a.sh"))
        self.assertIn('tar -C "$root" --no-overwrite-dir -xpf /factory/files.tar', text)
        first, second = text.index("/run/factory/hooks/01-b.sh"), text.index("/run/factory/hooks/02-a.sh")
        self.assertLess(first, second)
        self.assertLess(text.index("files.tar"), first)
        self.assertLess(second, text.index('rm -rf "$root/run/factory"'))
        self.assertLess(text.index('rm -rf "$root/run/factory"'), text.index("no machine identity"))

    def test_hook_environment_names_parameters_as_hooks_read_them(self) -> None:
        self.assertEqual(
            core.param_env({"vendor_tools": True, "level": 3, "name": "x-y"}),
            [("FACTORY_PARAM_LEVEL", "3"), ("FACTORY_PARAM_NAME", "x-y"), ("FACTORY_PARAM_VENDOR_TOOLS", "true")],
        )
        self.assertEqual(core.env_suffix("node-26"), "NODE_26")


class FilesTarTest(unittest.TestCase):
    def test_tree_is_owned_by_root_with_git_modes_and_fixed_times(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "files" / "etc").mkdir(parents=True)
            (root / "files" / "etc" / "motd").write_bytes(b"hello\n")
            facts = {
                "files": FileFact(None, "0755", directory=True),
                "files/etc": FileFact(None, "0755", directory=True),
                "files/etc/motd": FileFact("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03", "0644"),
                "files/etc/issue": FileFact(None, "0777", link="motd"),
                "other/x": FileFact("0" * 64, "0644"),
            }
            first = run.files_tar(root, "files", facts, 1754697600)
            self.assertEqual(first, run.files_tar(root, "files", facts, 1754697600))
            with tarfile.open(fileobj=io.BytesIO(first)) as archive:
                members = {member.name: member for member in archive.getmembers()}
            self.assertEqual(sorted(members), ["./etc", "./etc/issue", "./etc/motd"])
            motd = members["./etc/motd"]
            self.assertEqual((motd.uid, motd.gid, motd.mode, motd.mtime), (0, 0, 0o644, 1754697600))
            self.assertEqual(members["./etc/issue"].linkname, "motd")
            (root / "files" / "etc" / "motd").write_bytes(b"changed\n")
            with self.assertRaisesRegex(Exception, "changed while the build read it"):
                run.files_tar(root, "files", facts, 1754697600)


class EdgeHelpersTest(unittest.TestCase):
    def test_repository_of_drops_the_tag_and_digest(self) -> None:
        self.assertEqual(
            run.repository_of("debian-image-factory-builder:20261121T004329Z"), "debian-image-factory-builder"
        )
        self.assertEqual(run.repository_of("ghcr.io/o/b@sha256:" + "a" * 64), "ghcr.io/o/b")
        self.assertEqual(run.repository_of("localhost:5000/b"), "localhost:5000/b")
        self.assertEqual(run.repository_of("localhost:5000/b:tag"), "localhost:5000/b")

    def test_reason_says_why_the_plan_builds(self) -> None:
        self.assertEqual(run.reason_text([{"rebuild": "key rotation"}, {"package": "a"}]), "rebuild: key rotation")
        self.assertEqual(
            run.reason_text(
                [{"published": "no artifact with this identity"}, {"package": "a", "from": "1", "to": "2"}]
            ),
            "no artifact with this identity; package a 1 -> 2",
        )
        self.assertIsNone(run.reason_text(None))

    def test_input_file_name_is_the_url_basename(self) -> None:
        self.assertEqual(run.input_file_name({"url": "https://example.com/a/node-v1.tar.xz?x=1"}), "node-v1.tar.xz")
        self.assertEqual(run.input_file_name({"url": "https://example.com/"}), "file")

    def test_builder_snapshot_is_the_repository_lock_snapshot(self) -> None:
        lock = json.loads((ROOT / "lock.json").read_text())
        self.assertEqual(tools.BUILDER_SNAPSHOT, lock["debian_snapshot"])
        self.assertTrue(tools.BUILDER_IMAGE.endswith(":" + tools.BUILDER_SNAPSHOT))


if __name__ == "__main__":
    unittest.main()
