"""The Incus kind's build, without docker: the script text the builder runs, how a parent is found and its
ancestors listed, the device nodes a parent's root holds, and the records an image gets."""

import gzip
import hashlib
import io
import itertools
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from unittest import mock

from input_lock import Package
from input_lock.records import PROVENANCE_PREDICATE, SPDX_PREDICATE

from debian_image_factory import commands, planfile, published, records, squashfs
from debian_image_factory.build import core, parents, run
from debian_image_factory.build import incus as incus_build
from tests.support import incusimage
from tests.support.definitions import example_lock
from tests.support.incusimage import Image, write_image
from tests.support.rootfs import BASE, IDENTITY

EPOCH = 1754697600
BOOT = ["# boot line one", "# boot line two"]


def shell_is_valid(text: str) -> bool:
    return subprocess.run(["sh", "-n"], input=text, text=True, capture_output=True, check=False).returncode == 0


def script(**changes: object) -> str:
    arguments: dict[str, object] = {
        "parent": "core",
        "request": (),
        "source_date_epoch": EPOCH,
        "owner": None,
        "files": False,
        "module_lines": (),
        "hooks": (),
        "boot_lines": (),
    }
    arguments.update(changes)
    return incus_build.build_script(**arguments)  # type: ignore[arg-type]  # the keywords are the function's own, built as a dict


def position(text: str, needle: str) -> int:
    """Where the first `needle` is; a missing one fails the test with its text."""
    found = text.find(needle)
    assert found >= 0, f"{needle!r} is not in the script"
    return found


class UnpackTest(unittest.TestCase):
    def test_a_core_parent_goes_through_the_layer_program_which_skips_device_nodes(self) -> None:
        lines = incus_build.unpack_lines("core", EPOCH)
        text = "\n".join(lines)
        self.assertIn('mkdir -p "$root"', lines)
        self.assertIn(
            'python3 -I /factory/layer.py unpack --root "$root" --state /factory/parent.state.json '
            "--epoch 1754697600 /factory/parent.tar.gz",
            text,
        )
        self.assertNotIn("unsquashfs", text)

    def test_an_incus_parent_is_unpacked_by_unsquashfs_without_the_device_nodes_it_lists(self) -> None:
        line = next(one for one in incus_build.unpack_lines("incus", EPOCH) if one.startswith("unsquashfs"))
        for part in ("-no-progress", "-quiet", incus_build.DEVICES_LIST, '-d "$root"', incus_build.PARENT_SQUASHFS):
            self.assertIn(part, line)
        self.assertTrue(line.endswith(incus_build.PARENT_SQUASHFS))

    def test_the_epoch_is_written_as_a_whole_number(self) -> None:
        self.assertIn("--epoch 1754697600 ", "\n".join(incus_build.unpack_lines("core", 1754697600)))

    def test_any_other_parent_is_refused(self) -> None:
        for parent in ("oci", "installer", ""):
            with self.assertRaisesRegex(ValueError, "built on core or on an Incus image"):
                incus_build.unpack_lines(parent, EPOCH)


class SetupTest(unittest.TestCase):
    def test_networkd_is_enabled_only_when_the_image_has_its_unit(self) -> None:
        text = "\n".join(incus_build.setup_lines(networkd=True))
        self.assertIn('if [ -e "$root/usr/lib/systemd/system/systemd-networkd.service" ]; then', text)
        self.assertIn('chroot "$root" systemctl enable systemd-networkd.service', text)
        self.assertNotIn("networkd", "\n".join(incus_build.setup_lines(networkd=False)))

    def test_the_cloud_config_line_writes_exactly_the_text_whatever_it_holds(self) -> None:
        text = script()
        start = position(text, 'mkdir -p "$root/etc/cloud/cloud.cfg.d"')
        end = position(text, f'chmod 0644 "$root/{incus_build.CLOUD_CONFIG}"')
        self.assertEqual(text.count("printf '%s' '# Written by debian-image-factory"), 1)
        commands_ = text[start:end] + f'chmod 0644 "$root/{incus_build.CLOUD_CONFIG}"\n'
        with tempfile.TemporaryDirectory(prefix="cloud-config-") as scratch:
            done = subprocess.run(
                ["sh", "-eu", "-c", commands_],
                env={"root": scratch, "PATH": os.environ["PATH"]},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            written = Path(scratch) / incus_build.CLOUD_CONFIG
            self.assertEqual(written.read_text(), incus_build.CLOUD_CONFIG_TEXT)
            self.assertEqual(written.stat().st_mode & 0o777, 0o644)

    def test_the_cloud_config_reads_the_nocloud_seed_only(self) -> None:
        self.assertTrue(incus_build.CLOUD_CONFIG_TEXT.endswith("datasource_list: [NoCloud, None]\n"))
        self.assertTrue(incus_build.CLOUD_CONFIG.startswith("etc/cloud/cloud.cfg.d/"))


class PackTest(unittest.TestCase):
    def test_the_root_is_packed_with_gzip_and_the_parents_device_nodes(self) -> None:
        text = "\n".join(incus_build.pack_lines(EPOCH, None))
        self.assertIn(f'cp "$root/var/lib/dpkg/status" {incus_build.STATUS}', text)
        self.assertIn(
            f'mksquashfs "$root" {incus_build.ROOTFS} -comp gzip -noappend -no-progress -xattrs -quiet '
            f"-pf {incus_build.DEVICES_PSEUDO}",
            text,
        )
        self.assertNotIn("-all-time", text)
        self.assertNotIn("-mkfs-time", text)
        self.assertNotIn("chown", text)

    def test_the_outputs_are_handed_back_to_the_owner(self) -> None:
        text = "\n".join(incus_build.pack_lines(EPOCH, "1000:1000"))
        self.assertIn(f"chown 1000:1000 {incus_build.ROOTFS} {incus_build.STATUS}", text)


class ScriptTest(unittest.TestCase):
    def test_the_build_stops_on_an_error_and_exports_the_time_stamp_and_the_environment(self) -> None:
        lines = script().splitlines()
        self.assertEqual(lines[0], "set -eu")
        self.assertEqual(lines[1], "export SOURCE_DATE_EPOCH=1754697600")
        self.assertIn("export LC_ALL=C.UTF-8 LANG=C.UTF-8 LANGUAGE=C.UTF-8", lines)
        self.assertIn("umask 022", lines)
        self.assertIn('root="/factory/root"', lines)

    def test_the_trap_unmounts_and_deletes_the_root_whatever_happens(self) -> None:
        text = script(request=["jq"])
        trap = text[position(text, "cleanup() {") : position(text, "trap cleanup EXIT")]
        self.assertIn('umount "$root/run/factory/mirror" 2>/dev/null || true', trap)
        self.assertIn('rm -rf --one-file-system "$root" /factory/aside', trap)
        self.assertIn('exit "$status"', trap)
        self.assertLess(position(text, "trap cleanup EXIT"), position(text, "unpack"))

    def test_a_core_parent_is_unpacked_by_the_layer_program(self) -> None:
        text = script(parent="core")
        self.assertIn("layer.py unpack --root", text)
        self.assertNotIn("unsquashfs", text)

    def test_an_incus_parent_is_unpacked_from_its_squashfs(self) -> None:
        text = script(parent="incus")
        self.assertIn("unsquashfs", text)
        self.assertIn("/factory/parent.squashfs", text)
        self.assertNotIn("layer.py unpack", text)

    def test_any_other_parent_fails_before_a_script_is_written(self) -> None:
        with self.assertRaises(ValueError):
            script(parent="oci")

    def test_every_step_comes_in_its_order(self) -> None:
        for parent in ("core", "incus"):
            text = script(
                parent=parent,
                request=["jq", "ca-certificates"],
                files=True,
                module_lines=["# module node"],
                hooks=["hooks/x.sh"],
                boot_lines=BOOT,
            )
            steps = [
                "unsquashfs" if parent == "incus" else "layer.py unpack",
                "mount -t proc",
                "mount --bind /mirror",
                "00factory-build",
                "apt-get update",
                "--no-install-recommends install ca-certificates jq",
                "-xpf /factory/files.tar",
                "# module node",
                "/run/factory/hooks/01-x.sh",
                'rm -rf "$root/run/factory/hooks"',
                "Dir::Etc::SourceList=/dev/null",
                "90-factory-nocloud.cfg",
                "systemctl enable systemd-networkd.service",
                'rm -f "$root/var/log/dpkg.log"',
                ': > "$root/etc/machine-id"',
                "# boot line one",
                "# boot line two",
                'umount "$root/run/factory/mirror"\n',
                'find "$root/tmp"',
                'cp "$root/var/lib/dpkg/status"',
                "mksquashfs",
            ]
            for first, second in itertools.pairwise(steps):
                self.assertLess(position(text, first), position(text, second), f"{parent}: {first!r} before {second!r}")

    def test_a_build_without_packages_runs_no_apt_and_mounts_no_mirror(self) -> None:
        text = script(boot_lines=BOOT)
        for absent in ("apt-get", "/mirror", "policy-rc.d", "run/factory/mirror"):
            self.assertNotIn(absent, text)
        for present in ("mount -t proc", "90-factory-nocloud.cfg", ': > "$root/etc/machine-id"', "# boot line one"):
            self.assertIn(present, text)

    def test_the_file_tree_and_the_hooks_are_there_only_when_asked_for(self) -> None:
        bare = script()
        self.assertNotIn("files.tar", bare)
        self.assertNotIn("hooks/", bare)
        self.assertIn("-xpf /factory/files.tar", script(files=True))
        text = script(hooks=["a/one.sh", "b/two.sh"])
        self.assertLess(position(text, "/run/factory/hooks/01-one.sh"), position(text, "/run/factory/hooks/02-two.sh"))
        for name in ("hooks", "inputs", "build.env"):
            self.assertIn(f'rm -rf "$root/run/factory/{name}"', text)

    def test_modules_run_after_the_file_tree_and_before_the_hooks(self) -> None:
        text = script(files=True, module_lines=["# module"], hooks=["x.sh"])
        self.assertLess(position(text, "files.tar"), position(text, "# module"))
        self.assertLess(position(text, "# module"), position(text, "/run/factory/hooks/01-x.sh"))

    def test_the_images_own_apt_and_service_blockers_are_put_back_before_the_cloud_config(self) -> None:
        text = script(request=["jq"])
        self.assertIn('rm -f "$root/etc/apt/sources.list" "$root/usr/sbin/policy-rc.d"', text)
        self.assertIn('mv "$root/usr/sbin/start-stop-daemon.REAL" "$root/usr/sbin/start-stop-daemon"', text)
        self.assertLess(
            position(text, 'rm -f "$root/etc/apt/apt.conf.d/99factory-build"'), position(text, "90-factory")
        )

    def test_the_identity_lines_every_child_ends_with_are_in_the_script(self) -> None:
        text = script()
        for line in core.identity_lines():
            self.assertIn(line, text)

    def test_the_outputs_are_handed_back_where_the_container_root_is_the_host_root(self) -> None:
        self.assertNotIn("chown", script())
        self.assertIn("chown 1000:1000 /factory/rootfs.squashfs /factory/dpkg-status", script(owner="1000:1000"))

    def test_the_script_ends_with_a_newline_after_the_pack(self) -> None:
        text = script()
        self.assertTrue(text.endswith("\n"))
        self.assertGreater(position(text, "mksquashfs"), position(text, "umount"))

    def test_every_combination_is_valid_shell(self) -> None:
        for parent, request, files, hooks, owner in itertools.product(
            ("core", "incus"), ((), ("jq",)), (False, True), ((), ("x.sh", "y.sh")), (None, "1000:1000")
        ):
            text = script(
                parent=parent,
                request=request,
                files=files,
                hooks=hooks,
                owner=owner,
                module_lines=["# module"],
                boot_lines=BOOT,
            )
            self.assertTrue(shell_is_valid(text), f"{parent} {request} {files} {hooks} {owner}")


class DevicePseudoTest(unittest.TestCase):
    def test_a_char_device_is_one_pseudo_definition(self) -> None:
        self.assertEqual(incus_build.device_pseudo("/dev/null", "char", 0o666, 0, 0, 1, 3), "/dev/null c 666 0 0 1 3\n")

    def test_a_block_device_keeps_its_owner_and_numbers(self) -> None:
        self.assertEqual(
            incus_build.device_pseudo("/dev/loop0", "block", 0o660, 0, 6, 7, 0), "/dev/loop0 b 660 0 6 7 0\n"
        )
        self.assertEqual(
            incus_build.device_pseudo("/dev/wide", "char", 0o600, 1000, 2000, 259, 300),
            "/dev/wide c 600 1000 2000 259 300\n",
        )

    def test_only_the_permission_bits_are_written_in_octal(self) -> None:
        self.assertEqual(incus_build.device_pseudo("/d", "char", 0o20666, 0, 0, 1, 3), "/d c 666 0 0 1 3\n")
        self.assertEqual(incus_build.device_pseudo("/d", "block", 0o4755, 0, 0, 1, 3), "/d b 4755 0 0 1 3\n")

    def test_any_other_kind_is_refused(self) -> None:
        for kind in ("file", "dir", "symlink", "fifo", "socket", "c", ""):
            with self.assertRaisesRegex(ValueError, "is not a device node"):
                incus_build.device_pseudo("/dev/x", kind, 0o600, 0, 0, 1, 1)

    def test_a_path_with_white_space_is_refused(self) -> None:
        for path in ("/dev/with space", "/dev/tab\there", "/dev/new\nline", "/dev/x "):
            with self.assertRaisesRegex(ValueError, "white space"):
                incus_build.device_pseudo(path, "char", 0o600, 0, 0, 1, 1)


# ---- artifacts on disk ----------------------------------------------------------------------------


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entry_for(image: Image, identity: str, kind: str = "incus", **extra: str) -> planfile.ImageEntry:
    """A plan entry as far as `locate_parent` reads one."""
    return {"kind": kind, "identity": identity, **extra}  # type: ignore[typeddict-item]  # only the fields locate_parent reads


def refuse_pull(target: published.OciTarget, digest: str, dest: Path) -> Path:
    raise AssertionError("nothing is pulled for an Incus image")


def described(image: Image) -> parents.ParentArtifact:
    return parents.describe_incus(image.metadata)


class TemporaryTest(unittest.TestCase):
    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory(prefix="build-incus-test-")
        self.addCleanup(scratch.cleanup)
        self.dir = Path(scratch.name)
        self.out = self.dir / "out"
        self.out.mkdir()


class DescribeTest(TemporaryTest):
    def test_an_incus_image_is_read_by_its_metadata_tarball_and_its_fingerprint(self) -> None:
        image = write_image(self.out, "incus-base", incusimage.BASE_IDENTITY, incusimage.fixture("incus-root"))
        found = parents.describe_incus(image.metadata)
        self.assertEqual(
            found,
            parents.ParentArtifact("incus-base", "incus", image.names.metadata, image.fingerprint, image.metadata),
        )
        self.assertEqual(parents.describe(image.metadata, "incus"), found)

    def test_a_name_that_is_not_an_incus_images_is_refused(self) -> None:
        image = write_image(self.out, "incus-base", incusimage.BASE_IDENTITY, incusimage.fixture("incus-root"))
        with self.assertRaisesRegex(commands.Failed, "is not the name of a incus artifact"):
            parents.describe_incus(image.rootfs)
        with self.assertRaisesRegex(commands.Failed, "is not the name of a incus artifact"):
            parents.describe_incus(self.out / "core-trixie-amd64-abababababababab-123456789abc.tar.gz")

    def test_a_missing_rootfs_is_refused(self) -> None:
        image = write_image(self.out, "incus-base", incusimage.BASE_IDENTITY, incusimage.fixture("incus-root"))
        image.rootfs.unlink()
        with self.assertRaisesRegex(commands.Failed, "no rootfs"):
            parents.describe_incus(image.metadata)

    def test_a_rootfs_that_is_not_the_one_the_name_says_is_refused(self) -> None:
        image = write_image(self.out, "incus-base", incusimage.BASE_IDENTITY, incusimage.fixture("incus-root"))
        image.rootfs.write_bytes(incusimage.fixture("scan"))
        with self.assertRaisesRegex(commands.Failed, "does not match the digest in its name"):
            parents.describe_incus(image.metadata)


class RootfsTest(TemporaryTest):
    def test_the_rootfs_is_the_file_beside_the_metadata_tarball(self) -> None:
        image = write_image(self.out, "incus-base", incusimage.BASE_IDENTITY, incusimage.fixture("incus-root"))
        self.assertEqual(parents.incus_rootfs(described(image)), image.rootfs)

    def test_an_ancestor_known_only_by_name_has_no_rootfs_to_build_on(self) -> None:
        image = write_image(self.out, "incus-base", incusimage.BASE_IDENTITY, incusimage.fixture("incus-root"))
        unknown = parents.ParentArtifact("incus-base", "incus", image.names.metadata, image.fingerprint, None)
        with self.assertRaisesRegex(commands.Failed, "its rootfs is needed"):
            parents.incus_rootfs(unknown)

    def test_a_name_without_a_rootfs_is_refused(self) -> None:
        odd = parents.ParentArtifact("core", "core", "core.tar.gz", "0" * 64, self.out / "core.tar.gz")
        with self.assertRaisesRegex(commands.Failed, "its rootfs is needed"):
            parents.incus_rootfs(odd)


class LineageTest(TemporaryTest):
    def setUp(self) -> None:
        super().setUp()
        self.core_digest = "5c" * 32
        self.root = incusimage.fixture("incus-root")
        self.base = write_image(
            self.out, "incus-base", incusimage.BASE_IDENTITY, self.root, ancestors=[("core", self.core_digest)]
        )
        self.app = write_image(
            self.out,
            "incus-app",
            incusimage.APP_IDENTITY,
            self.root,
            ancestors=[("incus-base", self.base.fingerprint), ("core", self.core_digest)],
        )

    def test_a_core_parent_is_the_whole_lineage(self) -> None:
        core_ = parents.ParentArtifact("core", "core", "core-x.tar.gz", self.core_digest, None)
        self.assertEqual(parents.incus_lineage(core_), [records.Parent("core", self.core_digest)])

    def test_an_incus_parent_comes_first_then_what_its_provenance_names_in_order(self) -> None:
        chain = parents.incus_lineage(described(self.app))
        self.assertEqual(
            [(one.name, one.sha256) for one in chain],
            [("incus-app", self.app.fingerprint), ("incus-base", self.base.fingerprint), ("core", self.core_digest)],
        )

    def test_a_parent_directly_on_core_lists_core_after_it(self) -> None:
        chain = parents.incus_lineage(described(self.base))
        self.assertEqual(
            [(one.name, one.sha256) for one in chain],
            [("incus-base", self.base.fingerprint), ("core", self.core_digest)],
        )

    def test_a_parent_known_only_by_name_has_no_records_to_read(self) -> None:
        unknown = parents.ParentArtifact("incus-base", "incus", self.base.names.metadata, self.base.fingerprint, None)
        with self.assertRaisesRegex(commands.Failed, "its records are needed"):
            parents.incus_lineage(unknown)

    def test_missing_records_fail_saying_which_file(self) -> None:
        found = described(self.app)
        self.app.records.unlink()
        with self.assertRaisesRegex(
            commands.Failed, r"intoto\.jsonl: the records of incus-app-trixie.* cannot be read"
        ):
            parents.incus_lineage(found)

    def test_malformed_records_fail(self) -> None:
        found = described(self.app)
        self.app.records.write_text("not json\n")
        with self.assertRaisesRegex(commands.Failed, "cannot be read .*line 1"):
            parents.incus_lineage(found)

    def test_records_without_provenance_about_the_parent_fail(self) -> None:
        found = described(self.app)
        lines = self.app.records.read_text().splitlines(keepends=True)
        self.app.records.write_text("".join(lines[1:]))  # the SBOM only
        with self.assertRaisesRegex(
            commands.Failed, "provenance records of incus-app-trixie.* name 0 ancestries, not one"
        ):
            parents.incus_lineage(found)

    def test_two_provenance_records_that_agree_are_one_lineage(self) -> None:
        found = described(self.app)
        text = self.app.records.read_text()
        once = parents.incus_lineage(found)
        self.app.records.write_text(text + text.splitlines(keepends=True)[0])  # a rebuild of the same bytes
        self.assertEqual(parents.incus_lineage(found), once)


class LocateTest(TemporaryTest):
    def setUp(self) -> None:
        super().setUp()
        self.base = write_image(self.out, "incus-base", incusimage.BASE_IDENTITY, incusimage.fixture("incus-root"))
        self.parent = described(self.base)

    def locate(
        self,
        *,
        entry: planfile.ImageEntry | None = None,
        out: Path | None = None,
        directories: Sequence[Path] = (),
        registries: Sequence[published.OciTarget] = (),
        built: Mapping[str, parents.ParentArtifact] | None = None,
    ) -> parents.ParentArtifact:
        return parents.locate_parent(
            "incus-app",
            "incus-base",
            entry or entry_for(self.base, incusimage.BASE_IDENTITY, artifact=self.base.fingerprint),
            suite="trixie",
            arch="amd64",
            built=built or {},
            out_dir=out or self.out,
            directories=directories,
            registries=registries,
            pull=refuse_pull,
            scratch=self.dir / "pulled",
        )

    def test_found_in_the_output_directory_by_the_digest_the_plan_names(self) -> None:
        self.assertEqual(self.locate(), self.parent)

    def test_found_by_identity_when_the_plan_names_no_digest(self) -> None:
        self.assertEqual(self.locate(entry=entry_for(self.base, incusimage.BASE_IDENTITY)), self.parent)

    def test_found_in_a_parent_target_directory(self) -> None:
        empty = self.dir / "empty"
        empty.mkdir()
        self.assertEqual(self.locate(out=empty, directories=[self.out]), self.parent)

    def test_a_parent_built_in_this_run_is_the_one_used(self) -> None:
        elsewhere = parents.ParentArtifact("incus-base", "incus", "x.incus.tar.gz", "0" * 64, None)
        self.assertIs(self.locate(built={"incus-base": elsewhere}), elsewhere)

    def test_two_builds_of_the_parent_without_a_named_digest_are_ambiguous(self) -> None:
        write_image(self.out, "incus-base", incusimage.BASE_IDENTITY, incusimage.fixture("scan"))
        with self.assertRaisesRegex(commands.Failed, "several builds of incus-base"):
            self.locate(entry=entry_for(self.base, incusimage.BASE_IDENTITY))

    def test_the_digest_the_plan_names_picks_one_of_several(self) -> None:
        write_image(self.out, "incus-base", incusimage.BASE_IDENTITY, incusimage.fixture("scan"))
        self.assertEqual(self.locate(), self.parent)

    def test_a_pair_whose_rootfs_changed_is_refused(self) -> None:
        self.base.rootfs.write_bytes(incusimage.fixture("scan"))
        with self.assertRaisesRegex(commands.Failed, "does not match the digest in its name"):
            self.locate()

    def test_a_missing_parent_fails_naming_the_digest_and_the_places_and_asks_no_registry(self) -> None:
        empty = self.dir / "empty"
        empty.mkdir()
        registry = published.OciTarget("registry.example", "images/incus-base")
        with self.assertRaises(commands.Failed) as caught:
            self.locate(out=empty, directories=[self.dir / "nowhere"], registries=[registry])
        message = str(caught.exception)
        for part in ("incus-base", self.base.fingerprint, str(empty), str(self.dir / "nowhere"), "--parents"):
            self.assertIn(part, message)


# ---- the parent's device nodes --------------------------------------------------------------------


def device_tarball(members: Sequence[tarfile.TarInfo]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for member in members:
            archive.addfile(member, io.BytesIO(b"x\n") if member.isfile() else None)
    return gzip.compress(raw.getvalue(), mtime=0)


def member(
    name: str, kind: bytes, mode: int = 0o644, uid: int = 0, gid: int = 0, major: int = 0, minor: int = 0
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode, info.uid, info.gid, info.devmajor, info.devminor = mode, uid, gid, major, minor
    info.size = 2 if kind == tarfile.REGTYPE else 0
    return info


class DeviceLinesTest(TemporaryTest):
    def core_parent(self, members: Sequence[tarfile.TarInfo]) -> parents.ParentArtifact:
        data = device_tarball(members)
        name = published.artifact_name("core", "trixie", "amd64", IDENTITY, sha(data), "tar.gz")
        (self.out / name).write_bytes(data)
        return parents.describe_core(self.out / name)

    def test_a_core_tarballs_device_nodes_are_listed_with_absolute_paths(self) -> None:
        parent = self.core_parent(
            [
                member("./", tarfile.DIRTYPE, 0o755),
                member("./etc/os-release", tarfile.REGTYPE),
                member("./dev/", tarfile.DIRTYPE, 0o755),
                member("./dev/null", tarfile.CHRTYPE, 0o666, 0, 0, 1, 3),
                member("dev/loop0", tarfile.BLKTYPE, 0o660, 0, 6, 7, 0),
                member("./dev/fifo", tarfile.FIFOTYPE, 0o600),
                member("./dev/wide/", tarfile.CHRTYPE, 0o600, 1000, 2000, 259, 300),
            ]
        )
        self.assertEqual(
            run.device_lines(parent),
            ["/dev/null c 666 0 0 1 3\n", "/dev/loop0 b 660 0 6 7 0\n", "/dev/wide c 600 1000 2000 259 300\n"],
        )

    def test_a_core_tarball_without_device_nodes_lists_none(self) -> None:
        parent = self.core_parent([member("./etc/os-release", tarfile.REGTYPE)])
        self.assertEqual(run.device_lines(parent), [])

    def test_a_device_node_whose_path_has_white_space_is_refused(self) -> None:
        parent = self.core_parent([member("./dev/odd name", tarfile.CHRTYPE, 0o600, 0, 0, 1, 1)])
        with self.assertRaisesRegex(ValueError, "white space"):
            run.device_lines(parent)

    def test_an_incus_parents_device_nodes_are_read_from_its_squashfs(self) -> None:
        image = write_image(self.out, "incus-base", incusimage.BASE_IDENTITY, incusimage.fixture("incus-root"))
        self.assertEqual(
            run.device_lines(described(image)),
            ["/dev/loop0 b 660 0 6 7 0\n", "/dev/null c 666 0 0 1 3\n", "/dev/wide c 600 1000 2000 259 300\n"],
        )

    def test_the_other_kinds_of_a_squashfs_are_not_device_nodes(self) -> None:
        image = write_image(self.out, "incus-base", incusimage.BASE_IDENTITY, incusimage.fixture("scan"))
        lines = run.device_lines(described(image))
        self.assertEqual({line.split(" ")[0] for line in lines}, {"/dev/loop0", "/dev/null", "/dev/wide"})
        self.assertEqual(len(lines), 3)  # not the fifo or the socket beside them

    def test_a_rootfs_that_is_not_a_squashfs_fails_naming_it(self) -> None:
        image = write_image(self.out, "incus-base", incusimage.BASE_IDENTITY, b"not a squashfs image at all" * 8)
        with self.assertRaisesRegex(commands.Failed, r"\.rootfs\.squashfs: "):
            run.device_lines(described(image))

    def test_a_parent_known_only_by_name_has_no_files_to_list(self) -> None:
        unknown = parents.ParentArtifact("core", "core", "core.tar.gz", "0" * 64, None)
        with self.assertRaisesRegex(commands.Failed, "its files are needed"):
            run.device_lines(unknown)


# ---- the records of an image ----------------------------------------------------------------------


class ImageRecordsTest(unittest.TestCase):
    def records(
        self, files: Sequence[tuple[str, str]] = (), packages: Sequence[Package] = BASE
    ) -> list[dict[str, object]]:
        plan = planfile.parse_plan(
            json.loads(incusimage.plan_text({"incus-base": (incusimage.BASE_IDENTITY, "core", "incus")}))
        )
        entry = plan["images"]["incus-base"]
        entry["recipe"] = "34" * 32
        with mock.patch.dict(os.environ, {}, clear=True):
            statements = run.image_records(
                image="incus-base",
                entry=entry,
                plan=plan,
                lock=example_lock(),
                name="incus-base-trixie-amd64-cdcdcdcdcdcdcdcd-123456789abc",
                digest="12" * 32,
                packages=packages,
                source=None,
                releases=[],
                builder_=run.Builder("ghcr.io/example/builder:1", "sha256:" + "56" * 32, None),
                started="2026-11-21T02:17:05Z",
                finished="2026-11-21T02:19:41Z",
                ancestors=[],
                files=files,
            )
        return [{str(key): value for key, value in one.items()} for one in statements]

    def test_the_image_alone_is_the_one_subject_of_both_statements(self) -> None:
        provenance, sbom = self.records()
        expected = [{"name": "incus-base-trixie-amd64-cdcdcdcdcdcdcdcd-123456789abc", "digest": {"sha256": "12" * 32}}]
        self.assertEqual(provenance["subject"], expected)
        self.assertEqual(sbom["subject"], expected)

    def test_the_files_of_an_image_are_subjects_after_the_first_in_both_statements(self) -> None:
        files = [("incus-base.incus.tar.gz", "aa" * 32), ("incus-base.rootfs.squashfs", "bb" * 32)]
        provenance, sbom = self.records(files)
        expected = [
            {"name": "incus-base-trixie-amd64-cdcdcdcdcdcdcdcd-123456789abc", "digest": {"sha256": "12" * 32}},
            {"name": "incus-base.incus.tar.gz", "digest": {"sha256": "aa" * 32}},
            {"name": "incus-base.rootfs.squashfs", "digest": {"sha256": "bb" * 32}},
        ]
        self.assertEqual(provenance["subject"], expected)
        self.assertEqual(sbom["subject"], expected)

    def test_a_provenance_and_an_sbom_are_made_in_that_order(self) -> None:
        provenance, sbom = self.records()
        self.assertEqual(provenance["predicateType"], PROVENANCE_PREDICATE)
        self.assertEqual(sbom["predicateType"], SPDX_PREDICATE)


class IncusRemovedFromTest(unittest.TestCase):
    """The parent's paths the new root does not hold, as the build records them (removedFromParent)."""

    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.rootfs = self.root / "child.rootfs.squashfs"
        self.rootfs.write_bytes(incusimage.fixture("incus-root"))

    @staticmethod
    def paths(image: bytes) -> set[str]:
        return {entry.path for entry in squashfs.entries(io.BytesIO(image))}

    def test_a_core_parent_s_paths_the_child_lacks_are_listed_and_the_root_never(self) -> None:
        kept = sorted(self.paths(incusimage.fixture("incus-root")) - {"/"})[0]
        tarball = self.root / "core.tar.gz"
        with tarfile.open(tarball, "w:gz") as archive:
            for name, kind in ((".", tarfile.DIRTYPE), ("." + kept, tarfile.REGTYPE), ("./gone", tarfile.DIRTYPE)):
                member = tarfile.TarInfo(name)
                member.type = kind
                archive.addfile(member, io.BytesIO(b"") if kind == tarfile.REGTYPE else None)
            gone = tarfile.TarInfo("./gone/file")
            archive.addfile(gone, io.BytesIO(b""))
        parent = parents.ParentArtifact("core", "core", tarball.name, "a" * 64, tarball)
        self.assertEqual(run.incus_removed_from(parent, self.rootfs), ["/gone", "/gone/file"])

    def test_an_incus_parent_is_read_from_its_squashfs(self) -> None:
        image = write_image(self.root, "incus-base", IDENTITY, incusimage.fixture("scan"))
        parent = parents.describe_incus(image.metadata)
        expected = sorted(self.paths(incusimage.fixture("scan")) - self.paths(incusimage.fixture("incus-root")) - {"/"})
        self.assertTrue(expected)
        self.assertEqual(run.incus_removed_from(parent, self.rootfs), expected)

    def test_a_root_that_cannot_be_read_fails_with_the_parent_named(self) -> None:
        tarball = self.root / "core.tar.gz"
        tarball.write_bytes(b"not a tarball")
        parent = parents.ParentArtifact("core", "core", tarball.name, "a" * 64, tarball)
        with self.assertRaisesRegex(commands.Failed, "the roots of core and its Incus child cannot be compared"):
            run.incus_removed_from(parent, self.rootfs)


if __name__ == "__main__":
    unittest.main()
