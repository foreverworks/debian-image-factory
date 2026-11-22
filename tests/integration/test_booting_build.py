"""The installer and os kinds' builds, end to end on the example definition at the example lock's snapshot.

Core, the example `installer` (a kernel, openssh-server and the kind defaults, with a hook) and the example
`os` (a kernel, grub-efi-amd64, openssh-server, baseline-except-security sources) are built in one run. A copy
of the examples adds a child of each (`os-tools` on os, `installer-tools` on the installer, each installing
jq), built in a second run that finds its parents in the first one's output, so an os parent's tarball and an
installer parent's kit are unpacked for real. Needs docker, the builder image (`scripts/builder build`) and
network access to snapshot.debian.org.

The installer and the os are then built a second time from the same plan, and their digests must be equal:
the engine revision guard below records them (DESIGN 12), and `test --check byte-equal --twin` compares them.

What it checks: the os tarball holds the kernel and the initrd its postinst made in /boot; the kit's layout,
kit.json and its initrd (newc, /init, sorted, inodes in order); a booting root's machine ID waits for the
first boot and holds no SSH host keys, while Debian's own first-boot unit makes them; the os image carries
its own apt sources pinned to the baseline and nowhere the build snapshot; the records' subjects and
ancestors; the SBOM lists the planned packages.
"""

import gzip
import hashlib
import json
import os
import shutil
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path

from debian_image_factory import ENGINE, published, records
from debian_image_factory.build import initrd
from tests.support import builder_images

from .test_core_build import EXAMPLES, ROOT, factory, files, sha256_of

EPOCH = 1754697600
BASELINE = "20261108T000000Z"

EXPECTED_OS: dict[int, str] = {1: "47b403d5e3f21d01f247a69945ee6bdeada5290650db466872f101a42707497a"}
EXPECTED_INSTALLER: dict[int, str] = {1: "204e53953a4da90061aef02e216139dc9f2b44752138e66bd6327f6590a8916f"}
"""The engine revision guard (DESIGN 12) for the example `os` and `installer` at the example lock's snapshot, the
sha256 of the file per engine revision, as `test_core_build.EXPECTED_CORE` does for core. A change to these bytes
without a raised ENGINE fails here; a change to the examples, the lock or the builder updates them in the same
commit."""

CHILDREN = """
[images.os-tools]
kind = "os"
parent = "os"
packages = ["jq"]
apt_sources = "baseline-except-security"

[images.installer-tools]
kind = "installer"
parent = "installer"
packages = ["jq"]
"""


def artifact_of(out: Path, image: str, ext: str) -> Path:
    found = []
    for path in out.iterdir():
        parts = published.parse_artifact_name(path.name)
        if parts is not None and (parts.image, parts.ext) == (image, ext):
            found.append(path)
    if len(found) != 1:
        raise AssertionError(f"{out} holds {len(found)} {ext} artifacts of {image}, expected one")
    return found[0]


def tar_members(path: Path) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(path, mode="r:*") as archive:
        return {member.name: member for member in archive}


def tar_file(path: Path, name: str) -> bytes:
    with tarfile.open(path, mode="r:*") as archive:
        handle = archive.extractfile(name)
        assert handle is not None
        return handle.read()


def kit_initrd(kit: Path, scratch: Path) -> Path:
    target = scratch / f"{kit.name}.initrd.img"
    if not target.exists():
        target.write_bytes(tar_file(kit, "initrd.img"))
    return target


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class BootingBuildTest(unittest.TestCase):
    work: Path
    scratch: tempfile.TemporaryDirectory[str]
    plan: dict[str, object]
    children_plan: dict[str, object]

    @classmethod
    def setUpClass(cls) -> None:
        tag = builder_images.image()
        (ROOT / "dist").mkdir(exist_ok=True)
        cls.scratch = tempfile.TemporaryDirectory(prefix="integration-booting-", dir=ROOT / "dist")
        cls.work = Path(cls.scratch.name)
        plan = cls.work / "plan.json"
        factory("plan", *files(), "--out", str(plan))
        factory("fetch", str(plan))
        cls.plan = json.loads(plan.read_text())
        images = ["--image", "core", "--image", "installer", "--image", "os"]
        factory("build", str(plan), "--out", str(cls.work / "out1"), *images, "--builder-image", tag, *files())
        # The same plan again, for the installer and the os only: their parent core is out1's.
        factory(
            "build", str(plan), "--out", str(cls.work / "out3"), "--image", "installer", "--image", "os",
            "--parents", f"dir://{cls.work / 'out1'}", "--builder-image", tag, *files(),
        )  # fmt: skip
        children = cls.work / "children"
        shutil.copytree(EXAMPLES, children)
        with (children / "factory.toml").open("a") as handle:
            handle.write(CHILDREN)
        child_files = ["--lock", str(children / "lock.json"), "--definition", str(children / "factory.toml")]
        children_plan = cls.work / "children-plan.json"
        factory("plan", *child_files, "--out", str(children_plan))
        factory("fetch", str(children_plan))
        cls.children_plan = json.loads(children_plan.read_text())
        factory(
            "build", str(children_plan), "--out", str(cls.work / "out2"),
            "--image", "os-tools", "--image", "installer-tools",
            "--parents", f"dir://{cls.work / 'out1'}", "--builder-image", tag, *child_files,
        )  # fmt: skip

    @classmethod
    def tearDownClass(cls) -> None:
        cls.scratch.cleanup()

    def os_tarball(self, out: str = "out1", image: str = "os") -> Path:
        return artifact_of(self.work / out, image, "tar.gz")

    def kit(self, out: str = "out1", image: str = "installer") -> Path:
        return artifact_of(self.work / out, image, "tar")

    def statements(self, path: Path) -> list[dict[str, object]]:
        return records.decode_statements((path.parent / published.records_name_for(sha256_of(path))).read_text())

    def dependency_names(self, path: Path) -> list[tuple[str, str]]:
        predicate = self.statements(path)[0]["predicate"]
        assert isinstance(predicate, dict)
        found = predicate["buildDefinition"]["resolvedDependencies"]
        return [(str(one["name"]), one["digest"]["sha256"]) for one in found if "name" in one]

    def sbom_packages(self, path: Path) -> list[list[str]]:
        predicate = self.statements(path)[1]["predicate"]
        assert isinstance(predicate, dict)
        rows = []
        for package in predicate["packages"]:
            refs = package.get("externalRefs", [])
            locator = refs[0]["referenceLocator"] if refs else ""
            if locator.startswith("pkg:deb/"):
                arch = locator.split("arch=", 1)[1].split("&", 1)[0]
                rows.append([package["name"], package["versionInfo"], arch])
        return sorted(rows)

    def planned(self, plan: dict[str, object], image: str) -> list[list[str]]:
        images = plan["images"]
        assert isinstance(images, dict)
        return sorted([str(part) for part in row] for row in images[image]["packages"])

    def initrd_members(self, kit: Path, contents: tuple[str, ...] = ()) -> list[initrd.Member]:
        return initrd.members(str(kit_initrd(kit, self.work)), contents=contents)

    # ---- the os tarball ---------------------------------------------------------------------------

    def test_the_os_tarball_holds_the_kernel_and_the_initrd_its_postinst_made(self) -> None:
        members = tar_members(self.os_tarball())
        kernels = [name for name in members if name.startswith("boot/vmlinuz-")]
        self.assertEqual(len(kernels), 1, kernels)
        version = kernels[0].removeprefix("boot/vmlinuz-")
        self.assertTrue(members[f"boot/initrd.img-{version}"].isfile())
        self.assertGreater(members[f"boot/initrd.img-{version}"].size, 1_000_000)
        self.assertIn(f"usr/lib/modules/{version}/modules.dep", members)
        self.assertIn("usr/lib/grub/x86_64-efi/linux.mod", members)  # grub-efi-amd64, for os-boot's grub-mkstandalone

    def test_the_os_tarball_is_the_whole_root_as_layer_py_writes_it(self) -> None:
        members = list(tar_members(self.os_tarball()).values())
        names = [member.name for member in members]
        self.assertEqual(names, sorted(names, key=lambda name: name.split("/")), "parents before children, sorted")
        for expected in ("etc/os-release", "usr/bin/apt", "var/lib/dpkg/status", "usr/sbin/sshd", "usr/bin/sudo"):
            self.assertIn(expected, names)
        self.assertEqual({(member.uname, member.gname) for member in members}, {("", "")})
        self.assertTrue(all(member.mtime <= EPOCH for member in members))
        for gone in ("etc/hostname", "etc/resolv.conf", "var/lib/dbus/machine-id", "usr/sbin/policy-rc.d"):
            self.assertNotIn(gone, names)
        # apt's archive cache keeps only its lock and partial directory, as in core
        self.assertFalse([name for name in names if name.startswith(("run/factory", "tmp/")) or name.endswith(".deb")])
        with gzip.open(self.os_tarball()) as handle:
            header = handle.read(512)
        self.assertNotEqual(header[:5], b"./\0\0\0", "member names carry no ./")

    def test_the_os_image_carries_its_own_baseline_sources_and_never_the_build_snapshot(self) -> None:
        sources = tar_file(self.os_tarball(), "etc/apt/sources.list.d/debian.sources").decode()
        paragraphs = sources.split("\n\n")
        self.assertEqual(len(paragraphs), 2, sources)
        self.assertIn(f"Snapshot: {BASELINE}", paragraphs[0])
        self.assertIn("deb.debian.org", paragraphs[0])
        self.assertNotIn("Snapshot:", paragraphs[1], "security stays live")
        self.assertNotIn("etc/apt/sources.list", tar_members(self.os_tarball()))
        snapshot = str(self.plan["snapshot"]).encode()
        for path in (self.os_tarball(), self.os_tarball("out2", "os-tools")):
            with gzip.open(path) as handle:
                tail = b""
                while block := handle.read(1 << 22):
                    self.assertNotIn(snapshot, tail + block, f"{path.name} holds the build snapshot ID")
                    tail = block[-len(snapshot) :]

    # ---- byte for byte ----------------------------------------------------------------------------

    def test_two_builds_of_the_os_and_the_installer_from_one_plan_give_the_same_bytes(self) -> None:
        for first, second in (
            (self.os_tarball(), self.os_tarball("out3")),
            (self.kit(), self.kit("out3")),
        ):
            self.assertEqual(first.name, second.name)
            self.assertEqual(sha256_of(first), sha256_of(second), f"two builds of {first.name} differ")

    def test_the_byte_equal_check_passes_on_the_second_build(self) -> None:
        printed = factory("test", str(self.work / "out3"), "--check", "byte-equal", "--twin", str(self.work / "out1"))
        self.assertIn("os: byte-equal PASSED", printed)
        self.assertIn("installer: byte-equal PASSED", printed)

    def test_engine_revision_guard(self) -> None:
        for label, path, expected in (
            ("os", self.os_tarball(), EXPECTED_OS),
            ("installer", self.kit(), EXPECTED_INSTALLER),
        ):
            self.assertIn(ENGINE, expected, f"record the example {label}'s digest for engine revision {ENGINE}")
            self.assertEqual(
                sha256_of(path),
                expected[ENGINE],
                f"the example {label}'s bytes changed without a raised engine revision",
            )

    # ---- the installer kit ------------------------------------------------------------------------

    def test_the_kit_holds_kit_json_the_kernel_and_the_initrd_in_order(self) -> None:
        kit = self.kit()
        with tarfile.open(kit, mode="r:") as archive:
            members = archive.getmembers()
        self.assertEqual([member.name for member in members], ["kit.json", "vmlinuz", "initrd.img"])
        for member in members:
            self.assertEqual(
                (member.mode, member.uid, member.gid, member.uname, member.gname, member.mtime, member.isfile()),
                (0o644, 0, 0, "", "", EPOCH, True),
            )
        described = initrd.read_kit(str(kit))
        raw = tar_file(kit, "kit.json")
        self.assertEqual(raw, json.dumps(described, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        self.assertEqual((described["schema"], described["image"]), (1, "installer"))
        kernel = described["kernel"]
        # the same kernel package as the os image's: its vmlinuz byte for byte
        self.assertEqual(tar_file(kit, "vmlinuz"), tar_file(self.os_tarball(), f"boot/vmlinuz-{kernel}"))
        self.assertEqual(tar_file(kit, "initrd.img")[:3], b"\x1f\x8b\x08")
        self.assertEqual(tar_file(kit, "initrd.img")[4:8], b"\0\0\0\0", "a zero gzip time stamp")

    def test_the_initrd_is_the_whole_root_with_init_as_systemd(self) -> None:
        members = self.initrd_members(self.kit(), ("etc/machine-id",))
        names = [member.name for member in members]
        self.assertEqual(names[0], ".")
        self.assertEqual(names, sorted(names, key=lambda name: () if name == "." else tuple(name.split("/"))))
        by_name = {member.name: member for member in members}
        init = by_name["init"]
        self.assertTrue(stat.S_ISLNK(init.mode))
        self.assertEqual(init.link, "/sbin/init")
        self.assertEqual(by_name["usr/sbin/init"].link, "../lib/systemd/systemd")
        kernel = initrd.read_kit(str(self.kit()))["kernel"]
        self.assertIn(f"boot/vmlinuz-{kernel}", by_name)
        self.assertIn(f"usr/lib/modules/{kernel}/modules.dep", by_name)
        self.assertIn("usr/sbin/sshd", by_name)
        self.assertTrue(all(member.mtime <= EPOCH for member in members))
        inodes = [member.ino for member in members]
        self.assertEqual(sorted(set(inodes)), list(range(1, len(set(inodes)) + 1)), "inode numbers in order")
        self.assertFalse([name for name in names if name.startswith("usr/share/doc/") and name.count("/") > 3])

    def test_hard_links_in_the_initrd_share_one_inode_and_the_content_comes_last(self) -> None:
        members = self.initrd_members(self.kit())
        groups: dict[int, list[initrd.Member]] = {}
        for member in members:
            if stat.S_ISREG(member.mode) and member.nlink > 1:
                groups.setdefault(member.ino, []).append(member)
        self.assertTrue(groups, "Debian's root has hard links (perl, for one)")
        for group in groups.values():
            self.assertEqual(len(group), group[0].nlink)
            self.assertTrue(all(one.size == 0 for one in group[:-1]))

    # ---- what every booting root holds ------------------------------------------------------------

    def test_a_booting_root_waits_for_its_first_boot_and_holds_no_host_keys(self) -> None:
        os_members = tar_members(self.os_tarball())
        self.assertEqual(tar_file(self.os_tarball(), "etc/machine-id"), b"uninitialized\n")
        self.assertEqual(os_members["etc/machine-id"].mode, 0o444)
        initrd_members = {member.name: member for member in self.initrd_members(self.kit(), ("etc/machine-id",))}
        self.assertEqual(initrd_members["etc/machine-id"].data, b"uninitialized\n")
        for names in (list(os_members), list(initrd_members)):
            self.assertFalse([name for name in names if name.startswith("etc/ssh/ssh_host_")])
            # Debian's own first-boot unit makes the host keys, so the factory adds none
            self.assertIn("etc/systemd/system/ssh.service.wants/sshd-keygen.service", names)
            self.assertNotIn("etc/systemd/system/factory-ssh-host-keys.service", names)

    # ---- records ----------------------------------------------------------------------------------

    def test_the_kits_records_name_the_kit_then_its_kernel_and_initrd(self) -> None:
        kit = self.kit()
        expected = [
            {"name": kit.name, "digest": {"sha256": sha256_of(kit)}},
            {"name": "vmlinuz", "digest": {"sha256": hashlib.sha256(tar_file(kit, "vmlinuz")).hexdigest()}},
            {"name": "initrd.img", "digest": {"sha256": hashlib.sha256(tar_file(kit, "initrd.img")).hexdigest()}},
        ]
        for statement in self.statements(kit):
            self.assertEqual(statement["subject"], expected)
        path = self.os_tarball()
        for statement in self.statements(path):
            self.assertEqual(statement["subject"], [{"name": path.name, "digest": {"sha256": sha256_of(path)}}])

    def test_provenance_names_the_parent_and_every_ancestor_up_to_core(self) -> None:
        core = sha256_of(artifact_of(self.work / "out1", "core", "tar.gz"))
        self.assertEqual(self.dependency_names(self.kit())[-1], ("parent: core", core))
        self.assertEqual(self.dependency_names(self.os_tarball())[-1], ("parent: core", core))
        self.assertEqual(
            self.dependency_names(self.os_tarball("out2", "os-tools"))[-2:],
            [("parent: os", sha256_of(self.os_tarball())), ("ancestor: core", core)],
        )
        self.assertEqual(
            self.dependency_names(self.kit("out2", "installer-tools"))[-2:],
            [("parent: installer", sha256_of(self.kit())), ("ancestor: core", core)],
        )

    def test_the_sbom_lists_the_planned_packages(self) -> None:
        self.assertEqual(self.sbom_packages(self.os_tarball()), self.planned(self.plan, "os"))
        self.assertEqual(self.sbom_packages(self.kit()), self.planned(self.plan, "installer"))
        children = self.children_plan
        self.assertEqual(self.sbom_packages(self.os_tarball("out2", "os-tools")), self.planned(children, "os-tools"))
        self.assertEqual(
            self.sbom_packages(self.kit("out2", "installer-tools")), self.planned(children, "installer-tools")
        )

    # ---- children of an os image and of an installer ----------------------------------------------

    def test_children_hold_their_parents_root_and_their_own_package(self) -> None:
        parent = tar_members(self.os_tarball())
        child = tar_members(self.os_tarball("out2", "os-tools"))
        self.assertIn("usr/bin/jq", child)
        self.assertNotIn("usr/bin/jq", parent)
        kernel = next(name for name in parent if name.startswith("boot/vmlinuz-"))
        self.assertEqual(child[kernel].size, parent[kernel].size)
        self.assertEqual(tar_file(self.os_tarball("out2", "os-tools"), "etc/machine-id"), b"uninitialized\n")
        kit = self.kit("out2", "installer-tools")
        names = [member.name for member in self.initrd_members(kit)]
        self.assertIn("usr/bin/jq", names)
        self.assertEqual(names.count("init"), 1)
        parent_names = {member.name for member in self.initrd_members(self.kit())}
        self.assertEqual(parent_names - set(names), set(), "the child's initrd holds every path of its parent's")
        self.assertEqual(initrd.read_kit(str(kit))["kernel"], initrd.read_kit(str(self.kit()))["kernel"])

    def test_a_build_leaves_no_scratch_directory_behind(self) -> None:
        for out in ("out1", "out2"):
            self.assertEqual(sorted(path.name for path in (self.work / out).iterdir() if path.name.startswith(".")), [])


if __name__ == "__main__":
    unittest.main()
