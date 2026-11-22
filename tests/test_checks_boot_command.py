"""`test` on an output directory holding an OS root tarball and an installer kit built on core: the kind comes
from the plan entry, the file checks read the root (the kit's initrd), and the boot checks share boots,
here from a stand-in for QEMU."""

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

from debian_image_factory import published, records
from debian_image_factory.checks import command, vm, vmrun
from debian_image_factory.checks.model import NotRun
from debian_image_factory.commands import Sources
from debian_image_factory.planfile import read_plan
from tests.support import newc
from tests.support.ocimage import entry, plan_json
from tests.support.rootfs import ARCH, BASE, IDENTITY, SUITE, Entry, clean_files, rootfs, sbom_line, write_artifact

KERNEL = "6.12.0-1-amd64"
OS_IDENTITY = "12" * 32
KIT_IDENTITY = "34" * 32
BOOT_PACKAGES = (*BASE, ("linux-image-amd64", "6.12", "amd64"), ("openssh-server", "1:10.0", "amd64"))
OS_CHECKS = (
    "ancestry",
    "no-build-snapshot",
    "no-machine-identity",
    "os-boot",
    "package-set",
    "sbom-complete",
    "two-clones",
)
INSTALLER_CHECKS = tuple(sorted({*OS_CHECKS, "installer-boot"} - {"os-boot"}))


def parent_files() -> dict[str, Entry]:
    files = clean_files()
    files["./usr/"] = None
    files["./usr/bin/"] = None
    files["./usr/bin/core-tool"] = b"#!/bin/sh\n"
    return files


def child_files() -> dict[str, Entry]:
    files = parent_files()
    files["./boot/"] = None
    files[f"./boot/vmlinuz-{KERNEL}"] = b"kernel"
    files["./var/lib/dpkg/status"] = status(BOOT_PACKAGES)
    return files


def status(packages: Sequence[tuple[str, str, str]]) -> bytes:
    return "\n".join(
        f"Package: {n}\nStatus: install ok installed\nVersion: {v}\nArchitecture: {a}\n" for n, v, a in packages
    ).encode()


def initrd_of(files: Mapping[str, Entry]) -> bytes:
    items = [newc.symlink("init", "/sbin/init")]
    for name, content in files.items():
        stored = name.removeprefix("./").rstrip("/") or "."
        assert content is None or isinstance(content, bytes), "the fixtures hold no links"
        items.append(newc.directory(stored) if content is None else newc.file(stored, content))
    return newc.initrd(items)


def report(machine: str, ssh: str, kernel: str = KERNEL) -> vm.Boot:
    return vm.boot_of(0, f"FACTORY-REPORT kernel={kernel} machine-id={machine} ssh={ssh} state=running\n", 600)


class Boots:
    """A stand-in for QEMU: the boots each call gives, and the calls made."""

    def __init__(self, boots: list[vm.Boot] | vmrun.Unready | None = None) -> None:
        self.boots = boots if boots is not None else [report("a" * 32, "b" * 64), report("c" * 32, "d" * 64)]
        self.calls: list[tuple[str, int]] = []

    def installer(self, path: Path, count: int, machine: vmrun.Vm) -> list[vm.Boot] | vmrun.Unready:
        self.calls.append((path.name, count))
        return self.boots if isinstance(self.boots, vmrun.Unready) else self.boots[:count]

    def os(self, path: Path, facts: vmrun.RootFacts, count: int, machine: vmrun.Vm) -> list[vm.Boot] | vmrun.Unready:
        self.calls.append((path.name, count))
        assert facts.kernels == (KERNEL,)
        return self.boots if isinstance(self.boots, vmrun.Unready) else self.boots[:count]


class Out:
    def __init__(self, root: Path, child: Mapping[str, Entry] | None = None) -> None:
        self.root = root
        core_path, self.core_digest = write_artifact(root, parent_files(), IDENTITY)
        files = child if child is not None else child_files()
        data = rootfs(files)
        self.os_digest = hashlib.sha256(data).hexdigest()
        self.os_path = root / published.artifact_name("os", SUITE, ARCH, OS_IDENTITY, self.os_digest, "tar.gz")
        self.os_path.write_bytes(data)
        initrd = initrd_of(files)
        vmlinuz = b"kernel"
        sums = {name: hashlib.sha256(blob).hexdigest() for name, blob in (("vmlinuz", vmlinuz), ("initrd.img", initrd))}
        manifest = {
            "schema": 1,
            "image": "installer",
            "kernel": KERNEL,
            "files": {
                name: {"sha256": sums[name], "size": len(blob)}
                for name, blob in (("vmlinuz", vmlinuz), ("initrd.img", initrd))
            },
        }
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, blob in (
                ("kit.json", json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"),
                ("vmlinuz", vmlinuz),
                ("initrd.img", initrd),
            ):
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(blob), 0o644
                archive.addfile(info, io.BytesIO(blob))
        kit = raw.getvalue()
        self.kit_digest = hashlib.sha256(kit).hexdigest()
        self.kit_path = root / published.artifact_name("installer", SUITE, ARCH, KIT_IDENTITY, self.kit_digest, "tar")
        self.kit_path.write_bytes(kit)
        images = {
            "core": entry("core", identity=IDENTITY),
            "os": entry("os", parent="core", identity=OS_IDENTITY, checks=OS_CHECKS, packages=BOOT_PACKAGES),
            "installer": entry(
                "installer", parent="core", identity=KIT_IDENTITY, checks=INSTALLER_CHECKS, packages=BOOT_PACKAGES
            ),
        }
        (root / "plan.json").write_text(plan_json(images))
        self.core_path = core_path
        (root / published.records_name_for(self.os_digest)).write_text(
            sbom_line(self.os_path.name, self.os_digest, BOOT_PACKAGES)
        )
        (root / published.records_name_for(self.kit_digest)).write_text(
            sbom_line(
                self.kit_path.name,
                self.kit_digest,
                BOOT_PACKAGES,
                more_subjects=[("vmlinuz", sums["vmlinuz"]), ("initrd.img", sums["initrd.img"])],
            )
        )

    def run(self, boots: Boots, requested: Sequence[str] = (), parents: tuple[Path, ...] = ()) -> tuple[int, str]:
        out = io.StringIO()
        effects = command.Effects(
            clones_check=lambda path: NotRun("two-clones", "core is not tested here"),
            boot_installer=boots.installer,
            boot_os=boots.os,
            parents=parents,
        )
        status = command.test_command(self.root, requested, Sources(), out, effects)
        return status, out.getvalue()


def lines_of(text: str, image: str) -> dict[str, str]:
    found = {}
    for line in text.splitlines():
        if line.startswith(f"{image}: "):
            check, _, rest = line.removeprefix(f"{image}: ").partition(" ")
            found[check] = rest
    return found


class BootKindsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_discovery_tells_an_os_root_from_core_by_the_plan(self) -> None:
        out = Out(Path(self.tmp.name))
        found, skipped = command.find_artifacts(out.root, read_plan(out.root / "plan.json"))
        self.assertEqual(skipped, [])
        self.assertEqual({one.image: one.kind for one in found}, {"core": "core", "os": "os", "installer": "installer"})

    def test_good_artifacts_pass_every_check_with_two_boots_each(self) -> None:
        out = Out(Path(self.tmp.name))
        boots = Boots()
        status, text = out.run(boots)
        for image, checks in (("os", OS_CHECKS), ("installer", INSTALLER_CHECKS)):
            found = lines_of(text, image)
            self.assertEqual(set(found), set(checks), text)
            self.assertTrue(all(value == "PASSED" for value in found.values()), text)
        self.assertEqual(status, 0, text)
        self.assertEqual(sorted(boots.calls), sorted([(out.os_path.name, 2), (out.kit_path.name, 2)]))
        recorded = (out.root / f"{out.kit_digest}.intoto.jsonl").read_text()
        self.assertEqual(len(records.decode_statements(recorded)), 1 + len(INSTALLER_CHECKS))

    def test_one_boot_serves_the_boot_check_alone(self) -> None:
        out = Out(Path(self.tmp.name))
        boots = Boots()
        status, text = out.run(boots, ["os-boot", "installer-boot"])
        self.assertEqual(status, 0, text)
        self.assertEqual(sorted(count for _, count in boots.calls), [1, 1])

    def test_a_failed_boot_keeps_its_serial_logs_beside_the_artifact(self) -> None:
        out = Out(Path(self.tmp.name))
        status, text = out.run(Boots([report("a" * 32, "b" * 64), vm.boot_of(124, "stuck in initramfs\n", 600)]))
        self.assertEqual(status, 1)
        self.assertIn("two-clones FAILED: both-instances-reported: boot 2: no FACTORY-REPORT line", text)
        log = out.root / vm.log_name(out.os_path.name, 2)
        self.assertEqual(log.read_text(), "stuck in initramfs\n")
        self.assertIn("ending: stuck in initramfs", text)

    def test_no_boot_image_means_the_boot_checks_are_not_run(self) -> None:
        out = Out(Path(self.tmp.name))
        status, text = out.run(Boots(vmrun.Unready("the boot image is not here")), ["os-boot", "two-clones"])
        self.assertEqual(status, 0)
        self.assertIn("os: os-boot not run: the boot image is not here", text)

    def test_a_root_without_uefi_grub_fails_os_boot(self) -> None:
        out = Out(Path(self.tmp.name))
        status, text = out.run(Boots(vmrun.Unready("the OS has no grub-mkstandalone", True)), ["os-boot"])
        self.assertEqual(status, 1)
        self.assertIn("os: os-boot FAILED: bootable: the OS has no grub-mkstandalone", text)

    def test_a_parent_file_gone_fails_ancestry_and_a_parent_elsewhere_is_found_by_its_name(self) -> None:
        files = child_files()
        del files["./usr/bin/core-tool"]
        out = Out(Path(self.tmp.name), files)
        status, text = out.run(Boots(), ["ancestry"])
        self.assertEqual(status, 1)
        self.assertIn("/usr/bin/core-tool is in the parent", lines_of(text, "os")["ancestry"])
        self.assertIn("/usr/bin/core-tool is in the parent", lines_of(text, "installer")["ancestry"])
        elsewhere = Path(self.tmp.name) / "parents"
        elsewhere.mkdir()
        moved = elsewhere / out.core_path.name
        out.core_path.rename(moved)
        _, alone = out.run(Boots(), ["ancestry"])
        self.assertIn("not in the output and not given with --parent", alone)
        _, given = out.run(Boots(), ["ancestry"], parents=(moved,))
        self.assertIn("/usr/bin/core-tool is in the parent", lines_of(given, "os")["ancestry"])

    def test_a_kit_whose_subjects_are_wrong_fails_sbom_complete(self) -> None:
        out = Out(Path(self.tmp.name))
        (out.root / f"{out.kit_digest}.intoto.jsonl").write_text(
            sbom_line(out.kit_path.name, out.kit_digest, BOOT_PACKAGES)
        )
        status, text = out.run(Boots(), ["sbom-complete"])
        self.assertEqual(status, 1)
        self.assertIn("subjects-are-the-kit-files", lines_of(text, "installer")["sbom-complete"])
        self.assertEqual(lines_of(text, "os")["sbom-complete"], "PASSED")


if __name__ == "__main__":
    unittest.main()
