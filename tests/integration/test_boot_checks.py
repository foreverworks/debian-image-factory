"""The installer and OS checks on real artifacts, boots included: a small OS root and installer kit built with
mmdebstrap at the builder's snapshot (`tests/support/bootimages.py`), tested by `test` with QEMU in the boot
checks' image, KVM when /dev/kvm opens and TCG otherwise. Prints each artifact's wall time.

Needs docker, network access to snapshot.debian.org (for the fixture) and about 3 GiB of memory per boot,
two boots at once. Builds the builder and boot images (`scripts/builder build`, `scripts/builder vm`).
"""

import io
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import ClassVar

from debian_image_factory import debian, published
from debian_image_factory.checks import command, kit, packages, tarball, vmrun
from debian_image_factory.checks.model import TWO_CLONES
from debian_image_factory.commands import Sources
from debian_image_factory.planfile import read_plan
from tests.support import bootimages, builder_images
from tests.support.ocimage import entry, plan_json
from tests.support.rootfs import sbom_line

ROOT = Path(__file__).resolve().parent.parent.parent
STATIC = ("no-build-snapshot", "no-machine-identity", "package-set", "sbom-complete")
PLAN_SNAPSHOT = "20261101T000000Z"
"""A build snapshot the fixture was not built at: `no-build-snapshot` must find it nowhere."""


def installed_in_root(path: Path) -> list[tuple[str, str, str]]:
    """The packages of an OS root tarball, read the way the checks read it."""
    scanned = tarball.scan_tarball(path, frozenset({packages.STATUS_PATH}), None, False)
    return debian.installed_packages(scanned.contents[packages.STATUS_PATH].decode())


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class BootChecksTest(unittest.TestCase):
    scratch: ClassVar[tempfile.TemporaryDirectory[str]]
    built: ClassVar[bootimages.Built]
    packages: ClassVar[list[tuple[str, str, str]]]
    vm_image: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        builder = builder_images.image()
        cls.vm_image = builder_images.image("vm")
        # Under dist/, not /tmp: the docker daemon mounts these paths from its own view of the host, where
        # a private /tmp (systemd PrivateTmp, a sandbox) does not exist.
        (ROOT / "dist").mkdir(exist_ok=True)
        cls.scratch = tempfile.TemporaryDirectory(prefix="integration-boot-", dir=ROOT / "dist")
        build = Path(cls.scratch.name) / "build"
        build.mkdir()
        started = time.monotonic()
        cls.built = bootimages.build(build, builder)
        print(f"\nboot fixture built in {time.monotonic() - started:.0f} s", file=sys.stderr)
        cls.packages = installed_in_root(cls.built.os_root)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.scratch.cleanup()

    def out_with(self, kind: str, artifact: Path, digest: str, checks: tuple[str, ...]) -> Path:
        """An output directory holding the one artifact, a plan naming it, and its SBOM."""
        out = Path(self.scratch.name) / kind
        out.mkdir()
        shutil.move(artifact, out / artifact.name)
        image = entry(kind, identity=bootimages.IDENTITY, checks=checks, packages=self.packages)
        (out / "plan.json").write_text(plan_json({kind: image}, snapshot=PLAN_SNAPSHOT))
        more = []
        if kind == "installer":
            facts = kit.read_kit(out / artifact.name)
            more = [(name, facts.files[name][0]) for name in ("vmlinuz", "initrd.img")]
        line = sbom_line(artifact.name, digest, self.packages, more_subjects=more)
        (out / published.records_name_for(digest)).write_text(line)
        return out

    def run_checks(self, out: Path, checks: tuple[str, ...]) -> str:
        text = io.StringIO()
        effects = command.Effects(vm=vmrun.Vm(image=self.vm_image))
        started = time.monotonic()
        status = command.test_command(out, checks, Sources(), text, effects)
        accel = "KVM" if vmrun.kvm_usable() else "TCG"
        print(f"{out.name}: {', '.join(checks)} in {time.monotonic() - started:.0f} s ({accel})", file=sys.stderr)
        self.assertEqual(status, 0, text.getvalue())
        return text.getvalue()

    def assert_all_passed(self, text: str, image: str, checks: tuple[str, ...]) -> None:
        found = {line.split(" ")[1]: line for line in text.splitlines() if line.startswith(f"{image}: ")}
        self.assertEqual(set(found), set(checks), text)
        for check, line in found.items():
            self.assertTrue(line.startswith(f"{image}: {check} PASSED"), line)

    def test_the_installer_kit_boots_twice_with_two_identities(self) -> None:
        checks = ("installer-boot", TWO_CLONES, *STATIC)
        out = self.out_with("installer", self.built.kit, self.built.kit_digest, checks)
        self.assertEqual(read_plan(out / "plan.json")["images"]["installer"]["kind"], "installer")
        text = self.run_checks(out, checks)
        self.assert_all_passed(text, "installer", checks)
        self.assertEqual(list(out.glob("*.serial.log")), [], "a passing boot keeps no log")

    def test_the_os_root_boots_twice_by_uefi_with_two_identities(self) -> None:
        checks = ("os-boot", TWO_CLONES, *STATIC)
        out = self.out_with("os", self.built.os_root, self.built.os_digest, checks)
        text = self.run_checks(out, checks)
        self.assert_all_passed(text, "os", checks)
        self.assertEqual(list(out.glob("*.serial.log")), [], "a passing boot keeps no log")


if __name__ == "__main__":
    unittest.main()
