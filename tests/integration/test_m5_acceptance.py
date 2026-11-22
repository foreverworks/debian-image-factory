"""M5's acceptance (DESIGN 14), on the example definition with a real signed vendor repository.

The example's made-up vendor .deb is replaced by the GitHub CLI from its own apt repository: the lock pins
the vendor's keyring by sha256 (a trust root), takes the version the vendor's index lists now, and `lock
checksums` fills its sha256 from that index after checking the repository's signed InRelease. Then:

- with the flag on, core, the installer kit and the OS root are built and `test` runs every check of theirs,
  so installer-boot, os-boot and two-clones boot the real artifacts in QEMU (KVM when /dev/kvm opens, TCG
  otherwise), and the results are published to a `dir://` target;
- with the flag off, the plan against that target builds the installer and the OS again under new
  identities and reuses everything else, and the rebuilt kit and root no longer hold the vendor's package;
- with the baseline moved, the plan against the target builds the OS and nothing else.

Needs docker, network access to snapshot.debian.org and cli.github.com, and about 3 GiB of memory per boot.
Builds the builder and boot images (`scripts/builder build`, `scripts/builder vm`). Takes about 20 minutes
under TCG.
"""

import contextlib
import gzip
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import urllib.request
from pathlib import Path
from typing import ClassVar

import input_lock

from debian_image_factory import cli, debian
from debian_image_factory.build import initrd
from debian_image_factory.checks import packages, tarball

from .test_booting_build import artifact_of, tar_file
from .test_core_build import EXAMPLES, ROOT, factory

VENDOR = "https://cli.github.com/packages"
REGISTRY = f"{VENDOR}?suite=stable&components=main&binaryArch=amd64"
KEYRING_SHA256 = "6084d5d7bd8e288441e0e94fc6275570895da18e6751f70f057485dc2d1a811b"
"""The GitHub CLI's archive keyring, read 2026-11-22. A trust root: a rotated key fails this test loudly."""

MOVED_BASELINE = "20261115T000000Z"
"""A completed snapshot ID other than the example's baseline (20261108T000000Z)."""

BOOTING = ("installer", "os")
OTHERS = ("core", "oci-base", "node-26", "incus-base")


def scripts_builder(command: str) -> str:
    ran = subprocess.run([str(ROOT / "scripts" / "builder"), command], check=True, capture_output=True, text=True)
    return ran.stdout.split()[-1]


def vendor_version() -> str:
    """The version of `gh` the vendor's index lists now. Read without its signature only to choose the version:
    `lock checksums` then reads the same stanza through the signed InRelease and fails on any mismatch."""
    url = f"{VENDOR}/dists/stable/main/binary-amd64/Packages.gz"
    with urllib.request.urlopen(url, timeout=60) as response:
        text = gzip.decompress(response.read()).decode()
    versions = [
        line.removeprefix("Version: ")
        for stanza in text.split("\n\n")
        if "Package: gh\n" in stanza + "\n"
        for line in stanza.splitlines()
        if line.startswith("Version: ")
    ]
    if not versions:
        raise AssertionError(f"{url} lists no gh")
    return max(versions, key=lambda version: [int(part) for part in version.split(".")])


def vendor_lock(source: Path, target: Path) -> None:
    """The example lock with its made-up vendor entries replaced by the GitHub CLI's, the .deb's checksum unset."""
    lock = json.loads(source.read_text())
    inputs = {name: entry for name, entry in lock["inputs"].items() if entry.get("module") != "vendor-deb"}
    inputs["gh"] = {
        "apt": "gh",
        "datasource": "deb",
        "depName": "gh",
        "description": "The GitHub CLI from its vendor's apt repository; its dependency (git) from the snapshot.",
        "module": "vendor-deb",
        "registryUrl": REGISTRY,
        "sha256": "0" * 64,
        "signed_by": "gh-keys",
        "url": f"{VENDOR}/pool/main/g/gh/gh_{{version}}_amd64.deb",
        "used_by": list(BOOTING),
        "version": vendor_version(),
    }
    inputs["gh-keys"] = {
        "description": "The keyring the GitHub CLI's repository signs its InRelease with.",
        "module": "vendor-deb",
        "sha256": KEYRING_SHA256,
        "url": f"{VENDOR}/githubcli-archive-keyring.gpg",
        "used_by": list(BOOTING),
        "version": "1",
    }
    target.write_text(input_lock.dump({**lock, "inputs": inputs}))


def os_packages(path: Path) -> set[str]:
    scanned = tarball.scan_tarball(path, frozenset({packages.STATUS_PATH}), None, False)
    return {name for name, _, _ in debian.installed_packages(scanned.contents[packages.STATUS_PATH].decode())}


def kit_packages(kit: Path, scratch: Path) -> set[str]:
    image = scratch / f"{kit.name}.initrd.img"
    image.write_bytes(tar_file(kit, "initrd.img"))
    status = packages.STATUS_PATH.lstrip("/")
    found = [member for member in initrd.members(str(image), contents=(status,)) if member.name == status]
    assert found and found[0].data is not None, f"{kit} has no {status}"
    return {name for name, _, _ in debian.installed_packages(found[0].data.decode())}


def tested(out: Path, *argv: str) -> str:
    """`test OUT`'s report; on a failed check the error carries the report, which names what failed."""
    printed, errors = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(errors):
        status = cli.main(["test", str(out), *argv])
    if status != 0:
        raise AssertionError(f"test {out} exited {status}:\n{printed.getvalue()}{errors.getvalue()}")
    return printed.getvalue()


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class M5AcceptanceTest(unittest.TestCase):
    scratch: ClassVar[tempfile.TemporaryDirectory[str]]
    work: ClassVar[Path]
    plans: ClassVar[dict[str, dict[str, dict[str, object]]]]
    tested: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        builder, vm_image = scripts_builder("build"), scripts_builder("vm")
        # Under dist/, not /tmp: the docker daemon mounts these paths from its own view of the host.
        (ROOT / "dist").mkdir(exist_ok=True)
        # DIF_KEEP=1 keeps the artifacts, the plans and any boot's serial log for a look after a failure.
        keep = os.environ.get("DIF_KEEP") == "1"
        cls.scratch = tempfile.TemporaryDirectory(prefix="integration-m5-", dir=ROOT / "dist", delete=not keep)
        work = cls.work = Path(cls.scratch.name)
        definition = work / "def"
        shutil.copytree(EXAMPLES, definition)
        lock = definition / "lock.json"
        vendor_lock(EXAMPLES / "lock.json", lock)
        files = ["--lock", str(lock), "--definition", str(definition / "factory.toml")]
        factory("lock", "checksums", *files, "--entry", "gh")
        moved = definition / "lock-moved.json"
        shutil.copy(lock, moved)
        factory("lock", "baseline", "--lock", str(moved), "--definition", str(definition / "factory.toml"),
                "--id", MOVED_BASELINE)  # fmt: skip
        published = f"dir://{work / 'published'}"

        # The flag on: build, test (boots included) and publish core, the installer and the OS.
        on = work / "plan-on.json"
        factory("plan", *files, "--param", "vendor_tools=true", "--out", str(on))
        factory("fetch", str(on))
        out_on = work / "out-on"
        built = ["--image", "core", "--image", "installer", "--image", "os"]
        factory("build", str(on), "--out", str(out_on), *built, "--builder-image", builder, *files)
        cls.tested = tested(out_on, "--definition", str(definition / "factory.toml"), "--vm-image", vm_image)
        factory("publish", str(out_on), "--to", published)

        # The flag off and the moved baseline, each planned against what was published.
        off = work / "plan-off.json"
        factory("plan", *files, "--param", "vendor_tools=false", "--against", published, "--out", str(off))
        moved_plan = work / "plan-moved.json"
        factory("plan", "--lock", str(moved), "--definition", str(definition / "factory.toml"),
                "--param", "vendor_tools=true", "--against", published, "--out", str(moved_plan))  # fmt: skip
        factory("fetch", str(off))
        factory("build", str(off), "--out", str(work / "out-off"), "--image", "installer", "--image", "os",
                "--parents", published, "--builder-image", builder, *files)  # fmt: skip
        cls.plans = {name: json.loads((work / f"plan-{name}.json").read_text())["images"]
                     for name in ("on", "off", "moved")}  # fmt: skip

    @classmethod
    def tearDownClass(cls) -> None:
        cls.scratch.cleanup()

    def identity(self, plan: str, image: str) -> str:
        return str(self.plans[plan][image]["identity"])

    def state(self, plan: str, image: str) -> str:
        return str(self.plans[plan][image]["state"])

    # ---- both boot in QEMU ------------------------------------------------------------------------

    def test_every_check_of_the_installer_and_the_os_passed_boots_included(self) -> None:
        for image, boot in (("installer", "installer-boot"), ("os", "os-boot")):
            lines = {line.split(" ")[1]: line for line in self.tested.splitlines() if line.startswith(f"{image}: ")}
            for check in (boot, "two-clones"):
                self.assertTrue(lines.get(check, "").startswith(f"{image}: {check} PASSED"), self.tested)
            failed = [line for line in lines.values() if " FAILED" in line]
            self.assertEqual(failed, [], self.tested)

    # ---- a flag off removes its module from both and changes both identities --------------------

    def test_the_vendor_package_is_in_both_with_the_flag_on(self) -> None:
        out = self.work / "out-on"
        self.assertIn("gh", os_packages(artifact_of(out, "os", "tar.gz")))
        self.assertIn("gh", kit_packages(artifact_of(out, "installer", "tar"), self.work))

    def test_the_flag_off_removes_the_vendor_package_from_both(self) -> None:
        out = self.work / "out-off"
        self.assertNotIn("gh", os_packages(artifact_of(out, "os", "tar.gz")))
        self.assertNotIn("gh", kit_packages(artifact_of(out, "installer", "tar"), self.work))

    def test_the_flag_off_changes_both_identities_and_no_other(self) -> None:
        for image in BOOTING:
            self.assertNotEqual(self.identity("on", image), self.identity("off", image), image)
            self.assertEqual(self.state("off", image), "build", image)
        for image in OTHERS:
            self.assertEqual(self.identity("on", image), self.identity("off", image), image)
        self.assertNotEqual(self.state("off", "core"), "build")

    # ---- moving the baseline rebuilds the OS and nothing else -------------------------------------

    def test_moving_the_baseline_rebuilds_the_os_and_nothing_else(self) -> None:
        images = self.plans["on"]
        changed = sorted(image for image in images if self.identity("on", image) != self.identity("moved", image))
        self.assertEqual(changed, ["os"])
        self.assertEqual(self.state("moved", "os"), "build")
        for image in ("core", "installer"):
            self.assertNotEqual(self.state("moved", image), "build", image)


if __name__ == "__main__":
    unittest.main()
