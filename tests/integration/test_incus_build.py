"""The Incus kind's build, end to end, on a copy of the example definition at the example lock's snapshot.

Core and incus-base are built, then `incus-tools`, an Incus child of incus-base with a package, a file
tree and a hook, in another output directory with incus-base found through `--parents`; incus-base is
built a second time from the same inputs. Needs docker, the builder image (`scripts/builder build`) and
network access to snapshot.debian.org.

What it checks: the same inputs give the same fingerprint; Incus's two files are named by it and the
records name it with both files' sha256; the metadata is the factory's; the child's provenance names its
parent and core; every file check passes on both images (`incus-boot` and `two-clones` are not run without
an Incus host, and never passed); the child holds its parent's files, its package, its file tree and what
its hook wrote. With DIF_INCUS_HOST=1 (on an Incus host: scripts/incus-vm gives one) `incus-boot` and
`two-clones` must pass too, for the base and for the child: the boot contract of DESIGN 14's M4.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from debian_image_factory import fileartifacts, incus, published, squashfs

from .test_core_build import EXAMPLES, ROOT, factory

CHILD = """
[images.incus-tools]
kind = "incus"
parent = "incus-base"
packages = ["jq"]
files = "files/incus-tools"
hooks = ["hooks/incus-tools.sh"]
"""

HOOK = """#!/bin/sh
set -eu
jq --version > /usr/local/share/incus-tools-hook
"""

HOSTED = ("incus-boot", "two-clones")


def artifact(out: Path, image: str) -> fileartifacts.FileArtifact:
    found = [one for one in fileartifacts.file_artifacts(out)[0] if one.parts.image == image]
    if len(found) != 1:
        raise AssertionError(f"{out} holds {len(found)} artifacts of {image}, expected one")
    return found[0]


def rootfs_paths(one: fileartifacts.FileArtifact) -> dict[str, squashfs.Entry]:
    with one.files[1].open("rb") as handle:
        return {entry.path: entry for entry in squashfs.entries(handle)}


def provenance(out: Path, digest: str) -> dict[str, object]:
    for line in (out / published.records_name_for(digest)).read_text().splitlines():
        body = json.loads(base64.b64decode(json.loads(line)["payload"]))
        if body["predicateType"] == "https://slsa.dev/provenance/v1":
            assert isinstance(body, dict)
            return body
    raise AssertionError("no provenance")


def outcomes(printed: str, image: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in printed.splitlines():
        head, _, rest = line.partition(": ")
        if head == image and rest:
            check, _, outcome = rest.partition(" ")
            found[check] = outcome.split(":", 1)[0]
    return found


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class IncusBuildTest(unittest.TestCase):
    work: Path
    scratch: tempfile.TemporaryDirectory[str]

    @classmethod
    def setUpClass(cls) -> None:
        tag = subprocess.run(
            [str(ROOT / "scripts" / "builder"), "build"], check=True, capture_output=True, text=True
        ).stdout.split()[-1]
        (ROOT / "dist").mkdir(exist_ok=True)
        cls.scratch = tempfile.TemporaryDirectory(prefix="integration-incus-", dir=ROOT / "dist")
        cls.work = Path(cls.scratch.name)
        tools = cls.work / "examples"
        shutil.copytree(EXAMPLES, tools)
        (tools / "factory.toml").write_text((tools / "factory.toml").read_text() + CHILD)
        tree = tools / "files" / "incus-tools" / "usr" / "local" / "share"
        tree.mkdir(parents=True)
        (tree / "incus-tools-file").write_text("from the file tree\n")
        (tools / "hooks" / "incus-tools.sh").write_text(HOOK)
        (tools / "hooks" / "incus-tools.sh").chmod(0o755)
        definition = ["--lock", str(tools / "lock.json"), "--definition", str(tools / "factory.toml")]
        plan = cls.work / "plan.json"
        factory("plan", *definition, "--out", str(plan))
        factory("fetch", str(plan))
        common = ["--builder-image", tag, *definition]
        images = ["--image", "core", "--image", "incus-base"]
        factory("build", str(plan), "--out", str(cls.work / "out1"), *images, *common)
        parents = f"dir://{cls.work / 'out1'}"
        factory(
            "build", str(plan), "--out", str(cls.work / "out2"), "--image", "incus-tools", "--parents", parents, *common
        )
        factory(
            "build", str(plan), "--out", str(cls.work / "out3"), "--image", "incus-base", "--parents", parents, *common
        )
        for one in ("core", "incus-base"):  # the child's own output gets its ancestors, for `ancestry`
            for path in artifact(cls.work / "out1", one).files:
                shutil.copy2(path, cls.work / "out2" / path.name)
            digest = artifact(cls.work / "out1", one).digest
            shutil.copy2(cls.work / "out1" / published.records_name_for(digest), cls.work / "out2")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.scratch.cleanup()

    def test_the_same_inputs_give_the_same_fingerprint(self) -> None:
        first, second = artifact(self.work / "out1", "incus-base"), artifact(self.work / "out3", "incus-base")
        self.assertEqual(first.digest, second.digest)
        self.assertEqual([p.read_bytes() for p in first.files[:1]], [p.read_bytes() for p in second.files[:1]])

    def test_files_and_records_carry_the_fingerprint(self) -> None:
        one = artifact(self.work / "out1", "incus-base")
        metadata, rootfs = one.files
        self.assertEqual(one.digest, hashlib.sha256(metadata.read_bytes() + rootfs.read_bytes()).hexdigest())
        self.assertEqual(rootfs.read_bytes()[:4], b"hsqs")
        subjects = provenance(self.work / "out1", one.digest)["subject"]
        assert isinstance(subjects, list)
        self.assertEqual(
            [(s["name"], s["digest"]["sha256"]) for s in subjects],
            [
                (metadata.name.removesuffix(f".{incus.METADATA_EXT}"), one.digest),
                (metadata.name, hashlib.sha256(metadata.read_bytes()).hexdigest()),
                (rootfs.name, hashlib.sha256(rootfs.read_bytes()).hexdigest()),
            ],
        )
        with tarfile.open(metadata, mode="r:gz") as archive:
            handle = archive.extractfile("metadata.yaml")
            assert handle is not None
            self.assertIn('variant: "incus-base"', handle.read().decode())

    def test_the_child_names_its_ancestors_and_holds_what_it_added(self) -> None:
        base = artifact(self.work / "out1", "incus-base")
        core = artifact(self.work / "out1", "core")
        child = artifact(self.work / "out2", "incus-tools")
        dependencies = provenance(self.work / "out2", child.digest)["predicate"]
        assert isinstance(dependencies, dict)
        names = {
            d["name"]: d["digest"]["sha256"]
            for d in dependencies["buildDefinition"]["resolvedDependencies"]
            if "name" in d
        }
        self.assertEqual(names["parent: incus-base"], base.digest)
        self.assertEqual(names["ancestor: core"], core.digest)
        held = rootfs_paths(child)
        self.assertIn("/usr/bin/jq", held)
        self.assertIn("/usr/local/share/incus-tools-file", held)
        self.assertIn("/usr/local/share/incus-tools-hook", held)
        self.assertFalse(set(rootfs_paths(base)) - set(held) - {"/etc/hostname"})
        machine_id = held["/etc/machine-id"]
        self.assertEqual(machine_id.size, len("uninitialized\n"))
        self.assertIn("/dev/null", held)
        self.assertEqual(held["/dev/null"].kind, "char")

    def test_every_check_passes_or_needs_an_incus_host(self) -> None:
        printed = factory("test", str(self.work / "out1")) + factory("test", str(self.work / "out2"))
        hosted = os.environ.get("DIF_INCUS_HOST") == "1"
        for image in ("incus-base", "incus-tools"):
            found = outcomes(printed, image)
            self.assertEqual(
                sorted(found),
                [
                    "ancestry",
                    "incus-boot",
                    "no-build-snapshot",
                    "no-machine-identity",
                    "package-set",
                    "sbom-complete",
                    "two-clones",
                ],
                printed,
            )
            for check, outcome in found.items():
                wanted = "PASSED" if hosted or check not in HOSTED else "not run"
                self.assertEqual(outcome, wanted, f"{image} {check}:\n{printed}")


if __name__ == "__main__":
    unittest.main()
