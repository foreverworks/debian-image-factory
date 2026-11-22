"""The OCI kind's build, end to end on the example definition at the example lock's snapshot.

Core is built once; oci-base (config only: no builder container, its first layer is core's tarball) and
node-26 (one module and two locked inputs: one added layer) follow in the same run. The builtin:node-tarball
module is stubbed, so this does not depend on its own tests: the stub leaves a marker file naming the inputs
it was handed, which also proves they were staged for a module that has no hooks. A copy of the examples
with one more image (`oci-tools`: a package, a file tree and a hook, so apt, the mirror mount and the
cleanup run) is built on top. Needs docker, the builder image (`scripts/builder build`) and network access
to snapshot.debian.org.

What it checks: the base layer is core's tarball byte for byte; each layout reads back; `docker load` takes
it and `docker run` starts it; the same inputs give the same manifest digest, also when the parent comes from
another output directory (`--parents`); a layer holds nothing of the build; provenance names every ancestor.
"""

import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from unittest import mock

from input_lock import Value

from debian_image_factory import modules, ocilayout, published, records
from debian_image_factory.definition import Module

from .test_core_build import EXAMPLES, ROOT, factory, files, sha256_of

CORE_PARENT_INPUTS = "usr/local/inputs-seen"

HOOK = """#!/bin/sh
set -eu
echo "hook ran as $(id -u)" > /usr/local/share/hook-output
jq --version >> /usr/local/share/hook-output
"""

TOOLS_IMAGE = """
[images.oci-tools]
kind = "oci"
parent = "oci-base"
packages = ["jq"]
files = "files/tools"
hooks = ["hooks/oci-tools.sh"]
"""

SKIPPED_BY_A_LAYER = (
    "run/",
    "tmp/",
    "var/lib/apt/lists/",
    "var/cache/apt/",
    "var/log/",
    "etc/apt/",
    "usr/sbin/policy-rc.d",
    "usr/sbin/start-stop-daemon",
    "etc/hostname",
    "etc/resolv.conf",
    "var/lib/dbus/machine-id",
)
"""Paths no added layer of this definition may hold: what the build used and removed, or put back."""


def stub_install(
    module: Module, entries: Mapping[str, Mapping[str, Value]], *, inputs: str, source_date_epoch: int
) -> list[str]:
    """What the node module would install, as a marker: the file names its inputs arrived under."""
    return [f'ls {inputs}/{name} >> "$root/{CORE_PARENT_INPUTS}"' for name in sorted(entries)]


def build(*argv: str) -> str:
    with mock.patch.object(modules, "install_lines", stub_install):
        return factory("build", *argv)


def layout_of(out: Path, image: str) -> Path:
    found = [path for path in out.iterdir() if path.name.startswith(f"{image}-trixie-") and path.name.endswith(".oci")]
    if len(found) != 1:
        raise AssertionError(f"{out} holds {len(found)} layouts of {image}, expected one")
    return found[0]


def manifest_digest(out: Path, image: str) -> str:
    return ocilayout.read_layout(layout_of(out, image)).descriptor.digest


def planned_packages(plan: Mapping[str, object], image: str) -> list[list[str]]:
    """The package set the plan resolved for `image`, sorted: [name, version, architecture] rows."""
    images = plan["images"]
    assert isinstance(images, dict)
    packages = images[image]["packages"]
    assert isinstance(packages, list)
    return sorted([str(part) for part in row] for row in packages)


def layer_members(layout: ocilayout.Layout) -> list[tarfile.TarInfo]:
    with tarfile.open(layout.layers[-1], mode="r:gz") as archive:
        return archive.getmembers()


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class OciBuildTest(unittest.TestCase):
    work: Path
    scratch: tempfile.TemporaryDirectory[str]
    tag: str
    plan: dict[str, object]
    tools_plan: dict[str, object]
    loaded: set[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.tag = subprocess.run(
            [str(ROOT / "scripts" / "builder"), "build"], check=True, capture_output=True, text=True
        ).stdout.split()[-1]
        (ROOT / "dist").mkdir(exist_ok=True)
        cls.scratch = tempfile.TemporaryDirectory(prefix="integration-oci-", dir=ROOT / "dist")
        cls.work = Path(cls.scratch.name)
        cls.loaded = set()
        plan = cls.work / "plan.json"
        factory("plan", *files(), "--out", str(plan))
        factory("fetch", str(plan))
        cls.plan = json.loads(plan.read_text())
        common = ["--builder-image", cls.tag, *files()]
        first = f"dir://{cls.work / 'out1'}"
        # core, oci-base and node-26 in one run: each parent is built before its child, in this run
        images = ["--image", "core", "--image", "oci-base", "--image", "node-26"]
        build(str(plan), "--out", str(cls.work / "out1"), *images, *common)
        # node-26 alone: its parent is in another output directory, found by identity; core is named by annotations
        build(str(plan), "--out", str(cls.work / "out2"), "--image", "node-26", "--parents", first, *common)
        build(str(plan), "--out", str(cls.work / "out3"), "--image", "oci-base", "--parents", first, *common)
        # the examples with one more image: a package, a file tree and a hook
        tools = cls.work / "tools"
        shutil.copytree(EXAMPLES, tools)
        (tools / "files" / "tools" / "usr" / "local" / "share").mkdir(parents=True)
        (tools / "files" / "tools" / "usr" / "local" / "share" / "tools-file").write_text("tools file\n")
        (tools / "hooks" / "oci-tools.sh").write_text(HOOK)
        with (tools / "factory.toml").open("a") as handle:
            handle.write(TOOLS_IMAGE)
        tool_files = ["--lock", str(tools / "lock.json"), "--definition", str(tools / "factory.toml")]
        tools_plan = cls.work / "tools-plan.json"
        factory("plan", *tool_files, "--out", str(tools_plan))
        factory("fetch", str(tools_plan))
        cls.tools_plan = json.loads(tools_plan.read_text())
        for out in ("out-tools1", "out-tools2"):
            image, parents = ["--image", "oci-tools"], ["--parents", first, "--builder-image", cls.tag]
            build(str(tools_plan), "--out", str(cls.work / out), *image, *parents, *tool_files)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.loaded:
            subprocess.run(["docker", "rmi", "--force", *sorted(cls.loaded)], capture_output=True, check=False)
        cls.scratch.cleanup()

    def core_tarball(self) -> Path:
        return next((self.work / "out1").glob("core-trixie-*.tar.gz"))

    def statements(self, out: str, image: str) -> list[dict[str, object]]:
        digest = manifest_digest(self.work / out, image)
        return records.decode_statements((self.work / out / f"{digest}.intoto.jsonl").read_text())

    def dependencies(self, out: str, image: str) -> list[dict[str, object]]:
        provenance = self.statements(out, image)[0]["predicate"]
        assert isinstance(provenance, dict)
        found = provenance["buildDefinition"]["resolvedDependencies"]
        assert isinstance(found, list)
        return found

    def sbom_packages(self, out: str, image: str) -> list[list[str]]:
        sbom = self.statements(out, image)[1]["predicate"]
        assert isinstance(sbom, dict)
        rows = []
        for package in sbom["packages"]:
            refs = package.get("externalRefs", [])
            locator = refs[0]["referenceLocator"] if refs else ""
            if locator.startswith("pkg:deb/"):
                arch = locator.split("arch=", 1)[1].split("&", 1)[0]
                rows.append([package["name"], package["versionInfo"], arch])
        return sorted(rows)

    def load(self, out: str, image: str) -> str:
        """`docker load` the layout (as a tar of its directory) and return the image's ID."""
        layout = layout_of(self.work / out, image)
        archive = self.work / f"{image}.tar"
        subprocess.run(["tar", "-C", str(layout), "-cf", str(archive), "."], check=True)
        done = subprocess.run(["docker", "load", "-i", str(archive)], capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        found = re.search(r"sha256:[0-9a-f]{64}", done.stdout)
        self.assertIsNotNone(found, done.stdout)
        assert found is not None
        type(self).loaded.add(found.group(0))
        return found.group(0)

    def docker_run(self, image_id: str, *command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "run", "--rm", "--network", "none", image_id, *command],
            capture_output=True,
            text=True,
            check=False,
        )

    # ---- the base layer is core's tarball -------------------------------------------------------

    def test_oci_bases_first_layer_is_cores_tarball_byte_for_byte(self) -> None:
        layout = ocilayout.read_layout(layout_of(self.work / "out1", "oci-base"))
        core = self.core_tarball()
        self.assertEqual(len(layout.manifest.layers), 1, "oci-base only sets config: it adds no layer")
        self.assertEqual(layout.manifest.layers[0].digest, sha256_of(core))
        self.assertEqual(layout.manifest.layers[0].media_type, "application/vnd.oci.image.layer.v1.tar+gzip")
        self.assertEqual(layout.layers[0].read_bytes(), core.read_bytes())
        self.assertEqual(layout.diff_ids, (hashlib.sha256(gzip.decompress(core.read_bytes())).hexdigest(),))
        self.assertEqual((layout.config.user, layout.config.cmd), ("0:0", ("/bin/bash",)))
        self.assertEqual(
            layout.manifest.annotations["org.opencontainers.image.base.digest"], f"sha256:{sha256_of(core)}"
        )

    def test_node_26_adds_exactly_one_layer_on_core_and_inherits_oci_bases_config(self) -> None:
        layout = ocilayout.read_layout(layout_of(self.work / "out1", "node-26"))
        self.assertEqual(len(layout.manifest.layers), 2)
        self.assertEqual(layout.manifest.layers[0].digest, sha256_of(self.core_tarball()))
        members = {member.name: member for member in layer_members(layout)}
        self.assertIn("usr/lib/x86_64-linux-gnu/libatomic.so.1", members)  # what the node module asks apt for
        of_libatomic = (
            "etc/ld.so.cache",
            "usr/lib/x86_64-linux-gnu/libatomic",
            "usr/share/doc/libatomic1",
            "var/lib/dpkg/",
        )
        self.assertEqual(sorted(name for name in members if not name.startswith(of_libatomic)), [CORE_PARENT_INPUTS])
        with tarfile.open(layout.layers[-1], mode="r:gz") as archive:
            handle = archive.extractfile(CORE_PARENT_INPUTS)
            assert handle is not None
            # the tarball was staged although node-26 has no hooks; the release keyring is a trust root
            # (signed_by), checked at fetch and never handed to the module's install
            self.assertEqual(handle.read().decode().split(), ["node-v26.13.1-linux-x64.tar.xz"])
        self.assertEqual(
            (layout.config.user, layout.config.cmd, layout.config.env), ("0:0", ("node",), (("LANG", "C.UTF-8"),))
        )

    # ---- layouts, docker, records ---------------------------------------------------------------

    def test_every_layout_reads_back_with_its_records_named_by_the_manifest_digest(self) -> None:
        for out, image in (("out1", "oci-base"), ("out1", "node-26"), ("out-tools1", "oci-tools")):
            layout = ocilayout.read_layout(layout_of(self.work / out, image))
            name = layout_of(self.work / out, image).name
            parsed = published.parse_artifact_name(name)
            assert parsed is not None
            self.assertEqual((parsed.image, parsed.ext), (image, "oci"))
            self.assertTrue(layout.descriptor.digest.startswith(parsed.digest12))
            for statement in self.statements(out, image):
                self.assertEqual(statement["subject"], [{"name": name, "digest": {"sha256": layout.descriptor.digest}}])

    def test_docker_loads_every_image_and_runs_it(self) -> None:
        for out, image in (("out1", "oci-base"), ("out1", "node-26"), ("out-tools1", "oci-tools")):
            with self.subTest(image=image):
                image_id = self.load(out, image)
                self.assertEqual(self.docker_run(image_id, "/bin/true").returncode, 0)
        image_id = self.load("out-tools1", "oci-tools")
        found = self.docker_run(image_id, "jq", "--version")
        self.assertEqual((found.returncode, found.stdout.strip()), (0, "jq-1.7"))
        found = self.docker_run(image_id, "cat", "/usr/local/share/hook-output", "/usr/local/share/tools-file")
        self.assertEqual(found.stdout.splitlines(), ["hook ran as 0", "jq-1.7", "tools file"])

    def test_the_sbom_lists_the_final_package_set(self) -> None:
        planned = planned_packages(self.plan, "oci-base")
        self.assertEqual(self.sbom_packages("out1", "oci-base"), planned)
        self.assertEqual(self.sbom_packages("out1", "node-26"), planned_packages(self.plan, "node-26"))
        tools = planned_packages(self.tools_plan, "oci-tools")
        self.assertEqual(self.sbom_packages("out-tools1", "oci-tools"), tools)
        self.assertIn("jq", [row[0] for row in tools])

    def test_provenance_names_the_parent_and_every_ancestor_up_to_core(self) -> None:
        core = sha256_of(self.core_tarball())
        for out in ("out1", "out2"):
            with self.subTest(out=out):
                found = self.dependencies(out, "node-26")
                tail = [(one["name"], one["digest"]["sha256"]) for one in found[-2:]]  # type: ignore[index]  # JSON from our own records
                self.assertEqual(
                    tail,
                    [("parent: oci-base", manifest_digest(self.work / "out1", "oci-base")), ("ancestor: core", core)],
                )
        names = [str(one.get("name") or one.get("uri")) for one in self.dependencies("out1", "oci-base")]
        self.assertEqual(names[-1], "parent: core")
        self.assertEqual(sum(name.startswith("ancestor") for name in names), 0)
        self.assertIn("node-26", [str(one.get("name")) for one in self.dependencies("out1", "node-26")])

    # ---- determinism and what a layer holds -----------------------------------------------------

    def test_the_same_inputs_give_the_same_manifest_digest(self) -> None:
        self.assertEqual(
            manifest_digest(self.work / "out1", "oci-base"), manifest_digest(self.work / "out3", "oci-base")
        )
        self.assertEqual(manifest_digest(self.work / "out1", "node-26"), manifest_digest(self.work / "out2", "node-26"))
        self.assertEqual(
            manifest_digest(self.work / "out-tools1", "oci-tools"),
            manifest_digest(self.work / "out-tools2", "oci-tools"),
        )
        first = ocilayout.read_layout(layout_of(self.work / "out-tools1", "oci-tools"))
        second = ocilayout.read_layout(layout_of(self.work / "out-tools2", "oci-tools"))
        self.assertEqual(first.layers[-1].read_bytes(), second.layers[-1].read_bytes())

    def test_a_layer_holds_the_change_and_nothing_of_the_build(self) -> None:
        layout = ocilayout.read_layout(layout_of(self.work / "out-tools1", "oci-tools"))
        self.assertEqual(len(layout.manifest.layers), 2, "core's tarball, then one layer: oci-base added none")
        members = layer_members(layout)
        names = [member.name for member in members]
        for expected in (
            "usr/bin/jq",
            "usr/local/share/tools-file",
            "usr/local/share/hook-output",
            "var/lib/dpkg/status",
        ):
            self.assertIn(expected, names)
        for name in names:
            self.assertFalse(name.startswith(SKIPPED_BY_A_LAYER), f"{name} is in the layer")
            self.assertNotIn(".wh.", name)
        self.assertEqual(
            {(member.uid, member.gid, member.uname, member.gname) for member in members if member.name == "usr/bin/jq"},
            {(0, 0, "", "")},
        )
        self.assertTrue(
            all(member.mtime <= 1754697600 for member in members), "a time stamp later than SOURCE_DATE_EPOCH"
        )
        self.assertEqual(names, sorted(names, key=lambda name: name.split("/")), "parents before children, sorted")
        # the images' own apt sources were put back exactly, so the layer does not touch them
        self.assertNotIn("etc/apt/sources.list.d/debian.sources", names)

    def test_a_build_leaves_no_scratch_directory_behind(self) -> None:
        listing: Sequence[str] = sorted(
            path.name for path in (self.work / "out1").iterdir() if path.name.startswith(".")
        )
        self.assertEqual(listing, [], "a build leaves no scratch directory behind")


if __name__ == "__main__":
    unittest.main()
