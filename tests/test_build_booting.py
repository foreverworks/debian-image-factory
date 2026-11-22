"""The installer and os kinds' builds, without docker: the script text the builder runs, how a parent of each
kind is found and its ancestors read from its records, and `build_booting` end to end with the builder
container replaced by a function that writes what the real one would (an os tarball, or a kit written by
initrd.py itself, and dpkg's status)."""

import json
import re
import shutil
import tarfile
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from input_lock import Value

from debian_image_factory import commands, definition, modules, planfile, published, records
from debian_image_factory import plan as plan_module
from debian_image_factory.build import boot, booting, core, initrd, parents, run
from debian_image_factory.build import oci as oci_build
from debian_image_factory.definition import Module
from tests.support.definitions import EXAMPLES, example_lock_data
from tests.support.rootfs import BASE, rootfs, status_text
from tests.test_build_oci import ARCH, EPOCH, SNAPSHOT, SUITE, before, put_core, refuse_pull, sha, shell_is_valid

BASELINE = "20261108T000000Z"
KERNEL = "6.12.99+deb13-amd64"

CHILDREN = """
[images.os-tools]
kind = "os"
parent = "os"
packages = ["jq"]
hooks = ["hooks/installer-trim.sh"]

[images.installer-tools]
kind = "installer"
parent = "installer"
packages = ["jq"]
apt_sources = "baseline"
"""


def script(**changes: object) -> str:
    arguments: dict[str, object] = {
        "kind": "os",
        "image": "os",
        "parent_kind": "core",
        "request": ("linux-image-amd64", "udev"),
        "source_date_epoch": EPOCH,
        "owner": None,
        "files": False,
        "module_lines": (),
        "hooks": (),
    }
    arguments.update(changes)
    return booting.build_script(**arguments)  # type: ignore[arg-type]  # the keywords are the function's own, built as a dict


class ScriptTest(unittest.TestCase):
    def test_an_os_image_builds_like_an_oci_child_and_packs_the_whole_root(self) -> None:
        text = script(files=True, module_lines=("# module lines",), hooks=("hooks/a.sh",))
        self.assertTrue(shell_is_valid(text))
        self.assertIn(f'{oci_build.LAYER_PROGRAM} unpack --root "$root" --state {oci_build.STATE}', text)
        self.assertIn(f"{oci_build.LAYERS}/000.tar.gz", text)
        child = "\n".join(
            oci_build.child_lines(
                request=("linux-image-amd64", "udev"),
                files=True,
                module_lines=("# module lines",),
                hooks=("hooks/a.sh",),
                sources=core.sources_lines(),
                finish=boot.boot_lines(),
            )
        )
        self.assertIn(child, text, "the child lines are OCI's, the image's sources and the boot lines added")
        self.assertIn(f'pack --full --root "$root" --state {oci_build.STATE} --epoch {EPOCH}', text)
        self.assertIn(f"--out {booting.ROOTFS} --status-out {oci_build.STATUS}", text)
        self.assertNotIn("initrd.py", text)

    def test_the_images_own_sources_replace_the_parents_once_apt_is_done(self) -> None:
        text = script()
        install = f'install -m 0644 {core.SOURCES} "$root/etc/apt/sources.list.d/debian.sources"'
        self.assertTrue(before(text, "apt-get clean", install))
        self.assertTrue(before(text, 'find "$root/etc/apt/sources.list.d" -mindepth 1 -delete', install))
        self.assertTrue(before(text, install, 'rm -f "$root"/etc/ssh/ssh_host_*'))

    def test_the_boot_lines_come_after_the_identity_removal_and_before_the_unmounts(self) -> None:
        text = script()
        self.assertTrue(before(text, 'then : > "$root/etc/machine-id"', boot.boot_lines()[1]))
        self.assertTrue(before(text, boot.boot_lines()[-1], 'umount -R "$root/proc"\n'))
        self.assertNotIn("factory-ssh-host-keys", text)

    def test_an_installer_packs_its_kit_and_an_installer_parent_is_unpacked_from_its_kit(self) -> None:
        on_core = script(kind="installer", image="rescue")
        self.assertIn(
            f'{booting.INITRD_PROGRAM} kit --root "$root" --state {oci_build.STATE} --epoch {EPOCH}'
            f" --image rescue --out {booting.KIT} --status-out {oci_build.STATUS}",
            on_core,
        )
        self.assertIn(f"{oci_build.LAYER_PROGRAM} unpack", on_core)
        on_installer = script(kind="installer", image="rescue", parent_kind="installer")
        self.assertTrue(shell_is_valid(on_installer))
        self.assertIn(
            f'{booting.INITRD_PROGRAM} unpack --root "$root" --state {oci_build.STATE} --kit {booting.PARENT_KIT}',
            on_installer,
        )
        self.assertNotIn(f"{oci_build.LAYER_PROGRAM} unpack", on_installer)
        self.assertNotIn("--full", on_installer)

    def test_vendor_debs_go_through_the_same_apt_transaction_as_for_an_oci_child(self) -> None:
        deb = f"{core.WORK}/run/inputs/vendor/vendor_1.0_amd64.deb"
        text = script(request=(), debs=(deb,))
        self.assertTrue(shell_is_valid(text))
        self.assertIn("\n".join(oci_build.install_lines((), (deb,))), text)
        self.assertIn(f'umount "$root{oci_build.CHILD_MIRROR}"', text, "a .deb alone mounts the mirror for apt")
        self.assertNotIn("vendor_1.0_amd64.deb", script(request=()))

    def test_outputs_are_handed_back_where_the_container_root_is_the_host_root(self) -> None:
        self.assertIn(f"for output in {booting.ROOTFS} {oci_build.STATUS}; do", script(owner="1000:1000"))
        self.assertIn(f"for output in {booting.KIT} {oci_build.STATUS}; do", script(kind="installer", owner="1:1"))
        self.assertNotIn("chown", script())

    def test_only_core_or_the_same_kind_is_a_parent(self) -> None:
        for kind, parent in (("os", "installer"), ("installer", "os"), ("os", "oci")):
            with self.subTest(kind=kind, parent=parent), self.assertRaises(ValueError):
                script(kind=kind, parent_kind=parent)
        with self.assertRaises(ValueError):
            script(kind="oci")

    def test_the_oci_script_is_its_prologue_unpack_child_lines_and_pack(self) -> None:
        text = oci_build.build_script(
            layers=2, request=("jq",), source_date_epoch=EPOCH, owner=None, files=True, module_lines=(), hooks=()
        )
        expected = [
            *oci_build.prologue_lines(EPOCH, mirror=True),
            *oci_build.unpack_lines(2, EPOCH),
            *oci_build.child_lines(request=("jq",), files=True, module_lines=(), hooks=()),
            *oci_build.pack_lines(EPOCH, None),
            "",
        ]
        self.assertEqual(text, "\n".join(expected))
        self.assertNotIn("debian.sources", text, "an OCI child keeps its parent's sources")


@dataclass(frozen=True, slots=True)
class Seen:
    """What the builder found in its work directory."""

    files: list[str]
    script: str
    sources: str
    layer: bytes | None
    parent_kit: bytes | None


class BuildBootingTest(unittest.TestCase):
    """The examples' os and installer images, and a child of each, through `build_booting`."""

    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory(prefix="build-booting-test-")
        self.addCleanup(scratch.cleanup)
        self.dir = Path(scratch.name)
        shutil.copytree(EXAMPLES, self.dir / "examples")
        with (self.dir / "examples" / "factory.toml").open("a") as handle:
            handle.write(CHILDREN)
        (self.dir / "examples" / "lock.json").write_text(json.dumps(example_lock_data()))
        self.loaded = commands.load(self.dir / "examples" / "lock.json", self.dir / "examples" / "factory.toml")
        lock = commands.checked_lock(self.loaded)
        names = definition.top_down(self.loaded.definition)
        inputs = commands.compute_inputs(
            lock,
            self.loaded,
            {name: tuple(BASE) for name in names},
            definition.resolve_params(self.loaded.definition, {}),
        )
        images = {
            name: planfile.parse_image(
                name, {**plan_module.image_entry(self.loaded.definition, inputs[name]), "state": "build"}
            )
            for name in names
        }
        plan: planfile.Plan = {
            "schema": 1,
            "factory": "0",
            "engine": 1,
            "snapshot": SNAPSHOT,
            "baseline": BASELINE,
            "debian": {"suite": SUITE, "components": ("main",), "architecture": ARCH},
            "params": {},
            "images": images,
        }
        self.keyring = self.dir / "keyring.pgp"
        self.keyring.write_bytes(b"keyring")
        self.out = self.dir / "out"
        self.out.mkdir()
        sources = commands.Sources(cache=self.dir / "cache", keyring=self.keyring)
        builder_ = run.Builder("builder:1", "sha256:" + "5" * 64, None)
        self.context = run.Run(
            plan, lock, self.loaded, sources, self.dir / "mirror", [], builder_, None, self.out, (), ()
        )
        self.core = put_core(self.out, images["core"]["identity"])
        self.seen: list[Seen] = []

    def fake_builder(self, builder_: run.Builder, work: Path, mirror: Path, log: Path) -> None:
        """What the container writes: the os tarball or the kit (by initrd.py itself), and dpkg's status."""
        text = (work / "build.sh").read_text()
        layer, kit = work / "layers" / "000.tar.gz", work / "parent.tar"
        self.seen.append(
            Seen(
                sorted(str(path.relative_to(work)) for path in work.rglob("*") if path.is_file()),
                text,
                (work / "debian.sources").read_text(),
                layer.read_bytes() if layer.exists() else None,
                kit.read_bytes() if kit.exists() else None,
            )
        )
        status = status_text([*BASE, ("jq", "1.7", "amd64")])
        if "--full" in text:
            (work / "os.tar.gz").write_bytes(rootfs({"./": None, "./var/lib/dpkg/status": status}))
            (work / "dpkg-status").write_bytes(status)
            return
        image = re.search(r"--image (\S+)", text)
        assert image is not None
        root = work / "fake-root"
        (root / "boot").mkdir(parents=True)
        (root / "boot" / f"vmlinuz-{KERNEL}").write_bytes(b"kernel\n")
        (root / "var" / "lib" / "dpkg").mkdir(parents=True)
        (root / "var" / "lib" / "dpkg" / "status").write_bytes(status)
        initrd.kit(str(root), None, EPOCH, image.group(1), str(work / "kit.tar"), str(work / "dpkg-status"))

    def build(self, image: str, built: Mapping[str, parents.ParentArtifact] | None = None) -> run.Result:
        with (
            mock.patch.object(run, "run_builder", self.fake_builder),
            tempfile.TemporaryDirectory(prefix=f".work-{image}-", dir=self.out) as scratch,
        ):
            return run.build_booting(self.context, image, Path(scratch), built or {})

    def statements(self, result: run.Result) -> list[dict[str, object]]:
        return records.decode_statements((self.out / published.records_name_for(result.artifact.digest)).read_text())

    def dependencies(self, result: run.Result) -> list[tuple[str, str]]:
        predicate = self.statements(result)[0]["predicate"]
        assert isinstance(predicate, dict)
        found = predicate["buildDefinition"]["resolvedDependencies"]
        return [(str(one["name"]), str(one["digest"]["sha256"])) for one in found if "name" in one]

    def test_an_os_image_is_built_on_cores_tarball_and_named_by_its_own_sha256(self) -> None:
        result = self.build("os")
        assert result.artifact.path is not None and self.core.path is not None
        seen = self.seen[0]
        self.assertEqual(seen.layer, self.core.path.read_bytes(), "core's tarball is the single layer")
        self.assertIn("layer.py", seen.files)
        self.assertIn("initrd.py", seen.files)
        self.assertIn("--full", seen.script)
        digest = sha(result.artifact.path.read_bytes())
        entry = self.context.plan["images"]["os"]
        self.assertEqual(
            result.artifact.name, published.artifact_name("os", SUITE, ARCH, entry["identity"], digest, "tar.gz")
        )
        self.assertEqual((result.artifact.kind, result.artifact.digest, result.packages), ("os", digest, len(BASE) + 1))
        for statement in self.statements(result):
            self.assertEqual(statement["subject"], [{"name": result.artifact.name, "digest": {"sha256": digest}}])
        self.assertEqual(self.dependencies(result)[-1], ("parent: core", self.core.digest))
        self.assertNotIn("ancestor", " ".join(name for name, _ in self.dependencies(result)))
        self.assertEqual(sorted(path.name for path in self.out.iterdir() if path.name.startswith(".")), [])

    def test_the_os_image_carries_its_own_sources_pinned_to_the_baseline(self) -> None:
        self.build("os")
        sources = self.seen[0].sources
        self.assertEqual(sources, core.image_sources("baseline-except-security", SUITE, ("main",), BASELINE))
        self.assertIn(f"Snapshot: {BASELINE}", sources)
        self.assertNotIn(SNAPSHOT, sources)

    def test_an_image_asking_for_baseline_sources_with_no_baseline_in_the_plan_fails(self) -> None:
        self.context.plan["baseline"] = None
        with self.assertRaisesRegex(
            commands.Failed, "images.os: apt_sources 'baseline-except-security' needs the baseline"
        ):
            self.build("os")

    def test_an_os_child_of_an_os_image_names_both_ancestors_from_its_parents_records(self) -> None:
        parent = self.build("os")
        assert parent.artifact.path is not None
        child = self.build("os-tools", {"os": parent.artifact})
        self.assertEqual(self.seen[1].layer, parent.artifact.path.read_bytes())
        self.assertEqual(
            self.dependencies(child)[-2:],
            [("parent: os", parent.artifact.digest), ("ancestor: core", self.core.digest)],
        )
        self.assertEqual(self.seen[1].sources, core.image_sources("live", SUITE, ("main",), BASELINE))

    def test_an_os_parent_built_in_an_earlier_run_is_found_in_the_output_by_its_extension(self) -> None:
        parent = self.build("os")
        child = self.build("os-tools")  # nothing built in this run: found in the output directory
        self.assertEqual(self.dependencies(child)[-2][1], parent.artifact.digest)

    def test_a_parent_without_its_records_cannot_name_its_ancestors(self) -> None:
        parent = self.build("os")
        (self.out / published.records_name_for(parent.artifact.digest)).unlink()
        with self.assertRaisesRegex(commands.Failed, r"its records .* name the images below it"):
            self.build("os-tools")

    def test_an_installer_kit_names_the_kit_then_its_kernel_and_initrd(self) -> None:
        result = self.build("installer")
        assert result.artifact.path is not None
        kit = result.artifact.path
        self.assertTrue(kit.name.endswith(".tar") and kit.name.startswith("installer-trixie-amd64-"))
        self.assertIn("--image installer", self.seen[0].script)
        with tarfile.open(kit, mode="r:") as archive:
            files = {name: archive.extractfile(name).read() for name in initrd.KIT_MEMBERS}  # type: ignore[union-attr]  # regular files
        expected = [
            {"name": kit.name, "digest": {"sha256": sha(kit.read_bytes())}},
            {"name": "vmlinuz", "digest": {"sha256": sha(files["vmlinuz"])}},
            {"name": "initrd.img", "digest": {"sha256": sha(files["initrd.img"])}},
        ]
        for statement in self.statements(result):
            self.assertEqual(statement["subject"], expected)
        sbom = self.statements(result)[1]["predicate"]
        assert isinstance(sbom, dict)
        self.assertEqual(sbom["packages"][0]["primaryPackagePurpose"], "INSTALL")
        self.assertEqual(self.dependencies(result)[-1], ("parent: core", self.core.digest))

    def test_an_installer_child_starts_from_its_parents_kit(self) -> None:
        parent = self.build("installer")
        assert parent.artifact.path is not None
        child = self.build("installer-tools", {"installer": parent.artifact})
        seen = self.seen[1]
        self.assertEqual(seen.parent_kit, parent.artifact.path.read_bytes())
        self.assertIsNone(seen.layer)
        self.assertIn(
            f'initrd.py unpack --root "$root" --state {oci_build.STATE} --kit {booting.PARENT_KIT}', seen.script
        )
        self.assertEqual(seen.sources, core.image_sources("baseline", SUITE, ("main",), BASELINE))
        self.assertEqual(
            self.dependencies(child)[-2:],
            [("parent: installer", parent.artifact.digest), ("ancestor: core", self.core.digest)],
        )

    def test_a_kit_that_is_not_one_stops_the_build(self) -> None:
        def broken(builder_: run.Builder, work: Path, mirror: Path, log: Path) -> None:
            with tarfile.open(work / "kit.tar", mode="w") as archive:
                archive.addfile(tarfile.TarInfo("kit.json"))
            (work / "dpkg-status").write_bytes(status_text(BASE))

        with (
            mock.patch.object(run, "run_builder", broken),
            tempfile.TemporaryDirectory(dir=self.out) as scratch,
            self.assertRaisesRegex(commands.Failed, "the builder's kit is not one"),
        ):
            run.build_booting(self.context, "installer", Path(scratch), {})

    def test_module_lines_reach_a_booting_childs_script(self) -> None:
        seen: list[str] = []

        def install(
            module: Module, entries: Mapping[str, Mapping[str, Value]], *, inputs: str, source_date_epoch: int
        ) -> list[str]:
            seen.append(module.use)
            return ["# the module installs here"]

        entry = self.context.plan["images"]["os"]
        changed = dict(self.context.plan["images"])
        changed["os"] = {**entry, "modules": ("node",)}
        self.context.plan["images"] = changed
        with mock.patch.object(modules, "install_lines", install):
            self.build("os")
        self.assertEqual(seen, ["builtin:node-tarball"])
        self.assertTrue(before(self.seen[0].script, "# the module installs here", "apt-get clean"))


class AncestryTest(unittest.TestCase):
    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory(prefix="ancestry-test-")
        self.addCleanup(scratch.cleanup)
        self.dir = Path(scratch.name)

    def provenance(self, digest: str, *dependencies: tuple[str, str]) -> dict[str, object]:
        return {
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": "x", "digest": {"sha256": digest}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"uri": "oci://builder", "digest": {"sha256": "5" * 64}},
                        *({"name": name, "digest": {"sha256": value}} for name, value in dependencies),
                    ]
                }
            },
        }

    def test_core_needs_no_records(self) -> None:
        core_ = parents.ParentArtifact("core", "core", "core.tar.gz", "a" * 64, None)
        self.assertEqual(parents.file_ancestors(core_, lambda name: None), (records.Parent("core", "a" * 64),))

    def test_the_parents_own_parent_and_ancestors_follow_it(self) -> None:
        found = parents.provenance_ancestors(
            self.provenance("b" * 64, ("parent: os", "c" * 64), ("ancestor: core", "a" * 64)), "b" * 64
        )
        self.assertEqual(found, [records.Parent("os", "c" * 64), records.Parent("core", "a" * 64)])

    def test_records_of_another_artifact_are_not_read_as_the_parents(self) -> None:
        self.assertIsNone(parents.provenance_ancestors(self.provenance("b" * 64, ("parent: core", "a" * 64)), "d" * 64))
        self.assertIsNone(parents.provenance_ancestors(None, "d" * 64))

    def test_a_parent_found_by_extension_in_a_directory(self) -> None:
        identity = "ab" * 32
        data = b"a kit"
        name = published.artifact_name("rescue", SUITE, ARCH, identity, sha(data), "tar")
        (self.dir / name).write_bytes(data)
        entry: planfile.ImageEntry = {"kind": "installer", "identity": identity}  # type: ignore[typeddict-item]  # only the fields locate_parent reads
        found = parents.locate_parent(
            "child", "rescue", entry, suite=SUITE, arch=ARCH, built={}, out_dir=self.dir / "none",
            directories=[self.dir], registries=[], pull=refuse_pull, scratch=self.dir / "pulled",
        )  # fmt: skip
        self.assertEqual((found.kind, found.name, found.digest), ("installer", name, sha(data)))
        self.assertEqual(parents.EXTENSIONS["os"], "tar.gz")
        self.assertEqual(run.EXTENSIONS["installer"], "tar")
        self.assertEqual(set(booting.KINDS) <= set(run.SUPPORTED_KINDS), True)


if __name__ == "__main__":
    unittest.main()
