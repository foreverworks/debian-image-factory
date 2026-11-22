"""The OCI kind's build, without docker: the script text the builder runs, how a parent is found and its
ancestors listed, and `build_oci` end to end with the builder container replaced by a function that
writes what the real one would (a layer, its diff_id and dpkg's status)."""

import gzip
import hashlib
import io
import itertools
import json
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from input_lock import JsonValue, Value

from debian_image_factory import archive, cli, commands, definition, modules, oci, ocilayout, planfile, published
from debian_image_factory import plan as plan_module
from debian_image_factory.build import core, layer, parents, run
from debian_image_factory.build import oci as oci_build
from debian_image_factory.definition import Module
from tests.support.definitions import EXAMPLES, entry_of, example_lock_data
from tests.support.rootfs import BASE, rootfs, status_text

SNAPSHOT = "20261121T004329Z"
EPOCH = 1754697600
ARCH, SUITE = "amd64", "trixie"


def shell_is_valid(text: str) -> bool:
    return subprocess.run(["sh", "-n"], input=text, text=True, capture_output=True, check=False).returncode == 0


def script(**changes: object) -> str:
    arguments: dict[str, object] = {
        "layers": 1,
        "request": (),
        "source_date_epoch": EPOCH,
        "owner": None,
        "files": False,
        "module_lines": (),
        "hooks": (),
    }
    arguments.update(changes)
    return oci_build.build_script(**arguments)  # type: ignore[arg-type]  # the keywords are the function's own, built as a dict


def before(text: str, first: str, second: str) -> bool:
    return text.index(first) < text.index(second)


class ScriptTest(unittest.TestCase):
    def test_a_build_without_packages_runs_no_apt_and_mounts_no_mirror(self) -> None:
        text = script(files=True)
        self.assertNotIn("apt-get", text)
        self.assertNotIn("/mirror", text)
        self.assertNotIn("policy-rc.d", text)
        self.assertIn("mount -t proc", text)
        self.assertIn("-xpf /factory/files.tar", text)
        self.assertTrue(shell_is_valid(text))

    def test_packages_are_installed_from_the_mounted_mirror_in_the_order_that_keeps_the_root_clean(self) -> None:
        text = script(
            request=["jq", "ca-certificates"], files=True, module_lines=["# module node"], hooks=["hooks/x.sh"]
        )
        steps = [
            "unpack --root",
            "mount -t proc",
            "mount --bind /mirror",
            'mv "$root/etc/apt/sources.list"',
            "00factory-build",
            "exit 101",
            "apt-get update",
            "--no-install-recommends install ca-certificates jq",
            "-xpf /factory/files.tar",
            "# module node",
            "/run/factory/hooks/01-x.sh",
            "Dir::Etc::SourceList=/dev/null",
            "apt-get clean",
            'rm -f "$root/var/log/dpkg.log"',
            'rm -f "$root/etc/hostname"',
            'umount "$root/run/factory/mirror"\n',
            " pack --root",
        ]
        for first, second in itertools.pairwise(steps):
            self.assertTrue(before(text, first, second), f"{first!r} must come before {second!r}")
        self.assertTrue(shell_is_valid(text))

    def test_the_build_exports_what_mmdebstrap_exports(self) -> None:
        text = script()
        self.assertIn("export SOURCE_DATE_EPOCH=1754697600", text)
        self.assertIn("export DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true", text)
        self.assertIn("export LC_ALL=C.UTF-8", text)

    def test_the_images_own_sources_and_service_blockers_are_put_back(self) -> None:
        text = script(request=["jq"])
        self.assertIn("mv -t /factory/aside/sources.list.d {} +", text)
        self.assertIn('-exec mv -t "$root/etc/apt/sources.list.d" {} +', text)
        self.assertIn('mv "$root/usr/sbin/start-stop-daemon.REAL" "$root/usr/sbin/start-stop-daemon"', text)
        self.assertIn('rm -f "$root/etc/apt/sources.list" "$root/usr/sbin/policy-rc.d"', text)
        self.assertIn('rm -f "$root/etc/apt/apt.conf.d/99factory-build"', text)

    def test_the_trap_unmounts_and_deletes_the_root_whatever_happens(self) -> None:
        text = script(request=["jq"])
        trap = text[text.index("cleanup() {") : text.index("trap cleanup EXIT")]
        self.assertIn('umount "$root/run/factory/mirror" 2>/dev/null || true', trap)
        self.assertIn('rm -rf --one-file-system "$root" /factory/aside', trap)
        self.assertIn('exit "$status"', trap)

    def test_the_outputs_are_handed_back_where_the_container_root_is_the_host_root(self) -> None:
        self.assertNotIn("chown", script())
        self.assertIn("chown 1000:1000", script(owner="1000:1000"))

    def test_every_parent_layer_is_unpacked_base_first(self) -> None:
        text = script(layers=3)
        self.assertIn("/factory/layers/000.tar.gz /factory/layers/001.tar.gz /factory/layers/002.tar.gz", text)

    def test_core_and_children_end_with_the_same_identity_lines(self) -> None:
        for line in core.identity_lines():
            self.assertIn(line, script())
        self.assertTrue(core.customize_script(files=False, hooks=()).endswith("\n".join(core.identity_lines()) + "\n"))

    def test_the_child_sources_read_the_mirror_and_keyring_inside_the_root(self) -> None:
        text = core.build_sources("trixie", ["main"], mirror=oci_build.CHILD_MIRROR, keyring=oci_build.CHILD_KEYRING)
        self.assertEqual(
            text.splitlines()[0],
            "deb [signed-by=/run/factory/keyring.pgp check-valid-until=no] "
            "copy:///run/factory/mirror/debian trixie main",
        )

    def test_layer_names_sort_in_layer_order(self) -> None:
        names = [oci_build.layer_name(index) for index in (0, 1, 2, 10)]
        self.assertEqual(names, sorted(names))


# ---- artifacts on disk ----------------------------------------------------------------------------


def targz(files: Mapping[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive_:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive_.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def put_core(directory: Path, identity: str = "ab" * 32) -> parents.ParentArtifact:
    data = rootfs({"./etc/os-release": b"x\n", "./var/lib/dpkg/status": status_text(BASE)})
    digest = sha(data)
    name = published.artifact_name("core", SUITE, ARCH, identity, digest, "tar.gz")
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(data)
    return parents.ParentArtifact("core", "core", name, digest, directory / name)


def put_layout(
    directory: Path,
    image: str,
    identity: str,
    *,
    base: parents.ParentArtifact,
    table: Mapping[str, JsonValue] | None = None,
) -> parents.ParentArtifact:
    """An OCI layout of `image` on `base`, adding one layer of its own: what `build_oci` writes."""
    below = parents.base_of(base)
    own = targz({f"usr/local/{image}": image.encode()})
    own_path = directory / f".{image}.layer"
    directory.mkdir(parents=True, exist_ok=True)
    own_path.write_bytes(own)
    config = oci.merged_config(below.config, table or {})
    diff_id = sha(gzip.decompress(own))
    config_bytes = oci.image_config(config, [*below.diff_ids, diff_id], ARCH)
    annotations = oci.image_annotations(
        identity=identity, base_digest=base.digest, base_name=base.name, source=None, revision=None
    )
    target = directory / f".{image}.building"
    descriptor = ocilayout.write_layout(
        target,
        config=config_bytes,
        layers=[*below.layers, (own_path, sha(own), len(own))],
        annotations=annotations,
    )
    own_path.unlink()
    name = published.artifact_name(image, SUITE, ARCH, identity, descriptor.digest, "oci")
    target.rename(directory / name)
    return parents.ParentArtifact(image, "oci", name, descriptor.digest, directory / name)


def entry_for(parent: parents.ParentArtifact, identity: str, **extra: str) -> planfile.ImageEntry:
    """A plan entry as far as `locate_parent` reads one."""
    return {"kind": parent.kind, "identity": identity, **extra}  # type: ignore[typeddict-item]  # only the fields locate_parent reads


def refuse_pull(target: published.OciTarget, digest: str, dest: Path) -> Path:
    raise AssertionError("nothing should be pulled")


class LocateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="locate-test-")
        self.addCleanup(self.scratch.cleanup)
        self.dir = Path(self.scratch.name)
        self.out = self.dir / "out"
        self.core = put_core(self.out)
        self.base = put_layout(self.out, "oci-base", "cd" * 32, base=self.core)

    def locate(
        self,
        *,
        built: Mapping[str, parents.ParentArtifact] | None = None,
        directories: Sequence[Path] = (),
        registries: Sequence[published.OciTarget] = (),
        pull: parents.Pull = refuse_pull,
        parent: str = "oci-base",
        entry: planfile.ImageEntry | None = None,
        out: Path | None = None,
    ) -> parents.ParentArtifact:
        return parents.locate_parent(
            "node-26",
            parent,
            entry or entry_for(self.base, "cd" * 32),
            suite=SUITE,
            arch=ARCH,
            built=built or {},
            out_dir=out or self.out,
            directories=directories,
            registries=registries,
            pull=pull,
            scratch=self.dir / "pulled",
        )

    def test_a_parent_built_in_this_run_is_the_one_used(self) -> None:
        elsewhere = parents.ParentArtifact("oci-base", "oci", "x.oci", "0" * 64, None)
        self.assertIs(self.locate(built={"oci-base": elsewhere}), elsewhere)

    def test_found_in_the_output_directory_by_identity_when_the_plan_names_no_digest(self) -> None:
        self.assertEqual(self.locate(), self.base)

    def test_found_by_the_digest_the_plan_names(self) -> None:
        entry = entry_for(self.base, "cd" * 32, artifact=self.base.digest)
        self.assertEqual(self.locate(entry=entry), self.base)

    def test_found_in_a_parent_target_directory(self) -> None:
        empty = self.dir / "empty"
        empty.mkdir()
        entry = entry_for(self.base, "cd" * 32, artifact=self.base.digest)
        self.assertEqual(self.locate(entry=entry, out=empty, directories=[self.out]), self.base)

    def test_a_core_parent_is_a_tarball_checked_against_its_name(self) -> None:
        entry = entry_for(self.core, "ab" * 32, artifact=self.core.digest)
        self.assertEqual(self.locate(parent="core", entry=entry), self.core)
        assert self.core.path is not None
        self.core.path.write_bytes(self.core.path.read_bytes() + b"x")
        with self.assertRaisesRegex(commands.Failed, "its sha256 is"):
            self.locate(parent="core", entry=entry)

    def test_a_parent_found_nowhere_fails_naming_the_image_the_digest_and_the_places(self) -> None:
        empty = self.dir / "empty"
        empty.mkdir()
        entry = entry_for(self.base, "cd" * 32, artifact=self.base.digest)
        with self.assertRaises(commands.Failed) as caught:
            self.locate(entry=entry, out=empty, directories=[self.dir / "nowhere"])
        message = str(caught.exception)
        for part in ("node-26", "oci-base", self.base.digest, str(empty), str(self.dir / "nowhere"), "--parents"):
            self.assertIn(part, message)

    def test_two_builds_of_the_parent_without_a_named_digest_are_ambiguous(self) -> None:
        put_layout(self.out, "oci-base", "cd" * 32, base=self.core, table={"cmd": ["/bin/sh"]})
        with self.assertRaisesRegex(commands.Failed, "several builds of oci-base"):
            self.locate()

    def test_a_layout_whose_name_does_not_say_its_manifest_is_refused(self) -> None:
        assert self.base.path is not None
        wrong = self.out / self.base.name.replace(self.base.digest[:12], "0" * 12)
        self.base.path.rename(wrong)
        entry = entry_for(self.base, "cd" * 32, artifact=self.base.digest)
        with self.assertRaises(commands.Failed):
            self.locate(entry=entry)

    def test_a_registry_is_asked_for_the_digest_the_plan_names(self) -> None:
        empty = self.dir / "empty"
        empty.mkdir()
        entry = entry_for(self.base, "cd" * 32, artifact=self.base.digest)
        registry = published.OciTarget("registry.example", "images/oci-base")
        calls: list[tuple[str, str]] = []

        def pull(target: published.OciTarget, digest: str, dest: Path) -> Path:
            calls.append((target.registry, digest))
            assert self.base.path is not None
            return self.base.path

        self.assertEqual(self.locate(entry=entry, out=empty, registries=[registry], pull=pull), self.base)
        self.assertEqual(calls, [("registry.example", self.base.digest)])

    def test_the_default_pull_names_the_registry_it_could_not_read(self) -> None:
        empty = self.dir / "empty"
        empty.mkdir()
        entry = entry_for(self.base, "cd" * 32, artifact=self.base.digest)
        registry = published.OciTarget("127.0.0.1:9", "images/oci-base")  # nothing listens on port 9
        with self.assertRaisesRegex(commands.Failed, r"oci://127\.0\.0\.1:9/images/oci-base@sha256:"):
            self.locate(entry=entry, out=empty, registries=[registry], pull=run.pull_parent)

    def test_a_parent_that_is_not_core_or_oci_is_refused(self) -> None:
        entry: planfile.ImageEntry = {"kind": "incus", "identity": "ef" * 32}  # type: ignore[typeddict-item]  # only the fields locate_parent reads
        with self.assertRaisesRegex(commands.Failed, "incus image"):
            self.locate(entry=entry)


class LineageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="lineage-test-")
        self.addCleanup(self.scratch.cleanup)
        self.out = Path(self.scratch.name)
        self.core = put_core(self.out)
        self.base = put_layout(self.out, "oci-base", "cd" * 32, base=self.core)
        self.node = put_layout(self.out, "node-26", "ef" * 32, base=self.base)

    def find(self, name: str) -> Path | None:
        return self.out / name if (self.out / name).exists() else None

    def test_core_has_no_ancestors(self) -> None:
        self.assertEqual(parents.lineage(self.core, self.find), (self.core,))

    def test_a_chain_is_read_from_each_images_own_annotations_nearest_first(self) -> None:
        chain = parents.lineage(self.node, self.find)
        self.assertEqual([one.image for one in chain], ["node-26", "oci-base", "core"])
        self.assertEqual([one.digest for one in chain], [self.node.digest, self.base.digest, self.core.digest])
        self.assertIsNone(chain[-1].path, "core's tarball is not needed to name it")

    def test_an_ancestor_that_cannot_be_found_fails_saying_which(self) -> None:
        with self.assertRaisesRegex(commands.Failed, "oci-base-trixie.*not in the build's output"):
            parents.lineage(self.node, lambda name: None)

    def test_a_layout_that_says_nothing_about_its_base_fails(self) -> None:
        assert self.base.path is not None
        manifest = ocilayout.read_layout(self.base.path)
        bare = oci.image_manifest(manifest.manifest.config, manifest.manifest.layers, {})
        digest = ocilayout.write_blob(self.base.path, bare)
        (self.base.path / "index.json").write_bytes(oci.index([oci.Descriptor(oci.MANIFEST, digest, len(bare))]))
        renamed = self.out / published.artifact_name("oci-base", SUITE, ARCH, "cd" * 32, digest, "oci")
        self.base.path.rename(renamed)
        with self.assertRaisesRegex(commands.Failed, "does not say what it is built on"):
            parents.lineage(parents.describe_layout(renamed, check_layers=False), self.find)

    def test_an_ancestor_whose_manifest_is_not_the_one_named_fails(self) -> None:
        other = put_layout(self.out, "oci-base", "cd" * 32, base=self.core, table={"cmd": ["/bin/sh"]})
        assert other.path is not None and self.base.path is not None
        shutil.rmtree(self.base.path)
        # the file the annotation names is now another image's layout under the same name
        other.path.rename(self.out / self.base.name)
        with self.assertRaises(commands.Failed):
            parents.lineage(self.node, self.find)


class BaseTest(unittest.TestCase):
    def test_a_core_tarball_is_its_own_single_layer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="base-test-") as scratch:
            core_ = put_core(Path(scratch))
            base = parents.base_of(core_)
            assert core_.path is not None
            self.assertEqual(base.layers, ((core_.path, core_.digest, core_.path.stat().st_size),))
            self.assertEqual(base.diff_ids, (sha(gzip.decompress(core_.path.read_bytes())),))
            self.assertIsNone(base.config)

    def test_a_layout_gives_its_layers_diff_ids_and_config(self) -> None:
        with tempfile.TemporaryDirectory(prefix="base-test-") as scratch:
            core_ = put_core(Path(scratch))
            image = put_layout(
                Path(scratch), "oci-base", "cd" * 32, base=core_, table={"user": "0:0", "cmd": ["/bin/sh"]}
            )
            base = parents.base_of(image)
            self.assertEqual(len(base.layers), 2)
            self.assertEqual(base.layers[0][1], core_.digest)
            self.assertEqual(len(base.diff_ids), 2)
            assert base.config is not None
            self.assertEqual((base.config.user, base.config.cmd), ("0:0", ("/bin/sh",)))
            self.assertEqual(
                parents.dpkg_status([path for path, _, _ in base.layers]).count("Status: install ok installed"), 3
            )

    def test_the_last_layer_with_a_status_file_wins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="base-test-") as scratch:
            first, second = Path(scratch) / "1.tar.gz", Path(scratch) / "2.tar.gz"
            first.write_bytes(targz({"./var/lib/dpkg/status": b"old"}))
            second.write_bytes(targz({"var/lib/dpkg/status": b"new", "other": b"x"}))
            self.assertEqual(parents.dpkg_status([first, second]), "new")
            self.assertEqual(parents.dpkg_status([second, first]), "old")
            first.write_bytes(targz({"x": b"1"}))
            with self.assertRaisesRegex(commands.Failed, "no layer holds"):
                parents.dpkg_status([first])


# ---- build_oci ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Seen:
    """What the builder found in its work directory."""

    files: list[str]
    script: str
    layer_program: str
    build_list: str
    first_layer: bytes
    inputs: dict[str, bytes]


class BuildOciTest(unittest.TestCase):
    """The examples' oci-base (config only) and node-26 (one module, two locked inputs) through `build_oci`."""

    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="build-oci-test-")
        self.addCleanup(self.scratch.cleanup)
        self.dir = Path(self.scratch.name)
        shutil.copytree(EXAMPLES, self.dir / "examples")
        data = example_lock_data()
        self.cache = self.dir / "cache"
        self.node_file, self.keys_file = b"a node tarball", b"a keyring"
        for name, content in (("node-26", self.node_file), ("node-release-keys", self.keys_file)):
            entry_of(data, name)["sha256"] = sha(content)
            archive.store(self.cache, content)
        (self.dir / "examples" / "lock.json").write_text(json.dumps(data))
        self.loaded = commands.load(self.dir / "examples" / "lock.json", self.dir / "examples" / "factory.toml")
        lock = commands.checked_lock(self.loaded)
        names = definition.top_down(self.loaded.definition)
        resolved = {name: tuple(BASE) for name in names}
        inputs = commands.compute_inputs(
            lock, self.loaded, resolved, definition.resolve_params(self.loaded.definition, {})
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
            "baseline": None,
            "debian": {"suite": SUITE, "components": ("main",), "architecture": ARCH},
            "params": {},
            "images": images,
        }
        self.keyring = self.dir / "keyring.pgp"
        self.keyring.write_bytes(b"keyring")
        self.out = self.dir / "out"
        self.out.mkdir()
        sources = commands.Sources(cache=self.cache, keyring=self.keyring)
        builder_ = run.Builder("builder:1", "sha256:" + "5" * 64, None)
        self.context = run.Run(
            plan, lock, self.loaded, sources, self.dir / "mirror", [], builder_, None, self.out, (), ()
        )
        core_entry = images["core"]
        self.core = put_core(self.out, core_entry["identity"])
        self.seen: Seen | None = None
        self.builds = 0

    def fake_builder(self, builder_: run.Builder, work: Path, mirror: Path, log: Path) -> None:
        """What the container writes: one layer, its diff_id and dpkg's status."""
        self.seen = Seen(
            sorted(str(path.relative_to(work)) for path in work.rglob("*") if path.is_file()),
            (work / "build.sh").read_text(),
            (work / "layer.py").read_text(),
            (work / "build.list").read_text(),
            (work / "layers" / "000.tar.gz").read_bytes(),
            {
                str(path.relative_to(work)): path.read_bytes()
                for path in (work / "run" / "inputs").rglob("*")
                if path.is_file()
            },
        )
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive_:
            info = tarfile.TarInfo("usr/local/stub")
            info.size = 4
            archive_.addfile(info, io.BytesIO(b"stub"))
        (work / "layer.tar.gz").write_bytes(gzip.compress(raw.getvalue(), mtime=0))
        (work / "layer.diff_id").write_text(sha(raw.getvalue()) + "\n")
        (work / "dpkg-status").write_bytes(status_text([*BASE, ("node-stub", "1", "amd64")]))
        self.builds += 1

    def build(self, image: str, built: Mapping[str, parents.ParentArtifact] | None = None) -> run.Result:
        with tempfile.TemporaryDirectory(prefix=f".work-{image}-", dir=self.out) as scratch:
            return run.build_oci(self.context, image, Path(scratch), built or {})

    def statements(self, result: run.Result) -> list[dict[str, object]]:
        text = (self.out / published.records_name_for(result.artifact.digest)).read_text()
        from debian_image_factory import records

        return records.decode_statements(text)

    def dependencies(self, result: run.Result) -> list[str]:
        predicate = self.statements(result)[0]["predicate"]
        assert isinstance(predicate, dict)
        found = predicate["buildDefinition"]["resolvedDependencies"]
        return [str(one.get("name") or one.get("uri")) for one in found]

    def test_an_image_that_only_sets_config_adds_no_layer_and_runs_no_builder(self) -> None:
        with mock.patch.object(run, "run_builder", side_effect=AssertionError("no container for a config")):
            result = self.build("oci-base")
        assert result.artifact.path is not None
        layout = ocilayout.read_layout(result.artifact.path)
        self.assertEqual(len(layout.manifest.layers), 1)
        self.assertEqual(layout.manifest.layers[0].digest, self.core.digest, "the base layer is core's tarball")
        self.assertEqual(layout.manifest.layers[0].media_type, oci.LAYER_GZIP)
        assert self.core.path is not None
        self.assertEqual(layout.layers[0].read_bytes(), self.core.path.read_bytes())
        self.assertEqual(layout.diff_ids, (sha(gzip.decompress(self.core.path.read_bytes())),))
        self.assertEqual(result.artifact.digest, layout.descriptor.digest)
        self.assertEqual(
            result.artifact.name,
            published.artifact_name(
                "oci-base",
                SUITE,
                ARCH,
                self.context.plan["images"]["oci-base"]["identity"],
                layout.descriptor.digest,
                "oci",
            ),
        )
        self.assertEqual(
            (layout.config.user, layout.config.cmd, layout.config.env), ("0:0", ("/bin/bash",), (("LANG", "C.UTF-8"),))
        )
        annotations = layout.manifest.annotations
        self.assertEqual(annotations[oci.BASE_DIGEST], f"sha256:{self.core.digest}")
        self.assertEqual(annotations[oci.BASE_NAME], self.core.name)
        self.assertEqual(annotations[oci.IDENTITY], self.context.plan["images"]["oci-base"]["identity"])
        self.assertEqual(result.packages, len(BASE))

    def test_oci_base_records_name_core_as_the_parent_and_the_manifest_as_the_subject(self) -> None:
        result = self.build("oci-base")
        provenance, sbom = self.statements(result)
        for one in (provenance, sbom):
            self.assertEqual(
                one["subject"], [{"name": result.artifact.name, "digest": {"sha256": result.artifact.digest}}]
            )
        self.assertEqual(self.dependencies(result)[-1], "parent: core")
        self.assertNotIn("ancestor", " ".join(self.dependencies(result)))
        predicate = sbom["predicate"]
        assert isinstance(predicate, dict)
        self.assertEqual(predicate["packages"][0]["primaryPackagePurpose"], "CONTAINER")
        self.assertEqual(len(predicate["packages"]), 1 + len(BASE))

    def test_an_image_with_a_module_adds_one_layer_built_by_the_builder(self) -> None:
        base = self.build("oci-base")
        seen: list[tuple[str, dict[str, object], str, int]] = []

        def install(
            module: Module, entries: Mapping[str, Mapping[str, Value]], *, inputs: str, source_date_epoch: int
        ) -> list[str]:
            seen.append((module.use, dict(entries), inputs, source_date_epoch))
            return [f"# stub installs {sorted(entries)}"]

        with (
            mock.patch.object(run, "run_builder", self.fake_builder),
            mock.patch.object(modules, "install_lines", install),
        ):
            result = self.build("node-26", {"oci-base": base.artifact})
        self.assertEqual(self.builds, 1)
        assert result.artifact.path is not None
        layout = ocilayout.read_layout(result.artifact.path)
        self.assertEqual(len(layout.manifest.layers), 2, "core's tarball, then the one added layer")
        self.assertEqual(layout.manifest.layers[0].digest, self.core.digest)
        self.assertEqual(len(layout.diff_ids), 2)
        with gzip.open(layout.layers[1]) as handle:
            self.assertEqual(sha(handle.read()), layout.diff_ids[1])
        # the module was called once, with its own lock entries and the builder path of the inputs
        ((use, entries, inputs, epoch),) = seen
        self.assertEqual(
            (use, sorted(entries), inputs, epoch),
            ("builtin:node-tarball", ["node-26", "node-release-keys"], "/factory/run/inputs", EPOCH),
        )
        seen_ = self.seen
        assert seen_ is not None
        self.assertIn("# stub installs ['node-26', 'node-release-keys']", seen_.script)
        # inputs are staged for a module although the image has no hooks (the M2 gap)
        self.assertEqual(
            seen_.inputs,
            {
                "run/inputs/node-26/node-v26.13.1-linux-x64.tar.xz": self.node_file,
                "run/inputs/node-release-keys/pubring.kbx": self.keys_file,
            },
        )
        assert self.core.path is not None
        self.assertEqual(seen_.first_layer, self.core.path.read_bytes())
        self.assertEqual(seen_.layer_program, Path(layer.__file__).read_text())
        self.assertIn("copy:///run/factory/mirror/debian trixie main", seen_.build_list)
        self.assertNotIn("debian.sources", seen_.files)
        self.assertNotIn("customize.sh", seen_.files)
        # config inherited from oci-base and laid over with node-26's own table
        self.assertEqual(
            (layout.config.user, layout.config.cmd, layout.config.env), ("0:0", ("node",), (("LANG", "C.UTF-8"),))
        )
        annotations = layout.manifest.annotations
        self.assertEqual(annotations[oci.BASE_DIGEST], f"sha256:{base.artifact.digest}")
        self.assertEqual(annotations[oci.BASE_NAME], base.artifact.name)
        # the SBOM lists the status the builder copied out, then the locked inputs
        self.assertEqual(result.packages, len(BASE) + 1)
        # provenance: its parent, then every ancestor up to core's tarball digest, nearest first
        names = self.dependencies(result)
        self.assertEqual(names[-2:], ["parent: oci-base", "ancestor: core"])
        provenance = self.statements(result)[0]["predicate"]
        assert isinstance(provenance, dict)
        digests = [one["digest"]["sha256"] for one in provenance["buildDefinition"]["resolvedDependencies"][-2:]]
        self.assertEqual(digests, [base.artifact.digest, self.core.digest])
        self.assertIn("node-26", names)

    def test_a_parent_built_in_an_earlier_run_is_found_in_the_output_and_still_names_core(self) -> None:
        base = self.build("oci-base")
        with (
            mock.patch.object(run, "run_builder", self.fake_builder),
            mock.patch.object(modules, "install_lines", return_value=[]),
        ):
            result = self.build("node-26", {})
        self.assertEqual(self.dependencies(result)[-2:], ["parent: oci-base", "ancestor: core"])
        assert result.artifact.path is not None
        annotations = ocilayout.read_layout(result.artifact.path).manifest.annotations
        self.assertEqual(annotations[oci.BASE_DIGEST], f"sha256:{base.artifact.digest}")

    def test_the_same_inputs_give_the_same_manifest_digest(self) -> None:
        first = self.build("oci-base")
        second = self.build("oci-base")
        self.assertEqual(first.artifact.digest, second.artifact.digest)
        self.assertEqual(first.artifact.name, second.artifact.name)

    def test_a_missing_parent_stops_the_build_with_a_clear_message(self) -> None:
        shutil.rmtree(self.out)
        self.out.mkdir()
        with self.assertRaisesRegex(commands.Failed, r"images\.oci-base: its parent core .* not built in this run"):
            self.build("oci-base")

    def test_the_image_adds_a_layer_only_when_it_changes_the_filesystem(self) -> None:
        images = self.loaded.definition.images
        entries = self.context.plan["images"]
        self.assertFalse(run.adds_layer(images["oci-base"], entries["oci-base"]))
        self.assertTrue(run.adds_layer(images["node-26"], entries["node-26"]))
        with_packages = {**entries["oci-base"], "request": ("jq",)}
        self.assertTrue(run.adds_layer(images["oci-base"], with_packages))  # type: ignore[arg-type]  # a plan entry with one field changed
        with_hooks = definition.Image("x", "oci", "core", (), None, ("hooks/a.sh",), "live", "gzip", {}, {})
        self.assertTrue(run.adds_layer(with_hooks, entries["oci-base"]))
        with_files = definition.Image("x", "oci", "core", (), "files/x", (), "live", "gzip", {}, {})
        self.assertTrue(run.adds_layer(with_files, entries["oci-base"]))


class CommandLineTest(unittest.TestCase):
    def test_build_takes_parents_targets_repeatedly(self) -> None:
        arguments = cli.parser().parse_args(
            ["build", "plan.json", "--out", "out", "--parents", "dir:///a", "--parents", "oci://r.example/x"]
        )
        self.assertEqual(arguments.parents, ["dir:///a", "oci://r.example/x"])
        self.assertEqual(cli.parser().parse_args(["build", "plan.json", "--out", "out"]).parents, [])

    def test_parent_targets_are_split_by_kind_and_a_bad_one_is_a_usage_error(self) -> None:
        directories, registries = run.split_parent_targets(["dir:///srv/images", "oci://r.example/team/img"])
        self.assertEqual(directories, [Path("/srv/images")])
        self.assertEqual(registries, [published.OciTarget("r.example", "team/img")])
        for bad in ("github-release://o/r@v1", "ftp://x", "nonsense"):
            with self.assertRaises(commands.Usage):
                run.split_parent_targets([bad])

    def test_oci_is_a_supported_kind_and_selected_in_parent_order(self) -> None:
        self.assertIn("oci", run.SUPPORTED_KINDS)
        self.assertEqual(run.EXTENSIONS["oci"], "oci")


if __name__ == "__main__":
    unittest.main()
