"""`test` on an output directory holding OCI image layouts: discovery, each check on synthetic layers, and
the records it writes, with a stand-in for docker."""

import io
import json
import shutil
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

from debian_image_factory import oci, records
from debian_image_factory.checks import command
from debian_image_factory.checks.container import ProbeRunner
from debian_image_factory.checks.model import LOCKED_INPUTS, CheckOutcome, NotRun, Result, result
from debian_image_factory.commands import Sources, Usage
from debian_image_factory.definition import Module
from debian_image_factory.modules import Probe
from debian_image_factory.planfile import ImageEntry, parse_plan
from tests.support import ocimage
from tests.support.fakedocker import FakeDocker, reading
from tests.support.ocimage import OCI_IDENTITY, Built
from tests.support.rootfs import BASE, IDENTITY, SNAPSHOT, Entry, clean_files, sbom_line, status_text, write_artifact

KEY = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n"
OCI_CHECKS = (
    "ancestry",
    "no-build-snapshot",
    "no-machine-identity",
    "oci-run",
    "package-set",
    "sbom-complete",
    "two-clones",
)
MACHINE = "/etc/machine-id"
APP_LAYER: dict[str, Entry] = {"./srv/": None, "./srv/app": b"#!/bin/sh\n"}
DECLARED = oci.OciConfig("0:0", None, ("/bin/sh", "-c", "exit 0"))


def output_of(lines: str, *, check: str) -> list[str]:
    return [line for line in lines.splitlines() if f": {check} " in line]


class Out:
    """An output directory: a core tarball, an OCI image built on it, and the plan."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.core_path, self.core_digest = write_artifact(root, clean_files(), IDENTITY)
        self.core_bytes = self.core_path.read_bytes()

    def image(
        self,
        layers: Sequence[Mapping[str, Entry] | bytes] | None = None,
        *,
        annotations: Mapping[str, str] | None = None,
        config: oci.OciConfig = DECLARED,
        checks: Sequence[str] = OCI_CHECKS,
        core_artifact: str | None = None,
    ) -> Built:
        stack: Sequence[Mapping[str, Entry] | bytes] = layers if layers is not None else [self.core_bytes, APP_LAYER]
        notes = {oci.BASE_DIGEST: f"sha256:{self.core_digest}"} if annotations is None else dict(annotations)
        built = ocimage.write_oci(self.root, "app", stack, config=config, annotations=notes)
        core = ocimage.entry("core", identity=IDENTITY, artifact=core_artifact)
        app = ocimage.entry("oci", parent="core", checks=checks)
        (self.root / "plan.json").write_text(ocimage.plan_json({"core": core, "app": app}))
        (self.root / records_name(built.digest)).write_text(sbom_line(built.path.name, built.digest, BASE))
        return built

    def run(
        self,
        docker: FakeDocker,
        requested: Sequence[str] = (),
        locked: command.LockedInputs = command.locked_inputs_result,
    ) -> tuple[int, str]:
        out = io.StringIO()
        effects = command.Effects(
            clones_check=lambda path: NotRun("two-clones", "core is not tested here"),
            docker=docker.docker(),
            locked_inputs=locked,
        )
        status = command.test_command(self.root, requested, Sources(), out, effects)
        return status, out.getvalue()

    def statements(self, built: Built) -> list[dict[str, object]]:
        path = self.root / records_name(built.digest)
        text = path.read_text() if path.exists() else ""
        return [
            s
            for s in records.decode_statements(text)
            if s.get("predicateType") == "https://in-toto.io/attestation/test-result/v0.1"
        ]


def records_name(digest: str) -> str:
    return f"{digest}.intoto.jsonl"


def checks_recorded(statements: Sequence[Mapping[str, object]]) -> dict[str, object]:
    found: dict[str, object] = {}
    for statement in statements:
        predicate = statement["predicate"]
        assert isinstance(predicate, dict)
        configuration = predicate["configuration"]
        assert isinstance(configuration, list)
        found[str(configuration[0]["name"])] = predicate["result"]
    return found


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Out(Path(self.tmp.name))


class DiscoveryTest(Base):
    def found(self) -> tuple[list[command.Found], list[str]]:
        plan = parse_plan(json.loads((self.out.root / "plan.json").read_text()))
        return command.find_artifacts(self.out.root, plan)

    def test_a_layout_is_found_with_its_manifest_digest_and_its_layers(self) -> None:
        built = self.out.image()
        found, skipped = self.found()
        self.assertEqual(skipped, [])
        by_image = {one.image: one for one in found}
        self.assertEqual(set(by_image), {"core", "app"})
        app = by_image["app"]
        self.assertEqual((app.path, app.digest), (built.path, built.digest))
        assert app.layout is not None
        self.assertEqual(tuple(layer.digest for layer in app.layout.manifest.layers), built.layers)
        self.assertIsNone(by_image["core"].layout)

    def test_a_directory_whose_name_does_not_say_its_manifest_is_skipped(self) -> None:
        built = self.out.image()
        renamed = built.path.with_name(built.path.name.replace(built.digest[:12], "0" * 12))
        built.path.rename(renamed)
        found, skipped = self.found()
        self.assertEqual([one.image for one in found], ["core"])
        self.assertEqual(len(skipped), 1)
        self.assertIn(renamed.name, skipped[0])
        self.assertIn("does not say", skipped[0])

    def test_a_directory_that_is_not_a_layout_is_skipped_with_the_reason(self) -> None:
        built = self.out.image()
        (built.path / "index.json").unlink()
        found, skipped = self.found()
        self.assertEqual([one.image for one in found], ["core"])
        self.assertIn("not a readable OCI image layout", skipped[0])

    def test_a_layout_with_a_blob_that_does_not_match_is_skipped(self) -> None:
        built = self.out.image()
        (built.path / "blobs" / "sha256" / built.layers[1]).write_bytes(b"other")
        found, skipped = self.found()
        self.assertEqual([one.image for one in found], ["core"])
        self.assertIn("does not match", skipped[0])

    def test_an_oci_directory_of_an_image_that_is_not_oci_is_skipped(self) -> None:
        built = self.out.image()
        text = (self.out.root / "plan.json").read_text().replace('"kind": "oci"', '"kind": "incus"')
        (self.out.root / "plan.json").write_text(text)
        found, skipped = command.find_artifacts(self.out.root, parse_plan(json.loads(text)))
        self.assertEqual([one.image for one in found], ["core"])
        self.assertIn(built.path.name, skipped[0])

    def test_an_unknown_image_is_skipped(self) -> None:
        self.out.image()
        text = (
            (self.out.root / "plan.json")
            .read_text()
            .replace('"identity": "' + OCI_IDENTITY, '"identity": "' + "99" * 32)
        )
        found, skipped = command.find_artifacts(self.out.root, parse_plan(json.loads(text)))
        self.assertEqual([one.image for one in found], ["core"])
        self.assertIn("no image of the plan", skipped[0])


class RunTest(Base):
    def test_a_good_image_passes_every_check_and_each_is_recorded_for_the_directory(self) -> None:
        built = self.out.image()
        fake = FakeDocker(identities=[reading({MACHINE: b"a\n"}), reading({MACHINE: b"b\n"})])
        status, printed = self.out.run(fake)
        self.assertEqual(status, 0, printed)
        recorded = self.out.statements(built)
        self.assertEqual(checks_recorded(recorded), dict.fromkeys(OCI_CHECKS, "PASSED"))
        for statement in recorded:
            self.assertEqual(statement["subject"], [{"name": built.path.name, "digest": {"sha256": built.digest}}])
        self.assertEqual(len(output_of(printed, check="oci-run")), 1)
        self.assertEqual(fake.loaded, [built.path])
        self.assertEqual(fake.verbs().count("load"), 1)
        self.assertIn("rmi", fake.verbs())

    def test_the_image_is_loaded_once_for_every_check_that_runs_it(self) -> None:
        self.out.image(checks=("oci-run", "two-clones", "locked-inputs"))
        fake = FakeDocker(identities=["", ""])
        self.out.run(fake)
        self.assertEqual(fake.verbs().count("load"), 1)
        self.assertEqual(fake.verbs().count("rmi"), 1)

    def test_no_image_is_loaded_when_no_check_runs_it(self) -> None:
        self.out.image(checks=("package-set", "ancestry"))
        fake = FakeDocker()
        self.out.run(fake)
        self.assertEqual(fake.commands, [])

    def test_a_failing_cmd_fails_oci_run_and_the_exit_status(self) -> None:
        built = self.out.image()
        status, printed = self.out.run(FakeDocker(exit_code=1, identities=["", ""]))
        self.assertEqual(status, 1)
        self.assertEqual(checks_recorded(self.out.statements(built))["oci-run"], "FAILED")
        self.assertIn("app: oci-run FAILED: exits-0: it exited 1", printed)

    def test_without_docker_the_container_checks_are_not_run_and_write_nothing(self) -> None:
        built = self.out.image()
        status, printed = self.out.run(FakeDocker(missing=True))
        self.assertEqual(status, 0)
        recorded = checks_recorded(self.out.statements(built))
        self.assertEqual(
            sorted(recorded), ["ancestry", "no-build-snapshot", "no-machine-identity", "package-set", "sbom-complete"]
        )
        self.assertIn("app: oci-run not run: docker is not available", printed)
        self.assertIn("app: two-clones not run: docker is not available", printed)

    def test_a_requested_check_runs_alone(self) -> None:
        built = self.out.image()
        self.out.run(FakeDocker(), ["package-set"])
        self.assertEqual(checks_recorded(self.out.statements(built)), {"package-set": "PASSED"})

    def test_a_name_that_is_no_check_is_refused(self) -> None:
        self.out.image()
        with self.assertRaises(Usage):
            self.out.run(FakeDocker(), ["installer-boot"])

    def test_package_set_and_sbom_read_the_status_of_the_last_layer_that_holds_it(self) -> None:
        newer = (*BASE, ("tool-b", "2.0", "amd64"))
        layers: list[Mapping[str, Entry] | bytes] = [
            self.out.core_bytes,
            {"./var/": None, "./var/lib/": None, "./var/lib/dpkg/": None, "./var/lib/dpkg/status": status_text(newer)},
        ]
        built = self.out.image(layers)
        status, printed = self.out.run(FakeDocker(), ["package-set"])
        self.assertEqual(status, 1, printed)
        self.assertIn("tool-b 2.0 (amd64) is in the image and not in the plan", printed)
        self.assertEqual(checks_recorded(self.out.statements(built)), {"package-set": "FAILED"})

    def test_a_status_a_later_layer_deletes_is_gone_from_the_merged_view(self) -> None:
        layers: list[Mapping[str, Entry] | bytes] = [self.out.core_bytes, {"./var/lib/dpkg/.wh.status": b""}]
        self.out.image(layers)
        status, printed = self.out.run(FakeDocker(), ["package-set"])
        self.assertEqual(status, 1)
        self.assertIn("dpkg-status-readable", printed)


class MachineIdentityTest(Base):
    def test_a_machine_id_a_later_layer_empties_passes(self) -> None:
        lower = {"./etc/": None, "./etc/machine-id": b"deadbeef\n"}
        built = self.out.image([lower, {"./etc/machine-id": b"uninitialized\n"}], checks=("no-machine-identity",))
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 0, printed)
        self.assertEqual(checks_recorded(self.out.statements(built)), {"no-machine-identity": "PASSED"})

    def test_a_machine_id_a_later_layer_deletes_is_not_in_the_image(self) -> None:
        lower = {"./etc/": None, "./etc/machine-id": b"deadbeef\n", "./etc/hostname": b"build-box\n"}
        self.out.image(
            [lower, {"./etc/.wh.machine-id": b"", "./etc/.wh.hostname": b""}], checks=("no-machine-identity",)
        )
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 0, printed)

    def test_a_machine_id_with_content_in_the_last_layer_fails(self) -> None:
        self.out.image(
            [{"./etc/": None, "./etc/machine-id": b"deadbeef\n"}], annotations={}, checks=("no-machine-identity",)
        )
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 1)
        self.assertIn("/etc/machine-id holds an identity", printed)

    def test_a_key_a_later_layer_deletes_still_ships_and_fails(self) -> None:
        lower = {"./root/": None, "./root/id_ed25519": KEY}
        built = self.out.image([lower, {"./root/.wh.id_ed25519": b""}], annotations={}, checks=("no-machine-identity",))
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 1)
        self.assertIn("no-private-keys: /root/id_ed25519", printed)
        self.assertEqual(checks_recorded(self.out.statements(built)), {"no-machine-identity": "FAILED"})

    def test_ssh_host_keys_in_a_lower_layer_that_a_later_layer_removes_are_not_members(self) -> None:
        lower = {"./etc/": None, "./etc/ssh/": None, "./etc/ssh/ssh_host_ed25519_key": b"x"}
        self.out.image(
            [lower, {"./etc/ssh/.wh..wh..opq": b"", "./etc/ssh/": None}],
            annotations={},
            checks=("no-machine-identity",),
        )
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 0, printed)


class SnapshotTest(Base):
    def test_the_snapshot_id_in_a_deleted_file_still_fails(self) -> None:
        lower = {"./etc/": None, "./etc/sources": f"file:///snapshot/{SNAPSHOT}\n".encode()}
        self.out.image([lower, {"./etc/.wh.sources": b""}], annotations={}, checks=("no-build-snapshot",))
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 1)
        self.assertIn(f"{SNAPSHOT} is in a content of /etc/sources", printed)

    def test_the_snapshot_id_in_the_config_fails(self) -> None:
        config = oci.OciConfig("0:0", None, ("/bin/sh",), labels=(("built-from", SNAPSHOT),))
        self.out.image([APP_LAYER], annotations={}, config=config, checks=("no-build-snapshot",))
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 1)
        self.assertIn(f"{SNAPSHOT} is in a content of the image config", printed)

    def test_the_snapshot_id_in_the_manifest_fails(self) -> None:
        self.out.image(
            [APP_LAYER], annotations={"org.opencontainers.image.source": f"x/{SNAPSHOT}"}, checks=("no-build-snapshot",)
        )
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 1)
        self.assertIn("the image manifest", printed)

    def test_a_clean_image_passes(self) -> None:
        self.out.image(checks=("no-build-snapshot",))
        self.assertEqual(self.out.run(FakeDocker())[0], 0)


class AncestryCommandTest(Base):
    def ancestry(
        self, layers: Sequence[Mapping[str, Entry] | bytes] | None = None, annotations: Mapping[str, str] | None = None
    ) -> tuple[int, str, Built]:
        built = self.out.image(layers, annotations=annotations, checks=("ancestry",))
        status, printed = self.out.run(FakeDocker())
        return status, printed, built

    def test_an_image_on_a_core_artifact_passes(self) -> None:
        status, printed, built = self.ancestry()
        self.assertEqual(status, 0, printed)
        self.assertEqual(checks_recorded(self.out.statements(built)), {"ancestry": "PASSED"})

    def test_a_first_layer_that_is_not_the_parent_fails(self) -> None:
        status, printed, _ = self.ancestry([{"./etc/": None}, APP_LAYER])
        self.assertEqual(status, 1)
        self.assertIn("parent-layers-are-first: layer 1 is sha256:", printed)

    def test_the_parent_layer_in_second_place_fails(self) -> None:
        status, printed, _ = self.ancestry([APP_LAYER, self.out.core_bytes])
        self.assertEqual(status, 1)
        self.assertIn("parent-layers-are-first", printed)

    def test_a_wrong_base_digest_fails(self) -> None:
        status, printed, _ = self.ancestry(annotations={oci.BASE_DIGEST: "sha256:" + "7" * 64})
        self.assertEqual(status, 1)
        self.assertIn("base-digest-annotation", printed)

    def test_a_missing_core_parent_is_not_run_when_the_plan_names_no_artifact(self) -> None:
        built = self.out.image(checks=("ancestry",))
        self.out.core_path.unlink()
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 0)
        self.assertIn(
            "app: ancestry not run: the parent core is not in the output and the plan names no artifact for it", printed
        )
        self.assertEqual(self.out.statements(built), [])

    def test_a_core_parent_not_built_here_is_known_by_the_plans_artifact_digest(self) -> None:
        built = self.out.image(checks=("ancestry",), core_artifact=f"sha256:{self.out.core_digest}")
        self.out.core_path.unlink()
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 0, printed)
        self.assertEqual(checks_recorded(self.out.statements(built)), {"ancestry": "PASSED"})

    def test_an_oci_parent_not_in_the_output_is_not_run(self) -> None:
        parent = ocimage.write_oci(
            self.out.root,
            "base",
            [self.out.core_bytes],
            annotations={oci.BASE_DIGEST: f"sha256:{self.out.core_digest}"},
            identity=ocimage.CHILD_IDENTITY,
        )
        child = ocimage.write_oci(
            self.out.root,
            "app",
            [self.out.core_bytes, APP_LAYER],
            annotations={oci.BASE_DIGEST: f"sha256:{parent.digest}"},
        )
        entries = {
            "core": ocimage.entry("core", identity=IDENTITY),
            "base": ocimage.entry(
                "oci", parent="core", identity=ocimage.CHILD_IDENTITY, artifact=f"sha256:{parent.digest}"
            ),
            "app": ocimage.entry("oci", parent="base", checks=("ancestry",)),
        }
        (self.out.root / "plan.json").write_text(ocimage.plan_json(entries))
        shutil.rmtree(parent.path)
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 0)
        self.assertIn("app: ancestry not run: the parent sha256:" + parent.digest + " is not in the output", printed)
        self.assertEqual(self.out.statements(child), [])

    def test_an_oci_parent_in_the_output_gives_its_layers(self) -> None:
        parent = ocimage.write_oci(
            self.out.root,
            "base",
            [self.out.core_bytes, {"./b": b"1"}],
            annotations={oci.BASE_DIGEST: f"sha256:{self.out.core_digest}"},
            identity=ocimage.CHILD_IDENTITY,
        )
        notes = {oci.BASE_DIGEST: f"sha256:{parent.digest}"}
        wrong = ocimage.write_oci(
            self.out.root, "app", [self.out.core_bytes, {"./b": b"2"}, APP_LAYER], annotations=notes
        )
        entries = {
            "core": ocimage.entry("core", identity=IDENTITY),
            "base": ocimage.entry("oci", parent="core", identity=ocimage.CHILD_IDENTITY),
            "app": ocimage.entry("oci", parent="base", checks=("ancestry",)),
        }
        (self.out.root / "plan.json").write_text(ocimage.plan_json(entries))
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 1)
        self.assertIn("layer 2 is sha256:", printed)
        shutil.rmtree(wrong.path)
        good = ocimage.write_oci(
            self.out.root, "app", [self.out.core_bytes, {"./b": b"1"}, APP_LAYER], annotations=notes
        )
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 0, printed)
        self.assertEqual(checks_recorded(self.out.statements(good))["ancestry"], "PASSED")


class LockedInputsTest(Base):
    def test_an_image_without_entries_passes_with_nothing_to_probe(self) -> None:
        built = self.out.image(checks=("locked-inputs",))
        status, printed = self.out.run(FakeDocker())
        self.assertEqual(status, 0, printed)
        self.assertIn("app: locked-inputs PASSED", printed)
        self.assertEqual(checks_recorded(self.out.statements(built)), {"locked-inputs": "PASSED"})

    def test_the_seam_gets_the_entry_the_status_and_a_runner_into_the_loaded_image(self) -> None:
        built = self.out.image(checks=("locked-inputs",))
        seen: list[tuple[ImageEntry, bytes | None, str, tuple[int, str]]] = []

        def locked(
            entry: ImageEntry, status: bytes | None, run: ProbeRunner, modules: Mapping[str, Module] | None
        ) -> CheckOutcome:
            seen.append((entry, status, "", run(Probe("node", ("/usr/bin/node", "-v"), "v1"))))
            return result(LOCKED_INPUTS, ["locked-inputs"])

        fake = FakeDocker(probes={"/usr/bin/node": (0, "v1\n")})
        status, printed = self.out.run(fake, locked=locked)
        self.assertEqual(status, 0, printed)
        ((entry, dpkg, _, ran),) = seen
        self.assertEqual(entry["kind"], "oci")
        self.assertIn(b"Package: apt", dpkg or b"")
        self.assertEqual(ran, (0, "v1\n"))
        self.assertEqual(checks_recorded(self.out.statements(built)), {"locked-inputs": "PASSED"})
        self.assertIn("rmi", fake.verbs())

    def test_docker_failing_inside_the_seam_is_not_run(self) -> None:
        self.out.image(checks=("locked-inputs",))

        def locked(
            entry: ImageEntry, status: bytes | None, run: ProbeRunner, modules: Mapping[str, Module] | None
        ) -> CheckOutcome:
            raise FileNotFoundError("docker")

        status, printed = self.out.run(FakeDocker(), locked=locked)
        self.assertEqual(status, 0)
        self.assertIn("locked-inputs not run: docker failed", printed)


if __name__ == "__main__":
    unittest.main()


class LockedInputsSeamTest(unittest.TestCase):
    """The default `locked-inputs` seam: module probes need the definition's tables."""

    def entry(self) -> ImageEntry:
        plan = json.loads(ocimage.plan_json({"node": ocimage.entry(kind="oci", parent="core")}))
        entry: ImageEntry = plan["images"]["node"]
        entry["inputs"] = {
            "node-26": {"module": "node", "version": "26.13.1", "sha256": "0" * 64, "url": "https://x/n.tar.xz"},
            "node-release-keys": {"module": "node", "version": "1", "sha256": "1" * 64, "url": "https://x/k.kbx"},
        }
        entry["trust"] = {"node-26": {"signed_by": "node-release-keys", "sums_url": "https://x/SHASUMS256.txt.asc"}}
        return entry

    def test_without_a_definition_module_entries_are_not_run(self) -> None:
        outcome = command.locked_inputs_result(self.entry(), None, lambda probe: (0, ""), None)
        self.assertIsInstance(outcome, NotRun)

    def test_the_node_probe_runs_and_the_keyring_is_a_trust_root(self) -> None:
        modules = {"node": Module("node", "builtin:node-tarball", None, {"prefix": "/usr/local"})}
        ran: list[tuple[str, ...]] = []

        def run(probe: Probe) -> tuple[int, str]:
            ran.append(probe.argv)
            return 0, "v26.13.1\n"

        outcome = command.locked_inputs_result(self.entry(), None, run, modules)
        assert isinstance(outcome, Result)
        self.assertEqual(outcome.outcome, "PASSED", outcome.failed)
        self.assertEqual(ran, [("/usr/local/bin/node", "--version")])
        wrong = command.locked_inputs_result(self.entry(), None, lambda probe: (0, "v26.12.0\n"), modules)
        assert isinstance(wrong, Result)
        self.assertEqual(wrong.outcome, "FAILED")
