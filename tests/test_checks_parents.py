"""`test` on a child whose parent is not in OUT: the digest the plan names for it, and with `--parents` the
layers its registry's manifest lists, so `ancestry` runs instead of waiting for a parent that is never there
(a Node bump on a night Debian published nothing: Node builds, its Debian-built parent is only reused)."""

import io
import json
import tempfile
import unittest
from pathlib import Path

from debian_image_factory import cli, commands, oci, ocilayout, publish, records
from debian_image_factory.checks import command
from debian_image_factory.planfile import parse_plan
from debian_image_factory.published import OciTarget, TargetTemplate, format_target, parse_template
from tests.support import fake_registry, ocimage
from tests.support.definitions import example_definition
from tests.support.fake_registry import Fake
from tests.support.oci_fixtures import make_image
from tests.support.rootfs import IDENTITY, clean_files, write_artifact
from tests.test_plan import inputs_for, make, reuse_all


def template(target: OciTarget) -> TargetTemplate:
    return parse_template(format_target(target))


APP_LAYER: dict[str, object] = {"./srv/": None, "./srv/app": b"#!/bin/sh\n"}
PARENT_IDENTITY = "c3" * 32


class PlannedDigestTest(unittest.TestCase):
    def test_the_digest_a_plan_writes_is_the_digest_test_reads(self) -> None:
        spec = example_definition()
        document = make(inputs_for(spec), reuse_all(spec), spec)
        read = parse_plan(json.loads(json.dumps(document)))
        for name, entry in read["images"].items():
            digest = command.planned_digest(entry)
            self.assertEqual(entry["artifact"], f"sha256:{digest}", name)
            self.assertIsNotNone(digest, name)

    def test_an_image_the_plan_builds_names_none(self) -> None:
        spec = example_definition()
        decisions = reuse_all(spec)
        del decisions["core"]
        read = parse_plan(json.loads(json.dumps(make(inputs_for(spec), decisions, spec))))
        self.assertIsNone(command.planned_digest(read["images"]["core"]))


class ParentFromRegistryTest(unittest.TestCase):
    """A child in OUT, built on an OCI parent that is reused from a registry."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "out"
        self.out.mkdir()
        self.core_path, self.core_digest = write_artifact(self.out, clean_files(), IDENTITY)
        self.core_bytes = self.core_path.read_bytes()
        # the parent, as a registry holds it: published from its own directory, never in OUT
        self.parent = make_image(self.root / "parent", image="base", identity=PARENT_IDENTITY)
        layout = ocilayout.read_layout(self.parent.layout)
        self.parent_layers = [
            ocilayout.blob_path(self.parent.layout, one.digest).read_bytes() for one in layout.manifest.layers
        ]

    def child(self, layers: list[bytes | dict[str, object]], base: str | None = None) -> ocimage.Built:
        built = ocimage.write_oci(
            self.out,
            "node-26",
            layers,  # type: ignore[arg-type]  # a test layer is gzip bytes or the entries `rootfs` takes
            annotations={oci.BASE_DIGEST: f"sha256:{base or self.parent.digest}"},
        )
        entries = {
            "core": ocimage.entry("core", identity=IDENTITY, artifact=f"sha256:{self.core_digest}"),
            "base": ocimage.entry(
                "oci", parent="core", identity=PARENT_IDENTITY, artifact=f"sha256:{self.parent.digest}"
            ),
            "node-26": ocimage.entry("oci", parent="base", checks=("ancestry",)),
        }
        (self.out / "plan.json").write_text(ocimage.plan_json(entries))
        return built

    def run_test(self, **more: object) -> tuple[int, str]:
        said = io.StringIO()
        used = command.Effects(**more)  # type: ignore[arg-type]  # keyword fields of Effects, passed through
        status = command.test_command(self.out, [], commands.Sources(), said, used)
        return status, said.getvalue()

    def recorded(self, built: ocimage.Built) -> dict[str, object]:
        """The results of `test` attested for `built`, by check name."""
        path = self.out / f"{built.digest}.intoto.jsonl"
        found: dict[str, object] = {}
        for statement in records.decode_statements(path.read_text() if path.exists() else ""):
            predicate = statement["predicate"]
            if isinstance(predicate, dict) and "result" in predicate:
                found[str(predicate["configuration"][0]["name"])] = predicate["result"]
        return found

    def test_without_parents_the_ancestry_check_is_not_run(self) -> None:
        self.child([*self.parent_layers, APP_LAYER])
        status, printed = self.run_test()
        self.assertEqual(status, 0, printed)
        self.assertIn("node-26: ancestry not run: the parent sha256:" + self.parent.digest, printed)

    def test_with_the_parents_registry_a_child_on_the_reused_parent_passes_ancestry(self) -> None:
        built = self.child([*self.parent_layers, APP_LAYER])
        asked: list[tuple[OciTarget, str]] = []

        def layers(target: OciTarget, digest: str) -> tuple[str, ...]:
            asked.append((target, digest))
            return tuple(one.digest for one in ocilayout.read_layout(self.parent.layout).manifest.layers)

        target = OciTarget("registry.example.com", "team/base")
        status, printed = self.run_test(parent_registries=(template(target),), parent_layers=layers)
        self.assertEqual(status, 0, printed)
        self.assertEqual(asked, [(target, self.parent.digest)])
        self.assertIn("node-26: ancestry PASSED", printed)
        self.assertEqual(self.recorded(built), {"ancestry": "PASSED"})

    def test_a_child_that_does_not_start_with_the_parents_layers_fails(self) -> None:
        self.child([self.core_bytes, APP_LAYER])
        target = OciTarget("registry.example.com", "team/base")
        status, printed = self.run_test(
            parent_registries=(template(target),), parent_layers=lambda _t, _d: tuple(["f0" * 32, "f1" * 32])
        )
        self.assertEqual(status, 1)
        self.assertIn("node-26: ancestry FAILED", printed)

    def test_a_registry_that_cannot_give_the_manifest_leaves_the_check_not_run_and_says_why(self) -> None:
        built = self.child([*self.parent_layers, APP_LAYER])

        def refuse(target: OciTarget, digest: str) -> tuple[str, ...]:
            raise OSError(f"{target.registry}: no manifest sha256:{digest}")

        status, printed = self.run_test(
            parent_registries=(template(OciTarget("a.example.com", "x")), template(OciTarget("b.example.com", "y"))),
            parent_layers=refuse,
        )
        self.assertEqual(status, 0, printed)
        self.assertIn("node-26: ancestry not run: the parent base (sha256:" + self.parent.digest, printed)
        self.assertIn("a.example.com: no manifest", printed)
        self.assertIn("b.example.com: no manifest", printed)
        self.assertEqual(self.recorded(built), {})

    def test_the_next_registry_is_tried_when_the_first_lacks_the_parent(self) -> None:
        self.child([*self.parent_layers, APP_LAYER])
        real = tuple(one.digest for one in ocilayout.read_layout(self.parent.layout).manifest.layers)

        def second_only(target: OciTarget, digest: str) -> tuple[str, ...]:
            if target.registry == "a.example.com":
                raise OSError("no such manifest")
            return real

        status, printed = self.run_test(
            parent_registries=(template(OciTarget("a.example.com", "x")), template(OciTarget("b.example.com", "y"))),
            parent_layers=second_only,
        )
        self.assertEqual(status, 0, printed)
        self.assertIn("node-26: ancestry PASSED", printed)

    def test_through_the_command_line_the_manifest_is_read_from_a_real_registry(self) -> None:
        built = self.child([*self.parent_layers, APP_LAYER])
        fake = Fake()
        with fake_registry.running(fake) as name:
            publish.publish_command(self.root / "parent", [f"oci://{name}/team/base"], "none", io.StringIO())
            fake.log.clear()
            said = io.StringIO()
            code = cli.main(["test", str(self.out), "--check", "ancestry", "--parents", f"oci://{name}/team/base"])
            self.assertEqual(code, 0)
            reads = [line for line in fake.log if f"/manifests/sha256:{self.parent.digest}" in line]
            self.assertEqual(len(reads), 1, fake.log)
            self.assertEqual([line for line in fake.log if "/blobs/" in line], [], "only the manifest is read")
        self.assertEqual(self.recorded(built), {"ancestry": "PASSED"})
        self.assertEqual(said.getvalue(), "")

    def test_parents_takes_registries_only(self) -> None:
        for text in ("dir:///somewhere", "github-release://example/images@v1", "not a target"):
            with self.subTest(text), self.assertRaises(commands.Usage):
                cli.parent_registries([text])
        self.assertEqual(
            [one.target for one in cli.parent_registries(["oci://example.com/a/b"])], [OciTarget("example.com", "a/b")]
        )

    def test_a_templated_registry_is_asked_for_the_parent_by_its_own_name(self) -> None:
        self.child([*self.parent_layers, APP_LAYER])
        asked: list[OciTarget] = []

        def layers(target: OciTarget, digest: str) -> tuple[str, ...]:
            asked.append(target)
            return tuple(one.digest for one in ocilayout.read_layout(self.parent.layout).manifest.layers)

        found = cli.parent_registries(["oci://registry.example.com/team/{image}"])
        status, printed = self.run_test(parent_registries=found, parent_layers=layers)
        self.assertEqual(status, 0, printed)
        # the child is node-26 and the parent base: the repository is the parent's, never the child's
        self.assertEqual(asked, [OciTarget("registry.example.com", "team/base")])
        self.assertIn("node-26: ancestry PASSED", printed)

    def test_parents_refuses_a_placeholder_outside_an_oci_repository(self) -> None:
        for text in ("dir:///parents/{image}", "github-release://example/{image}@v1", "oci://{image}.example.com/x"):
            with self.subTest(text), self.assertRaisesRegex(commands.Usage, "belongs in the repository of an oci://"):
                cli.parent_registries([text])


class RegistryLayersTest(unittest.TestCase):
    def test_a_registry_without_the_manifest_says_so(self) -> None:
        with fake_registry.running(Fake()) as name, self.assertRaisesRegex(OSError, "no manifest"):
            command.registry_layers(OciTarget(name, "team/base"), "ab" * 32)
