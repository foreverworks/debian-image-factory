"""`plan.json` read back: a real plan's output parses, and every field the plan command writes is checked."""

import json
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from debian_image_factory import planfile
from tests.support.fixture_archive import FIRST_ID
from tests.test_fetch import FetchCase


def obj(document: dict[str, object], *keys: str) -> dict[str, object]:
    """The object at `keys` inside a parsed JSON document, checked on the way down."""
    node: object = document
    for key in keys:
        assert isinstance(node, dict)
        node = node[key]
    assert isinstance(node, dict)
    return node


class PlanFileTest(FetchCase):
    def failing(self, edit: Callable[[dict[str, object]], object], pattern: str) -> None:
        document = json.loads(self.plan_text)
        edit(document)
        with self.assertRaisesRegex(ValueError, pattern):
            planfile.parse_plan(document)

    def test_a_real_plan_parses(self) -> None:
        plan = planfile.parse_plan(json.loads(self.plan_text))
        self.assertEqual((plan["schema"], plan["engine"], plan["baseline"]), (2, 1, None))
        self.assertEqual(plan["snapshots"], {"debian": FIRST_ID, "debian-security": FIRST_ID})
        self.assertEqual(plan["debian"], {"suite": "trixie", "components": ("main",), "architecture": "amd64"})
        self.assertEqual(sorted(plan["images"]), ["app-a", "app-b", "app-c", "core"])
        core, app_a = plan["images"]["core"], plan["images"]["app-a"]
        self.assertEqual((core["kind"], core["parent"], core["parent_identity"]), ("core", None, None))
        self.assertEqual((app_a["parent"], app_a["state"]), ("core", "build"))
        self.assertIn(("lib-a", "1.0", "all"), app_a["packages"])
        self.assertTrue(all(isinstance(package, tuple) and len(package) == 3 for package in app_a["packages"]))
        self.assertEqual(plan["images"]["app-b"]["params"], {"flag": False})
        self.assertEqual(app_a["inputs"], {})
        self.assertEqual(core["because"], [{"published": "no artifact with this identity"}])

    def test_read_plan_reads_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "plan.json"
            path.write_text(self.plan_text)
            self.assertEqual(planfile.read_plan(path), planfile.parse_plan(json.loads(self.plan_text)))
            path.write_text("[")
            with self.assertRaisesRegex(ValueError, "not JSON"):
                planfile.read_plan(path)
            with self.assertRaises(FileNotFoundError):
                planfile.read_plan(Path(name) / "missing.json")

    def test_input_fields_may_be_text_lists_or_null(self) -> None:
        def add(d: dict[str, object]) -> None:
            obj(d, "images", "core")["inputs"] = {"x": {"url": "u", "module": None, "used_by": ["core"]}}

        document = json.loads(self.plan_text)
        add(document)
        plan = planfile.parse_plan(document)
        self.assertEqual(plan["images"]["core"]["inputs"]["x"]["module"], None)
        self.assertEqual(plan["images"]["core"]["inputs"]["x"]["used_by"], ["core"])

    def test_optional_fields_are_kept_when_present(self) -> None:
        def add(d: dict[str, object]) -> None:
            obj(d, "images", "app-a").update(
                {"artifact": f"sha256:{'ab' * 32}", "waiting_for": ["c"], "rejected": ["why"]}
            )

        document = json.loads(self.plan_text)
        add(document)
        app_a = planfile.parse_plan(document)["images"]["app-a"]
        self.assertEqual(
            (app_a["artifact"], app_a["waiting_for"], app_a["rejected"]), (f"sha256:{'ab' * 32}", ["c"], ["why"])
        )

    def test_an_artifact_that_is_not_a_sha256_digest_is_refused(self) -> None:
        for bad in ("ab" * 32, "sha256:x", 7):
            document = json.loads(self.plan_text)
            obj(document, "images", "app-a")["artifact"] = bad
            with self.assertRaisesRegex(ValueError, "artifact"):
                planfile.parse_plan(document)

    def test_every_top_level_field_is_checked(self) -> None:
        self.failing(lambda d: d.update(schema=3), "schema must be 2")
        for key in ("snapshots", "factory", "engine", "baseline", "debian", "params", "images"):
            self.failing(lambda d, key=key: d.pop(key), f"{key} is missing")  # type: ignore[misc]  # bound per key
        self.failing(lambda d: obj(d, "snapshots").update(debian="../x"), r"snapshots\.debian is '../x'")
        self.failing(
            lambda d: obj(d, "snapshots").pop("debian-security"), "snapshots must name exactly debian, debian-security"
        )
        self.failing(lambda d: obj(d, "snapshots").update(other=FIRST_ID), "snapshots must name exactly")
        self.failing(lambda d: d.update(snapshots=FIRST_ID), "snapshots must be an object")
        self.failing(lambda d: d.update(engine="1"), "engine must be a whole number")
        self.failing(lambda d: d.update(baseline=3), "baseline must be non-empty text")
        self.failing(lambda d: d.update(params=[]), "params must be an object")
        self.failing(lambda d: d.update(params={"a": [1]}), r"params\.a must be text")
        self.failing(lambda d: d.update(images=[]), "images must be an object")

    def test_a_schema_1_plan_is_refused_and_says_why(self) -> None:
        document = json.loads(self.plan_text)
        document["schema"] = 1
        document["snapshot"] = document.pop("snapshots")["debian"]
        with self.assertRaisesRegex(ValueError, r"schema 1, which names one snapshot for both archives.*`plan`"):
            planfile.parse_plan(document)

    def test_debian_is_checked(self) -> None:
        self.failing(lambda d: obj(d, "debian").pop("suite"), r"debian\.suite is missing")
        self.failing(lambda d: obj(d, "debian").update(suite="../x"), "debian.suite is '../x'")
        self.failing(lambda d: obj(d, "debian").update(components="main"), "debian.components must be a list")
        self.failing(lambda d: obj(d, "debian").update(components=[]), "debian.components must name")
        self.failing(lambda d: obj(d, "debian").update(architecture=3), "debian.architecture must be")

    def test_every_image_field_is_checked(self) -> None:
        for key in (
            "kind", "parent", "identity", "parent_identity", "recipe", "apt_sources", "request", "packages",
            "inputs", "modules", "trust", "params", "checks", "state",
        ):  # fmt: skip
            self.failing(lambda d, key=key: obj(d, "images", "core").pop(key), rf"images\.core\.{key} is missing")  # type: ignore[misc]  # bound per key
        self.failing(lambda d: obj(d, "images").update(core=[]), r"images\.core must be an object")
        self.failing(lambda d: obj(d, "images", "core").update(state="done"), r"images\.core\.state is 'done'")
        self.failing(lambda d: obj(d, "images", "core").update(request="apt"), r"images\.core\.request must be a list")
        self.failing(lambda d: obj(d, "images", "core").update(checks=[1]), r"images\.core\.checks\[0\] must be")
        self.failing(lambda d: obj(d, "images", "core").update(modules={}), r"images\.core\.modules must be a list")
        self.failing(lambda d: obj(d, "images", "core").update(params=[]), r"images\.core\.params must be an object")
        self.failing(lambda d: obj(d, "images", "core").update(trust=[]), r"images\.core\.trust must be an object")
        self.failing(
            lambda d: obj(d, "images", "core").update(trust={"a": 3}), r"images\.core\.trust\.a must be an object"
        )
        self.failing(
            lambda d: obj(d, "images", "core").update(trust={"a": {"sums_url": "https://x.example/s"}}),
            r"images\.core\.trust\.a\.signed_by is missing",
        )
        self.failing(
            lambda d: obj(d, "images", "core").update(trust={"a": {"signed_by": "k", "url": "https://x.example/s"}}),
            r"images\.core\.trust\.a has fields \['url'\]",
        )
        self.failing(
            lambda d: obj(d, "images", "core").update(
                trust={"a": {"signed_by": "k", "sums_sig_url": "https://x.example/s"}}
            ),
            r"sums_sig_url needs a sums_url",
        )
        self.failing(
            lambda d: obj(d, "images", "core").update(trust={"a": {"signed_by": 3}}),
            r"images\.core\.trust\.a\.signed_by must be non-empty text",
        )
        self.failing(lambda d: obj(d, "images", "core").update(parent=4), r"images\.core\.parent must be")

    def test_packages_are_three_texts(self) -> None:
        self.failing(
            lambda d: obj(d, "images", "core").update(packages=[["apt", "1"]]),
            r"packages\[0\] must be \[name, version, arch",
        )
        self.failing(
            lambda d: obj(d, "images", "core").update(packages=[["apt", 1, "amd64"]]), r"packages\[0\]\[1\] must be"
        )
        self.failing(
            lambda d: obj(d, "images", "core").update(packages="apt"), r"images\.core\.packages must be a list"
        )

    def test_inputs_fields_are_checked(self) -> None:
        self.failing(lambda d: obj(d, "images", "core").update(inputs=[]), r"images\.core\.inputs must be an object")
        self.failing(
            lambda d: obj(d, "images", "core").update(inputs={"x": 3}), r"images\.core\.inputs\.x must be an object"
        )
        self.failing(
            lambda d: obj(d, "images", "core").update(inputs={"x": {"url": 3}}), r"inputs\.x\.url must be text"
        )

    def test_a_document_that_is_not_an_object(self) -> None:
        with self.assertRaisesRegex(ValueError, "the plan must be an object"):
            planfile.parse_plan([])


if __name__ == "__main__":
    unittest.main()
