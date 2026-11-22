"""The GitHub Action (action.yml) and scripts/action-support: the release read from the lock, the plan's summary,
the YAML subset the Action is written in, and the Action's own rules (pinned actions, no expression inside a
script, the inputs and outputs DESIGN 9.2 lists), then its input checks run for real."""

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Final

from tests.support import action, incusimage
from tests.support.action import ROOT, parse_yaml, run_action, support
from tests.support.definitions import example_lock_data
from tests.support.oci_fixtures import make_core_file

WORKFLOWS: Final = ROOT / ".github" / "workflows"
SHA: Final = "ab" * 32


def lock_with(**fields: object) -> dict[str, object]:
    entry = {
        "datasource": "github-releases",
        "sha256": SHA,
        "url": "https://github.com/example/factory/releases/download/v{version}/factory-{version}.pyz",
        "version": "0.6.0",
        **fields,
    }
    return {"inputs": {"debian-image-factory": entry}, "schema": 1}


class ReleaseTest(unittest.TestCase):
    def test_the_release_is_the_lock_s_entry_with_its_url_rendered(self) -> None:
        found = support.release_of(lock_with())
        self.assertEqual(found.version, "0.6.0")
        self.assertEqual(found.url, "https://github.com/example/factory/releases/download/v0.6.0/factory-0.6.0.pyz")
        self.assertEqual(found.sha256, SHA)

    def test_the_example_lock_has_a_placeholder_checksum_and_is_refused_by_name(self) -> None:
        with self.assertRaisesRegex(ValueError, "inputs.debian-image-factory.sha256 is the placeholder"):
            support.release_of(example_lock_data())

    def test_a_lock_without_the_entry_says_to_pin_the_release(self) -> None:
        with self.assertRaisesRegex(ValueError, "inputs.debian-image-factory is missing"):
            support.release_of({"inputs": {}})

    def test_every_field_is_checked(self) -> None:
        for fields, message in (
            ({"version": "../x"}, "version must be a release version"),
            ({"version": 6}, "version must be a release version"),
            ({"url": "http://example.com/{version}.pyz"}, "must be an https URL"),
            ({"url": "https://example.com/a b.pyz"}, "must be an https URL"),
            ({"url": 3}, "url must be the release asset's URL"),
            ({"sha256": "AB" * 32}, "sha256 must be 64 lowercase hex"),
            ({"sha256": "ab"}, "sha256 must be 64 lowercase hex"),
        ):
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, message):
                support.release_of(lock_with(**fields))

    def test_the_lock_s_own_name_is_the_one_the_factory_reserves(self) -> None:
        from debian_image_factory import lockrules

        self.assertEqual(support.FACTORY_ENTRY, lockrules.FACTORY_ENTRY)

    def test_the_command_prints_version_url_and_sha256_one_per_line(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "lock.json"
            path.write_text(json.dumps(lock_with()))
            done = run_support("release", str(path))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.split(), ["0.6.0", support.release_of(lock_with()).url, SHA])


def run_support(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(action.SUPPORT), *argv], capture_output=True, text=True, check=False, env=support_env()
    )


def support_env() -> dict[str, str]:
    return {**os.environ, "PYTHONPATH": f"{ROOT / 'src'}:{ROOT / '.vendor'}"}


def plan_document(**states: tuple[str, str]) -> dict[str, object]:
    """A plan of images given as name=(kind, state)."""
    images: dict[str, object] = {}
    for name, (kind, state) in states.items():
        entry: dict[str, object] = {"kind": kind, "state": state}
        if state != "build":
            entry["artifact"] = "sha256:" + "ab" * 32
        images[name] = entry
    return {"images": images}


class SummaryTest(unittest.TestCase):
    def test_nothing_to_build_is_changed_false(self) -> None:
        document = plan_document(core=("core", "reuse"), box=("os", "wait"))
        self.assertEqual(support.summary_lines(document), ["changed=false", "images=", "vm=false"])

    def test_the_images_that_build_are_named_in_order(self) -> None:
        document = plan_document(core=("core", "reuse"), b=("incus", "build"), a=("oci", "build"))
        self.assertEqual(support.summary_lines(document), ["changed=true", "images=a,b", "vm=false"])

    def test_a_built_installer_or_os_needs_the_vm_image(self) -> None:
        for kind in ("installer", "os"):
            with self.subTest(kind=kind):
                document = plan_document(core=("core", "reuse"), box=(kind, "build"))
                self.assertEqual(support.summary_lines(document)[2], "vm=true")

    def test_an_installer_that_is_reused_needs_no_vm_image(self) -> None:
        self.assertEqual(support.summary_lines(plan_document(box=("installer", "reuse")))[2], "vm=false")

    def test_changed_is_the_factory_s_own_function(self) -> None:
        from debian_image_factory import plan

        document = plan_document(core=("core", "build"), b=("oci", "reuse"))
        self.assertEqual(support.build_names(document), plan.changed(json.loads(json.dumps(document))))

    def test_a_plan_without_images_builds_nothing(self) -> None:
        self.assertEqual(support.summary_lines({})[0], "changed=false")


class ArtifactsTest(unittest.TestCase):
    def test_reused_and_waited_for_artifacts_are_named_with_their_digest(self) -> None:
        document = plan_document(core=("core", "reuse"), box=("os", "wait"), app=("oci", "build"))
        self.assertEqual(
            support.artifacts_of(document, None), {"box": f"sha256:{'ab' * 32}", "core": f"sha256:{'ab' * 32}"}
        )

    def test_a_digest_that_is_already_a_reference_is_kept(self) -> None:
        document = {"images": {"app": {"kind": "oci", "state": "reuse", "artifact": "sha256:" + "cd" * 32}}}
        self.assertEqual(support.artifacts_of(document, None), {"app": "sha256:" + "cd" * 32})

    def test_what_a_build_left_in_out_replaces_the_plan_and_names_every_image(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw)
            core = make_core_file(out, identity="aa" * 32)
            base = incusimage.write_image(out, "incus-base", "bb" * 32, b"a rootfs")
            (out / "plan.json").write_text("{}")
            (out / "core.build.log").write_text("")
            document = plan_document(
                core=("core", "build"), **{"incus-base": ("incus", "build")}, installer=("installer", "reuse")
            )
            found = support.artifacts_of(document, out)
        self.assertEqual(
            found,
            {
                "core": f"sha256:{core.digest}",
                "incus-base": f"sha256:{base.fingerprint}",
                "installer": f"sha256:{'ab' * 32}",
            },
        )

    def test_a_build_directory_that_is_not_there_adds_nothing(self) -> None:
        self.assertEqual(support.artifacts_of(plan_document(), Path("/nonexistent/out")), {})

    def test_an_artifact_without_its_records_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw)
            make_core_file(out, identity="aa" * 32).records.unlink()
            with self.assertRaisesRegex(ValueError, "0 records files"):
                support.built_artifacts(out)

    def test_the_command_prints_one_line_of_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan_path = Path(raw) / "plan.json"
            plan_path.write_text(json.dumps(plan_document(core=("core", "reuse"))))
            done = run_support("artifacts", str(plan_path))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout), {"core": f"sha256:{'ab' * 32}"})
        self.assertEqual(done.stdout.count("\n"), 1)

    def test_the_summary_command_says_what_builds_on_standard_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan_path = Path(raw) / "plan.json"
            plan_path.write_text(json.dumps(plan_document(core=("core", "build"))))
            done = run_support("summary", str(plan_path))
        self.assertEqual(done.stdout.split(), ["changed=true", "images=core", "vm=false"])
        self.assertIn("images to build: core", done.stderr)


class YamlTest(unittest.TestCase):
    def test_mappings_sequences_scalars_and_block_scalars(self) -> None:
        text = (
            "# a comment\n"
            "name: demo\n"
            "on:\n"
            "  schedule:\n"
            '    - cron: "17 2 * * *"\n'
            "jobs:\n"
            "  one:\n"
            "    steps:\n"
            "      - uses: a/b@c # v1\n"
            "        with:\n"
            "          key: value\n"
            "      - name: Run\n"
            "        run: |\n"
            "          echo one\n"
            "\n"
            "            indented\n"
            "          echo two\n"
            "      - run: |-\n"
            "          echo last\n"
            "      - plain item\n"
            "folded: >-\n"
            "  one\n"
            "  two\n"
            'empty: ""\n'
        )
        self.assertEqual(
            parse_yaml(text),
            {
                "name": "demo",
                "on": {"schedule": [{"cron": "17 2 * * *"}]},
                "jobs": {
                    "one": {
                        "steps": [
                            {"uses": "a/b@c", "with": {"key": "value"}},
                            {"name": "Run", "run": "echo one\n\n  indented\necho two\n"},
                            {"run": "echo last"},
                            "plain item",
                        ]
                    }
                },
                "folded": "one two",
                "empty": "",
            },
        )

    def test_flow_collections_are_refused_rather_than_misread(self) -> None:
        with self.assertRaisesRegex(ValueError, "flow collections"):
            parse_yaml("branches: [main]\n")

    def test_the_workflows_the_static_tier_extracts_from_parse(self) -> None:
        for path in (ROOT / "action.yml", WORKFLOWS / "nightly.yml", WORKFLOWS / "ci.yml"):
            with self.subTest(path=path.name):
                self.assertIsInstance(parse_yaml(path.read_text(encoding="utf-8")), dict)

    def test_extraction_writes_each_run_step_and_fails_an_expression_in_one(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            good = directory / "good.yml"
            good.write_text(
                "jobs:\n  a:\n    steps:\n      - name: Hello\n        run: |\n          echo hi\n      - uses: x/y@z\n"
            )
            bad = directory / "bad.yml"
            bad.write_text("jobs:\n  a:\n    steps:\n      - name: Leak\n        run: echo ${{ github.head_ref }}\n")
            out = directory / "out"
            self.assertEqual(support.shell_command(out, [good]), 0)
            scripts = sorted(path.name for path in out.iterdir())
            self.assertEqual(scripts, ["good-01-hello.sh"])
            self.assertEqual((out / scripts[0]).read_text(), "#!/usr/bin/env bash\nset -eo pipefail\necho hi\n")
            self.assertEqual(support.shell_command(out, [bad]), 1)


class ActionFileTest(unittest.TestCase):
    def test_the_inputs_and_outputs_are_the_ones_design_9_2_lists(self) -> None:
        document = action.read_action()
        self.assertEqual(
            list(action.mapping(document["inputs"])),
            [
                "definition",
                "lock",
                "params",
                "snapshot",
                "against",
                "steps",
                "publish",
                "sign",
                "mirror",
                "pyz",
                "token",
                "keep-work",
            ],
        )
        self.assertEqual(list(action.mapping(document["outputs"])), ["changed", "plan", "artifacts"])
        self.assertEqual(action.input_defaults()["steps"], "plan,fetch,build,test")

    def test_it_is_a_composite_action(self) -> None:
        runs = action.mapping(action.read_action()["runs"])
        self.assertEqual(runs["using"], "composite")

    def test_every_run_step_names_its_shell(self) -> None:
        document = action.read_action()
        steps = action.mapping(document["runs"])["steps"]
        assert isinstance(steps, list)
        for step in steps:
            fields = action.mapping(step)
            if "run" in fields:
                self.assertEqual(fields.get("shell"), "bash", fields.get("name"))

    def test_no_script_holds_an_expression(self) -> None:
        for path in (ROOT / "action.yml", WORKFLOWS / "nightly.yml"):
            with tempfile.TemporaryDirectory() as raw:
                self.assertEqual(support.shell_command(Path(raw), [path]), 0, path.name)

    def test_every_action_a_workflow_uses_is_pinned_by_commit_with_its_version(self) -> None:
        pattern = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")
        checked = 0
        for path in (ROOT / "action.yml", *sorted(WORKFLOWS.glob("*.yml"))):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                found = pattern.match(line)
                if found is None or found[1].startswith("./"):
                    continue
                checked += 1
                where = f"{path.name}:{number}"
                self.assertRegex(found[1], r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", where)
                self.assertRegex(found[2], r"^\s+# v\d+(\.\d+)*$", where)
        self.assertGreater(checked, 8)

    def test_the_token_defaults_to_the_workflow_s_and_reaches_only_plan_and_publish_through_env(self) -> None:
        self.assertEqual(action.input_defaults()["token"], "${{ github.token }}")
        holders = {}
        for step in action.read_steps():
            for name, value in step.env.items():
                if "inputs.token" in value:
                    holders[step.id] = name
            self.assertNotIn("token", step.run.lower().replace("github_token", ""), step.name)
        self.assertEqual(holders, {"plan": "GITHUB_TOKEN", "publish": "GITHUB_TOKEN"})

    def test_the_documented_examples_log_in_to_the_registry_with_a_pinned_action_and_say_what_they_need(self) -> None:
        pinned = re.compile(r"docker/login-action@[0-9a-f]{40} # v\d+(\.\d+)*\n")
        for path in (ROOT / "README.md", ROOT / "DESIGN.md"):
            text = path.read_text(encoding="utf-8")
            for block in re.findall(r"```yaml\n(.*?)```", text, re.DOTALL):
                if "oci://" not in block or "foreverworks/debian-image-factory@" not in block:
                    continue
                with self.subTest(path=path.name):
                    self.assertRegex(block, pinned)
                    self.assertIn("password: ${{ github.token }}", block)
                    self.assertIn("packages: write", block)
                    self.assertLess(
                        block.index("docker/login-action"), block.index("foreverworks/debian-image-factory@")
                    )

    def test_the_nightly_uses_the_local_action_and_never_a_public_target(self) -> None:
        text = (WORKFLOWS / "nightly.yml").read_text(encoding="utf-8")
        self.assertIn("uses: ./\n", text)
        self.assertIn("snapshot: latest", text)
        self.assertRegex(text, r"against: dir://")
        self.assertNotRegex(text, r"oci://|github-release://|packages: write|contents: write")
        self.assertIn("group: nightly", text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("runs-on: ubuntu-26.04\n", text)

    def test_the_nightly_definition_needs_no_registry(self) -> None:
        from debian_image_factory import definition

        spec = definition.parse((ROOT / ".github" / "nightly" / "factory.toml").read_text(encoding="utf-8"))
        self.assertEqual({image.kind for image in spec.images.values()}, {"core", "incus"})


class InputChecksTest(unittest.TestCase):
    """The Action's first step, run for real: it is what turns inputs into the steps that run."""

    def run_setup(self, **inputs: str) -> action.Result:
        with tempfile.TemporaryDirectory() as raw:
            return run_action(inputs, scratch=Path(raw) / "temp", cwd=Path(raw), until="setup")

    def test_the_defaults_run_plan_fetch_build_and_test(self) -> None:
        result = self.run_setup()
        self.assertTrue(result.ok, result.log)
        outputs = result.outputs["setup"]
        self.assertEqual([outputs[k] for k in ("fetch", "build", "test")], ["true", "true", "true"])

    def test_steps_may_be_spaced_and_a_plan_only_run_skips_the_rest(self) -> None:
        result = self.run_setup(steps=" plan ")
        self.assertTrue(result.ok, result.log)
        self.assertEqual([result.outputs["setup"][k] for k in ("fetch", "build", "test")], ["false"] * 3)

    def test_an_unknown_step_is_named(self) -> None:
        result = self.run_setup(steps="plan,deploy")
        self.assertFalse(result.ok)
        self.assertIn("steps names 'deploy'", result.log)

    def test_a_step_that_needs_the_one_before_it_says_so(self) -> None:
        for steps, message in (
            ("fetch", "steps must include plan"),
            ("plan,build", "build step needs the fetch step"),
            ("plan,fetch,test", "test step needs the build step"),
        ):
            with self.subTest(steps=steps):
                result = self.run_setup(steps=steps)
                self.assertFalse(result.ok)
                self.assertIn(message, result.log)

    def test_publish_needs_targets_and_a_build(self) -> None:
        self.assertIn("publish needs against", self.run_setup(publish="true").log)
        result = self.run_setup(publish="true", against="dir:///x", steps="plan")
        self.assertIn("publish needs the build step", result.log)
        self.assertTrue(self.run_setup(publish="true", against="dir:///x").ok)

    def test_keep_work_is_true_or_false(self) -> None:
        self.assertIn("keep-work is true or false, not 'maybe'", self.run_setup(**{"keep-work": "maybe"}).log)

    def test_publish_is_true_or_false(self) -> None:
        self.assertIn("publish is true or false, not 'yes'", self.run_setup(publish="yes").log)


class CleanupTest(unittest.TestCase):
    """keep-work false makes the last step remove the work directory, passed or failed; by default it stays."""

    @staticmethod
    def failing_run(root: Path, **inputs: str) -> action.Result:
        """A run whose plan fails: the .pyz it is given exits at once."""
        failing = root / "factory.py"
        failing.write_text("raise SystemExit('this stands in for a plan that fails')\n")
        return run_action({"pyz": str(failing), **inputs}, scratch=root / "temp", cwd=root, skip=("prerequisites",))

    def test_a_failed_run_leaves_no_work_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = self.failing_run(Path(raw), **{"keep-work": "false"})
            self.assertFalse(result.ok)
            self.assertEqual(result.failed, "plan")
            self.assertIn("cleanup", result.outputs)
            work = Path(result.outputs["setup"]["work"])
            self.assertTrue(work.parent.is_dir())
            self.assertFalse(work.exists())

    def test_by_default_it_stays(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = self.failing_run(Path(raw))
            self.assertNotIn("cleanup", result.outputs)
            self.assertTrue(Path(result.outputs["setup"]["work"]).is_dir())

    def test_a_run_that_stopped_before_it_made_a_work_directory_has_nothing_to_remove(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            result = run_action({"steps": "deploy"}, scratch=root / "temp", cwd=root)
            self.assertFalse(result.ok)
            self.assertNotIn("cleanup", result.outputs)


if __name__ == "__main__":
    unittest.main()
