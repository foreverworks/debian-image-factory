"""`verify`: an artifact's records match its bits (layout, file and registry), the provenance names the
image, an identity equal to the artifact's and the lock, there is one SBOM that belongs to the digest,
and with `--require-checks` every required check has a passing last result. Every refusal names itself."""

import base64
import contextlib
import io
import json
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Final

import input_lock
from input_lock.records import SPDX_PREDICATE, statement, subject

from debian_image_factory import cli, commands, definition, ocilayout, publish, published, records, registry, verify
from tests.support import fake_registry
from tests.support.definitions import CORE, HEADER, as_lock, child, entry_of, example_lock, example_lock_data
from tests.support.fake_registry import Fake
from tests.support.oci_fixtures import IDENTITY, Built, make_core_file, make_image, result_line

DEFINITION: Final = HEADER + CORE + child("app", "oci", "core")
REQUIRED: Final = definition.required_checks(definition.parse(DEFINITION), "app", False)
ALL_PASSING: Final = tuple((check, "PASSED") for check in REQUIRED)


def table(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return {str(key): item for key, item in value.items()}


def build_definition(body: dict[str, object]) -> dict[str, object]:
    """The provenance's `buildDefinition`, in place: what an update to it changes."""
    predicate = body["predicate"]
    assert isinstance(predicate, dict)
    found = predicate["buildDefinition"]
    assert isinstance(found, dict)
    return found


def external_parameters(body: dict[str, object]) -> dict[str, object]:
    found = build_definition(body)["externalParameters"]
    assert isinstance(found, dict)
    return found


def rewritten(line: str, change: Callable[[dict[str, object]], None]) -> str:
    """One records line with its statement changed by `change(statement)`, re-encoded as the factory does."""
    envelope = json.loads(line)
    body = table(json.loads(base64.b64decode(envelope["payload"])))
    change(body)
    envelope["payload"] = base64.b64encode(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).decode()
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n"


class VerifyBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.definition = self.root / "factory.toml"
        self.definition.write_text(DEFINITION)

    def run_verify(self, ref: str, *, require: bool = False, lock: Path | None = None) -> str:
        said = io.StringIO()
        self.assertEqual(verify.verify_command(ref, require, lock, self.definition, said), 0)
        return said.getvalue()

    def problems(self, ref: str, *, require: bool = False, lock: Path | None = None) -> list[str]:
        with self.assertRaises(commands.Failed) as caught:
            verify.verify_command(ref, require, lock, self.definition, io.StringIO())
        return str(caught.exception).splitlines()

    def lines_of(self, built: Built) -> list[str]:
        return built.records.read_text().splitlines(keepends=True)

    def write(self, built: Built, lines: list[str]) -> None:
        built.records.write_text("".join(lines))


class LayoutTest(VerifyBase):
    def test_an_image_with_good_records_verifies(self) -> None:
        built = make_image(self.root / "out", checks=ALL_PASSING)
        said = self.run_verify(str(built.layout))
        self.assertIn(f"{built.layout}: verified", said)
        self.assertIn(f"app identity {IDENTITY}: {4 + len(REQUIRED) - 2} records", said)
        self.assertIn("1 provenance, 1 SBOM", said)

    def test_the_checks_present_are_listed_without_require_checks(self) -> None:
        built = make_image(self.root / "out", checks=[("package-set", "PASSED"), ("oci-run", "FAILED")])
        said = self.run_verify(str(built.layout))
        self.assertIn("checks: oci-run FAILED, package-set PASSED", said)

    def test_every_required_check_passing_is_enough(self) -> None:
        built = make_image(self.root / "out", checks=ALL_PASSING)
        said = self.run_verify(str(built.layout), require=True)
        self.assertIn("required checks all passing:", said)

    def test_a_missing_or_failing_required_check_is_named(self) -> None:
        built = make_image(self.root / "out", checks=[*ALL_PASSING[:-2], (REQUIRED[-2], "FAILED")])
        found = self.problems(str(built.layout), require=True)
        self.assertEqual(len(found), 2)
        self.assertTrue(any(f"required check {REQUIRED[-2]}: its last result is FAILED" in line for line in found))
        self.assertTrue(any(f"required check {REQUIRED[-1]}: no result" in line for line in found))

    def test_the_last_result_wins_and_a_warning_passes(self) -> None:
        built = make_image(
            self.root / "out",
            checks=[(REQUIRED[0], "FAILED"), (REQUIRED[0], "PASSED"), *[(c, "WARNED") for c in REQUIRED[1:]]],
        )
        self.run_verify(str(built.layout), require=True)
        built.records.write_text(
            built.records.read_text() + result_line(built.name, built.digest, REQUIRED[0], "FAILED")
        )
        self.assertEqual(len(self.problems(str(built.layout), require=True)), 1)

    def test_an_image_the_definition_does_not_know_is_a_problem(self) -> None:
        built = make_image(self.root / "out", image="other", checks=ALL_PASSING)
        self.assertIn("has no image 'other'", self.problems(str(built.layout), require=True)[0])

    def test_a_layer_that_changed_is_found(self) -> None:
        built = make_image(self.root / "out")
        layer = ocilayout.read_layout(built.layout).layers[0]
        layer.write_bytes(layer.read_bytes() + b"x")
        self.assertRegex(self.problems(str(built.layout))[0], "layer [0-9a-f]+ does not match its descriptor")

    def test_the_lock_must_be_the_one_the_provenance_names(self) -> None:
        built = make_image(self.root / "out")
        good = self.root / "lock.json"
        good.write_text(input_lock.dump(example_lock()))
        self.run_verify(str(built.layout), lock=good)
        data = example_lock_data()
        entry_of(data, "node-26")["version"] = "1.0.0"
        other = self.root / "other-lock.json"
        other.write_text(input_lock.dump(as_lock(data)))
        found = self.problems(str(built.layout), lock=other)
        self.assertEqual(len(found), 1)
        self.assertIn("is not the sha256 of the --lock file", found[0])

    def test_records_about_another_artifact_do_not_count(self) -> None:
        built = make_image(self.root / "out")
        elsewhere = make_image(self.root / "else", content=b"other")
        self.write(built, self.lines_of(elsewhere))
        found = self.problems(str(built.layout))
        self.assertEqual(sum("is not one of its subjects" in line for line in found), 4)
        self.assertIn("0 provenance records, expected exactly one", "\n".join(found))
        self.assertIn("0 SBOM records, expected exactly one", "\n".join(found))

    def test_two_provenances_or_no_sbom_are_named(self) -> None:
        built = make_image(self.root / "out")
        lines = self.lines_of(built)
        self.write(built, [lines[0], lines[0], lines[2], lines[3]])
        found = "\n".join(self.problems(str(built.layout)))
        self.assertIn("2 provenance records, expected exactly one", found)
        self.assertIn("0 SBOM records, expected exactly one", found)

    def test_a_record_that_is_not_an_envelope_is_named_by_its_line(self) -> None:
        built = make_image(self.root / "out")
        self.write(built, [*self.lines_of(built), "not json\n"])
        self.assertEqual(self.problems(str(built.layout)), [f"{built.layout}: record 5: not JSON (Expecting value)"])

    def test_no_records_file_is_a_problem(self) -> None:
        built = make_image(self.root / "out")
        built.records.unlink()
        found = "\n".join(self.problems(str(built.layout)))
        self.assertIn(f"no records file {built.digest}.intoto.jsonl beside it", found)

    def test_a_provenance_of_another_build_type_is_refused(self) -> None:
        built = make_image(self.root / "out")
        lines = self.lines_of(built)
        lines[0] = rewritten(lines[0], lambda s: build_definition(s).update(buildType="https://example.com/other"))
        self.write(built, lines)
        self.assertIn("is not a build type of this factory", self.problems(str(built.layout))[0])

    def test_another_release_of_this_factory_is_accepted(self) -> None:
        built = make_image(self.root / "out")
        lines = self.lines_of(built)
        lines[0] = rewritten(lines[0], lambda s: build_definition(s).update(buildType=records.build_type("9.9.9")))
        self.write(built, lines)
        self.run_verify(str(built.layout))

    def test_a_provenance_of_the_first_build_type_is_still_accepted(self) -> None:
        # build type v1 recorded one `buildSnapshot`; records already published keep verifying
        built = make_image(self.root / "out")
        v1 = records.build_type("0.7.0").replace("build-type-v2.md", "build-type-v1.md")
        lines = self.lines_of(built)
        lines[0] = rewritten(lines[0], lambda s: build_definition(s).update(buildType=v1))
        self.write(built, lines)
        self.run_verify(str(built.layout))

    def test_a_build_type_that_is_neither_v1_nor_v2_is_refused(self) -> None:
        built = make_image(self.root / "out")
        v3 = records.build_type("9.9.9").replace("build-type-v2.md", "build-type-v3.md")
        lines = self.lines_of(built)
        lines[0] = rewritten(lines[0], lambda s: build_definition(s).update(buildType=v3))
        self.write(built, lines)
        self.assertIn("is not a build type of this factory", self.problems(str(built.layout))[0])

    def test_a_provenance_that_names_another_identity_than_the_manifest_is_refused(self) -> None:
        built = make_image(self.root / "out", provenance_identity="d4" * 32)
        found = self.problems(str(built.layout))
        self.assertTrue(
            any(f"provenance names identity {'d4' * 32}, but the artifact carries {IDENTITY}" in line for line in found)
        )

    def test_a_provenance_without_the_lock_is_refused(self) -> None:
        built = make_image(self.root / "out")
        lines = self.lines_of(built)

        def drop_lock(body: dict[str, object]) -> None:
            dependencies = build_definition(body)["resolvedDependencies"]
            assert isinstance(dependencies, list)
            dependencies[:] = [one for one in dependencies if table(one).get("name") != "lock.json"]

        lines[0] = rewritten(lines[0], drop_lock)
        self.write(built, lines)
        self.assertIn("names lock.json 0 times", self.problems(str(built.layout))[0])

    def test_an_sbom_of_another_digest_is_refused(self) -> None:
        built = make_image(self.root / "out")
        other = "ab" * 32
        document = records.sbom(
            image="app",
            kind="oci",
            suite="trixie",
            arch="amd64",
            artifact_digest=other,
            packages=[],
            lock=example_lock(),
            entries=[],
            namespace_base="https://github.com/example/images",
            created="2026-11-21T02:31:12Z",
            version="1",
        )
        lines = self.lines_of(built)
        lines[1] = records.record_lines([statement([subject(built.name, built.digest)], SPDX_PREDICATE, document)])
        self.write(built, lines)
        found = self.problems(str(built.layout))
        self.assertEqual(len(found), 2)
        self.assertIn("documentNamespace does not end in", found[0])
        self.assertIn("versionInfo", found[1])

    def test_a_layout_that_is_not_one_is_refused(self) -> None:
        with self.assertRaisesRegex(commands.Failed, "not an OCI image layout"):
            verify.verify_command(str(self.root), False, None, self.definition, io.StringIO())


class FileTest(VerifyBase):
    def test_a_core_tarball_with_its_records_verifies(self) -> None:
        built = make_core_file(self.root / "out", checks=[("package-set", "PASSED")])
        said = self.run_verify(str(built.layout))
        self.assertIn(f"{built.layout}: verified", said)
        self.assertIn(f"core identity {IDENTITY}", said)

    def test_a_file_whose_bytes_changed_has_no_records(self) -> None:
        built = make_core_file(self.root / "out")
        built.layout.write_bytes(b"changed")
        found = "\n".join(self.problems(str(built.layout)))
        self.assertIn("which its name does not carry", found)
        self.assertIn("no records file", found)

    def test_the_name_must_carry_the_identity_and_image_of_the_provenance(self) -> None:
        built = make_core_file(self.root / "out")
        lines = built.records.read_text().splitlines(keepends=True)
        lines[0] = rewritten(lines[0], lambda s: external_parameters(s).update(image="other"))
        built.records.write_text("".join(lines))
        self.assertIn(
            "provenance names image 'other', but the artifact's name says 'core'",
            "\n".join(self.problems(str(built.layout))),
        )

    def test_something_that_is_not_there_is_a_failure(self) -> None:
        with self.assertRaisesRegex(commands.Failed, "not an oci:// reference"):
            verify.verify_command(str(self.root / "nothing"), False, None, self.definition, io.StringIO())


class RegistryTest(VerifyBase):
    def published(self, name: str, out: str = "out") -> Built:
        built = make_image(self.root / out, checks=ALL_PASSING)
        publish.publish_command(self.root / out, [f"oci://{name}/team/app"], "none", io.StringIO())
        return built

    def test_an_image_verifies_by_digest_and_by_tag_on_either_kind_of_registry(self) -> None:
        for mode, fake in (("api", Fake()), ("tag", Fake(referrers_api=False, subject_header=False))):
            with self.subTest(mode), fake_registry.running(fake) as name:
                built = self.published(name, mode)
                by_digest = f"oci://{name}/team/app@sha256:{built.digest}"
                self.assertIn(f"{by_digest}: verified", self.run_verify(by_digest, require=True))
                by_tag = f"oci://{name}/team/app:identity-{IDENTITY}"
                self.assertIn(f"{by_digest}: verified", self.run_verify(by_tag, require=True))

    def test_a_tag_that_does_not_exist_is_a_failure(self) -> None:
        with fake_registry.running(Fake()) as name:
            self.assertEqual(
                self.problems(f"oci://{name}/team/app:v1"), [f"oci://{name}/team/app:v1: no such manifest"]
            )

    def test_a_record_the_registry_corrupted_is_named(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            built = self.published(name)
            attached = registry.referrers_of(
                registry.connect(published.OciTarget(name, "team/app")), built.digest
            ).attached
            fake.broken_blobs.add(f"sha256:{attached[0].envelope.digest}")
            found = "\n".join(self.problems(f"oci://{name}/team/app@sha256:{built.digest}"))
            self.assertIn("does not match its digest", found)

    def test_a_layer_the_registry_lost_is_named(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            built = self.published(name)
            layer = ocilayout.read_layout(built.layout).manifest.layers[0].digest
            del fake.blobs[f"sha256:{layer}"]
            found = self.problems(f"oci://{name}/team/app@sha256:{built.digest}")
            self.assertEqual(
                found, [f"oci://{name}/team/app@sha256:{built.digest}: blob sha256:{layer} is not in the registry"]
            )

    def test_pull_downloads_the_layers_and_checks_them_in_full(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            built = self.published(name)
            ref = f"oci://{name}/team/app@sha256:{built.digest}"
            said = io.StringIO()
            self.assertEqual(
                verify.verify_command(ref, True, None, self.definition, said, pull_wanted=True), 0, said.getvalue()
            )
            self.assertIn(f"{ref}: verified", said.getvalue())
            layer = ocilayout.read_layout(built.layout).manifest.layers[0].digest
            fake.broken_blobs.add(f"sha256:{layer}")
            self.run_verify(ref)  # without --pull a layer is only looked for
            with self.assertRaises(commands.Failed) as caught:
                verify.verify_command(ref, False, None, self.definition, io.StringIO(), pull_wanted=True)
            self.assertIn(f"blob sha256:{layer} does not match its digest", str(caught.exception))

    def test_pull_names_a_layer_the_registry_lost(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            built = self.published(name)
            layer = ocilayout.read_layout(built.layout).manifest.layers[0].digest
            del fake.blobs[f"sha256:{layer}"]
            with self.assertRaises(commands.Failed) as caught:
                verify.verify_command(
                    f"oci://{name}/team/app@sha256:{built.digest}",
                    False,
                    None,
                    self.definition,
                    io.StringIO(),
                    pull_wanted=True,
                )
            self.assertIn("pulling the image: ", str(caught.exception))

    def test_a_manifest_that_does_not_hash_to_its_digest_is_a_failure(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            built = self.published(name)
            fake.manifests[f"sha256:{built.digest}"] += b" "
            with self.assertRaisesRegex(commands.Failed, "does not match its digest"):
                verify.verify_command(
                    f"oci://{name}/team/app@sha256:{built.digest}", False, None, self.definition, io.StringIO()
                )

    def test_a_dead_registry_is_a_failure(self) -> None:
        with self.assertRaisesRegex(commands.Failed, "oci://127.0.0.1:9/team/app:v1: "):
            verify.verify_command("oci://127.0.0.1:9/team/app:v1", False, None, self.definition, io.StringIO())


def main(*arguments: str) -> int:
    """`cli.main` with its output kept out of the test run's."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return cli.main(list(arguments))


class CommandLineTest(VerifyBase):
    def test_exit_codes(self) -> None:
        built = make_image(self.root / "out", checks=ALL_PASSING)
        self.assertEqual(main("verify", str(built.layout)), 0)
        self.assertEqual(main("verify", str(built.layout), "--require-checks", "--definition", str(self.definition)), 0)
        layer = ocilayout.read_layout(built.layout).layers[0]
        layer.write_bytes(b"x")
        self.assertEqual(main("verify", str(built.layout)), 1)
        self.assertEqual(main("verify", "oci://not a reference"), 2)
        self.assertEqual(main("verify", "oci://registry.example.com/app"), 2)

    def test_pull_and_artifact_on_the_command_line(self) -> None:
        core = make_core_file(self.root / "out", checks=[("package-set", "PASSED")])
        ref = f"dir://{self.root / 'out'}"
        self.assertEqual(main("verify", ref, "--pull", "--artifact", core.name), 0)
        self.assertEqual(main("verify", ref, "--pull", "--artifact", core.digest), 0)
        self.assertEqual(main("verify", ref, "--artifact", core.name), 2)
        self.assertEqual(main("verify", ref, "--pull"), 2)
        self.assertEqual(main("verify", ref, "--pull", "--artifact", "nothing"), 1)
        self.assertEqual(main("verify", str(core.layout), "--pull"), 2)

    def test_the_definition_is_read_only_with_require_checks(self) -> None:
        built = make_image(self.root / "out")
        self.assertEqual(main("verify", str(built.layout), "--definition", str(self.root / "missing.toml")), 0)
        self.assertEqual(
            main("verify", str(built.layout), "--require-checks", "--definition", str(self.root / "missing.toml")), 1
        )


if __name__ == "__main__":
    unittest.main()
