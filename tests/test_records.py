"""Records: the SBOM, the provenance, the records file, and the helpers that feed them.

The SBOM is validated against SPDX's published 2.3 JSON schema, vendored unchanged as
tests/fixtures/spdx/spdx-schema-2.3.json:

    source  https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json
    sha256  239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b

by the small validator in tests/support/jsonschema.py (standard library only). Nothing here uses the network.
"""

import hashlib
import json
import unittest
from pathlib import Path
from typing import Final

from input_lock import Package, dump
from input_lock.records import Statement, subject

from debian_image_factory import __version__
from debian_image_factory.published import Artifact, Rejected, artifact_from_records, artifact_name
from debian_image_factory.records import (
    BUILD_TYPE,
    CHECKS_DOC,
    DefinitionSource,
    Parent,
    RecordsError,
    Remote,
    decode_statements,
    definition_uri,
    namespace_base,
    provenance_statement,
    record_lines,
    run_details,
    sbom,
    spdx_packages,
)
from tests.support import jsonschema
from tests.support.definitions import example_lock

SCHEMA_PATH: Final = Path(__file__).parent / "fixtures" / "spdx" / "spdx-schema-2.3.json"
SCHEMA_SHA256: Final = "239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b"

IDENTITY: Final = "ab" * 32
DIGEST: Final = "12" * 32
RECIPE: Final = "34" * 32
BUILDER: Final = "56" * 32
PARENT: Final = "78" * 32
REVISION: Final = "9a" * 20
CREATED: Final = "2026-11-21T02:31:12Z"
STARTED: Final = "2026-11-21T02:17:05Z"
FINISHED: Final = "2026-11-21T02:19:41Z"
NAME: Final = artifact_name("core", "trixie", "amd64", IDENTITY, DIGEST, "tar.gz")
ENTRIES: Final = ("node-26", "example-tool")
SOURCE: Final = DefinitionSource("git+https://github.com/example/images", REVISION, "factory.toml")
IN_RELEASES: Final = (
    Remote("https://snapshot.debian.org/archive/debian/20261121T004329Z/dists/trixie/InRelease", "a1" * 32),
    Remote(
        "https://snapshot.debian.org/archive/debian-security/20261121T004329Z/dists/trixie-security/InRelease",
        "a2" * 32,
    ),
)
GITHUB_ENV: Final = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_WORKFLOW_REF": "example/images/.github/workflows/images.yml@refs/heads/main",
    "GITHUB_REPOSITORY": "example/images",
    "GITHUB_RUN_ID": "1234567890",
    "GITHUB_RUN_ATTEMPT": "2",
}


def obj(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return {str(key): item for key, item in value.items()}


def arr(value: object) -> list[object]:
    assert isinstance(value, list)
    return list(value)


def core_packages(count: int = 120) -> list[Package]:
    """A core-sized dpkg status: made-up names plus the awkward ones (a plus sign, an epoch)."""
    found: list[Package] = [
        ("libstdc++6", "14.2.0-19", "amd64"),
        ("libc6", "2.41-12", "amd64"),
        ("tzdata", "1:2025b-4", "all"),
    ]
    found.extend((f"example-lib{number:03d}", f"1.{number}-1", "amd64") for number in range(count))
    return found


def provenance_of(**changes: object) -> Statement:
    arguments: dict[str, object] = {
        "subjects": [subject(NAME, DIGEST)],
        "image": "core",
        "params": {},
        "definition": SOURCE,
        "identity": IDENTITY,
        "engine": 1,
        "build_snapshot": "20261121T004329Z",
        "architecture": "amd64",
        "reason": "package libssl3t64 3.5.1-1+deb13u1 -> 3.5.1-1+deb13u2",
        "lock": example_lock(),
        "entries": ENTRIES,
        "recipe_digest": RECIPE,
        "in_releases": IN_RELEASES,
        "builder_image": "ghcr.io/foreverworks/debian-image-factory-builder",
        "builder_digest": BUILDER,
        "ancestors": (),
        "builder_id": "https://github.com/example/images/.github/workflows/images.yml@refs/heads/main",
        "invocation_id": "https://github.com/example/images/actions/runs/1/attempts/1",
        "version": __version__,
        "started_on": STARTED,
        "finished_on": FINISHED,
    }
    arguments.update(changes)
    return provenance_statement(**arguments)  # type: ignore[arg-type]  # the keywords are the function's own, built as a dict


def sbom_of(**changes: object) -> dict[str, object]:
    arguments: dict[str, object] = {
        "image": "core",
        "kind": "core",
        "suite": "trixie",
        "arch": "amd64",
        "artifact_digest": DIGEST,
        "packages": core_packages(),
        "lock": example_lock(),
        "entries": ENTRIES,
        "namespace_base": "https://github.com/example/images",
        "created": CREATED,
        "version": __version__,
    }
    arguments.update(changes)
    return obj(sbom(**arguments))  # type: ignore[arg-type]  # the keywords are the function's own, built as a dict


def load_schema() -> dict[str, object]:
    return obj(json.loads(SCHEMA_PATH.read_text()))


class ValidatorTest(unittest.TestCase):
    def test_the_vendored_schema_is_the_published_one(self) -> None:
        self.assertEqual(hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest(), SCHEMA_SHA256)

    def test_each_keyword(self) -> None:
        schema: dict[str, object] = {
            "type": "object",
            "required": ["a"],
            "additionalProperties": False,
            "properties": {
                "a": {"type": "string", "enum": ["x", "y"]},
                "b": {"type": "array", "minItems": 1, "items": {"type": "integer"}},
                "c": {"$ref": "#/definitions/tag"},
                "d": {"oneOf": [{"type": "string"}, {"type": "null"}]},
            },
            "definitions": {"tag": {"type": "string", "pattern": "^v[0-9]+$"}},
        }
        self.assertEqual(jsonschema.validate({"a": "x", "b": [1], "c": "v2", "d": None}, schema), [])
        problems = jsonschema.validate({"a": "z", "b": [], "c": "2", "d": 3, "e": 1}, schema)
        self.assertEqual(len(problems), 5, problems)
        self.assertEqual(len(jsonschema.validate({"a": "x", "b": [True]}, schema)), 1)  # a bool is not an integer
        self.assertEqual(jsonschema.validate({}, schema), ["$: missing 'a'"])

    def test_an_unknown_keyword_is_refused_not_ignored(self) -> None:
        with self.assertRaises(jsonschema.UnsupportedKeywordError):
            jsonschema.validate(1, {"multipleOf": 2})


class SbomTest(unittest.TestCase):
    def test_a_core_sized_sbom_conforms_to_the_spdx_schema(self) -> None:
        document = sbom_of()
        self.assertGreater(len(arr(document["packages"])), 100)
        self.assertEqual(jsonschema.validate(document, load_schema()), [])

    def test_every_kind_conforms(self) -> None:
        for kind in ("core", "oci", "incus", "installer", "os"):
            with self.subTest(kind):
                self.assertEqual(jsonschema.validate(sbom_of(kind=kind), load_schema()), [])

    def test_the_schema_check_rejects_a_missing_required_field(self) -> None:
        for field in ("SPDXID", "creationInfo", "dataLicense", "name", "spdxVersion"):
            with self.subTest(field):
                broken = sbom_of()
                del broken[field]
                self.assertIn(f"$: missing {field!r}", jsonschema.validate(broken, load_schema()))
        package = obj(arr(sbom_of()["packages"])[0])
        broken = sbom_of()
        broken["packages"] = [{key: value for key, value in package.items() if key != "downloadLocation"}]
        self.assertTrue(any("downloadLocation" in line for line in jsonschema.validate(broken, load_schema())))

    def test_the_document_has_the_shape_of_the_design(self) -> None:
        document = sbom_of()
        self.assertEqual(document["name"], "core-trixie-amd64")
        self.assertEqual(document["documentNamespace"], f"https://github.com/example/images/sbom/core/sha256-{DIGEST}")
        self.assertEqual(
            obj(document["creationInfo"]),
            {"created": CREATED, "creators": [f"Tool: debian-image-factory-{__version__}"]},
        )
        root = obj(arr(document["packages"])[0])
        self.assertEqual(
            root,
            {
                "SPDXID": "SPDXRef-Image",
                "name": "core",
                "versionInfo": f"sha256:{DIGEST}",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "primaryPackagePurpose": "OPERATING_SYSTEM",
            },
        )
        by_id = {str(obj(one)["SPDXID"]): obj(one) for one in arr(document["packages"])}
        self.assertEqual(by_id["SPDXRef-Package-libstdc--6-amd64"]["name"], "libstdc++6")
        self.assertIn(
            "pkg:deb/debian/libstdc%2B%2B6@14.2.0-19?arch=amd64&distro=trixie",
            json.dumps(by_id["SPDXRef-Package-libstdc--6-amd64"]),
        )
        self.assertEqual(by_id["SPDXRef-Input-node-26"]["versionInfo"], "26.13.1")
        relationships = [obj(one) for one in arr(document["relationships"])]
        self.assertEqual(
            relationships[0],
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Image",
            },
        )
        self.assertEqual(len(relationships), len(by_id))

    def test_the_root_purpose_follows_the_kind(self) -> None:
        purposes = {
            kind: obj(arr(sbom_of(kind=kind)["packages"])[0])["primaryPackagePurpose"]
            for kind in ("core", "os", "oci", "incus", "installer")
        }
        self.assertEqual(
            purposes,
            {
                "core": "OPERATING_SYSTEM",
                "os": "OPERATING_SYSTEM",
                "oci": "CONTAINER",
                "incus": "CONTAINER",
                "installer": "INSTALL",
            },
        )
        with self.assertRaises(ValueError):
            sbom_of(kind="vm")

    def test_the_namespace_differs_for_every_digest(self) -> None:
        other = sbom_of(artifact_digest="cd" * 32)
        self.assertNotEqual(sbom_of()["documentNamespace"], other["documentNamespace"])
        self.assertTrue(str(other["documentNamespace"]).endswith(f"/sbom/core/sha256-{'cd' * 32}"))

    def test_the_namespace_base_without_a_public_address_is_a_urn(self) -> None:
        document = sbom_of(namespace_base=namespace_base(None))
        self.assertEqual(document["documentNamespace"], f"urn:debian-image-factory/sbom/core/sha256-{DIGEST}")

    def test_bad_arguments_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            sbom_of(artifact_digest="abc")
        with self.assertRaises(ValueError):
            sbom_of(created="2026-11-21 02:31:12")


class CollisionTest(unittest.TestCase):
    def test_a_plus_and_a_hyphen_both_get_a_suffix_of_their_own(self) -> None:
        found = spdx_packages([("a+b", "1", "amd64"), ("a-b", "1", "amd64")], example_lock(), [], "trixie")
        ids = [one["SPDXID"] for one in found]
        self.assertEqual(len(set(ids)), 2)
        for one, label in zip(found, ("Package-a+b-amd64", "Package-a-b-amd64"), strict=True):
            suffix = hashlib.sha256(label.encode()).hexdigest()[:8]
            self.assertEqual(one["SPDXID"], f"SPDXRef-Package-a-b-amd64-{suffix}")
        self.assertEqual([one["name"] for one in found], ["a+b", "a-b"])

    def test_a_package_that_collides_with_nothing_keeps_its_plain_id(self) -> None:
        found = spdx_packages(
            [("a+b", "1", "amd64"), ("a-b", "1", "amd64"), ("c", "1", "amd64")], example_lock(), ["node-26"], "trixie"
        )
        self.assertEqual([one["SPDXID"] for one in found][2:], ["SPDXRef-Package-c-amd64", "SPDXRef-Input-node-26"])

    def test_the_same_name_in_two_architectures_does_not_collide(self) -> None:
        found = spdx_packages([("libc6", "2", "amd64"), ("libc6", "2", "i386")], example_lock(), [], "trixie")
        self.assertEqual(
            [one["SPDXID"] for one in found], ["SPDXRef-Package-libc6-amd64", "SPDXRef-Package-libc6-i386"]
        )

    def test_a_collision_still_makes_a_valid_document(self) -> None:
        document = sbom_of(packages=[("a+b", "1", "amd64"), ("a-b", "1", "amd64")])
        self.assertEqual(jsonschema.validate(document, load_schema()), [])

    def test_distro_is_the_suite(self) -> None:
        found = spdx_packages([("libc6", "2", "amd64")], example_lock(), [], "forky")
        self.assertIn("distro=forky", json.dumps(found))


class DefinitionUriTest(unittest.TestCase):
    def test_https_loses_its_token_and_keeps_its_suffix(self) -> None:
        self.assertEqual(definition_uri("https://github.com/example/images"), "git+https://github.com/example/images")
        self.assertEqual(
            definition_uri("https://x-access-token:ghs_secret@example.com/example/images.git"),
            "git+https://example.com/example/images.git",
        )
        self.assertEqual(
            definition_uri("https://tok@example.com:8443/a/b.git?x=y#z"), "git+https://example.com:8443/a/b.git"
        )

    def test_scp_style_becomes_ssh_without_the_user(self) -> None:
        self.assertEqual(definition_uri("git@github.com:example/images.git"), "git+ssh://github.com/example/images.git")
        self.assertEqual(definition_uri("git@example.com:/srv/git/images"), "git+ssh://example.com/srv/git/images")

    def test_ssh_urls_lose_their_user(self) -> None:
        self.assertEqual(
            definition_uri("ssh://git@example.com:2222/example/images.git"),
            "git+ssh://example.com:2222/example/images.git",
        )
        self.assertEqual(definition_uri("ssh://example.com/images"), "git+ssh://example.com/images")

    def test_a_local_path_is_refused(self) -> None:
        for remote in (
            "/srv/git/images",
            "../images",
            "./images",
            "file:///srv/git/images",
            "file:/srv/images",
            "C:\\work\\images",
            "images",
            "",
            "http://example.com/a",
            "git://example.com/a",
            "https://example.com",
            "https:///a",
        ):
            with self.subTest(remote):
                self.assertIsNone(definition_uri(remote))

    def test_the_namespace_base_is_the_https_repository(self) -> None:
        self.assertEqual(
            namespace_base("git+https://github.com/example/images.git"), "https://github.com/example/images"
        )
        self.assertEqual(namespace_base("git+https://github.com/example/images"), "https://github.com/example/images")
        self.assertEqual(namespace_base("git+ssh://github.com/example/images.git"), "urn:debian-image-factory")
        self.assertEqual(namespace_base(None), "urn:debian-image-factory")


class RunDetailsTest(unittest.TestCase):
    def test_under_github_actions(self) -> None:
        builder, invocation = run_details(GITHUB_ENV, __version__)
        self.assertEqual(builder, "https://github.com/example/images/.github/workflows/images.yml@refs/heads/main")
        self.assertEqual(invocation, "https://github.com/example/images/actions/runs/1234567890/attempts/2")

    def test_elsewhere_the_id_is_local_and_there_is_no_invocation(self) -> None:
        self.assertEqual(run_details({}, __version__), (BUILD_TYPE + "#local", None))
        self.assertEqual(
            run_details({"HOSTNAME": "build-box", "USER": "someone", "HOME": "/home/someone"}, "9.9.9")[1], None
        )
        self.assertEqual(run_details({}, "9.9.9")[0], BUILD_TYPE.replace(f"v{__version__}", "v9.9.9") + "#local")

    def test_an_incomplete_github_environment_is_local(self) -> None:
        for missing in GITHUB_ENV:
            with self.subTest(missing):
                env = {key: value for key, value in GITHUB_ENV.items() if key != missing}
                self.assertEqual(run_details(env, __version__), (BUILD_TYPE + "#local", None))
        self.assertEqual(run_details({**GITHUB_ENV, "GITHUB_ACTIONS": "false"}, __version__)[1], None)

    def test_nothing_about_the_machine_reaches_the_ids(self) -> None:
        env = {
            **GITHUB_ENV,
            "HOSTNAME": "build-box",
            "USER": "someone",
            "RUNNER_NAME": "runner-7",
            "PWD": "/work/secret",
        }
        for text in run_details(env, __version__):
            for secret in ("build-box", "someone", "runner-7", "/work/secret"):
                self.assertNotIn(secret, text or "")

    def test_the_documents_are_named_for_the_release(self) -> None:
        self.assertEqual(
            BUILD_TYPE,
            f"https://github.com/foreverworks/debian-image-factory/blob/v{__version__}/docs/build-type-v1.md",
        )
        self.assertEqual(
            CHECKS_DOC, f"https://github.com/foreverworks/debian-image-factory/blob/v{__version__}/docs/checks.md"
        )


class ProvenanceTest(unittest.TestCase):
    def predicate(self, **changes: object) -> dict[str, object]:
        return obj(provenance_of(**changes)["predicate"])

    def test_the_required_fields(self) -> None:
        statement = obj(provenance_of())
        self.assertEqual(statement["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(statement["predicateType"], "https://slsa.dev/provenance/v1")
        self.assertEqual(statement["subject"], [{"name": NAME, "digest": {"sha256": DIGEST}}])
        predicate = obj(statement["predicate"])
        definition = obj(predicate["buildDefinition"])
        self.assertEqual(definition["buildType"], BUILD_TYPE)
        self.assertEqual(obj(definition["externalParameters"])["image"], "core")
        run = obj(predicate["runDetails"])
        builder = obj(run["builder"])
        self.assertEqual(
            builder["id"], "https://github.com/example/images/.github/workflows/images.yml@refs/heads/main"
        )
        self.assertEqual(builder["version"], {"debian-image-factory": __version__})
        self.assertEqual(
            run["metadata"],
            {
                "invocationId": "https://github.com/example/images/actions/runs/1/attempts/1",
                "startedOn": STARTED,
                "finishedOn": FINISHED,
            },
        )

    def test_the_parameters(self) -> None:
        definition = obj(self.predicate(params={"node": "26", "extras": True})["buildDefinition"])
        self.assertEqual(
            definition["externalParameters"],
            {
                "image": "core",
                "definition": {
                    "uri": "git+https://github.com/example/images",
                    "revision": REVISION,
                    "path": "factory.toml",
                },
                "params": {"node": "26", "extras": True},
            },
        )
        self.assertEqual(
            definition["internalParameters"],
            {
                "identity": IDENTITY,
                "engine": 1,
                "buildSnapshot": "20261121T004329Z",
                "architecture": "amd64",
                "reason": "package libssl3t64 3.5.1-1+deb13u1 -> 3.5.1-1+deb13u2",
            },
        )

    def test_no_reason_key_when_there_is_none(self) -> None:
        for reason in (None, ""):
            definition = obj(self.predicate(reason=reason)["buildDefinition"])
            self.assertNotIn("reason", obj(definition["internalParameters"]))

    def test_the_dependencies_come_in_the_designed_order(self) -> None:
        lock = example_lock()
        found = arr(obj(self.predicate(ancestors=(Parent("core", PARENT),))["buildDefinition"])["resolvedDependencies"])
        names = [obj(one).get("name") or obj(one).get("uri") for one in found]
        self.assertEqual(
            obj(found[0]),
            {"uri": f"git+https://github.com/example/images@{REVISION}", "digest": {"gitCommit": REVISION}},
        )
        self.assertEqual(
            names[1:],
            [
                "lock.json",
                "example-tool",
                "node-26",
                "recipe of core",
                IN_RELEASES[0].uri,
                IN_RELEASES[1].uri,
                "oci://ghcr.io/foreverworks/debian-image-factory-builder",
                "parent: core",
            ],
        )
        self.assertEqual(
            obj(found[1])["digest"],
            {"sha256": hashlib.sha256(dump(lock).encode()).hexdigest()},
        )
        self.assertEqual(obj(found[3])["uri"], "https://nodejs.org/dist/v26.13.1/node-v26.13.1-linux-x64.tar.xz")
        self.assertEqual(obj(found[4]), {"name": "recipe of core", "digest": {"sha256": RECIPE}})
        self.assertEqual(
            obj(found[7]),
            {"uri": "oci://ghcr.io/foreverworks/debian-image-factory-builder", "digest": {"sha256": BUILDER}},
        )
        self.assertEqual(obj(found[8]), {"name": "parent: core", "digest": {"sha256": PARENT}})

    def test_ancestors_come_nearest_first_as_parent_then_ancestor(self) -> None:
        middle, top = "ee" * 32, "ff" * 32
        found = arr(
            obj(
                self.predicate(ancestors=(Parent("oci-base", middle), Parent("core", top), Parent("older", PARENT)))[
                    "buildDefinition"
                ]
            )["resolvedDependencies"]
        )
        tail = [obj(one) for one in found[-3:]]
        self.assertEqual(
            tail,
            [
                {"name": "parent: oci-base", "digest": {"sha256": middle}},
                {"name": "ancestor: core", "digest": {"sha256": top}},
                {"name": "ancestor: older", "digest": {"sha256": PARENT}},
            ],
        )

    def test_without_a_definition_or_a_parent_those_entries_are_absent(self) -> None:
        predicate = self.predicate(definition=None, invocation_id=None)
        definition = obj(predicate["buildDefinition"])
        self.assertNotIn("definition", obj(definition["externalParameters"]))
        found = [obj(one) for one in arr(definition["resolvedDependencies"])]
        self.assertEqual(found[0]["name"], "lock.json")
        self.assertNotIn("parent: core", [one.get("name") for one in found])
        self.assertNotIn("invocationId", obj(obj(predicate["runDetails"])["metadata"]))

    def test_bad_values_are_refused(self) -> None:
        for change in (
            {"identity": "ab"},
            {"recipe_digest": "x"},
            {"started_on": "yesterday"},
            {"ancestors": (Parent("core", "z"),)},
            {"definition": DefinitionSource("git+https://example.com/a", "main", "f")},
        ):
            with self.subTest(change), self.assertRaises(ValueError):
                provenance_of(**change)

    def test_the_lookup_reads_what_is_written(self) -> None:
        records = record_lines([provenance_of()])
        found = artifact_from_records(NAME, DIGEST, "core", IDENTITY, records)
        self.assertIsInstance(found, Artifact)
        assert isinstance(found, Artifact)
        self.assertEqual(
            (found.image, found.identity, found.digest, found.finished_on), ("core", IDENTITY, DIGEST, FINISHED)
        )
        wrong = artifact_from_records(NAME, DIGEST, "core", "cd" * 32, records)
        self.assertIsInstance(wrong, Rejected)


class RecordLinesTest(unittest.TestCase):
    def test_one_unsigned_envelope_per_line_that_decodes_back(self) -> None:
        first = provenance_of()
        second = provenance_of(image="node-26", ancestors=(Parent("core", PARENT),))
        text = record_lines([first, second])
        lines = text.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(text.endswith("\n"))
        for line in lines:
            envelope = obj(json.loads(line))
            self.assertEqual(envelope["payloadType"], "application/vnd.in-toto+json")
            self.assertEqual(envelope["signatures"], [])
        self.assertEqual(decode_statements(text), [obj(first), obj(second)])

    def test_nothing_is_nothing(self) -> None:
        self.assertEqual(record_lines([]), "")
        self.assertEqual(decode_statements(""), [])

    def test_decoding_names_a_bad_line(self) -> None:
        with self.assertRaisesRegex(RecordsError, "line 2"):
            decode_statements(record_lines([provenance_of()]) + "not json\n")

    def test_a_record_holds_no_path_token_or_machine_name(self) -> None:
        text = record_lines([provenance_of(), provenance_of(definition=None)])
        decoded = json.dumps(decode_statements(text))
        for needle in ("/home/", "/tmp/", "ghs_", "localhost"):
            self.assertNotIn(needle, decoded)


if __name__ == "__main__":
    unittest.main()
