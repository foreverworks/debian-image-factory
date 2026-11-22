"""M2's acceptance, end to end on the example definition at the example lock's snapshot.

plan, fetch, build core twice (offline, in the builder), test, publish to a `dir://` target, and plan
against it. It proves the milestone's four claims: two builds from one lock resolve the same set (and
here give the same bytes, which also guards the engine revision); the artifact carries no machine
identity; the build snapshot is nowhere in its bytes; its SBOM lists every installed package. Needs
docker, the builder image (`scripts/builder build`) and network access to snapshot.debian.org.
"""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from debian_image_factory import ENGINE, cli, published, records

ROOT = Path(__file__).resolve().parent.parent.parent
EXAMPLES = ROOT / "examples"

EXPECTED_CORE: dict[int, str] = {1: "6b9547107518bccd947bb570cc9689447192b85e9fa460fcc3cc4b3c44f855bc"}
"""The engine revision guard (DESIGN 12): the sha256 of the example core at the example lock's
snapshot, per engine revision. A change that alters these bytes without raising ENGINE fails here;
a change to the example's core, its lock or the builder updates the digest in the same commit."""

CORE_CHECKS = (
    "no-build-snapshot",
    "no-machine-identity",
    "package-set",
    "same-resolution",
    "sbom-complete",
    "two-clones",
)


def factory(*argv: str) -> str:
    """Run the command line in this process and return what it printed; fail the test on a non-zero exit."""
    printed, errors = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(errors):
        status = cli.main(list(argv))
    if status != 0:
        raise AssertionError(f"debian-image-factory {' '.join(argv)} exited {status}:\n{errors.getvalue()}")
    return printed.getvalue()


def files(*paths: Path) -> list[str]:
    return ["--lock", str(EXAMPLES / "lock.json"), "--definition", str(EXAMPLES / "factory.toml"), *map(str, paths)]


def artifact(out: Path) -> Path:
    found = [path for path in out.iterdir() if published.parse_artifact_name(path.name) is not None]
    if len(found) != 1:
        raise AssertionError(f"{out} holds {len(found)} artifacts, expected one")
    return found[0]


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class CoreBuildTest(unittest.TestCase):
    work: Path
    scratch: tempfile.TemporaryDirectory[str]
    plan: dict[str, object]

    @classmethod
    def setUpClass(cls) -> None:
        tag = subprocess.run(
            [str(ROOT / "scripts" / "builder"), "build"], check=True, capture_output=True, text=True
        ).stdout.split()[-1]
        cls.scratch = tempfile.TemporaryDirectory(prefix="dif-core-")
        cls.work = Path(cls.scratch.name)
        plan = cls.work / "plan.json"
        factory("plan", *files(), "--out", str(plan))
        factory("fetch", str(plan))
        for out in ("out1", "out2"):
            factory(
                "build", str(plan), "--out", str(cls.work / out), "--image", "core", "--builder-image", tag, *files()
            )
        factory("test", str(cls.work / "out1"))
        cls.plan = json.loads(plan.read_text())

    @classmethod
    def tearDownClass(cls) -> None:
        cls.scratch.cleanup()

    def statements(self, out: str) -> list[dict[str, object]]:
        path = artifact(self.work / out)
        digest = published.parse_artifact_name(path.name)
        assert digest is not None
        records_file = next((self.work / out).glob(f"{digest.digest12}*.intoto.jsonl"))
        return records.decode_statements(records_file.read_text())

    def sbom_packages(self, out: str) -> list[list[str]]:
        sbom = next(one for one in self.statements(out) if one["predicateType"] == "https://spdx.dev/Document/v2.3")
        predicate = sbom["predicate"]
        assert isinstance(predicate, dict)
        rows = []
        for package in predicate["packages"]:
            refs = package.get("externalRefs", [])
            locator = refs[0]["referenceLocator"] if refs else ""
            if locator.startswith("pkg:deb/"):
                arch = locator.split("arch=", 1)[1].split("&", 1)[0]
                rows.append([package["name"], package["versionInfo"], arch])
        return sorted(rows)

    def test_two_builds_from_one_lock_resolve_the_same_set_and_give_the_same_bytes(self) -> None:
        images = self.plan["images"]
        assert isinstance(images, dict)
        planned = sorted(images["core"]["packages"])
        again = self.work / "plan-again.json"
        factory("plan", *files(), "--out", str(again))
        self.assertEqual(sorted(json.loads(again.read_text())["images"]["core"]["packages"]), planned)
        self.assertEqual(self.sbom_packages("out1"), planned)
        self.assertEqual(self.sbom_packages("out2"), planned)
        first, second = artifact(self.work / "out1"), artifact(self.work / "out2")
        self.assertEqual(first.name, second.name, "two builds from the same inputs gave different bytes")

    def test_engine_revision_guard(self) -> None:
        name = published.parse_artifact_name(artifact(self.work / "out1").name)
        assert name is not None
        self.assertIn(ENGINE, EXPECTED_CORE, f"record the example core's digest for engine revision {ENGINE}")
        self.assertTrue(
            EXPECTED_CORE[ENGINE].startswith(name.digest12),
            "the example core's bytes changed without a raised engine revision (DESIGN 7.1)",
        )

    def test_every_core_check_passed(self) -> None:
        results: dict[str, str] = {}
        for one in self.statements("out1"):
            predicate = one["predicate"]
            if one["predicateType"] == "https://in-toto.io/attestation/test-result/v0.1" and isinstance(
                predicate, dict
            ):
                results[predicate["configuration"][0]["name"]] = predicate["result"]
        self.assertEqual(results, dict.fromkeys(CORE_CHECKS, "PASSED"))

    def test_published_core_is_reused(self) -> None:
        target = self.work / "target"
        factory("publish", str(self.work / "out1"), "--to", f"dir://{target}")
        after = self.work / "plan-after.json"
        factory("plan", *files(), "--against", f"dir://{target}", "--out", str(after))
        core = json.loads(after.read_text())["images"]["core"]
        digest = published.parse_artifact_name(artifact(self.work / "out1").name)
        assert digest is not None
        self.assertEqual(core["state"], "reuse")
        self.assertTrue(core["artifact"].startswith(digest.digest12))


if __name__ == "__main__":
    unittest.main()
