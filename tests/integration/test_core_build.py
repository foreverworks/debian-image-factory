"""M2's acceptance, end to end on the example definition at the example lock's snapshot.

plan, fetch, build core twice (offline, in the builder), test, publish to a `dir://` target, and plan
against it. It proves the milestone's four claims: two builds from one lock resolve the same set (and
here give the same bytes, which also guards the engine revision); the artifact carries no machine
identity; the build snapshot is nowhere in its bytes, and the same package set built at a second build
snapshot gives the same bytes (DESIGN 11); its SBOM lists every installed package. Needs
docker, the builder image (`scripts/builder build`) and network access to snapshot.debian.org.
"""

import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

from debian_image_factory import ENGINE, cli, published, records
from debian_image_factory.checks import tarball
from tests.support import builder_images

ROOT = Path(__file__).resolve().parent.parent.parent
EXAMPLES = ROOT / "examples"

EXPECTED_CORE: dict[int, str] = {1: "6b9547107518bccd947bb570cc9689447192b85e9fa460fcc3cc4b3c44f855bc"}
"""The engine revision guard (DESIGN 12): the sha256 of the example core at the example lock's
snapshot, per engine revision. A change that alters these bytes without raising ENGINE fails here;
a change to the example's core, its lock or the builder updates the digest in the same commit."""

SECOND_SNAPSHOT = "20261120T203430Z"
"""A build snapshot other than the example lock's at which core resolves to the same package set: both
archives sit at earlier snapshots under this ID, and none of core's packages moved in between."""

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
    started = time.monotonic()
    with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(errors):
        status = cli.main(list(argv))
    # progress for the job's log: a fixture runs many of these and the log says where its time went
    print(f"  [{time.monotonic() - started:6.1f} s] debian-image-factory {argv[0]}", file=sys.stderr, flush=True)
    if status != 0:
        raise AssertionError(f"debian-image-factory {' '.join(argv)} exited {status}:\n{errors.getvalue()}")
    return printed.getvalue()


def files(*paths: Path) -> list[str]:
    return ["--lock", str(EXAMPLES / "lock.json"), "--definition", str(EXAMPLES / "factory.toml"), *map(str, paths)]


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    second_plan: dict[str, object]

    @classmethod
    def setUpClass(cls) -> None:
        tag = builder_images.image()
        # Under dist/, not /tmp: the docker daemon mounts the build directory from its own view of the
        # host, where a private /tmp (systemd PrivateTmp, a sandbox) does not exist.
        (ROOT / "dist").mkdir(exist_ok=True)
        cls.scratch = tempfile.TemporaryDirectory(prefix="integration-core-", dir=ROOT / "dist")
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
        # The same definition with its lock moved to a second build snapshot: plan, fetch, build core.
        second = cls.work / "second"
        shutil.copytree(EXAMPLES, second)
        second_files = ["--lock", str(second / "lock.json"), "--definition", str(second / "factory.toml")]
        factory("lock", "snapshot", "--lock", str(second / "lock.json"), "--id", SECOND_SNAPSHOT)
        second_plan = cls.work / "plan-second.json"
        factory("plan", *second_files, "--out", str(second_plan))
        factory("fetch", str(second_plan))
        factory(
            "build", str(second_plan), "--out", str(cls.work / "out-second"), "--image", "core",
            "--builder-image", tag, *second_files,
        )  # fmt: skip
        cls.second_plan = json.loads(second_plan.read_text())

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
        self.assertEqual(first.name, second.name)
        self.assertEqual(sha256_of(first), sha256_of(second), "two builds from the same inputs gave different bytes")

    def test_one_package_set_at_two_build_snapshots_gives_the_same_bytes(self) -> None:
        images, second_images = self.plan["images"], self.second_plan["images"]
        assert isinstance(images, dict) and isinstance(second_images, dict)
        self.assertNotEqual(self.plan["snapshot"], self.second_plan["snapshot"])
        self.assertEqual(
            sorted(second_images["core"]["packages"]),
            sorted(images["core"]["packages"]),
            f"core's package set moved at {SECOND_SNAPSHOT}: choose a snapshot where it did not",
        )
        self.assertEqual(second_images["core"]["identity"], images["core"]["identity"])
        self.assertEqual(
            sha256_of(artifact(self.work / "out-second")),
            sha256_of(artifact(self.work / "out1")),
            "the build snapshot reached the bytes: one package set at two build snapshots gave different bytes",
        )

    def test_engine_revision_guard(self) -> None:
        name = published.parse_artifact_name(artifact(self.work / "out1").name)
        assert name is not None
        self.assertIn(ENGINE, EXPECTED_CORE, f"record the example core's digest for engine revision {ENGINE}")
        self.assertEqual(
            sha256_of(artifact(self.work / "out1")),
            EXPECTED_CORE[ENGINE],
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

    def test_no_key_or_credential_token_in_any_file_of_core(self) -> None:
        """The scan `no-machine-identity` runs, on Debian 13's own files: private key blocks and the credential
        shapes of checks/scanning.py (GitHub, AWS, Slack, npm, PyPI, GitLab) must find nothing, so a hit later
        is a real leak and not the distribution's own text. Plain files under /usr/share/doc are searched."""
        found = tarball.scan_tarball(artifact(self.work / "out1"), frozenset(), None, True)
        self.assertGreater(len(found.members), 1000, "the scan read the whole root")
        self.assertEqual(found.key_files, ())

    def test_published_core_is_reused(self) -> None:
        target = self.work / "target"
        factory("publish", str(self.work / "out1"), "--to", f"dir://{target}")
        after = self.work / "plan-after.json"
        factory("plan", *files(), "--against", f"dir://{target}", "--out", str(after))
        core = json.loads(after.read_text())["images"]["core"]
        digest = published.parse_artifact_name(artifact(self.work / "out1").name)
        assert digest is not None
        self.assertEqual(core["state"], "reuse")
        self.assertTrue(core["artifact"].startswith(f"sha256:{digest.digest12}"))


if __name__ == "__main__":
    unittest.main()
