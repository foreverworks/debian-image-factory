"""M3's acceptance (DESIGN 14), end to end on the example definition with the real node module.

From the examples: plan, fetch, build core, oci-base and node-26 (Node.js from nodejs.org, checked against
the signed SHASUMS256.txt), `test` the output with the definition's module tables, then publish: core to a
dir:// target, the OCI images to two registries in Docker on 127.0.0.1, zot (the referrers API) and the CNCF
distribution registry (no referrers API: the tag schema). What it proves, one test each:

- the Node runtime image's provenance names core's digest (`ancestor: core`, after `parent: oci-base`);
- its Node version equals the lock's: `locked-inputs` passed (its probe ran `node --version`), and the
  image pulled back from the registry by digest prints that version;
- records attach on a registry without the referrers API: the tag `sha256-<manifest digest>` lists every
  record, `verify --require-checks --lock` passes on it, and `plan --against` reuses all three images.

Needs docker, the builder image (`scripts/builder build`), network access to snapshot.debian.org and
nodejs.org, and the two registry images. Containers and images are removed by the IDs this test made.
"""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar

from debian_image_factory import cli, oci, ocilayout, published, records, registry, targets

from .test_core_build import EXAMPLES, ROOT, factory, files, sha256_of
from .test_oci_build import layout_of
from .test_registries import DISTRIBUTION, ZOT, docker, referrers_status, start

IMAGES = ("core", "oci-base", "node-26")
NODE = "/usr/local/bin/node"


def locked_node_version() -> str:
    """The version the example lock pins for node-26's tarball, as `node --version` prints it."""
    lock = json.loads((EXAMPLES / "lock.json").read_text())
    entries = lock.get("inputs", lock)
    return f"v{entries['node-26']['version']}"


def exit_status(*argv: str) -> tuple[int, str]:
    """Run the command line in this process: its exit status and what it printed on both streams."""
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(printed):
        status = cli.main(list(argv))
    return status, printed.getvalue()


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class OciAcceptanceTest(unittest.TestCase):
    scratch: ClassVar[tempfile.TemporaryDirectory[str]]
    work: ClassVar[Path]
    out: ClassVar[Path]
    plan: ClassVar[dict[str, object]]
    containers: ClassVar[list[str]]
    pulled: ClassVar[list[str]]
    registries: ClassVar[dict[str, str]]  # "zot" / "distribution" -> 127.0.0.1:<port>

    @classmethod
    def setUpClass(cls) -> None:
        tag = subprocess.run(
            [str(ROOT / "scripts" / "builder"), "build"], check=True, capture_output=True, text=True
        ).stdout.split()[-1]
        (ROOT / "dist").mkdir(exist_ok=True)
        cls.scratch = tempfile.TemporaryDirectory(prefix="integration-acceptance-", dir=ROOT / "dist")
        cls.work = Path(cls.scratch.name)
        cls.out = cls.work / "out"
        cls.containers, cls.pulled, cls.registries = [], [], {}
        try:
            plan = cls.work / "plan.json"
            factory("plan", *files(), "--out", str(plan))
            factory("fetch", str(plan))
            cls.plan = json.loads(plan.read_text())
            images = [argument for image in IMAGES for argument in ("--image", image)]
            factory("build", str(plan), "--out", str(cls.out), *images, "--builder-image", tag, *files())
            status, said = exit_status("test", str(cls.out), "--definition", str(EXAMPLES / "factory.toml"))
            if status != 0:
                raise AssertionError(f"test exited {status}:\n{said}")
            for kind, image in (("zot", ZOT), ("distribution", DISTRIBUTION)):
                container, name = start(image)
                cls.containers.append(container)
                cls.registries[kind] = name
            targets_ = [f"--to={cls.target(kind)}" for kind in cls.registries]
            factory("publish", str(cls.out), f"--to=dir://{cls.work / 'published'}", *targets_)
            # node-26 again, in an empty directory, its parent pulled from the registry without the API
            reuse = cls.work / "plan-reuse.json"
            against = ["--against", f"dir://{cls.work / 'published'}", "--against", cls.target("distribution")]
            factory("plan", *files(), *against, "--out", str(reuse))
            factory("fetch", str(reuse))
            # the first target holds nothing, so the second is asked: each target in turn (DESIGN 9.1)
            empty = f"oci://{cls.registries['zot']}/factory/empty"
            parents = ["--parents", empty, "--parents", cls.target("distribution")]
            factory(
                "build", str(reuse), "--out", str(cls.work / "out-pulled"), "--image", "node-26",
                *parents, "--builder-image", tag, *files(),
            )  # fmt: skip
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.pulled:
            subprocess.run(["docker", "rmi", "--force", *cls.pulled], capture_output=True, check=False)
        if cls.containers:
            subprocess.run(["docker", "rm", "--force", *cls.containers], capture_output=True, check=False)
        cls.scratch.cleanup()

    @classmethod
    def target(cls, kind: str) -> str:
        return f"oci://{cls.registries[kind]}/factory/images"

    def digest(self, image: str) -> str:
        return ocilayout.read_layout(layout_of(self.out, image)).descriptor.digest

    def identity(self, image: str) -> str:
        images = self.plan["images"]
        assert isinstance(images, dict)
        return str(images[image]["identity"])

    def local_records(self, image: str) -> list[str]:
        return (self.out / f"{self.digest(image)}.intoto.jsonl").read_text().splitlines()

    def client(self, kind: str) -> registry.Client:
        return registry.connect(published.OciTarget(self.registries[kind], "factory/images"))

    # ---- a parent pulled from a registry ----------------------------------------------------------

    def test_a_parent_pulled_from_a_registry_gives_the_same_image(self) -> None:
        self.assertEqual(
            ocilayout.read_layout(layout_of(self.work / "out-pulled", "node-26")).descriptor.digest,
            self.digest("node-26"),
        )

    # ---- a Node runtime image's provenance names core's digest ----------------------------------

    def test_node_26s_provenance_names_cores_digest(self) -> None:
        core = sha256_of(next(self.out.glob("core-trixie-*.tar.gz")))
        provenance = records.decode_statements("\n".join(self.local_records("node-26")))[0]["predicate"]
        assert isinstance(provenance, dict)
        found = provenance["buildDefinition"]["resolvedDependencies"]
        named = [(one.get("name"), one.get("digest", {}).get("sha256")) for one in found]
        self.assertIn(("parent: oci-base", self.digest("oci-base")), named)
        self.assertIn(("ancestor: core", core), named)
        self.assertEqual(ocilayout.read_layout(layout_of(self.out, "node-26")).manifest.layers[0].digest, core)

    # ---- its Node version equals the lock's -----------------------------------------------------

    def test_node_26s_node_version_equals_the_locks(self) -> None:
        expected = locked_node_version()
        for kind in self.registries:
            with self.subTest(registry=kind):
                found = targets.lookup(
                    published.OciTarget(self.registries[kind], "factory/images"),
                    "node-26",
                    "trixie",
                    "amd64",
                    self.identity("node-26"),
                )
                self.assertEqual(found.rejected, ())
                (artifact,) = found.artifacts
                self.assertEqual(dict(artifact.results).get("locked-inputs"), "PASSED")
        # the image as a consumer gets it: pulled from the registry without the referrers API, by digest
        ref = f"{self.registries['distribution']}/factory/images@sha256:{self.digest('node-26')}"
        docker("pull", "--quiet", ref)
        type(self).pulled.append(ref)
        printed = docker("run", "--rm", "--network", "none", "--entrypoint", NODE, ref, "--version")
        self.assertEqual(printed, expected)

    # ---- records attach on a registry without the referrers API ---------------------------------

    def test_records_attach_on_a_registry_without_the_referrers_api(self) -> None:
        self.assertEqual(referrers_status(self.registries["distribution"]), 404)
        self.assertEqual(referrers_status(self.registries["zot"]), 200)
        client = self.client("distribution")
        for image in ("oci-base", "node-26"):
            with self.subTest(image=image):
                digest = self.digest(image)
                index = registry.tag_index(client, digest)
                self.assertIsNotNone(index, f"no tag {oci.referrers_tag(digest)} on the distribution registry")
                assert index is not None
                self.assertEqual(len(oci.parse_index(index)), len(self.local_records(image)))
                held = registry.referrers_of(client, digest)
                self.assertEqual((held.via, held.problems), ("tag", ()))
                self.assertIsNone(registry.tag_index(self.client("zot"), digest), "zot has the API: no tag")

    def test_verify_requires_every_check_on_both_registries(self) -> None:
        for kind in self.registries:
            for image in ("oci-base", "node-26"):
                with self.subTest(registry=kind, image=image):
                    ref = f"{self.target(kind)}@sha256:{self.digest(image)}"
                    status, said = exit_status(
                        "verify",
                        ref,
                        "--require-checks",
                        "--definition",
                        str(EXAMPLES / "factory.toml"),
                        "--lock",
                        str(EXAMPLES / "lock.json"),
                    )
                    self.assertEqual(status, 0, said)
                    self.assertIn("verified", said)

    def test_plan_against_the_targets_reuses_all_three_images(self) -> None:
        for kind in self.registries:
            with self.subTest(registry=kind):
                plan = self.work / f"plan-{kind}.json"
                against = ["--against", f"dir://{self.work / 'published'}", "--against", self.target(kind)]
                factory("plan", *files(), *against, "--out", str(plan))
                images = json.loads(plan.read_text())["images"]
                self.assertEqual({image: images[image]["state"] for image in IMAGES}, dict.fromkeys(IMAGES, "reuse"))


if __name__ == "__main__":
    unittest.main()
