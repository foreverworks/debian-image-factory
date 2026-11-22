"""The registry edge against two real registries in rootless Docker on 127.0.0.1 (DESIGN 12).

One lists referrers through the API, one does not, so both branches of DESIGN 8.2 run against software
that exists: zot (`ghcr.io/project-zot/zot`) and the CNCF distribution registry
(`docker.io/library/registry`). The test confirms which is which by asking each for the referrers of a
digest before it relies on it. A synthetic one-layer image and records shaped like the factory's own are
published to each, published again (no second copy of anything), looked up by identity, pulled back byte
for byte and verified; a changed byte then fails `verify`. Needs docker and network access for the
images. Containers are removed by the ID this test started, never by name.
"""

import contextlib
import io
import os
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Final

from debian_image_factory import commands, oci, ocilayout, prune, publish, published, registry, targets, verify
from tests.support.definitions import CORE, HEADER, child
from tests.support.oci_fixtures import IDENTITY, make_image

ZOT: Final = "ghcr.io/project-zot/zot:v2.1.23"
DISTRIBUTION: Final = "docker.io/library/registry:3.1.2"
DELETE_DISABLED: Final = "REGISTRY_STORAGE_DELETE_ENABLED=false"
"""The official distribution image's default configuration allows DELETE (`storage.delete.enabled: true`), as
zot does; a registry configured like this refuses it (405), as distribution itself does by default."""
PORT: Final = "5000/tcp"
ABSENT: Final = "ab" * 32
GOOD: Final = (("package-set", "PASSED"), ("oci-run", "PASSED"))


def docker(*arguments: str) -> str:
    done = subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=300, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"docker {' '.join(arguments)}: {done.stderr.strip()}")
    return done.stdout.strip()


def start(image: str, *environment: str) -> tuple[str, str]:
    """Run `image` (with the given `NAME=value` environment) with its registry port published on a free
    port of 127.0.0.1: the container ID and the registry's name (`127.0.0.1:<port>`), once it answers."""
    flags = [flag for entry in environment for flag in ("-e", entry)]
    container = docker("run", "-d", "-p", f"127.0.0.1::{PORT.partition('/')[0]}", *flags, image)
    port = docker("port", container, PORT).splitlines()[0].rpartition(":")[2]
    name = f"127.0.0.1:{port}"
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError), urllib.request.urlopen(f"http://{name}/v2/", timeout=2) as answer:
            if answer.status == 200:
                return container, name
        time.sleep(0.3)
    raise RuntimeError(f"{image} did not answer on {name}: {docker('logs', container)[-500:]}")


def referrers_status(name: str) -> int:
    """What the registry answers on the referrers endpoint for a digest it has never seen."""
    try:
        with urllib.request.urlopen(f"http://{name}/v2/probe/referrers/sha256:{ABSENT}", timeout=5) as answer:
            return int(answer.status)
    except urllib.error.HTTPError as error:
        return int(error.code)


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 (docker and network needed)")
class RegistriesTest(unittest.TestCase):
    def registry(self, image: str, *environment: str) -> str:
        container, name = start(image, *environment)
        self.addCleanup(docker, "rm", "-f", container)
        return name

    def check(self, name: str, *, api: bool) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.assertEqual(referrers_status(name), 200 if api else 404, "the registry is not the kind this test expects")
        built = make_image(root / "out", checks=[("package-set", "PASSED"), ("oci-run", "PASSED")])
        target = f"oci://{name}/factory/app"
        client = registry.connect(published.OciTarget(name, "factory/app"))

        said = io.StringIO()
        publish.publish_command(root / "out", [target], "none", said)
        self.assertEqual(said.getvalue(), f"{target}: {built.name} pushed, 4 records added\n")

        again = io.StringIO()
        publish.publish_command(root / "out", [target], "none", again)
        self.assertEqual(again.getvalue(), f"{target}: {built.name} already there, 0 records added\n")
        held = registry.referrers_of(client, built.digest)
        self.assertEqual((held.via, len(held.attached), held.problems), ("api" if api else "tag", 4, ()))
        index = registry.tag_index(client, built.digest)
        self.assertEqual(index is None, api)  # the tag schema is used only where there is no API
        if index is not None:
            self.assertEqual(len(oci.parse_index(index)), 4)

        found = targets.lookup(published.OciTarget(name, "factory/app"), "app", "trixie", "amd64", IDENTITY)
        self.assertEqual(found.rejected, ())
        (artifact,) = found.artifacts
        self.assertEqual(
            (artifact.identity, artifact.digest, artifact.name),
            (IDENTITY, built.digest, f"{target}@sha256:{built.digest}"),
        )
        self.assertEqual(dict(artifact.results), {"package-set": "PASSED", "oci-run": "PASSED"})

        pulled = registry.pull_layout(client, built.digest, root / "pulled")
        original, copy = ocilayout.read_layout(built.layout), ocilayout.read_layout(pulled)
        self.assertEqual(copy.manifest_bytes, original.manifest_bytes)
        self.assertEqual(copy.config_bytes, original.config_bytes)
        self.assertEqual([p.read_bytes() for p in copy.layers], [p.read_bytes() for p in original.layers])

        definition = root / "factory.toml"
        definition.write_text(HEADER + CORE + child("app", "oci", "core"))
        for ref in (f"{target}@sha256:{built.digest}", f"{target}:{oci.identity_tag(IDENTITY)}", str(built.layout)):
            with self.subTest(ref=ref):
                verified = io.StringIO()
                self.assertEqual(verify.verify_command(ref, False, None, definition, verified), 0)
                self.assertIn("verified", verified.getvalue())

        layer = original.layers[0]
        layer.write_bytes(layer.read_bytes() + b"x")
        with self.assertRaisesRegex(commands.Failed, "does not match its descriptor"):
            verify.verify_command(str(built.layout), False, None, definition, io.StringIO())

    def published_images(self, name: str, root: Path) -> list[str]:
        """Three images of one repository, oldest first: good, failed, good. Their manifest digests."""
        digests: list[str] = []
        for number, checks in enumerate(
            ([*GOOD], [("package-set", "PASSED"), ("oci-run", "FAILED")], [*GOOD]), start=1
        ):
            out = root / f"out-{number}"
            built = make_image(
                out,
                identity=f"{number:02x}" * 32,
                content=f"image {number}".encode(),
                checks=checks,  # type: ignore[arg-type]  # outcomes spelled out above
                finished=f"2026-11-{number:02d}T02:00:00Z",
            )
            publish.publish_command(out, [f"oci://{name}/factory/app"], "none", io.StringIO())
            digests.append(built.digest)
        return digests

    def prune_check(self, name: str, *, deletes: bool) -> None:
        """`prune` keeps the newest good build and deletes the older one and the failed one (when the
        registry allows it: else it fails, naming each artifact, and touches nothing)."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        client = registry.connect(published.OciTarget(name, "factory/app"))
        first, failed, newest = self.published_images(name, root)
        definition = root / "factory.toml"
        definition.write_text(
            HEADER + CORE + child("app", "oci", "core") + '[checks]\ndefault = ["package-set", "oci-run"]\n'
        )
        said = io.StringIO()
        target = f"oci://{name}/factory/app"
        if deletes:
            self.assertEqual(prune.prune_command([target], [], 1, 0, False, definition, said), 0)
        else:
            with self.assertRaisesRegex(commands.Failed, "HTTP 405") as caught:
                prune.prune_command([target], [], 1, 0, False, definition, said)
            for digest in (first, failed):
                self.assertIn(f"@sha256:{digest}: the delete failed", str(caught.exception))
        for digest, identity in ((first, "01" * 32), (failed, "02" * 32)):
            gone = deletes
            self.assertEqual(registry.manifest_digest(client, f"sha256:{digest}") is None, gone, said.getvalue())
            self.assertEqual(registry.manifest_digest(client, oci.identity_tag(identity)) is None, gone)
            if gone:
                self.assertEqual(registry.referrers_of(client, digest).attached, ())
                self.assertIsNone(registry.tag_index(client, digest))
        self.assertEqual(registry.manifest_digest(client, f"sha256:{newest}"), newest)
        self.assertEqual(len(registry.referrers_of(client, newest).attached), 4)
        found = targets.lookup(published.OciTarget(name, "factory/app"), "app", "trixie", "amd64", "03" * 32)
        self.assertEqual((found.rejected, [one.digest for one in found.artifacts]), ((), [newest]))
        self.assertIn(f"@sha256:{newest} kept, ", said.getvalue())
        self.assertEqual(len(registry.list_tags(client)) > 0, True)

    def test_prune_on_a_registry_with_the_referrers_api_zot(self) -> None:
        self.prune_check(self.registry(ZOT), deletes=True)

    def test_prune_on_a_registry_without_it_the_distribution_registry(self) -> None:
        self.prune_check(self.registry(DISTRIBUTION), deletes=True)

    def test_prune_on_a_distribution_registry_with_deletes_disabled_is_refused_per_artifact(self) -> None:
        self.prune_check(self.registry(DISTRIBUTION, DELETE_DISABLED), deletes=False)

    def test_a_registry_with_the_referrers_api_zot(self) -> None:
        self.check(self.registry(ZOT), api=True)

    def test_a_registry_without_it_the_distribution_registry(self) -> None:
        self.check(self.registry(DISTRIBUTION), api=False)


if __name__ == "__main__":
    unittest.main()
