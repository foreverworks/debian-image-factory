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

from debian_image_factory import commands, oci, ocilayout, publish, published, registry, targets, verify
from tests.support.definitions import CORE, HEADER, child
from tests.support.oci_fixtures import IDENTITY, make_image

ZOT: Final = "ghcr.io/project-zot/zot:v2.1.23"
DISTRIBUTION: Final = "docker.io/library/registry:3.1.2"
PORT: Final = "5000/tcp"
ABSENT: Final = "ab" * 32


def docker(*arguments: str) -> str:
    done = subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=300, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"docker {' '.join(arguments)}: {done.stderr.strip()}")
    return done.stdout.strip()


def start(image: str) -> tuple[str, str]:
    """Run `image` with its registry port published on a free port of 127.0.0.1: the container ID and
    the registry's name (`127.0.0.1:<port>`), once it answers."""
    container = docker("run", "-d", "-p", f"127.0.0.1::{PORT.partition('/')[0]}", image)
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
    def registry(self, image: str) -> str:
        container, name = start(image)
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

    def test_a_registry_with_the_referrers_api_zot(self) -> None:
        self.check(self.registry(ZOT), api=True)

    def test_a_registry_without_it_the_distribution_registry(self) -> None:
        self.check(self.registry(DISTRIBUTION), api=False)


if __name__ == "__main__":
    unittest.main()
