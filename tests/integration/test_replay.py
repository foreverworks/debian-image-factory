"""M6's acceptance check 3, for real: a bundle rebuilds with snapshot.debian.org unreachable (DESIGN 7.7, 12).

The example definition plus one more OCI image (`oci-tools`, which installs `jq`) is planned at the example lock's
snapshot. Core, oci-base and oci-tools are the images that build; the others are marked `reuse`, so `fetch` reads
nothing for them (DESIGN 7.7: only what builds). `fetch --bundle` writes one bundle per image that builds, and
the three images are built once the normal way, with the network. Then `build --offline --bundle` replays each
bundle inside a docker container started with `--network none`: the factory process itself has no route to
anything, not only the builder it starts. The container reaches the host's docker through its socket and
mounts the work paths at the same paths, so the builder's bind mounts resolve. A request to snapshot.debian.org
from the same container is made first and must fail.

Core is byte-equal across builds (M2), so the replayed core must have the first build's digest; an OCI image
is compared by its manifest digest. oci-tools builds on oci-base on core, found in the replay's output
directory: its bundle holds only what it adds (jq and what jq pulls), so a replay that finishes also proves a
child reads nothing of its parent from the mirror. Needs docker, the builder image (`scripts/builder build`)
and network access to snapshot.debian.org for the first fetch.
"""

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from debian_image_factory import bundle, published, resolve

from .test_core_build import EXAMPLES, ROOT, factory, sha256_of
from .test_oci_build import manifest_digest

TOOLS_IMAGE = """
[images.oci-tools]
kind = "oci"
parent = "oci-base"
packages = ["jq"]
"""

BUILDING = ("core", "oci-base", "oci-tools")
"""The images this test builds; the example's others are marked `reuse` and fetch reads nothing for them."""

PROBE = """\
import urllib.request

try:
    urllib.request.urlopen("https://snapshot.debian.org/", timeout=15)
except OSError as error:
    print("snapshot.debian.org is unreachable here:", type(error).__name__, error)
else:
    raise SystemExit("snapshot.debian.org answered: this container has a network")
"""


def artifact(out: Path, image: str) -> Path:
    found = [
        path
        for path in out.iterdir()
        if (name := published.parse_artifact_name(path.name)) is not None and name.image == image
    ]
    if len(found) != 1:
        raise AssertionError(f"{out} holds {len(found)} artifacts of {image}, expected one")
    return found[0]


def members(path: Path) -> list[str]:
    with tarfile.open(path, "r:") as archive:
        return archive.getnames()


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class ReplayTest(unittest.TestCase):
    work: Path
    scratch: tempfile.TemporaryDirectory[str]
    tag: str
    plan: dict[str, dict[str, object]]
    bundles: Path
    command: list[str]
    files: list[str]
    cache: list[str]
    fetched: str
    replay_output: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.tag = subprocess.run(
            [str(ROOT / "scripts" / "builder"), "build"], check=True, capture_output=True, text=True
        ).stdout.split()[-1]
        (ROOT / "dist").mkdir(exist_ok=True)
        cls.scratch = tempfile.TemporaryDirectory(prefix="integration-replay-", dir=ROOT / "dist")
        cls.work = Path(cls.scratch.name).resolve()
        definition = cls.work / "examples"
        shutil.copytree(EXAMPLES, definition)
        with (definition / "factory.toml").open("a") as handle:
            handle.write(TOOLS_IMAGE)
        cls.files = ["--lock", str(definition / "lock.json"), "--definition", str(definition / "factory.toml")]
        planned = cls.work / "plan.json"
        factory("plan", *cls.files, "--out", str(planned))
        document = json.loads(planned.read_text())
        for name, entry in document["images"].items():
            entry["state"] = "build" if name in BUILDING else "reuse"
        planned.write_text(json.dumps(document, indent=2) + "\n")
        cls.plan = document["images"]
        cache = cls.work / "cache"
        cls.cache = ["--cache", str(cache)]
        cls.bundles = cls.work / "bundles"
        cls.fetched = factory("fetch", str(planned), "--bundle", "--bundle-dir", str(cls.bundles), *cls.cache)
        # The first build, the normal way, from the cache fetch filled. An OCI image's annotations name the git
        # source of its definition when there is one, and the replay's container has no git: git is told to
        # look for no repository above the work directory, so both builds record the same (no) source.
        ceiling = mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": str(ROOT)})
        ceiling.start()
        cls.addClassCleanup(ceiling.stop)
        factory(
            "build", str(planned), "--out", str(cls.work / "out1"), *cls.files, *cls.cache,
            *[arg for image in BUILDING for arg in ("--image", image)], "--builder-image", cls.tag,
        )  # fmt: skip
        # the replay: every bundle, in order, by a factory with no network, in one container
        cls.replay_output = cls.replay_with_no_network()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.scratch.cleanup()

    @classmethod
    def bundle_of(cls, image: str) -> Path:
        entry = cls.plan[image]
        identity = entry["identity"]
        assert isinstance(identity, str)
        return cls.bundles / bundle.bundle_name(image, "trixie", "amd64", identity)

    @classmethod
    def replay_with_no_network(cls) -> str:
        """Run the probe and then every replay in one container with `--network none`; return what it printed.

        The factory runs as this user, in the builder image (it has Python 3.13), with the source tree and the
        work directory mounted at the paths they have on the host, the docker CLI and socket of the host, and no
        cache: a replay reads its bundle only, and `--cache` is not given."""
        socket = Path("/var/run/docker.sock")
        lines = ["set -eu", f"python3 {cls.work / 'probe.py'}"]
        (cls.work / "probe.py").write_text(PROBE)
        for image in BUILDING:
            arguments = ["--bundle", str(cls.bundle_of(image)), "--out", str(cls.work / "out2")]
            arguments += ["--builder-image", cls.tag, "--keyring", str(resolve.DEFAULT_KEYRING), *cls.files]
            lines.append("python3 -m debian_image_factory build --offline " + " ".join(arguments))
        (cls.work / "replay.sh").write_text("\n".join(lines) + "\n")
        cls.command = [
            "docker", "run", "--rm", "--network", "none",
            "--user", f"{os.getuid()}:{os.getgid()}", "--group-add", str(socket.stat().st_gid),
            "-e", f"PYTHONPATH={ROOT / 'src'}:{ROOT / '.vendor'}", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp",
            "-v", "/usr/bin/docker:/usr/bin/docker:ro", "-v", f"{socket}:{socket}",
            "-v", f"{ROOT}:{ROOT}:ro", "-v", f"{resolve.DEFAULT_KEYRING}:{resolve.DEFAULT_KEYRING}:ro",
            "-v", f"{cls.work}:{cls.work}",
            "--workdir", str(cls.work),
            cls.tag, "sh", str(cls.work / "replay.sh"),
        ]  # fmt: skip
        done = subprocess.run(cls.command, capture_output=True, text=True, check=False)
        shown = f"$ {' '.join(cls.command)}\n{done.stdout}{done.stderr}"
        if done.returncode != 0:
            raise AssertionError(f"the offline replay failed (exit {done.returncode}):\n{shown}")
        return shown

    def test_the_container_had_no_route_to_snapshot_debian_org(self) -> None:
        self.assertIn("snapshot.debian.org is unreachable here:", self.replay_output)
        self.assertIn("--network none", self.replay_output)

    def test_every_replay_built_its_image(self) -> None:
        for image in BUILDING:
            self.assertRegex(self.replay_output, rf"(?m)^{image}: ")

    def test_the_replayed_core_has_the_digest_of_the_first_build(self) -> None:
        first, again = artifact(self.work / "out1", "core"), artifact(self.work / "out2", "core")
        self.assertEqual(first.name, again.name)
        self.assertEqual(sha256_of(first), sha256_of(again), "the replay did not rebuild the same bytes")

    def test_the_replayed_oci_images_have_the_manifest_digests_of_the_first_build(self) -> None:
        for image in ("oci-base", "oci-tools"):
            self.assertEqual(
                manifest_digest(self.work / "out2", image), manifest_digest(self.work / "out1", image), image
            )

    def test_only_the_images_that_build_were_fetched_and_bundled(self) -> None:
        self.assertEqual(
            sorted(path.name for path in self.bundles.iterdir()), sorted(self.bundle_of(name).name for name in BUILDING)
        )
        self.assertIn("images: 3 build, 4 need nothing (reuse or wait)", self.fetched)
        # node-26's tarball, the installer's kernel and the OS image's bootloader were never read
        pool = [name for name in members(self.bundle_of("core")) if "/pool/" in name]
        self.assertTrue(pool)
        for name in ("linux-image", "grub-efi", "openssh-server"):
            self.assertEqual([one for one in pool if f"/{name}" in one], [], name)

    def test_a_child_bundle_holds_only_what_it_adds_to_its_parent(self) -> None:
        core = {name.rsplit("/", 1)[1] for name in members(self.bundle_of("core")) if "/pool/" in name}
        tools = {name.rsplit("/", 1)[1] for name in members(self.bundle_of("oci-tools")) if "/pool/" in name}
        self.assertTrue(any(name.startswith("jq_") for name in tools), "jq is what oci-tools adds")
        self.assertEqual(tools & core, set(), "a child's bundle repeats nothing of its parent's")
        self.assertEqual([name for name in members(self.bundle_of("oci-base")) if "/pool/" in name], [])

    def test_the_bundles_are_byte_identical_when_fetched_again(self) -> None:
        again = self.work / "bundles-again"
        factory("fetch", str(self.work / "plan.json"), "--bundle", "--bundle-dir", str(again), *self.cache)
        for name in BUILDING:
            path = self.bundle_of(name)
            self.assertEqual(sha256_of(path), sha256_of(again / path.name), path.name)

    def test_a_replay_leaves_no_unpacked_cache_in_the_output(self) -> None:
        self.assertEqual([path.name for path in (self.work / "out2").glob(".bundle-*")], [])


if __name__ == "__main__":
    unittest.main()
