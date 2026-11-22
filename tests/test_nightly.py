"""M6's acceptance checks 1 and 2 (DESIGN 14), on the nightly path itself: the Action's own plan and summary steps
(action.yml, run for real by tests/support/action.py) call the command line, `plan --snapshot latest --against
dir://...`, against the fixture archive served over HTTP, with a target that holds published artifacts and their
passing check records.

1. A night with no relevant upload builds nothing: at a later snapshot with no new version of any package an
   image installs, every image reads `reuse`, the Action's `changed` is false, and fetch, build, test and
   publish do not run.
2. A night with one upload rebuilds exactly its chain: with one new version of a package that one image
   installs, that image and its descendants read `build`, every other image `reuse`, and `changed` is true.
"""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Final

from input_lock.records import TestOutcome

from debian_image_factory import published
from tests import test_cli
from tests.support import action, incusimage
from tests.support.fixture_archive import FIRST_ID, SECOND_ID
from tests.support.oci_fixtures import records_text, result_line

EXTENSIONS: Final = {"core": "tar.gz", "os": "tar.gz", "installer": "tar"}
"""The file artifacts a `dir://` target holds, by kind (an Incus image is two files, written apart)."""

SHARED: Final = """\
schema = 1

[debian]
suite = "trixie"

[images.core]
kind = "core"
packages = ["tool-b"]

[images.installer]
kind = "installer"
parent = "core"
packages = ["linux-image-fixture"]

[images.os]
kind = "os"
parent = "core"
packages = ["linux-image-fixture"]

[images.incus-base]
kind = "incus"
parent = "core"
{base_packages}
[images.incus-app]
kind = "incus"
parent = "incus-base"
"""
QUIET: Final = SHARED.format(base_packages='packages = ["tool-b"]\n')
"""No image installs lib-a, the one package the fixture archive moves between its two snapshots."""
CHAIN: Final = SHARED.format(base_packages='packages = ["tool-a"]\n')
"""incus-base installs tool-a, which needs lib-a: the upload at the second snapshot reaches it and incus-app."""


def read_plan(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


class NightTest(test_cli.CliCase):
    document: dict[str, object]
    """The plan.json of the last `night`."""
    images: dict[str, dict[str, object]]
    """Its images."""

    def wrapper(self) -> Path:
        """A stand-in for the .pyz the Action runs: the factory from this checkout, told the fixture's keyring."""
        path = self.tmp / "factory.py"
        path.write_text(
            "import sys\n"
            f"sys.path[:0] = [{str(action.ROOT / 'src')!r}, {str(action.ROOT / '.vendor')!r}]\n"
            "from debian_image_factory.cli import main\n"
            f"keyring = ['--keyring', {str(self.fixture.keyring)!r}] if sys.argv[1] in ('plan', 'fetch') else []\n"
            "sys.exit(main([*sys.argv[1:], *keyring]))\n"
        )
        return path

    def night(self, root: Path, snapshot: str, target: Path | None, **inputs: str) -> action.Result:
        """One run of the Action as the nightly workflow gives it inputs: the definition and lock in `root`,
        `snapshot`, the target. Its first steps are the ones that run on a quiet night."""
        with tempfile.TemporaryDirectory(dir=self.tmp) as raw:
            result = action.run_action(
                {
                    "definition": str(root / "factory.toml"),
                    "lock": str(root / "lock.json"),
                    "snapshot": snapshot,
                    "against": "" if target is None else f"dir://{target}",
                    "mirror": self.mirror,
                    "pyz": str(self.wrapper()),
                    "keep-work": "true",  # the tests read plan.json after the run
                    **inputs,
                },
                scratch=Path(raw) / "temp",
                cwd=root,
                env={
                    "PYTHONPATH": f"{action.ROOT / 'src'}:{action.ROOT / '.vendor'}",
                    "XDG_CACHE_HOME": str(self.tmp / "cache"),
                },
                skip=("prerequisites",),
            )
            self.assertTrue(result.ok, result.log)
            self.document = read_plan(Path(result.outputs["plan"]["path"]))
            images = self.document["images"]
            assert isinstance(images, dict)
            self.images = images
            return result

    def publish_all(self, plan: dict[str, dict[str, object]], target: Path) -> dict[str, str]:
        """Every image of `plan` as a good artifact in `target`: its files, its provenance and a passing
        result for each check the plan requires. Returns the digest of each."""
        target.mkdir(parents=True, exist_ok=True)
        digests: dict[str, str] = {}
        for name, entry in plan.items():
            identity, kind, required = str(entry["identity"]), str(entry["kind"]), entry["checks"]
            assert isinstance(required, list)
            checks: list[tuple[str, TestOutcome]] = [(str(check), "PASSED") for check in required]
            if kind == "incus":
                built = incusimage.write_image(target, name, identity, f"rootfs of {name}".encode())
                with built.records.open("a", encoding="utf-8") as handle:
                    for check, _ in checks:
                        handle.write(result_line(built.names.image, built.fingerprint, check))
                digests[name] = built.fingerprint
                continue
            content = f"{name} {identity}".encode()
            digest = hashlib.sha256(content).hexdigest()
            file = published.artifact_name(name, "trixie", "amd64", identity, digest, EXTENSIONS[kind])
            (target / file).write_bytes(content)
            text = records_text(file, digest, image=name, kind=kind, identity=identity, checks=checks)
            (target / published.records_name_for(digest)).write_text(text)
            digests[name] = digest
        return digests

    def first_night(self, definition: str) -> tuple[Path, Path, dict[str, str], dict[str, dict[str, object]]]:
        """A workspace at the first snapshot whose every image is published, passing, in a target."""
        root = self.workspace(snapshot=FIRST_ID, factory=definition)
        target = Path(tempfile.mkdtemp(dir=self.tmp)) / "target"
        empty = self.night(root, FIRST_ID, target, steps="plan")
        self.assertEqual(empty.outputs["summary"]["changed"], "true", "nothing published yet: everything builds")
        first = self.images
        self.assertEqual({entry["state"] for entry in first.values()}, {"build"})
        digests = self.publish_all(first, target)
        return root, target, digests, first

    def test_a_night_with_no_relevant_upload_builds_nothing(self) -> None:
        root, target, digests, first = self.first_night(QUIET)
        result = self.night(root, "latest", target, publish="true")
        states = {name: entry["state"] for name, entry in self.images.items()}
        self.assertEqual(states, dict.fromkeys(first, "reuse"))
        # a later snapshot, and the same identities: the build snapshot enters no identity
        self.assertEqual(self.document["snapshot"], SECOND_ID)
        self.assertEqual(
            {n: e["identity"] for n, e in self.images.items()}, {n: e["identity"] for n, e in first.items()}
        )
        self.assertEqual(result.outputs["summary"], {"changed": "false", "images": "", "vm": "false"})
        for step in ("fetch", "build", "test", "publish"):
            self.assertNotIn(step, result.outputs, f"{step} must not run when nothing builds")
        self.assertEqual(
            json.loads(result.outputs["artifacts"]["json"]), {n: f"sha256:{d}" for n, d in digests.items()}
        )

    def test_one_upload_rebuilds_exactly_its_chain(self) -> None:
        root, target, digests, first = self.first_night(CHAIN)
        result = self.night(root, "latest", target, steps="plan")
        states = {name: entry["state"] for name, entry in self.images.items()}
        self.assertEqual(
            states,
            {
                "core": "reuse",
                "installer": "reuse",
                "os": "reuse",
                "incus-base": "build",
                "incus-app": "build",
            },
        )
        self.assertEqual(result.outputs["summary"]["changed"], "true")
        self.assertEqual(result.outputs["summary"]["images"], "incus-app,incus-base")
        # the new package is why the base builds, and the base is why its child does
        because = self.images["incus-base"]["because"]
        self.assertEqual(because, [{"published": "no artifact with this identity"}])
        self.assertEqual(self.images["incus-app"]["because"], [{"parent": "incus-base", "state": "build"}])
        for name in ("core", "installer", "os"):
            self.assertEqual(self.images[name]["identity"], first[name]["identity"], name)
            self.assertEqual(self.images[name]["artifact"], f"sha256:{digests[name]}", name)
        for name in ("incus-base", "incus-app"):
            self.assertNotEqual(self.images[name]["identity"], first[name]["identity"], name)
        artifacts = json.loads(result.outputs["artifacts"]["json"])
        self.assertEqual(sorted(artifacts), ["core", "installer", "os"])

    def test_the_nightly_s_prune_keeps_every_published_build_and_the_next_night_is_still_quiet(self) -> None:
        root, target, digests, _ = self.first_night(QUIET)
        before = sorted(path.name for path in target.iterdir())
        done = subprocess.run(
            [
                "python3", str(self.wrapper()), "prune", "--against", f"dir://{target}",
                "--definition", str(root / "factory.toml"),
            ],
            capture_output=True, text=True, check=False, env={**os.environ, "XDG_CACHE_HOME": str(self.tmp / "cache")},
        )  # fmt: skip
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(sorted(path.name for path in target.iterdir()), before)
        self.assertEqual(self.night(root, "latest", target).outputs["summary"]["changed"], "false")
        self.assertEqual(len(digests), 5)

    def test_the_same_night_twice_changes_nothing(self) -> None:
        root, target, _, _ = self.first_night(QUIET)
        again = self.night(root, "latest", target)
        self.assertEqual(again.outputs["summary"]["changed"], "false")

    def test_a_target_that_fails_a_required_check_is_built_again(self) -> None:
        root, target, _, first = self.first_night(QUIET)
        core = next(path for path in target.iterdir() if path.name.startswith("core-"))
        digest = hashlib.sha256(core.read_bytes()).hexdigest()
        records = target / published.records_name_for(digest)
        records.write_text(records.read_text() + result_line(core.name, digest, "package-set", "FAILED"))
        self.night(root, "latest", target, steps="plan")
        self.assertEqual(self.images["core"]["state"], "build")
        because = self.images["core"]["because"]
        assert isinstance(because, list)
        self.assertEqual(because[0], {"failed": ["package-set"]}, first["core"]["checks"])


if __name__ == "__main__":
    unittest.main()
