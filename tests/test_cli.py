"""The command line end to end against the fixture archive, served over HTTP the way snapshot.debian.org is."""

import contextlib
import hashlib
import http.server
import io
import json
import os
import stat
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
from email.message import Message
from pathlib import Path
from unittest import mock

import input_lock
from input_lock import JsonValue
from input_lock import fetch as input_lock_fetch
from input_lock.records import TestOutcome

from debian_image_factory import cli, commands, definition, publish
from tests.support import fake_github, fake_registry, fixture_archive
from tests.support.definitions import jsonable
from tests.support.fake_github import Fake as GithubFake
from tests.support.fake_registry import Fake
from tests.support.fixture_archive import FIRST_ID, LATER_ID, SECOND_ID, Fixture
from tests.support.oci_fixtures import make_core_file, make_image

FACTORY = """\
schema = 1

[debian]
suite = "trixie"

[params]
flag = false
vendor = false

[modules.vendor]
use = "builtin:deb"
enabled_by = "vendor"

[images.core]
kind = "core"
packages = ["tool-b"]

[images.app-a]
kind = "oci"
parent = "core"
packages = ["tool-a"]

[images.app-b]
kind = "oci"
parent = "core"
hooks = ["hooks/b.sh"]

[images.app-c]
kind = "oci"
parent = "app-a"
"""
BOX = """
[images.box]
kind = "os"
parent = "core"
apt_sources = "baseline"
"""
FACTORY_WITH_BASELINE = FACTORY + BOX
HOOK = '#!/bin/sh\necho "$FACTORY_PARAM_FLAG"\n'
VENDOR_ENTRY = {
    "apt": "example-tool",
    "datasource": "deb",
    "module": "vendor",
    "registryUrl": "https://packages.example.com/debian?suite=trixie&components=main&binaryArch=amd64",
    "sha256": "1" * 64,
    "url": "https://packages.example.com/pool/example-tool_{version}_amd64.deb",
    "signed_by": "vendor-keys",
    "used_by": ["app-b"],
    "version": "2.4.0-1",
    "depName": "example-tool",
}
VENDOR_KEYS = {
    "module": "vendor",
    "sha256": "2" * 64,
    "url": "https://packages.example.com/debian/keyring.pgp",
    "used_by": ["app-b"],
    "version": "1",
}
INSTALLS_LIB_A = ["app-a", "app-c"]
"""app-a installs tool-a, which needs lib-a; app-c is its child. Core and app-b do not have it."""


class Mirror(http.server.SimpleHTTPRequestHandler):
    """The fixture root as snapshot.debian.org serves it: `/mr/timestamp/?archive=NAME` answers from the
    recorded listings, and the fixture's one main suite also answers as `trixie-updates` (the fixture
    archive has none, and the resolver always reads one)."""

    def translate_path(self, path: str) -> str:
        parts = urllib.parse.urlsplit(path)
        if parts.path.rstrip("/") == "/mr/timestamp":
            archive = urllib.parse.parse_qs(parts.query).get("archive", [""])[0]
            return str(Path(self.directory) / "mr" / "timestamp" / f"{archive}.json")
        return super().translate_path(parts.path.replace("/dists/trixie-updates/", "/dists/trixie/"))

    def log_message(self, format: str, *args: object) -> None:
        pass


class Run:
    """What one `cli.main` call did."""

    def __init__(self, code: int, out: str, err: str) -> None:
        self.code, self.out, self.err = code, out, err

    def plan(self) -> dict[str, dict[str, JsonValue]]:
        document = jsonable(json.loads(self.out))
        images = document["images"]
        assert isinstance(images, dict)
        return {name: jsonable(entry) for name, entry in images.items()}


def packages_of(plan: dict[str, dict[str, JsonValue]], name: str) -> list[tuple[str, str]]:
    """(name, version) of every package an image of a plan installs."""
    packages = plan[name]["packages"]
    assert isinstance(packages, list)
    found = []
    for item in packages:
        assert isinstance(item, list)
        found.append((str(item[0]), str(item[1])))
    return found


class CliCase(unittest.TestCase):
    fixture: Fixture
    server: http.server.ThreadingHTTPServer
    mirror: str
    _tmp: tempfile.TemporaryDirectory[str]
    tmp: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="dif-cli-")
        cls.tmp = Path(cls._tmp.name)
        cls.fixture = fixture_archive.build_fixture(cls.tmp / "fixture")
        root = str(cls.fixture.root)

        def handler(*args: object, **kwargs: object) -> Mirror:
            return Mirror(*args, directory=root, **kwargs)  # type: ignore[arg-type]  # http.server's own call shape

        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.mirror = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls._tmp.cleanup()

    def baseline_entry(self, snapshot_id: str) -> dict[str, object]:
        """The reserved baseline entry `lock baseline --id` writes, computed from the fixture's InRelease."""
        in_release = (
            self.fixture.root / "archive" / "debian" / snapshot_id / "dists" / "trixie" / "InRelease"
        ).read_bytes()
        return {
            "sha256": hashlib.sha256(in_release).hexdigest(),
            "url": "https://snapshot.debian.org/archive/debian/{version}/dists/trixie/InRelease",
            "version": snapshot_id,
        }

    def workspace(
        self, snapshot: str = FIRST_ID, factory: str = FACTORY, inputs: dict[str, object] | None = None
    ) -> Path:
        """A directory holding factory.toml, a lock at `snapshot` and the hook. A definition with an image
        on snapshot sources gets the baseline entry at the first fixture ID."""
        root = Path(tempfile.mkdtemp(dir=self.tmp))
        (root / "hooks").mkdir()
        (root / "hooks" / "b.sh").write_text(HOOK)
        (root / "factory.toml").write_text(factory)
        entries = dict(inputs or {})
        if "apt_sources" in factory:
            entries["debian-baseline"] = self.baseline_entry(FIRST_ID)
        self.write_lock(root, snapshot, entries)
        return root

    def write_lock(self, root: Path, snapshot: str, inputs: dict[str, object]) -> None:
        (root / "lock.json").write_text(input_lock.dump({"debian_snapshot": snapshot, "inputs": inputs}))

    def sources(self, mirror: str | None = None) -> list[str]:
        return [
            "--mirror", mirror or self.mirror,
            "--keyring", str(self.fixture.keyring),
            "--cache", str(self.tmp / "cache"),
        ]  # fmt: skip

    def run_cli(self, root: Path, *argv: str, files: bool = True, sources: bool = True) -> Run:
        """`cli.main` in `root`'s files, its output captured."""
        out, err = io.StringIO(), io.StringIO()
        arguments = [*argv]
        if files:
            arguments += ["--lock", str(root / "lock.json")]
            if argv[0] != "lock" or argv[1] != "snapshot":
                arguments += ["--definition", str(root / "factory.toml")]
        if sources:
            arguments += self.sources()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(arguments)
        return Run(code, out.getvalue(), err.getvalue())

    def plan(self, root: Path, *extra: str) -> Run:
        return self.run_cli(root, "plan", *extra)


class PlanTest(CliCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        root = Path(tempfile.mkdtemp(dir=cls.tmp))
        (root / "hooks").mkdir()
        (root / "hooks" / "b.sh").write_text(HOOK)
        (root / "factory.toml").write_text(FACTORY)
        (root / "lock.json").write_text(input_lock.dump({"debian_snapshot": FIRST_ID, "inputs": {}}))
        cls.root = root
        cls.first = cls.run_plan("--snapshot", FIRST_ID)
        cls.second = cls.run_plan("--snapshot", SECOND_ID)

    @classmethod
    def run_plan(cls, *extra: str) -> Run:
        out, err = io.StringIO(), io.StringIO()
        arguments = [
            "plan", "--lock", str(cls.root / "lock.json"), "--definition", str(cls.root / "factory.toml"),
            "--mirror", cls.mirror, "--keyring", str(cls.fixture.keyring), "--cache", str(cls.tmp / "cache"),
            *extra,
        ]  # fmt: skip
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(arguments)
        return Run(code, out.getvalue(), err.getvalue())

    root: Path
    first: Run
    second: Run

    def test_both_plans_succeed(self) -> None:
        self.assertEqual((self.first.code, self.first.err), (0, ""))
        self.assertEqual((self.second.code, self.second.err), (0, ""))
        self.assertEqual(jsonable(json.loads(self.first.out))["snapshot"], FIRST_ID)
        self.assertEqual(jsonable(json.loads(self.second.out))["snapshot"], SECOND_ID)

    def test_every_image_is_resolved_from_the_fixture(self) -> None:
        found = sorted(name for name, _ in packages_of(self.first.plan(), "core"))
        self.assertEqual(found, ["apt", "base-files", "dpkg", "fixture-essential", "lib-b", "tool-b"])

    def test_exactly_the_images_installing_lib_a_change_identity(self) -> None:
        one, two = self.first.plan(), self.second.plan()
        moved = sorted(name for name in one if one[name]["identity"] != two[name]["identity"])
        self.assertEqual(moved, INSTALLS_LIB_A)
        for name in ("core", "app-b"):
            self.assertEqual(one[name]["identity"], two[name]["identity"], name)

    def test_the_images_that_did_not_move_keep_everything(self) -> None:
        one, two = self.first.plan(), self.second.plan()
        self.assertEqual(one["core"], {**two["core"]})
        self.assertEqual(one["app-b"]["packages"], two["app-b"]["packages"])

    def test_the_moved_images_carry_the_new_package(self) -> None:
        def lib_a(plan: dict[str, dict[str, JsonValue]], name: str) -> list[str]:
            return [version for package, version in packages_of(plan, name) if package == "lib-a"]

        for name in INSTALLS_LIB_A:
            self.assertEqual(lib_a(self.first.plan(), name), ["1.0"], name)
            self.assertEqual(lib_a(self.second.plan(), name), ["1.1"], name)

    def test_without_a_target_everything_builds(self) -> None:
        self.assertEqual({entry["state"] for entry in self.first.plan().values()}, {"build"})

    def test_a_param_flip_changes_only_the_image_whose_hook_reads_it(self) -> None:
        flipped = self.run_plan("--snapshot", FIRST_ID, "--param", "flag=true").plan()
        one = self.first.plan()
        self.assertEqual(sorted(n for n in one if one[n]["identity"] != flipped[n]["identity"]), ["app-b"])
        self.assertEqual(flipped["app-b"]["params"], {"flag": True})

    def test_params_from_a_file_do_the_same(self) -> None:
        params = self.root / "params.json"
        params.write_text('{"flag": true}')
        flipped = self.run_plan("--snapshot", FIRST_ID, "--params", str(params)).plan()
        self.assertEqual(flipped["app-b"]["params"], {"flag": True})

    def test_a_param_flag_beats_the_file(self) -> None:
        params = self.root / "params2.json"
        params.write_text('{"flag": true}')
        run = self.run_plan("--snapshot", FIRST_ID, "--params", str(params), "--param", "flag=false")
        self.assertEqual(run.plan()["app-b"]["params"], {"flag": False})

    def test_previous_names_what_moved(self) -> None:
        before = self.root / "before.json"
        before.write_text(self.first.out)
        run = self.run_plan("--snapshot", SECOND_ID, "--previous", str(before))
        self.assertEqual(run.code, 0)
        because = run.plan()["app-a"]["because"]
        assert isinstance(because, list)
        self.assertIn({"package": "lib-a", "from": "1.0", "to": "1.1"}, because)
        child_because = run.plan()["app-c"]["because"]
        assert isinstance(child_because, list)
        self.assertEqual(child_because[0], {"parent": "app-a", "state": "build"})
        self.assertIn(
            {
                "parent_identity": {
                    "from": self.first.plan()["app-a"]["identity"],
                    "to": run.plan()["app-a"]["identity"],
                }
            },
            child_because,
        )

    def test_the_plan_can_be_written_to_a_file(self) -> None:
        target = self.root / "plan.json"
        run = self.run_plan("--snapshot", FIRST_ID, "--out", str(target))
        self.assertEqual((run.code, run.out), (0, ""))
        self.assertEqual(json.loads(target.read_text()), json.loads(self.first.out))

    def test_the_lock_s_own_snapshot_is_the_default(self) -> None:
        self.assertEqual(self.run_plan().out, self.first.out)

    def test_latest_is_the_newest_completed_id(self) -> None:
        self.assertEqual(jsonable(json.loads(self.run_plan("--snapshot", "latest").out))["snapshot"], SECOND_ID)

    def test_against_an_empty_directory_builds(self) -> None:
        empty = Path(tempfile.mkdtemp(dir=self.tmp))
        run = self.run_plan("--snapshot", FIRST_ID, "--against", f"dir://{empty}")
        self.assertEqual(run.code, 0)
        self.assertEqual({entry["state"] for entry in run.plan().values()}, {"build"})
        self.assertEqual(run.plan()["core"]["because"], [{"published": "no artifact with this identity"}])

    def test_against_a_missing_directory_builds_too(self) -> None:
        run = self.run_plan("--snapshot", FIRST_ID, "--against", f"dir://{self.tmp}/nowhere")
        self.assertEqual({entry["state"] for entry in run.plan().values()}, {"build"})

    def test_against_an_empty_registry_builds_too(self) -> None:
        with fake_registry.running(Fake()) as name:
            run = self.run_plan("--snapshot", FIRST_ID, "--against", f"oci://{name}/images")
        self.assertEqual(run.code, 0)
        self.assertEqual({entry["state"] for entry in run.plan().values()}, {"build"})

    def test_against_a_registry_that_holds_an_image_reuses_it(self) -> None:
        identity = str(self.run_plan("--snapshot", FIRST_ID).plan()["core"]["identity"])
        checks: list[tuple[str, TestOutcome]] = [(check, "PASSED") for check in definition.BUILTIN_CHECKS["core"]]
        out = Path(tempfile.mkdtemp(dir=self.tmp))
        built = make_image(out, image="core", identity=identity, checks=checks)
        with fake_registry.running(Fake()) as name:
            publish.publish_command(out, [f"oci://{name}/images"], "none", io.StringIO())
            run = self.run_plan("--snapshot", FIRST_ID, "--against", f"oci://{name}/images")
        self.assertEqual(run.code, 0)
        self.assertEqual(run.plan()["core"]["state"], "reuse")
        self.assertEqual(run.plan()["core"]["artifact"], f"sha256:{built.digest}")
        self.assertEqual(run.plan()["app-a"]["state"], "build")

    def test_against_a_templated_registry_looks_each_image_up_in_its_own_repository(self) -> None:
        identity = str(self.run_plan("--snapshot", FIRST_ID).plan()["core"]["identity"])
        checks: list[tuple[str, TestOutcome]] = [(check, "PASSED") for check in definition.BUILTIN_CHECKS["core"]]
        out = Path(tempfile.mkdtemp(dir=self.tmp))
        built = make_image(out, image="core", identity=identity, checks=checks)
        fake = Fake()
        with fake_registry.running(fake) as name:
            publish.publish_command(out, [f"oci://{name}/team/{{image}}"], "none", io.StringIO())
            self.assertIn(f"sha256:{built.digest}", fake.manifests)
            fake.log.clear()
            run = self.run_plan("--snapshot", FIRST_ID, "--against", f"oci://{name}/team/{{image}}")
        self.assertEqual(run.code, 0, run.err)
        self.assertEqual(run.plan()["core"]["state"], "reuse")
        self.assertEqual(run.plan()["core"]["artifact"], f"sha256:{built.digest}")
        self.assertEqual(run.plan()["app-a"]["state"], "build")
        asked = {line.split("/")[3] for line in fake.log if line.startswith("GET /v2/team/")}
        self.assertEqual(asked, {"core", "app-a", "app-b", "app-c"})

    def test_against_refuses_a_placeholder_outside_an_oci_repository(self) -> None:
        for target in ("dir:///srv/{image}", "github-release://example/{image}@v1", "oci://{image}.example.com/x"):
            with self.subTest(target):
                run = self.run_plan("--snapshot", FIRST_ID, "--against", target)
                self.assertEqual(run.code, 2)
                self.assertIn("{image} belongs in the repository of an oci:// target", run.err)

    def test_against_a_tag_without_a_release_builds_too(self) -> None:
        with fake_github.running(GithubFake()) as api, fake_github.environment(api):
            run = self.run_plan("--snapshot", FIRST_ID, "--against", "github-release://example/images@v1")
        self.assertEqual(run.code, 0)
        self.assertEqual({entry["state"] for entry in run.plan().values()}, {"build"})

    def test_against_a_release_that_holds_core_reuses_it(self) -> None:
        identity = str(self.run_plan("--snapshot", FIRST_ID).plan()["core"]["identity"])
        checks: list[tuple[str, TestOutcome]] = [(check, "PASSED") for check in definition.BUILTIN_CHECKS["core"]]
        out = Path(tempfile.mkdtemp(dir=self.tmp))
        built = make_core_file(out, identity=identity, checks=checks)
        with fake_github.running(GithubFake()) as api, fake_github.environment(api):
            publish.publish_command(out, ["github-release://example/images@v1"], "none", io.StringIO())
            run = self.run_plan("--snapshot", FIRST_ID, "--against", "github-release://example/images@v1")
        self.assertEqual(run.code, 0)
        self.assertEqual(run.plan()["core"]["state"], "reuse")
        self.assertEqual(run.plan()["core"]["artifact"], f"sha256:{built.digest}")
        self.assertEqual(run.plan()["app-a"]["state"], "build")

    def test_a_release_that_cannot_be_read_is_exit_1_naming_it(self) -> None:
        down = GithubFake(fail_once=["GET /repos"] * 8)
        with fake_github.running(down) as api, fake_github.environment(api):
            run = self.run_plan("--snapshot", FIRST_ID, "--against", "github-release://example/images@v1")
        self.assertEqual(run.code, 1)
        self.assertIn("cannot read target", run.err)
        self.assertIn("HTTP 503", run.err)

    def test_rebuild_with_a_reason_is_recorded(self) -> None:
        run = self.run_plan("--snapshot", FIRST_ID, "--rebuild", "app-b", "--reason", "key rotation")
        self.assertEqual(run.plan()["app-b"]["because"], [{"rebuild": "key rotation"}])


class ExitCodeTest(CliCase):
    def test_a_snapshot_that_is_not_completed_is_exit_1(self) -> None:
        root = self.workspace()
        run = self.plan(root, "--snapshot", LATER_ID)
        self.assertEqual(run.code, 1)
        self.assertIn(f"snapshot ID {LATER_ID} cannot be used", run.err)
        self.assertIn("is not completed", run.err)
        self.assertEqual(run.out, "")

    def test_a_lock_whose_snapshot_is_not_completed_is_exit_1(self) -> None:
        run = self.plan(self.workspace(LATER_ID))
        self.assertEqual(run.code, 1)
        self.assertIn("the lock's snapshot ID", run.err)

    def test_a_snapshot_that_is_not_an_id_is_exit_1(self) -> None:
        run = self.plan(self.workspace(), "--snapshot", "yesterday")
        self.assertEqual(run.code, 1)
        self.assertIn("is not a snapshot ID", run.err)

    def test_an_invalid_definition_is_exit_1_naming_the_file(self) -> None:
        root = self.workspace(factory=FACTORY + '[images.second]\nkind = "core"\n')
        run = self.plan(root)
        self.assertEqual(run.code, 1)
        self.assertIn("factory.toml: a definition has exactly one core image, not 2", run.err)

    def test_a_missing_hook_is_exit_1(self) -> None:
        root = self.workspace()
        (root / "hooks" / "b.sh").unlink()
        run = self.plan(root)
        self.assertEqual(run.code, 1)
        self.assertIn("factory.toml: hooks/b.sh: a hook or module script must be a regular file", run.err)

    def test_a_missing_definition_is_exit_1(self) -> None:
        root = self.workspace()
        (root / "factory.toml").unlink()
        run = self.plan(root)
        self.assertEqual(run.code, 1)
        self.assertIn("factory.toml: No such file or directory", run.err)

    def test_a_lock_that_breaks_a_rule_is_exit_1_naming_every_problem(self) -> None:
        root = self.workspace(inputs={"thing": {**VENDOR_ENTRY, "used_by": ["ghost"], "module": "nope"}})
        run = self.plan(root)
        self.assertEqual(run.code, 1)
        self.assertIn("lock.json: inputs.thing.used_by names ['ghost']", run.err)

    def test_a_switched_on_builtin_deb_module_on_core_is_exit_1(self) -> None:
        # a vendor .deb that resolves is planned in tests/test_vendor_deb.py, against a signed fixture repository
        on_core = {"used_by": ["core"]}
        inputs: dict[str, object] = {
            "example-tool": {**VENDOR_ENTRY, **on_core},
            "vendor-keys": {**VENDOR_KEYS, **on_core},
        }
        root = self.workspace(inputs=inputs)
        self.assertEqual(
            self.plan(root, "--snapshot", FIRST_ID).code, 0
        )  # the switch is off: its entry is installed nowhere
        run = self.plan(root, "--snapshot", FIRST_ID, "--param", "vendor=true")
        self.assertEqual(run.code, 1)
        self.assertIn("images.core: module vendor (builtin:deb) installs into child images only", run.err)

    def test_a_failing_package_is_exit_1_with_apts_message(self) -> None:
        root = self.workspace(factory=FACTORY.replace('packages = ["tool-a"]', 'packages = ["no-such-package"]'))
        run = self.plan(root, "--snapshot", FIRST_ID)
        self.assertEqual(run.code, 1)
        self.assertIn("Unable to locate package no-such-package", run.err)

    def test_a_child_that_asks_for_what_its_parent_holds_does_not_fail(self) -> None:
        # the refusal of an upgrade needs a parent resolved at another snapshot than the child, which one
        # plan never does (every image of a plan resolves at one ID); test_resolve covers the refusal itself
        factory = FACTORY.replace('packages = ["tool-b"]', 'packages = ["lib-a"]').replace(
            'packages = ["tool-a"]', 'packages = ["lib-a"]'
        )
        run = self.plan(self.workspace(factory=factory), "--snapshot", SECOND_ID)
        self.assertEqual(run.code, 0)

    def raw(self, *arguments: str) -> Run:
        """`cli.main` with exactly these arguments."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(arguments))
        return Run(code, out.getvalue(), err.getvalue())

    def test_an_unreachable_service_is_exit_1(self) -> None:
        root = self.workspace()
        run = self.raw(
            "plan", "--lock", str(root / "lock.json"), "--definition", str(root / "factory.toml"),
            "--mirror", "http://127.0.0.1:9", "--keyring", str(self.fixture.keyring),
            "--cache", str(self.tmp / "cache"),
        )  # fmt: skip
        self.assertEqual(run.code, 1)
        self.assertIn("cannot read the snapshot listings from http://127.0.0.1:9", run.err)

    def test_a_file_mirror_cannot_serve_the_listings(self) -> None:
        # urllib's file: handler keeps the query in the path, so `/mr/timestamp/?archive=debian` finds nothing:
        # a file: root serves the archive's files (test_resolve) but not the listings, which need a server.
        root = self.workspace()
        run = self.raw(
            "lock", "check", "--lock", str(root / "lock.json"), "--definition", str(root / "factory.toml"),
            "--mirror", f"file://{self.fixture.root}", "--keyring", str(self.fixture.keyring),
        )  # fmt: skip
        self.assertEqual(run.code, 1)
        self.assertIn("cannot read the snapshot listings", run.err)

    def test_rebuild_without_a_reason_is_exit_2(self) -> None:
        run = self.plan(self.workspace(), "--rebuild", "app-b")
        self.assertEqual(run.code, 2)
        self.assertIn('--rebuild needs --reason "<why>"', run.err)

    def test_rebuild_of_an_unknown_image_is_exit_2(self) -> None:
        run = self.plan(self.workspace(), "--rebuild", "ghost", "--reason", "x")
        self.assertEqual(run.code, 2)
        self.assertIn("--rebuild names ['ghost'], which are not images", run.err)

    def test_an_unknown_param_is_exit_2(self) -> None:
        run = self.plan(self.workspace(), "--param", "colour=red")
        self.assertEqual(run.code, 2)
        self.assertIn("unknown parameters ['colour']", run.err)

    def test_a_badly_typed_param_is_exit_2(self) -> None:
        run = self.plan(self.workspace(), "--param", "flag=maybe")
        self.assertEqual(run.code, 2)
        self.assertIn("parameter flag is a boolean", run.err)

    def test_a_param_without_a_value_is_exit_2(self) -> None:
        run = self.plan(self.workspace(), "--param", "flag")
        self.assertEqual(run.code, 2)
        self.assertIn("--param flag: NAME=VALUE", run.err)

    def test_a_params_file_that_is_not_an_object_is_exit_2(self) -> None:
        root = self.workspace()
        (root / "params.json").write_text("[1]")
        run = self.plan(root, "--params", str(root / "params.json"))
        self.assertEqual(run.code, 2)
        self.assertIn("a JSON object of parameter values", run.err)

    def test_a_params_file_that_is_missing_is_exit_2(self) -> None:
        root = self.workspace()
        self.assertEqual(self.plan(root, "--params", str(root / "none.json")).code, 2)

    def test_a_bad_target_is_exit_2(self) -> None:
        run = self.plan(self.workspace(), "--snapshot", FIRST_ID, "--against", "ftp://example.com/x")
        self.assertEqual(run.code, 2)
        self.assertIn("unknown target scheme", run.err)

    def test_a_target_that_is_not_one_is_refused_before_anything_is_resolved(self) -> None:
        root = self.workspace()
        for target in ("github-release://someone/repo", "github-release://someone@v1", "nonsense"):
            with self.subTest(target=target):
                run = self.raw(
                    "plan", "--lock", str(root / "lock.json"), "--definition", str(root / "factory.toml"),
                    "--mirror", "http://127.0.0.1:9", "--keyring", str(self.fixture.keyring),
                    "--cache", str(self.tmp / "cache"), "--against", target,
                )  # fmt: skip
                self.assertEqual(run.code, 2)  # not 1: the unreachable service was never asked
                self.assertIn(
                    "not a target" if target == "nonsense" else "github-release://<owner>/<repo>@<tag>", run.err
                )

    def test_a_lock_that_is_not_utf8_is_exit_1_naming_the_file(self) -> None:
        root = self.workspace()
        (root / "lock.json").write_bytes(b'{"inputs": "\xff"}')
        run = self.plan(root)
        self.assertEqual(run.code, 1)
        self.assertIn("lock.json: not UTF-8 text", run.err)

    def test_a_definition_that_is_not_utf8_is_exit_1_naming_the_file(self) -> None:
        root = self.workspace()
        (root / "factory.toml").write_bytes(b"schema = 1\n# \xff\n")
        run = self.plan(root)
        self.assertEqual(run.code, 1)
        self.assertIn("factory.toml: not UTF-8 text", run.err)

    def test_a_lock_that_cannot_be_read_is_exit_1_naming_the_file(self) -> None:
        root = self.workspace()
        (root / "lock.json").unlink()
        (root / "lock.json").mkdir()
        run = self.plan(root)
        self.assertEqual(run.code, 1)
        self.assertIn("lock.json: ", run.err)

    def test_a_missing_lock_is_exit_1(self) -> None:
        root = self.workspace()
        (root / "lock.json").unlink()
        run = self.plan(root)
        self.assertEqual(run.code, 1)
        self.assertIn("lock.json: No such file or directory", run.err)

    def test_a_plan_that_cannot_be_written_is_exit_1_naming_the_file(self) -> None:
        root = self.workspace()
        target = root / "no-such-directory" / "plan.json"
        run = self.plan(root, "--snapshot", FIRST_ID, "--out", str(target))
        self.assertEqual(run.code, 1)
        self.assertIn(f"{target}: No such file or directory", run.err)

    def test_a_previous_plan_that_is_not_utf8_is_exit_1(self) -> None:
        root = self.workspace()
        (root / "prev.json").write_bytes(b"\xff")
        run = self.plan(root, "--snapshot", FIRST_ID, "--previous", str(root / "prev.json"))
        self.assertEqual(run.code, 1)
        self.assertIn("prev.json: not UTF-8 text", run.err)

    def test_a_previous_plan_that_is_not_json_is_exit_2(self) -> None:
        root = self.workspace()
        (root / "prev.json").write_text("{")
        run = self.plan(root, "--snapshot", FIRST_ID, "--previous", str(root / "prev.json"))
        self.assertEqual(run.code, 2)
        self.assertIn("--previous", run.err)

    def test_lock_needs_a_command(self) -> None:
        run = self.run_cli(self.workspace(), "lock", files=False, sources=False)
        self.assertEqual(run.code, 2)
        self.assertIn("lock needs a command", run.err)

    def test_no_command_is_exit_2(self) -> None:
        run = self.raw()
        self.assertEqual(run.code, 2)
        self.assertIn("a command is needed", run.err)

    def test_the_arguments_parser_exits_2_on_its_own_errors(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            cli.main(["plan", "--nope"])
        self.assertEqual(caught.exception.code, 2)

    def test_version_exits_0(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as caught:
            cli.main(["--version"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("debian-image-factory", out.getvalue())


class LockTest(CliCase):
    def baselined(self) -> Path:
        """A workspace whose baseline entry `lock baseline --id` wrote."""
        root = self.workspace(factory=FACTORY_WITH_BASELINE)
        (root / "lock.json").unlink()
        self.write_lock(root, FIRST_ID, {})
        run = self.run_cli(root, "lock", "baseline", "--id", FIRST_ID)
        self.assertEqual((run.code, run.err), (0, ""))
        return root

    def test_lock_check_passes_and_reports_serving_per_archive(self) -> None:
        root = self.baselined()
        run = self.run_cli(root, "lock", "check")
        self.assertEqual((run.code, run.err), (0, ""))
        lines = run.out.splitlines()
        self.assertEqual(lines[0], "lock.json and factory.toml agree: 5 images, 1 entries")
        self.assertEqual(
            lines[1],
            f"debian_snapshot {FIRST_ID}: completed; debian serves {FIRST_ID}, debian-security serves {FIRST_ID}",
        )
        self.assertEqual(
            lines[2],
            f"inputs.debian-baseline {FIRST_ID}: completed; "
            f"debian serves {FIRST_ID}, debian-security serves {FIRST_ID}",
        )

    def test_lock_check_reports_what_a_later_id_serves(self) -> None:
        root = self.baselined()
        self.write_lock(root, SECOND_ID, json.loads((root / "lock.json").read_text())["inputs"])
        run = self.run_cli(root, "lock", "check")
        self.assertEqual(run.code, 0)
        self.assertIn(
            f"debian_snapshot {SECOND_ID}: completed; debian serves {SECOND_ID}, debian-security serves {SECOND_ID}",
            run.out,
        )

    def test_lock_check_between_two_listed_ids_serves_the_earlier(self) -> None:
        root = self.baselined()
        between = "20261105T120000Z"
        self.write_lock(root, between, json.loads((root / "lock.json").read_text())["inputs"])
        run = self.run_cli(root, "lock", "check")
        self.assertEqual(run.code, 0)
        self.assertIn(f"debian serves {FIRST_ID}, debian-security serves {FIRST_ID}", run.out)

    def test_lock_check_fails_an_id_that_is_not_completed(self) -> None:
        root = self.baselined()
        self.write_lock(root, LATER_ID, json.loads((root / "lock.json").read_text())["inputs"])
        run = self.run_cli(root, "lock", "check")
        self.assertEqual(run.code, 1)
        self.assertIn(f"debian_snapshot {LATER_ID}: NOT usable", run.out)
        self.assertIn(f"debian_snapshot {LATER_ID}: {LATER_ID} is not completed", run.err)

    def test_lock_check_without_its_baseline_fails_the_rules(self) -> None:
        root = self.baselined()
        data = json.loads((root / "lock.json").read_text())
        del data["inputs"]["debian-baseline"]
        (root / "lock.json").write_text(input_lock.dump(data))
        run = self.run_cli(root, "lock", "check")
        self.assertEqual(run.code, 1)
        self.assertIn("lock.json: inputs.debian-baseline is required: ['box']", run.err)

    def test_lock_check_offline_does_not_touch_the_service(self) -> None:
        root = self.baselined()
        run = self.run_cli(root, "lock", "check", "--offline", sources=False)
        self.assertEqual(run.code, 0)
        self.assertIn("snapshot IDs not re-resolved (--offline)", run.out)

    def test_lock_check_notices_a_baseline_whose_in_release_changed(self) -> None:
        root = self.baselined()
        data = json.loads((root / "lock.json").read_text())
        data["inputs"]["debian-baseline"]["sha256"] = "0" * 64
        (root / "lock.json").write_text(input_lock.dump(data))
        run = self.run_cli(root, "lock", "check")
        self.assertEqual(run.code, 1)
        self.assertIn("does not match its sha256", run.err)

    BLOB_URL = "https://downloads.example.com/blob-1.bin"

    def blob_workspace(self) -> Path:
        """A workspace whose core places a `builtin:file` download, its checksum stale."""
        factory = FACTORY.replace(
            "[images.core]", '[modules.blob]\nuse = "builtin:file"\npath = "/opt/blob"\n\n[images.core]'
        )
        blob = {"module": "blob", "sha256": "3" * 64, "url": self.BLOB_URL, "used_by": ["core"], "version": "1"}
        return self.workspace(factory=factory, inputs={"blob": blob})

    def checksums(self, root: Path, served: dict[str, bytes], *argv: str) -> Run:
        """`lock checksums` with input-lock's downloads answered from `served` (a missing URL is a 404)."""

        def hashes(url: str, algorithms: list[str]) -> dict[str, str]:
            if url not in served:
                raise urllib.error.HTTPError(url, 404, "Not Found", Message(), None)
            return {algorithm: hashlib.new(algorithm, served[url]).hexdigest() for algorithm in algorithms}

        with mock.patch.object(input_lock_fetch, "hashes", side_effect=hashes):
            return self.run_cli(root, "lock", "checksums", *argv, sources=False)

    def test_lock_checksums_fills_the_named_entry_from_its_download(self) -> None:
        root = self.blob_workspace()
        run = self.checksums(root, {self.BLOB_URL: b"the blob"}, "--entry", "blob")
        self.assertEqual(run.code, 0, run.err)
        entry = json.loads((root / "lock.json").read_text())["inputs"]["blob"]
        self.assertEqual(entry["sha256"], hashlib.sha256(b"the blob").hexdigest())
        self.assertIn(f"blob: sha256 {'3' * 64} -> {entry['sha256']}", run.out)

    def test_lock_checksums_needs_an_entry_or_a_base(self) -> None:
        run = self.checksums(self.blob_workspace(), {})
        self.assertEqual(run.code, 2)
        self.assertIn("--entry NAME", run.err)

    def test_lock_checksums_writes_nothing_when_a_download_fails(self) -> None:
        root = self.blob_workspace()
        before = (root / "lock.json").read_text()
        run = self.checksums(root, {}, "--entry", "blob")
        self.assertEqual(run.code, 1)
        self.assertIn("nothing written", run.err)
        self.assertEqual((root / "lock.json").read_text(), before)

    def test_lock_checksums_refuses_a_lock_the_definition_disagrees_with(self) -> None:
        root = self.blob_workspace()
        (root / "factory.toml").write_text(FACTORY)
        run = self.checksums(root, {self.BLOB_URL: b"the blob"}, "--entry", "blob")
        self.assertEqual(run.code, 1)
        self.assertIn("blob", run.err)

    def test_lock_baseline_writes_the_reserved_entry(self) -> None:
        root = self.workspace()
        run = self.run_cli(root, "lock", "baseline", "--id", SECOND_ID)
        self.assertEqual(run.out, f"baseline: None -> {SECOND_ID}\n")
        entry = json.loads((root / "lock.json").read_text())["inputs"]["debian-baseline"]
        self.assertEqual(entry["version"], SECOND_ID)
        self.assertEqual(entry["url"], "https://snapshot.debian.org/archive/debian/{version}/dists/trixie/InRelease")
        in_release = (
            self.fixture.root / "archive" / "debian" / SECOND_ID / "dists" / "trixie" / "InRelease"
        ).read_bytes()
        self.assertEqual(entry["sha256"], hashlib.sha256(in_release).hexdigest())

    def test_lock_baseline_moves_an_existing_one(self) -> None:
        root = self.baselined()
        run = self.run_cli(root, "lock", "baseline", "--id", SECOND_ID)
        self.assertEqual(run.out, f"baseline: {FIRST_ID} -> {SECOND_ID}\n")

    def test_lock_baseline_refuses_an_id_that_is_not_completed(self) -> None:
        root = self.workspace()
        before = (root / "lock.json").read_text()
        run = self.run_cli(root, "lock", "baseline", "--id", LATER_ID)
        self.assertEqual(run.code, 1)
        self.assertIn(f"baseline {LATER_ID} cannot be used", run.err)
        self.assertEqual((root / "lock.json").read_text(), before)

    def test_lock_snapshot_latest_writes_the_newest_completed_id(self) -> None:
        root = self.workspace()
        run = self.run_cli(root, "lock", "snapshot", "--latest")
        self.assertEqual((run.code, run.err), (0, ""))
        self.assertEqual(run.out, f"debian_snapshot: {FIRST_ID} -> {SECOND_ID}\n")
        self.assertEqual(json.loads((root / "lock.json").read_text())["debian_snapshot"], SECOND_ID)

    def test_lock_snapshot_latest_twice_stays(self) -> None:
        root = self.workspace()
        self.run_cli(root, "lock", "snapshot", "--latest")
        run = self.run_cli(root, "lock", "snapshot", "--latest")
        self.assertEqual(run.out, f"debian_snapshot stays {SECOND_ID}\n")

    def test_lock_snapshot_keeps_the_rest_of_the_lock(self) -> None:
        root = self.workspace(inputs={"example-tool": VENDOR_ENTRY})
        self.run_cli(root, "lock", "snapshot", "--latest")
        self.assertEqual(json.loads((root / "lock.json").read_text())["inputs"], {"example-tool": VENDOR_ENTRY})

    def test_lock_snapshot_refuses_an_id_that_is_not_completed(self) -> None:
        root = self.workspace()
        before = (root / "lock.json").read_text()
        run = self.run_cli(root, "lock", "snapshot", "--id", LATER_ID)
        self.assertEqual(run.code, 1)
        self.assertIn(f"snapshot ID {LATER_ID} cannot be used", run.err)
        self.assertIn("is not completed", run.err)
        self.assertEqual((root / "lock.json").read_text(), before)

    def test_lock_snapshot_takes_a_given_completed_id(self) -> None:
        root = self.workspace()
        run = self.run_cli(root, "lock", "snapshot", "--id", SECOND_ID)
        self.assertEqual(run.code, 0)
        self.assertEqual(json.loads((root / "lock.json").read_text())["debian_snapshot"], SECOND_ID)

    def test_lock_snapshot_refuses_what_is_not_an_id(self) -> None:
        self.assertEqual(self.run_cli(self.workspace(), "lock", "snapshot", "--id", "soon").code, 1)

    def test_lock_snapshot_needs_latest_or_an_id(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            cli.main(["lock", "snapshot"])
        self.assertEqual(caught.exception.code, 2)

    def test_a_lock_that_is_not_json_is_exit_1(self) -> None:
        root = self.workspace()
        (root / "lock.json").write_text("{")
        run = self.run_cli(root, "lock", "snapshot", "--latest")
        self.assertEqual(run.code, 1)
        self.assertIn("lock.json", run.err)


class SourcesTest(unittest.TestCase):
    def test_defaults_point_at_the_real_service(self) -> None:
        sources = commands.Sources()
        self.assertEqual(sources.service, "https://snapshot.debian.org")

    def test_the_default_cache_follows_xdg_cache_home(self) -> None:
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "/somewhere/cache"}):
            self.assertEqual(commands.default_cache(), Path("/somewhere/cache/debian-image-factory"))
            self.assertEqual(commands.Sources().cache, Path("/somewhere/cache/debian-image-factory"))

    def test_the_default_cache_is_under_home_otherwise(self) -> None:
        env = {key: value for key, value in os.environ.items() if key != "XDG_CACHE_HOME"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(commands.default_cache(), Path.home() / ".cache" / "debian-image-factory")

    def no_home(self, scratch: str) -> contextlib.ExitStack:
        env = {key: value for key, value in os.environ.items() if key != "XDG_CACHE_HOME"}
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.dict(os.environ, env, clear=True))
        stack.enter_context(mock.patch.object(Path, "home", side_effect=RuntimeError))
        stack.enter_context(mock.patch.object(tempfile, "tempdir", scratch))
        return stack

    def test_the_default_cache_survives_a_missing_home_directory_in_a_private_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dif-tmp-") as scratch, self.no_home(scratch):
            cache = commands.default_cache()
            self.assertEqual(cache, Path(scratch) / f"debian-image-factory-cache-{os.geteuid()}")
            self.assertEqual(stat.S_IMODE(cache.stat().st_mode), 0o700)
            self.assertEqual(commands.default_cache(), cache)

    def test_a_shared_directory_is_not_used_as_the_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dif-tmp-") as scratch, self.no_home(scratch):
            planted = Path(scratch) / f"debian-image-factory-cache-{os.geteuid()}"
            planted.mkdir(mode=0o755)
            planted.chmod(0o755)
            with self.assertRaisesRegex(commands.Usage, "not a private directory"):
                commands.default_cache()

    def test_a_link_is_not_used_as_the_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dif-tmp-") as scratch, self.no_home(scratch):
            elsewhere = Path(scratch) / "elsewhere"
            elsewhere.mkdir(mode=0o700)
            (Path(scratch) / f"debian-image-factory-cache-{os.geteuid()}").symlink_to(elsewhere)
            with self.assertRaisesRegex(commands.Usage, "not a private directory"):
                commands.default_cache()

    def test_a_file_url_is_readable_through_the_default_reader(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dif-read-") as scratch:
            (Path(scratch) / "x").write_bytes(b"data")
            self.assertEqual(commands.Sources().read(f"file://{scratch}/x"), b"data")

    def test_service_url_swaps_the_host(self) -> None:
        sources = commands.Sources(service="http://127.0.0.1:1/")
        self.assertEqual(
            commands.service_url(sources, "https://snapshot.debian.org/archive/debian/X/dists/trixie/InRelease"),
            "http://127.0.0.1:1/archive/debian/X/dists/trixie/InRelease",
        )


if __name__ == "__main__":
    unittest.main()
