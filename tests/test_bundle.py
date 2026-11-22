"""Inputs bundles (DESIGN 7.7): `fetch --bundle` writes them, `bundle.unpack` and `replay` read them back, and
`build --offline` refuses the network. No docker: the build itself is the integration test's."""

import contextlib
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from debian_image_factory import archive, bundle, cli, commands, fetch, planfile, replay
from debian_image_factory.build import run
from tests.support.fixture_archive import FIRST_ID
from tests.test_fetch import TOOL_BYTES, TOOL_URL, FetchCase, recording, tool_fields

IDENTITY = "ab" * 32


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class BundleCase(FetchCase):
    def with_states(self, **states: str) -> Path:
        document = json.loads(self.plan_text)
        for image, state in states.items():
            document["images"][image]["state"] = state
        return self.write_plan(json.dumps(document))

    def bundles(self, plan: Path, cache: Path | None = None, read: Callable[[str], bytes] | None = None) -> Path:
        """Fetch with --bundle into a new directory and return it."""
        directory = Path(tempfile.mkdtemp(dir=self.tmp))
        out = io.StringIO()
        status = fetch.fetch_command(
            plan,
            self.sources_in(cache or self.new_cache(), read) if read else self.sources_in(cache or self.new_cache()),
            bundle=True,
            out=out,
            bundle_dir=directory,
        )
        self.assertEqual(status, 0)
        return directory

    def only_core_and_app_a(self) -> Path:
        return self.with_states(**{"app-b": "reuse", "app-c": "wait"})


def members(path: Path) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    with tarfile.open(path, "r:") as archive_:
        for member in archive_:
            handle = archive_.extractfile(member)
            assert handle is not None
            found[member.name] = handle.read()
    return found


def rewritten(source: Path, edit: Callable[[dict[str, bytes]], None], first: str | None = bundle.MANIFEST) -> Path:
    """A copy of the bundle with its members edited, written as a plain tar (the manifest first unless `first`)."""
    found = members(source)
    edit(found)
    target = source.with_name("edited-" + source.name)
    names = sorted(found, key=lambda name: (name != first, name))
    with tarfile.open(target, "w") as archive_:
        for name in names:
            info = tarfile.TarInfo(name)
            info.size = len(found[name])
            archive_.addfile(info, io.BytesIO(found[name]))
    return target


class NameTest(unittest.TestCase):
    def test_a_bundle_is_named_by_what_determines_its_content(self) -> None:
        self.assertEqual(
            bundle.bundle_name("node-26", "trixie", "amd64", IDENTITY), f"node-26-trixie-amd64-{'ab' * 8}.inputs.tar"
        )
        with self.assertRaisesRegex(ValueError, "64 lowercase hex"):
            bundle.bundle_name("core", "trixie", "amd64", "abc")


class WriteTest(unittest.TestCase):
    def build(self, root: Path, name: str, long: bool = False) -> Path:
        (root / "a").write_bytes(b"alpha")
        (root / "b").write_bytes(b"beta" * 1000)
        deep = "cache/" + "d" * 150 + "/" + "e" * 80 if long else "cache/z"
        items = [
            bundle.hashed(deep, root / "b"),
            bundle.hashed("plan.json", root / "a"),
            bundle.hashed("cache/a", root / "a"),
        ]
        manifest = bundle.manifest_bytes(
            image="core", identity=IDENTITY, snapshot=FIRST_ID, suite="trixie", architecture="amd64", members=items
        )
        target = root / name
        bundle.write(target, manifest, list(reversed(items)))
        return target

    def test_the_same_members_in_any_order_give_the_same_bytes_with_fixed_headers(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            first, second = self.build(root, "one.tar"), self.build(root, "two.tar")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as archive_:
                infos = list(archive_)
            self.assertEqual([one.name for one in infos], ["manifest.json", "cache/a", "cache/z", "plan.json"])
            self.assertEqual(
                {(one.mtime, one.uid, one.gid, one.mode, one.uname, one.gname) for one in infos},
                {(0, 0, 0, 0o644, "", "")},
            )

    def test_a_member_name_too_long_for_a_plain_header_is_still_deterministic_and_unpacks(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            first, second = self.build(root, "one.tar", long=True), self.build(root, "two.tar", long=True)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            unpacked = bundle.unpack(first, root / "into")
            self.assertEqual((unpacked.cache / ("d" * 150) / ("e" * 80)).read_bytes(), b"beta" * 1000)
            self.assertEqual(unpacked.plan, b"alpha")

    def test_a_source_that_changed_since_it_was_hashed_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "a").write_bytes(b"alpha")
            item = bundle.hashed("plan.json", root / "a")
            (root / "a").write_bytes(b"alphabet")
            with self.assertRaisesRegex(commands.Failed, "changed while the bundle was being written"):
                bundle.write(root / "x.tar", b"{}", [item])
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["a"])


class FetchBundleTest(BundleCase):
    def test_one_bundle_per_image_that_builds_and_none_for_the_rest(self) -> None:
        directory = self.bundles(self.only_core_and_app_a())
        plan = planfile.parse_plan(json.loads(self.plan_text))
        expected = sorted(
            bundle.bundle_name(image, "trixie", "amd64", plan["images"][image]["identity"])
            for image in ("core", "app-a")
        )
        self.assertEqual(sorted(path.name for path in directory.iterdir()), expected)

    def test_a_bundle_holds_the_signed_indices_the_images_pool_files_and_its_plan(self) -> None:
        plan_path = self.only_core_and_app_a()
        directory = self.bundles(plan_path)
        plan = planfile.parse_plan(json.loads(self.plan_text))
        path = directory / bundle.bundle_name("app-a", "trixie", "amd64", plan["images"]["app-a"]["identity"])
        found = members(path)
        manifest = bundle.parse_manifest(json.loads(found["manifest.json"]))
        self.assertEqual((manifest["image"], manifest["snapshot"]), ("app-a", FIRST_ID))
        self.assertEqual(manifest["identity"], plan["images"]["app-a"]["identity"])
        self.assertEqual(found["plan.json"], plan_path.read_bytes())
        self.assertNotIn("verified_at", manifest, "no vendor .deb: no Release to judge")
        self.assertEqual(
            {one["path"]: one["sha256"] for one in manifest["files"]},
            {name: sha256(data) for name, data in found.items() if name != "manifest.json"},
        )
        stem = f"cache/mirror/{FIRST_ID}"
        for dist, archive_ in (
            ("trixie", "debian"),
            ("trixie-updates", "debian"),
            ("trixie-security", "debian-security"),
        ):
            self.assertIn(f"{stem}/{archive_}/dists/{dist}/InRelease", found)
        self.assertIn(f"{stem}/debian/dists/trixie/main/binary-amd64/Packages", found)
        self.assertIn(f"{stem}/debian/dists/trixie/main/binary-amd64/Packages.xz", found)
        pool = sorted(name.rsplit("/", 1)[1] for name in found if "/pool/" in name)
        self.assertEqual(pool, ["lib-a_1.0_all.deb", "tool-a_1.0_amd64.deb"], "only what app-a adds to core")

    def test_a_locked_input_travels_with_the_image(self) -> None:
        document = json.loads(self.plan_text)
        document["images"]["core"]["inputs"] = {"tool": tool_fields()}
        document["images"]["core"]["state"] = "build"
        for image in ("app-a", "app-b", "app-c"):
            document["images"][image]["state"] = "reuse"
        plan_path = self.write_plan(json.dumps(document))
        directory = self.bundles(plan_path, read=recording([], {TOOL_URL: TOOL_BYTES}))
        (path,) = directory.iterdir()
        found = members(path)
        self.assertEqual(found[f"cache/sha256/{sha256(TOOL_BYTES)[:2]}/{sha256(TOOL_BYTES)}"], TOOL_BYTES)

    def test_two_fetches_of_one_plan_write_the_same_bytes(self) -> None:
        plan = self.only_core_and_app_a()
        first, second = self.bundles(plan), self.bundles(plan)
        self.assertEqual(sorted(path.name for path in first.iterdir()), sorted(path.name for path in second.iterdir()))
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes(), path.name)

    def test_the_bundles_go_beside_the_plan_unless_told_otherwise(self) -> None:
        plan = self.only_core_and_app_a()
        out = io.StringIO()
        fetch.fetch_command(plan, self.sources_in(self.new_cache()), bundle=True, out=out)
        self.assertEqual(len(list((plan.parent / "bundles").glob("*.inputs.tar"))), 2)
        self.assertIn(f"bundle: {plan.parent.resolve() / 'bundles'}", out.getvalue())

    def test_a_plan_where_nothing_builds_writes_no_bundle_and_says_so(self) -> None:
        plan = self.with_states(core="reuse", **{"app-a": "reuse", "app-b": "wait", "app-c": "reuse"})
        out = io.StringIO()
        fetch.fetch_command(plan, self.sources_in(self.new_cache()), bundle=True, out=out)
        self.assertFalse((plan.parent / "bundles").exists())
        self.assertIn("bundles: none written, no image builds", out.getvalue())


class PackedCase(BundleCase):
    """A bundle of app-a (built on core, which builds too), fetched once for the class."""

    bundle_path: Path
    plan_path: Path

    def setUp(self) -> None:
        cls = type(self)
        if "bundle_path" not in vars(cls):
            cls.plan_path = self.only_core_and_app_a()
            plan = planfile.parse_plan(json.loads(self.plan_text))
            name = bundle.bundle_name("app-a", "trixie", "amd64", plan["images"]["app-a"]["identity"])
            cls.bundle_path = self.bundles(cls.plan_path) / name

    def scratch(self) -> Path:
        return Path(tempfile.mkdtemp(dir=self.tmp)) / "into"


class UnpackTest(PackedCase):
    def test_a_bundle_unpacks_to_a_cache_the_build_reads(self) -> None:
        unpacked = bundle.unpack(self.bundle_path, self.scratch())
        mirror = fetch.mirror_dir(unpacked.cache, FIRST_ID)
        self.assertTrue((mirror / "debian" / "dists" / "trixie" / "InRelease").is_file())
        self.assertTrue((mirror / "debian" / "pool" / "main" / "t" / "tool-a" / "tool-a_1.0_amd64.deb").is_file())

    def test_a_changed_byte_is_refused_naming_the_member(self) -> None:
        def flip(found: dict[str, bytes]) -> None:
            name = next(name for name in found if name.endswith("tool-a_1.0_amd64.deb"))
            found[name] = found[name][:-1] + bytes([found[name][-1] ^ 1])

        with self.assertRaisesRegex(commands.Failed, r"tool-a_1.0_amd64.deb does not match the manifest"):
            bundle.unpack(rewritten(self.bundle_path, flip), self.scratch())

    def test_a_member_the_manifest_does_not_list_is_refused(self) -> None:
        with self.assertRaisesRegex(commands.Failed, "cache/extra is not listed in the manifest"):
            bundle.unpack(
                rewritten(self.bundle_path, lambda found: found.update({"cache/extra": b"x"})), self.scratch()
            )

    def test_a_missing_member_is_refused(self) -> None:
        def drop(found: dict[str, bytes]) -> None:
            del found["plan.json"]

        with self.assertRaisesRegex(commands.Failed, "lacks"):
            bundle.unpack(rewritten(self.bundle_path, drop), self.scratch())

    def test_a_bundle_whose_manifest_is_not_first_is_refused(self) -> None:
        with self.assertRaisesRegex(commands.Failed, "its first member must be manifest.json"):
            bundle.unpack(rewritten(self.bundle_path, lambda found: None, first="plan.json"), self.scratch())

    def test_a_manifest_naming_a_path_outside_the_bundle_is_refused(self) -> None:
        def escape(found: dict[str, bytes]) -> None:
            manifest = json.loads(found["manifest.json"])
            manifest["files"][0]["path"] = "cache/../../escape"
            found["manifest.json"] = json.dumps(manifest).encode()

        with self.assertRaisesRegex(commands.Failed, "not a member name this bundle may hold"):
            bundle.unpack(rewritten(self.bundle_path, escape), self.scratch())

    def test_a_link_in_place_of_a_file_is_refused(self) -> None:
        target = self.bundle_path.with_name("link.tar")
        with tarfile.open(target, "w") as archive_:
            manifest = json.dumps(
                {
                    "schema": 1,
                    "image": "core",
                    "identity": IDENTITY,
                    "snapshot": FIRST_ID,
                    "suite": "trixie",
                    "architecture": "amd64",
                    "files": [{"path": "plan.json", "sha256": "0" * 64, "size": 0}],
                }
            ).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest)
            archive_.addfile(info, io.BytesIO(manifest))
            link = tarfile.TarInfo("plan.json")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            archive_.addfile(link)
        with self.assertRaisesRegex(commands.Failed, "not a regular file"):
            bundle.unpack(target, self.scratch())

    def test_what_is_not_a_tar_is_not_a_bundle(self) -> None:
        junk = self.bundle_path.with_name("junk.tar")
        junk.write_bytes(b"not a tar" * 100)
        with self.assertRaisesRegex(commands.Failed, "not an inputs bundle"):
            bundle.unpack(junk, self.scratch())
        with self.assertRaisesRegex(commands.Failed, "no-such-bundle.tar"):
            bundle.unpack(self.bundle_path.with_name("no-such-bundle.tar"), self.scratch())


class ReplayTest(PackedCase):
    def test_a_bundle_and_its_own_plan_open(self) -> None:
        opened = replay.open_replay(self.bundle_path, self.scratch(), None)
        self.assertEqual((opened.image, opened.plan), ("app-a", self.plan_path.read_bytes()))
        again = replay.open_replay(self.bundle_path, self.scratch(), self.plan_path)
        self.assertEqual(again.image, "app-a")

    def test_another_plan_is_refused(self) -> None:
        other = self.new_cache() / "plan.json"
        other.write_text(self.plan_text)  # the same plan with its states as planned: other bytes
        with self.assertRaisesRegex(commands.Failed, "is not the plan .* was fetched from"):
            replay.open_replay(self.bundle_path, self.scratch(), other)

    def test_a_manifest_that_names_another_identity_is_refused(self) -> None:
        def move(found: dict[str, bytes]) -> None:
            manifest = json.loads(found["manifest.json"])
            manifest["identity"] = "cd" * 32
            found["manifest.json"] = json.dumps(manifest).encode()

        with self.assertRaisesRegex(commands.Failed, "disagree on identity"):
            replay.open_replay(rewritten(self.bundle_path, move), self.scratch(), None)

    def test_an_image_the_plan_lacks_is_refused(self) -> None:
        def rename(found: dict[str, bytes]) -> None:
            manifest = json.loads(found["manifest.json"])
            manifest["image"] = "ghost"
            found["manifest.json"] = json.dumps(manifest).encode()

        with self.assertRaisesRegex(commands.Failed, "its plan has no image ghost"):
            replay.open_replay(rewritten(self.bundle_path, rename), self.scratch(), None)

    def test_a_bundle_without_a_signed_index_is_refused(self) -> None:
        def drop(found: dict[str, bytes]) -> None:
            manifest = json.loads(found["manifest.json"])
            gone = next(one["path"] for one in manifest["files"] if one["path"].endswith("trixie-security/InRelease"))
            manifest["files"] = [one for one in manifest["files"] if one["path"] != gone]
            found["manifest.json"] = json.dumps(manifest).encode()
            del found[gone]

        with self.assertRaisesRegex(
            commands.Failed, r"lacks 1 files its image's build reads.*trixie-security/InRelease"
        ):
            replay.open_replay(rewritten(self.bundle_path, drop), self.scratch(), None)

    def test_a_bundle_without_a_locked_input_is_refused(self) -> None:
        document = json.loads(self.plan_text)
        document["images"]["core"]["inputs"] = {"tool": tool_fields()}
        for image in ("app-a", "app-b", "app-c"):
            document["images"][image]["state"] = "reuse"
        directory = self.bundles(self.write_plan(json.dumps(document)), read=recording([], {TOOL_URL: TOOL_BYTES}))
        (path,) = directory.iterdir()
        digest = sha256(TOOL_BYTES)

        def drop(found: dict[str, bytes]) -> None:
            manifest = json.loads(found["manifest.json"])
            name = f"cache/sha256/{digest[:2]}/{digest}"
            manifest["files"] = [one for one in manifest["files"] if one["path"] != name]
            found["manifest.json"] = json.dumps(manifest).encode()
            del found[name]

        with self.assertRaisesRegex(commands.Failed, rf"lacks 1 files.*{digest}"):
            replay.open_replay(rewritten(path, drop), self.scratch(), None)
        self.assertEqual(archive.cache_path(Path("c"), digest).name, digest)


class OfflineTest(PackedCase):
    def build(self, *args: str) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["build", *args, "--out", str(self.scratch())])
        return code, err.getvalue()

    def test_offline_refuses_a_registry_parent(self) -> None:
        code, message = self.build(str(self.plan_path), "--offline", "--parents", "oci://registry.example.com/images")
        self.assertEqual(code, 2)
        self.assertIn("--offline reads nothing from a registry", message)
        self.assertIn("dir://PATH", message)

    def test_a_directory_parent_is_fine_offline(self) -> None:
        directories, registries = run.split_parent_targets(["dir:///parents"], offline=True)
        self.assertEqual((directories, registries), ([Path("/parents")], []))

    def test_the_offline_reader_refuses_every_url(self) -> None:
        with self.assertRaisesRegex(commands.Failed, "--offline: refusing to read https://snapshot.debian.org/x"):
            run.offline_read("https://snapshot.debian.org/x")

    def test_a_bundle_holds_one_image(self) -> None:
        code, message = self.build("--bundle", str(self.bundle_path), "--image", "core")
        self.assertEqual(code, 2)
        self.assertIn("holds the inputs of app-a only", message)

    def test_without_a_plan_or_a_bundle_there_is_nothing_to_build(self) -> None:
        code, message = self.build()
        self.assertEqual(code, 2)
        self.assertIn("build needs the plan (PLAN), or an inputs bundle", message)

    def test_a_bundle_of_another_plan_is_refused_before_anything_builds(self) -> None:
        other = self.new_cache() / "plan.json"
        other.write_text(self.plan_text)
        code, message = self.build(str(other), "--bundle", str(self.bundle_path))
        self.assertEqual(code, 1)
        self.assertIn("was fetched from", message)

    def test_a_replay_leaves_no_scratch_cache_behind(self) -> None:
        out = self.scratch()
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["build", "--bundle", str(self.bundle_path), "--out", str(out), "--image", "core"])
        self.assertEqual(code, 2)
        self.assertEqual([path.name for path in out.iterdir() if path.name.startswith(".bundle-")], [])


if __name__ == "__main__":
    unittest.main()
