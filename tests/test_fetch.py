"""`fetch` end to end against the fixture archive: the cache, the partial mirror, locked inputs, and apt itself."""

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path

from debian_image_factory import archive, cli, commands, fetch, planfile, remote, resolve
from debian_image_factory.snapshots import ARCHIVES
from tests.support.fixture_archive import FIRST_ID
from tests.test_cli import FACTORY, HOOK, CliCase

FIRST_IDS = dict.fromkeys(ARCHIVES, FIRST_ID)
TOOL_URL = "https://downloads.example.com/tool-1.0.tar"
TOOL_BYTES = b"the locked tool\n"
KEY_URL = "https://downloads.example.com/keys-1.0.pgp"
KEY_BYTES = b"a locked trust root\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recording(urls: list[str], served: Mapping[str, bytes] | None = None) -> Callable[[str], bytes]:
    """A reader that notes every URL it is asked for and answers `served` URLs itself, the rest from the fixture."""

    def read(url: str) -> bytes:
        urls.append(url)
        if served is not None and url in served:
            return served[url]
        return remote.read_url(url)

    return read


def tool_fields(**extra: str) -> dict[str, object]:
    return {"url": TOOL_URL, "version": "1.0", "sha256": sha256(TOOL_BYTES), **extra}


class FetchCase(CliCase):
    plan_text: str

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        root = Path(tempfile.mkdtemp(dir=cls.tmp))
        (root / "hooks").mkdir()
        (root / "hooks" / "b.sh").write_text(HOOK)
        (root / "factory.toml").write_text(FACTORY)
        (root / "lock.json").write_text(json.dumps({"schema": 1, "debian_snapshot": FIRST_ID, "inputs": {}}))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(
                [
                    "plan",
                    "--lock",
                    str(root / "lock.json"),
                    "--definition",
                    str(root / "factory.toml"),
                    "--mirror",
                    cls.mirror,
                    "--keyring",
                    str(cls.fixture.keyring),
                    "--cache",
                    str(cls.tmp / "cache"),
                ]
            )
        assert code == 0, err.getvalue()
        cls.plan_text = out.getvalue()

    def sources_in(self, cache: Path, read: Callable[[str], bytes] = remote.read_url) -> commands.Sources:
        return commands.Sources(service=self.mirror, keyring=self.fixture.keyring, cache=cache, read=read)

    def new_cache(self) -> Path:
        return Path(tempfile.mkdtemp(dir=self.tmp))

    def write_plan(self, text: str) -> Path:
        path = self.new_cache() / "plan.json"
        path.write_text(text)
        return path

    def edited_plan(self, image: str, key: str, value: object) -> Path:
        document = json.loads(self.plan_text)
        document["images"][image][key] = value
        return self.write_plan(json.dumps(document))

    def fetch(self, plan: Path, cache: Path, read: Callable[[str], bytes] = remote.read_url) -> str:
        out = io.StringIO()
        status = fetch.fetch_command(plan, self.sources_in(cache, read), bundle=False, out=out)
        self.assertEqual(status, 0)
        return out.getvalue()


class FetchTest(FetchCase):
    def plan_packages(self) -> set[tuple[str, str, str]]:
        return {tuple(p) for entry in json.loads(self.plan_text)["images"].values() for p in entry["packages"]}

    def test_lays_out_the_signed_indices_and_every_pool_file(self) -> None:
        cache = self.new_cache()
        summary = self.fetch(self.write_plan(self.plan_text), cache)
        mirror = fetch.mirror_dir(cache, FIRST_IDS)
        self.assertEqual(mirror, cache / "mirror" / f"{FIRST_ID}_{FIRST_ID}")
        served = self.fixture.root / "archive" / "debian" / FIRST_ID
        self.assertEqual(
            (mirror / "debian" / "dists" / "trixie" / "InRelease").read_bytes(),
            (served / "dists" / "trixie" / "InRelease").read_bytes(),
        )
        for dist in ("trixie", "trixie-updates"):
            self.assertTrue((mirror / "debian" / "dists" / dist / "main" / "binary-amd64" / "Packages.xz").is_file())
            self.assertTrue((mirror / "debian" / "dists" / dist / "main" / "binary-amd64" / "Packages").is_file())
        self.assertTrue((mirror / "debian-security" / "dists" / "trixie-security" / "InRelease").is_file())
        packages = self.plan_packages()
        self.assertGreaterEqual(len(packages), 7)
        for name, version, arch in packages:
            relative = f"pool/main/{name[0]}/{name}/{name}_{version}_{arch}.deb"
            placed = mirror / "debian" / relative
            self.assertTrue(placed.is_file() and not placed.is_symlink(), relative)
            self.assertEqual(sha256(placed.read_bytes()), sha256((served / relative).read_bytes()), relative)
            self.assertGreater(placed.stat().st_nlink, 1, f"{relative} is hard-linked from the cache")
        self.assertIn(f"packages: {len(packages)} fetched, 0 already cached", summary)
        self.assertIn("suites: 3 verified", summary)
        self.assertIn("inputs: 0 fetched, 0 already cached", summary)

    def test_a_second_fetch_reads_no_pool_file(self) -> None:
        cache = self.new_cache()
        plan = self.write_plan(self.plan_text)
        first: list[str] = []
        self.fetch(plan, cache, recording(first))
        self.assertTrue(any(url.endswith(".deb") for url in first))
        second: list[str] = []
        summary = self.fetch(plan, cache, recording(second))
        self.assertEqual([url for url in second if url.endswith(".deb")], [])
        self.assertIn("packages: 0 fetched,", summary)
        self.assertIn(f"{len(self.plan_packages())} already cached", summary)

    def test_a_stale_file_at_a_pool_path_is_replaced(self) -> None:
        cache = self.new_cache()
        plan = self.write_plan(self.plan_text)
        self.fetch(plan, cache)
        pool = fetch.mirror_dir(cache, FIRST_IDS) / "debian" / "pool" / "main" / "l" / "lib-b" / "lib-b_2.0_amd64.deb"
        good = pool.read_bytes()
        pool.unlink()
        pool.write_bytes(b"stale")
        link = fetch.mirror_dir(cache, FIRST_IDS) / "debian" / "pool" / "main" / "d" / "dpkg" / "dpkg_1.0_amd64.deb"
        link.unlink()
        link.symlink_to(pool)
        self.fetch(plan, cache)
        self.assertEqual(pool.read_bytes(), good)
        self.assertTrue(link.is_file() and not link.is_symlink())

    def test_a_tampered_pool_file_is_refused_naming_its_url(self) -> None:
        def tamper(url: str) -> bytes:
            data = remote.read_url(url)
            return data[:-1] + bytes([data[-1] ^ 1]) if url.endswith("lib-b_2.0_amd64.deb") else data

        cache = self.new_cache()
        with self.assertRaises(commands.Failed) as caught:
            self.fetch(self.write_plan(self.plan_text), cache, tamper)
        message = str(caught.exception)
        self.assertIn(f"{self.mirror}/archive/debian/{FIRST_ID}/pool/main/l/lib-b/lib-b_2.0_amd64.deb", message)
        self.assertIn("does not match the signed index", message)
        self.assertFalse((fetch.mirror_dir(cache, FIRST_IDS) / "debian" / "pool").exists())

    def test_a_package_the_snapshot_lacks_is_named(self) -> None:
        document = json.loads(self.plan_text)
        document["images"]["core"]["packages"].extend([["no-such-thing", "9.9", "amd64"], ["lib-b", "3.0", "amd64"]])
        with self.assertRaises(commands.Failed) as caught:
            self.fetch(self.write_plan(json.dumps(document)), self.new_cache())
        lines = str(caught.exception).splitlines()
        self.assertEqual(len(lines), 2, lines)
        self.assertIn("no-such-thing 9.9 (amd64)", lines[0] + lines[1])
        self.assertIn("lib-b 3.0 (amd64)", lines[0] + lines[1])

    def test_the_command_line_prints_the_summary_and_exits_zero(self) -> None:
        cache = self.new_cache()
        out, err = io.StringIO(), io.StringIO()
        arguments = [
            "fetch", str(self.write_plan(self.plan_text)),
            "--mirror", self.mirror, "--keyring", str(self.fixture.keyring), "--cache", str(cache),
        ]  # fmt: skip
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(arguments)
        self.assertEqual((code, err.getvalue()), (0, ""))
        self.assertEqual(len(out.getvalue().splitlines()), 4)

    def test_the_command_line_names_failures_and_exits_one(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        arguments = [
            "fetch", str(self.write_plan('{"schema": 3}')),
            "--mirror", self.mirror, "--keyring", str(self.fixture.keyring), "--cache", str(self.new_cache()),
        ]  # fmt: skip
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(arguments)
        self.assertEqual((code, out.getvalue()), (1, ""))
        self.assertIn("schema", err.getvalue())

    def test_a_schema_1_plan_is_refused_and_the_message_says_how_to_get_a_new_one(self) -> None:
        document = json.loads(self.plan_text)
        document["schema"] = 1
        document["snapshot"] = document.pop("snapshots")["debian"]
        err = io.StringIO()
        arguments = ["fetch", str(self.write_plan(json.dumps(document))), "--cache", str(self.new_cache())]
        with contextlib.redirect_stderr(err):
            code = cli.main(arguments)
        self.assertEqual(code, 1)
        self.assertIn("this plan is schema 1, which names one snapshot for both archives", err.getvalue())
        self.assertIn("make the plan again with `plan`", err.getvalue())

    def test_bundle_dir_without_bundle_is_a_usage_error(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.main(
                ["fetch", str(self.write_plan(self.plan_text)), "--bundle-dir", str(self.new_cache()), "--cache", "c"]
            )
        self.assertEqual(code, 2)
        self.assertIn("--bundle-dir says where --bundle writes", err.getvalue())


class OnlyWhatBuildsTest(FetchCase):
    """`fetch` reads for the images whose state is `build`, and for a child only what it adds to its parent."""

    def with_states(self, **states: str) -> Path:
        document = json.loads(self.plan_text)
        for image, state in states.items():
            document["images"][image]["state"] = state
        return self.write_plan(json.dumps(document))

    def pool_files(self, cache: Path) -> list[str]:
        pool = fetch.mirror_dir(cache, FIRST_IDS) / "debian" / "pool"
        return sorted(path.name for path in pool.rglob("*.deb")) if pool.exists() else []

    def test_a_child_that_builds_on_a_reused_parent_fetches_only_what_it_adds(self) -> None:
        cache = self.new_cache()
        urls: list[str] = []
        summary = self.fetch(
            self.with_states(core="reuse", **{"app-b": "reuse", "app-c": "wait"}), cache, recording(urls)
        )
        self.assertEqual(self.pool_files(cache), ["lib-a_1.0_all.deb", "tool-a_1.0_amd64.deb"])
        self.assertEqual(sorted(url.rsplit("/", 1)[1] for url in urls if url.endswith(".deb")), self.pool_files(cache))
        self.assertIn("images: 1 build, 3 need nothing (reuse or wait)", summary)
        self.assertIn("packages: 2 fetched, 0 already cached (2 in all)", summary)

    def test_a_plan_where_nothing_builds_fetches_nothing_and_says_so(self) -> None:
        cache = self.new_cache()
        urls: list[str] = []
        summary = self.fetch(
            self.with_states(core="reuse", **{"app-a": "wait", "app-b": "reuse", "app-c": "reuse"}),
            cache,
            recording(urls),
        )
        self.assertEqual(urls, [])
        self.assertEqual(summary, "nothing to fetch: no image builds (4 are reused or wait)\n")
        self.assertFalse((cache / "mirror").exists())

    def test_a_chain_that_builds_needs_each_link_only_for_what_it_adds(self) -> None:
        plan = fetch.fetch_plan(planfile.parse_plan(json.loads(self.plan_text)))
        added = {one.image: [name for name, _version, _arch in one.packages] for one in plan.images}
        self.assertEqual(added["core"], ["apt", "base-files", "dpkg", "fixture-essential", "lib-b", "tool-b"])
        self.assertEqual(added["app-a"], ["lib-a", "tool-a"])
        self.assertEqual((added["app-b"], added["app-c"]), ([], []))
        self.assertEqual(plan.skipped, ())

    def test_an_input_of_a_reused_image_is_not_read(self) -> None:
        document = json.loads(self.plan_text)
        document["images"]["app-a"]["inputs"] = {"tool": tool_fields()}
        document["images"]["app-a"]["state"] = "reuse"
        urls: list[str] = []
        self.fetch(self.write_plan(json.dumps(document)), self.new_cache(), recording(urls, {TOOL_URL: TOOL_BYTES}))
        self.assertNotIn(TOOL_URL, urls)


class InputsTest(FetchCase):
    def inputs_plan(self, **entries: dict[str, object]) -> Path:
        document = json.loads(self.plan_text)
        document["images"]["core"]["inputs"] = entries if entries else {"tool": tool_fields()}
        document["images"]["app-b"]["inputs"] = {"tool": tool_fields()}
        return self.write_plan(json.dumps(document))

    def test_a_locked_input_is_stored_by_sha256_and_fetched_once(self) -> None:
        cache = self.new_cache()
        urls: list[str] = []
        summary = self.fetch(self.inputs_plan(), cache, recording(urls, {TOOL_URL: TOOL_BYTES}))
        self.assertEqual(urls.count(TOOL_URL), 1, "shared by two images, read once")
        self.assertIn("inputs: 1 fetched, 0 already cached", summary)
        found = fetch.input_path(cache, tool_fields())
        self.assertEqual(found, archive.cache_path(cache, sha256(TOOL_BYTES)))
        self.assertEqual(found.read_bytes(), TOOL_BYTES)
        again: list[str] = []
        summary = self.fetch(self.inputs_plan(), cache, recording(again, {TOOL_URL: TOOL_BYTES}))
        self.assertNotIn(TOOL_URL, again)
        self.assertIn("inputs: 0 fetched, 1 already cached", summary)

    def test_every_checksum_the_entry_carries_is_verified(self) -> None:
        # a lock may carry sha1 beside its sha256
        both = {"sha512": hashlib.sha512(TOOL_BYTES).hexdigest(), "sha1": hashlib.sha1(TOOL_BYTES).hexdigest()}
        self.fetch(self.inputs_plan(tool=tool_fields(**both)), self.new_cache(), recording([], {TOOL_URL: TOOL_BYTES}))
        for algorithm in both:
            bad = {**both, algorithm: "0" * len(both[algorithm])}
            with self.assertRaises(commands.Failed, msg=algorithm) as caught:
                self.fetch(
                    self.inputs_plan(tool=tool_fields(**bad)), self.new_cache(), recording([], {TOOL_URL: TOOL_BYTES})
                )
            self.assertIn(TOOL_URL, str(caught.exception))
            self.assertIn(algorithm, str(caught.exception))

    def test_a_wrong_checksum_fails_naming_the_url_and_stores_nothing(self) -> None:
        cache = self.new_cache()
        with self.assertRaises(commands.Failed) as caught:
            self.fetch(self.inputs_plan(), cache, recording([], {TOOL_URL: b"something else"}))
        self.assertIn(TOOL_URL, str(caught.exception))
        self.assertIn("does not match the lock's sha256", str(caught.exception))
        self.assertIsNone(archive.cached(cache, sha256(b"something else")))
        self.assertIsNone(archive.cached(cache, sha256(TOOL_BYTES)))

    def test_every_failing_input_is_named(self) -> None:
        plan = self.inputs_plan(tool=tool_fields(), keys={"url": KEY_URL, "sha256": sha256(KEY_BYTES)})
        with self.assertRaises(commands.Failed) as caught:
            self.fetch(plan, self.new_cache(), recording([], {TOOL_URL: b"x", KEY_URL: b"y"}))
        self.assertIn(TOOL_URL, str(caught.exception))
        self.assertIn(KEY_URL, str(caught.exception))

    def test_an_entry_without_a_sha256_points_at_lock_checksums(self) -> None:
        fields = tool_fields()
        del fields["sha256"]
        with self.assertRaisesRegex(commands.Failed, r"images\.core\.inputs\.tool\.sha256.*lock checksums"):
            self.fetch(
                self.inputs_plan(tool={**fields, "sha1": hashlib.sha1(TOOL_BYTES).hexdigest()}), self.new_cache()
            )  # a lock may carry sha1

    def test_only_https_is_read(self) -> None:
        with self.assertRaisesRegex(commands.Failed, r"images\.core\.inputs\.tool\.url must be an https://"):
            self.fetch(self.inputs_plan(tool=tool_fields() | {"url": "file:///etc/passwd"}), self.new_cache())

    def test_an_input_that_was_not_fetched_has_no_path(self) -> None:
        with self.assertRaisesRegex(commands.Failed, "run `fetch` first"):
            fetch.input_path(self.new_cache(), tool_fields())
        with self.assertRaisesRegex(commands.Failed, "needs a sha256"):
            fetch.input_path(self.new_cache(), {"url": TOOL_URL})


class PlanShapeTest(FetchCase):
    def failing(self, edit: Callable[[dict[str, object]], None], pattern: str) -> None:
        document = json.loads(self.plan_text)
        edit(document)
        with self.assertRaisesRegex(commands.Failed, pattern):
            fetch.fetch_plan(planfile.parse_plan(document))

    def test_the_real_plan_is_read(self) -> None:
        parsed = fetch.fetch_plan(planfile.parse_plan(json.loads(self.plan_text)))
        self.assertEqual((parsed.snapshots, parsed.suite, parsed.components), (FIRST_IDS, "trixie", ("main",)))
        self.assertEqual(parsed.architecture, "amd64")
        self.assertIn(("lib-a", "1.0", "all"), parsed.packages)
        self.assertEqual(parsed.inputs, ())

    def test_an_input_of_the_wrong_shape_names_the_field(self) -> None:
        def inputs(**fields: object) -> Callable[[dict[str, object]], None]:
            return lambda d: d["images"]["core"].update(inputs={"x": fields})  # type: ignore[index]  # json

        self.failing(inputs(sha256="0" * 64), r"images\.core\.inputs\.x\.url is missing")
        self.failing(inputs(url=TOOL_URL, sha256="ABC"), r"images\.core\.inputs\.x\.sha256 must be 64")
        self.failing(inputs(url=TOOL_URL, sha256="0" * 64, sha1="0"), r"images\.core\.inputs\.x\.sha1 must be 40")
        self.failing(inputs(url="http://example.com/x", sha256="0" * 64), r"inputs\.x\.url must be an https://")

    def test_a_plan_of_the_wrong_shape_fails_the_command_naming_the_field(self) -> None:
        plan = self.edited_plan("core", "packages", "apt")
        with self.assertRaisesRegex(commands.Failed, r"images\.core\.packages must be a list"):
            self.fetch(plan, self.new_cache())
        with self.assertRaisesRegex(commands.Failed, "not JSON"):
            self.fetch(self.write_plan("{"), self.new_cache())
        with self.assertRaisesRegex(commands.Failed, "schema must be 2"):
            self.fetch(self.write_plan('{"schema": 3}'), self.new_cache())
        with self.assertRaisesRegex(commands.Failed, "no-such-plan.json"):
            self.fetch(self.new_cache() / "no-such-plan.json", self.new_cache())


class PoolFilesTest(unittest.TestCase):
    def index(self, root: Path, dist: str, archive_: str, stanzas: str) -> archive.SuiteIndex:
        path = root / f"{archive_}-{dist}-Packages"
        path.write_text(stanzas)
        return archive.SuiteIndex(
            f"https://example.test/archive/{archive_}/{FIRST_ID}", dist, b"", (("main/binary-amd64/Packages", path),)
        )

    @staticmethod
    def stanza(sha: str, filename: str = "pool/main/a/a/a_1_amd64.deb") -> str:
        return f"Package: a\nVersion: 1\nArchitecture: amd64\nFilename: {filename}\nSize: 10\nSHA256: {sha}\n"

    def test_disagreeing_sha256_is_a_problem_and_agreeing_listings_merge(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            key = [("a", "1", "amd64")]
            main = self.index(root, "trixie", "debian", self.stanza("1" * 64))
            updates = self.index(root, "trixie-updates", "debian", self.stanza("1" * 64))
            security = self.index(root, "trixie-security", "debian-security", self.stanza("1" * 64))
            found, problems = fetch.pool_files([main, updates, security], key)
            self.assertEqual(problems, [])
            self.assertEqual(
                [(where[0], where[2]) for where in found[key[0]].locations],
                [("debian", "pool/main/a/a/a_1_amd64.deb"), ("debian-security", "pool/main/a/a/a_1_amd64.deb")],
            )
            other = self.index(root, "trixie-security", "debian-security", self.stanza("2" * 64))
            _, problems = fetch.pool_files([main, other], key)
            self.assertEqual(len(problems), 1)
            self.assertIn("a 1 (amd64): the indices disagree on its sha256", problems[0])

    def test_unsafe_or_incomplete_stanzas_are_problems(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            index = self.index(Path(name), "trixie", "debian", self.stanza("1" * 64, "../../etc/passwd"))
            found, problems = fetch.pool_files([index], [("a", "1", "amd64")])
            self.assertEqual(found, {})
            self.assertEqual(len(problems), 1, problems)
            self.assertIn("no usable Filename", problems[0])


class PlaceTest(unittest.TestCase):
    def test_copies_when_a_link_is_impossible(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "a").write_bytes(b"data")
            real_link = os.link

            def refuse(*args: object, **kwargs: object) -> None:
                raise OSError(18, "Invalid cross-device link")

            os.link = refuse  # simulates a cache on another device
            try:
                fetch.place(root / "a", root / "deep" / "b")
            finally:
                os.link = real_link
            self.assertEqual((root / "deep" / "b").read_bytes(), b"data")
            self.assertFalse((root / "a").samefile(root / "deep" / "b"))
            fetch.place(root / "a", root / "deep" / "b")
            self.assertEqual(os.listdir(root / "deep"), ["b"])


@unittest.skipUnless(shutil.which("apt-get"), "apt-get is not installed")
class AptReadsTheMirrorTest(FetchCase):
    def test_apt_updates_from_the_mirror_and_downloads_a_package(self) -> None:
        cache = self.new_cache()
        self.fetch(self.write_plan(self.plan_text), cache)
        mirror = fetch.mirror_dir(cache, FIRST_IDS)
        keyring = self.fixture.keyring
        root = Path(tempfile.mkdtemp(dir=self.tmp)) / "apt"
        for directory in (
            "state/lists/partial",
            "cache/archives/partial",
            "etc/sources.list.d",
            "etc/apt.conf.d",
            "etc/preferences.d",
        ):
            (root / directory).mkdir(parents=True)
        (root / "status").write_text("")
        (root / "apt.conf").write_text(resolve.apt_conf(root, "amd64"))
        (root / "sources.list").write_text(
            "".join(
                f"deb [signed-by={keyring}] copy:{mirror / one.archive} {one.dist} main\n"
                for one in resolve.suites("trixie")
            )
        )
        resolve.run_apt(root, "update")
        resolve.run_apt(root, "-y", "--download-only", "install", "--", "tool-a")
        downloaded = sorted(path.name for path in (root / "cache" / "archives").glob("*.deb"))
        self.assertEqual(
            downloaded, ["lib-a_1.0_all.deb", "lib-b_2.0_amd64.deb", "tool-a_1.0_amd64.deb", "tool-b_1.0_amd64.deb"]
        )
        scratch = Path(tempfile.mkdtemp(dir=self.tmp))
        done = subprocess.run(
            ["apt-get", "-q", "download", "dpkg"],
            env=resolve.apt_env(root),
            cwd=scratch,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(os.listdir(scratch), ["dpkg_1.0_amd64.deb"])


if __name__ == "__main__":
    unittest.main()
