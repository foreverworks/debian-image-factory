"""`prune` on all three kinds of target (DESIGN 9.1, 9.3, 11): what is kept and what is deleted, the lines it
prints, `--dry-run`, pins, and a registry or a release that refuses a delete. Registries and releases are
the in-process fakes of `tests.support`; no test here reaches a real one."""

import contextlib
import io
import shutil
import tempfile
import unittest
from collections.abc import Callable, Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Final
from unittest import mock

from input_lock.records import TestOutcome

from debian_image_factory import cli, commands, github, incus, oci, prune, publish, published, registry
from tests.support import fake_github, fake_registry
from tests.support.definitions import CORE, HEADER, child
from tests.support.fake_registry import Fake as FakeRegistry
from tests.support.oci_fixtures import make_core_file, make_image
from tests.test_publish_release import make_incus

GOOD: Final[Sequence[tuple[str, TestOutcome]]] = (("package-set", "PASSED"), ("oci-run", "PASSED"))
PENDING: Final[Sequence[tuple[str, TestOutcome]]] = (("package-set", "PASSED"),)
BAD: Final[Sequence[tuple[str, TestOutcome]]] = (("package-set", "PASSED"), ("oci-run", "FAILED"))
DEFINITION: Final = HEADER + CORE + child("app", "oci", "core") + '[checks]\ndefault = ["package-set", "oci-run"]\n'


def identity(n: int) -> str:
    return f"{n:02x}" * 32


def finished(n: int) -> str:
    return f"2026-11-{n:02d}T02:00:00Z"


class PruneCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.definition = self.root / "factory.toml"
        self.definition.write_text(DEFINITION)

    def prune(self, against: Sequence[str], *, pins: Sequence[str] = (), good: int = 5, candidates: int = 1) -> str:
        said = io.StringIO()
        status = prune.prune_command(against, pins, good, candidates, False, self.definition, said)
        self.assertEqual(status, 0)
        return said.getvalue()

    def lines(self, text: str, verb: str) -> list[str]:
        return [line for line in text.splitlines() if f" {verb}, " in line and f"would be {verb}" not in line]


class DirTest(PruneCase):
    def setUp(self) -> None:
        super().setUp()
        self.dir = self.root / "published"
        self.target = f"dir://{self.dir}"

    def core(self, n: int, checks: Sequence[tuple[str, TestOutcome]] = GOOD) -> tuple[str, str, Path]:
        """Core build `n`: the identity and finish time follow the number, the content is its own."""
        built = make_core_file(
            self.dir, identity=identity(n), checks=checks, content=f"core {n}".encode(), finished=finished(n)
        )
        return built.name, built.digest, built.records

    def names(self) -> set[str]:
        return {one.name for one in self.dir.iterdir()}

    def test_the_newest_five_good_builds_and_one_candidate_stay_and_the_rest_goes_with_its_records(self) -> None:
        good = [self.core(n) for n in range(1, 9)]
        failed = self.core(9, BAD)
        late = [self.core(10, PENDING), self.core(11, PENDING)]
        said = self.prune([self.target])
        gone = [*good[:3], failed, late[0]]
        stays = [*good[3:], late[1]]
        self.assertEqual(self.names(), {file for name, _, records in stays for file in (name, records.name)})
        for name, _, records in gone:
            self.assertIn(f"{self.target}: {name} deleted, ", said)
            self.assertFalse(records.exists())
        self.assertEqual(len(self.lines(said, "kept")), 6)
        self.assertEqual(len(self.lines(said, "deleted")), 5)

    def test_every_line_names_the_artifact_and_the_reason(self) -> None:
        name, _, _ = self.core(1, BAD)
        kept, _, _ = self.core(2)
        said = self.prune([self.target])
        self.assertIn(
            f"{self.target}: {name} deleted, a required check failed and its checks have ended", said.splitlines()
        )
        self.assertIn(f"{self.target}: {kept} kept, good build 1 of the newest 5 good builds kept", said.splitlines())

    def test_dry_run_deletes_nothing_and_says_what_it_would(self) -> None:
        for n in range(1, 4):
            self.core(n, BAD)
        before = self.names()
        said = io.StringIO()
        self.assertEqual(prune.prune_command([self.target], [], 5, 1, True, self.definition, said), 0)
        self.assertEqual(self.names(), before)
        self.assertEqual(len([line for line in said.getvalue().splitlines() if " would be deleted, " in line]), 3)
        self.assertEqual(self.lines(said.getvalue(), "deleted"), [])

    def test_a_pinned_artifact_stays_whatever_its_standing(self) -> None:
        old = [self.core(n) for n in range(1, 4)]
        bad = self.core(4, BAD)
        said = self.prune([self.target], pins=[old[0][1], f"sha256:{bad[1].upper()}"], good=1, candidates=0)
        self.assertEqual(
            self.names(), {file for name, _, records in (old[0], bad, old[2]) for file in (name, records.name)}
        )
        self.assertEqual(len(self.lines(said, "kept")), 3)
        self.assertIn("pinned (good)", said)
        self.assertIn("pinned (failed)", said)

    def test_a_pin_that_matches_nothing_is_noted(self) -> None:
        self.core(1)
        said = self.prune([self.target], pins=["ab" * 32])
        self.assertIn(f"pin sha256:{'ab' * 32} matches no artifact in these targets", said)

    def test_a_good_build_is_never_pushed_out_by_failed_ones(self) -> None:
        good = [self.core(n) for n in range(1, 6)]
        for n in range(6, 20):
            self.core(n, BAD)
        self.prune([self.target])
        self.assertEqual(self.names(), {file for name, _, records in good for file in (name, records.name)})

    def test_a_required_check_added_to_the_definition_deletes_none_of_the_good_builds(self) -> None:
        good = [self.core(n) for n in range(1, 6)]
        self.definition.write_text(DEFINITION.replace('"oci-run"]', '"oci-run", "package-scan"]'))
        said = self.prune([self.target])
        self.assertEqual(self.names(), {file for name, _, records in good for file in (name, records.name)})
        self.assertEqual(self.lines(said, "deleted"), [])

    def test_keep_numbers_come_from_the_options(self) -> None:
        for n in range(1, 6):
            self.core(n)
        self.prune([self.target], good=2, candidates=0)
        self.assertEqual(len([name for name in self.names() if name.endswith(".tar.gz")]), 2)

    def test_an_incus_image_goes_with_its_rootfs_and_records(self) -> None:
        self.definition.write_text(DEFINITION + child("incus-base", "incus", "core"))
        old, old_print = make_incus(self.dir, metadata=b"old metadata", rootfs=b"old rootfs")
        new, new_print = make_incus(self.dir, metadata=b"new metadata", rootfs=b"new rootfs")
        # both are candidates (no results): keep the one with the smaller digest, delete the other
        said = self.prune([self.target], candidates=1)
        (gone, stays) = (old, new) if old_print > new_print else (new, old)
        remaining = self.names()
        self.assertEqual(
            remaining,
            {stays.metadata, stays.rootfs, published.records_name_for(min(old_print, new_print))},
        )
        self.assertIn(f"{gone.metadata} deleted, ", said)

    def incus_artifact(self) -> tuple[published.Artifact, incus.Names]:
        names, fingerprint = make_incus(self.dir)
        return published.Artifact("incus-base", "ab" * 32, fingerprint, names.metadata, None), names

    def test_an_incus_image_goes_rootfs_first_then_metadata_then_records(self) -> None:
        artifact, names = self.incus_artifact()
        gone: list[str] = []
        real = Path.unlink

        def record(path: Path, missing_ok: bool = False) -> None:
            gone.append(path.name)
            real(path, missing_ok=missing_ok)

        with mock.patch.object(Path, "unlink", record):
            prune.delete_from_dir(self.dir, artifact, True)
        self.assertEqual(gone, [names.rootfs, names.metadata, published.records_name_for(artifact.digest)])

    @staticmethod
    def refusing(stuck: str) -> Callable[[Path, bool], None]:
        """An `unlink` that refuses the file called `stuck` and does the rest."""
        real = Path.unlink

        def unlink(path: Path, missing_ok: bool = False) -> None:
            if path.name == stuck:
                raise PermissionError(13, "Permission denied")
            real(path, missing_ok=missing_ok)

        return unlink

    def test_a_failed_delete_leaves_the_file_a_listing_finds_and_never_a_lone_rootfs(self) -> None:
        for stuck in ("rootfs", "metadata"):
            with self.subTest(stuck=stuck):
                shutil.rmtree(self.dir, ignore_errors=True)
                artifact, names = self.incus_artifact()
                with (
                    mock.patch.object(Path, "unlink", self.refusing(getattr(names, stuck))),
                    self.assertRaises(PermissionError),
                ):
                    prune.delete_from_dir(self.dir, artifact, True)
                left = self.names()
                self.assertIn(names.metadata, left)
                self.assertIn(published.records_name_for(artifact.digest), left)
                self.assertEqual(names.rootfs in left, stuck == "rootfs")

    def test_records_shared_with_a_kept_artifact_stay(self) -> None:
        name, digest, records = self.core(1)
        twin = published.artifact_name("core", "forky", "amd64", identity(1), digest, "tar.gz")
        (self.dir / twin).write_bytes((self.dir / name).read_bytes())  # the same bytes under another name
        self.prune([self.target], good=1, candidates=0)
        self.assertTrue(records.exists())
        self.assertEqual(len([n for n in self.names() if n.endswith(".tar.gz")]), 1)
        self.prune([self.target], good=0, candidates=0)
        self.assertEqual(self.names(), set())

    def test_files_that_do_not_count_are_listed_and_left_alone(self) -> None:
        name, _, records = self.core(1)
        orphan, _, orphan_records = self.core(2)
        orphan_records.unlink()
        (self.dir / "notes.txt").write_text("keep me")
        said = self.prune([self.target], good=0, candidates=0)
        self.assertIn(f"{self.target}: {orphan} ignored, no records file {orphan_records.name} beside it", said)
        self.assertEqual(self.names(), {orphan, "notes.txt"})
        self.assertFalse(records.exists() or (self.dir / name).exists())

    def test_an_image_the_definition_does_not_name_is_kept(self) -> None:
        self.definition.write_text(HEADER + CORE + '[checks]\ndefault = ["package-set", "oci-run"]\n')
        built = make_image(self.root / "unused")
        del built
        name, _, _ = self.core(1, BAD)
        self.prune([self.target])  # core is named: failed, deleted
        self.assertNotIn(name, self.names())
        self.definition.write_text(HEADER + '[images.base]\nkind = "core"\n')
        name2, _, _ = self.core(2, BAD)
        said = self.prune([self.target])
        self.assertIn(name2, self.names())
        self.assertIn("core is not in the definition, so it stays", said)

    def test_a_directory_that_is_not_there_holds_nothing(self) -> None:
        self.assertEqual(self.prune([self.target]), "")

    def test_the_required_checks_come_from_the_definition(self) -> None:
        self.core(1, PENDING)
        self.core(2, PENDING)
        self.definition.write_text(DEFINITION.replace('["package-set", "oci-run"]', '["package-set"]'))
        self.prune([self.target], good=1, candidates=0)
        self.assertEqual(len([n for n in self.names() if n.endswith(".tar.gz")]), 1)


class CommandLineTest(PruneCase):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["prune", "--definition", str(self.definition), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_a_run_exits_0_and_prints_a_line_per_artifact(self) -> None:
        directory = self.root / "d"
        make_core_file(directory, identity=identity(1), checks=BAD, content=b"a", finished=finished(1))
        code, out, err = self.run_cli("--against", f"dir://{directory}", "--dry-run")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("would be deleted", out)
        self.assertEqual(len(list(directory.iterdir())), 2)

    def test_a_bad_pin_a_bad_target_and_a_negative_number_are_usage_errors_exit_2(self) -> None:
        for argv in (
            ["--against", f"dir://{self.root}", "--pin", "abc"],
            ["--against", "ftp://x"],
            ["--against", f"dir://{self.root}", "--keep-good", "-1"],
        ):
            with self.subTest(argv=argv):
                code, _, err = self.run_cli(*argv)
                self.assertEqual(code, 2, err)

    def test_without_a_target_it_is_a_usage_error(self) -> None:
        with self.assertRaises(SystemExit) as caught, contextlib.redirect_stderr(io.StringIO()):
            cli.main(["prune"])
        self.assertEqual(caught.exception.code, 2)

    def test_a_definition_that_cannot_be_read_is_exit_1(self) -> None:
        self.definition.unlink()
        code, _, err = self.run_cli("--against", f"dir://{self.root}")
        self.assertEqual(code, 1)
        self.assertIn("factory.toml", err)

    def test_a_file_that_cannot_be_deleted_is_reported_and_the_others_still_go(self) -> None:
        directory = self.root / "d"
        stuck = make_core_file(directory, identity=identity(1), checks=BAD, content=b"a", finished=finished(1))
        free = make_core_file(directory, identity=identity(2), checks=BAD, content=b"b", finished=finished(2))
        directory.chmod(0o555)
        self.addCleanup(directory.chmod, 0o755)
        if (directory / "probe").parent.stat().st_mode & 0o200 == 0:
            try:
                (directory / "probe").write_text("x")
            except PermissionError:
                pass
            else:  # running as root: a read-only directory stops nothing
                self.skipTest("the directory can be written to anyway")
        code, out, err = self.run_cli("--against", f"dir://{directory}")
        self.assertEqual(code, 1)
        self.assertIn(f"{stuck.name}: the delete failed", err)
        self.assertIn(f"{free.name}: the delete failed", err)
        self.assertIn("delete failed", out)


class ReleaseTest(PruneCase):
    def setUp(self) -> None:
        super().setUp()
        self.fake = fake_github.Fake()
        stack = ExitStack()
        self.addCleanup(stack.close)
        api = stack.enter_context(fake_github.running(self.fake))
        stack.enter_context(fake_github.environment(api))
        self.address = f"github-release://{fake_github.OWNER}/{fake_github.REPO}@v1"

    def put(self, n: int, checks: Sequence[tuple[str, TestOutcome]] = GOOD) -> tuple[str, str]:
        out = self.root / f"out-{n}"
        built = make_core_file(
            out, identity=identity(n), checks=checks, content=f"core {n}".encode(), finished=finished(n)
        )
        self.assertEqual(publish.publish_command(out, [self.address], "none", io.StringIO()), 0)
        return built.name, built.records.name

    def assets(self) -> set[str]:
        return set(self.fake.assets("v1"))

    def test_the_assets_of_the_artifacts_beyond_the_limit_are_deleted_with_their_records(self) -> None:
        puts = [self.put(n) for n in range(1, 5)]
        self.put(5, BAD)
        said = self.prune([self.address], good=2, candidates=0)
        self.assertEqual(self.assets(), {file for pair in puts[2:] for file in pair})
        self.assertEqual(len(self.lines(said, "deleted")), 3)
        self.assertEqual(len(self.lines(said, "kept")), 2)

    def test_dry_run_sends_no_delete(self) -> None:
        self.put(1, BAD)
        said = io.StringIO()
        self.assertEqual(prune.prune_command([self.address], [], 5, 1, True, self.definition, said), 0)
        self.assertEqual([line for line in self.fake.log if line.startswith("DELETE")], [])
        self.assertIn("would be deleted", said.getvalue())

    def test_a_pinned_digest_stays(self) -> None:
        name, records = self.put(1, BAD)
        digest = records.removesuffix(".intoto.jsonl")
        self.prune([self.address], pins=[digest])
        self.assertEqual(self.assets(), {name, records})

    def test_an_unfinished_upload_is_listed_as_ignored_and_not_touched(self) -> None:
        self.put(1)
        partial = published.partial_name("core-trixie-amd64-" + identity(9)[:16] + "-" + "0" * 12 + ".tar.gz", "ab" * 8)
        self.fake.releases["v1"].assets.append(fake_github.Stored(fake_github.new_id(self.fake), partial, b"half"))
        said = self.prune([self.address], good=0, candidates=0)
        self.assertIn(f"{self.address}: {partial} ignored, an unfinished upload", said)
        self.assertEqual(self.assets(), {partial})

    def test_a_tag_without_a_release_holds_nothing(self) -> None:
        self.assertEqual(self.prune([self.address]), "")

    def test_a_refused_delete_is_reported_and_exits_1(self) -> None:
        self.put(1, BAD)
        self.put(2, BAD)
        self.fake.fail_once.extend(["DELETE /repos"] * 4)  # one asset's delete fails on every try
        said = io.StringIO()
        with self.assertRaises(commands.Failed) as caught:
            prune.prune_command([self.address], [], 5, 1, False, self.definition, said)
        self.assertIn("the delete failed", str(caught.exception))
        self.assertIn("HTTP 503", str(caught.exception))
        self.assertNotIn(fake_github.TOKEN, str(caught.exception))
        self.assertEqual(len(self.lines(said.getvalue(), "deleted")), 1)  # the second artifact still went


class ReleaseOrderTest(unittest.TestCase):
    def test_an_incus_image_goes_rootfs_first_then_metadata_then_records(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            names, fingerprint = make_incus(Path(raw))
        artifact = published.Artifact("incus-base", "ab" * 32, fingerprint, names.metadata, None)
        records = published.records_name_for(fingerprint)
        held: dict[str, github.Asset] = {
            name: {"id": number, "name": name, "size": 1, "digest": None}
            for number, name in enumerate((names.metadata, names.rootfs, records))
        }
        gone: list[str] = []
        with mock.patch.object(github, "delete_asset", lambda client, asset: gone.append(asset["name"])):
            prune.delete_from_release(mock.sentinel.client, held, artifact, True)
        self.assertEqual(gone, [names.rootfs, names.metadata, records])
        self.assertEqual(held, {})


class RegistryCase(PruneCase):
    def put(self, name: str, n: int, checks: Sequence[tuple[str, TestOutcome]] = GOOD) -> str:
        """Publish image `n` (own content, identity and finish time) to the registry `name`; its manifest digest."""
        out = self.root / f"out-{name.rpartition(':')[2]}-{n}"
        built = make_image(
            out, identity=identity(n), content=f"image {n}".encode(), checks=checks, finished=finished(n)
        )
        self.assertEqual(publish.publish_command(out, [f"oci://{name}/team/app"], "none", io.StringIO()), 0)
        return built.digest


class RegistryTest(RegistryCase):
    def modes(self) -> list[tuple[str, FakeRegistry]]:
        return [
            ("api", FakeRegistry()),
            ("tag", FakeRegistry(referrers_api=False, subject_header=False)),
            ("paged", FakeRegistry(page_size=1, tag_page_size=2)),
        ]

    def test_a_deleted_image_takes_its_tag_and_every_record_with_it(self) -> None:
        for mode, fake in self.modes():
            with self.subTest(mode), fake_registry.running(fake) as name:
                digests = [self.put(name, n) for n in range(1, 5)]
                bad = self.put(name, 5, BAD)
                said = self.prune([f"oci://{name}/team/app"], good=2, candidates=0)
                for digest in [*digests[:2], bad]:
                    self.assertNotIn(f"sha256:{digest}", fake.manifests)
                    self.assertEqual(fake_registry.referrers_of(fake, f"sha256:{digest}"), [])
                    self.assertNotIn(oci.referrers_tag(digest), fake.tags)
                for digest in digests[2:]:
                    self.assertIn(f"sha256:{digest}", fake.manifests)
                    self.assertEqual(len(fake_registry.referrers_of(fake, f"sha256:{digest}")), 4)
                self.assertEqual(
                    sorted(fake.tags),
                    sorted(
                        [oci.identity_tag(identity(3)), oci.identity_tag(identity(4))]
                        + ([oci.referrers_tag(d) for d in digests[2:]] if mode == "tag" else [])
                    ),
                )
                self.assertEqual(len(self.lines(said, "deleted")), 3)
                self.assertIn(f"oci://{name}/team/app@sha256:{digests[0]} deleted, ", said)

    def test_dry_run_sends_no_delete(self) -> None:
        fake = FakeRegistry()
        with fake_registry.running(fake) as name:
            self.put(name, 1, BAD)
            before = (dict(fake.manifests), dict(fake.tags))
            said = io.StringIO()
            self.assertEqual(prune.prune_command([f"oci://{name}/team/app"], [], 5, 1, True, self.definition, said), 0)
            self.assertEqual((fake.manifests, fake.tags), before)
            self.assertEqual([line for line in fake.log if line.startswith("DELETE")], [])
            self.assertIn("would be deleted", said.getvalue())

    def test_a_pinned_manifest_stays_with_its_tag_and_records(self) -> None:
        fake = FakeRegistry()
        with fake_registry.running(fake) as name:
            digest = self.put(name, 1, BAD)
            self.prune([f"oci://{name}/team/app"], pins=[f"sha256:{digest}"])
            self.assertIn(f"sha256:{digest}", fake.manifests)
            self.assertEqual(len(fake_registry.referrers_of(fake, f"sha256:{digest}")), 4)

    def test_a_registry_that_refuses_delete_is_reported_per_artifact_and_nothing_is_touched(self) -> None:
        fake = FakeRegistry(delete_enabled=False)
        with fake_registry.running(fake) as name:
            first, second = self.put(name, 1, BAD), self.put(name, 2, BAD)
            before = (dict(fake.manifests), dict(fake.tags))
            said = io.StringIO()
            with self.assertRaises(commands.Failed) as caught:
                prune.prune_command([f"oci://{name}/team/app"], [], 5, 1, False, self.definition, said)
            for digest in (first, second):
                self.assertIn(f"@sha256:{digest}: the delete failed", str(caught.exception))
            self.assertIn("HTTP 405", str(caught.exception))
            self.assertIn("UNSUPPORTED", str(caught.exception))
            self.assertEqual((fake.manifests, fake.tags), before)
            self.assertEqual(len(self.lines(said.getvalue(), "delete failed")), 2)

    def test_a_tag_the_registry_kept_and_that_answers_404_is_deleted_too(self) -> None:
        fake = FakeRegistry(keep_tags_on_delete=True)
        with fake_registry.running(fake) as name:
            digest = self.put(name, 1, BAD)
            self.prune([f"oci://{name}/team/app"])
            self.assertNotIn(f"sha256:{digest}", fake.manifests)
            self.assertNotIn(oci.identity_tag(identity(1)), fake.tags)  # it would never be listed again

    def test_a_tag_that_names_another_manifest_stays(self) -> None:
        fake = FakeRegistry()
        with fake_registry.running(fake) as name:
            old = self.put(name, 1, BAD)
            newer = self.put(name, 2, BAD)
            fake.tags[oci.identity_tag(identity(1))] = f"sha256:{newer}"  # a rebuild moved the tag
            client = registry.connect(published.OciTarget(name, "team/app"))
            artifact = published.Artifact("app", identity(1), old, "app", None)
            prune.delete_from_registry(client, artifact)
            self.assertNotIn(f"sha256:{old}", fake.manifests)
            self.assertEqual(fake.tags[oci.identity_tag(identity(1))], f"sha256:{newer}")

    def test_a_registry_that_has_nothing_tagged_holds_nothing(self) -> None:
        with fake_registry.running(FakeRegistry()) as name:
            self.assertEqual(self.prune([f"oci://{name}/team/app"]), "")

    def test_other_tags_are_not_listed_and_are_left_alone(self) -> None:
        fake = FakeRegistry()
        with fake_registry.running(fake) as name:
            digest = self.put(name, 1, BAD)
            fake.tags["stable"] = f"sha256:{digest}"
            self.prune([f"oci://{name}/team/app"])
            self.assertNotIn(f"sha256:{digest}", fake.manifests)
            self.assertNotIn("stable", fake.tags)  # the registry drops tags of a deleted manifest

    def test_the_client_reads_tags_deletes_and_refuses_as_documented(self) -> None:
        fake = FakeRegistry()
        with fake_registry.running(fake) as name:
            digest = self.put(name, 1)
            client = registry.connect(published.OciTarget(name, "team/app"))
            self.assertIn(oci.identity_tag(identity(1)), registry.list_tags(client))
            self.assertTrue(registry.delete_reference(client, f"sha256:{digest}"))
            self.assertFalse(registry.delete_reference(client, f"sha256:{digest}"))
            self.assertFalse(registry.delete_reference(client, "no-such-tag"))
            fake.delete_enabled = False
            with self.assertRaisesRegex(registry.RegistryError, "HTTP 405"):
                registry.delete_reference(client, f"sha256:{'ab' * 32}")


if __name__ == "__main__":
    unittest.main()
