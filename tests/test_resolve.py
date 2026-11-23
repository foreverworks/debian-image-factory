"""resolve against the fixture archive: apt's own solver on a tiny signed archive, no network."""

import tempfile
import unittest
from pathlib import Path

from input_lock import Package

from debian_image_factory import archive, remote, resolve
from debian_image_factory.snapshots import ARCHIVES
from tests.support import fixture_archive
from tests.support.fixture_archive import FIRST_ID, Fixture

ESSENTIAL = ["base-files", "fixture-essential"]


def read_with_updates(url: str) -> bytes:
    """Read `url`, serving the fixture's `trixie` suite where the resolver asks for `trixie-updates`.

    The fixture archive has no -updates suite and the resolver always reads one (DESIGN 2.1), so the main
    suite stands in for it: its signed InRelease is read from the same files under the other name."""
    return remote.read_url(url.replace("/dists/trixie-updates/", "/dists/trixie/"))


def names(packages: tuple[Package, ...]) -> list[str]:
    return sorted(name for name, _, _ in packages)


def version_of(packages: tuple[Package, ...], name: str) -> str:
    return next(version for package, version, _ in packages if package == name)


class ResolveTest(unittest.TestCase):
    fixture: Fixture
    first: resolve.OpenArchive
    second: resolve.OpenArchive
    _tmp: tempfile.TemporaryDirectory[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="dif-resolve-")
        tmp = Path(cls._tmp.name)
        cls.fixture = fixture_archive.build_fixture(tmp / "fixture")
        cls.first = cls.open(tmp, 0)
        cls.second = cls.open(tmp, 1)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    @classmethod
    def open(cls, tmp: Path, which: int) -> resolve.OpenArchive:
        return resolve.open_archive(
            dict.fromkeys(ARCHIVES, cls.fixture.snapshot_ids[which]),
            "trixie",
            ["main"],
            "amd64",
            keyring=cls.fixture.keyring,
            cache=tmp / "cache",
            workdir=tmp / f"work-{which}",
            service=f"file://{cls.fixture.root}",
            read=read_with_updates,
        )


class OpenArchiveTest(ResolveTest):
    def test_the_indices_of_every_suite_are_read(self) -> None:
        keys = set(self.first.stanzas)
        self.assertIn(("lib-a", "1.0", "all"), keys)
        self.assertIn(("tool-a", "1.0", "amd64"), keys)
        self.assertNotIn(("lib-a", "1.1", "all"), keys)

    def test_the_second_snapshot_adds_the_security_upload(self) -> None:
        self.assertIn(("lib-a", "1.0", "all"), self.second.stanzas)
        self.assertIn(("lib-a", "1.1", "all"), self.second.stanzas)
        self.assertEqual(len(self.second.stanzas), len(self.first.stanzas) + 1)

    def test_essential_is_the_suites_own_set(self) -> None:
        self.assertEqual(list(self.first.essential), ESSENTIAL)
        self.assertEqual(list(self.second.essential), ESSENTIAL)

    def test_the_apt_root_is_scratch_and_the_arch_is_kept(self) -> None:
        self.assertEqual(self.first.arch, "amd64")
        self.assertEqual(self.first.keyring, self.fixture.keyring)
        self.assertTrue((self.first.root / "apt.conf").is_file())
        self.assertEqual((self.first.root / "status").read_text(), "")
        sources = (self.first.root / "sources.list").read_text().splitlines()
        self.assertEqual(len(sources), 3)
        self.assertTrue(all(line.startswith("deb [signed-by=") and "file:" in line for line in sources))

    def test_an_unknown_snapshot_cannot_be_opened(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="dif-resolve-") as scratch,
            self.assertRaisesRegex(
                archive.ArchiveError, r"archive/debian/20200101T000000Z/dists/trixie/InRelease: cannot be read"
            ),
        ):
            resolve.open_archive(
                dict.fromkeys(ARCHIVES, "20200101T000000Z"),
                "trixie",
                ["main"],
                "amd64",
                keyring=self.fixture.keyring,
                cache=Path(scratch) / "cache",
                workdir=Path(scratch) / "work",
                service=f"file://{self.fixture.root}",
                read=read_with_updates,
            )


class CoreTest(ResolveTest):
    def test_core_is_the_essential_set_then_apt_and_its_dependencies(self) -> None:
        core = resolve.resolve_core(self.first, [])
        self.assertEqual(names(core), ["apt", "base-files", "dpkg", "fixture-essential"])

    def test_core_adds_the_requested_packages_and_their_dependencies(self) -> None:
        core = resolve.resolve_core(self.first, ["tool-a"])
        self.assertEqual(
            names(core), ["apt", "base-files", "dpkg", "fixture-essential", "lib-a", "lib-b", "tool-a", "tool-b"]
        )
        self.assertEqual(version_of(core, "lib-a"), "1.0")

    def test_the_result_is_sorted_with_versions_and_architectures(self) -> None:
        core = resolve.resolve_core(self.first, ["tool-a"])
        self.assertEqual(list(core), sorted(core))
        self.assertIn(("fixture-essential", "1.0", "all"), core)
        self.assertIn(("lib-b", "2.0", "amd64"), core)

    def test_a_later_snapshot_picks_the_security_version(self) -> None:
        core = resolve.resolve_core(self.second, ["tool-a"])
        self.assertEqual(version_of(core, "lib-a"), "1.1")
        self.assertEqual(version_of(core, "tool-a"), "1.0")

    def test_two_snapshots_differ_only_in_the_package_that_moved(self) -> None:
        one = set(resolve.resolve_core(self.first, ["tool-a"]))
        two = set(resolve.resolve_core(self.second, ["tool-a"]))
        self.assertEqual(one - two, {("lib-a", "1.0", "all")})
        self.assertEqual(two - one, {("lib-a", "1.1", "all")})

    def test_the_same_snapshot_resolves_the_same_set(self) -> None:
        self.assertEqual(resolve.resolve_core(self.first, ["tool-a"]), resolve.resolve_core(self.first, ["tool-a"]))

    def test_an_unknown_package_fails_with_apts_message(self) -> None:
        with self.assertRaises(resolve.ResolveError) as caught:
            resolve.resolve_core(self.first, ["no-such-package"])
        self.assertIn("Unable to locate package no-such-package", str(caught.exception))
        self.assertIn("apt-get --simulate install", str(caught.exception))


class ChildTest(ResolveTest):
    def test_a_child_gets_only_the_new_packages(self) -> None:
        core = resolve.resolve_core(self.first, [])
        kit = resolve.resolve_child(self.first, core, ["tool-a"], "kit")
        self.assertEqual(set(core) - set(kit), set())
        self.assertEqual(names(tuple(set(kit) - set(core))), ["lib-a", "lib-b", "tool-a", "tool-b"])

    def test_a_package_the_parent_has_is_not_installed_again(self) -> None:
        core = resolve.resolve_core(self.first, ["tool-b"])
        kit = resolve.resolve_child(self.first, core, ["tool-a"], "kit")
        self.assertEqual(names(tuple(set(kit) - set(core))), ["lib-a", "tool-a"])

    def test_an_empty_request_changes_nothing(self) -> None:
        core = resolve.resolve_core(self.first, [])
        self.assertEqual(resolve.resolve_child(self.first, core, [], "plain"), core)

    def test_requesting_what_the_parent_has_changes_nothing(self) -> None:
        core = resolve.resolve_core(self.first, ["lib-a"])
        self.assertEqual(resolve.resolve_child(self.first, core, ["lib-a"], "plain"), core)

    def test_a_child_never_upgrades_what_its_parent_installed(self) -> None:
        # core installs lib-a 1.0 at the first snapshot; at the second, trixie-security has 1.1.
        # tool-a only asks for lib-a, which 1.0 satisfies, so the child keeps the parent's version.
        core = resolve.resolve_core(self.first, ["lib-a"])
        kit = resolve.resolve_child(self.second, core, ["tool-a"], "kit")
        self.assertEqual(version_of(kit, "lib-a"), "1.0")
        self.assertIn(("tool-a", "1.0", "amd64"), kit)

    def test_a_child_request_that_would_upgrade_a_parent_package_is_refused(self) -> None:
        # asking for lib-a itself at the second snapshot makes apt pick 1.1 over the parent's 1.0.
        core = resolve.resolve_core(self.first, ["lib-a"])
        with self.assertRaises(resolve.ResolveError) as caught:
            resolve.resolve_child(self.second, core, ["lib-a"], "kit")
        message = str(caught.exception)
        self.assertIn("kit: apt would upgrade lib-a from 1.0 to 1.1, which its parent installed", message)
        self.assertIn("rebuild the parent first", message)

    def test_core_itself_may_take_the_newer_version(self) -> None:
        core = resolve.resolve_core(self.second, ["lib-a"])
        self.assertEqual(version_of(core, "lib-a"), "1.1")

    def test_a_parent_package_missing_from_the_snapshot_is_named(self) -> None:
        with self.assertRaises(resolve.ResolveError) as caught:
            resolve.resolve_child(self.first, [("ghost", "9", "amd64")], [], "kit")
        self.assertIn("ghost 9 (amd64) is not in the snapshots' indices", str(caught.exception))
        self.assertIn(f"debian {FIRST_ID} and debian-security {FIRST_ID}", str(caught.exception))

    def test_each_suite_is_read_at_its_own_archives_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dif-resolve-") as scratch:
            opened = resolve.open_archive(
                {"debian": fixture_archive.FIRST_ID, "debian-security": fixture_archive.SECOND_ID},
                "trixie",
                ["main"],
                "amd64",
                keyring=self.fixture.keyring,
                cache=Path(scratch) / "cache",
                workdir=Path(scratch) / "work",
                service=f"file://{self.fixture.root}",
                read=read_with_updates,
            )
            self.assertIn(("lib-a", "1.1", "all"), opened.stanzas, "the security archive's own, newer snapshot")
            self.assertEqual(len([key for key in opened.stanzas if key[0] == "lib-a"]), 2, "and debian's older one")
            self.assertEqual(
                opened.snapshots, {"debian": fixture_archive.FIRST_ID, "debian-security": fixture_archive.SECOND_ID}
            )

    def test_an_error_names_both_ids(self) -> None:
        with self.assertRaises(resolve.ResolveError) as caught:
            resolve.resolve_core(self.first, ["no-such-package"])
        message = str(caught.exception)
        self.assertIn("core:", message)
        self.assertIn(f"the indices are those of debian {FIRST_ID} and debian-security {FIRST_ID}", message)

    def test_an_unknown_package_fails_with_apts_message(self) -> None:
        core = resolve.resolve_core(self.first, [])
        with self.assertRaises(resolve.ResolveError) as caught:
            resolve.resolve_child(self.first, core, ["no-such-package"], "kit")
        self.assertIn("Unable to locate package no-such-package", str(caught.exception))


class PureHelpersTest(unittest.TestCase):
    def test_suites_cover_main_updates_and_security(self) -> None:
        self.assertEqual(
            resolve.suites("trixie"),
            (
                resolve.Suite("debian", "trixie"),
                resolve.Suite("debian", "trixie-updates"),
                resolve.Suite("debian-security", "trixie-security"),
            ),
        )

    def test_snapshot_base(self) -> None:
        self.assertEqual(
            resolve.snapshot_base("https://mirror.example.com/", "debian", "20261101T000000Z"),
            "https://mirror.example.com/archive/debian/20261101T000000Z",
        )

    def test_parse_simulation_reads_installs_and_upgrades(self) -> None:
        output = (
            "Reading package lists...\n"
            "Inst lib-b (2.0 trixie [amd64])\n"
            "Inst lib-a [1.0] (1.1 trixie-security [all])\n"
            "Conf lib-b (2.0 trixie [amd64])\n"
        )
        self.assertEqual(
            resolve.parse_simulation(output),
            [resolve.Inst("lib-b", "2.0", "amd64", None), resolve.Inst("lib-a", "1.1", "all", "1.0")],
        )

    def test_parse_simulation_reads_two_origins(self) -> None:
        line = "Inst tzdata [2025a-1] (2025b-1 Debian:13.1/stable, Debian-Security:13/stable-security [all])"
        self.assertEqual(resolve.parse_simulation(line), [resolve.Inst("tzdata", "2025b-1", "all", "2025a-1")])

    def test_a_removal_is_refused(self) -> None:
        with self.assertRaisesRegex(resolve.ResolveError, "apt would remove a package: Remv lib-a"):
            resolve.parse_simulation("Remv lib-a [1.0]\n")

    def test_an_inst_line_it_cannot_read_is_refused(self) -> None:
        with self.assertRaisesRegex(resolve.ResolveError, "cannot read apt's line: Inst nonsense"):
            resolve.parse_simulation("Inst nonsense\n")

    def test_status_text_is_written_from_the_stanzas(self) -> None:
        stanza = {
            "Package": "lib-a",
            "Version": "1.0",
            "Architecture": "all",
            "Filename": "pool/x.deb",
            "SHA256": "a" * 64,
            "Size": "5",
        }
        opened = resolve.OpenArchive(Path("/nowhere"), Path("/nowhere"), "amd64", {("lib-a", "1.0", "all"): stanza}, ())
        text = resolve.status_text(opened, [("lib-a", "1.0", "all")])
        self.assertEqual(text, "Package: lib-a\nStatus: install ok installed\nVersion: 1.0\nArchitecture: all\n")

    def test_apt_conf_reads_nothing_from_the_host(self) -> None:
        conf = resolve.apt_conf(Path("/scratch"), "amd64")
        self.assertIn('Dir "/scratch";', conf)
        self.assertIn('Dir::Etc::SourceList "/scratch/sources.list";', conf)
        self.assertIn('APT::Install-Recommends "false";', conf)
        self.assertIn('APT::Sandbox::User "root";', conf)


if __name__ == "__main__":
    unittest.main()
