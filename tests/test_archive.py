import hashlib
import os
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from debian_image_factory import archive, debian, remote
from tests.support import fixture_archive
from tests.support.fixture_archive import Fixture, base_url

ARCH = "amd64"


def tampering(change: Callable[[bytes], bytes], match: str = "") -> Callable[[str], bytes]:
    """A reader that returns `change(bytes)` for every URL except InRelease, or only InRelease when `match` is set."""

    def read(url: str) -> bytes:
        data = remote.read_url(url)
        return change(data) if url.endswith("InRelease") == bool(match) else data

    return read


def apt_conf(root: Path) -> str:
    """The apt.conf of a scratch apt root: everything lives under `root`, nothing is read from /etc/apt.

    Dir::State::status is an empty file (nothing installed), Dir::Etc::SourceList the sources file,
    SourceParts and the *.d directories are empty or absent so the host's apt config is never read.
    """
    return f"""Dir "{root}";
Dir::State "{root}/state";
Dir::State::Lists "{root}/state/lists";
Dir::State::status "{root}/status";
Dir::Cache "{root}/cache";
Dir::Etc "{root}/etc";
Dir::Etc::SourceList "{root}/sources.list";
Dir::Etc::SourceParts "{root}/etc/sources.list.d";
Dir::Etc::Parts "{root}/etc/apt.conf.d";
Dir::Etc::PreferencesParts "{root}/etc/preferences.d";
Debug::NoLocking "true";
APT::Architecture "{ARCH}";
APT::Architectures "{ARCH}";
Acquire::Check-Valid-Until "false";
"""


def apt_get(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("APT_", "LC_", "LANG"))}
    env["APT_CONFIG"] = str(root / "apt.conf")
    return subprocess.run(["apt-get", *args], env=env, capture_output=True, text=True, check=False)


class ArchiveTest(unittest.TestCase):
    fixture: Fixture
    _tmp: tempfile.TemporaryDirectory[str]
    tmp: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="dif-test-")
        cls.tmp = Path(cls._tmp.name)
        cls.fixture = fixture_archive.build_fixture(cls.tmp / "fixture")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def fetch(
        self,
        archive_name: str = "debian",
        snapshot: int = 0,
        read: Callable[[str], bytes] = remote.read_url,
        cache: Path | None = None,
    ) -> archive.SuiteIndex:
        dist = fixture_archive.ARCHIVES[archive_name]
        return archive.fetch_suite(
            base_url(self.fixture, archive_name, self.fixture.snapshot_ids[snapshot]),
            dist,
            ["main"],
            ARCH,
            self.fixture.keyring,
            cache if cache is not None else Path(tempfile.mkdtemp(dir=self.tmp)),
            read,
        )

    def test_good_path(self) -> None:
        cache = Path(tempfile.mkdtemp(dir=self.tmp))
        index = self.fetch(cache=cache)
        files = dict(index.files)
        self.assertEqual(sorted(files), ["main/binary-amd64/Packages", "main/binary-amd64/Packages.xz"])
        self.assertTrue(index.release.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----"))
        self.assertEqual(index.dist, "trixie")
        for path in files.values():
            self.assertEqual(path, archive.cache_path(cache, hashlib.sha256(path.read_bytes()).hexdigest()))
        stanzas = debian.packages_stanzas(files["main/binary-amd64/Packages"].read_text())
        self.assertEqual({s["Package"] for s in stanzas} >= {"tool-a", "lib-a", "apt", "dpkg"}, True)
        self.assertEqual(debian.essential(stanzas, ARCH), ["base-files", "fixture-essential"])

    def test_second_snapshot_has_one_security_change(self) -> None:
        first = debian.packages_stanzas(
            dict(self.fetch("debian-security", 0).files)["main/binary-amd64/Packages"].read_text()
        )
        second = debian.packages_stanzas(
            dict(self.fetch("debian-security", 1).files)["main/binary-amd64/Packages"].read_text()
        )
        self.assertEqual(first, [])
        self.assertEqual([(s["Package"], s["Version"]) for s in second], [("lib-a", "1.1")])

    def test_tampered_packages_refused(self) -> None:
        read = tampering(lambda data: data[:-1] + bytes([data[-1] ^ 1]))
        with self.assertRaisesRegex(archive.ArchiveError, "does not match Release"):
            self.fetch(read=read)

    def test_truncated_packages_refused(self) -> None:
        with self.assertRaisesRegex(archive.ArchiveError, "does not match Release"):
            self.fetch(read=tampering(lambda data: data[:-4]))

    def test_bad_signature_refused_with_gpgv_message(self) -> None:
        read = tampering(lambda data: data.replace(b"Suite: trixie", b"Suite: sid"), "InRelease")
        with self.assertRaises(archive.ArchiveError) as caught:
            self.fetch(read=read)
        self.assertIn("failed signature verification", str(caught.exception))
        self.assertIn("gpgv:", str(caught.exception))

    def test_wrong_keyring_refused(self) -> None:
        other = Path(tempfile.mkdtemp(dir=self.tmp)) / "empty.gpg"
        other.write_bytes(b"")
        with self.assertRaises(archive.ArchiveError):
            archive.fetch_suite(
                base_url(self.fixture, "debian", self.fixture.snapshot_ids[0]),
                "trixie",
                ["main"],
                ARCH,
                other,
                Path(tempfile.mkdtemp(dir=self.tmp)),
            )

    def test_falls_back_to_gz_then_plain(self) -> None:
        def without(*suffixes: str) -> Callable[[str], bytes]:
            def read(url: str) -> bytes:
                if "/by-hash/" in url or url.endswith(suffixes):
                    raise FileNotFoundError(url)
                return remote.read_url(url)

            return read

        gz = dict(self.fetch(read=without("Packages.xz")).files)
        self.assertEqual(sorted(gz), ["main/binary-amd64/Packages", "main/binary-amd64/Packages.gz"])
        plain = dict(self.fetch(read=without("Packages.xz", "Packages.gz")).files)
        self.assertEqual(sorted(plain), ["main/binary-amd64/Packages"])
        self.assertEqual(gz["main/binary-amd64/Packages"].name, plain["main/binary-amd64/Packages"].name)

    def test_by_hash_is_used(self) -> None:
        urls: list[str] = []

        def record(url: str) -> bytes:
            urls.append(url)
            return remote.read_url(url)

        self.fetch(read=record)
        self.assertEqual(sum("/by-hash/SHA256/" in url for url in urls), 1)
        self.assertFalse(any(url.endswith("Packages.xz") for url in urls))

    def test_missing_index_is_an_error(self) -> None:
        def nothing(url: str) -> bytes:
            if url.endswith("InRelease"):
                return remote.read_url(url)
            raise FileNotFoundError(url)

        with self.assertRaisesRegex(archive.ArchiveError, "no Packages index"):
            self.fetch(read=nothing)

    def test_cache_reuse(self) -> None:
        cache = Path(tempfile.mkdtemp(dir=self.tmp))
        first = self.fetch(cache=cache)
        calls: list[str] = []

        def only_in_release(url: str) -> bytes:
            calls.append(url)
            if not url.endswith("InRelease"):
                raise AssertionError(f"read a second time: {url}")
            return remote.read_url(url)

        second = self.fetch(read=only_in_release, cache=cache)
        self.assertEqual(second, first)
        self.assertEqual(len(calls), 1)

    def test_corrupt_cache_entry_is_refetched(self) -> None:
        cache = Path(tempfile.mkdtemp(dir=self.tmp))
        first = self.fetch(cache=cache)
        compressed = dict(first.files)["main/binary-amd64/Packages.xz"]
        compressed.write_bytes(b"garbage")
        again = self.fetch(cache=cache)
        self.assertEqual(dict(again.files), dict(first.files))
        self.assertNotEqual(compressed.read_bytes(), b"garbage")

    def test_archive_name(self) -> None:
        self.assertEqual(archive.archive_name("https://snapshot.debian.org/archive/debian/20261121T004329Z"), "debian")
        self.assertEqual(
            archive.archive_name("file:///tmp/x/archive/debian-security/20261121T004329Z"), "debian-security"
        )
        with self.assertRaises(archive.ArchiveError):
            archive.archive_name("https://example.com/debian/2026")

    def test_listings(self) -> None:
        import json

        for name in fixture_archive.ARCHIVES:
            listing = json.loads((self.fixture.listings_dir / f"{name}.json").read_text())
            self.assertEqual(listing, {"_comment": "", "result": {name: list(self.fixture.listed_ids)}})

    def test_mirror_layout_and_apt_accepts_it(self) -> None:
        security = self.fetch("debian-security", 1)
        main = self.fetch("debian", 0)
        mirror = archive.lay_out_mirror([main, security], self.tmp / "mirror")
        self.assertEqual(mirror, self.tmp / "mirror")
        self.assertEqual((mirror / "debian/dists/trixie/InRelease").read_bytes(), main.release)
        self.assertTrue((mirror / "debian-security/dists/trixie-security/main/binary-amd64/Packages.xz").is_file())
        self.assertTrue((mirror / "debian/dists/trixie/main/binary-amd64/Packages").is_file())

        root = self.tmp / "apt"
        for sub in (
            "state/lists/partial",
            "cache/archives/partial",
            "etc/sources.list.d",
            "etc/apt.conf.d",
            "etc/preferences.d",
        ):
            (root / sub).mkdir(parents=True)
        (root / "status").write_text("")
        key = f"[signed-by={self.fixture.keyring}]"
        (root / "sources.list").write_text(
            f"deb {key} file:{mirror}/debian trixie main\n"
            f"deb {key} file:{mirror}/debian-security trixie-security main\n"
        )
        (root / "apt.conf").write_text(apt_conf(root))

        update = apt_get(root, "update")
        self.assertEqual(update.returncode, 0, update.stderr)
        self.assertNotIn("W:", update.stderr)
        simulate = apt_get(root, "--simulate", "install", "tool-a")
        self.assertEqual(simulate.returncode, 0, simulate.stderr)
        self.assertNotIn("W:", simulate.stderr)
        inst = [line.split(" (")[0] for line in simulate.stdout.splitlines() if line.startswith("Inst ")]
        self.assertEqual(sorted(inst), ["Inst lib-a", "Inst lib-b", "Inst tool-a", "Inst tool-b"])
        self.assertIn("Inst lib-a (1.1 Fixture:trixie-security [all])", simulate.stdout)

        # a tampered index in the mirror is refused by apt itself
        packages = mirror / "debian/dists/trixie/main/binary-amd64/Packages.xz"
        packages.write_bytes(packages.read_bytes() + b"x")
        for lists in (root / "state/lists").glob("*"):
            if lists.is_file():
                lists.unlink()
        broken = apt_get(root, "update")
        self.assertIn("Hash Sum mismatch", broken.stdout + broken.stderr)
        self.assertNotEqual(broken.returncode, 0)


if __name__ == "__main__":
    unittest.main()
