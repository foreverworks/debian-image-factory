"""`builtin:deb` end to end without a network: plan and fetch against the fixture archive and a vendor repository
signed with a throwaway key (DESIGN 6.4, 16.7).

Every link of the chain fails closed, naming the URL: a signature by another key, a Release of another suite, one
past its Valid-Until, a Packages file that is not the one the Release lists, a stanza whose sha256 is not the
lock's, a keyring that is not the one the lock pins.
"""

import io
import json
import tempfile
from collections.abc import Mapping
from pathlib import Path

import input_lock
from input_lock import JsonValue

from debian_image_factory import archive, commands, fetch, planfile, remote
from tests.support import signing, vendor_repo
from tests.support.definitions import jsonable
from tests.support.fixture_archive import FIRST_ID
from tests.support.vendor_repo import VendorRepo
from tests.test_cli import CliCase

FACTORY = """\
schema = 1

[debian]
suite = "trixie"

[params]
vendor = true

[modules.vendor]
use = "builtin:deb"
enabled_by = "vendor"

[images.core]
kind = "core"
packages = ["tool-b"]

[images.app-a]
kind = "oci"
parent = "core"

[images.app-b]
kind = "oci"
parent = "core"

[images.app-c]
kind = "oci"
parent = "app-b"
packages = ["tool-a"]
"""
VENDOR = "https://packages.example.com/"


class VendorCase(CliCase):
    signer: signing.Signer
    stranger: signing.Signer
    deb: bytes
    repo: VendorRepo

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.signer = signing.make_signer("Vendor <vendor@example.com>")
        cls.stranger = signing.make_signer("Stranger <stranger@example.com>")
        cls.deb = vendor_repo.build_deb()
        cls.repo = vendor_repo.build_repo(cls.signer, cls.deb)

    @classmethod
    def tearDownClass(cls) -> None:
        signing.close(cls.signer)
        signing.close(cls.stranger)
        super().tearDownClass()

    def setUp(self) -> None:
        self.read_urls: list[str] = []

    def vendor_sources(self, served: Mapping[str, bytes], cache: Path | None = None) -> commands.Sources:
        def read(url: str) -> bytes:
            if url.startswith(VENDOR):
                self.read_urls.append(url)
                if url not in served:
                    raise OSError(f"{url}: 404 Not Found")
                return served[url]
            return remote.read_url(url)

        return commands.Sources(
            service=self.mirror, keyring=self.fixture.keyring, cache=cache or self.tmp / "cache", read=read
        )

    def deb_workspace(self, repo: VendorRepo | None = None, *, sha: str | None = None) -> Path:
        root = Path(tempfile.mkdtemp(dir=self.tmp))
        (root / "factory.toml").write_text(FACTORY)
        inputs = vendor_repo.entries(repo or self.repo, ["app-b"], sha=sha)
        (root / "lock.json").write_text(input_lock.dump({"debian_snapshot": FIRST_ID, "inputs": inputs}))
        return root

    def run_plan(
        self, root: Path, served: Mapping[str, bytes] | None = None, *pairs: str
    ) -> dict[str, dict[str, JsonValue]]:
        out = io.StringIO()
        commands.plan_command(
            root / "lock.json",
            root / "factory.toml",
            self.vendor_sources(self.repo.files if served is None else served),
            snapshot_choice=FIRST_ID,
            param_pairs=pairs,
            params_file=None,
            against=(),
            rebuild={},
            previous_path=None,
            out=out,
        )
        (root / "plan.json").write_text(out.getvalue())
        images = jsonable(json.loads(out.getvalue()))["images"]
        assert isinstance(images, dict)
        return {name: jsonable(entry) for name, entry in images.items()}

    def failure(self, repo: VendorRepo, *, sha: str | None = None) -> str:
        with self.assertRaises(commands.Failed) as caught:
            self.run_plan(self.deb_workspace(repo, sha=sha), repo.files)
        return str(caught.exception)


def names(entry: Mapping[str, JsonValue]) -> dict[str, str]:
    packages = entry["packages"]
    assert isinstance(packages, list)
    found: dict[str, str] = {}
    for item in packages:
        assert isinstance(item, list)
        found[str(item[0])] = str(item[1])
    return found


class PlanTest(VendorCase):
    planned: dict[str, dict[str, JsonValue]]
    off: dict[str, dict[str, JsonValue]]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        case = cls()
        case.setUp()
        root = case.deb_workspace()
        cls.planned = case.run_plan(root)
        cls.off = case.run_plan(root, None, "vendor=false")

    def test_the_vendor_package_and_its_dependency_are_in_the_image_s_set(self) -> None:
        found = names(self.planned["app-b"])
        self.assertEqual(found["example-tool"], "2.4.0-1")
        self.assertEqual(found["lib-a"], "1.0", "its Depends resolved from the snapshot in the same transaction")

    def test_a_sibling_does_not_see_it(self) -> None:
        self.assertNotIn("example-tool", names(self.planned["app-a"]))
        self.assertNotIn("lib-a", names(self.planned["app-a"]))

    def test_a_child_resolves_on_top_of_it(self) -> None:
        found = names(self.planned["app-c"])
        self.assertEqual(found["example-tool"], "2.4.0-1")
        self.assertIn("tool-a", found)
        self.assertEqual(self.planned["app-c"]["debs"], {}, "the child installs no .deb of its own")

    def test_the_request_does_not_list_it_and_debs_names_it(self) -> None:
        self.assertEqual(self.planned["app-b"]["request"], [])
        self.assertEqual(
            self.planned["app-b"]["debs"],
            {
                "example-tool": {
                    "package": "example-tool",
                    "registry_url": vendor_repo.REGISTRY_URL,
                    "version": "2.4.0-1",
                }
            },
        )
        self.assertEqual(self.planned["app-b"]["trust"], {"example-tool": {"signed_by": "vendor-keys"}})

    def test_the_plan_reads_back(self) -> None:
        parsed = planfile.parse_image("app-b", self.planned["app-b"])
        self.assertEqual(parsed["debs"]["example-tool"]["package"], "example-tool")

    def test_switched_off_the_entry_leaves_and_the_identity_moves(self) -> None:
        self.assertNotIn("example-tool", names(self.off["app-b"]))
        self.assertEqual((self.off["app-b"]["inputs"], self.off["app-b"]["debs"]), ({}, {}))
        for image in ("app-b", "app-c"):
            self.assertNotEqual(self.off[image]["identity"], self.planned[image]["identity"], image)
        for image in ("core", "app-a"):
            self.assertEqual(self.off[image]["identity"], self.planned[image]["identity"], image)


class ChainTest(VendorCase):
    def test_a_release_without_in_release_is_read_with_its_detached_signature(self) -> None:
        repo = vendor_repo.build_repo(self.signer, self.deb, detached=True)
        plan = self.run_plan(self.deb_workspace(repo), repo.files)
        self.assertIn("example-tool", names(plan["app-b"]))
        self.assertIn(vendor_repo.RELEASE_GPG, self.read_urls)

    def test_a_signature_by_another_key_fails_naming_the_in_release(self) -> None:
        message = self.failure(vendor_repo.build_repo(self.signer, self.deb, signed_by=self.stranger))
        self.assertIn(f"{vendor_repo.IN_RELEASE}: the signature does not verify", message)

    def test_a_release_of_another_suite_fails(self) -> None:
        message = self.failure(vendor_repo.build_repo(self.signer, self.deb, suite="bookworm"))
        self.assertIn(f"{vendor_repo.IN_RELEASE}: the signed Release is for suite 'bookworm'", message)

    def test_an_expired_release_fails(self) -> None:
        message = self.failure(vendor_repo.build_repo(self.signer, self.deb, valid_until=vendor_repo.EXPIRED))
        self.assertIn(f"{vendor_repo.IN_RELEASE}: the signed Release expired", message)

    def test_a_packages_file_the_release_does_not_list_fails(self) -> None:
        message = self.failure(vendor_repo.build_repo(self.signer, self.deb, tamper_packages=True))
        self.assertIn(f"{vendor_repo.PACKAGES}: hashes to", message)

    def test_a_stanza_whose_sha256_is_not_the_lock_s_fails(self) -> None:
        message = self.failure(self.repo, sha="3" * 64)
        self.assertIn(f"{vendor_repo.PACKAGES}: the signed index gives example-tool 2.4.0-1 sha256", message)
        self.assertIn("the lock's example-tool says " + "3" * 64, message)

    def test_a_keyring_that_is_not_the_lock_s_fails(self) -> None:
        served = {**self.repo.files, vendor_repo.KEYRING_URL: self.stranger.keyring}
        with self.assertRaises(commands.Failed) as caught:
            self.run_plan(self.deb_workspace(), served)
        self.assertIn(f"{vendor_repo.KEYRING_URL}: the keyring does not match the lock's sha256", str(caught.exception))

    def test_a_repository_with_nothing_signed_fails(self) -> None:
        served = {url: data for url, data in self.repo.files.items() if url != vendor_repo.IN_RELEASE}
        with self.assertRaises(commands.Failed) as caught:
            self.run_plan(self.deb_workspace(), served)
        self.assertIn(f"{vendor_repo.DISTS}: no InRelease, nor a Release with its Release.gpg", str(caught.exception))


class FetchTest(VendorCase):
    def test_fetch_verifies_the_chain_again_and_names_the_in_release(self) -> None:
        root = self.deb_workspace()
        self.run_plan(root)
        cache = Path(tempfile.mkdtemp(dir=self.tmp))
        loaded = fetch.load_plan(root / "plan.json")
        self.assertNotIn("example-tool", [name for name, _, _ in loaded.packages], "not a snapshot package")
        self.assertIn("lib-a", [name for name, _, _ in loaded.packages])
        self.assertEqual([item.pin.package for item in loaded.apt], ["example-tool"])
        self.read_urls.clear()
        out = io.StringIO()
        self.assertEqual(
            fetch.fetch_command(root / "plan.json", self.vendor_sources(self.repo.files, cache), bundle=False, out=out),
            0,
        )
        self.assertIn(vendor_repo.IN_RELEASE, self.read_urls)
        found = fetch.vouched_by(cache, vendor_repo.sha256(self.deb))
        self.assertEqual([one.uri for one in found], [vendor_repo.IN_RELEASE, vendor_repo.PACKAGES])
        self.assertEqual(found[0].sha256, vendor_repo.sha256(self.repo.files[vendor_repo.IN_RELEASE]))
        self.assertIsNotNone(archive.cached(cache, vendor_repo.sha256(self.deb)))
        self.read_urls.clear()
        fetch.fetch_command(
            root / "plan.json", self.vendor_sources(self.repo.files, cache), bundle=False, out=io.StringIO()
        )
        self.assertEqual(self.read_urls, [], "a second fetch verifies the cached chain again and reads nothing")

    def test_fetch_fails_closed_when_the_repository_changed_since_the_plan(self) -> None:
        root = self.deb_workspace()
        self.run_plan(root)
        cache = Path(tempfile.mkdtemp(dir=self.tmp))
        resigned = vendor_repo.build_repo(self.signer, self.deb, signed_by=self.stranger)
        with self.assertRaises(commands.Failed) as caught:
            fetch.fetch_command(
                root / "plan.json", self.vendor_sources(resigned.files, cache), bundle=False, out=io.StringIO()
            )
        self.assertIn(f"example-tool: {vendor_repo.IN_RELEASE}: the signature does not verify", str(caught.exception))
