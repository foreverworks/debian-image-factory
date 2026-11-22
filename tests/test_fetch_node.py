"""`fetch` of an input with `signed_by` and `sums_url`: the vendor's signed checksum list is verified with the keyring.

Node.js's SHASUMS256.txt.asc is the case that matters; the keys here are throwaway ones made on the spot, as the
archive tests do. The real release is in tests/integration/test_node_release.py.
"""

import hashlib
import json
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path

from debian_image_factory import archive, commands, fetch, planfile, records, remote
from debian_image_factory.fetch import LockedInput, Vouched
from tests.support import signing
from tests.test_fetch import FetchCase

BASE = "https://downloads.example.com/dist/v1.2.3"
TARBALL_URL = f"{BASE}/node-v1.2.3-linux-x64.tar.xz"
KEYRING_URL = "https://keys.example.com/release-keys/abc/pubring.kbx"
SUMS_URL = f"{BASE}/SHASUMS256.txt.asc"
SIG_URL = f"{BASE}/SHASUMS256.txt.sig"
TARBALL = b"a pretend release tarball\n"
NAME = "node-v1.2.3-linux-x64.tar.xz"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def listing(name: str = NAME, digest: str | None = None) -> str:
    return f"{'f' * 64}  node-v1.2.3-aix-ppc64.tar.gz\n{digest or sha256(TARBALL)}  {name}\n"


class NodeCase(unittest.TestCase):
    signer: signing.Signer
    stranger: signing.Signer

    @classmethod
    def setUpClass(cls) -> None:
        cls.signer = signing.make_signer("Releaser <release@example.com>")
        cls.stranger = signing.make_signer("Stranger <stranger@example.com>")

    @classmethod
    def tearDownClass(cls) -> None:
        signing.close(cls.signer)
        signing.close(cls.stranger)

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dif-fetch-node-")
        self.addCleanup(self._tmp.cleanup)
        self.cache = Path(self._tmp.name) / "cache"
        self.urls: list[str] = []

    def item(
        self, keyring: bytes | None = None, *, sig: bool = False, checksums: tuple[tuple[str, str], ...] | None = None
    ) -> Vouched:
        keys = self.signer.keyring if keyring is None else keyring
        archive.store(self.cache, keys)  # what download_input leaves in the cache
        entry = LockedInput("node-26", TARBALL_URL, sha256(TARBALL), checksums or (("sha256", sha256(TARBALL)),))
        return Vouched(
            entry,
            LockedInput("node-release-keys", KEYRING_URL, sha256(keys), (("sha256", sha256(keys)),)),
            SUMS_URL,
            SIG_URL if sig else None,
        )

    def sources(self, served: Mapping[str, bytes]) -> commands.Sources:
        def read(url: str) -> bytes:
            self.urls.append(url)
            if url not in served:
                raise OSError(f"{url}: not served here")
            return served[url]

        return commands.Sources(cache=self.cache, read=read)

    def signed(self, text: str | None = None, signer: signing.Signer | None = None) -> bytes:
        return signing.clearsign(signer or self.signer, listing() if text is None else text)


class VerifyTest(NodeCase):
    def test_a_good_signature_and_checksum_are_kept_with_a_note(self) -> None:
        item, asc = self.item(), self.signed()
        self.assertTrue(fetch.check_vouched(item, self.sources({SUMS_URL: asc})))
        self.assertEqual(self.urls, [SUMS_URL])
        self.assertIsNotNone(archive.cached(self.cache, sha256(asc)))
        note = json.loads(fetch.note_path(self.cache, sha256(TARBALL)).read_text())
        self.assertEqual(note, {"list": {"sha256": sha256(asc), "uri": SUMS_URL}})
        self.assertEqual(fetch.vouched_by(self.cache, sha256(TARBALL)), (records.Remote(SUMS_URL, sha256(asc)),))

    def test_a_detached_signature_is_kept_too(self) -> None:
        data = listing().encode()
        signature = signing.detach(self.signer, data)
        item = self.item(sig=True)
        self.assertTrue(fetch.check_vouched(item, self.sources({SUMS_URL: data, SIG_URL: signature})))
        found = fetch.vouched_by(self.cache, sha256(TARBALL))
        self.assertEqual([one.uri for one in found], [SUMS_URL, SIG_URL])
        self.assertEqual([one.sha256 for one in found], [sha256(data), sha256(signature)])
        self.urls.clear()
        self.assertFalse(fetch.check_vouched(item, self.sources({})))
        self.assertEqual(self.urls, [])

    def test_a_second_fetch_reads_nothing_and_verifies_again(self) -> None:
        item, asc = self.item(), self.signed()
        fetch.check_vouched(item, self.sources({SUMS_URL: asc}))
        self.urls.clear()
        self.assertFalse(fetch.check_vouched(item, self.sources({})))
        self.assertEqual(self.urls, [])

    def test_a_cached_copy_that_no_longer_verifies_is_read_again(self) -> None:
        fetch.check_vouched(self.item(), self.sources({SUMS_URL: self.signed()}))
        self.urls.clear()
        rotated = self.item(self.stranger.keyring)  # the lock now names another keyring
        resigned = self.signed(signer=self.stranger)
        self.assertTrue(fetch.check_vouched(rotated, self.sources({SUMS_URL: resigned})))
        self.assertEqual(self.urls, [SUMS_URL])

    def test_no_note_without_the_file(self) -> None:
        self.assertEqual(fetch.vouched_by(self.cache, sha256(TARBALL)), ())
        asc = self.signed()
        fetch.check_vouched(self.item(), self.sources({SUMS_URL: asc}))
        archive.cache_path(self.cache, sha256(asc)).unlink()
        self.assertEqual(fetch.vouched_by(self.cache, sha256(TARBALL)), ())

    def test_a_note_of_the_wrong_shape_is_empty(self) -> None:
        note = fetch.note_path(self.cache, "a" * 64)
        note.parent.mkdir(parents=True)
        for text in ("not json", "[]", '{"list": 3}', '{"list": {"uri": "u", "sha256": "xyz"}}', '{"signature": {}}'):
            note.write_text(text)
            self.assertEqual(fetch.vouched_by(self.cache, "a" * 64), (), text)

    def test_an_armored_keyring_is_accepted(self) -> None:
        item = self.item(signing.armored_keyring(self.signer))
        self.assertTrue(fetch.check_vouched(item, self.sources({SUMS_URL: self.signed()})))

    def test_a_list_that_names_the_file_by_a_relative_path(self) -> None:
        item = self.item()
        asc = self.signed(f"{sha256(TARBALL)}  ./{NAME}\n")
        self.assertTrue(fetch.check_vouched(item, self.sources({SUMS_URL: asc})))

    def test_another_algorithm_the_lock_also_has_is_compared(self) -> None:
        sha512 = hashlib.sha512(TARBALL).hexdigest()
        item = self.item(checksums=(("sha256", sha256(TARBALL)), ("sha512", sha512)))
        self.assertTrue(fetch.check_vouched(item, self.sources({SUMS_URL: self.signed(f"{sha512}  {NAME}\n")})))

    def test_a_second_algorithm_that_disagrees_is_refused(self) -> None:
        sha512 = hashlib.sha512(TARBALL).hexdigest()
        item = self.item(checksums=(("sha256", sha256(TARBALL)), ("sha512", sha512)))
        asc = self.signed(f"{'1' * 128}  {NAME}\n{sha256(TARBALL)}  {NAME}\n")
        with self.assertRaisesRegex(commands.Failed, "disagree: sha512"):
            fetch.check_vouched(item, self.sources({SUMS_URL: asc}))


class RefusalTest(NodeCase):
    def refused(
        self, served: Mapping[str, bytes], pattern: str, item: Vouched | None = None, url: str = SUMS_URL
    ) -> None:
        with self.assertRaisesRegex(commands.Failed, pattern) as caught:
            fetch.check_vouched(item or self.item(), self.sources(served))
        self.assertIn(url, str(caught.exception))
        self.assertEqual(fetch.vouched_by(self.cache, sha256(TARBALL)), (), "nothing is noted for a refusal")

    def test_a_signature_by_another_key(self) -> None:
        self.refused({SUMS_URL: self.signed(signer=self.stranger)}, "signature does not verify")

    def test_a_tampered_list(self) -> None:
        asc = self.signed().decode().replace("f" * 64, "e" * 64).encode()
        self.refused({SUMS_URL: asc}, "signature does not verify")

    def test_a_tampered_line_for_the_file(self) -> None:
        asc = self.signed().decode().replace(sha256(TARBALL), "0" * 64).encode()
        self.refused({SUMS_URL: asc}, "signature does not verify")

    def test_a_list_that_is_not_signed(self) -> None:
        self.refused({SUMS_URL: listing().encode()}, "not a clear-signed message")

    def test_text_beside_the_signed_message_is_refused(self) -> None:
        forged = f"{sha256(TARBALL)}  {NAME}\n".encode() + self.signed(listing("other.tar.xz"))
        self.refused({SUMS_URL: forged}, "not a clear-signed message")

    def test_a_missing_line(self) -> None:
        self.refused({SUMS_URL: self.signed(listing("node-v1.2.3-linux-arm64.tar.xz"))}, f"does not name {NAME}")

    def test_a_line_with_another_checksum(self) -> None:
        self.refused({SUMS_URL: self.signed(listing(digest="d" * 64))}, f"disagree: sha256 {'d' * 64} in the list")

    def test_a_list_with_no_algorithm_the_lock_has(self) -> None:
        item = self.item()
        self.refused(
            {SUMS_URL: self.signed(f"{hashlib.sha512(TARBALL).hexdigest()}  {NAME}\n")}, "nothing to compare", item
        )

    def test_a_file_that_cannot_be_read(self) -> None:
        self.refused({}, "cannot be read")

    def test_a_detached_signature_by_another_key(self) -> None:
        data = listing().encode()
        self.refused(
            {SUMS_URL: data, SIG_URL: signing.detach(self.stranger, data)},
            "signature does not verify",
            self.item(sig=True),
        )

    def test_a_detached_signature_that_is_missing(self) -> None:
        self.refused({SUMS_URL: listing().encode()}, "cannot be read", self.item(sig=True), SIG_URL)

    def test_a_keyring_that_is_not_one(self) -> None:
        self.refused({SUMS_URL: self.signed()}, "signature does not verify", self.item(b"\x00not a keyring"))

    def test_a_keyring_missing_from_the_cache(self) -> None:
        item = self.item()
        archive.cache_path(self.cache, item.keyring.sha256).unlink()
        with self.assertRaisesRegex(commands.Failed, "the keyring is not in the cache"):
            fetch.check_vouched(item, self.sources({SUMS_URL: self.signed()}))


class FetchCommandTest(FetchCase):
    signer: signing.Signer

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.signer = signing.make_signer()

    @classmethod
    def tearDownClass(cls) -> None:
        signing.close(cls.signer)
        super().tearDownClass()

    def node_plan(self, trust: dict[str, dict[str, str]] | None = None) -> Path:
        document = json.loads(self.plan_text)
        document["images"]["core"]["inputs"] = {
            "node-26": {"module": "node", "url": TARBALL_URL, "version": "1.2.3", "sha256": sha256(TARBALL)},
            "node-release-keys": {
                "module": "node", "url": KEYRING_URL, "version": "abc", "sha256": sha256(self.signer.keyring),
            },
        }  # fmt: skip
        document["images"]["core"]["trust"] = (
            {"node-26": {"signed_by": "node-release-keys", "sums_url": SUMS_URL}} if trust is None else trust
        )
        return self.write_plan(json.dumps(document))

    def reader(self, asc: bytes | None) -> Callable[[str], bytes]:
        served = {TARBALL_URL: TARBALL, KEYRING_URL: self.signer.keyring}
        if asc is not None:
            served[SUMS_URL] = asc
        return lambda url: served[url] if url in served else remote.read_url(url)

    def test_the_whole_fetch_verifies_the_release(self) -> None:
        cache = self.new_cache()
        summary = self.fetch(self.node_plan(), cache, self.reader(signing.clearsign(self.signer, listing())))
        self.assertIn("signed checksum lists: 1 fetched, 0 already cached (1 in all)", summary)
        self.assertEqual(len(fetch.vouched_by(cache, sha256(TARBALL))), 1)
        again = self.fetch(self.node_plan(), cache, self.reader(None))
        self.assertIn("signed checksum lists: 0 fetched, 1 already cached (1 in all)", again)

    def test_a_bad_signature_fails_the_fetch_naming_the_url(self) -> None:
        stranger = signing.make_signer("Other <other@example.com>")
        self.addCleanup(signing.close, stranger)
        with self.assertRaisesRegex(commands.Failed, SUMS_URL):
            self.fetch(self.node_plan(), self.new_cache(), self.reader(signing.clearsign(stranger, listing())))

    def test_an_input_without_a_signed_list_is_not_checked(self) -> None:
        summary = self.fetch(self.node_plan({}), self.new_cache(), self.reader(None))
        self.assertNotIn("signed checksum lists", summary)

    def test_a_signer_that_is_not_an_input_is_refused(self) -> None:
        plan = self.node_plan({"node-26": {"signed_by": "ghost", "sums_url": SUMS_URL}})
        with self.assertRaisesRegex(
            commands.Failed, "images.core.trust.node-26: node-26 and its keyring ghost must both be"
        ):
            fetch.fetch_plan(planfile.read_plan(plan))

    def test_a_list_that_is_not_https_is_refused(self) -> None:
        plan = self.node_plan({"node-26": {"signed_by": "node-release-keys", "sums_url": "http://x.example/s"}})
        with self.assertRaisesRegex(commands.Failed, r"trust.node-26.sums_url must be an https://"):
            fetch.fetch_plan(planfile.read_plan(plan))

    def fetched(self) -> tuple[Path, planfile.ImageEntry]:
        """A node plan fetched into a new cache: the cache, and the plan's entry for `core`."""
        cache = self.new_cache()
        plan = self.node_plan()
        self.fetch(plan, cache, self.reader(signing.clearsign(self.signer, listing())))
        return cache, planfile.read_plan(plan)["images"]["core"]

    def reverified(self, cache: Path, entry: planfile.ImageEntry) -> None:
        fetch.reverify_vouched("core", entry, "amd64", cache)

    def test_a_build_verifies_the_signed_list_again_from_the_cache(self) -> None:
        cache, entry = self.fetched()
        self.reverified(cache, entry)  # reads nothing: it has no way to

    def test_a_note_alone_is_not_trusted(self) -> None:
        cache, entry = self.fetched()
        (note,) = fetch.vouched_by(cache, sha256(TARBALL))
        stranger = signing.make_signer("Other <other@example.com>")
        self.addCleanup(signing.close, stranger)
        forged = signing.clearsign(stranger, listing())
        archive.cache_path(cache, note.sha256).write_bytes(forged)  # the cached list is no longer the one noted
        with self.assertRaisesRegex(commands.Failed, f"{SUMS_URL}: `fetch` has not verified the signed list"):
            self.reverified(cache, entry)
        fetch.write_note(cache, sha256(TARBALL), {"list": (SUMS_URL, forged)})  # a note that names the forgery
        with self.assertRaisesRegex(commands.Failed, f"{SUMS_URL}: .*signature does not verify"):
            self.reverified(cache, entry)

    def test_a_list_that_no_longer_agrees_with_the_lock_fails_the_build(self) -> None:
        cache, entry = self.fetched()
        other = signing.clearsign(self.signer, listing(digest="d" * 64))  # signed by the right key, another file
        fetch.write_note(cache, sha256(TARBALL), {"list": (SUMS_URL, other)})
        with self.assertRaisesRegex(commands.Failed, f"{SUMS_URL}: the signed list and the lock disagree"):
            self.reverified(cache, entry)

    def test_a_keyring_that_does_not_hash_to_its_lock_fails_the_build(self) -> None:
        cache, entry = self.fetched()
        archive.cache_path(cache, sha256(self.signer.keyring)).write_bytes(b"other bytes")
        with self.assertRaisesRegex(commands.Failed, "the keyring is not in the cache"):
            self.reverified(cache, entry)

    def test_a_missing_note_or_input_fails_the_build_and_names_fetch(self) -> None:
        cache, entry = self.fetched()
        fetch.note_path(cache, sha256(TARBALL)).unlink()
        with self.assertRaisesRegex(commands.Failed, "`fetch` has not verified the signed list of node-26"):
            self.reverified(cache, entry)
        archive.cache_path(cache, sha256(TARBALL)).unlink()
        with self.assertRaisesRegex(commands.Failed, "run `fetch`"):
            self.reverified(cache, entry)

    def test_an_image_without_signed_lists_has_nothing_to_verify(self) -> None:
        plan = self.node_plan({})
        fetch.reverify_vouched("core", planfile.read_plan(plan)["images"]["core"], "amd64", self.new_cache())

    def test_an_apt_entry_signed_by_a_keyring_is_left_to_the_deb_module(self) -> None:
        plan = fetch.fetch_plan(planfile.read_plan(self.node_plan({"node-26": {"signed_by": "node-release-keys"}})))
        self.assertEqual(plan.vouched, ())


if __name__ == "__main__":
    unittest.main()
