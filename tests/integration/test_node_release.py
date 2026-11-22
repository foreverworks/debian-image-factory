"""The real Node.js release: its signed SHASUMS256.txt.asc verified with the real release keyring.

Reads nodejs.org and raw.githubusercontent.com, so it runs only with DIF_INTEGRATION=1. The tarball
itself is not downloaded: fetch checks its sha256 against the lock, this checks the lock against Node's
own signed checksums, with the node-26 and node-release-keys entries of examples/lock.json (a keybox,
which gpgv reads) and input-lock's gpgv.
"""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

import input_lock

from debian_image_factory import archive, commands, fetch, plan, remote
from tests.support.definitions import example_lock

LOCK = example_lock()
NODE = LOCK["inputs"]["node-26"]
KEYS = LOCK["inputs"]["node-release-keys"]


def locked(name: str, entry: input_lock.Entry) -> fetch.LockedInput:
    sha256 = entry["sha256"]
    assert isinstance(sha256, str)
    return fetch.LockedInput(name, input_lock.render_url(entry), sha256, (("sha256", sha256),))


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to run integration tests")
class RealReleaseTest(unittest.TestCase):
    cache: Path
    _tmp: tempfile.TemporaryDirectory[str]
    item: fetch.Vouched

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="dif-node-release-")
        cls.cache = Path(cls._tmp.name)
        keyring = locked("node-release-keys", KEYS)
        data = remote.read_url(keyring.url)
        assert hashlib.sha256(data).hexdigest() == keyring.sha256, "the example lock's keyring checksum is stale"
        archive.store(cls.cache, data)
        trust = plan.trust_of(NODE)
        assert trust["signed_by"] == "node-release-keys"
        cls.item = fetch.Vouched(locked("node-26", NODE), keyring, str(trust["sums_url"]), None)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_the_example_locks_tarball_checksum_is_the_one_node_signed(self) -> None:
        sources = commands.Sources(cache=self.cache)
        self.assertTrue(fetch.check_vouched(self.item, sources))
        found = fetch.vouched_by(self.cache, self.item.entry.sha256)
        self.assertEqual([one.uri for one in found], ["https://nodejs.org/dist/v26.13.1/SHASUMS256.txt.asc"])
        signed = archive.cached(self.cache, found[0].sha256)
        assert signed is not None
        self.assertIn(b"-----BEGIN PGP SIGNED MESSAGE-----", signed.read_bytes())
        self.assertFalse(fetch.check_vouched(self.item, sources), "the second time it is read from the cache")

    def test_a_different_checksum_is_refused(self) -> None:
        wrong = fetch.Vouched(
            fetch.LockedInput("node-26", self.item.entry.url, "0" * 64, (("sha256", "0" * 64),)),
            self.item.keyring,
            self.item.sums_url,
            None,
        )
        with self.assertRaisesRegex(commands.Failed, "disagree: sha256 " + self.item.entry.sha256):
            fetch.check_vouched(wrong, commands.Sources(cache=self.cache))

    def test_another_keyring_does_not_verify_it(self) -> None:
        junk = b"\x99\x00\x00"
        archive.store(self.cache, junk)
        other = fetch.Vouched(
            self.item.entry,
            fetch.LockedInput(
                "junk",
                self.item.keyring.url,
                hashlib.sha256(junk).hexdigest(),
                (("sha256", hashlib.sha256(junk).hexdigest()),),
            ),
            self.item.sums_url,
            None,
        )
        with self.assertRaisesRegex(commands.Failed, "signature does not verify"):
            fetch.check_vouched(other, commands.Sources(cache=self.cache))


if __name__ == "__main__":
    unittest.main()
