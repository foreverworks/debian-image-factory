"""Signed records with the real cosign (DESIGN 8.3), against the registries and directories the tier uses.

`SigningKeyTest` signs with a key pair made on the spot (`cosign generate-key-pair`, an empty password) and
needs cosign 3.1.4 on PATH, docker and network access for the registry images. `KeylessTest` signs with the
CI's OIDC identity and verifies with the workflow's own: it runs only where `DIF_KEYLESS=1` is set and GitHub
Actions offers an identity token (signing.yml), and its signatures go to the public Rekor log.
"""

import dataclasses
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Final

from debian_image_factory import commands, publish, published, registry, sign, verify
from tests.integration.test_registries import DISTRIBUTION, ZOT, docker, start
from tests.support.definitions import CORE, HEADER, child
from tests.support.oci_fixtures import Built, make_image
from tests.test_publish import make_out

ISSUER: Final = "https://token.actions.githubusercontent.com"
NEEDS_COSIGN: Final = shutil.which("cosign") is not None


def records_of(client: registry.Client, digest: str) -> list[str]:
    envelopes, unread = registry.fetch_envelopes(client, registry.referrers_of(client, digest).attached)
    assert not unread
    return [one.decode("utf-8") for one in envelopes]


class Signed(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.definition = self.root / "factory.toml"
        self.definition.write_text(HEADER + CORE + child("app", "oci", "core"))

    def registry(self, image: str) -> str:
        container, name = start(image)
        self.addCleanup(docker, "rm", "-f", container)
        return name

    def verified(self, ref: str, options: sign.VerifyOptions, env: dict[str, str]) -> str:
        said = io.StringIO()
        self.assertEqual(verify.verify_command(ref, False, None, self.definition, said, signatures=options, env=env), 0)
        return said.getvalue()

    def check_signed_image(
        self, name: str, built: Built, publish_sign: str, good: sign.VerifyOptions, env: dict[str, str]
    ) -> None:
        """Publish `built` signed, publish again (nothing is signed twice), and verify by digest."""
        target = f"oci://{name}/factory/app"
        said = io.StringIO()
        publish.publish_command(built.layout.parent, [target], publish_sign, said, env=env)
        self.assertEqual(said.getvalue(), f"{target}: {built.name} pushed, 4 records added\n")
        again = io.StringIO()
        publish.publish_command(built.layout.parent, [target], publish_sign, again, env=env)
        self.assertIn("4 records are already attached and are not signed again", again.getvalue())
        self.assertIn(f"{built.name} already there, 0 records added", again.getvalue())

        client = registry.connect(published.OciTarget(name, "factory/app"))
        lines = records_of(client, built.digest)
        self.assertEqual(len(lines), 4)
        self.assertTrue(all(sign.is_signed(one) for one in lines))
        ref = f"{target}@sha256:{built.digest}"
        required = dataclasses.replace(good, require=True)
        self.assertIn("signatures: 4 verified", self.verified(ref, required, env))
        self.assertIn("4 signed but not checked", self.verified(ref, sign.NO_OPTIONS, env))


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 (docker and network needed)")
@unittest.skipUnless(NEEDS_COSIGN, f"cosign {sign.COSIGN_VERSION} is not on PATH")
class SigningKeyTest(Signed):
    def setUp(self) -> None:
        super().setUp()
        self.env = {**os.environ, "COSIGN_PASSWORD": ""}
        self.keys = self.root / "keys"
        self.keys.mkdir()
        subprocess.run(["cosign", "generate-key-pair"], cwd=self.keys, env=self.env, check=True, capture_output=True)
        self.private, self.public = str(self.keys / "cosign.key"), str(self.keys / "cosign.pub")

    def test_a_zot_image_is_signed_with_a_key_and_verified_with_its_public_half(self) -> None:
        built = make_image(self.root / "out")
        name = self.registry(ZOT)
        self.check_signed_image(name, built, f"key:{self.private}", sign.VerifyOptions(key=self.public), self.env)

    def test_a_distribution_registry_holds_signed_records_through_the_tag_schema(self) -> None:
        built = make_image(self.root / "out")
        name = self.registry(DISTRIBUTION)
        self.check_signed_image(name, built, f"key:{self.private}", sign.VerifyOptions(key=self.public), self.env)

    def test_a_missing_signature_another_key_and_a_tampered_payload_fail(self) -> None:
        built = make_image(self.root / "out")
        ref = str(built.layout)
        self.assertNotIn("signatures", self.verified(ref, sign.NO_OPTIONS, self.env))  # unsigned still verifies
        right = sign.VerifyOptions(key=self.public, require=True)
        with self.assertRaisesRegex(commands.Failed, "not signed, and a signature is required"):
            self.verified(ref, right, self.env)

        records = built.layout.parent / published.records_name_for(built.digest)
        signer = sign.prepare(sign.parse_mode(f"key:{self.private}"), self.env)
        assert signer is not None
        signed = [sign.sign_line(signer, one) for one in records.read_text(encoding="utf-8").splitlines()]
        records.write_text("".join(one + "\n" for one in signed), encoding="utf-8")
        self.assertIn("signatures: 4 verified", self.verified(ref, right, self.env))

        other = self.root / "other"
        other.mkdir()
        subprocess.run(["cosign", "generate-key-pair"], cwd=other, env=self.env, check=True, capture_output=True)
        with self.assertRaisesRegex(commands.Failed, "no signature verifies"):
            self.verified(ref, sign.VerifyOptions(key=str(other / "cosign.pub")), self.env)

        payload = sign.payload_of(signed[0])
        flipped = payload[:-4] + ("AAAA" if not payload.endswith("AAAA") else "BBBB")
        records.write_text(signed[0].replace(payload, flipped) + "\n", encoding="utf-8")
        with self.assertRaises(commands.Failed):
            self.verified(ref, sign.VerifyOptions(key=self.public), self.env)

    def test_a_signed_dir_target_is_not_signed_twice(self) -> None:
        out = self.root / "files"
        _, digest = make_out(out)
        target = f"dir://{self.root}/published"
        said = [io.StringIO(), io.StringIO()]
        for stream in said:
            publish.publish_command(out, [target], f"key:{self.private}", stream, env=self.env)
        held = (self.root / "published" / published.records_name_for(digest)).read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(held), 1)
        self.assertTrue(sign.is_signed(held[0]))
        self.assertIn("1 records are already there and are not signed again", said[1].getvalue())


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 (docker and network needed)")
@unittest.skipUnless(os.environ.get("DIF_KEYLESS") == "1" and NEEDS_COSIGN, "keyless needs signing.yml's identity")
class KeylessTest(Signed):
    def test_a_zot_image_is_signed_with_the_workflows_identity_and_verified_with_it(self) -> None:
        built = make_image(self.root / "out")
        name = self.registry(ZOT)
        identity = "https://github.com/" + os.environ["GITHUB_WORKFLOW_REF"]
        good = sign.VerifyOptions(identity=identity, issuer=ISSUER)
        self.check_signed_image(name, built, "keyless", good, dict(os.environ))
        wrong = sign.VerifyOptions(identity=identity + "-other", issuer=ISSUER, require=True)
        client = registry.connect(published.OciTarget(name, "factory/app"))
        self.assertTrue(records_of(client, built.digest))
        with self.assertRaisesRegex(commands.Failed, "no signature verifies"):
            self.verified(f"oci://{name}/factory/app@sha256:{built.digest}", wrong, dict(os.environ))


if __name__ == "__main__":
    unittest.main()
