"""Signing and checking records (DESIGN 8.3) with a stand-in for cosign: the arguments it is given, the
envelope it leaves, and every refusal that comes before it is asked to do anything."""

import base64
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

from debian_image_factory import cli, commands, publish, published, sign, verify
from tests.support.oci_fixtures import make_image
from tests.test_publish import make_out, provenance_line

VERSION_TEXT: Final = f"GitVersion:    v{sign.COSIGN_VERSION}\nGitCommit:     abc\n"
TYPE: Final = "https://slsa.dev/provenance/v1"
DIGEST: Final = "0" * 64


class FakeCosign:
    """Answers `version`, writes a Sigstore bundle for `attest-blob` and accepts `verify-blob-attestation`
    unless told to refuse; remembers every call."""

    def __init__(self, *, version: str = VERSION_TEXT, refuse: bool = False) -> None:
        self.version, self.refuse = version, refuse
        self.calls: list[list[str]] = []

    def __call__(self, arguments: Sequence[str], env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(arguments))
        command = arguments[1]
        if command == "version":
            return subprocess.CompletedProcess(arguments, 0, self.version, "")
        if command == "attest-blob":
            statement = Path(arguments[arguments.index("--statement") + 1]).read_bytes()
            bundle = {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {"publicKey": {"hint": "h"}},
                "dsseEnvelope": {
                    "payload": base64.b64encode(statement).decode(),
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [{"sig": "c2ln"}],
                },
            }
            Path(arguments[arguments.index("--bundle") + 1]).write_text(json.dumps(bundle), encoding="utf-8")
            return subprocess.CompletedProcess(arguments, 0, "", "")
        if self.refuse:
            return subprocess.CompletedProcess(arguments, 1, "", "Error: no matching signatures\nexit status 1")
        return subprocess.CompletedProcess(arguments, 0, "", "Verified OK")


def line() -> str:
    return provenance_line("a", DIGEST).strip()


def prepared(fake: FakeCosign, mode: str, key: Path | None = None) -> sign.Signer:
    signer = sign.prepare(
        sign.parse_mode(mode.replace("KEY", str(key))), {"PATH": str(fake_path()), "SIGSTORE_ID_TOKEN": "t"}, fake
    )
    assert signer is not None
    return signer


def fake_path() -> Path:
    """A directory with an executable `cosign`: only its presence matters to the fake."""
    folder = Path(tempfile.mkdtemp(prefix="debian-image-factory-fake-cosign-"))
    program = folder / "cosign"
    program.write_text("#!/bin/sh\n")
    program.chmod(0o755)
    return folder


class ArgumentsTest(unittest.TestCase):
    def test_the_modes(self) -> None:
        self.assertEqual(sign.parse_mode("none"), sign.Mode("none"))
        self.assertEqual(sign.parse_mode("keyless"), sign.Mode("keyless"))
        self.assertEqual(sign.parse_mode("key:cosign.key"), sign.Mode("key", "cosign.key"))
        self.assertEqual(sign.parse_mode("key:gcpkms://projects/p"), sign.Mode("key", "gcpkms://projects/p"))
        for text in ("", "sigstore", "key:", "KEYLESS"):
            with self.subTest(text=text), self.assertRaises(sign.UsageError):
                sign.parse_mode(text)

    def test_verify_options_need_a_whole_signer(self) -> None:
        sign.check_verify_options(sign.NO_OPTIONS)
        sign.check_verify_options(sign.VerifyOptions(key="k.pub", require=True))
        sign.check_verify_options(sign.VerifyOptions(identity="i", issuer="u", require=True))
        sign.check_verify_options(sign.VerifyOptions(identity_regexp="i.*", issuer_regexp="u.*"))
        for options in (
            sign.VerifyOptions(key="k", identity="i", issuer="u"),
            sign.VerifyOptions(identity="i"),
            sign.VerifyOptions(issuer="u"),
            sign.VerifyOptions(identity="i", identity_regexp="j", issuer="u"),
            sign.VerifyOptions(identity="i", issuer="u", issuer_regexp="v"),
            sign.VerifyOptions(require=True),
        ):
            with self.subTest(options=options), self.assertRaises(sign.UsageError):
                sign.check_verify_options(options)

    def test_cli_takes_the_options_and_refuses_a_bad_sign(self) -> None:
        parsed = cli.parser().parse_args(["verify", "x", "--require-signature", "--key", "k.pub"])
        self.assertEqual((parsed.require_signature, parsed.key), (True, "k.pub"))
        parsed = cli.parser().parse_args(["publish", "out", "--sign", "key:k"])
        self.assertEqual(parsed.sign, "key:k")
        with tempfile.TemporaryDirectory() as scratch, contextlib.redirect_stderr(io.StringIO()) as said:
            self.assertEqual(cli.main(["publish", scratch, "--to", f"dir://{scratch}/t", "--sign", "pgp"]), 2)
            self.assertEqual(cli.main(["verify", scratch, "--require-signature"]), 2)
        self.assertIn("none, keyless or key:", said.getvalue())
        self.assertIn("--require-signature needs the signer", said.getvalue())


class PrepareTest(unittest.TestCase):
    def test_a_missing_cosign_names_the_pinned_version(self) -> None:
        with (
            tempfile.TemporaryDirectory() as empty,
            self.assertRaisesRegex(sign.SignError, f"cosign {sign.COSIGN_VERSION}"),
        ):
            sign.prepare(sign.Mode("keyless"), {"PATH": empty, "SIGSTORE_ID_TOKEN": "t"}, FakeCosign())

    def test_another_version_is_refused(self) -> None:
        fake = FakeCosign(version="GitVersion:    v2.5.0\n")
        with self.assertRaisesRegex(sign.SignError, f"is cosign 2.5.0.*written for {sign.COSIGN_VERSION}"):
            prepared(fake, "keyless")

    def test_keyless_needs_an_oidc_identity(self) -> None:
        with self.assertRaisesRegex(sign.SignError, "OIDC identity.*id-token: write"):
            sign.prepare(sign.Mode("keyless"), {"PATH": str(fake_path())}, FakeCosign())
        ambient = {"PATH": str(fake_path()), "ACTIONS_ID_TOKEN_REQUEST_URL": "u", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t"}
        self.assertIsNotNone(sign.prepare(sign.Mode("keyless"), ambient, FakeCosign()))
        half = {"PATH": str(fake_path()), "ACTIONS_ID_TOKEN_REQUEST_URL": "u"}
        with self.assertRaises(sign.SignError):
            sign.prepare(sign.Mode("keyless"), half, FakeCosign())

    def test_a_key_file_must_exist_and_a_kms_uri_need_not(self) -> None:
        env = {"PATH": str(fake_path())}
        with self.assertRaisesRegex(sign.SignError, "no such key file"):
            sign.prepare(sign.Mode("key", "/nonexistent/cosign.key"), env, FakeCosign())
        self.assertIsNotNone(sign.prepare(sign.Mode("key", "awskms:///alias/x"), env, FakeCosign()))

    def test_none_needs_nothing(self) -> None:
        self.assertIsNone(sign.prepare(sign.Mode("none"), {}, FakeCosign()))


class SigningTest(unittest.TestCase):
    def test_a_signed_record_differs_only_in_its_signatures(self) -> None:
        fake = FakeCosign()
        signed = sign.sign_line(prepared(fake, "keyless"), line())
        before, after = json.loads(line()), json.loads(signed)
        self.assertEqual(before["signatures"], [])
        self.assertEqual(
            {k: v for k, v in after.items() if k != "signatures"},
            {k: v for k, v in before.items() if k != "signatures"},
        )
        (found,) = after["signatures"]
        self.assertEqual(found["sig"], "c2ln")
        self.assertEqual(sorted(found["bundle"]), ["mediaType", "verificationMaterial"])
        self.assertTrue(sign.is_signed(signed) and not sign.is_signed(line()))
        self.assertEqual(signed, sign.with_signature(line(), found))
        published.parse_envelope(signed)  # still a record every reader takes

    def test_the_statement_is_signed_byte_for_byte(self) -> None:
        fake = FakeCosign()
        sign.sign_line(prepared(fake, "keyless"), line())
        (call,) = [one for one in fake.calls if one[1] == "attest-blob"]
        self.assertEqual(call[2], "--statement")
        self.assertEqual(call[4:], ["--bundle", call[5], "--yes"])
        self.assertNotIn("--key", call)

    def test_a_key_signs_without_a_transparency_log(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            key = Path(scratch) / "cosign.key"
            key.write_text("k")
            fake = FakeCosign()
            sign.sign_line(prepared(fake, "key:KEY", key), line())
        (call,) = [one for one in fake.calls if one[1] == "attest-blob"]
        self.assertEqual(call[call.index("--key") + 1], str(key))
        self.assertIn("--signing-config", call)

    def test_a_signed_line_is_left_alone_and_a_failure_names_cosign(self) -> None:
        signer = prepared(FakeCosign(), "keyless")
        signed = sign.sign_line(signer, line())
        self.assertEqual(sign.sign_line(signer, signed), signed)

        def failing(arguments: Sequence[str], env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
            if arguments[1] == "version":
                return subprocess.CompletedProcess(arguments, 0, VERSION_TEXT, "")
            return subprocess.CompletedProcess(arguments, 1, "", "no token")

        with self.assertRaisesRegex(sign.SignError, "cosign attest-blob failed.*no token"):
            sign.sign_line(prepared(failing, "keyless"), line())  # type: ignore[arg-type]  # a function is a Run

    def test_a_bundle_for_another_payload_is_refused(self) -> None:
        bundle = {
            "mediaType": "m",
            "verificationMaterial": {},
            "dsseEnvelope": {"payload": "other", "payloadType": "t", "signatures": [{"sig": "s"}]},
        }
        with self.assertRaisesRegex(sign.SignError, "another payload"):
            sign.bundle_signature(bundle, "mine")
        with self.assertRaisesRegex(sign.SignError, "without a DSSE envelope"):
            sign.bundle_signature({}, "mine")

    def test_what_a_target_holds_is_not_signed_again(self) -> None:
        fake = FakeCosign()
        signer = prepared(fake, "keyless")
        other = provenance_line("b", "1" * 64).strip()
        added, skipped = sign.to_add(signer, [line(), other], [line()])
        self.assertEqual((len(added), skipped), (1, 1))
        self.assertEqual(sign.payload_of(added[0]), sign.payload_of(other))
        self.assertEqual(sign.to_add(None, [line(), other], [line()]), ([line(), other], 0))


class VerifyingTest(unittest.TestCase):
    def signed(self) -> str:
        return sign.sign_line(prepared(FakeCosign(), "keyless"), line())

    def check(self, lines: list[str], options: sign.VerifyOptions, fake: FakeCosign) -> sign.Report:
        return sign.check_signatures(lines, DIGEST, [TYPE] * len(lines), options, {"PATH": str(fake_path())}, fake)

    def test_a_key_is_checked_without_the_log_and_an_identity_with_it(self) -> None:
        fake = FakeCosign()
        report = self.check([self.signed()], sign.VerifyOptions(key="k.pub"), fake)
        self.assertEqual((report.problems, report.verified, report.unsigned, report.unchecked), ((), 1, 0, 0))
        call = fake.calls[-1]
        self.assertEqual(call[call.index("--key") + 1], "k.pub")
        self.assertIn("--insecure-ignore-tlog", call)
        self.assertEqual(call[call.index("--digest") + 1], DIGEST)
        self.assertEqual(call[call.index("--type") + 1], TYPE)
        fake = FakeCosign()
        self.check([self.signed()], sign.VerifyOptions(identity="me", issuer_regexp="https://.*"), fake)
        call = fake.calls[-1]
        self.assertEqual(call[call.index("--certificate-identity") + 1], "me")
        self.assertEqual(call[call.index("--certificate-oidc-issuer-regexp") + 1], "https://.*")
        self.assertNotIn("--insecure-ignore-tlog", call)

    def test_the_bundle_is_rebuilt_from_the_envelope(self) -> None:
        signed = self.signed()
        (found,) = json.loads(signed)["signatures"]
        bundle = sign.rebuilt_bundle(signed, found)
        assert bundle is not None
        self.assertEqual(bundle["dsseEnvelope"]["payload"], json.loads(signed)["payload"])  # type: ignore[index]  # a dict built just above
        self.assertEqual(bundle["verificationMaterial"], {"publicKey": {"hint": "h"}})
        self.assertIsNone(sign.rebuilt_bundle(signed, {"sig": "x"}))

    def test_unsigned_records_pass_unless_a_signature_is_required(self) -> None:
        fake = FakeCosign()
        self.assertEqual(self.check([line()], sign.NO_OPTIONS, fake).unsigned, 1)
        report = self.check([line(), self.signed()], sign.VerifyOptions(key="k", require=True), fake)
        self.assertEqual(report.problems, ("record 1: not signed, and a signature is required",))
        self.assertEqual(report.verified, 1)

    def test_signatures_with_no_signer_named_are_counted_not_checked(self) -> None:
        fake = FakeCosign()
        report = self.check([self.signed()], sign.NO_OPTIONS, fake)
        self.assertEqual((report.problems, report.verified, report.unchecked), ((), 0, 1))
        self.assertEqual(fake.calls, [])

    def test_a_refused_signature_is_a_problem_with_cosigns_reason(self) -> None:
        report = self.check([self.signed()], sign.VerifyOptions(key="k"), FakeCosign(refuse=True))
        self.assertEqual(report.verified, 0)
        (problem,) = report.problems
        self.assertIn("no signature verifies", problem)
        self.assertIn("exit status 1", problem)

    def test_a_signature_without_a_bundle_cannot_be_checked(self) -> None:
        bare = sign.with_signature(line(), {"sig": "x", "keyid": "k"})
        (problem,) = self.check([bare], sign.VerifyOptions(key="k"), FakeCosign()).problems
        self.assertIn("without a Sigstore bundle", problem)


class CommandsTest(unittest.TestCase):
    def test_publish_signs_a_directory_target_and_verify_reads_it(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            out, target = Path(scratch) / "out", Path(scratch) / "t"
            name, digest = make_out(out)
            key = Path(scratch) / "cosign.key"
            key.write_text("k")
            fake = FakeCosign()
            env = {"PATH": str(fake_path())}
            said = io.StringIO()
            publish.publish_command(out, [f"dir://{target}"], f"key:{key}", said, env=env, run=fake)
            held = (target / published.records_name_for(digest)).read_text(encoding="utf-8").splitlines()
            self.assertTrue(held and all(sign.is_signed(one) for one in held))
            self.assertEqual(
                sorted(p.name for p in target.iterdir()), sorted([name, published.records_name_for(digest)])
            )
            self.assertEqual(
                (out / published.records_name_for(digest)).read_text(encoding="utf-8"),
                provenance_line(name, digest),
                "the build's own records stay unsigned",
            )

    def test_publish_checks_cosign_before_it_writes_anything(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            out, target = Path(scratch) / "out", Path(scratch) / "t"
            make_out(out)
            with self.assertRaisesRegex(commands.Failed, "OIDC identity"):
                publish.publish_command(
                    out, [f"dir://{target}"], "keyless", io.StringIO(), env={"PATH": str(fake_path())}, run=FakeCosign()
                )
            self.assertFalse(target.exists())

    def test_verify_of_a_signed_layout_summarises_its_signatures(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            built = make_image(root / "out")
            records = built.records
            signer = prepared(FakeCosign(), "keyless")
            records.write_text("".join(sign.sign_line(signer, one) + "\n" for one in records.read_text().splitlines()))
            definition = root / "factory.toml"
            definition.write_text("")
            said = io.StringIO()
            env = {"PATH": str(fake_path())}
            options = sign.VerifyOptions(identity="me", issuer="u", require=True)
            self.assertEqual(
                verify.verify_command(
                    str(built.layout), False, None, definition, said, signatures=options, env=env, run=FakeCosign()
                ),
                0,
            )
            self.assertIn("signatures: 4 verified", said.getvalue())
            with self.assertRaisesRegex(commands.Failed, "no signature verifies"):
                verify.verify_command(
                    str(built.layout),
                    False,
                    None,
                    definition,
                    io.StringIO(),
                    signatures=options,
                    env=env,
                    run=FakeCosign(refuse=True),
                )


if __name__ == "__main__":
    unittest.main()
