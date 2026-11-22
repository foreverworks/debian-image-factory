"""Signing and checking records (DESIGN 8.3), with cosign.

A record is a DSSE envelope of an in-toto statement. Signing leaves the payload and the payload type as they
are and fills `signatures`: `cosign attest-blob --statement` signs the statement's exact bytes as a DSSE
payload and writes a Sigstore bundle, and the envelope keeps that bundle's DSSE signature (`sig`) with the
bundle's `mediaType` and `verificationMaterial` beside it (`bundle`): the certificate and the transparency log
entry of a keyless signature, the key's hint for a key. `verify` rebuilds the bundle from the envelope and
gives it to `cosign verify-blob-attestation`, so the same envelope is checked by cosign's own rules.

The factory holds no key. `keyless` signs with the CI's OIDC identity (Fulcio and Rekor), `key:REF` with a key
file or KMS URI of the caller, whose signatures are never sent to a transparency log. cosign is a program found
on PATH at exactly `COSIGN_VERSION`; everything else here is pure, and the one effect (running cosign) is a
parameter, so tests can stand in for it.
"""

import base64
import binascii
import json
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

COSIGN_VERSION: Final = "3.1.4"
"""The cosign release signing and verifying are written for."""

COSIGN_TIMEOUT: Final = 300
"""Seconds one cosign call may take (a keyless signature waits for Fulcio and Rekor)."""

EMPTY_SIGNING_CONFIG: Final = (
    '{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json","rekorTlogConfig":{},"tsaConfig":{}}'
)
"""A signing config without any service: a key's signature then goes into the bundle and nowhere else."""

TOKEN_VARIABLES: Final = ("SIGSTORE_ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL")

type Run = Callable[[Sequence[str], Mapping[str, str]], subprocess.CompletedProcess[str]]
"""Runs a program with an environment and captures its text output; never raises for a failing exit."""


class SignError(Exception):
    """A signing or checking step that cannot go on: the message says why and what to do."""


class UsageError(SignError):
    """A command line that asks for something that does not exist."""


@dataclass(frozen=True, slots=True)
class Mode:
    """What `--sign` asks for: nothing, the CI's identity, or a key."""

    kind: Literal["none", "keyless", "key"]
    key: str = ""


@dataclass(frozen=True, slots=True)
class Signer:
    """A mode that signs, with the cosign it uses and the environment it runs in."""

    mode: Mode
    cosign: str
    env: Mapping[str, str]
    run: Run


@dataclass(frozen=True, slots=True)
class VerifyOptions:
    """Who a record must be signed by: a key, or the certificate identity and OIDC issuer of a keyless
    signature (exact or by regular expression, as cosign takes them)."""

    key: str = ""
    identity: str = ""
    identity_regexp: str = ""
    issuer: str = ""
    issuer_regexp: str = ""
    require: bool = False

    def names_signer(self) -> bool:
        return bool(self.key or self.identity or self.identity_regexp or self.issuer or self.issuer_regexp)


NO_OPTIONS: Final = VerifyOptions()
"""No signer named and no signature required: unsigned records pass, signed ones are counted."""


@dataclass(frozen=True, slots=True)
class Report:
    """What checking the signatures of a records file found."""

    problems: tuple[str, ...]
    verified: int
    unsigned: int
    unchecked: int


def run_process(arguments: Sequence[str], env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    """The real `Run`: the program with exactly `env`, output captured, a timeout."""
    try:
        return subprocess.run(
            list(arguments), capture_output=True, text=True, timeout=COSIGN_TIMEOUT, check=False, env=dict(env)
        )
    except subprocess.TimeoutExpired:
        raise SignError(f"{arguments[0]} {arguments[1]} did not finish in {COSIGN_TIMEOUT} seconds") from None
    except OSError as error:
        raise SignError(f"cannot run {arguments[0]}: {error.strerror or error}") from None


# ---- arguments --------------------------------------------------------------------------------


def parse_mode(text: str) -> Mode:
    """`none`, `keyless` or `key:REF` (a key file or a KMS URI). Raises UsageError for anything else."""
    if text == "none":
        return Mode("none")
    if text == "keyless":
        return Mode("keyless")
    if text.startswith("key:"):
        if not text.removeprefix("key:"):
            raise UsageError("--sign key: needs a key file or a KMS URI after the colon: key:cosign.key")
        return Mode("key", text.removeprefix("key:"))
    raise UsageError(f"--sign {text!r}: use none, keyless or key:<key file or KMS URI>")


def check_verify_options(options: VerifyOptions) -> None:
    """Raises UsageError for options cosign cannot take together, or too few of them."""
    keyless = bool(options.identity or options.identity_regexp or options.issuer or options.issuer_regexp)
    if options.key and keyless:
        raise UsageError("--key and --certificate-identity or --certificate-oidc-issuer are two ways to name a signer")
    if options.identity and options.identity_regexp:
        raise UsageError("--certificate-identity and --certificate-identity-regexp exclude each other")
    if options.issuer and options.issuer_regexp:
        raise UsageError("--certificate-oidc-issuer and --certificate-oidc-issuer-regexp exclude each other")
    if keyless and not ((options.identity or options.identity_regexp) and (options.issuer or options.issuer_regexp)):
        raise UsageError(
            "a keyless signature is checked against both the certificate identity and its OIDC issuer: "
            "--certificate-identity (or -regexp) and --certificate-oidc-issuer (or -regexp)"
        )
    if options.require and not options.names_signer():
        raise UsageError(
            "--require-signature needs the signer: --key, or --certificate-identity and --certificate-oidc-issuer"
        )


# ---- cosign -----------------------------------------------------------------------------------

_VERSION: Final = re.compile(r"^GitVersion:\s+v?(\S+)", re.MULTILINE)


def locate_cosign(env: Mapping[str, str], run: Run) -> str:
    """The cosign on PATH, which must be `COSIGN_VERSION`. Raises SignError naming the version when it
    is missing or another one."""
    path = shutil.which("cosign", path=env.get("PATH"))
    if path is None:
        raise SignError(
            f"cosign {COSIGN_VERSION} is needed and not on PATH: install it "
            f"(https://github.com/sigstore/cosign/releases/tag/v{COSIGN_VERSION}, or sigstore/cosign-installer "
            f"with cosign-release: v{COSIGN_VERSION} in a workflow)"
        )
    found = _VERSION.search(run([path, "version"], env).stdout)
    if found is None or found.group(1) != COSIGN_VERSION:
        was = found.group(1) if found else "a version that could not be read"
        raise SignError(f"{path} is cosign {was}; this release of debian-image-factory is written for {COSIGN_VERSION}")
    return path


def prepare(mode: Mode, env: Mapping[str, str], run: Run = run_process) -> Signer | None:
    """The signer for `mode`, or None for `none`. Everything signing needs is checked here, before any record
    is written anywhere: cosign, the key file, the OIDC identity of the CI."""
    if mode.kind == "none":
        return None
    cosign = locate_cosign(env, run)
    if mode.kind == "key":
        if "://" not in mode.key and not Path(mode.key).is_file():
            raise SignError(f"--sign key:{mode.key}: no such key file (a KMS key is a URI such as gcpkms://...)")
    elif not (
        env.get("SIGSTORE_ID_TOKEN")
        or (env.get("ACTIONS_ID_TOKEN_REQUEST_URL") and env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
    ):
        raise SignError(
            "--sign keyless needs an OIDC identity: run in GitHub Actions with `permissions: id-token: write`, "
            "or set SIGSTORE_ID_TOKEN to a token; outside a CI there is none, and a key is --sign key:<path>"
        )
    return Signer(mode, cosign, env, run)


# ---- envelopes --------------------------------------------------------------------------------


def _envelope(line: str) -> dict[str, object]:
    try:
        found: object = json.loads(line)
    except json.JSONDecodeError:
        raise SignError("a record is not JSON") from None
    if not isinstance(found, dict):
        raise SignError("a record is not a JSON object")
    return {str(key): value for key, value in found.items()}


def signatures_of(envelope: Mapping[str, object]) -> list[object]:
    found = envelope.get("signatures")
    return list(found) if isinstance(found, list) else []


def payload_of(line: str) -> str:
    """The base64 payload of the envelope on `line`: what two copies of one record share."""
    payload = _envelope(line).get("payload")
    if not isinstance(payload, str):
        raise SignError("a record has no payload")
    return payload


def is_signed(line: str) -> bool:
    return bool(signatures_of(_envelope(line)))


def with_signature(line: str, signature: Mapping[str, object]) -> str:
    """`line` with `signature` as its only signature; payload and payload type are untouched. The text is
    the same canonical form `records.record_lines` writes."""
    envelope = _envelope(line)
    envelope["signatures"] = [dict(signature)]
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"))


def bundle_signature(bundle: object, payload: str) -> dict[str, object]:
    """The envelope signature of a Sigstore bundle cosign wrote for `payload`: the DSSE signature, and the
    bundle's media type and verification material. Raises SignError for a bundle that is not that."""
    root = {str(k): v for k, v in bundle.items()} if isinstance(bundle, dict) else {}
    dsse = root.get("dsseEnvelope")
    material = root.get("verificationMaterial")
    media = root.get("mediaType")
    sigs = dsse.get("signatures") if isinstance(dsse, dict) else None
    if not (isinstance(dsse, dict) and isinstance(material, dict) and isinstance(media, str)):
        raise SignError("cosign wrote a bundle without a DSSE envelope and verification material")
    if dsse.get("payload") != payload:
        raise SignError("cosign wrote a bundle for another payload than the record's")
    if not (
        isinstance(sigs, list) and len(sigs) == 1 and isinstance(sigs[0], dict) and isinstance(sigs[0].get("sig"), str)
    ):
        raise SignError("cosign wrote a bundle that does not hold exactly one signature")
    return {"sig": sigs[0]["sig"], "bundle": {"mediaType": media, "verificationMaterial": material}}


def rebuilt_bundle(line: str, signature: Mapping[str, object]) -> dict[str, object] | None:
    """The Sigstore bundle of one signature of the envelope on `line`, or None when the signature has no
    bundle (a signature made by something else)."""
    envelope = _envelope(line)
    held = signature.get("bundle")
    if not (isinstance(held, dict) and isinstance(signature.get("sig"), str)):
        return None
    return {
        "mediaType": held.get("mediaType"),
        "verificationMaterial": held.get("verificationMaterial"),
        "dsseEnvelope": {
            "payload": envelope.get("payload"),
            "payloadType": envelope.get("payloadType"),
            "signatures": [{"sig": signature["sig"]}],
        },
    }


# ---- signing ----------------------------------------------------------------------------------


def sign_line(signer: Signer, line: str) -> str:
    """The record on `line`, signed. A line that already has a signature is returned as it is."""
    envelope = _envelope(line)
    if signatures_of(envelope):
        return line
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise SignError("a record has no payload")
    try:
        statement = base64.b64decode(payload, validate=True)
    except binascii.Error:
        raise SignError("a record's payload is not base64") from None
    with tempfile.TemporaryDirectory(prefix="debian-image-factory-sign-") as scratch:
        folder = Path(scratch)
        (folder / "statement.json").write_bytes(statement)
        arguments = [
            signer.cosign,
            "attest-blob",
            "--statement",
            str(folder / "statement.json"),
            "--bundle",
            str(folder / "bundle.json"),
            "--yes",
        ]
        if signer.mode.kind == "key":
            (folder / "signing-config.json").write_text(EMPTY_SIGNING_CONFIG, encoding="utf-8")
            arguments += ["--key", signer.mode.key, "--signing-config", str(folder / "signing-config.json")]
        done = signer.run(arguments, signer.env)
        if done.returncode != 0:
            raise SignError(f"cosign attest-blob failed ({done.returncode}): {done.stderr.strip()}")
        try:
            bundle: object = json.loads((folder / "bundle.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise SignError("cosign attest-blob wrote no bundle") from None
    return with_signature(line, bundle_signature(bundle, payload))


def to_add(signer: Signer | None, lines: Sequence[str], held: Sequence[str]) -> tuple[list[str], int]:
    """The records to add to a target that holds `held`: with a signer, each line of `lines` signed; and the
    number of lines left out because the target already holds that record's payload (signed or not).
    Published records are never rewritten, so a record that is already there stays as it is, and a signed
    publish run twice adds nothing. Without a signer, every line, as it is."""
    if signer is None:
        return list(lines), 0
    held_payloads = {payload_of(one) for one in held if one.strip()}
    found: list[str] = []
    skipped = 0
    for line in lines:
        if payload_of(line) in held_payloads:
            skipped += 1
        else:
            found.append(sign_line(signer, line))
    return found, skipped


# ---- verifying --------------------------------------------------------------------------------


def verify_arguments(options: VerifyOptions, bundle: Path, digest: str, predicate_type: str) -> list[str]:
    """The `cosign verify-blob-attestation` arguments that check a bundle against `options`: the statement
    must name `digest` and have `predicate_type`. A key's signature is in no transparency log."""
    arguments = [
        "verify-blob-attestation",
        "--bundle",
        str(bundle),
        "--digest",
        digest,
        "--digestAlg",
        "sha256",
        "--type",
        predicate_type,
    ]
    if options.key:
        return [*arguments, "--key", options.key, "--insecure-ignore-tlog"]
    for flag, value in (
        ("--certificate-identity", options.identity),
        ("--certificate-identity-regexp", options.identity_regexp),
        ("--certificate-oidc-issuer", options.issuer),
        ("--certificate-oidc-issuer-regexp", options.issuer_regexp),
    ):
        if value:
            arguments += [flag, value]
    return arguments


def check_signatures(
    lines: Sequence[str],
    digest: str,
    predicate_types: Sequence[str],
    options: VerifyOptions,
    env: Mapping[str, str],
    run: Run = run_process,
) -> Report:
    """Every record that has signatures is checked against `options` with cosign (`predicate_types` are the
    records' statement types, in the order of `lines`, empty for a line that is no record). A record that is
    unsigned is fine unless `options.require`; signatures with no signer named are counted as unchecked. A
    record is verified when one of its signatures verifies."""
    problems: list[str] = []
    verified = unsigned = unchecked = 0
    cosign: str | None = None
    for number, (line, predicate_type) in enumerate(zip(lines, predicate_types, strict=True), start=1):
        if not predicate_type:
            continue  # not a record at all: verify reports that
        found = signatures_of(_envelope(line))
        if not found:
            unsigned += 1
            if options.require:
                problems.append(f"record {number}: not signed, and a signature is required")
            continue
        if not options.names_signer():
            unchecked += 1
            continue
        if cosign is None:
            cosign = locate_cosign(env, run)
        reasons: list[str] = []
        for signature in found:
            bundle = rebuilt_bundle(line, signature) if isinstance(signature, dict) else None
            if bundle is None:
                reasons.append("a signature without a Sigstore bundle")
                continue
            with tempfile.TemporaryDirectory(prefix="debian-image-factory-verify-") as scratch:
                path = Path(scratch) / "bundle.json"
                path.write_text(json.dumps(bundle), encoding="utf-8")
                done = run([cosign, *verify_arguments(options, path, digest, predicate_type)], env)
            if done.returncode == 0:
                break
            reasons.append(done.stderr.strip().splitlines()[-1] if done.stderr.strip() else "cosign refused it")
        else:
            problems.append(f"record {number}: no signature verifies: {'; '.join(reasons)}")
            continue
        verified += 1
    return Report(tuple(problems), verified, unsigned, unchecked)
