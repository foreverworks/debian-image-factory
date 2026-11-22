"""Throwaway signing keys for tests: a gpg home made on the spot, never anything real."""

import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Signer:
    """A throwaway key: the home it lives in, and its public key as a binary keyring."""

    home: Path
    keyring: bytes


def run(home: Path, args: Sequence[str], stdin: bytes | None = None) -> bytes:
    done = subprocess.run(
        ["gpg", "--homedir", str(home), "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", *args],
        input=stdin,
        capture_output=True,
        check=True,
    )
    return done.stdout


def make_signer(identity: str = "Throwaway Releaser <release@example.com>") -> Signer:
    """A new ed25519 signing key in a fresh home (in the system temp directory: gpg-agent's socket path is short)."""
    home = Path(tempfile.mkdtemp(prefix="dif-gpg-"))
    home.chmod(0o700)
    run(home, ["--quick-gen-key", identity, "ed25519", "sign", "never"])
    return Signer(home, run(home, ["--export"]))


def armored_keyring(signer: Signer) -> bytes:
    return run(signer.home, ["--armor", "--export"])


def clearsign(signer: Signer, text: str) -> bytes:
    """`text` clear-signed as `gpg --clearsign` does."""
    return run(signer.home, ["--digest-algo", "SHA256", "--clearsign"], text.encode())


def detach(signer: Signer, data: bytes) -> bytes:
    """The detached binary signature of `data`."""
    return run(signer.home, ["--digest-algo", "SHA256", "--detach-sign"], data)


def close(signer: Signer) -> None:
    subprocess.run(["gpgconf", "--homedir", str(signer.home), "--kill", "all"], capture_output=True, check=False)
    shutil.rmtree(signer.home, ignore_errors=True)
