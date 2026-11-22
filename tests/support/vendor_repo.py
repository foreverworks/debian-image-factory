"""A vendor's Debian repository for tests, signed with a throwaway key: what a `builtin:deb` entry points at.

`build_repo` makes one package, `example-tool` 2.4.0-1 (depending on the fixture archive's `lib-a`), with
`dpkg-deb`, indexes it, writes a Release and signs it as `InRelease` (or as `Release.gpg`, signed apart). The
result is a mapping of URL to bytes for a test's reader, and the lock entries that pin the package. Every way
the repository can be made wrong (another signer, another suite, an expired Valid-Until, a Packages file that
is not the one the Release lists) is a keyword.
"""

import gzip
import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from tests.support import fixture_archive, signing

REPO: Final = "https://packages.example.com/debian"
REGISTRY_URL: Final = f"{REPO}?suite=trixie&components=main&binaryArch=amd64"
DISTS: Final = f"{REPO}/dists/trixie"
IN_RELEASE: Final = f"{DISTS}/InRelease"
RELEASE: Final = f"{DISTS}/Release"
RELEASE_GPG: Final = f"{DISTS}/Release.gpg"
PACKAGES: Final = f"{DISTS}/main/binary-amd64/Packages"
KEYRING_URL: Final = f"{REPO}/vendor-keys.pgp"
PACKAGE: Final = fixture_archive.Package("example-tool", "2.4.0-1", depends="lib-a")
FILENAME: Final = "pool/main/e/example-tool/example-tool_2.4.0-1_amd64.deb"
DEB_URL: Final = f"{REPO}/{FILENAME}"
VALID: Final = "Sat, 01 Jan 2098 00:00:00 UTC"
EXPIRED: Final = "Sun, 01 Nov 2026 00:00:00 UTC"


@dataclass(frozen=True, slots=True)
class VendorRepo:
    files: dict[str, bytes]
    """URL -> bytes, everything the repository serves."""
    deb: bytes
    keyring: bytes


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_deb() -> bytes:
    with tempfile.TemporaryDirectory(prefix="dif-vendor-deb-") as work:
        return fixture_archive._build_deb(PACKAGE, Path(work)).read_bytes()


def build_repo(
    signer: signing.Signer,
    deb: bytes,
    *,
    signed_by: signing.Signer | None = None,
    suite: str = "trixie",
    valid_until: str = VALID,
    detached: bool = False,
    tamper_packages: bool = False,
) -> VendorRepo:
    """The repository: `signer`'s keyring is the one the lock pins, `signed_by` (default: `signer`) signs."""
    packages = fixture_archive._stanza(PACKAGE, FILENAME, deb).encode()
    compressed = gzip.compress(packages, mtime=0)
    lines = "".join(
        f" {sha256(data)} {len(data):>8} main/binary-amd64/{name}\n"
        for name, data in (("Packages", packages), ("Packages.gz", compressed))
    )
    release = (
        f"Origin: Example\nLabel: Example\nSuite: {suite}\nCodename: {suite}\n"
        f"Date: Sun, 01 Nov 2026 00:00:00 UTC\nValid-Until: {valid_until}\n"
        f"Architectures: amd64\nComponents: main\nSHA256:\n{lines}"
    )
    key = signed_by or signer
    files: dict[str, bytes] = {
        PACKAGES: packages + (b"Tampered: yes\n" if tamper_packages else b""),
        f"{PACKAGES}.gz": compressed,
        DEB_URL: deb,
        KEYRING_URL: signer.keyring,
    }
    if detached:
        files[RELEASE] = release.encode()
        files[RELEASE_GPG] = signing.detach(key, release.encode())
    else:
        files[IN_RELEASE] = signing.clearsign(key, release)
    return VendorRepo(files, deb, signer.keyring)


def entries(repo: VendorRepo, users: list[str], *, sha: str | None = None) -> dict[str, object]:
    """The lock entries of the vendor package and its keyring, for the images `users`."""
    return {
        "example-tool": {
            "apt": PACKAGE.name,
            "datasource": "deb",
            "depName": PACKAGE.name,
            "module": "vendor",
            "registryUrl": REGISTRY_URL,
            "sha256": sha or sha256(repo.deb),
            "signed_by": "vendor-keys",
            "url": f"{REPO}/pool/main/e/example-tool/example-tool_{{version}}_amd64.deb",
            "used_by": users,
            "version": PACKAGE.version,
        },
        "vendor-keys": {
            "module": "vendor",
            "sha256": sha256(repo.keyring),
            "url": KEYRING_URL,
            "used_by": users,
            "version": "1",
        },
    }
