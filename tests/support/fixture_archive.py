"""A tiny Debian-format archive for tests, laid out the way snapshot.debian.org serves it.

`build_fixture(root)` makes a handful of packages with `dpkg-deb`, indexes them, signs each suite's
`InRelease` with a throwaway key and writes the `/mr/timestamp/` listings. Two archives (`debian`,
suite `trixie`; `debian-security`, suite `trixie-security`) exist at two timestamps; the second holds
exactly one change: `lib-a` 1.1, a security-style upload in `trixie-security`.
"""

import gzip
import hashlib
import json
import lzma
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ARCHIVES: Final = {"debian": "trixie", "debian-security": "trixie-security"}
"""Archive name -> the suite it serves."""

FIRST_ID: Final = "20261101T000000Z"
SECOND_ID: Final = "20261108T000000Z"
LATER_ID: Final = "20261115T000000Z"
"""The newest listed ID of both archives: it serves what SECOND_ID serves, and no ID is listed after it, so the
older rule (a later snapshot in every archive) does not complete it."""


@dataclass(frozen=True, slots=True)
class Fixture:
    root: Path
    snapshot_ids: tuple[str, str]
    listed_ids: tuple[str, str, str]
    keyring: Path
    listings_dir: Path


@dataclass(frozen=True, slots=True)
class Package:
    name: str
    version: str
    depends: str = ""
    essential: bool = False
    priority: str = "optional"
    architecture: str = "amd64"
    section: str = "misc"


INCUS_DEFAULTS: Final = ("cloud-init", "dbus", "iproute2", "netbase", "systemd-resolved", "systemd-sysv", "udev")
"""What an Incus image asks apt for besides its own packages (definition.KIND_DEFAULTS), so a fixture plan can
hold one."""

PACKAGES: Final = (
    Package("base-files", "1.0", essential=True, priority="required", architecture="amd64", section="admin"),
    Package("fixture-essential", "1.0", essential=True, priority="required", architecture="all", section="admin"),
    Package("dpkg", "1.0", priority="required", section="admin"),
    Package("apt", "1.0", depends="dpkg", priority="important", section="admin"),
    Package("tool-a", "1.0", depends="lib-a, tool-b"),
    Package("lib-a", "1.0", architecture="all", section="libs"),
    Package("tool-b", "1.0", depends="lib-b (>= 2)"),
    Package("lib-b", "2.0", section="libs"),
    Package("linux-image-fixture", "1.0", section="kernel"),
    *(Package(name, "1.0") for name in INCUS_DEFAULTS),
)
LIB_A_SECURITY: Final = Package("lib-a", "1.1", architecture="all", section="libs")

SUITE_PACKAGES: Final = {
    (FIRST_ID, "debian"): PACKAGES,
    (SECOND_ID, "debian"): PACKAGES,
    (FIRST_ID, "debian-security"): (),
    (SECOND_ID, "debian-security"): (LIB_A_SECURITY,),
    (LATER_ID, "debian"): PACKAGES,
    (LATER_ID, "debian-security"): (LIB_A_SECURITY,),
}


def base_url(fixture: Fixture, archive: str, snapshot_id: str) -> str:
    """The `file:` base URL of one archive at one timestamp, shaped like snapshot.debian.org's."""
    return f"file://{fixture.root}/archive/{archive}/{snapshot_id}"


def _run(args: list[str], env: dict[str, str] | None = None) -> None:
    result = subprocess.run(args, capture_output=True, check=False, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"{args[0]} failed: {result.stderr.decode('utf-8', 'replace')}")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_deb(package: Package, work: Path) -> Path:
    tree = work / f"{package.name}_{package.version}"
    (tree / "DEBIAN").mkdir(parents=True)
    docs = tree / "usr" / "share" / "doc" / package.name
    docs.mkdir(parents=True)
    (docs / "README").write_text(f"{package.name} {package.version}\n", encoding="utf-8")
    control = {
        "Package": package.name,
        "Version": package.version,
        "Architecture": package.architecture,
        "Maintainer": "Fixture <fixture@example.com>",
        "Section": package.section,
        "Priority": package.priority,
        "Description": f"fixture package {package.name}",
    }
    if package.depends:
        control["Depends"] = package.depends
    if package.essential:
        control["Essential"] = "yes"
    (tree / "DEBIAN" / "control").write_text("".join(f"{k}: {v}\n" for k, v in control.items()), encoding="utf-8")
    deb = work / f"{package.name}_{package.version}_{package.architecture}.deb"
    _run(["dpkg-deb", "--build", "--root-owner-group", "-Zgzip", str(tree), str(deb)])
    return deb


def _stanza(package: Package, filename: str, deb: bytes) -> str:
    fields = {
        "Package": package.name,
        "Version": package.version,
        "Architecture": package.architecture,
        "Maintainer": "Fixture <fixture@example.com>",
        "Installed-Size": "1",
        "Section": package.section,
        "Priority": package.priority,
        "Description": f"fixture package {package.name}",
        "Filename": filename,
        "Size": str(len(deb)),
        "SHA256": _sha256(deb),
    }
    if package.depends:
        fields["Depends"] = package.depends
    if package.essential:
        fields["Essential"] = "yes"
    return "".join(f"{k}: {v}\n" for k, v in fields.items())


def _write_with_by_hash(directory: Path, name: str, data: bytes) -> tuple[str, int]:
    """Write `data` as `directory/name` and as its by-hash copy; return (sha256, size)."""
    digest = _sha256(data)
    (directory / name).write_bytes(data)
    by_hash = directory / "by-hash" / "SHA256"
    by_hash.mkdir(parents=True, exist_ok=True)
    (by_hash / digest).write_bytes(data)
    return digest, len(data)


def _write_suite(
    root: Path, gpg_home: Path, archive: str, snapshot_id: str, debs: dict[Package, Path], pool_dir: str
) -> None:
    dist = ARCHIVES[archive]
    base = root / "archive" / archive / snapshot_id
    dist_dir = base / "dists" / dist
    binary = dist_dir / "main" / "binary-amd64"
    binary.mkdir(parents=True)
    stanzas = []
    for package, deb in debs.items():
        filename = f"{pool_dir}/{package.name[0]}/{package.name}/{deb.name}"
        target = base / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(deb, target)
        stanzas.append(_stanza(package, filename, deb.read_bytes()))
    packages = "\n".join(stanzas).encode()
    entries = {
        "main/binary-amd64/Packages": _write_with_by_hash(binary, "Packages", packages),
        "main/binary-amd64/Packages.xz": _write_with_by_hash(binary, "Packages.xz", lzma.compress(packages)),
        "main/binary-amd64/Packages.gz": _write_with_by_hash(binary, "Packages.gz", gzip.compress(packages, mtime=0)),
    }
    lines = "".join(f" {digest} {size:>8} {path}\n" for path, (digest, size) in sorted(entries.items()))
    release = (
        f"Origin: Fixture\nLabel: Fixture\nSuite: {dist}\nCodename: {dist}\n"
        "Date: Sun, 01 Nov 2026 00:00:00 UTC\nValid-Until: Mon, 02 Nov 2026 00:00:00 UTC\n"
        "Architectures: amd64\nComponents: main\nAcquire-By-Hash: yes\n"
        f"SHA256:\n{lines}"
    )
    (dist_dir / "Release").write_text(release, encoding="utf-8")
    _run(
        [
            "gpg", "--homedir", str(gpg_home), "--batch", "--yes", "--pinentry-mode", "loopback",
            "--passphrase", "", "--digest-algo", "SHA512", "--clearsign",
            "-o", str(dist_dir / "InRelease"), str(dist_dir / "Release"),
        ]
    )  # fmt: skip


def _make_keyring(gpg_home: Path, keyring: Path) -> None:
    _run(
        [
            "gpg", "--homedir", str(gpg_home), "--batch", "--passphrase", "",
            "--quick-gen-key", "Fixture Archive <archive@example.com>", "ed25519", "sign", "never",
        ]
    )  # fmt: skip
    result = subprocess.run(["gpg", "--homedir", str(gpg_home), "--batch", "--export"], capture_output=True, check=True)
    keyring.write_bytes(result.stdout)


def build_fixture(root: Path) -> Fixture:
    """Generate the archive under `root` (takes a few seconds) and describe it."""
    root = root.resolve()
    keyring = root / "keyring" / "fixture-archive.gpg"
    keyring.parent.mkdir(parents=True)
    # gpg-agent's socket path is limited, so the throwaway home lives in the system temp directory.
    gpg_home = Path(tempfile.mkdtemp(prefix="dif-gpg-"))
    gpg_home.chmod(0o700)
    try:
        _make_keyring(gpg_home, keyring)
        with tempfile.TemporaryDirectory(prefix="dif-debs-") as work_name:
            work = Path(work_name)
            built = {package: _build_deb(package, work) for package in (*PACKAGES, LIB_A_SECURITY)}
            for (snapshot_id, archive), packages in SUITE_PACKAGES.items():
                pool = "pool/updates/main" if archive == "debian-security" else "pool/main"
                _write_suite(root, gpg_home, archive, snapshot_id, {p: built[p] for p in packages}, pool)
    finally:
        subprocess.run(["gpgconf", "--homedir", str(gpg_home), "--kill", "all"], capture_output=True, check=False)
        shutil.rmtree(gpg_home, ignore_errors=True)
    listings = root / "mr" / "timestamp"
    listings.mkdir(parents=True)
    ids = [FIRST_ID, SECOND_ID, LATER_ID]
    for archive in ARCHIVES:
        listing = {"_comment": "", "result": {archive: ids}}
        (listings / f"{archive}.json").write_text(json.dumps(listing), encoding="utf-8")
    os.chmod(keyring, 0o644)
    return Fixture(root, (FIRST_ID, SECOND_ID), (FIRST_ID, SECOND_ID, LATER_ID), keyring, listings)
