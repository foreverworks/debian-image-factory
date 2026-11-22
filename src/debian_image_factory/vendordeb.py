"""The `builtin:deb` module (DESIGN 6.4, 16.7): a vendor `.deb`, checked through its repository's signature.

Every entry of the module (but a keyring another entry's `signed_by` names) is an `apt` entry with a
`registryUrl` and a `signed_by`. `plan` and `fetch` both walk the same chain before they trust it:

1. the keyring entry's file, pinned by the lock's checksums (a trust root);
2. the repository's `dists/<suite>/InRelease` (else `Release` with `Release.gpg`), verified by `gpgv`
   against that keyring alone (input-lock's `gpgv`);
3. its suite and Valid-Until (input-lock's `release_sums`), checked against the time given;
4. the `Packages` index (plain, `.gz` or `.xz`) the signed Release lists, by its sha256;
5. the index's stanza for the entry's package at its version: its `SHA256` must be the lock's sha256 and
   its `Filename` must end in the file name of the entry's url (input-lock's `same_file`).

Anything that does not hold fails closed, naming the URL. Reads go through the `read` the caller passes
(`Sources.read`), never input-lock's own urllib reader, so tests and mirrors use the same code. The table
and lock rules here are pure; `verify` runs `gpgv`.
"""

import datetime
import gzip
import hashlib
import lzma
import zlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from input_lock import Entry, Value
from input_lock.deb import Published, dists_url, index_urls, release_sums, same_file, suite_of
from input_lock.fetch import gpgv
from input_lock.signed import dearmor

from . import debian

MODULE: Final = "builtin:deb"
"""The `use` value of the module."""

KEYS: Final = frozenset(("use", "enabled_by"))
"""What a deb module's table may hold: nothing but the module's own switch."""

REQUIRED: Final = ("apt", "registryUrl", "signed_by")
"""What every entry of a deb module carries, keyrings aside."""

COMPRESSED: Final[tuple[tuple[str, Callable[[bytes], bytes] | None], ...]] = (
    ("", None),
    (".gz", gzip.decompress),
    (".xz", lzma.decompress),
)
"""The forms of a Packages index, in the order they are tried (input-lock's `read_index` order)."""

type Read = Callable[[str], bytes]


class VendorError(Exception):
    """The vendor's repository does not vouch for the entry: the message names the URL."""


# ---- the definition and the lock ------------------------------------------------------------------


def table_problems(table: Mapping[str, object]) -> list[str]:
    """Every problem of a deb module's table (the caller prefixes the module)."""
    return [f"unknown key {key!r}: this module takes only enabled_by" for key in sorted(set(table) - KEYS)]


def entry_problems(name: str, entry: Entry) -> list[str]:
    """The fields a deb module's entry lacks, each named."""
    return [
        f"inputs.{name}: an entry of a builtin:deb module needs {field} ({why})"
        for field, why in (
            ("apt", "the package name it installs"),
            ("registryUrl", "the vendor repository whose signed InRelease vouches for it"),
            ("signed_by", "the keyring entry that repository signs with"),
        )
        if not isinstance(entry.get(field), str) or not entry.get(field)
    ]


# ---- what one entry pins ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Pin:
    """One apt entry, as the chain checks it."""

    entry: str
    package: str
    version: str
    registry_url: str
    url: str
    """The rendered url of the .deb."""
    sha256: str


@dataclass(frozen=True, slots=True)
class Verified:
    """What the chain read and verified for one pin."""

    pin: Pin
    stanza: Mapping[str, str]
    """The index's stanza for the package at its version, as the index gives it."""
    signed: tuple[tuple[str, bytes], ...]
    """(URL, bytes) of the signed file, then of its detached signature when it has one."""
    index: tuple[str, bytes]
    """(URL, bytes) of the Packages index the stanza came from, as read."""


def pin_of(entry: str, fields: Mapping[str, Value], registry_url: str) -> Pin:
    """A pin from an entry's `build_fields` (url rendered) and its registryUrl (a hint, kept out of them)."""

    def text(field: str) -> str:
        value = fields.get(field)
        return value if isinstance(value, str) else ""

    return Pin(entry, text("apt"), text("version"), registry_url, text("url"), text("sha256"))


def checked_keyring(url: str, data: bytes, checksums: Mapping[str, str]) -> bytes:
    """The keyring file `data`, checked against every checksum the lock gives and unwrapped from armor."""
    if not checksums:
        raise VendorError(f"{url}: the keyring has no checksum in the lock: it is a trust root")
    for algorithm, expected in sorted(checksums.items()):
        if hashlib.new(algorithm, data).hexdigest() != expected:
            raise VendorError(f"{url}: the keyring does not match the lock's {algorithm} ({expected})")
    try:
        return dearmor(data)
    except ValueError as error:
        raise VendorError(f"{url}: {error}") from None


def _read(read: Read, url: str) -> bytes | None:
    try:
        return read(url)
    except (OSError, ValueError):
        return None


def signed_release(
    registry_url: str, ring: bytes, read: Read, now: datetime.datetime
) -> tuple[dict[str, str], tuple[tuple[str, bytes], ...]]:
    """{path under dists/<suite>/: sha256} the repository's signed Release vouches for, and the signed files.

    The InRelease is read first; only when it cannot be read are Release and Release.gpg tried. A file that
    is read and does not verify fails: never a fall back to another form."""
    dists = dists_url(registry_url)
    in_release_url = f"{dists}/InRelease"
    in_release = _read(read, in_release_url)
    files: tuple[tuple[str, bytes], ...]
    if in_release is not None:
        source, files = in_release_url, ((in_release_url, in_release),)
        signature = None
        signed = in_release
    else:
        release_url, signature_url = f"{dists}/Release", f"{dists}/Release.gpg"
        release, detached = _read(read, release_url), _read(read, signature_url)
        if release is None or detached is None:
            raise VendorError(f"{dists}: no InRelease, nor a Release with its Release.gpg: nothing signed to check")
        source, files = release_url, ((release_url, release), (signature_url, detached))
        signature, signed = detached, release
    try:
        text = gpgv(ring, signed, signature).decode("utf-8")
        return release_sums(text, suite_of(registry_url), now), files
    except ValueError as error:  # gpgv's refusals, a text that is not UTF-8, another suite, an expired Release
        raise VendorError(f"{source}: {error}") from None


def vouched_index(dists: str, path: str, sums: Mapping[str, str], read: Read) -> tuple[str, bytes, str] | None:
    """(URL, bytes read, text) of the first form of the index at `path` the signed Release lists that can be
    read, checked against its sha256; None when the Release lists none of its forms or none can be read."""
    for suffix, unpack in COMPRESSED:
        listed = sums.get(path + suffix)
        if listed is None:
            continue
        url = f"{dists}/{path}{suffix}"
        data = _read(read, url)
        if data is None:
            continue
        got = hashlib.sha256(data).hexdigest()
        if got != listed:
            raise VendorError(f"{url}: hashes to {got}, the signed Release lists {listed}")
        try:
            return url, data, (unpack(data) if unpack else data).decode("utf-8")
        except (OSError, EOFError, lzma.LZMAError, zlib.error, UnicodeDecodeError) as error:
            raise VendorError(f"{url}: not a readable index: {error}") from None
    return None


def stanza_problem(pin: Pin, stanza: Mapping[str, str], arch: str) -> str | None:
    """Why the index's stanza does not vouch for the pin; None when it does."""
    if stanza.get("Architecture") not in (arch, "all"):
        return f"{pin.package} {pin.version} is built for {stanza.get('Architecture')!r}, not {arch} or all"
    if stanza.get("SHA256", "").lower() != pin.sha256:
        return (
            f"the signed index gives {pin.package} {pin.version} sha256 {stanza.get('SHA256')!r}, "
            f"the lock's {pin.entry} says {pin.sha256}"
        )
    published = Published(filename=stanza.get("Filename", ""), checksums={"sha256": pin.sha256})
    if not same_file({"url": pin.url, "version": pin.version}, published):
        return f"the index's file is {stanza.get('Filename')!r}, and {pin.entry}'s url is {pin.url}"
    return None


def verify(pin: Pin, ring: bytes, read: Read, now: datetime.datetime, arch: str) -> Verified:
    """The whole chain for one pin, with `ring` (a checked keyring) the only key trusted. Raises VendorError
    naming the URL that fails."""
    sums, signed = signed_release(pin.registry_url, ring, read, now)
    dists = dists_url(pin.registry_url)
    indices = index_urls(pin.registry_url)
    for index_url in indices:
        found = vouched_index(dists, index_url.removeprefix(dists + "/"), sums, read)
        if found is None:
            continue
        url, data, text = found
        try:
            stanzas = debian.packages_stanzas(text)
        except ValueError as error:
            raise VendorError(f"{url}: {error}") from None
        for stanza in stanzas:
            if stanza.get("Package") == pin.package and stanza.get("Version") == pin.version:
                problem = stanza_problem(pin, stanza, arch)
                if problem is not None:
                    raise VendorError(f"{url}: {problem}")
                return Verified(pin, stanza, signed, (url, data))
    raise VendorError(
        f"{pin.package} {pin.version} is in no index the signed Release of {dists} vouches for "
        f"({', '.join(indices)}): the version is not published there, or the registryUrl is wrong"
    )


def package_of(verified: Verified) -> tuple[str, str, str]:
    """(name, version, architecture) of the verified stanza."""
    stanza = verified.stanza
    return (stanza["Package"], stanza["Version"], stanza["Architecture"])


def stanza_text(stanzas: Sequence[Mapping[str, str]]) -> str:
    """A Packages file holding `stanzas`, as the index gave them."""
    return "\n".join("".join(f"{key}: {value}\n" for key, value in stanza.items()) for stanza in stanzas)
