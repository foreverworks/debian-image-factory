"""The `fetch` stage (DESIGN 5.3, 7.7): everything a plan names, downloaded, verified and laid out for the build.

`fetch plan.json` reads the plan alone. It re-reads the plan's snapshot indices (verified against the
archive keyring, as `plan` did), finds every package of every image in them, downloads each pool file
into the content-addressed cache checking its size and sha256 against the signed index, and lays out the
partial mirror (`mirror_dir`) the build reads through `file:` sources: the signed `InRelease` and indices
as `plan` laid them out, plus the pool files, hard-linked from the cache. Every locked input an image
installs is downloaded the same way, checked against the lock's checksums and stored in the cache by
sha256 (`input_path` says where).

A file that does not match is refused, naming its URL, and never tried from another source: a mirror or
cache is a performance layer, never an authority (7.7). Reads go through `Sources.read`, so tests and
`--mirror` use the same code as snapshot.debian.org.

An entry that has `signed_by` and `sums_url` (input-lock 0.2.0's trust fields, DESIGN 6.1) is also checked
against its vendor's signed checksum list: `gpgv` verifies the list with the keyring entry `signed_by` names, and
the list's checksum for the file must equal the lock's (Node's `SHASUMS256.txt.asc` is one). The list is kept in
the cache by its sha256, with a small note keyed by the entry's sha256 that `vouched_by` reads back for provenance.

A vendor .deb (an image's `debs`, the `builtin:deb` module) is verified the same way through its repository: the
keyring from the cache, the repository's signed `InRelease` (or `Release` and `Release.gpg`) checked by `gpgv`,
its suite and Valid-Until, the `Packages` index by the sha256 the Release lists, and the index's stanza, whose
sha256 must be the lock's (`vendordeb.verify`). The signed file and the index are kept in the cache with the same
kind of note. Vendor packages are not looked for in the snapshot's indices: they are not Debian's.
"""

import datetime
import filecmp
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, TextIO

from input_lock import Package, Value
from input_lock.fetch import gpgv
from input_lock.signed import dearmor, listed, sums_name

from . import archive, debian, records, resolve, vendordeb
from .commands import Failed, Sources, Usage
from .planfile import ImageEntry, Plan, read_plan

CHECKSUMS: Final = (("sha256", 64, hashlib.sha256), ("sha512", 128, hashlib.sha512), ("sha1", 40, hashlib.sha1))
"""Field name, hex length and constructor of the checksums a locked input may carry."""


@dataclass(frozen=True, slots=True)
class LockedInput:
    """One locked input as the plan carries it: where it is read and what it must hash to."""

    name: str
    url: str
    sha256: str
    checksums: tuple[tuple[str, str], ...]
    """(algorithm, hex digest) for every checksum the entry carries, sha256 first."""


@dataclass(frozen=True, slots=True)
class Vouched:
    """A locked input whose checksum a vendor's signed list vouches for, and what verifies it."""

    entry: LockedInput
    keyring: LockedInput
    """The entry `signed_by` names: a trust root, already pinned by its own checksum."""
    sums_url: str
    sums_sig_url: str | None
    """The detached signature of the list, when it is not clear-signed."""


@dataclass(frozen=True, slots=True)
class AptVouched:
    """A vendor .deb whose checksum its repository's signed InRelease vouches for, and what verifies it."""

    entry: LockedInput
    keyring: LockedInput
    pin: vendordeb.Pin
    architecture: str


@dataclass(frozen=True, slots=True)
class FetchPlan:
    """What `fetch` reads of a plan.json: the snapshot, where to look, and everything to fetch."""

    snapshot: str
    suite: str
    components: tuple[str, ...]
    architecture: str
    packages: tuple[Package, ...]
    """The union of every image's resolved set, sorted."""
    inputs: tuple[LockedInput, ...]
    """Every locked input of every image, once each, sorted."""
    vouched: tuple[Vouched, ...]
    """Every input with a signed checksum list, once each, sorted."""
    apt: tuple[AptVouched, ...] = ()
    """Every vendor .deb, once each, sorted."""


@dataclass(frozen=True, slots=True)
class PoolFile:
    """One package's file as the signed indices describe it."""

    sha256: str
    size: int
    locations: tuple[tuple[str, str, str], ...]
    """(archive name, archive base URL, Filename), sorted: where the file is, and where the mirror lays it."""


# ---- reading plan.json --------------------------------------------------------------------------


def locked_input(image: str, name: str, fields: Mapping[str, Value]) -> LockedInput:
    """One image's locked input, checked for what fetch needs of it; Failed naming the field."""
    where = f"images.{image}.inputs.{name}"
    url = fields.get("url")
    if not isinstance(url, str) or not url:
        raise Failed(f"plan: {where}.url is missing: nothing says where to read it")
    if not url.startswith("https://"):
        raise Failed(f"plan: {where}.url must be an https:// URL, not {url!r}")
    checksums: list[tuple[str, str]] = []
    for algorithm, length, _constructor in CHECKSUMS:
        if algorithm not in fields:
            continue
        digest = fields[algorithm]
        if not isinstance(digest, str) or not re.fullmatch(f"[0-9a-f]{{{length}}}", digest):
            raise Failed(f"plan: {where}.{algorithm} must be {length} lowercase hex digits")
        checksums.append((algorithm, digest))
    if not checksums or checksums[0][0] != "sha256":
        raise Failed(f"plan: {where}.sha256 is missing: `lock checksums` adds a sha256 to an entry that has none")
    return LockedInput(name, url, checksums[0][1], tuple(checksums))


def vouched_inputs(image: str, entry: ImageEntry) -> list[Vouched]:
    """The inputs of an image that name a signed checksum list (`sums_url`) and the keyring that signs it.

    Failed when the keyring is not among the image's inputs, or is not https like every input."""
    found: list[Vouched] = []
    for name, trust in sorted(entry["trust"].items()):
        if "sums_url" not in trust:
            continue  # an apt entry's signed list is its repository's InRelease: `apt_inputs`
        keyring = trust["signed_by"]
        if keyring not in entry["inputs"] or name not in entry["inputs"]:
            raise Failed(f"plan: images.{image}.trust.{name}: {name} and its keyring {keyring} must both be inputs")
        for field in ("sums_url", "sums_sig_url"):
            if field in trust and not trust[field].startswith("https://"):
                raise Failed(f"plan: images.{image}.trust.{name}.{field} must be an https:// URL, not {trust[field]!r}")
        found.append(
            Vouched(
                locked_input(image, name, entry["inputs"][name]),
                locked_input(image, keyring, entry["inputs"][keyring]),
                trust["sums_url"],
                trust.get("sums_sig_url"),
            )
        )
    return found


def apt_inputs(image: str, entry: ImageEntry, architecture: str) -> list[AptVouched]:
    """The vendor .deb files an image installs (`debs`), each with the keyring its `signed_by` names.

    Failed when the plan's inputs do not hold what the plan's `debs` names."""
    found: list[AptVouched] = []
    for name, deb in sorted(entry["debs"].items()):
        keyring = entry["trust"][name]["signed_by"]
        fields = entry["inputs"][name]
        if keyring not in entry["inputs"]:
            raise Failed(f"plan: images.{image}.debs.{name}: its keyring {keyring} must be an input of the image")
        if (fields.get("apt"), fields.get("version")) != (deb["package"], deb["version"]):
            raise Failed(f"plan: images.{image}.debs.{name}: the package and version are not the input's")
        item = locked_input(image, name, fields)
        pin = vendordeb.Pin(name, deb["package"], deb["version"], deb["registry_url"], item.url, item.sha256)
        found.append(AptVouched(item, locked_input(image, keyring, entry["inputs"][keyring]), pin, architecture))
    return found


def fetch_plan(plan: Plan) -> FetchPlan:
    """What fetch needs of a plan: the union of every image's packages and locked inputs. A vendor .deb is a
    locked input, not a snapshot package: it leaves `packages` (in every image, its descendants included)."""
    packages: set[Package] = set()
    inputs: set[LockedInput] = set()
    vouched: set[Vouched] = set()
    apt: set[AptVouched] = set()
    architecture = plan["debian"]["architecture"]
    for image, entry in sorted(plan["images"].items()):
        packages.update(entry["packages"])
        inputs.update(locked_input(image, name, fields) for name, fields in sorted(entry["inputs"].items()))
        vouched.update(vouched_inputs(image, entry))
        apt.update(apt_inputs(image, entry, architecture))
    vendor = {(item.pin.package, item.pin.version) for item in apt}
    debian_ = plan["debian"]
    return FetchPlan(
        plan["snapshot"],
        debian_["suite"],
        debian_["components"],
        architecture,
        tuple(sorted(package for package in packages if package[:2] not in vendor)),
        tuple(sorted(inputs, key=lambda item: (item.name, item.url, item.checksums))),
        tuple(sorted(vouched, key=lambda item: (item.entry.name, item.entry.url, item.keyring.name))),
        tuple(sorted(apt, key=lambda item: (item.entry.name, item.entry.url, item.keyring.name))),
    )


# ---- finding packages in the signed indices -----------------------------------------------------


def _safe_filename(filename: str) -> bool:
    path = PurePosixPath(filename)
    return not path.is_absolute() and ".." not in path.parts and "." not in path.parts and bool(path.parts)


def pool_files(
    indices: Sequence[archive.SuiteIndex], wanted: Sequence[Package]
) -> tuple[dict[Package, PoolFile], list[str]]:
    """Where each wanted package's file is, and every problem: a package no index lists, a stanza without
    its file fields, two stanzas of one package that disagree on the sha256.

    Suites of one archive (`trixie` and `trixie-updates`) often list the same file; any listing will do.
    A package listed by both archives is laid out in both, so apt finds it wherever it chooses to read it.
    """
    wanted_set = set(wanted)
    found: dict[Package, tuple[str, int, set[tuple[str, str, str]]]] = {}
    problems: list[str] = []
    unusable: set[Package] = set()
    for index in indices:
        archive_ = archive.archive_name(index.base_url)
        for path, local in index.files:
            if not path.endswith("/Packages"):
                continue
            for stanza in debian.packages_stanzas(local.read_text(encoding="utf-8")):
                key = (stanza.get("Package", ""), stanza.get("Version", ""), stanza.get("Architecture", ""))
                if key not in wanted_set:
                    continue
                filename = stanza.get("Filename", "")
                sha256 = stanza.get("SHA256", "")
                size = stanza.get("Size", "")
                label = f"{key[0]} {key[1]} ({key[2]})"
                if not (_safe_filename(filename) and re.fullmatch("[0-9a-f]{64}", sha256) and size.isdigit()):
                    problems.append(f"{label}: the index of {index.dist} gives no usable Filename, Size and SHA256")
                    unusable.add(key)
                    continue
                earlier = found.get(key)
                if earlier is not None and earlier[0] != sha256:
                    problems.append(f"{label}: the indices disagree on its sha256 ({earlier[0]} and {sha256})")
                    continue
                locations = earlier[2] if earlier is not None else set()
                locations.add((archive_, index.base_url, filename))
                found[key] = (sha256, int(size), locations)
    problems.extend(
        f"{name} {version} ({arch}): not in the indices of any suite of the snapshot"
        for name, version, arch in wanted
        if (name, version, arch) not in found and (name, version, arch) not in unusable
    )
    return {key: PoolFile(sha, size, tuple(sorted(where))) for key, (sha, size, where) in found.items()}, problems


# ---- downloading ----------------------------------------------------------------------------------


def _digest(algorithm: str, data: bytes) -> str:
    return {name: constructor for name, _length, constructor in CHECKSUMS}[algorithm](data).hexdigest()


def download_pool_file(package: Package, pool: PoolFile, sources: Sources) -> bool:
    """Make sure the cache holds the package's file; True when it was downloaded, False when it was there.

    Raises Failed naming the URL when it cannot be read or is not the size and sha256 the index gives.
    """
    present = archive.cached(sources.cache, pool.sha256)
    if present is not None and present.stat().st_size == pool.size:
        return False
    _archive, base_url, filename = pool.locations[0]
    url = f"{base_url}/{filename}"
    try:
        data = sources.read(url)
    except (OSError, ValueError) as error:
        raise Failed(f"{url}: cannot be read: {error}") from None
    if len(data) != pool.size or hashlib.sha256(data).hexdigest() != pool.sha256:
        raise Failed(
            f"{url}: does not match the signed index for {package[0]} {package[1]} "
            f"(expected {pool.size} bytes, sha256 {pool.sha256})"
        )
    archive.store(sources.cache, data)
    return True


def verified_input(item: LockedInput, data: bytes) -> None:
    """Failed naming the URL unless `data` carries every checksum the lock gives."""
    for algorithm, expected in item.checksums:
        if _digest(algorithm, data) != expected:
            raise Failed(f"{item.url}: does not match the lock's {algorithm} for {item.name} ({expected})")


def download_input(item: LockedInput, sources: Sources) -> bool:
    """Make sure the cache holds the locked input, by sha256; True when it was downloaded."""
    present = archive.cached(sources.cache, item.sha256)
    if present is not None:
        verified_input(item, present.read_bytes())
        return False
    try:
        data = sources.read(item.url)
    except (OSError, ValueError) as error:
        raise Failed(f"{item.url}: cannot be read: {error}") from None
    verified_input(item, data)
    archive.store(sources.cache, data)
    return True


# ---- a vendor's signed checksum list ------------------------------------------------------------------


NOTES: Final = "vouched"
"""`<cache>/vouched/<input sha256>.json`: which signed list vouched for an input, and which signature."""

NOTED: Final = ("list", "signature", "index")
"""What a note names, in this order: the signed file (a checksum list, or a repository's InRelease or Release),
its detached signature when it has one, and, for a vendor .deb, the Packages index the Release vouched for."""


def note_path(cache: Path, sha256: str) -> Path:
    return cache / NOTES / f"{sha256}.json"


def _remote(value: object) -> records.Remote | None:
    if not isinstance(value, dict):
        return None
    uri, sha256 = value.get("uri"), value.get("sha256")
    ok = isinstance(uri, str) and isinstance(sha256, str) and re.fullmatch("[0-9a-f]{64}", sha256)
    return records.Remote(str(uri), str(sha256)) if ok else None


def vouched_by(cache: Path, sha256: str) -> tuple[records.Remote, ...]:
    """The signed files `fetch` verified for the input with this sha256, as provenance names dependencies: the
    checksum list (or the repository's InRelease), then its detached signature when it has one, then the
    Packages index for a vendor .deb, each with its address and the sha256 of the file in the cache. Empty when
    there is no note or a file it names is not in the cache any more."""
    try:
        note: object = json.loads(note_path(cache, sha256).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    if not isinstance(note, dict) or "list" not in note:
        return ()
    files = [_remote(note.get(key)) for key in NOTED if key in note]
    found = [one for one in files if one is not None]
    ok = len(found) == len(files) and all(archive.cached(cache, one.sha256) is not None for one in found)
    return tuple(found) if ok else ()


def agreement(item: Vouched, text: str) -> str | None:
    """Why the signed list `text` does not vouch for the input's lock checksums; None when it does.

    The list must give the file a checksum of at least one algorithm the lock has, and every checksum of an
    algorithm both have must be equal."""
    try:
        given = listed(text, sums_name(item.entry.url, item.sums_url))
    except ValueError as error:
        return str(error)
    ours = dict(item.entry.checksums)
    common = sorted(set(given) & set(ours))
    if not common:
        return f"the signed list gives {sorted(given)} for the file and the lock has {sorted(ours)}: nothing to compare"
    wrong = [
        f"{name} {given[name]} in the list, {ours[name]} in the lock" for name in common if given[name] != ours[name]
    ]
    return "the signed list and the lock disagree: " + "; ".join(wrong) if wrong else None


def read_url(url: str, sources: Sources) -> bytes:
    try:
        return sources.read(url)
    except (OSError, ValueError) as error:
        raise Failed(f"{url}: cannot be read: {error}") from None


def judged(item: Vouched, ring: bytes, data: bytes, signature: bytes | None) -> None:
    """Failed naming the list's URL unless its signature verifies with `ring` and it vouches for the input."""
    try:
        text = gpgv(ring, data, signature).decode("utf-8")
    except ValueError as error:  # gpgv's refusals and a text that is not UTF-8
        raise Failed(f"{item.sums_url}: {error}") from None
    problem = agreement(item, text)
    if problem is not None:
        raise Failed(f"{item.sums_url}: {problem}")


def check_vouched(item: Vouched, sources: Sources) -> bool:
    """Make sure the vendor's signed list vouches for the locked checksum; True when it was downloaded.

    The list is verified with the keyring entry (read from the cache, where `download_input` checked it
    against the lock's checksum) and must give the file the lock's checksum. A copy in the cache is verified
    again, never trusted; one that no longer verifies is replaced by a fresh download. Raises Failed naming
    the list's URL."""
    keyring_file = archive.cached(sources.cache, item.keyring.sha256)
    if keyring_file is None:
        raise Failed(f"{item.keyring.url}: the keyring is not in the cache {sources.cache}")
    try:
        ring = dearmor(keyring_file.read_bytes())
    except ValueError as error:
        raise Failed(f"{item.keyring.url}: {error}") from None
    noted = vouched_by(sources.cache, item.entry.sha256)
    kept = [archive.cached(sources.cache, one.sha256) for one in noted]
    if noted and noted[0].uri == item.sums_url and len(noted) == (1 if item.sums_sig_url is None else 2):
        blobs = [path.read_bytes() for path in kept if path is not None]
        try:
            judged(item, ring, blobs[0], blobs[1] if len(blobs) > 1 else None)
            return False
        except Failed:
            pass  # a cache is never an authority: the list may have been re-signed, so read it again
    data = read_url(item.sums_url, sources)
    signature = None if item.sums_sig_url is None else read_url(item.sums_sig_url, sources)
    judged(item, ring, data, signature)
    files = {"list": (item.sums_url, data)}
    if signature is not None and item.sums_sig_url is not None:
        files["signature"] = (item.sums_sig_url, signature)
    write_note(sources.cache, item.entry.sha256, files)
    return True


def write_note(cache: Path, sha256: str, files: Mapping[str, tuple[str, bytes]]) -> None:
    """Store every file in the cache and the note naming them (`NOTED` keys to (URL, bytes))."""
    note = {key: {"uri": url, "sha256": archive.store(cache, data).name} for key, (url, data) in files.items()}
    path = note_path(cache, sha256)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(note, sort_keys=True) + "\n", encoding="utf-8")


def cached_reader(cache: Path, noted: Sequence[records.Remote]) -> vendordeb.Read:
    """A reader that serves only the files a note names, from the cache; any other URL cannot be read."""
    files = {one.uri: archive.cached(cache, one.sha256) for one in noted}

    def read(url: str) -> bytes:
        path = files.get(url)
        if path is None:
            raise OSError(f"{url}: not in the cache")
        return path.read_bytes()

    return read


def check_apt(item: AptVouched, sources: Sources, now: datetime.datetime | None = None) -> bool:
    """Make sure the vendor's signed repository vouches for the .deb's locked sha256; True when it was read.

    The keyring comes from the cache (where `download_input` checked it against the lock's checksum). The
    copies a note names are verified again, the whole chain, never trusted; when they no longer verify (a
    Release past its Valid-Until, a rotated key) the chain is read from the repository again. Raises Failed
    naming the URL that fails."""
    keyring_file = archive.cached(sources.cache, item.keyring.sha256)
    if keyring_file is None:
        raise Failed(f"{item.keyring.url}: the keyring is not in the cache {sources.cache}")
    try:
        ring = vendordeb.checked_keyring(item.keyring.url, keyring_file.read_bytes(), dict(item.keyring.checksums))
    except vendordeb.VendorError as error:
        raise Failed(str(error)) from None
    moment = now or datetime.datetime.now(datetime.UTC)
    noted = vouched_by(sources.cache, item.entry.sha256)
    if noted:
        try:
            vendordeb.verify(item.pin, ring, cached_reader(sources.cache, noted), moment, item.architecture)
            return False
        except vendordeb.VendorError:
            pass  # a cache is never an authority: read the repository again
    try:
        verified = vendordeb.verify(item.pin, ring, sources.read, moment, item.architecture)
    except vendordeb.VendorError as error:
        raise Failed(f"{item.entry.name}: {error}") from None
    files = dict(zip(("list", "signature"), verified.signed, strict=False))
    write_note(sources.cache, item.entry.sha256, {**files, "index": verified.index})
    return True


def input_path(cache: Path, fields: Mapping[str, object]) -> Path:
    """The cached file of a locked input, from its `build_fields`; the build copies it into the container.

    Raises Failed when `fetch` has not stored it (or the file in the cache no longer hashes to its name).
    """
    sha256 = fields.get("sha256")
    if not isinstance(sha256, str) or not re.fullmatch("[0-9a-f]{64}", sha256):
        raise Failed("a locked input needs a sha256 to be found in the cache: `lock checksums` adds one")
    path = archive.cached(cache, sha256)
    if path is None:
        raise Failed(f"input {fields.get('url', sha256)} is not in the cache {cache}: run `fetch` first")
    return path


# ---- the partial mirror -----------------------------------------------------------------------------


def mirror_dir(cache: Path, snapshot: str) -> Path:
    """Where the partial mirror of a snapshot lives: `<cache>/mirror/<snapshot>`, read by the build as `file:`."""
    return cache / "mirror" / snapshot


def place(source: Path, target: Path) -> None:
    """Put `source` at `target` as a hard link (a copy across devices), replacing what is there.

    A file already identical is left alone. Never a symlink: the build bind-mounts the mirror into a container.
    """
    if target.is_file() and not target.is_symlink() and (target.samefile(source) or filecmp.cmp(source, target, False)):
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=target.parent, prefix=".tmp-")
    os.close(fd)
    temp = Path(name)
    try:
        temp.unlink()
        try:
            os.link(source, temp)
        except OSError:
            shutil.copyfile(source, temp)
        os.replace(temp, target)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def lay_out_pool(mirror: Path, cache: Path, files: Mapping[Package, PoolFile]) -> int:
    """Every pool file at `<mirror>/<archive>/<Filename>`, linked from the cache; how many files that is."""
    placed = 0
    for pool in files.values():
        source = archive.cache_path(cache, pool.sha256)
        for archive_, _base_url, filename in pool.locations:
            place(source, mirror / archive_ / filename)
            placed += 1
    return placed


# ---- the command --------------------------------------------------------------------------------------


def load_plan(path: Path) -> FetchPlan:
    try:
        return fetch_plan(read_plan(path))
    except OSError as error:
        raise Failed(f"{path}: {error.strerror or error}") from None
    except ValueError as error:
        raise Failed(f"{path}: {error}") from None


def open_indices(plan: FetchPlan, sources: Sources) -> list[archive.SuiteIndex]:
    try:
        return [
            archive.fetch_suite(
                resolve.snapshot_base(sources.service, one.archive, plan.snapshot),
                one.dist,
                plan.components,
                plan.architecture,
                sources.keyring,
                sources.cache,
                sources.read,
            )
            for one in resolve.suites(plan.suite)
        ]
    except (archive.ArchiveError, OSError, ValueError) as error:
        raise Failed(str(error)) from None


def fetch_command(plan_path: Path, sources: Sources, *, bundle: bool, out: TextIO) -> int:
    """`fetch`: indices, pool files, locked inputs and the partial mirror. Returns the exit status (0)."""
    if bundle:
        raise Usage("inputs bundles arrive in a later release (milestone M6)")
    plan = load_plan(plan_path)
    indices = open_indices(plan, sources)
    try:
        found, problems = pool_files(indices, plan.packages)
    except ValueError as error:
        raise Failed(f"a Packages index is malformed: {error}") from None
    if problems:
        raise Failed("\n".join(problems))
    fetched = reused = 0
    for package, pool in sorted(found.items()):
        try:
            if download_pool_file(package, pool, sources):
                fetched += 1
            else:
                reused += 1
        except Failed as error:
            problems.append(str(error))
    inputs_fetched = inputs_reused = 0
    for item in plan.inputs:
        try:
            if download_input(item, sources):
                inputs_fetched += 1
            else:
                inputs_reused += 1
        except Failed as error:
            problems.append(str(error))
    vouched_fetched = vouched_reused = 0
    if not problems:  # the keyrings are in the cache only when every input was
        for vouch in plan.vouched:
            try:
                if check_vouched(vouch, sources):
                    vouched_fetched += 1
                else:
                    vouched_reused += 1
            except Failed as error:
                problems.append(str(error))
        for apt in plan.apt:
            try:
                if check_apt(apt, sources):
                    vouched_fetched += 1
                else:
                    vouched_reused += 1
            except Failed as error:
                problems.append(str(error))
    if problems:
        raise Failed("\n".join(problems))
    mirror = mirror_dir(sources.cache, plan.snapshot)
    try:
        archive.lay_out_mirror(indices, mirror)
        lay_out_pool(mirror, sources.cache, found)
    except (archive.ArchiveError, OSError) as error:
        raise Failed(f"cannot lay out the mirror {mirror}: {error}") from None
    print(f"suites: {len(indices)} verified at snapshot {plan.snapshot}", file=out)
    print(f"packages: {fetched} fetched, {reused} already cached ({len(found)} in all)", file=out)
    print(f"inputs: {inputs_fetched} fetched, {inputs_reused} already cached ({len(plan.inputs)} in all)", file=out)
    if plan.vouched or plan.apt:
        print(
            f"signed checksum lists: {vouched_fetched} fetched, {vouched_reused} already cached "
            f"({len(plan.vouched) + len(plan.apt)} in all), each verified with its keyring",
            file=out,
        )
    print(f"mirror: {mirror}", file=out)
    return 0
