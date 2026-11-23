"""What each command does, between the pure core and the edges; `cli` only parses arguments.

Every command returns its exit status and writes to the streams it is given: 0 done, 1 a check or
validation failed (every problem named), 2 usage.
"""

import datetime
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, TextIO

import input_lock
from input_lock import JsonValue, Lock, Package
from input_lock import cli as input_lock_cli

from . import (
    archive,
    definition,
    identity,
    listings,
    lockrules,
    plan,
    published,
    remote,
    resolve,
    snapshots,
    targets,
    vendordeb,
)
from . import tools as builder
from .definition import Definition, DefinitionError, Param
from .files import read_files
from .identity import FileFact

ARCHIVES: Final = snapshots.ARCHIVES


def default_cache() -> Path:
    """`$XDG_CACHE_HOME/debian-image-factory`, else `~/.cache/...`, else a private directory of the temp dir."""
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "debian-image-factory"
    try:
        return Path.home() / ".cache" / "debian-image-factory"
    except RuntimeError:  # no home directory: a container run with a uid that has no passwd entry
        return private_temp_cache()


def private_temp_cache() -> Path:
    """The cache for a run with no home directory: `debian-image-factory-cache-<uid>` in the temp dir, made
    with mode 0700 and used only when it is a real directory that is the caller's own and closed to others, so
    nobody else can plant files in it. Raises Usage when it is not (set XDG_CACHE_HOME or pass --cache)."""
    uid = os.geteuid()
    path = Path(tempfile.gettempdir()) / f"debian-image-factory-cache-{uid}"
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o077:
        raise Usage(
            f"{path} is not a private directory of this user, so it is not used as the cache: "
            "set XDG_CACHE_HOME or pass --cache"
        )
    return path


class Failed(Exception):  # noqa: N818  # named for its exit status
    """A check or validation failed: the message names every problem, one per line (exit 1)."""


class Usage(Exception):  # noqa: N818  # named for its exit status
    """The command line asked for something this release cannot do (exit 2)."""


@dataclass(frozen=True, slots=True)
class Sources:
    """Where snapshots are read: snapshot.debian.org, or a mirror serving its paths (`--mirror`)."""

    service: str = resolve.SNAPSHOT_SERVICE
    keyring: Path = resolve.DEFAULT_KEYRING
    cache: Path = field(default_factory=default_cache)
    read: Callable[[str], bytes] = field(default=remote.read_url)


@dataclass(frozen=True, slots=True)
class Loaded:
    root: Path
    definition: Definition
    files: Mapping[str, FileFact]
    data: JsonValue


def load(lock_path: Path, definition_path: Path) -> Loaded:
    """The definition, the files it references and the lock's JSON. Raises Failed naming every problem."""
    try:
        parsed = definition.parse(read_text(definition_path))
    except DefinitionError as error:
        raise Failed("\n".join(f"{definition_path}: {line}" for line in str(error).splitlines())) from None
    root = definition_path.resolve().parent
    try:
        files, file_problems = read_files(root, parsed)
    except OSError as error:
        raise Failed(f"{error.filename}: {error.strerror or error}") from None
    try:
        data = input_lock.loads(read_text(lock_path))
    except input_lock.LockError as error:
        raise Failed(f"{lock_path}: {error}") from None
    found = [f"{definition_path.name}: {line}" for line in file_problems]
    found.extend(f"{lock_path.name}: {line}" for line in lockrules.problems(data, parsed))
    if found:
        raise Failed("\n".join(found))
    return Loaded(root, parsed, files, data)


def read_text(path: Path) -> str:
    """A file's text, or Failed naming the file: unreadable and non-UTF-8 files are problems, not tracebacks."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise Failed(f"{path}: {error.strerror or error}") from None
    except UnicodeDecodeError as error:
        raise Failed(f"{path}: not UTF-8 text ({error.reason} at byte {error.start})") from None


def checked_lock(loaded: Loaded) -> Lock:
    return lockrules.check(loaded.data, loaded.definition)


def read_listings(sources: Sources, named: Mapping[str, str] | None = None) -> dict[str, tuple[str, ...]]:
    """Each archive's listing. An ID in `named` that is newer than the listing's newest, which the service
    caches for ten minutes, is confirmed with a narrow read of that ID alone and added when it is listed."""
    try:
        found = listings.fetch_listings(ARCHIVES, base=sources.service, read=sources.read)
        return listings.confirm(found, named or {}, base=sources.service, read=sources.read)
    except (OSError, ValueError) as error:
        raise Failed(f"cannot read the snapshot listings from {sources.service}: {error}") from None


def resolve_snapshots(choice: snapshots.Pin, lock_pin: snapshots.Pin | None, sources: Sources) -> dict[str, str]:
    """The exact ID of each archive that `choice` (`plan --snapshot`) names. Raises Failed naming the problems."""
    pin = lock_pin if choice == "lock" else choice
    found = read_listings(sources, snapshots.named(pin) if pin is not None else None)
    try:
        return snapshots.resolve(choice, found, lock_pin)
    except ValueError as error:
        raise Failed(str(error)) from None


def service_url(sources: Sources, url: str) -> str:
    """A snapshot.debian.org URL, read through the configured service instead."""
    return sources.service.rstrip("/") + url.removeprefix(resolve.SNAPSHOT_SERVICE)


def baseline_in_release(sources: Sources, suite: str, snapshot_id: str) -> bytes:
    """The debian archive's InRelease for `suite` at the baseline ID, signature verified."""
    url = service_url(sources, lockrules.baseline_url(suite).replace("{version}", snapshot_id))
    try:
        data = sources.read(url)
    except OSError as error:
        raise Failed(f"cannot read {url}: {error}") from None
    try:
        archive.verify_in_release(data, sources.keyring, url)
    except archive.ArchiveError as error:
        raise Failed(str(error)) from None
    return data


# ---- lock check, lock snapshot, lock baseline -------------------------------------------------


def bare_report(label: str, snapshot_id: str, found: snapshots.Listings, out: TextIO) -> list[str]:
    """Say whether a bare ID (one for both archives) is completed and what each archive serves at it; the
    problems found, each led by `label`."""
    issues = snapshots.problems(snapshot_id, found)
    serving = ", ".join(f"{name} serves {served}" for name, served in snapshots.serving(snapshot_id, found).items())
    print(f"{label}: {'completed' if not issues else 'NOT usable'}; {serving}", file=out)
    return [f"{label}: {issue}" for issue in issues]


def lock_check(lock_path: Path, definition_path: Path, sources: Sources, offline: bool, out: TextIO) -> int:
    """The lock and the definition agree; unless offline, the snapshot IDs are re-resolved (DESIGN 7.5)."""
    loaded = load(lock_path, definition_path)
    lock = checked_lock(loaded)
    images = len(loaded.definition.images)
    print(
        f"{lock_path.name} and {definition_path.name} agree: {images} images, {len(lock['inputs'])} entries", file=out
    )
    if offline:
        print("snapshot IDs not re-resolved (--offline)", file=out)
        return 0
    pin = lockrules.snapshot_pin(lock)
    found_listings = read_listings(sources, snapshots.named(pin) if pin is not None else None)
    problems: list[str] = []
    if isinstance(pin, str):
        problems.extend(bare_report(f"debian_snapshot {pin}", pin, found_listings, out))
    elif pin is not None:
        for name, issues in snapshots.exact_problems(pin, found_listings).items():
            label = f"debian_snapshots.{name} {pin.get(name, '-')}"
            problems.extend(f"{label}: {issue}" for issue in issues)
            print(f"{label}: {f'completed (listed by {name})' if not issues else 'NOT usable'}", file=out)
    baseline = lockrules.baseline(lock)
    if baseline is not None:
        problems.extend(bare_report(f"inputs.{lockrules.BASELINE_ENTRY} {baseline}", baseline, found_listings, out))
    if baseline is not None and not problems:
        data = baseline_in_release(sources, loaded.definition.debian.suite, baseline)
        expected = lock["inputs"][lockrules.BASELINE_ENTRY].get("sha256")
        if hashlib.sha256(data).hexdigest() != expected:
            problems.append(
                f"inputs.{lockrules.BASELINE_ENTRY}: the InRelease served at {baseline} does not match its sha256"
            )
    if isinstance(pin, str):
        print("(`lock snapshot --latest` pins each archive on its own: debian_snapshots)", file=out)
    if problems:
        raise Failed("\n".join(problems))
    return 0


def write_lock(lock_path: Path, data: object) -> None:
    lock_path.write_text(input_lock.dump(data))


def lock_snapshot(lock_path: Path, choice: snapshots.Pin, sources: Sources, out: TextIO) -> int:
    """Pin the build snapshots: `latest` is the newest listed ID of each archive, a bare ID is resolved to what
    each archive serves at it, and `archive=ID` moves only the archives named. The result is always
    `debian_snapshots`, with `debian_snapshot` removed: the one command that migrates a lock."""
    try:
        data = input_lock.parse(read_text(lock_path))
    except input_lock.LockError as error:
        raise Failed(f"{lock_path}: {error}") from None
    lock_pin = lockrules.snapshot_pin(data)
    named = snapshots.named(choice)
    partial = bool(named) and set(named) != set(ARCHIVES)
    kept_ids = lock_pin if partial and isinstance(lock_pin, Mapping) else {}
    found = read_listings(sources, {**kept_ids, **named})
    try:
        if not partial:
            chosen = snapshots.resolve(choice, found, lock_pin)
        else:
            # some archives named: the others keep what the lock pins, a bare ID resolved to what each serves
            if lock_pin is None:
                raise ValueError(f"the lock pins no snapshot to keep: name every archive ({', '.join(ARCHIVES)})")
            kept = snapshots.resolve("lock", found, lock_pin)
            chosen = snapshots.resolve({**kept, **named}, found, None)
    except ValueError as error:
        raise Failed(str(error)) from None
    old_bare = data.get("debian_snapshot")
    before = dict(data.get("debian_snapshots", {})) or dict.fromkeys(ARCHIVES, old_bare)
    kept_fields = {key: value for key, value in data.items() if key not in ("debian_snapshot", "debian_snapshots")}
    write_lock(lock_path, {**kept_fields, "debian_snapshots": chosen})
    if old_bare is not None:
        print(f"debian_snapshot {old_bare} -> debian_snapshots (one ID for each archive)", file=out)
    for name, snapshot_id in chosen.items():
        was = before.get(name)
        print(
            f"debian_snapshots.{name}: {was} -> {snapshot_id}"
            if was != snapshot_id
            else f"debian_snapshots.{name} stays {snapshot_id}",
            file=out,
        )
    return 0


def lock_checksums(lock_path: Path, definition_path: Path, entries: Sequence[str], base: str | None) -> int:
    """input-lock's `refresh` on a lock the definition agrees with: the checksums of the named entries, or of
    the ones whose version moved since the git ref `base`, downloaded and verified (a `deb` entry through
    its vendor's signed InRelease). input-lock writes nothing unless every entry verified; the definition is
    checked against the result again, so a refresh never leaves a lock `plan` would refuse."""
    checked_lock(load(lock_path, definition_path))
    if not entries and base is None:
        raise Usage("lock checksums needs --entry NAME (repeat) or --base REF (the branch a bump goes into)")
    argv = ["refresh", "--lock", str(lock_path)]
    argv += ["--base", base] if base is not None else []
    for name in entries:
        argv += ["--entry", name]
    status = input_lock_cli.main(argv)
    if status == 0:
        checked_lock(load(lock_path, definition_path))
    return status


def lock_baseline(lock_path: Path, definition_path: Path, snapshot_id: str, sources: Sources, out: TextIO) -> int:
    """Move the baseline snapshot: the reserved entry's version and the sha256 of its InRelease."""
    try:
        parsed = definition.parse(read_text(definition_path))
        data = input_lock.parse(read_text(lock_path))
    except (DefinitionError, input_lock.LockError) as error:
        raise Failed(str(error)) from None
    issues = snapshots.problems(snapshot_id, read_listings(sources))
    if issues:
        raise Failed(f"baseline {snapshot_id} cannot be used: " + "; ".join(issues))
    in_release = baseline_in_release(sources, parsed.debian.suite, snapshot_id)
    entry: dict[str, input_lock.Value] = {
        "description": "The baseline snapshot: apt sources written into images that ask for them point here.",
        "sha256": hashlib.sha256(in_release).hexdigest(),
        "url": lockrules.baseline_url(parsed.debian.suite),
        "version": snapshot_id,
    }
    before = lockrules.baseline(data)
    write_lock(lock_path, {**data, "inputs": {**data["inputs"], lockrules.BASELINE_ENTRY: entry}})
    print(f"baseline: {before} -> {snapshot_id}", file=out)
    return 0


# ---- plan -------------------------------------------------------------------------------------


def given_params(pairs: Sequence[str], params_file: Path | None) -> dict[str, str]:
    """`--params FILE` (a JSON object) overlaid with every `--param NAME=VALUE`, as text."""
    given: dict[str, str] = {}
    if params_file is not None:
        try:
            raw: object = json.loads(params_file.read_text())
        except (OSError, ValueError) as error:
            raise Usage(f"--params {params_file}: {error}") from None
        if not isinstance(raw, dict):
            raise Usage(f"--params {params_file}: a JSON object of parameter values")
        for name, value in raw.items():
            if isinstance(value, bool):
                given[str(name)] = "true" if value else "false"
            elif isinstance(value, str | int):
                given[str(name)] = str(value)
            else:
                raise Usage(f"--params {params_file}: {name} must be a string, an integer or a boolean")
    for pair in pairs:
        name, sep, value = pair.partition("=")
        if not sep:
            raise Usage(f"--param {pair}: NAME=VALUE")
        given[name] = value
    return given


CHILD_ONLY: Final = ("builtin:deb", "builtin:file")
"""Modules a core image cannot use: mmdebstrap builds core, and the module install step runs in a child build."""


def unsupported_modules(lock: Lock, loaded: Loaded, params: Mapping[str, Param]) -> list[str]:
    found = []
    for image, spec in loaded.definition.images.items():
        if spec.kind != "core":
            continue
        for module in identity.modules_used(lock, loaded.definition, image, params):
            use = loaded.definition.modules[module].use
            if use in CHILD_ONLY:
                found.append(
                    f"images.{image}: module {module} ({use}) installs into child images only: "
                    "give its entries to an image derived from core"
                )
    return found


def keyring_of(lock: Lock, name: str, sources: Sources) -> bytes:
    """The keyring entry `name`, read through `sources`, checked against the lock's checksums, unarmored."""
    entry = lock["inputs"].get(name)
    if entry is None:
        raise Failed(f"signed_by names {name}, which is not an entry of the lock")
    url = input_lock.render_url(entry)
    try:
        data = sources.read(url)
    except (OSError, ValueError) as error:
        raise Failed(f"{url}: cannot be read: {error}") from None
    try:
        return vendordeb.checked_keyring(url, data, input_lock.checksums(entry))
    except vendordeb.VendorError as error:
        raise Failed(str(error)) from None


def verified_debs(
    lock: Lock, entries: Mapping[str, Mapping[str, input_lock.Value]], sources: Sources, arch: str
) -> list[vendordeb.Verified]:
    """Every vendor .deb entry, checked through its repository's signed InRelease (`vendordeb.verify`)."""
    rings: dict[str, bytes] = {}
    found: list[vendordeb.Verified] = []
    now = datetime.datetime.now(datetime.UTC)
    for name, entry in sorted(entries.items()):
        signer = str(entry.get("signed_by"))
        if signer not in rings:
            rings[signer] = keyring_of(lock, signer, sources)
        pin = vendordeb.pin_of(name, input_lock.build_fields(entry), str(entry.get("registryUrl")))
        try:
            found.append(vendordeb.verify(pin, rings[signer], sources.read, now, arch))
        except vendordeb.VendorError as error:
            raise Failed(f"inputs.{name}: {error}") from None
    return found


def resolve_all(
    lock: Lock,
    loaded: Loaded,
    params: Mapping[str, Param],
    snapshot_ids: snapshots.Snapshots,
    sources: Sources,
    workdir: Path,
) -> dict[str, tuple[Package, ...]]:
    """Every image's package set, top down. A vendor .deb is resolved with the image that installs it, from a
    stanza verified through its repository's signature, in the same transaction as the image's packages."""
    spec = loaded.definition
    arch = spec.debian.architectures[0]
    try:
        opened = resolve.open_archive(
            snapshot_ids,
            spec.debian.suite,
            spec.debian.components,
            arch,
            keyring=sources.keyring,
            cache=sources.cache,
            workdir=workdir,
            service=sources.service,
            read=sources.read,
        )
        resolved: dict[str, tuple[Package, ...]] = {}
        vendor: dict[Package, Mapping[str, str]] = {}
        for name in definition.top_down(spec):
            image = spec.images[name]
            if image.parent is None:
                resolved[name] = resolve.resolve_core(opened, image.packages)
                kernels = [p[0] for p in resolved[name] if definition.KERNEL.fullmatch(p[0])]
                if kernels:
                    raise Failed(
                        f"images.{name}: core resolves to a kernel ({', '.join(kernels)}); core never installs one"
                    )
            else:
                asked = plan.request(spec, name, identity.modules_used(lock, spec, name, params))
                debs = verified_debs(lock, lockrules.deb_entries(lock, spec, name, params), sources, arch)
                own = [one.stanza for one in debs]
                resolved[name] = resolve.resolve_child(
                    opened, resolved[image.parent], asked, name, own=own, vendor=vendor
                )
                vendor.update({vendordeb.package_of(one): one.stanza for one in debs})
    except (archive.ArchiveError, resolve.ResolveError, OSError, ValueError, KeyError) as error:
        raise Failed(str(error)) from None
    return resolved


def parse_targets(against: Sequence[str]) -> list[published.TargetTemplate]:
    """The targets, refused before anything is resolved when one is not a target. An `oci://` repository may
    carry `{image}` (`published.IMAGE_PLACEHOLDER`): `target_for` says what it is for one image."""
    try:
        return [published.parse_template(target) for target in against]
    except ValueError as error:
        raise Usage(str(error)) from None


def target_for(template: published.TargetTemplate, image: str) -> published.Target:
    """The target `template` is for `image`. Raises Usage when the image's name makes no repository."""
    try:
        return published.resolve_template(template, image)
    except ValueError as error:
        raise Usage(str(error)) from None


def lookups(
    parsed_targets: Sequence[published.TargetTemplate], loaded: Loaded, inputs: Mapping[str, identity.ImageInputs]
) -> tuple[dict[str, published.Decision], dict[str, list[str]]]:
    debian = loaded.definition.debian
    decisions: dict[str, published.Decision] = {}
    rejected: dict[str, list[str]] = {}
    for name, image_inputs in inputs.items():
        artifacts: list[published.Artifact] = []
        for template in parsed_targets:
            target = target_for(template, name)
            try:
                found = targets.lookup(target, name, debian.suite, debian.architectures[0], image_inputs.identity)
            except OSError as error:
                raise Failed(f"cannot read target {target}: {error.strerror or error}") from None
            artifacts.extend(found.artifacts)
            rejected.setdefault(name, []).extend(f"{one.name}: {one.reason}" for one in found.rejected)
        required = definition.required_checks(loaded.definition, name, bool(image_inputs.entries))
        decisions[name] = published.decide(artifacts, required)
    return decisions, {name: reasons for name, reasons in rejected.items() if reasons}


def compute_inputs(
    lock: Lock, loaded: Loaded, resolved: Mapping[str, Sequence[Package]], params: Mapping[str, Param]
) -> dict[str, identity.ImageInputs]:
    tools = builder.builder_tools()
    baseline = lockrules.baseline(lock)
    inputs: dict[str, identity.ImageInputs] = {}
    for name in definition.top_down(loaded.definition):
        parent = loaded.definition.images[name].parent
        inputs[name] = identity.image_inputs(
            lock,
            loaded.definition,
            name,
            packages=resolved[name],
            tools=tools,
            files=loaded.files,
            params=params,
            baseline=baseline,
            parent_identity=None if parent is None else inputs[parent].identity,
        )
    return inputs


def plan_command(
    lock_path: Path,
    definition_path: Path,
    sources: Sources,
    *,
    snapshot_choice: snapshots.Pin,
    param_pairs: Sequence[str],
    params_file: Path | None,
    against: Sequence[str],
    rebuild: Mapping[str, str],
    previous_path: Path | None,
    out: TextIO,
) -> int:
    loaded = load(lock_path, definition_path)
    lock = checked_lock(loaded)
    try:
        params = definition.resolve_params(loaded.definition, given_params(param_pairs, params_file))
    except ValueError as error:
        raise Usage(str(error)) from None
    unknown = sorted(set(rebuild) - set(loaded.definition.images))
    if unknown:
        raise Usage(f"--rebuild names {unknown}, which are not images")
    parsed_targets = parse_targets(against)
    unsupported = unsupported_modules(lock, loaded, params)
    if unsupported:
        raise Failed("\n".join(unsupported))
    snapshot_ids = resolve_snapshots(snapshot_choice, lockrules.snapshot_pin(lock), sources)
    previous: object = None
    if previous_path is not None:
        try:
            previous = json.loads(read_text(previous_path))
        except ValueError as error:
            raise Usage(f"--previous {previous_path}: {error}") from None
    with tempfile.TemporaryDirectory(prefix="debian-image-factory-plan-") as scratch:
        resolved = resolve_all(lock, loaded, params, snapshot_ids, sources, Path(scratch))
    inputs = compute_inputs(lock, loaded, resolved, params)
    decisions, rejected = lookups(parsed_targets, loaded, inputs)
    document = plan.build_plan(
        loaded.definition,
        snapshots=snapshot_ids,
        baseline=lockrules.baseline(lock),
        params=params,
        inputs=inputs,
        decisions=decisions,
        rejected=rejected,
        rebuild=rebuild,
        previous=previous,
    )
    out.write(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    return 0
