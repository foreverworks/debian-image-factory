"""What each command does, between the pure core and the edges; `cli` only parses arguments.

Every command returns its exit status and writes to the streams it is given: 0 done, 1 a check or
validation failed (every problem named), 2 usage.
"""

import datetime
import hashlib
import json
import os
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

ARCHIVES: Final = ("debian", "debian-security")


def default_cache() -> Path:
    """`$XDG_CACHE_HOME/debian-image-factory`, else `~/.cache/...`, else a directory under the temp dir."""
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "debian-image-factory"
    try:
        return Path.home() / ".cache" / "debian-image-factory"
    except RuntimeError:  # no home directory: a container run with a uid that has no passwd entry
        return Path(tempfile.gettempdir()) / "debian-image-factory-cache"


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


def read_listings(sources: Sources) -> dict[str, tuple[str, ...]]:
    try:
        return listings.fetch_listings(ARCHIVES, base=sources.service, read=sources.read)
    except (OSError, ValueError) as error:
        raise Failed(f"cannot read the snapshot listings from {sources.service}: {error}") from None


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
    found_listings = read_listings(sources)
    problems: list[str] = []
    ids = {"debian_snapshot": lock.get("debian_snapshot", "")}
    baseline = lockrules.baseline(lock)
    if baseline is not None:
        ids[f"inputs.{lockrules.BASELINE_ENTRY}"] = baseline
    for label, snapshot_id in ids.items():
        issues = snapshots.problems(snapshot_id, found_listings)
        problems.extend(f"{label} {snapshot_id}: {issue}" for issue in issues)
        serving = ", ".join(
            f"{name} serves {served}" for name, served in snapshots.serving(snapshot_id, found_listings).items()
        )
        print(f"{label} {snapshot_id}: {'completed' if not issues else 'NOT usable'}; {serving}", file=out)
    if baseline is not None and not problems:
        data = baseline_in_release(sources, loaded.definition.debian.suite, baseline)
        expected = lock["inputs"][lockrules.BASELINE_ENTRY].get("sha256")
        if hashlib.sha256(data).hexdigest() != expected:
            problems.append(
                f"inputs.{lockrules.BASELINE_ENTRY}: the InRelease served at {baseline} does not match its sha256"
            )
    if problems:
        raise Failed("\n".join(problems))
    return 0


def write_lock(lock_path: Path, data: object) -> None:
    lock_path.write_text(input_lock.dump(data))


def lock_snapshot(lock_path: Path, choice: str, sources: Sources, out: TextIO) -> int:
    """Move the build snapshot to the newest completed ID (`latest`) or to a given one."""
    try:
        data = input_lock.parse(read_text(lock_path))
    except input_lock.LockError as error:
        raise Failed(f"{lock_path}: {error}") from None
    found_listings = read_listings(sources)
    try:
        chosen = snapshots.resolve(choice, found_listings, choice)
    except ValueError as error:
        raise Failed(str(error)) from None
    before = data.get("debian_snapshot")
    updated: dict[str, object] = {**data, "debian_snapshot": chosen}
    write_lock(lock_path, updated)
    print(f"debian_snapshot: {before} -> {chosen}" if before != chosen else f"debian_snapshot stays {chosen}", file=out)
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
    lock: Lock, loaded: Loaded, params: Mapping[str, Param], snapshot_id: str, sources: Sources, workdir: Path
) -> dict[str, tuple[Package, ...]]:
    """Every image's package set, top down. A vendor .deb is resolved with the image that installs it, from a
    stanza verified through its repository's signature, in the same transaction as the image's packages."""
    spec = loaded.definition
    arch = spec.debian.architectures[0]
    try:
        opened = resolve.open_archive(
            snapshot_id,
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


def parse_targets(against: Sequence[str]) -> list[published.Target]:
    """The targets, refused before anything is resolved when one is not a target."""
    try:
        return [published.parse_target(target) for target in against]
    except ValueError as error:
        raise Usage(str(error)) from None


def lookups(
    parsed_targets: Sequence[published.Target], loaded: Loaded, inputs: Mapping[str, identity.ImageInputs]
) -> tuple[dict[str, published.Decision], dict[str, list[str]]]:
    debian = loaded.definition.debian
    decisions: dict[str, published.Decision] = {}
    rejected: dict[str, list[str]] = {}
    for name, image_inputs in inputs.items():
        artifacts: list[published.Artifact] = []
        for target in parsed_targets:
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
    snapshot_choice: str,
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
    try:
        snapshot_id = snapshots.resolve(snapshot_choice, read_listings(sources), lock.get("debian_snapshot", ""))
    except ValueError as error:
        raise Failed(str(error)) from None
    previous: object = None
    if previous_path is not None:
        try:
            previous = json.loads(read_text(previous_path))
        except ValueError as error:
            raise Usage(f"--previous {previous_path}: {error}") from None
    with tempfile.TemporaryDirectory(prefix="debian-image-factory-plan-") as scratch:
        resolved = resolve_all(lock, loaded, params, snapshot_id, sources, Path(scratch))
    inputs = compute_inputs(lock, loaded, resolved, params)
    decisions, rejected = lookups(parsed_targets, loaded, inputs)
    document = plan.build_plan(
        loaded.definition,
        snapshot=snapshot_id,
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
