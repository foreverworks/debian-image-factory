"""What the factory asks of a lock beyond input-lock's own checks (DESIGN 6.1).

input-lock owns the format: `input_lock.problems` checks it, and is called here with the
definition's image names so every `used_by` must name a real image. On top of it the factory adds
only what needs the definition:

- every entry names its images in `used_by` (optional in input-lock, required here), except the
  reserved entries, which name none;
- `module`, when set, names a module the definition declares;
- an entry's `signed_by` keyring is `used_by` every image the entry is: the keyring is a trust root `fetch`
  reads for each of them, and the plan of an image carries it;
- an image that uses a `builtin:node-tarball` module has exactly one release tarball entry (told by its
  rendered url) among the module's entries, and that entry has `signed_by` and `sums_url`
  (`nodejs.tarball_problems`);
- every entry of a `builtin:deb` module but a keyring (an entry some `signed_by` names) has `apt`,
  `registryUrl` and `signed_by` (`vendordeb.entry_problems`): every vendor .deb is signature-checked;
- an image that uses a `builtin:file` module has exactly one of its entries to place, keyrings aside, and an
  unpacked one is a tarball (`filemodule.placed_problems`);
- the build snapshots are present: `debian_snapshot` (one ID for both archives) or `debian_snapshots` (the exact
  ID of each archive the factory reads, `snapshots.ARCHIVES`, and no other);
- the baseline snapshot, when an image's `apt_sources` points at it, is the reserved entry
  `debian-baseline`: its `version` is the snapshot ID and it pins the debian archive's `InRelease`
  for the suite at that ID by sha256 (input-lock 0.1 has no top-level field for a second snapshot).

Pure functions over the lock's data and a parsed definition.
"""

from collections.abc import Mapping
from typing import Final, cast

import input_lock
from input_lock import SNAPSHOT_ID, Entry, JsonValue, Lock
from input_lock import entry_problems as entry_format_problems

from . import filemodule, nodejs, snapshots, vendordeb
from .definition import Definition, Param

FACTORY_ENTRY: Final = "debian-image-factory"
"""Reserved: the factory release itself, read by the Action. Its version enters no identity."""

BASELINE_ENTRY: Final = "debian-baseline"
"""Reserved: the baseline snapshot, for images whose apt sources point at it."""

RESERVED: Final = (BASELINE_ENTRY, FACTORY_ENTRY)

SNAPSHOT_SERVICE: Final = "https://snapshot.debian.org"


def baseline_url(suite: str) -> str:
    """The url template the baseline entry must carry: the debian archive's InRelease at that ID."""
    return f"{SNAPSHOT_SERVICE}/archive/debian/{{version}}/dists/{suite}/InRelease"


def needs_baseline(definition: Definition) -> bool:
    return any(image.apt_sources != "live" for image in definition.images.values())


def reserved_problems(name: str, entry: Entry, definition: Definition) -> list[str]:
    where = f"inputs.{name}"
    found = []
    if input_lock.used_by(entry) is not None:
        found.append(f"{where}: a reserved entry names no images (no used_by)")
    if entry.get("module") is not None:
        found.append(f"{where}: a reserved entry has no module")
    if name == BASELINE_ENTRY:
        version = entry.get("version")
        if not (isinstance(version, str) and SNAPSHOT_ID.fullmatch(version)):
            found.append(f"{where}.version must be a snapshot.debian.org ID (YYYYMMDDTHHMMSSZ)")
        if entry.get("url") != baseline_url(definition.debian.suite):
            found.append(f"{where}.url must be {baseline_url(definition.debian.suite)!r}")
        if "sha256" not in entry:
            found.append(f"{where}: needs the sha256 of that InRelease (`lock baseline --id` writes it)")
    return found


def entry_problems(name: str, entry: Entry, definition: Definition) -> list[str]:
    where = f"inputs.{name}"
    if name in RESERVED:
        return reserved_problems(name, entry, definition)
    found = []
    if input_lock.used_by(entry) is None:
        found.append(f"{where}: no used_by: name the images that install it (one of {sorted(definition.images)})")
    module = entry.get("module")
    if isinstance(module, str) and module not in definition.modules:
        found.append(f"{where}.module names {module!r}, which the definition does not declare")
    return found


def signer_problems(inputs: Mapping[str, Entry]) -> list[str]:
    """Every keyring a `signed_by` names is used by every image the signed entry is."""
    found: list[str] = []
    for name, entry in sorted(inputs.items()):
        signer = entry.get("signed_by")
        keyring = inputs.get(signer) if isinstance(signer, str) else None
        if keyring is None:
            continue  # input-lock names a signed_by that is not an entry
        missing = sorted(set(input_lock.used_by(entry) or []) - set(input_lock.used_by(keyring) or []))
        if missing:
            found.append(
                f"inputs.{name}.signed_by names {signer}, whose used_by lacks {missing}: "
                "the keyring is a trust root that each of those images' plans carries"
            )
    return found


def keyrings(inputs: Mapping[str, Entry]) -> set[str]:
    """The entries some `signed_by` names: trust roots, which a module never installs."""
    return {signer for entry in inputs.values() if isinstance(signer := entry.get("signed_by"), str)}


def module_entries(inputs: Mapping[str, Entry], module: str, image: str) -> dict[str, str]:
    """The entries of `module` that `image` uses, keyrings and reserved entries aside: entry name to rendered url
    (an entry whose url does not render is left to input-lock, which names the placeholder it lacks)."""
    roots = keyrings(inputs)
    found: dict[str, str] = {}
    for name, entry in sorted(inputs.items()):
        if name in RESERVED or name in roots or module_of(entry) != module:
            continue
        if image not in (input_lock.used_by(entry) or []):
            continue
        try:
            found[name] = input_lock.render_url(entry)
        except ValueError:
            continue
    return found


def node_problems(module_name: str, inputs: Mapping[str, Entry], definition: Definition) -> list[str]:
    """For `builtin:node-tarball`: one signed release tarball per image."""
    found: list[str] = []
    for image in sorted(definition.images):
        urls: dict[str, str] = {}
        signed: dict[str, bool] = {}
        for name, entry in sorted(inputs.items()):
            if name in RESERVED or module_of(entry) != module_name or image not in (input_lock.used_by(entry) or []):
                continue
            try:
                urls[name] = input_lock.render_url(entry)
            except ValueError:
                continue  # input-lock names the placeholder it lacks
            signed[name] = "signed_by" in entry and "sums_url" in entry
        if urls:
            found.extend(
                f"images.{image}: module {module_name} ({nodejs.MODULE}): {problem}"
                for problem in nodejs.tarball_problems(urls, signed)
            )
    return found


def deb_problems(module_name: str, inputs: Mapping[str, Entry]) -> list[str]:
    """For `builtin:deb`: every entry but a keyring is a signed apt entry."""
    roots = keyrings(inputs)
    found: list[str] = []
    for name, entry in sorted(inputs.items()):
        if name not in RESERVED and name not in roots and module_of(entry) == module_name:
            found.extend(vendordeb.entry_problems(name, entry))
    return found


def file_problems(module_name: str, inputs: Mapping[str, Entry], definition: Definition) -> list[str]:
    """For `builtin:file`: each image that has entries of the module places exactly one of them."""
    unpack = filemodule.unpacks(definition.modules[module_name].table)
    found: list[str] = []
    for image in sorted(definition.images):
        uses = any(
            module_of(entry) == module_name and image in (input_lock.used_by(entry) or [])
            for name, entry in inputs.items()
            if name not in RESERVED
        )
        if uses:
            found.extend(
                f"images.{image}: module {module_name} ({filemodule.MODULE}): {problem}"
                for problem in filemodule.placed_problems(module_entries(inputs, module_name, image), unpack)
            )
    return found


def module_problems(inputs: Mapping[str, Entry], definition: Definition) -> list[str]:
    """What the builtin modules need of the entries an image gives them. `inputs` are entries input-lock found
    well formed."""
    found: list[str] = []
    for module_name, module in sorted(definition.modules.items()):
        if module.use == nodejs.MODULE:
            found.extend(node_problems(module_name, inputs, definition))
        elif module.use == vendordeb.MODULE:
            found.extend(deb_problems(module_name, inputs))
        elif module.use == filemodule.MODULE:
            found.extend(file_problems(module_name, inputs, definition))
    return found


def snapshot_problems(data: Mapping[str, JsonValue]) -> list[str]:
    """The lock pins the build snapshots: `debian_snapshot` or `debian_snapshots` (input-lock rejects both, and
    a malformed ID or archive name), and the latter names exactly the archives the factory reads."""
    pinned = data.get("debian_snapshots")
    if "debian_snapshot" not in data and pinned is None:
        return [
            "debian_snapshots is required: the build snapshots, one per archive "
            f"({', '.join(snapshots.ARCHIVES)}); `lock snapshot --latest` writes it"
        ]
    if isinstance(pinned, dict) and set(pinned) != set(snapshots.ARCHIVES):
        wrong = sorted(set(pinned) ^ set(snapshots.ARCHIVES))
        return [
            f"debian_snapshots must name exactly {', '.join(snapshots.ARCHIVES)}, the archives a build reads "
            f"(not matching: {', '.join(wrong)})"
        ]
    return []


def problems(data: JsonValue, definition: Definition) -> list[str]:
    """Every way `data` is not a lock this definition can build from; [] when it is one."""
    found = input_lock.problems(data, images=definition.images)
    if not isinstance(data, dict):
        return found
    found.extend(snapshot_problems(data))
    inputs = data.get("inputs")
    if isinstance(inputs, dict):
        well_formed: dict[str, Entry] = {}
        for name, raw in sorted(inputs.items()):
            if isinstance(raw, dict) and not entry_format_problems(name, raw):
                # input-lock found this entry well formed, so its fields are strings, lists of names or null
                entry = cast(Entry, raw)
                well_formed[name] = entry
                found.extend(entry_problems(name, entry, definition))
        found.extend(signer_problems(well_formed))
        found.extend(module_problems(well_formed, definition))
        if needs_baseline(definition) and BASELINE_ENTRY not in inputs:
            users = sorted(name for name, image in definition.images.items() if image.apt_sources != "live")
            found.append(
                f"inputs.{BASELINE_ENTRY} is required: {users} write apt sources at the baseline snapshot "
                "(`lock baseline --id <ID>` adds it)"
            )
    return found


def check(data: JsonValue, definition: Definition) -> Lock:
    """The lock, checked against the definition. Raises input_lock.LockError naming every problem."""
    found = problems(data, definition)
    if found:
        raise input_lock.LockError("\n".join(found))
    return input_lock.parse(input_lock.dump(data), images=definition.images)


def snapshot_pin(lock: Lock) -> snapshots.Pin | None:
    """What the lock pins: `debian_snapshots` (an exact ID per archive), `debian_snapshot` (one bare ID for both)
    or None."""
    pinned = lock.get("debian_snapshots")
    if pinned is not None:
        return dict(pinned)
    return lock.get("debian_snapshot")


def baseline(lock: Lock) -> str | None:
    """The baseline snapshot ID, or None when the lock has none."""
    entry = lock["inputs"].get(BASELINE_ENTRY)
    version = None if entry is None else entry.get("version")
    return version if isinstance(version, str) else None


def module_enabled(definition: Definition, module: str | None, params: Mapping[str, Param]) -> bool:
    """Whether a module is switched on by the parameters (a module without enabled_by always is)."""
    if module is None:
        return True
    enabled_by = definition.modules[module].enabled_by
    return enabled_by is None or params.get(enabled_by) is True


def image_entries(
    lock: Lock, definition: Definition, image: str, params: Mapping[str, Param]
) -> dict[str, dict[str, input_lock.Value]]:
    """The lock entries `image` itself installs: its used_by entries whose module is switched on."""
    return {
        name: entry
        for name, entry in input_lock.entries_for(lock, image).items()
        if name not in RESERVED and module_enabled(definition, module_of(entry), params)
    }


def module_of(entry: Entry) -> str | None:
    module = entry.get("module")
    return module if isinstance(module, str) else None


def deb_entries(
    lock: Lock, definition: Definition, image: str, params: Mapping[str, Param]
) -> dict[str, dict[str, input_lock.Value]]:
    """The vendor .deb entries `image` itself installs: its switched-on `apt` entries of a `builtin:deb` module."""
    return {
        name: entry
        for name, entry in image_entries(lock, definition, image, params).items()
        if (module := module_of(entry)) is not None
        and definition.modules[module].use == vendordeb.MODULE
        and isinstance(entry.get("apt"), str)
    }
