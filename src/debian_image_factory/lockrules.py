"""What the factory asks of a lock beyond input-lock's own checks (DESIGN 6.1).

input-lock owns the format: `input_lock.problems` checks it, and is called here with the
definition's image names so every `used_by` must name a real image. On top of it the factory adds
only what needs the definition:

- every entry names its images in `used_by` (optional in input-lock, required here), except the
  reserved entries, which name none;
- `module`, when set, names a module the definition declares;
- `debian_snapshot` is present;
- the baseline snapshot, when an image's `apt_sources` points at it, is the reserved entry
  `debian-baseline`: its `version` is the snapshot ID and it pins the debian archive's `InRelease`
  for the suite at that ID by sha256 (input-lock 0.1 has no top-level field for a second snapshot).

Pure functions over the lock's data and a parsed definition. `SNAPSHOT_ID` and `entry_problems`
come from `input_lock.lock`, outside the package's `__all__`: the pinned version is what they are
read from, and a test fails if a new release moves them.
"""

from collections.abc import Mapping
from typing import Final, cast

import input_lock
from input_lock import Entry, JsonValue, Lock
from input_lock.lock import SNAPSHOT_ID
from input_lock.lock import entry_problems as entry_format_problems

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


def problems(data: JsonValue, definition: Definition) -> list[str]:
    """Every way `data` is not a lock this definition can build from; [] when it is one."""
    found = input_lock.problems(data, images=definition.images)
    if not isinstance(data, dict):
        return found
    if "debian_snapshot" not in data:
        found.append("debian_snapshot is required: the build snapshot (`lock snapshot --latest` writes it)")
    inputs = data.get("inputs")
    if isinstance(inputs, dict):
        for name, raw in sorted(inputs.items()):
            if isinstance(raw, dict) and not entry_format_problems(name, raw):
                # input-lock found this entry well formed, so its fields are strings, lists of names or null
                found.extend(entry_problems(name, cast(Entry, raw), definition))
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
