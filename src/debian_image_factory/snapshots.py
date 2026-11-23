"""Choosing and checking snapshot.debian.org IDs (DESIGN 7.5). Pure: no network, no files.

An ID is a timestamp, `YYYYMMDDTHHMMSSZ`. snapshot.debian.org keeps one timeline per archive
(`debian`, `debian-security`), and a build pins one ID for each: the exact ID that archive lists. A
listed ID always serves itself, and the service writes a snapshot's listing row and its whole import in
one database transaction, so a listed ID is complete. A bare ID that is meant for both archives (a lock
that has `debian_snapshot`, `--snapshot <ID>`) is not necessarily listed anywhere, so it keeps the older rule:
it is *completed* when every archive in use lists a snapshot strictly later than it, and it is resolved
to the exact ID each archive serves at it.

A listing is the ascending list of IDs one archive has published, as `listings.py` reads it. After
resolution everything works on `Snapshots`: archive name to the exact ID it lists.
"""

import re
from bisect import bisect_left, bisect_right
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Final

ARCHIVES: Final = ("debian", "debian-security")
"""The snapshot.debian.org archives a build reads, in the order their IDs are joined (`stem`)."""

type Listings = Mapping[str, Sequence[str]]
"""Archive name -> its snapshot IDs, strictly ascending."""

type Snapshots = Mapping[str, str]
"""Archive name -> the exact ID that archive lists: what a build reads."""

type Pin = str | Mapping[str, str]
"""What names the snapshots: one bare ID covering every archive, or an exact ID per archive."""

_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z")
_ID_FORMAT = "%Y%m%dT%H%M%SZ"
CHOICES = ("lock", "latest")
"""The words `plan --snapshot` accepts besides IDs."""


def is_snapshot_id(value: str) -> bool:
    """True for `YYYYMMDDTHHMMSSZ` naming a real UTC time."""
    if not _ID.fullmatch(value):
        return False
    try:
        datetime.strptime(value, _ID_FORMAT)
    except ValueError:
        return False
    return True


def parse_listing(data: object, archive: str) -> tuple[str, ...]:
    """The IDs of `archive` in a `/mr/timestamp/?archive=<name>` answer, checked.

    Raises ValueError naming the problem: wrong shape, an ID that is not a real timestamp, or IDs
    that are not strictly ascending.
    """
    if not isinstance(data, dict):
        raise ValueError(f"listing for {archive}: expected a JSON object, got {type(data).__name__}")
    result = data.get("result")
    if not isinstance(result, dict):
        raise ValueError(f"listing for {archive}: no 'result' object")
    ids = result.get(archive)
    if not isinstance(ids, list):
        raise ValueError(f"listing for {archive}: 'result' has no list for {archive!r}")
    checked: list[str] = []
    for position, value in enumerate(ids):
        if not isinstance(value, str):
            raise ValueError(f"listing for {archive}: entry {position} is not a string")
        if not is_snapshot_id(value):
            raise ValueError(f"listing for {archive}: entry {position} {value!r} is not a snapshot ID")
        if checked and value <= checked[-1]:
            raise ValueError(
                f"listing for {archive}: entry {position} {value} does not come after {checked[-1]}"
                " (not strictly ascending)"
            )
        checked.append(value)
    return tuple(checked)


def served(snapshot_id: str, ids: Sequence[str]) -> str | None:
    """The snapshot `snapshot_id` serves in one archive: the newest listed at or before it.

    None when the archive lists nothing that early, or when `snapshot_id` is not an ID.
    """
    if not is_snapshot_id(snapshot_id):
        return None
    index = bisect_right(ids, snapshot_id)
    return ids[index - 1] if index else None


def _newest(ids: Sequence[str]) -> str | None:
    return ids[-1] if ids else None


def completed(snapshot_id: str, listings: Listings) -> bool:
    """Every archive lists a snapshot strictly later than `snapshot_id`. False without archives."""
    if not listings or not is_snapshot_id(snapshot_id):
        return False
    return all((newest := _newest(ids)) is not None and newest > snapshot_id for ids in listings.values())


def latest_completed(listings: Listings) -> str | None:
    """The newest completed ID: the newest listed timestamp earlier than every archive's newest.

    None when there is none: no archives, an empty listing, or the candidate is earlier than some
    archive's first snapshot (so that archive serves nothing at it).
    """
    if not listings:
        return None
    newest = [_newest(ids) for ids in listings.values()]
    if any(value is None for value in newest):
        return None
    horizon = min(value for value in newest if value is not None)
    best: str | None = None
    for ids in listings.values():
        before = bisect_left(ids, horizon)  # the IDs strictly earlier than the horizon
        if before and (best is None or ids[before - 1] > best):
            best = ids[before - 1]
    if best is None or any(served(best, ids) is None for ids in listings.values()):
        return None
    return best


def problems(snapshot_id: str, listings: Listings) -> list[str]:
    """One sentence per reason `snapshot_id` cannot be used as a build snapshot; empty when it can."""
    if not is_snapshot_id(snapshot_id):
        return [f"{snapshot_id!r} is not a snapshot ID (YYYYMMDDTHHMMSSZ, a real UTC time)"]
    found: list[str] = []
    if not listings:
        found.append("no archive is in use, so nothing can be checked")
    for archive, ids in listings.items():
        newest = _newest(ids)
        if newest is None:
            found.append(f"archive {archive} lists no snapshots")
            continue
        if served(snapshot_id, ids) is None:
            found.append(f"archive {archive} serves nothing at {snapshot_id}: its first snapshot is {ids[0]}")
        if newest <= snapshot_id:
            found.append(
                f"{snapshot_id} is not completed: archive {archive} lists no snapshot after it (its newest is {newest})"
            )
    return found


def serving(snapshot_id: str, listings: Listings) -> dict[str, str | None]:
    """Per archive, the snapshot `snapshot_id` serves there (None: nothing that early)."""
    return {archive: served(snapshot_id, ids) for archive, ids in listings.items()}


def listed(snapshot_id: str, ids: Sequence[str]) -> bool:
    """True when the archive's own listing holds exactly `snapshot_id`."""
    index = bisect_left(ids, snapshot_id)
    return index < len(ids) and ids[index] == snapshot_id


def listed_in_answer(data: object, archive: str, snapshot_id: str) -> bool:
    """Whether a narrow `/mr/timestamp/?archive=<a>&after=<ID>&before=<ID>` answer lists `snapshot_id`.

    The service answers `{"result": {"<archive>": ["<ID>"]}}` when it is listed and `{"result": {}}` when
    it is not. Raises ValueError for any other shape.
    """
    if not isinstance(data, dict) or not isinstance(data.get("result"), dict):
        raise ValueError(f"narrow read for {archive} {snapshot_id}: no 'result' object")
    result: dict[object, object] = data["result"]
    if archive not in result:
        if result:
            raise ValueError(f"narrow read for {archive} {snapshot_id}: 'result' names {sorted(map(str, result))}")
        return False
    return snapshot_id in parse_listing(data, archive)


def latest(listings: Listings) -> dict[str, str]:
    """The newest listed ID of each archive. Raises ValueError when there is none or an archive lists nothing."""
    if not listings:
        raise ValueError("no archive is in use, so there is no snapshot to pick")
    empty = [archive for archive, ids in listings.items() if not ids]
    if empty:
        raise ValueError(f"archive {', '.join(empty)} lists no snapshots")
    return {archive: ids[-1] for archive, ids in listings.items()}


def _whereabouts(snapshot_id: str, ids: Sequence[str]) -> str:
    """Where an ID that an archive does not list lies in its listing, for the message."""
    if not ids:
        return "the archive lists nothing at all"
    if snapshot_id > ids[-1]:
        return f"its newest is {ids[-1]}"
    earlier = served(snapshot_id, ids)
    return f"the nearest listed one before it is {earlier}" if earlier else f"its first is {ids[0]}"


def exact_problems(snapshots: Snapshots, listings: Listings) -> dict[str, list[str]]:
    """Per archive, one sentence for each reason its pinned ID cannot be built from; [] when it can.

    An ID is usable when that archive's own listing holds it: a listed ID serves itself and is complete. An
    ID the listing lacks is refused, never replaced by an earlier one, so a build never uses something
    other than what was pinned.
    """
    found: dict[str, list[str]] = {archive: [] for archive in listings}
    for archive in sorted(set(snapshots) - set(listings)):
        found[archive] = [f"{archive} is not an archive this build reads (it reads {', '.join(listings)})"]
    for archive, ids in listings.items():
        snapshot_id = snapshots.get(archive)
        if snapshot_id is None:
            found[archive] = [f"no snapshot is pinned for archive {archive}"]
        elif not is_snapshot_id(snapshot_id):
            found[archive] = [f"{snapshot_id!r} is not a snapshot ID (YYYYMMDDTHHMMSSZ, a real UTC time)"]
        elif not listed(snapshot_id, ids):
            where = _whereabouts(snapshot_id, ids)
            found[archive] = [f"{snapshot_id} is not listed by archive {archive} ({where})"]
    return found


def stem(snapshots: Snapshots) -> str:
    """The IDs of `ARCHIVES` joined with `_` (`<debian ID>_<debian-security ID>`): one name for a pair of IDs."""
    return "_".join(snapshots[archive] for archive in ARCHIVES)


def parse_pairs(items: Sequence[str], *, partial: bool = False) -> dict[str, str]:
    """`archive=ID` items, checked: a known archive, a real ID, each archive once, and every archive unless
    `partial`. Raises ValueError saying what is wrong."""
    found: dict[str, str] = {}
    for item in items:
        name, sep, value = item.partition("=")
        if not sep:
            raise ValueError(f"{item!r} is not archive=ID (for example debian=20261123T084014Z)")
        if name not in ARCHIVES:
            raise ValueError(f"{name!r} is not an archive: the archives are {', '.join(ARCHIVES)}")
        if not is_snapshot_id(value):
            raise ValueError(f"{name}={value}: {value!r} is not a snapshot ID (YYYYMMDDTHHMMSSZ, a real UTC time)")
        if name in found:
            raise ValueError(f"archive {name} is named twice")
        found[name] = value
    missing = [archive for archive in ARCHIVES if archive not in found]
    if missing and not partial:
        raise ValueError(f"name every archive, archive=ID for {', '.join(missing)} is missing")
    if not found:
        raise ValueError("no archive=ID given")
    return found


def parse_choice(text: str) -> Pin:
    """What `plan --snapshot` asked for: `lock`, `latest`, a bare ID, or `archive=ID` for every archive,
    comma-separated. Raises ValueError saying what is wrong."""
    if text in CHOICES or is_snapshot_id(text):
        return text
    if "=" in text:
        return parse_pairs(text.split(","))
    raise ValueError(
        f"{text!r} is not lock, latest, a snapshot ID or archive=ID pairs "
        f"({','.join(f'{archive}=ID' for archive in ARCHIVES)})"
    )


def parse_ids(values: Sequence[str]) -> Pin:
    """What `lock snapshot --id` was given: one bare ID, or `archive=ID` (repeated or comma-separated), where an
    archive that is not named keeps what the lock holds. Raises ValueError saying what is wrong."""
    items = [part for value in values for part in value.split(",")]
    if len(items) == 1 and is_snapshot_id(items[0]):
        return items[0]
    if any(is_snapshot_id(item) for item in items):
        raise ValueError("a bare snapshot ID covers both archives: it cannot be given with archive=ID")
    return parse_pairs(items, partial=True)


def named(choice: Pin) -> dict[str, str]:
    """The exact IDs a choice names, which the listing may not hold yet and a narrow read can confirm."""
    return {} if isinstance(choice, str) else dict(choice)


def resolve_bare(snapshot_id: str, listings: Listings, label: str) -> dict[str, str]:
    """A bare ID for every archive, under the older rule: every archive lists a snapshot strictly later than
    it. The result is the exact ID each archive serves at it. Raises ValueError naming every problem."""
    issues = problems(snapshot_id, listings)
    if issues:
        raise ValueError(f"{label} snapshot ID {snapshot_id} cannot be used: " + "; ".join(issues))
    return {archive: value for archive, value in serving(snapshot_id, listings).items() if value is not None}


def resolve_exact(snapshots: Snapshots, listings: Listings, label: str) -> dict[str, str]:
    """An exact ID per archive: each must be listed by its own archive. Raises ValueError naming every problem."""
    issues = exact_problems(snapshots, listings)
    found = [f"{archive}: {line}" for archive, lines in issues.items() for line in lines]
    if found:
        raise ValueError(f"{label} snapshots cannot be used: " + "; ".join(found))
    return {archive: snapshots[archive] for archive in listings}


def resolve(choice: Pin, listings: Listings, lock_pin: Pin | None) -> dict[str, str]:
    """What `plan --snapshot <choice>` builds from, as the exact ID of each archive: the lock's (`lock`), the
    newest listed ID of each (`latest`), a bare ID (the older rule, then what each archive serves at it) or
    an exact ID per archive. Raises ValueError, with every problem named, when there is none or an ID cannot
    be used."""
    if choice == "latest":
        return latest(listings)
    if choice == "lock":
        if lock_pin is None:
            raise ValueError("the lock pins no snapshot (`lock snapshot --latest` writes debian_snapshots)")
        pin, label = lock_pin, "the lock's"
    else:
        pin, label = choice, "the"
    if isinstance(pin, str):
        return resolve_bare(pin, listings, label)
    return resolve_exact(pin, listings, label)
