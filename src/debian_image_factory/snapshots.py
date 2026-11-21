"""Choosing and checking snapshot.debian.org IDs (DESIGN 7.5). Pure: no network, no files.

An ID is a timestamp, `YYYYMMDDTHHMMSSZ`. snapshot.debian.org keeps one timeline per archive
(`debian`, `debian-security`) and serves an ID as each archive's newest snapshot at or before it.
An ID is *completed* when every archive in use lists a snapshot strictly later than it: what it
serves in each archive can then no longer change.

A listing is the ascending list of IDs one archive has published, as `listings.py` reads it.
"""

import re
from bisect import bisect_left, bisect_right
from collections.abc import Mapping, Sequence
from datetime import datetime

type Listings = Mapping[str, Sequence[str]]
"""Archive name -> its snapshot IDs, strictly ascending."""

_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z")
_ID_FORMAT = "%Y%m%dT%H%M%SZ"
CHOICES = ("lock", "latest")
"""The words `plan --snapshot` accepts besides an ID."""


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


def resolve(choice: str, listings: Listings, lock_id: str) -> str:
    """The ID `plan --snapshot <choice>` builds from: the lock's (`lock`), the newest completed
    (`latest`) or the ID given. Raises ValueError, with every problem named, when there is none or
    the ID cannot be used (not completed, or an archive serves nothing at it).
    """
    if choice == "latest":
        found = latest_completed(listings)
        if found is None:
            raise ValueError("no completed snapshot ID exists in the listings")
        return found
    chosen = lock_id if choice == "lock" else choice
    issues = problems(chosen, listings)
    if issues:
        label = "the lock's snapshot ID" if choice == "lock" else "snapshot ID"
        raise ValueError(f"{label} {chosen} cannot be used: " + "; ".join(issues))
    return chosen
