"""The network edge for snapshot listings (DESIGN 7.5): read `/mr/timestamp/` answers, live or recorded.

Whatever is read goes through `snapshots.parse_listing` before anything trusts it. The service caches a
listing for ten minutes, so an ID that is named explicitly and is newer than the newest the listing holds is
confirmed with a narrow read of just that ID (`confirm`), at a URL no cache has seen.
"""

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final

from debian_image_factory import remote
from debian_image_factory.snapshots import is_snapshot_id, listed_in_answer, parse_listing

BASE: Final = "https://snapshot.debian.org"


def fetch_listings(
    archives: Sequence[str],
    base: str = BASE,
    read: Callable[[str], bytes] = remote.read_url,
) -> dict[str, tuple[str, ...]]:
    """Each archive's listing from `<base>/mr/timestamp/?archive=<name>`, checked.

    Raises OSError when a read fails and ValueError when an answer is not a listing.
    """
    found: dict[str, tuple[str, ...]] = {}
    for archive in archives:
        raw = read(f"{base.rstrip('/')}/mr/timestamp/?archive={archive}")
        try:
            data: object = json.loads(raw)
        except ValueError as error:
            raise ValueError(f"listing for {archive}: not JSON ({error})") from error
        found[archive] = parse_listing(data, archive)
    return found


def narrow_url(archive: str, snapshot_id: str, base: str = BASE) -> str:
    """The read that asks whether one archive lists exactly `snapshot_id`: `after` and `before` are inclusive."""
    return f"{base.rstrip('/')}/mr/timestamp/?archive={archive}&after={snapshot_id}&before={snapshot_id}"


def confirm(
    found: Mapping[str, tuple[str, ...]],
    named: Mapping[str, str],
    base: str = BASE,
    read: Callable[[str], bytes] = remote.read_url,
) -> dict[str, tuple[str, ...]]:
    """`found` with each named ID that is newer than its archive's newest listed one added when a narrow read
    says the archive lists it. An older ID needs no read: the listing is cached, never ahead, so an older ID
    it lacks is not listed. Raises OSError when a read fails and ValueError when an answer is not a listing.
    """
    confirmed = dict(found)
    for archive, snapshot_id in sorted(named.items()):
        ids = found.get(archive)
        if ids is None or not is_snapshot_id(snapshot_id) or (ids and ids[-1] >= snapshot_id):
            continue
        raw = read(narrow_url(archive, snapshot_id, base))
        try:
            data: object = json.loads(raw)
        except ValueError as error:
            raise ValueError(f"narrow read for {archive} {snapshot_id}: not JSON ({error})") from error
        if listed_in_answer(data, archive, snapshot_id):
            confirmed[archive] = (*ids, snapshot_id)
    return confirmed


def load_listings(directory: Path) -> dict[str, tuple[str, ...]]:
    """The recorded listings in `directory`: one `<archive>.json` per archive, in the service's format."""
    found: dict[str, tuple[str, ...]] = {}
    for path in sorted(directory.glob("*.json")):
        found[path.stem] = parse_listing(json.loads(path.read_text()), path.stem)
    return found


def trim(data: object, archive: str, after: str) -> dict[str, object]:
    """A listing answer in the service's own shape, keeping only the IDs `after` and later.

    Used to record test fixtures: the full listings run to tens of thousands of IDs.
    """
    kept = [value for value in parse_listing(data, archive) if value >= after]
    return {"_comment": "trimmed copy of a snapshot.debian.org listing", "result": {archive: kept}}
