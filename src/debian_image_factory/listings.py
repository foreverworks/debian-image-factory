"""The network edge for snapshot listings (DESIGN 7.5): read `/mr/timestamp/` answers, live or recorded.

Whatever is read goes through `snapshots.parse_listing` before anything trusts it.
"""

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Final

from debian_image_factory import remote
from debian_image_factory.snapshots import parse_listing

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
