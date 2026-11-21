"""Records about artifacts (DESIGN 8.2): in-toto statements in DSSE envelopes, one per line of
`<digest>.intoto.jsonl`.

input-lock assembles the standard shapes (`input_lock.records`); this module holds what the factory
adds on top. Pure functions.
"""

import base64
import binascii
import json

from input_lock.records import DSSE_PAYLOAD_TYPE


class RecordsError(ValueError):
    """A records file that cannot be read as DSSE envelopes of in-toto statements."""


def decode_statements(text: str) -> list[dict[str, object]]:
    """Every statement in a records file, decoded from its envelope, in file order. Blank lines are
    skipped; a line that is not a DSSE envelope of a JSON object raises RecordsError naming it.
    Nothing here checks a statement's shape: `published.parse_envelopes` does that for lookups."""
    found: list[dict[str, object]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            envelope: object = json.loads(line)
            if not isinstance(envelope, dict) or envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
                raise RecordsError(f"line {number}: not a DSSE envelope of type {DSSE_PAYLOAD_TYPE}")
            payload = envelope.get("payload")
            if not isinstance(payload, str):
                raise RecordsError(f"line {number}: the envelope has no payload")
            statement: object = json.loads(base64.b64decode(payload, validate=True))
        except (json.JSONDecodeError, binascii.Error, UnicodeDecodeError):
            raise RecordsError(f"line {number}: not an envelope holding base64 of a JSON statement") from None
        if not isinstance(statement, dict):
            raise RecordsError(f"line {number}: the statement is not a JSON object")
        found.append({str(key): value for key, value in statement.items()})
    return found
