"""Finding a snapshot ID and a private key in a stream of chunks, pure.

A match may straddle two chunks, so each chunk is searched together with the tail of the text before it.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

OVERLAP: Final = 128
"""Bytes kept between chunks. At least as long as the longest thing looked for (a key header, its newline
and the first sixteen characters of its body come to 103 bytes; a snapshot ID is 16)."""

KEY_MARKER: Final = b"-----BEGIN "

KEY_BLOCK: Final = re.compile(
    rb"(?<![^\n])-----BEGIN (?:[A-Z0-9]{1,16} ){0,3}PRIVATE KEY(?: BLOCK)?-----[ \t]*\r?\n"
    rb"(?:[A-Za-z0-9+/]{16}|[A-Za-z][A-Za-z-]*: |\r?\n)"
)
"""A private key as a file holds one, not as a document talks about one: the header owns its line, from
its first column, and is followed by the key's own first line (base64, a `Proc-Type:` or armor header,
or the blank line after an armor header). A sentence that quotes the header does not match."""


@dataclass(frozen=True, slots=True)
class Hits:
    needle: bool
    key: bool


def scan(chunks: Iterable[bytes], needle: bytes | None, keys: bool) -> Hits:
    """Whether the bytes hold `needle`, and whether they hold a private key block (when `keys`).

    Stops reading once everything asked for was found.
    """
    found_needle, found_key = False, False
    tail = b"\n"  # the start of the file counts as the start of a line
    for chunk in chunks:
        buffer = tail + chunk
        if needle and not found_needle and needle in buffer:
            found_needle = True
        if keys and not found_key and KEY_MARKER in buffer:
            # a match that starts in the tail was complete in the buffer before: it was judged there
            found_key = any(match.start() > 0 for match in KEY_BLOCK.finditer(buffer))
        if (found_needle or not needle) and (found_key or not keys):
            break
        tail = buffer[-OVERLAP:]
    return Hits(found_needle, found_key)
