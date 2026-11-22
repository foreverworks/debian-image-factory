"""The network edge: one function that reads a URL. Nothing in the pure core imports this module.

What comes back is trusted only after the caller checks it (a signature, a checksum, a listing's
shape): a mirror or cache is a performance layer, never an authority (DESIGN 7.7).
"""

import urllib.request
from typing import Final

SCHEMES: Final = ("https://", "http://", "file:")
"""http is allowed for archive reads only because apt-style signatures and hashes vouch for them."""

READ_LIMIT: Final = 1 << 30
"""The most bytes one URL may give: a gigabyte, above any package, index or tool tarball a build reads, so a
server that never stops answering cannot fill the memory. The whole answer is held in memory, as callers
verify it by checksum before they use it."""

USER_AGENT: Final = "debian-image-factory"


def read_url(url: str, timeout: float = 120, limit: int = READ_LIMIT) -> bytes:
    """The bytes at `url`. Raises OSError (urllib.error.URLError included) when it cannot be read or when
    the answer is longer than `limit` bytes."""
    if not url.startswith(SCHEMES):
        raise ValueError(f"refusing to read {url!r}: only {', '.join(SCHEMES)} URLs are read")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data: bytes = response.read(limit + 1)
    if len(data) > limit:
        raise OSError(f"{url} answers with more than {limit} bytes, the most one read takes")
    return data
