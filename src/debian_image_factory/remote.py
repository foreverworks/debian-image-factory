"""The network edge: one function that reads a URL. Nothing in the pure core imports this module.

What comes back is trusted only after the caller checks it (a signature, a checksum, a listing's
shape): a mirror or cache is a performance layer, never an authority (DESIGN 7.7).
"""

import urllib.request
from typing import Final

SCHEMES: Final = ("https://", "http://", "file:")
"""http is allowed for archive reads only because apt-style signatures and hashes vouch for them."""

USER_AGENT: Final = "debian-image-factory"


def read_url(url: str, timeout: float = 120) -> bytes:
    """The bytes at `url`. Raises OSError (urllib.error.URLError included) when it cannot be read."""
    if not url.startswith(SCHEMES):
        raise ValueError(f"refusing to read {url!r}: only {', '.join(SCHEMES)} URLs are read")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data: bytes = response.read()
    return data
