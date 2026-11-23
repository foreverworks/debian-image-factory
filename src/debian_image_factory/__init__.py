"""debian-image-factory: Debian images from pinned archive snapshots, rebuilt only when their inputs change.

DESIGN.md is the reference. The pure core (definition, lockrules, snapshots, identity, plan) never
touches files, the network or subprocesses; the edges (resolve, archive, cli) do.
"""

from typing import Final

__version__: Final = "0.8.0"

ENGINE: Final = 1
"""The engine revision: raised only by a change that can alter the bytes the factory writes (DESIGN 7.1)."""
