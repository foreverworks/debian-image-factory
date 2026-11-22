"""The built-in checks for core and OCI artifacts (DESIGN 11) and the `test` command that attests them.

Each check is a pure function of what the edge read: `tarball` and `layers` (streaming passes over a root
filesystem tarball and over an image's layers), `resolution` (apt, offline), and `clones`, `container` and
`dockerio` (rootless docker) are the edges.
"""

from .command import test_command
from .model import CORE_CHECKS, OCI_CHECKS, CheckOutcome, NotRun, Result

__all__ = ["CORE_CHECKS", "OCI_CHECKS", "CheckOutcome", "NotRun", "Result", "test_command"]
