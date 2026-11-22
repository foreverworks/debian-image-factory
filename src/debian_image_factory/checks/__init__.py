"""The built-in checks for core artifacts (DESIGN 11) and the `test` command that attests them.

Each check is a pure function of what the edge read: `tarball` (a streaming pass over the root filesystem),
`resolution` (apt, offline) and `clones` (rootless docker) are the edges.
"""

from .command import test_command
from .model import CORE_CHECKS, CheckOutcome, NotRun, Result

__all__ = ["CORE_CHECKS", "CheckOutcome", "NotRun", "Result", "test_command"]
