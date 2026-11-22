"""The built-in checks (DESIGN 11) and the `test` command that attests them.

Each check is a pure function of what the edge read: `tarball`, `layers` and `kit` (streaming passes over a
root filesystem tarball, an image's layers, and an installer kit's initrd through `newc`), `resolution`
(apt, offline), `clones`, `container` and `dockerio` (docker), and `vmrun` (QEMU in a container, for the
boot checks whose pure part is `vm`) are the edges.
"""

from .command import Effects, test_command
from .model import CORE_CHECKS, INSTALLER_CHECKS, OCI_CHECKS, OS_CHECKS, CheckOutcome, NotRun, Result
from .vmrun import Vm

__all__ = [
    "CORE_CHECKS",
    "INSTALLER_CHECKS",
    "OCI_CHECKS",
    "OS_CHECKS",
    "CheckOutcome",
    "Effects",
    "NotRun",
    "Result",
    "Vm",
    "test_command",
]
