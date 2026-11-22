"""The builder image and the boot checks' image (scripts/builder), built once per run, not once per test class.

Many integration classes need the builder image. `docker build` of an image that is already built answers from
its cache in a second or two, but a cold build takes minutes, and workers running side by side would all start it
at once. Here the first caller of a run builds it under a file lock and the others wait, then read its tag from
the cache; a process asks the script once.
"""

import fcntl
import functools
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


@functools.cache
def image(command: str = "build") -> str:
    """The tag `scripts/builder <command>` prints: `build` is the builder, `vm` the boot checks' image."""
    (ROOT / "dist").mkdir(exist_ok=True)
    with (ROOT / "dist" / f".builder-{command}.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ran = subprocess.run([str(ROOT / "scripts" / "builder"), command], check=True, capture_output=True, text=True)
    return ran.stdout.split()[-1]
