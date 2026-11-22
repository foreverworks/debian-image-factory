"""How many jobs this machine can run side by side: the CPUs, held back by the memory that is free.

One rule for the factory's `build` (images that do not depend on each other build together) and for the
test runner (`scripts/run-tests`): jobs = min(CPUs, available memory / the job's memory budget), at least
one. The available memory is the tighter of the host's `MemAvailable` and what the cgroup the process runs
in still has (`memory.max` less `memory.current`), so a container with a limit is sized to the limit, not
to the host. The functions are pure; `available_memory` is the one that reads the machine.
"""

import os
from pathlib import Path
from typing import Final

GIB: Final = 1024**3
BUILD_BUDGET: Final = GIB
"""Memory one image build may need, in bytes: mmdebstrap or apt in a privileged builder container, the layer
writer, and the squashfs and tar writers of the Python process. Measured on the example definition's six
images (core, an OCI base and a Node child, an Incus base, the installer kit and an OS root filesystem), built
together: the builder containers peaked at 0.5 GiB for the biggest one (an OS image) and 0.7 GiB summed across
six running at once, and the host's available memory fell by about 1 GiB at most. A budget of 1 GiB is twice the
biggest peak."""
CGROUP: Final = Path("/sys/fs/cgroup")


def meminfo_available(text: str) -> int | None:
    """MemAvailable of /proc/meminfo in bytes, or None when the file does not say."""
    for line in text.splitlines():
        if line.startswith("MemAvailable:"):
            fields = line.split()
            if len(fields) >= 2 and fields[1].isdigit():
                return int(fields[1]) * 1024
    return None


def cgroup_headroom(limit: str | None, current: str | None) -> int | None:
    """What the cgroup still has: memory.max less memory.current, in bytes. None when there is no limit (`max`,
    or the files are absent or unreadable); 0 when the group is at or over its limit."""
    if limit is None or current is None:
        return None
    if not (limit.strip().isdigit() and current.strip().isdigit()):
        return None
    return max(int(limit) - int(current), 0)


def tighter(first: int | None, second: int | None) -> int | None:
    """The smaller of two optional amounts; the other when one is unknown."""
    known = [one for one in (first, second) if one is not None]
    return min(known) if known else None


def memory_cap(available: int | None, budget: int) -> int | None:
    """How many jobs of `budget` bytes fit in `available` bytes, at least one; None when memory is unknown."""
    return None if available is None else max(available // budget, 1)


def choose_workers(cpus: int, available: int | None, budget: int) -> tuple[int, str]:
    """The default job count, min(cpus, memory cap), and the sentence saying why."""
    if available is None:
        return cpus, f"{cpus} workers: one per CPU (available memory unknown)"
    cap = memory_cap(available, budget) or 1
    count = min(cpus, cap)
    limit = "memory" if cap < cpus else "CPUs"
    return count, (
        f"{count} workers: {limit} is the limit ({cpus} CPUs, {available / GIB:.1f} GiB available, "
        f"{budget / GIB:.1f} GiB a job)"
    )


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def available_memory() -> int | None:
    """The memory a new job can count on, in bytes: the tighter of the host's MemAvailable and the cgroup's room."""
    meminfo = read_text(Path("/proc/meminfo"))
    host = meminfo_available(meminfo) if meminfo is not None else None
    return tighter(host, cgroup_headroom(read_text(CGROUP / "memory.max"), read_text(CGROUP / "memory.current")))


def cpus() -> int:
    """The CPUs this process may use."""
    return os.process_cpu_count() or 1
