"""`no-build-snapshot` (DESIGN 11), pure: no build snapshot ID, of either archive, appears in the artifact."""

from collections.abc import Mapping, Sequence

from .model import NO_BUILD_SNAPSHOT, Result, result, split
from .tarball import Hit

TEST = "build-snapshot-absent"


def cannot_tell(snapshot: str, baseline: str | None) -> bool:
    """When the baseline snapshot is a build snapshot, an image may carry the ID on purpose (an
    `apt_sources` of "baseline" points at it), so a match proves nothing."""
    return baseline == snapshot


def searched(snapshots: Mapping[str, str], baseline: str | None) -> tuple[str, ...]:
    """The distinct build snapshot IDs to look for, sorted: every one the baseline does not share. Both archives
    at one ID make one needle."""
    return tuple(sorted({one for one in snapshots.values() if not cannot_tell(one, baseline)}))


def no_build_snapshot(snapshots: Mapping[str, str], baseline: str | None, hits: Sequence[Hit]) -> Result:
    """FAILED when a hit shows a build snapshot ID in the artifact. An ID equal to the baseline cannot be told
    apart from it and only warns; the other ID, if the archives differ, is still searched."""
    looking = searched(snapshots, baseline)
    warned: list[str] = []
    if baseline is not None and baseline in snapshots.values():
        archives = [name for name, one in snapshots.items() if one == baseline]
        of = "" if len(archives) == len(snapshots) else f" of {' and '.join(archives)}"
        warned.append(f"{TEST}: the baseline {baseline} is the build snapshot{of}, so a match cannot be told apart")
    if not looking:
        return result(NO_BUILD_SNAPSHOT, [], warned=warned)
    ids = " or ".join(looking)
    passed, failed = split(TEST, [f"{ids} is in a {hit.where} of {hit.path}" for hit in hits])
    return result(NO_BUILD_SNAPSHOT, passed, warned=warned, failed=failed)
