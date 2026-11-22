"""`no-build-snapshot` (DESIGN 11), pure: the build snapshot ID appears nowhere in the artifact."""

from collections.abc import Sequence

from .model import NO_BUILD_SNAPSHOT, Result, result, split
from .tarball import Hit

TEST = "build-snapshot-absent"


def cannot_tell(snapshot: str, baseline: str | None) -> bool:
    """When the baseline snapshot is the build snapshot, an image may carry the ID on purpose (an
    `apt_sources` of "baseline" points at it), so a match proves nothing."""
    return baseline == snapshot


def no_build_snapshot(snapshot: str, baseline: str | None, hits: Sequence[Hit]) -> Result:
    if cannot_tell(snapshot, baseline):
        return result(
            NO_BUILD_SNAPSHOT,
            [],
            warned=[f"{TEST}: the baseline {baseline} is the build snapshot, so a match cannot be told apart"],
        )
    passed, failed = split(TEST, [f"{snapshot} is in a {hit.where} of {hit.path}" for hit in hits])
    return result(NO_BUILD_SNAPSHOT, passed, failed=failed)
