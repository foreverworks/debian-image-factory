"""`byte-equal` (DESIGN 11): two builds from the same inputs give the same digest.

The check does not rebuild: a second build is an input, a directory given with `test --twin` that holds the
same image built again from the same plan (the same name up to the digest, since the identity is in the
name). A difference is not a fault of the artifact, so the check never fails: it is WARNED when a twin's
digest differs, and the difference is for a person to look at. Without a twin it is not run.
"""

from collections.abc import Sequence
from pathlib import Path

from ..published import ArtifactName
from .model import BYTE_EQUAL, CheckOutcome, NotRun, result

TEST: str = "same-digest"


def same_build(left: ArtifactName, right: ArtifactName) -> bool:
    """Whether two artifact names are two builds of one image: the same image, suite, architecture, identity
    and kind of file, whatever the digest."""
    return (left.image, left.suite, left.arch, left.identity16, left.ext) == (
        right.image,
        right.suite,
        right.arch,
        right.identity16,
        right.ext,
    )


def compare(digest: str, twins: Sequence[tuple[Path, str]]) -> CheckOutcome:
    """The check's outcome for an artifact of `digest` against its twins, each a (path, digest): PASSED when
    every twin has the digest, WARNED naming the twins that have another, not run when there is none."""
    if not twins:
        return NotRun(BYTE_EQUAL, "no second build of this image: pass the output of another build with --twin")
    differing = [f"{path.name} is {other}" for path, other in twins if other != digest]
    if differing:
        return result(BYTE_EQUAL, [], warned=[f"{TEST}: this build is {digest}, and " + "; ".join(differing)])
    return result(BYTE_EQUAL, [TEST])
