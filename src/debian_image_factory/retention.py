"""What `prune` keeps and what it deletes (DESIGN 9.1, 9.3, 11): a pure function of the builds a target
holds, their test results and the consumer's pins.

The rules, per image (one target at a time; an artifact of another target never counts here):

- A build is **good** when every check its image requires has a passing last result, a **candidate**
  when none failed and some has no result yet, and **failed** when a required check failed and every
  required check has a result: its checks have ended. The last result of a check wins, by the rules of
  `published`.
- A build with a failed required check and other required checks still without a result is not over: it
  is treated as a candidate (a checker that stops at the first failure leaves such builds behind, and
  they leave through the candidate limit like any other).
- A pinned digest is never deleted, and does not count against either limit ("plus pins").
- The newest `keep_good` good builds stay, the newest `keep_candidates` candidates stay, failed builds
  are deleted. "Newest" is `published`'s order: the latest `finishedOn`, a build without a time older
  than any with one, ties by the smallest digest.
- The two limits are separate counts, so a run of failed or unfinished nights never pushes out a good
  build, and an image keeps at most `keep_good + keep_candidates` builds plus its pins.
- A build of an image the definition does not name is kept: nothing says which checks make it good.
"""

from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from typing import Literal

from .published import Artifact, failed_and_missing, sort_newest_first

type Standing = Literal["good", "candidate", "failed", "unknown"]

type RequiredChecks = Callable[[str, bool], Sequence[str] | None]
"""The checks that make a build of an image good, given the image and whether the build lists locked
inputs; None for an image the definition does not name."""


@dataclass(frozen=True, slots=True)
class Verdict:
    """What happens to one artifact, and why (a sentence for the person reading the list)."""

    artifact: Artifact
    keep: bool
    reason: str
    standing: Standing


def standing_of(one: Artifact, required: RequiredChecks) -> Standing:
    """good, candidate (a failed build whose checks have not all ended is one too), failed, or unknown
    for an image the definition does not name."""
    checks = required(one.image, one.has_locked_inputs)
    if checks is None:
        return "unknown"
    bad, missing = failed_and_missing(one, checks)
    if missing:
        return "candidate"
    return "failed" if bad else "good"


def retain(
    artifacts: Sequence[Artifact],
    required: RequiredChecks,
    pins: Collection[str],
    keep_good: int,
    keep_candidates: int,
) -> tuple[Verdict, ...]:
    """A verdict for every artifact, grouped by image (by name) and newest first within it. `pins` are
    artifact digests in full hex. Raises ValueError for a negative limit."""
    if keep_good < 0 or keep_candidates < 0:
        raise ValueError("the numbers of builds to keep are not negative")
    verdicts: list[Verdict] = []
    for image in sorted({one.image for one in artifacts}):
        same = sort_newest_first([one for one in artifacts if one.image == image])
        counts: dict[Standing, int] = {"good": 0, "candidate": 0, "failed": 0, "unknown": 0}
        for one in same:
            standing = standing_of(one, required)
            if standing == "unknown":
                verdicts.append(Verdict(one, True, f"{image} is not in the definition, so it stays", standing))
            elif one.digest in pins:
                verdicts.append(Verdict(one, True, f"pinned ({standing})", standing))
            elif standing == "failed":
                verdicts.append(Verdict(one, False, "a required check failed and its checks have ended", standing))
            else:
                counts[standing] += 1
                limit = keep_good if standing == "good" else keep_candidates
                rank = counts[standing]
                keep = rank <= limit
                verdicts.append(Verdict(one, keep, _reason(standing, rank, limit, keep), standing))
    return tuple(verdicts)


def _reason(standing: Standing, rank: int, limit: int, keep: bool) -> str:
    if keep:
        return f"{standing} build {rank} of the newest {limit} {standing} builds kept"
    return f"{standing} build {rank}, older than the newest {limit} {standing} builds kept"
