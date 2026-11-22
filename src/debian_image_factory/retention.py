"""What `prune` keeps and what it deletes (DESIGN 9.1, 9.3, 11): a pure function of the builds a target
holds, their test results and the consumer's pins.

The rules, per image (one target at a time; an artifact of another target never counts here):

- A build is **good** when every check its image requires has a passing last result, a **candidate**
  when none failed and some has no result yet, and **failed** when a required check failed and every
  required check has a result: its checks have ended. The last result of a check wins, by the rules of
  `published`.
- A check added to the definition later does not demote the builds made before it. The records do not say
  which checks were required when a build was made, so the results tell: a required check the build has
  no result for is not held against it when the image's builds show the check came after it, that is
  when the oldest build with a result for the check is newer than this build, or when no build of the
  image has a result for the check at all and this one is not the newest (the newest build may be
  tested still). A build with no result for any required check is never helped by this: nothing was
  tested. The rule only ever keeps more builds than the strict one, so adding a required check never
  deletes a build that was good before it (DESIGN 11).
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

from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from .published import Artifact, failed_and_missing, instant, sort_newest_first

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


def first_results(builds: Sequence[Artifact]) -> Mapping[str, datetime]:
    """For each check any of `builds` has a result for, the finish time of the oldest such build."""
    first: dict[str, datetime] = {}
    for one in builds:
        moment = instant(one.finished_on)
        for check in one.results:
            if check not in first or moment < first[check]:
                first[check] = moment
    return first


def standing_of(
    one: Artifact, required: RequiredChecks, first: Mapping[str, datetime] | None = None, newest: bool = False
) -> Standing:
    """good, candidate (a failed build whose checks have not all ended is one too), failed, or unknown
    for an image the definition does not name. `first` (see `first_results`, for the builds of the image;
    None holds every missing result against the build) and `newest` (whether this is the image's newest
    build) say which missing results are a check added after the build, and are not held against it."""
    checks = required(one.image, one.has_locked_inputs)
    if checks is None:
        return "unknown"
    bad, missing = failed_and_missing(one, checks)
    if first is not None and any(check in one.results for check in checks):
        built = instant(one.finished_on)
        missing = tuple(check for check in missing if not _came_later(check, built, first, newest))
    if missing:
        return "candidate"
    return "failed" if bad else "good"


def _came_later(check: str, built: datetime, first: Mapping[str, datetime], newest: bool) -> bool:
    """Whether the results show that `check` was added after a build made at `built`."""
    seen = first.get(check)
    return built < seen if seen is not None else not newest


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
        first = first_results(same)
        counts: dict[Standing, int] = {"good": 0, "candidate": 0, "failed": 0, "unknown": 0}
        for position, one in enumerate(same):
            standing = standing_of(one, required, first, position == 0)
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
