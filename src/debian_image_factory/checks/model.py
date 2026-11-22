"""What a check returns, and the names every check shares (DESIGN 11, 8.2).

A check either ran and has a result (an outcome and the names of its tests), or could not run here and
says why; a check that did not run writes no record and is never counted as passed.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from input_lock.records import TestOutcome

PACKAGE_SET: Final = "package-set"
NO_MACHINE_IDENTITY: Final = "no-machine-identity"
SBOM_COMPLETE: Final = "sbom-complete"
NO_BUILD_SNAPSHOT: Final = "no-build-snapshot"
SAME_RESOLUTION: Final = "same-resolution"
TWO_CLONES: Final = "two-clones"
ANCESTRY: Final = "ancestry"
OCI_RUN: Final = "oci-run"
LOCKED_INPUTS: Final = "locked-inputs"
INCUS_BOOT: Final = "incus-boot"

CORE_CHECKS: Final = (
    NO_BUILD_SNAPSHOT,
    NO_MACHINE_IDENTITY,
    PACKAGE_SET,
    SAME_RESOLUTION,
    SBOM_COMPLETE,
    TWO_CLONES,
)
"""The checks this release runs on a core artifact (the same set as `definition.BUILTIN_CHECKS["core"]`)."""

OCI_CHECKS: Final = (
    ANCESTRY,
    LOCKED_INPUTS,
    NO_BUILD_SNAPSHOT,
    NO_MACHINE_IDENTITY,
    OCI_RUN,
    PACKAGE_SET,
    SBOM_COMPLETE,
    TWO_CLONES,
)
"""The checks this release runs on an OCI image: `definition.BUILTIN_CHECKS["oci"]` and `locked-inputs`,
which an image has when it uses lock entries."""

INCUS_CHECKS: Final = (
    ANCESTRY,
    INCUS_BOOT,
    NO_BUILD_SNAPSHOT,
    NO_MACHINE_IDENTITY,
    PACKAGE_SET,
    SBOM_COMPLETE,
    TWO_CLONES,
)
"""The checks this release runs on an Incus image: `definition.BUILTIN_CHECKS["incus"]`. `incus-boot` and
`two-clones` need an Incus host (they are not run elsewhere); `locked-inputs` is not run on Incus images yet."""

CHECKS_OF_KIND: Final[Mapping[str, tuple[str, ...]]] = {"core": CORE_CHECKS, "oci": OCI_CHECKS, "incus": INCUS_CHECKS}
"""The kinds `test` runs checks on, and each one's checks."""

LIMIT: Final = 25
"""The most failing items one test lists by name; the rest are counted, so a record stays small."""


@dataclass(frozen=True, slots=True)
class Result:
    """A check that ran. A test name in `failed` reads `<test>: <what is wrong>`; in `passed` it is bare."""

    check: str
    outcome: TestOutcome
    passed: tuple[str, ...]
    warned: tuple[str, ...]
    failed: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NotRun:
    """A check that cannot run here (no docker, no fetched mirror): no result, no record."""

    check: str
    reason: str


type CheckOutcome = Result | NotRun


def result(check: str, passed: Iterable[str], warned: Iterable[str] = (), failed: Iterable[str] = ()) -> Result:
    """FAILED when any test failed, else WARNED when any warned, else PASSED."""
    failed_names, warned_names = tuple(failed), tuple(warned)
    outcome: TestOutcome = "FAILED" if failed_names else "WARNED" if warned_names else "PASSED"
    return Result(check, outcome, tuple(passed), warned_names, failed_names)


def listed(test: str, items: Sequence[str]) -> list[str]:
    """One failing entry per item, `<test>: <item>`, the first LIMIT of them and then a count of the rest."""
    found = [f"{test}: {item}" for item in items[:LIMIT]]
    if len(items) > LIMIT:
        found.append(f"{test}: and {len(items) - LIMIT} more")
    return found


def split(test: str, items: Sequence[str]) -> tuple[list[str], list[str]]:
    """(passed, failed) of one test over its failing items: passed holds the bare name when none failed."""
    return ([test], []) if not items else ([], listed(test, items))
