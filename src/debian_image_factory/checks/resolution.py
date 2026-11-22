"""`same-resolution` (DESIGN 11): a second resolution of the same lock gives the same package set.

The pure comparison, and the edge that resolves core again with apt, offline, from the mirror `fetch`
left in the cache.
"""

import tempfile
from collections.abc import Callable, Collection, Sequence
from pathlib import Path

from input_lock import Package

from .. import archive, resolve
from .model import SAME_RESOLUTION, CheckOutcome, NotRun, Result, result, split
from .packages import differences, installed


def both_ways(left: Collection[Package], right: Collection[Package], left_name: str, right_name: str) -> list[str]:
    only_left, only_right = differences(left, right, left_name, right_name)
    return [*only_left, *only_right]


def compare(second: Collection[Package], planned: Collection[Package], status: bytes | None) -> Result:
    """`second` is the new resolution, `planned` the plan entry's set, `status` the tarball's dpkg status."""
    ok_plan, bad_plan = split(
        "resolution-matches-plan", both_ways(planned, second, "the plan", "the second resolution")
    )
    found = installed(status)
    if isinstance(found, str):
        return result(
            SAME_RESOLUTION,
            ["second-resolution-succeeds", *ok_plan],
            failed=[*bad_plan, f"dpkg-status-readable: {found}"],
        )
    ok_image, bad_image = split(
        "resolution-matches-image", both_ways(found, second, "the image", "the second resolution")
    )
    return result(
        SAME_RESOLUTION,
        ["second-resolution-succeeds", "dpkg-status-readable", *ok_plan, *ok_image],
        failed=[*bad_plan, *bad_image],
    )


def mirror_reader(service: str, mirror_dir: Path, snapshot: str) -> Callable[[str], bytes]:
    """A `read` for `resolve.open_archive`: `<service>/archive/<archive>/<snapshot>/<path>` is the file
    `<mirror_dir>/<archive>/<path>`. Anything else, or a file the mirror lacks, is an OSError, which is how
    `archive.fetch_suite` learns a by-hash path is not there."""
    prefix = f"{service.rstrip('/')}/archive/"

    def read(url: str) -> bytes:
        if not url.startswith(prefix):
            raise OSError(f"{url} is not under {prefix}")
        archive_name, _, rest = url.removeprefix(prefix).partition("/")
        stamp, _, path = rest.partition("/")
        if stamp != snapshot or not path:
            raise OSError(f"{url} is not in snapshot {snapshot}")
        return (mirror_dir / archive_name / path).read_bytes()

    return read


def second_resolution(
    *,
    snapshot: str,
    suite: str,
    components: Sequence[str],
    arch: str,
    request: Sequence[str],
    keyring: Path,
    cache: Path,
    service: str,
) -> tuple[Package, ...] | NotRun | str:
    """The package set of resolving core again from `<cache>/mirror/<snapshot>`. A NotRun when the mirror or
    a tool is missing; a string when apt ran and could not resolve (the second resolution failed)."""
    mirror = cache / "mirror" / snapshot
    if not mirror.is_dir():
        return NotRun(SAME_RESOLUTION, f"no fetched mirror at {mirror}: run fetch first")
    with tempfile.TemporaryDirectory(prefix="debian-image-factory-resolve-") as scratch:
        try:
            opened = resolve.open_archive(
                snapshot,
                suite,
                components,
                arch,
                keyring=keyring,
                cache=cache,
                workdir=Path(scratch),
                service=service,
                read=mirror_reader(service, mirror, snapshot),
            )
            return resolve.resolve_core(opened, request)
        except (OSError, archive.ArchiveError) as error:
            return NotRun(SAME_RESOLUTION, f"the mirror at {mirror} could not be read: {error}")
        except resolve.ResolveError as error:
            return str(error)


def same_resolution(
    *,
    snapshot: str,
    suite: str,
    components: Sequence[str],
    arch: str,
    request: Sequence[str],
    planned: Collection[Package],
    status: bytes | None,
    keyring: Path,
    cache: Path,
    service: str,
) -> CheckOutcome:
    second = second_resolution(
        snapshot=snapshot,
        suite=suite,
        components=components,
        arch=arch,
        request=request,
        keyring=keyring,
        cache=cache,
        service=service,
    )
    if isinstance(second, NotRun):
        return second
    if isinstance(second, str):
        return result(SAME_RESOLUTION, [], failed=[f"second-resolution-succeeds: {second.splitlines()[0]}"])
    return compare(second, planned, status)
