"""Run a plan's images as the dependency graph they are (DESIGN 9.1): an image starts when its parent is
built, siblings run together, and never more than `jobs` at a time.

Pure scheduling: what an image's build does is the `work` function the caller gives. `work` runs on a pool
thread, and every callback (`on_start`, `on_done`, `on_fail`) runs on the calling thread, so the caller
can print from them without a lock and a run's output is never interleaved inside a line.

When an image fails, nothing new starts. The images already running finish (a build is a container run
to its end: stopping one half way would leave its work directory in a state nobody reads), then every
failure is reported together with the images that never started.
"""

import concurrent.futures
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Outcome[T]:
    """How a run ended."""

    done: Mapping[str, T]
    """The images built, with what `work` returned, in the order they finished."""
    failed: Mapping[str, BaseException]
    """The images whose build raised, in the order they finished."""
    skipped: Sequence[str]
    """The images that never started: after a failure, or below a failed parent."""


def run[T](
    order: Sequence[str],
    parent_of: Mapping[str, str | None],
    work: Callable[[str, Mapping[str, T]], T],
    *,
    jobs: int,
    on_start: Callable[[str], None] = lambda image: None,
    on_done: Callable[[str, T], None] = lambda image, result: None,
    on_fail: Callable[[str, BaseException], None] = lambda image, error: None,
) -> Outcome[T]:
    """Build the images of `order` (parents before children), `jobs` at a time.

    `parent_of` says each image's parent; a parent that is not in `order` is already built (it is somewhere
    else), so it holds nothing back. `work(image, built)` gets a snapshot of the results of the images
    finished so far, and starts in the order of `order` as images become ready: with one job that is
    exactly `order`, one after another."""
    if jobs < 1:
        raise ValueError(f"jobs must be at least 1, not {jobs}")
    pending = list(order)
    done: dict[str, T] = {}
    failed: dict[str, BaseException] = {}
    running: dict[concurrent.futures.Future[T], str] = {}

    def ready(image: str) -> bool:
        parent = parent_of.get(image)
        return parent is None or parent not in order or parent in done

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        while True:
            while not failed and len(running) < jobs:
                found = next((image for image in pending if ready(image)), None)
                if found is None:
                    break
                pending.remove(found)
                on_start(found)
                running[pool.submit(work, found, dict(done))] = found
            if not running:
                break
            finished, _ = concurrent.futures.wait(running, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in sorted(finished, key=lambda one: order.index(running[one])):
                image = running.pop(future)
                error = future.exception()
                if error is None:
                    done[image] = future.result()
                    on_done(image, done[image])
                else:
                    failed[image] = error
                    on_fail(image, error)
    return Outcome(done, failed, tuple(pending))
