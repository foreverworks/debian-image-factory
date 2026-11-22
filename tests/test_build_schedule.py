"""The build scheduler (DESIGN 9.1): order, parallelism, failure, and the size of the pool."""

import contextlib
import io
import threading
import types
import unittest
from collections.abc import Mapping
from unittest import mock

from debian_image_factory import capacity, commands
from debian_image_factory.build import run, schedule

PLAN = {"core": None, "base": "core", "node-26": "base", "node-24": "base", "node-22": "base"}
ORDER = list(PLAN)


class Probe:
    """A `work` function that records when each image starts and ends, and holds images at a barrier on request."""

    def __init__(self, fail: tuple[str, ...] = ()) -> None:
        self.lock = threading.Lock()
        self.events: list[tuple[str, str]] = []
        self.running = 0
        self.peak = 0
        self.fail = fail
        self.saw: dict[str, list[str]] = {}
        self.gate: threading.Barrier | None = None

    def __call__(self, image: str, built: Mapping[str, str]) -> str:
        with self.lock:
            self.events.append(("start", image))
            self.saw[image] = sorted(built)
            self.running += 1
            self.peak = max(self.peak, self.running)
        try:
            if self.gate is not None and image.startswith("node-"):
                self.gate.wait(timeout=10)
            if image in self.fail:
                raise commands.Failed(f"{image} broke")
            return f"{image}-artifact"
        finally:
            with self.lock:
                self.events.append(("end", image))
                self.running -= 1


class OrderTest(unittest.TestCase):
    def test_a_child_starts_after_its_parent_ends(self) -> None:
        probe = Probe()
        outcome = schedule.run(ORDER, PLAN, probe, jobs=4)
        self.assertEqual(outcome.failed, {})
        self.assertEqual(sorted(outcome.done), sorted(ORDER))
        for child, parent in PLAN.items():
            if parent is not None:
                self.assertLess(probe.events.index(("end", parent)), probe.events.index(("start", child)))

    def test_a_child_is_given_every_image_finished_before_it(self) -> None:
        probe = Probe()
        schedule.run(ORDER, PLAN, probe, jobs=4)
        self.assertIn("core", probe.saw["base"])
        self.assertTrue({"core", "base"} <= set(probe.saw["node-26"]))
        self.assertEqual(probe.saw["core"], [])

    def test_siblings_run_together(self) -> None:
        probe = Probe()
        probe.gate = threading.Barrier(3)  # the three node images must be running at once to pass it
        outcome = schedule.run(ORDER, PLAN, probe, jobs=3)
        self.assertEqual(sorted(outcome.done), sorted(ORDER))
        self.assertEqual(probe.peak, 3)

    def test_one_job_builds_in_the_order_given(self) -> None:
        probe = Probe()
        schedule.run(ORDER, PLAN, probe, jobs=1)
        self.assertEqual([image for kind, image in probe.events if kind == "start"], ORDER)
        self.assertEqual(probe.peak, 1)

    def test_the_pool_is_never_larger_than_jobs(self) -> None:
        probe = Probe()
        probe.gate = threading.Barrier(2)  # pairs of images meet here, so two do run at once
        names = [f"node-{one}" for one in "abcdef"]
        schedule.run(names, dict.fromkeys(names), probe, jobs=2)
        self.assertEqual(probe.peak, 2)

    def test_a_parent_outside_the_run_holds_nothing_back(self) -> None:
        probe = Probe()
        outcome = schedule.run(["node-26"], PLAN, probe, jobs=2)
        self.assertEqual(list(outcome.done), ["node-26"])

    def test_the_callbacks_run_on_the_calling_thread(self) -> None:
        threads: set[int] = set()
        schedule.run(
            ORDER,
            PLAN,
            Probe(),
            jobs=4,
            on_start=lambda image: threads.add(threading.get_ident()),
            on_done=lambda image, result: threads.add(threading.get_ident()),
        )
        self.assertEqual(threads, {threading.get_ident()})

    def test_jobs_below_one_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            schedule.run(ORDER, PLAN, Probe(), jobs=0)


class FailureTest(unittest.TestCase):
    def test_nothing_below_a_failed_image_starts(self) -> None:
        probe = Probe(fail=("base",))
        outcome = schedule.run(ORDER, PLAN, probe, jobs=4)
        self.assertEqual(list(outcome.failed), ["base"])
        self.assertEqual(list(outcome.done), ["core"])
        self.assertEqual(sorted(outcome.skipped), ["node-22", "node-24", "node-26"])
        self.assertNotIn(("start", "node-26"), probe.events)

    def test_running_images_finish_and_no_new_one_starts_after_a_failure(self) -> None:
        probe = Probe(fail=("node-26",))
        probe.gate = threading.Barrier(3)  # all three siblings are running when the first fails
        failures: list[str] = []
        outcome = schedule.run(
            ORDER, PLAN, probe, jobs=3, on_fail=lambda image, error: failures.append(f"{image}: {error}")
        )
        self.assertEqual(sorted(outcome.done), ["base", "core", "node-22", "node-24"])
        self.assertEqual(failures, ["node-26: node-26 broke"])
        self.assertEqual(outcome.skipped, ())

    def test_every_failure_is_reported(self) -> None:
        probe = Probe(fail=("node-26", "node-24"))
        probe.gate = threading.Barrier(3)
        outcome = schedule.run(ORDER, PLAN, probe, jobs=3)
        self.assertEqual(sorted(outcome.failed), ["node-24", "node-26"])

    def test_an_image_waiting_for_a_slot_does_not_start_after_a_failure(self) -> None:
        probe = Probe(fail=("a",))
        outcome = schedule.run(["a", "b", "c"], dict.fromkeys("abc"), probe, jobs=1)
        self.assertEqual(list(outcome.failed), ["a"])
        self.assertEqual(sorted(outcome.skipped), ["b", "c"])


class PoolSizeTest(unittest.TestCase):
    def test_jobs_overrides_the_machine(self) -> None:
        size, why = run.pool_size(3, 10)
        self.assertEqual(size, 3)
        self.assertIn("--jobs 3", why)

    def test_the_pool_is_no_larger_than_the_images(self) -> None:
        self.assertEqual(run.pool_size(8, 2)[0], 2)

    def test_the_default_is_the_machines_rule_at_the_build_budget(self) -> None:
        expected, _ = capacity.choose_workers(capacity.cpus(), capacity.available_memory(), capacity.BUILD_BUDGET)
        self.assertEqual(run.pool_size(0, 1000)[0], min(expected, 1000))

    def test_failure_text_names_the_image_on_every_message(self) -> None:
        text = run.failure_text("os", commands.Failed("the builder failed\nlast line"))
        self.assertEqual(text, "os: the builder failed\n  last line")
        self.assertTrue(run.failure_text("os", OSError("disk full")).startswith("os: OSError: disk full"))


class ScheduleImagesTest(unittest.TestCase):
    """`schedule_images` with the builds themselves replaced: what is printed, and how failures are reported."""

    def images(self) -> run.Run:
        entries = {name: {"parent": parent, "kind": "oci"} for name, parent in PLAN.items()}
        return types.SimpleNamespace(plan={"images": entries})  # type: ignore[return-value]  # only plan["images"] is read

    def fake(self, broken: tuple[str, ...]) -> contextlib.AbstractContextManager[object]:
        def build(_run: run.Run, image: str, built: Mapping[str, object]) -> run.Result:
            if image in broken:
                raise commands.Failed(f"the builder failed (exit 2)\nthe end of {image}.build.log")
            artifact = types.SimpleNamespace(name=f"{image}.oci")
            return types.SimpleNamespace(artifact=artifact, packages=1)  # type: ignore[return-value]  # a stand-in with the two fields read

        return mock.patch.object(run, "build_image", build)

    def test_every_line_starts_with_the_image_it_is_about(self) -> None:
        out = io.StringIO()
        with self.fake(()):
            run.schedule_images(self.images(), ORDER, 3, out)
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], "building 5 images, 3 at a time: --jobs 3")
        self.assertTrue(all(line.split(":")[0] in PLAN for line in lines[1:]), lines)
        self.assertIn("node-26: node-26.oci (1 packages)", lines)

    def test_one_image_prints_no_scheduling_lines(self) -> None:
        out = io.StringIO()
        with self.fake(()):
            run.schedule_images(self.images(), ["core"], 4, out)
        self.assertEqual(out.getvalue(), "core: core.oci (1 packages)\n")

    def test_every_failure_is_named_and_the_rest_is_not_started(self) -> None:
        out = io.StringIO()
        with self.fake(("base",)), self.assertRaises(commands.Failed) as caught:
            run.schedule_images(self.images(), ORDER, 4, out)
        text = str(caught.exception)
        self.assertIn("base: the builder failed (exit 2)\n  the end of base.build.log", text)
        self.assertIn("not started: node-26, node-24, node-22", text)
        self.assertIn("base: FAILED", out.getvalue())
        self.assertIn("core: core.oci", out.getvalue())

    def test_two_failures_are_both_reported(self) -> None:
        with self.fake(("node-26", "node-22")), self.assertRaises(commands.Failed) as caught:
            run.schedule_images(self.images(), ORDER, 4, io.StringIO())
        text = str(caught.exception)
        self.assertIn("node-26: the builder failed", text)
        self.assertIn("node-22: the builder failed", text)
