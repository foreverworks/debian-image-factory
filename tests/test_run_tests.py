import importlib.machinery
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "run-tests"


def load() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("run_tests", str(SCRIPT))
    spec = importlib.util.spec_from_loader("run_tests", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


runner = load()

WEIGHTS = {"a": 100.0, "b": 60.0, "c": 50.0, "d": 40.0, "e": 30.0, "f": 20.0, "g": 5.0, "h": 5.0}


class LptTest(unittest.TestCase):
    def test_every_name_lands_in_exactly_one_bin(self) -> None:
        packed = runner.lpt(WEIGHTS, 3)
        self.assertEqual(sorted(name for one in packed for name in one), sorted(WEIGHTS))

    def test_the_heaviest_goes_first_and_the_bins_are_even(self) -> None:
        packed = runner.lpt(WEIGHTS, 3)
        loads = sorted(sum(WEIGHTS[name] for name in one) for one in packed)
        self.assertEqual(packed[0][0], "a")
        self.assertLessEqual(loads[-1] - loads[0], 25.0)

    def test_the_split_does_not_depend_on_the_order_of_the_input(self) -> None:
        reverse = dict(reversed(WEIGHTS.items()))
        self.assertEqual(runner.lpt(WEIGHTS, 4), runner.lpt(reverse, 4))

    def test_more_bins_than_names_leaves_empty_bins(self) -> None:
        self.assertEqual(sorted(len(one) for one in runner.lpt({"x": 1.0}, 3)), [0, 0, 1])


class ShardTest(unittest.TestCase):
    def test_the_shards_cover_the_tier_without_overlap(self) -> None:
        seen: list[str] = []
        for index in (1, 2, 3):
            seen += runner.shard_of(WEIGHTS, index, 3)
        self.assertEqual(sorted(seen), sorted(WEIGHTS))

    def test_one_shard_is_everything(self) -> None:
        self.assertEqual(runner.shard_of(WEIGHTS, 1, 1), WEIGHTS)

    def test_parse_shard(self) -> None:
        self.assertEqual(runner.parse_shard("2/5"), (2, 5))
        for bad in ("0/3", "4/3", "x/3", "2", "2/", "/3", "-1/3"):
            with self.assertRaises(ValueError, msg=bad):
                runner.parse_shard(bad)


class WeighTest(unittest.TestCase):
    def test_a_class_not_measured_weighs_the_mean(self) -> None:
        weights = runner.weigh(["a", "new"], {"a": 10.0, "gone": 30.0})
        self.assertEqual(weights, {"a": 10.0, "new": 20.0})

    def test_nothing_measured_weighs_one_second_each(self) -> None:
        self.assertEqual(runner.weigh(["a", "b"], {}), {"a": 1.0, "b": 1.0})


class BatchTest(unittest.TestCase):
    def test_every_class_is_in_exactly_one_job_longest_first(self) -> None:
        jobs = runner.batches(WEIGHTS, 2)
        self.assertEqual(sorted(name for job in jobs for name in job.names), sorted(WEIGHTS))
        self.assertEqual(jobs[0].names[0], "a")
        self.assertEqual([job.index for job in jobs], list(range(len(jobs))))

    def test_a_heavy_class_is_alone_and_light_ones_share_a_job(self) -> None:
        jobs = runner.batches({"big": 100.0, "s1": 1.0, "s2": 1.0, "s3": 1.0}, 2)
        self.assertEqual(jobs[0].names, ("big",))
        self.assertEqual(sorted(name for job in jobs[1:] for name in job.names), ["s1", "s2", "s3"])


class MemoryTest(unittest.TestCase):
    GIB = 1024**3

    def test_meminfo_available_is_read_in_bytes(self) -> None:
        text = "MemTotal:  100 kB\nMemAvailable:   11483433 kB\nSwapTotal: 0 kB\n"
        self.assertEqual(runner.meminfo_available(text), 11483433 * 1024)

    def test_meminfo_without_the_line_is_unknown(self) -> None:
        self.assertIsNone(runner.meminfo_available("MemTotal: 1 kB\n"))
        self.assertIsNone(runner.meminfo_available("MemAvailable: lots kB\n"))

    def test_cgroup_headroom_is_the_limit_less_the_use(self) -> None:
        self.assertEqual(runner.cgroup_headroom("34359738368\n", "24237191168\n"), 34359738368 - 24237191168)

    def test_cgroup_without_a_limit_has_no_headroom_figure(self) -> None:
        self.assertIsNone(runner.cgroup_headroom("max\n", "100\n"))
        self.assertIsNone(runner.cgroup_headroom(None, None))
        self.assertIsNone(runner.cgroup_headroom("100", None))

    def test_a_cgroup_over_its_limit_has_none_left(self) -> None:
        self.assertEqual(runner.cgroup_headroom("100", "200"), 0)

    def test_the_tighter_of_two_amounts_wins_and_an_unknown_gives_way(self) -> None:
        self.assertEqual(runner.tighter(5, 3), 3)
        self.assertEqual(runner.tighter(None, 3), 3)
        self.assertEqual(runner.tighter(5, None), 5)
        self.assertIsNone(runner.tighter(None, None))

    def test_memory_is_the_limit_when_fewer_jobs_fit_than_there_are_cpus(self) -> None:
        count, why = runner.choose_workers(16, 10 * self.GIB, 3 * self.GIB)
        self.assertEqual(count, 3)
        self.assertIn("memory is the limit", why)
        self.assertIn("3 workers", why)

    def test_cpus_are_the_limit_when_memory_is_plentiful(self) -> None:
        count, why = runner.choose_workers(4, 64 * self.GIB, 3 * self.GIB)
        self.assertEqual(count, 4)
        self.assertIn("CPUs is the limit", why)

    def test_there_is_always_one_worker(self) -> None:
        self.assertEqual(runner.choose_workers(8, 0, 3 * self.GIB)[0], 1)
        self.assertEqual(runner.choose_workers(8, 2 * self.GIB, 3 * self.GIB)[0], 1)

    def test_unknown_memory_falls_back_to_the_cpus(self) -> None:
        count, why = runner.choose_workers(6, None, 3 * self.GIB)
        self.assertEqual(count, 6)
        self.assertIn("unknown", why)

    def test_a_tier_that_boots_gets_a_bigger_budget_than_unit(self) -> None:
        self.assertLess(runner.BUDGETS["unit"], runner.BUDGETS["integration"])
        self.assertLess(runner.BUDGETS["integration"], runner.BUDGETS["boot"])
        self.assertEqual(set(runner.BUDGETS), set(runner.TIERS))


class ReadingTest(unittest.TestCase):
    def test_durations(self) -> None:
        self.assertEqual(runner.read_durations('{"units": {"a.B": 1.5, "c.D": 2}}'), {"a.B": 1.5, "c.D": 2.0})

    def test_durations_that_are_malformed_are_refused(self) -> None:
        for bad in ("[]", "{}", '{"units": {"a": "slow"}}', '{"units": {"a": true}}'):
            with self.assertRaises(ValueError, msg=bad):
                runner.read_durations(bad)

    def test_report(self) -> None:
        text = json.dumps(
            {"units": {"a.B": 1.0}, "tests": {"t": 0.5}, "ran": 3, "skipped": 1, "failures": ["x"], "wall": 2}
        )
        report = runner.parse_report(text)
        self.assertEqual((report.ran, report.skipped, report.failures, report.wall), (3, 1, ("x",), 2.0))

    def test_a_report_with_a_wrong_field_is_refused(self) -> None:
        text = json.dumps({"units": {}, "tests": {}, "ran": "3", "skipped": 0, "failures": [], "wall": 1})
        with self.assertRaises(ValueError):
            runner.parse_report(text)


class WorkerTest(unittest.TestCase):
    def test_a_worker_runs_a_class_and_reports_its_time_and_failures(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            result = Path(scratch) / "result.json"
            with mock.patch.dict(os.environ, {"RUN_TESTS_PROBE": "1"}):
                status = runner.worker(["tests.test_run_tests.Probe"], result)
            report = runner.parse_report(result.read_text())
            self.assertEqual(status, 1)
            self.assertEqual(report.ran, 2)
            self.assertEqual(len(report.failures), 1)
            self.assertIn("FAIL: test_fails", report.failures[0])
            self.assertEqual(list(report.units), ["tests.test_run_tests.Probe"])


class Probe(unittest.TestCase):
    """What WorkerTest runs. It is skipped in a normal run: only the worker test asks for it by name."""

    @classmethod
    def setUpClass(cls) -> None:
        if os.environ.get("RUN_TESTS_PROBE") != "1":
            raise unittest.SkipTest("the probe runs inside the worker test only")

    def test_passes(self) -> None:
        self.assertTrue(True)

    def test_fails(self) -> None:
        self.fail("on purpose")


if __name__ == "__main__":
    unittest.main()
