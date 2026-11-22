"""The sizing rule shared by `build` and the test runner: CPUs held back by free memory."""

import unittest

from debian_image_factory import capacity


class MemoryTest(unittest.TestCase):
    GIB = 1024**3

    def test_meminfo_available_is_read_in_bytes(self) -> None:
        text = "MemTotal:  100 kB\nMemAvailable:   11483433 kB\nSwapTotal: 0 kB\n"
        self.assertEqual(capacity.meminfo_available(text), 11483433 * 1024)

    def test_meminfo_without_the_line_is_unknown(self) -> None:
        self.assertIsNone(capacity.meminfo_available("MemTotal: 1 kB\n"))
        self.assertIsNone(capacity.meminfo_available("MemAvailable: lots kB\n"))

    def test_cgroup_headroom_is_the_limit_less_the_use(self) -> None:
        self.assertEqual(capacity.cgroup_headroom("34359738368\n", "24237191168\n"), 34359738368 - 24237191168)

    def test_cgroup_without_a_limit_has_no_headroom_figure(self) -> None:
        self.assertIsNone(capacity.cgroup_headroom("max\n", "100\n"))
        self.assertIsNone(capacity.cgroup_headroom(None, None))
        self.assertIsNone(capacity.cgroup_headroom("100", None))

    def test_a_cgroup_over_its_limit_has_none_left(self) -> None:
        self.assertEqual(capacity.cgroup_headroom("100", "200"), 0)

    def test_the_tighter_of_two_amounts_wins_and_an_unknown_gives_way(self) -> None:
        self.assertEqual(capacity.tighter(5, 3), 3)
        self.assertEqual(capacity.tighter(None, 3), 3)
        self.assertEqual(capacity.tighter(5, None), 5)
        self.assertIsNone(capacity.tighter(None, None))

    def test_memory_is_the_limit_when_fewer_jobs_fit_than_there_are_cpus(self) -> None:
        count, why = capacity.choose_workers(16, 10 * self.GIB, 3 * self.GIB)
        self.assertEqual(count, 3)
        self.assertIn("memory is the limit", why)
        self.assertIn("3 workers", why)

    def test_cpus_are_the_limit_when_memory_is_plentiful(self) -> None:
        count, why = capacity.choose_workers(4, 64 * self.GIB, 3 * self.GIB)
        self.assertEqual(count, 4)
        self.assertIn("CPUs is the limit", why)

    def test_there_is_always_one_worker(self) -> None:
        self.assertEqual(capacity.choose_workers(8, 0, 3 * self.GIB)[0], 1)
        self.assertEqual(capacity.choose_workers(8, 2 * self.GIB, 3 * self.GIB)[0], 1)

    def test_unknown_memory_falls_back_to_the_cpus(self) -> None:
        count, why = capacity.choose_workers(6, None, 3 * self.GIB)
        self.assertEqual(count, 6)
        self.assertIn("unknown", why)

    def test_a_build_budget_is_a_few_gib(self) -> None:
        self.assertGreaterEqual(capacity.BUILD_BUDGET, self.GIB)
