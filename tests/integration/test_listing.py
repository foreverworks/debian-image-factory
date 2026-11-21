"""Live checks of DESIGN 7.5's assumption against snapshot.debian.org. Run with DIF_INTEGRATION=1.

The checks are the ones `scripts/spike-listing` prints: this loads that script and asserts them.
"""

import os
import unittest
from functools import cache
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from types import ModuleType

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "spike-listing"


def load_spike() -> ModuleType:
    loader = SourceFileLoader("spike_listing", str(SCRIPT))
    spec = spec_from_loader(loader.name, loader)
    assert spec is not None
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


@cache
def run_spike() -> tuple[str | None, list[str], str]:
    """(newest completed ID, the failed assumptions, the full report), run once."""
    spike = load_spike()
    report = spike.run()
    failed: list[str] = [f"{check.name} [{check.detail}]" for check in report.hard if not check.ok]
    completed_id: str | None = report.completed_id
    return completed_id, failed, str(spike.render(report))


@unittest.skipUnless(os.environ.get("DIF_INTEGRATION") == "1", "set DIF_INTEGRATION=1 to reach snapshot.debian.org")
class LiveListingTests(unittest.TestCase):
    def test_a_completed_id_exists(self) -> None:
        completed_id, _, report = run_spike()
        self.assertIsNotNone(completed_id, report)

    def test_every_assumption_holds(self) -> None:
        _, failed, report = run_spike()
        self.assertEqual(failed, [], "\n" + report)


if __name__ == "__main__":
    unittest.main()
