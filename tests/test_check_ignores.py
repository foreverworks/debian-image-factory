import contextlib
import importlib.machinery
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check-ignores"


def load() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("check_ignores", str(SCRIPT))
    spec = importlib.util.spec_from_loader("check_ignores", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


check = load()


class ProblemTest(unittest.TestCase):
    def test_accepts_code_and_reason(self) -> None:
        self.assertIsNone(check.problem("x = f()  # type: ignore[no-any-return]  # f is untyped upstream"))

    def test_accepts_several_codes(self) -> None:
        self.assertIsNone(check.problem("x = f()  # type: ignore[arg-type, misc]  # why"))

    def test_noqa_needs_a_code_and_a_reason(self) -> None:
        self.assertIsNone(check.problem("class Failed(Exception):  # noqa: N818  # named for its exit status"))
        self.assertIn("reason", check.problem("x = 1  # noqa: F541"))
        self.assertIn("rule code", check.problem("x = 1  # noqa"))

    def test_accepts_a_line_without_an_ignore(self) -> None:
        self.assertIsNone(check.problem("x = 1  # a normal comment"))

    def test_rejects_bare_ignore(self) -> None:
        self.assertIn("error code", check.problem("x = f()  # type: ignore"))

    def test_rejects_bare_ignore_with_reason_only(self) -> None:
        self.assertIn("error code", check.problem("x = f()  # type: ignore  # why"))

    def test_rejects_empty_code(self) -> None:
        self.assertIn("error code", check.problem("x = f()  # type: ignore[]  # why"))

    def test_rejects_missing_reason(self) -> None:
        self.assertIn("reason", check.problem("x = f()  # type: ignore[misc]"))

    def test_rejects_empty_reason(self) -> None:
        self.assertIn("reason", check.problem("x = f()  # type: ignore[misc]  #   "))


class FilesTest(unittest.TestCase):
    def test_names_file_and_line(self) -> None:
        found = check.problems("a.py", "x = 1\ny = f()  # type: ignore[misc]\n")
        self.assertEqual(found, ["a.py:2: type: ignore without a reason after it (# type: ignore[code]  # why)"])

    def test_exit_status_and_scan(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tree = Path(raw)
            (tree / "good.py").write_text("x = f()  # type: ignore[misc]  # reason\n")
            (tree / "tool").write_text("#!/usr/bin/env python3\nx = f()  # type: ignore\n")
            (tree / "notes.txt").write_text("# type: ignore\n")
            self.assertEqual(check.main([str(tree / "good.py"), str(tree / "notes.txt")]), 0)
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(check.main([str(tree)]), 1)
            self.assertIn("tool:2:", errors.getvalue())

    def test_this_repository_is_clean(self) -> None:
        self.assertEqual(check.main([]), 0)


if __name__ == "__main__":
    unittest.main()
