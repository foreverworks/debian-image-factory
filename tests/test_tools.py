import json
import re
import unittest
from pathlib import Path

from debian_image_factory.tools import TOOL_PACKAGES, builder_tools, parse_tools

GOOD = [[name, "1.0", "amd64"] for name in sorted(TOOL_PACKAGES)]
ROOT = Path(__file__).resolve().parent.parent


class ParseToolsTest(unittest.TestCase):
    def test_accepts_a_sorted_complete_list(self) -> None:
        parsed = parse_tools(GOOD)
        self.assertEqual(len(parsed), len(TOOL_PACKAGES))
        self.assertEqual(parsed[0], (GOOD[0][0], "1.0", "amd64"))

    def test_rejects_wrong_shapes(self) -> None:
        bad_inputs: list[object] = [None, {}, "x", [1], [["a", "b"]], [["a", "b", 3]], [["", "1", "amd64"]]]
        for bad in bad_inputs:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_tools(bad)

    def test_rejects_unsorted(self) -> None:
        with self.assertRaisesRegex(ValueError, "sorted"):
            parse_tools(list(reversed(GOOD)))

    def test_rejects_missing_and_extra_names(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing"):
            parse_tools(GOOD[1:])
        with self.assertRaisesRegex(ValueError, "unexpected"):
            parse_tools(sorted([*GOOD, ["zzz", "1", "all"]]))

    def test_rejects_duplicates(self) -> None:
        with self.assertRaises(ValueError):
            parse_tools(sorted([*GOOD[1:], GOOD[1], GOOD[1]]))


class BuilderToolsTest(unittest.TestCase):
    def test_packaged_file_parses_and_covers_every_tool(self) -> None:
        tools = builder_tools()
        self.assertEqual(sorted(name for name, _, _ in tools), sorted(TOOL_PACKAGES))

    def test_scripts_builder_lists_the_same_packages(self) -> None:
        script = (ROOT / "scripts" / "builder").read_text(encoding="utf-8")
        match = re.search(r"tool_packages=\(([^)]*)\)", script)
        assert match is not None
        self.assertEqual(sorted(match.group(1).split()), sorted(TOOL_PACKAGES))

    def test_file_is_formatted_as_the_builder_script_writes_it(self) -> None:
        path = ROOT / "src" / "debian_image_factory" / "builder" / "tools.json"
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text, json.dumps(json.loads(text), indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
