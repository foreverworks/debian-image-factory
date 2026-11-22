"""`locked-inputs`: the check's logic with a fake runner, over the example definition's modules."""

import unittest

from debian_image_factory.checks import inputs
from debian_image_factory.checks.model import Result
from debian_image_factory.definition import Module
from debian_image_factory.modules import Probe
from tests.support.definitions import example_definition
from tests.support.rootfs import status_text

NODE = {
    "module": "node",
    "url": "https://nodejs.org/dist/v26.13.1/node-v26.13.1-linux-x64.tar.xz",
    "version": "26.13.1",
    "sha256": "5" * 64,
}
KEYS = {
    "module": "node",
    "url": "https://raw.githubusercontent.com/nodejs/release-keys/abc/gpg-only-active-keys/pubring.kbx",
    "version": "abc",
    "sha256": "1" * 64,
}
TOOL = {"module": "vendor-deb", "apt": "example-tool", "version": "2.4.0-1", "url": "https://x.example/t.deb"}


class Fake:
    """A runner that answers per command and notes what it was asked."""

    def __init__(self, answers: dict[str, tuple[int, str]] | None = None) -> None:
        self.answers = answers or {}
        self.asked: list[Probe] = []

    def __call__(self, probe: Probe) -> tuple[int, str]:
        self.asked.append(probe)
        return self.answers.get(probe.argv[0], (0, probe.expected + "\n"))


def run(entries: dict[str, dict[str, str]], runner: Fake, status: bytes | None = None) -> Result:
    """The check as `test` runs it on the example: the plan's `trust` names the Node keyring as `signed_by`."""
    return inputs.locked_inputs(entries, example_definition().modules, status, runner, {"node-release-keys"})


class ModuleEntriesTest(unittest.TestCase):
    def test_the_tarball_is_probed_and_the_keyring_is_a_trust_root(self) -> None:
        runner = Fake()
        found = run({"node-26": NODE, "node-release-keys": KEYS}, runner)
        self.assertEqual(found.check, "locked-inputs")
        self.assertEqual(found.outcome, "PASSED")
        self.assertEqual(found.passed, ("node-26", "node-release-keys (trust root, not installed)"))
        self.assertEqual(runner.asked, [Probe("node-26", ("/usr/local/bin/node", "--version"), "v26.13.1")])

    def test_another_version_fails_naming_both(self) -> None:
        found = run({"node-26": NODE, "node-release-keys": KEYS}, Fake({"/usr/local/bin/node": (0, "v25.0.0\n")}))
        self.assertEqual(found.outcome, "FAILED")
        self.assertEqual(len(found.failed), 1)
        self.assertIn(
            "node-26: `/usr/local/bin/node --version` printed 'v25.0.0', expected 'v26.13.1'", found.failed[0]
        )
        self.assertEqual(found.passed, ("node-release-keys (trust root, not installed)",))

    def test_a_probe_that_exits_non_zero_fails(self) -> None:
        found = run({"node-26": NODE, "node-release-keys": KEYS}, Fake({"/usr/local/bin/node": (127, "")}))
        self.assertEqual(found.failed, ("node-26: `/usr/local/bin/node --version` exited 127",))

    def test_output_is_stripped(self) -> None:
        found = run({"node-26": NODE, "node-release-keys": KEYS}, Fake({"/usr/local/bin/node": (0, "  v26.13.1  \n")}))
        self.assertEqual(found.outcome, "PASSED")

    def test_a_module_with_no_probe_yet_fails_naming_it(self) -> None:
        file_module = {"module": "files", "version": "1", "url": "https://x.example/f"}
        modules = {**example_definition().modules, "files": Module("files", "builtin:file", None, {})}
        found = inputs.locked_inputs({"f": file_module}, modules, None, Fake())
        self.assertEqual(found.failed, ("f: module files (builtin:file) has no version probe in this release",))

    def test_a_module_the_definition_lacks_fails(self) -> None:
        found = inputs.locked_inputs({"x": {**NODE, "module": "ghost"}}, {}, None, Fake())
        self.assertEqual(found.failed, ("x: module ghost is not in the definition",))

    def test_a_tarball_without_a_version_fails(self) -> None:
        bad = {key: value for key, value in NODE.items() if key != "version"}
        found = run({"node-26": bad, "node-release-keys": KEYS}, Fake())
        self.assertEqual(found.outcome, "FAILED")
        self.assertIn("needs a version", found.failed[0])


class AptEntriesTest(unittest.TestCase):
    def test_the_dpkg_version_is_compared(self) -> None:
        status = status_text([("example-tool", "2.4.0-1", "amd64"), ("other", "1", "all")])
        runner = Fake()
        found = run({"example-tool": TOOL}, runner, status)
        self.assertEqual(found.passed, ("example-tool",))
        self.assertEqual(runner.asked, [], "an apt entry is not probed")

    def test_another_version_is_named(self) -> None:
        found = run({"example-tool": TOOL}, Fake(), status_text([("example-tool", "2.3.0-1", "amd64")]))
        self.assertEqual(found.failed, ("example-tool: example-tool is installed at 2.3.0-1, the lock says 2.4.0-1",))

    def test_not_installed(self) -> None:
        found = run({"example-tool": TOOL}, Fake(), status_text([("other", "1", "all")]))
        self.assertEqual(found.failed, ("example-tool: example-tool 2.4.0-1 is not installed",))

    def test_no_status_file(self) -> None:
        found = run({"example-tool": TOOL}, Fake(), None)
        self.assertEqual(found.outcome, "FAILED")
        self.assertIn("is not in the tarball", found.failed[0])

    def test_a_module_entry_no_probe_sees_fails_unless_it_is_a_trust_root(self) -> None:
        found = inputs.locked_inputs(
            {"node-26": NODE, "node-release-keys": KEYS}, example_definition().modules, None, Fake()
        )
        self.assertEqual(found.outcome, "FAILED")
        self.assertEqual(found.failed, ("node-release-keys: module node has no probe that sees it installed",))

    def test_an_entry_missing_its_fields(self) -> None:
        found = run({"t": {"module": "vendor-deb", "apt": "x"}}, Fake(), status_text([]))
        self.assertIn("needs its package name and a version", found.failed[0])


class MixedTest(unittest.TestCase):
    def test_an_entry_with_no_module_and_no_apt_is_listed_as_not_probed(self) -> None:
        found = run({"data": {"url": "https://x.example/d", "version": "1"}}, Fake())
        self.assertEqual(found.outcome, "PASSED")
        self.assertTrue(found.passed[0].startswith("data (no module installs it"))

    def test_every_entry_is_judged(self) -> None:
        status = status_text([("example-tool", "2.4.0-1", "amd64")])
        found = run({"node-26": NODE, "node-release-keys": KEYS, "example-tool": TOOL}, Fake(), status)
        self.assertEqual(found.outcome, "PASSED")
        self.assertEqual(len(found.passed), 3)

    def test_a_named_trust_root_is_listed_whatever_its_module(self) -> None:
        runner = Fake()
        found = inputs.locked_inputs(
            {"node-26": NODE, "k": {"url": "https://x.example/k.pgp", "version": "1"}},
            example_definition().modules,
            None,
            runner,
            trust_roots={"k"},
        )
        self.assertEqual(found.passed, ("k (trust root, not installed)", "node-26"))
        self.assertEqual([p.entry for p in runner.asked], ["node-26"])

    def test_no_entries_is_a_pass(self) -> None:
        self.assertEqual(run({}, Fake()).outcome, "PASSED")

    def test_many_failures_are_cut_with_a_count(self) -> None:
        many = {f"t{i:03}": {**TOOL, "apt": f"p{i}"} for i in range(40)}
        found = run(many, Fake(), status_text([]))
        self.assertEqual(len(found.failed), 26)
        self.assertEqual(found.failed[-1], "and 15 more")


if __name__ == "__main__":
    unittest.main()
