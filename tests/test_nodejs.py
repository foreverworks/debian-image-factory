"""The node-tarball module: its table, how its entries are told apart, the signed checksums, install lines, probes."""

import unittest

from input_lock import JsonValue

from debian_image_factory import definition, modules, nodejs
from debian_image_factory import lockrules as rules
from debian_image_factory.definition import DefinitionError, Module
from tests.support.definitions import (
    HEADER,
    entries_of,
    entry_of,
    example_definition,
    example_lock_data,
)

TARBALL = "https://nodejs.org/dist/v26.13.1/node-v26.13.1-linux-x64.tar.xz"
KEYRING = "https://raw.githubusercontent.com/nodejs/release-keys/abc/gpg-only-active-keys/pubring.kbx"
SHA = "5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864"
OTHER = "a" * 64


def modules_toml(extra: str = "") -> str:
    return f'[modules.node]\nuse = "builtin:node-tarball"\n{extra}'


class TableTest(unittest.TestCase):
    def problems(self, extra: str) -> list[str]:
        try:
            definition.parse(HEADER + '[images.core]\nkind = "core"\n' + modules_toml(extra))
        except DefinitionError as error:
            return str(error).splitlines()
        return []

    def test_the_default_and_a_valid_prefix(self) -> None:
        self.assertEqual(self.problems(""), [])
        self.assertEqual(self.problems('prefix = "/opt/node-26"\n'), [])
        self.assertEqual(nodejs.prefix_of({}), "/usr/local")
        self.assertEqual(nodejs.prefix_of({"prefix": "/opt/node"}), "/opt/node")

    def test_a_prefix_must_be_an_absolute_normalised_path(self) -> None:
        for bad in ("usr/local", "/usr/local/", "/usr//local", "/usr/../etc", "/", "/a/./b", "/with space", "/q'uote"):
            with self.subTest(prefix=bad):
                found = self.problems(f'prefix = "{bad}"\n')
                self.assertEqual(len(found), 1, found)
                self.assertTrue(found[0].startswith("modules.node: prefix "), found[0])

    def test_a_prefix_must_be_a_string(self) -> None:
        self.assertEqual(self.problems("prefix = 3\n"), ["modules.node: prefix must be a string"])

    def test_any_other_key_is_refused_by_name(self) -> None:
        found = self.problems("links = false\nmirror = 'x'\n")
        self.assertEqual(len(found), 2)
        self.assertIn("modules.node: unknown key 'links'", found[0])
        self.assertIn("unknown key 'mirror'", found[1])

    def test_enabled_by_is_still_allowed(self) -> None:
        text = HEADER + '[params]\nflag = true\n[images.core]\nkind = "core"\n' + modules_toml('enabled_by = "flag"\n')
        self.assertEqual(definition.parse(text).modules["node"].enabled_by, "flag")

    def test_other_modules_are_not_held_to_these_keys(self) -> None:
        text = HEADER + '[images.core]\nkind = "core"\n[modules.f]\nuse = "builtin:file"\nlinks = false\n'
        self.assertEqual(definition.parse(text).modules["f"].table["links"], False)


class TarballRuleTest(unittest.TestCase):
    def test_the_tarball_is_told_by_its_url(self) -> None:
        self.assertTrue(nodejs.is_tarball(TARBALL))
        self.assertTrue(nodejs.is_tarball("https://x.example/n.tar.gz?token=1"))
        self.assertFalse(nodejs.is_tarball(KEYRING))

    def test_exactly_one_signed_tarball(self) -> None:
        urls = {"a": TARBALL, "b": KEYRING}
        self.assertEqual(nodejs.tarball_problems(urls, {"a": True, "b": False}), [])

    def test_none_or_two(self) -> None:
        self.assertIn("exactly one release tarball", nodejs.tarball_problems({"b": KEYRING}, {})[0])
        two = nodejs.tarball_problems({"a": TARBALL, "a2": TARBALL.replace("x64", "arm64")}, {"a": True, "a2": True})
        self.assertEqual(len(two), 1)
        self.assertIn("['a', 'a2']", two[0])

    def test_an_unsigned_tarball_is_named(self) -> None:
        found = nodejs.tarball_problems({"a": TARBALL, "b": KEYRING}, {"a": False})
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith("entry a needs signed_by"), found[0])
        self.assertIn("sums_url", found[0])


class LockRulesTest(unittest.TestCase):
    def test_the_example_passes(self) -> None:
        self.assertEqual(rules.problems(example_lock_data(), example_definition()), [])

    def test_a_tarball_with_neither_field_is_named(self) -> None:
        data = example_lock_data()
        del entry_of(data, "node-26")["signed_by"]
        del entry_of(data, "node-26")["sums_url"]
        found = rules.problems(data, example_definition())
        self.assertEqual(len(found), 1, found)
        self.assertIn("images.node-26: module node (builtin:node-tarball): entry node-26 needs signed_by", found[0])

    def test_one_of_the_two_fields_is_input_locks_to_name(self) -> None:
        for field, expected in (
            ("signed_by", "sums_url is a signed checksum list, so it needs signed_by"),
            ("sums_url", "signed_by needs a sums_url"),
        ):
            with self.subTest(field=field):
                data = example_lock_data()
                del entry_of(data, "node-26")[field]
                self.assertTrue(any(expected in line for line in rules.problems(data, example_definition())))

    def test_two_tarballs_are_named(self) -> None:
        data = example_lock_data()
        entries_of(data)["extra"] = {**entry_of(data, "node-26")}
        found = rules.problems(data, example_definition())
        self.assertTrue(any("exactly one release tarball" in line and "['extra', 'node-26']" in line for line in found))

    def test_no_tarball_is_named(self) -> None:
        data = example_lock_data()
        del entry_of(data, "node-26")["used_by"]
        found = rules.problems(data, example_definition())
        self.assertTrue(
            any("module node (builtin:node-tarball): needs exactly one release tarball" in x for x in found)
        )

    def test_the_keyring_must_be_used_by_the_images_of_its_signed_entry(self) -> None:
        data = example_lock_data()
        entry_of(data, "node-26")["used_by"] = ["node-26", "os"]
        found = [line for line in rules.problems(data, example_definition()) if "signed_by" in line]
        self.assertEqual(len(found), 1)
        self.assertIn("inputs.node-26.signed_by names node-release-keys, whose used_by lacks ['os']", found[0])

    def test_input_locks_own_trust_checks_apply(self) -> None:
        data = example_lock_data()
        entry_of(data, "node-26")["signed_by"] = "ghost"
        found = rules.problems(data, example_definition())
        self.assertTrue(any("signed_by names ghost, which is not an entry of this lock" in line for line in found))

    def test_a_signed_lock_is_schema_two_and_is_accepted(self) -> None:
        data = example_lock_data()
        self.assertEqual(data["schema"], 2)
        self.assertEqual(rules.check(data, example_definition())["inputs"]["node-26"]["signed_by"], "node-release-keys")
        data["schema"] = 1
        self.assertTrue(any('need "schema": 2' in line for line in rules.problems(data, example_definition())))


def node_module(**table: JsonValue) -> Module:
    return Module("node", nodejs.MODULE, None, {"use": nodejs.MODULE, **table})


ENTRIES = {
    "node-26": {"url": TARBALL, "version": "26.13.1", "sha256": SHA, "module": "node"},
    "node-release-keys": {"url": KEYRING, "version": "abc", "sha256": OTHER, "module": "node"},
}


class InstallLinesTest(unittest.TestCase):
    def lines(self, module: Module | None = None) -> list[str]:
        return modules.install_lines(
            module or node_module(), ENTRIES, inputs="/factory/run/inputs", source_date_epoch=1754697600
        )

    def test_the_script_runs_in_the_builder_on_the_staged_tarball(self) -> None:
        command = self.lines()[-1]
        self.assertEqual(
            command,
            'python3 /factory/node_install.py "$root" '
            "/factory/run/inputs/node-26/node-v26.13.1-linux-x64.tar.xz /usr/local 1754697600",
        )

    def test_the_prefix_is_passed(self) -> None:
        self.assertIn(" /opt/node 1754697600", self.lines(node_module(prefix="/opt/node"))[-1])

    def test_the_keyring_is_not_installed(self) -> None:
        self.assertNotIn("pubring", "\n".join(self.lines()))

    def test_the_helper_file_is_the_script(self) -> None:
        text = modules.helper_files(node_module())[modules.NODE_INSTALL]
        self.assertIn("def install(", text)
        self.assertEqual(modules.node_install_text(), text)
        self.assertEqual(modules.helper_files(Module("f", "builtin:file", None, {})), {})

    def test_the_script_imports_nothing_of_the_factory(self) -> None:
        text = modules.node_install_text()
        self.assertNotIn("debian_image_factory", text)
        self.assertNotIn("from .", text)

    def test_another_module_is_not_installed_here(self) -> None:
        with self.assertRaises(NotImplementedError):
            modules.install_lines(Module("f", "builtin:file", None, {}), ENTRIES, inputs="/i", source_date_epoch=0)

    def test_a_file_name_that_is_not_safe_is_staged_as_file(self) -> None:
        self.assertEqual(modules.input_file_name({"url": "https://x.example/"}), "file")
        self.assertEqual(modules.input_file_name({"url": "https://x.example/a%20b.tar.xz"}), "a b.tar.xz")

    def test_two_tarballs_are_refused(self) -> None:
        both = {**ENTRIES, "other": {**ENTRIES["node-26"], "url": TARBALL.replace("x64", "arm64")}}
        with self.assertRaisesRegex(ValueError, "exactly one release tarball"):
            modules.install_lines(node_module(), both, inputs="/i", source_date_epoch=0)


class ProbesTest(unittest.TestCase):
    def test_the_tarball_is_probed_at_its_prefix(self) -> None:
        self.assertEqual(
            modules.probes(node_module(), ENTRIES),
            [modules.Probe("node-26", ("/usr/local/bin/node", "--version"), "v26.13.1")],
        )
        self.assertEqual(
            modules.probes(node_module(prefix="/opt/n"), ENTRIES)[0].argv, ("/opt/n/bin/node", "--version")
        )

    def test_the_keyring_has_no_probe(self) -> None:
        self.assertEqual([p.entry for p in modules.probes(node_module(), ENTRIES)], ["node-26"])

    def test_a_version_is_needed(self) -> None:
        with self.assertRaisesRegex(ValueError, "needs a version"):
            modules.probes(node_module(), {**ENTRIES, "node-26": {"url": TARBALL}})

    def test_another_module_has_no_probes_yet(self) -> None:
        with self.assertRaises(NotImplementedError):
            modules.probes(Module("f", "builtin:file", None, {}), ENTRIES)
