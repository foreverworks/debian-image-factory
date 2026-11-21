"""Identity (DESIGN 7.1, 7.6): pure, from made-up package sets. One test per row of the table that needs no build."""

import dataclasses
import os
import re
import shutil
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import ClassVar
from unittest import mock

from input_lock import JsonValue, Package

from debian_image_factory import ENGINE, definition, files, identity
from debian_image_factory.definition import Definition, Param
from debian_image_factory.identity import FileFact, ImageInputs
from tests.support.definitions import (
    EXAMPLES,
    TOOLS,
    as_lock,
    changed_names,
    child,
    compute,
    entry_of,
    example_lock_data,
    example_text,
    identities,
    parse_definition,
)

CORE_SET: tuple[Package, ...] = (
    ("base-files", "1.0", "amd64"),
    ("dpkg", "1.0", "amd64"),
    ("fixture-essential", "1.0", "all"),
)
EXTRA = "[images.os-child]\nkind = 'os'\nparent = 'os'\n[images.node-child]\nkind = 'oci'\nparent = 'node-26'\n"
ALL = sorted(["core", "incus-base", "installer", "node-child", "node-26", "oci-base", "os", "os-child"])


def packages_for(core: tuple[Package, ...] = CORE_SET) -> dict[str, tuple[Package, ...]]:
    """Every image's set: the core's, plus one package of its own for the kinds that install any."""
    return {
        "core": core,
        "oci-base": core,
        "node-26": core,
        "node-child": core,
        "incus-base": (*core, ("openssh-server", "1.0", "amd64")),
        "installer": (*core, ("linux-image-fixture", "1.0", "amd64")),
        "os": (*core, ("linux-image-fixture", "1.0", "amd64")),
        "os-child": (*core, ("linux-image-fixture", "1.0", "amd64")),
    }


def read_example_files(spec: Definition, root: Path = EXAMPLES) -> dict[str, FileFact]:
    found, problems = files.read_files(root, spec)
    assert problems == [], problems
    return found


def reformatted(text: str) -> str:
    """The same definition written differently: comments gone, blank lines and indentation added, keys
    reversed inside each table and the tables in reverse order."""
    blocks = re.split(r"\n(?=\[)", re.sub(r"[ \t]*#[^\n]*", "", text))
    head, tables = blocks[0], blocks[1:]
    out = []
    for block in reversed(tables):
        lines = [line for line in block.splitlines() if line.strip()]
        out.append(lines[0] + "\n\n" + "\n".join("    " + line for line in reversed(lines[1:])))
    first = "\n".join(line for line in head.splitlines() if line.strip())
    return first + "\n\n\n" + "\n\n\n".join(out) + "\n\n"


def setting(key: str, value: str) -> Callable[[dict[str, JsonValue]], None]:
    """A change to a lock entry: set one field."""

    def change(entry: dict[str, JsonValue]) -> None:
        entry[key] = value

    return change


class IdentityCase(unittest.TestCase):
    """A base identity computed for the example plus two extra children, and helpers to move one input."""

    spec: Definition
    facts: dict[str, FileFact]
    base: dict[str, ImageInputs]

    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = definition.parse(example_text() + EXTRA)
        cls.facts = read_example_files(cls.spec)
        cls.base = compute(as_lock(example_lock_data()), cls.spec, packages_for(), files=cls.facts)

    def changed_by_lock(self, change: Callable[[dict[str, JsonValue]], None], entry: str = "node-26") -> list[str]:
        data = example_lock_data()
        change(entry_of(data, entry))
        return changed_names(self.base, compute(as_lock(data), self.spec, packages_for(), files=self.facts))

    def changed_by_params(self, params: Mapping[str, Param], files_: Mapping[str, FileFact] | None = None) -> list[str]:
        after = compute(
            as_lock(example_lock_data()), self.spec, packages_for(), files=files_ or self.facts, params=params
        )
        return changed_names(self.base, after)

    def changed_by_definition(self, text: str, files_: Mapping[str, FileFact] | None = None) -> list[str]:
        spec = definition.parse(text)
        after = compute(as_lock(example_lock_data()), spec, packages_for(), files=files_ or read_example_files(spec))
        return changed_names(self.base, after)


class PackageRowsTest(IdentityCase):
    def test_the_base_identities_are_distinct_hex_digests(self) -> None:
        values = list(identities(self.base).values())
        self.assertEqual(len(set(values)), len(ALL))
        for value in values:
            self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_no_package_change_leaves_every_identity_equal(self) -> None:
        again = compute(as_lock(example_lock_data()), self.spec, packages_for(), files=self.facts)
        self.assertEqual(identities(again), identities(self.base))

    def test_the_order_and_repeats_of_a_package_set_do_not_matter(self) -> None:
        shuffled = {name: (*reversed(pkgs), *pkgs) for name, pkgs in packages_for().items()}
        again = compute(as_lock(example_lock_data()), self.spec, shuffled, files=self.facts)
        self.assertEqual(identities(again), identities(self.base))

    def test_a_package_version_change_in_core_changes_core_and_every_descendant(self) -> None:
        sets = {
            name: tuple(("base-files", "1.1", "amd64") if p[0] == "base-files" else p for p in pkgs)
            for name, pkgs in packages_for().items()
        }
        after = compute(as_lock(example_lock_data()), self.spec, sets, files=self.facts)
        self.assertEqual(changed_names(self.base, after), ALL)

    def test_a_new_version_of_a_package_only_the_installer_installs_changes_only_the_installer(self) -> None:
        sets = packages_for()
        sets["installer"] = (*CORE_SET, ("linux-image-fixture", "1.1", "amd64"))
        after = compute(as_lock(example_lock_data()), self.spec, sets, files=self.facts)
        self.assertEqual(changed_names(self.base, after), ["installer"])

    def test_a_package_only_the_os_installs_changes_the_os_and_its_child(self) -> None:
        sets = packages_for()
        sets["os"] = (*CORE_SET, ("linux-image-fixture", "1.1", "amd64"))
        sets["os-child"] = sets["os"]
        after = compute(as_lock(example_lock_data()), self.spec, sets, files=self.facts)
        self.assertEqual(changed_names(self.base, after), ["os", "os-child"])

    def test_a_changed_architecture_is_a_change(self) -> None:
        sets = packages_for()
        sets["incus-base"] = (*CORE_SET, ("openssh-server", "1.0", "all"))
        after = compute(as_lock(example_lock_data()), self.spec, sets, files=self.facts)
        self.assertEqual(changed_names(self.base, after), ["incus-base"])

    def test_the_build_snapshot_never_enters(self) -> None:
        data = example_lock_data()
        data["debian_snapshot"] = "20261115T000000Z"
        after = compute(as_lock(data), self.spec, packages_for(), files=self.facts)
        self.assertEqual(identities(after), identities(self.base))

    def test_a_child_carries_its_parents_identity(self) -> None:
        for name, one in self.base.items():
            parent = self.spec.images[name].parent
            self.assertEqual(one.parent, parent)
            self.assertEqual(one.parent_identity, None if parent is None else self.base[parent].identity)


class BaselineRowTest(IdentityCase):
    def moved(self) -> list[str]:
        after = compute(
            as_lock(example_lock_data()), self.spec, packages_for(), files=self.facts, baseline="20261115T000000Z"
        )
        return changed_names(self.base, after)

    def test_a_moved_baseline_changes_only_images_with_baseline_sources_and_their_children(self) -> None:
        self.assertEqual(self.moved(), ["os", "os-child"])

    def test_the_baseline_enters_the_recipe_only_for_images_that_point_at_it(self) -> None:
        self.assertEqual(self.base["os"].recipe["baseline"], "20261108T000000Z")
        for name in ("core", "installer", "incus-base", "oci-base", "node-26"):
            self.assertIsNone(self.base[name].recipe["baseline"], name)

    def test_no_baseline_at_all_changes_only_the_baseline_images(self) -> None:
        after = compute(as_lock(example_lock_data()), self.spec, packages_for(), files=self.facts, baseline=None)
        self.assertEqual(changed_names(self.base, after), ["os", "os-child"])


class LockEntryRowsTest(IdentityCase):
    NODE_USERS: ClassVar[list[str]] = ["node-26", "node-child"]

    def test_a_version_change_changes_the_images_in_used_by_and_their_children(self) -> None:
        self.assertEqual(self.changed_by_lock(lambda entry: entry.update(version="26.14.0")), self.NODE_USERS)

    def test_a_checksum_change_does_the_same(self) -> None:
        self.assertEqual(self.changed_by_lock(lambda entry: entry.update(sha256="2" * 64)), self.NODE_USERS)

    def test_a_new_checksum_algorithm_does_the_same(self) -> None:
        self.assertEqual(self.changed_by_lock(lambda entry: entry.update(sha512="3" * 128)), self.NODE_USERS)

    def test_a_url_change_does_the_same(self) -> None:
        change = lambda entry: entry.update(url="https://mirror.example.com/node-v{version}.tar.xz")  # noqa: E731  # a one-line change to a lock entry, like the others
        self.assertEqual(self.changed_by_lock(change), self.NODE_USERS)

    def test_a_digest_change_does_the_same(self) -> None:
        self.assertEqual(self.changed_by_lock(lambda entry: entry.update(digest="0" * 40)), self.NODE_USERS)

    def test_the_second_entry_of_an_image_counts_too(self) -> None:
        self.assertEqual(
            self.changed_by_lock(lambda entry: entry.update(sha256="4" * 64), "node-release-keys"), self.NODE_USERS
        )

    def test_a_field_the_factory_does_not_know_does_the_same(self) -> None:
        for key, value in (("build", "7"), ("sdk_channel", "stable")):
            with self.subTest(key=key):
                self.assertEqual(self.changed_by_lock(setting(key, value)), self.NODE_USERS)

    def test_a_changed_unknown_field_changes_it_again(self) -> None:
        data = example_lock_data()
        entry_of(data, "node-26")["build"] = "7"
        before = compute(as_lock(data), self.spec, packages_for(), files=self.facts)
        entry_of(data, "node-26")["build"] = "8"
        after = compute(as_lock(data), self.spec, packages_for(), files=self.facts)
        self.assertEqual(changed_names(before, after), self.NODE_USERS)

    def test_renovate_hints_and_the_description_change_nothing(self) -> None:
        for key in (
            "datasource",
            "depName",
            "packageName",
            "extractVersion",
            "versioning",
            "registryUrl",
            "description",
        ):
            with self.subTest(key=key):
                self.assertEqual(self.changed_by_lock(setting(key, "something else")), [])

    def test_a_removed_hint_changes_nothing(self) -> None:
        def drop(entry: dict[str, JsonValue]) -> None:
            del entry["datasource"]
            del entry["depName"]

        self.assertEqual(self.changed_by_lock(drop), [])

    def test_the_reserved_entries_enter_no_identity(self) -> None:
        for name in ("debian-image-factory", "debian-baseline"):
            with self.subTest(name=name):
                self.assertEqual(self.changed_by_lock(lambda entry: entry.update(version="9.9.9"), name), [])
                self.assertEqual(self.changed_by_lock(lambda entry: entry.update(sha256="5" * 64), name), [])

    def test_a_switched_off_modules_entry_enters_no_identity(self) -> None:
        self.assertEqual(self.changed_by_lock(lambda entry: entry.update(version="9.9"), "example-tool"), [])
        self.assertEqual(self.changed_by_lock(lambda entry: entry.update(sha256="6" * 64), "example-tool"), [])

    def test_adding_an_image_to_used_by_changes_only_that_image_and_its_children(self) -> None:
        self.assertEqual(
            self.changed_by_lock(lambda entry: entry.update(used_by=["node-26", "os"])), ["os", "os-child"]
        )

    def test_removing_an_image_from_used_by_changes_that_image_and_its_children(self) -> None:
        data = example_lock_data()
        entry_of(data, "node-release-keys")["used_by"] = ["node-26", "os"]
        before = compute(as_lock(data), self.spec, packages_for(), files=self.facts)
        entry_of(data, "node-release-keys")["used_by"] = ["node-26"]
        after = compute(as_lock(data), self.spec, packages_for(), files=self.facts)
        self.assertEqual(changed_names(before, after), ["os", "os-child"])

    def test_an_images_entries_are_the_ones_listing_it(self) -> None:
        self.assertEqual(sorted(self.base["node-26"].entries), ["node-26", "node-release-keys"])
        self.assertEqual(sorted(self.base["os"].entries), [])
        self.assertEqual(self.base["node-child"].entries, {})


class DefinitionRowsTest(IdentityCase):
    def test_a_module_table_change_changes_the_images_using_it_and_their_children(self) -> None:
        text = (example_text() + EXTRA).replace('prefix = "/usr/local"', 'prefix = "/opt/node"')
        self.assertNotEqual(text, example_text() + EXTRA)
        self.assertEqual(self.changed_by_definition(text), ["node-26", "node-child"])

    def test_a_module_gaining_a_key_does_the_same(self) -> None:
        text = (example_text() + EXTRA).replace('prefix = "/usr/local"', 'prefix = "/usr/local"\nlinks = false')
        self.assertEqual(self.changed_by_definition(text), ["node-26", "node-child"])

    def test_a_modules_use_change_does_the_same(self) -> None:
        text = (example_text() + EXTRA).replace('use = "builtin:node-tarball"', 'use = "builtin:file"')
        self.assertEqual(self.changed_by_definition(text), ["node-26", "node-child"])

    def test_a_module_no_image_uses_changes_nothing(self) -> None:
        text = (example_text() + EXTRA).replace('use = "builtin:deb"', 'use = "builtin:file"')
        self.assertEqual(self.changed_by_definition(text), [])

    def test_a_hook_content_change_changes_that_image_and_its_children(self) -> None:
        hook = self.facts["hooks/installer-trim.sh"]
        edited = {**self.facts, "hooks/installer-trim.sh": dataclasses.replace(hook, sha256="7" * 64)}
        self.assertEqual(self.changed_by_params(self.spec.params, edited), ["installer"])

    def test_a_hook_content_change_reaches_children(self) -> None:
        spec = parse_definition(
            child("a", "installer", "core", 'hooks = ["h.sh"]\n')
            + child("b", "installer", "a")
            + "[images.core]\nkind='core'\n"
        )
        packages = {"core": CORE_SET, "a": CORE_SET, "b": CORE_SET}
        lock = as_lock({"debian_snapshot": "20261101T000000Z", "inputs": {}})
        one = {"h.sh": FileFact("1" * 64, "0755", text="echo")}
        two = {"h.sh": FileFact("2" * 64, "0755", text="echo")}
        self.assertEqual(
            changed_names(compute(lock, spec, packages, files=one), compute(lock, spec, packages, files=two)),
            ["a", "b"],
        )

    def test_a_file_tree_content_change_changes_core_and_everything_below(self) -> None:
        facts = dict(self.facts)
        facts["files/core/etc/motd"] = dataclasses.replace(facts["files/core/etc/motd"], sha256="8" * 64)
        self.assertEqual(self.changed_by_params(self.spec.params, facts), ALL)

    def test_a_file_added_to_a_tree_changes_it(self) -> None:
        facts = dict(self.facts)
        facts["files/core/etc/extra"] = FileFact("9" * 64, "0644")
        self.assertEqual(self.changed_by_params(self.spec.params, facts), ALL)

    def test_a_file_that_is_not_referenced_changes_nothing(self) -> None:
        facts = {**self.facts, "hooks/unused.sh": FileFact("a" * 64, "0755", text="x")}
        self.assertEqual(self.changed_by_params(self.spec.params, facts), [])

    def test_a_referenced_file_that_was_not_read_is_an_error(self) -> None:
        facts = {path: fact for path, fact in self.facts.items() if path != "hooks/installer-trim.sh"}
        with self.assertRaisesRegex(ValueError, r"images.installer: files not read: \['hooks/installer-trim.sh'\]"):
            compute(as_lock(example_lock_data()), self.spec, packages_for(), files=facts)

    def test_reformatting_the_definition_changes_nothing(self) -> None:
        text = example_text() + EXTRA
        other = reformatted(text)
        self.assertNotEqual(text, other)
        self.assertNotIn("#", other)
        self.assertEqual(definition.top_down(definition.parse(other)), definition.top_down(self.spec))
        self.assertEqual(self.changed_by_definition(other), [])

    def test_comments_alone_change_nothing(self) -> None:
        self.assertEqual(self.changed_by_definition("# a new comment\n" + example_text() + EXTRA + "\n# another\n"), [])

    def test_an_images_own_section_enters_its_recipe(self) -> None:
        text = (example_text() + EXTRA).replace(
            '[images.node-26]\nkind = "oci"', '[images.node-26]\nkind = "oci"\ncompression = "zstd"'
        )
        self.assertEqual(self.changed_by_definition(text), ["node-26", "node-child"])

    def test_the_kind_table_enters_its_recipe(self) -> None:
        text = (example_text() + EXTRA).replace('oci = { cmd = ["node"] }', 'oci = { cmd = ["node", "--version"] }')
        self.assertEqual(self.changed_by_definition(text), ["node-26", "node-child"])

    def test_the_debian_settings_enter_every_identity(self) -> None:
        text = (example_text() + EXTRA).replace("source_date_epoch = 1754697600", "source_date_epoch = 1754697601")
        self.assertEqual(self.changed_by_definition(text), ALL)

    def test_the_components_enter_every_identity(self) -> None:
        text = (example_text() + EXTRA).replace('components = ["main"]', 'components = ["main", "contrib"]')
        self.assertEqual(self.changed_by_definition(text), ALL)


class ParamRowsTest(IdentityCase):
    def test_a_flip_changes_only_the_images_whose_modules_it_switches(self) -> None:
        self.assertEqual(self.changed_by_params({"vendor_tools": True}), ["os", "os-child"])

    def test_an_image_reads_the_switch_of_its_module_on_or_off(self) -> None:
        self.assertEqual(self.base["os"].params, {"vendor_tools": False})
        self.assertEqual(self.base["node-26"].params, {})
        self.assertEqual(self.base["core"].params, {})

    def test_a_param_flip_via_a_hook_changes_only_the_images_whose_hook_reads_it(self) -> None:
        spec = parse_definition(
            "[params]\nflag = false\nother = false\n"
            + "[images.core]\nkind = 'core'\n"
            + child("kit", "installer", "core", 'hooks = ["h.sh"]\n')
            + child("plain", "installer", "core", 'hooks = ["p.sh"]\n')
            + child("below", "installer", "kit")
        )
        facts = {
            "h.sh": FileFact("1" * 64, "0755", text='echo "$FACTORY_PARAM_FLAG"'),
            "p.sh": FileFact("2" * 64, "0755", text="echo hello"),
        }
        packages = dict.fromkeys(("core", "kit", "plain", "below"), CORE_SET)
        lock = as_lock({"debian_snapshot": "20261101T000000Z", "inputs": {}})
        before = compute(lock, spec, packages, files=facts)
        self.assertEqual(before["kit"].params, {"flag": False})
        self.assertEqual(before["plain"].params, {})
        flipped = compute(lock, spec, packages, files=facts, params={"flag": True, "other": False})
        self.assertEqual(changed_names(before, flipped), ["below", "kit"])
        unread = compute(lock, spec, packages, files=facts, params={"flag": False, "other": True})
        self.assertEqual(changed_names(before, unread), [])

    def test_a_module_script_that_reads_a_param_counts_for_the_images_using_the_module(self) -> None:
        spec = parse_definition(
            '[params]\nflag = false\n[modules.sdk]\nuse = "hooks/sdk.sh"\n'
            + "[images.core]\nkind = 'core'\n"
            + child("kit", "installer", "core")
            + child("plain", "installer", "core")
        )
        lock = as_lock(
            {
                "debian_snapshot": "20261101T000000Z",
                "inputs": {
                    "sdk": {
                        "module": "sdk",
                        "sha256": "1" * 64,
                        "url": "https://example.com/sdk-{version}.tar",
                        "used_by": ["kit"],
                        "version": "1",
                    }
                },
            }
        )
        facts = {"hooks/sdk.sh": FileFact("3" * 64, "0755", text='[ "$FACTORY_PARAM_FLAG" = true ]')}
        packages = dict.fromkeys(("core", "kit", "plain"), CORE_SET)
        before = compute(lock, spec, packages, files=facts)
        after = compute(lock, spec, packages, files=facts, params={"flag": True})
        self.assertEqual(changed_names(before, after), ["kit"])

    def test_a_hook_reads_a_param_on_word_boundaries_only(self) -> None:
        spec = parse_definition(
            "[params]\nflag = false\nflag_more = false\n[images.core]\nkind = 'core'\n"
            + child("kit", "installer", "core", 'hooks = ["h.sh"]\n')
        )
        lock = as_lock({"debian_snapshot": "20261101T000000Z", "inputs": {}})
        packages = dict.fromkeys(("core", "kit"), CORE_SET)
        for text, reads in (
            ("echo $FACTORY_PARAM_FLAG_MORE", {"flag_more": False}),
            ("echo ${FACTORY_PARAM_FLAG}", {"flag": False}),
            ("echo $FACTORY_PARAM_FLAG_MORE $FACTORY_PARAM_FLAG", {"flag": False, "flag_more": False}),
            ("echo XFACTORY_PARAM_FLAG", {}),
        ):
            with self.subTest(text=text):
                facts = {"h.sh": FileFact("1" * 64, "0755", text=text)}
                self.assertEqual(compute(lock, spec, packages, files=facts)["kit"].params, reads)

    def test_param_env_names(self) -> None:
        self.assertEqual(identity.param_env("vendor_tools"), "FACTORY_PARAM_VENDOR_TOOLS")
        self.assertEqual(identity.param_env("a1"), "FACTORY_PARAM_A1")


class BuilderRowsTest(IdentityCase):
    def test_a_builder_tool_version_change_changes_everything(self) -> None:
        tools = (("dpkg", "1.1", "amd64"), TOOLS[1])
        after = compute(as_lock(example_lock_data()), self.spec, packages_for(), files=self.facts, tools=tools)
        self.assertEqual(changed_names(self.base, after), ALL)

    def test_the_order_of_an_images_packages_and_of_the_components_does_not_matter(self) -> None:
        text = example_text().replace(
            'packages = ["openssh-server", "sudo", "curl"]', 'packages = ["curl", "sudo", "openssh-server"]'
        )
        self.assertNotEqual(text, example_text())
        self.assertEqual(self.changed_by_definition(text + EXTRA), [])
        wider = example_text().replace('components = ["main"]', 'components = ["main", "contrib"]')
        flipped = wider.replace('components = ["main", "contrib"]', 'components = ["contrib", "main"]')
        spec_a, spec_b = definition.parse(wider + EXTRA), definition.parse(flipped + EXTRA)
        lock = as_lock(example_lock_data())
        one = compute(lock, spec_a, packages_for(), files=read_example_files(spec_a))
        two = compute(lock, spec_b, packages_for(), files=read_example_files(spec_b))
        self.assertEqual(identities(one), identities(two))

    def test_the_order_of_the_tools_does_not_matter(self) -> None:
        after = compute(
            as_lock(example_lock_data()), self.spec, packages_for(), files=self.facts, tools=tuple(reversed(TOOLS))
        )
        self.assertEqual(identities(after), identities(self.base))

    def test_a_raised_engine_revision_changes_everything(self) -> None:
        with mock.patch("debian_image_factory.identity.ENGINE", ENGINE + 1):
            after = compute(as_lock(example_lock_data()), self.spec, packages_for(), files=self.facts)
        self.assertEqual(changed_names(self.base, after), ALL)

    def test_the_factory_release_version_is_not_an_input(self) -> None:
        data = example_lock_data()
        entry_of(data, "debian-image-factory")["version"] = "0.2.0"
        after = compute(as_lock(data), self.spec, packages_for(), files=self.facts)
        self.assertEqual(identities(after), identities(self.base))


class FileModesTest(IdentityCase):
    """The file edge normalises modes, so a checkout's umask never changes an identity (DESIGN 7.1)."""

    def tree(self) -> Path:
        scratch = tempfile.TemporaryDirectory(prefix="dif-files-")
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name) / "example"
        shutil.copytree(EXAMPLES, root)
        return root

    def identities_at(self, root: Path) -> dict[str, ImageInputs]:
        return compute(
            as_lock(example_lock_data()), self.spec, packages_for(), files=read_example_files(self.spec, root)
        )

    def test_the_copy_is_the_same_as_the_original(self) -> None:
        self.assertEqual(identities(self.identities_at(self.tree())), identities(self.base))

    def test_0644_and_0664_are_the_same(self) -> None:
        root = self.tree()
        os.chmod(root / "files/core/etc/motd", 0o664)
        self.assertEqual(identities(self.identities_at(root)), identities(self.base))

    def test_0600_and_0644_are_the_same(self) -> None:
        root = self.tree()
        os.chmod(root / "files/core/etc/motd", 0o600)
        self.assertEqual(identities(self.identities_at(root)), identities(self.base))

    def test_the_executable_bit_on_a_file_in_a_tree_changes_core_and_below(self) -> None:
        root = self.tree()
        os.chmod(root / "files/core/etc/motd", 0o755)
        self.assertEqual(changed_names(self.base, self.identities_at(root)), ALL)

    def test_a_group_executable_bit_counts_as_executable(self) -> None:
        root = self.tree()
        os.chmod(root / "files/core/etc/motd", 0o654)
        self.assertEqual(changed_names(self.base, self.identities_at(root)), ALL)

    def test_the_executable_bit_on_a_hook_changes_that_image_only(self) -> None:
        root = self.tree()
        hook = root / "hooks/installer-trim.sh"
        os.chmod(hook, hook.stat().st_mode & ~0o111)
        self.assertEqual(changed_names(self.base, self.identities_at(root)), ["installer"])

    def test_directory_modes_are_normalised(self) -> None:
        root = self.tree()
        os.chmod(root / "files/core/etc", 0o700)
        self.assertEqual(identities(self.identities_at(root)), identities(self.base))

    def test_mode_of(self) -> None:
        self.assertEqual(files.mode_of(0o100644), "0644")
        self.assertEqual(files.mode_of(0o100664), "0644")
        self.assertEqual(files.mode_of(0o100755), "0755")
        self.assertEqual(files.mode_of(0o100700), "0755")
        self.assertEqual(files.mode_of(0o040700), "0755")

    def test_a_script_keeps_its_text_and_a_tree_does_not(self) -> None:
        facts = read_example_files(self.spec)
        self.assertIn("#!", facts["hooks/installer-trim.sh"].text)
        self.assertEqual(facts["files/core/etc/motd"].text, "")
        self.assertTrue(facts["files/core"].directory)
        self.assertIsNone(facts["files/core"].sha256)

    def test_a_fifo_in_a_tree_is_refused(self) -> None:
        root = self.tree()
        os.mkfifo(root / "files/core/etc/pipe")
        _, problems = files.read_files(root, self.spec)
        self.assertEqual(problems, ["files/core/etc/pipe: a file tree holds regular files, directories and links only"])

    def test_a_tree_or_hook_that_leaves_the_definition_through_a_link_is_refused(self) -> None:
        root = self.tree()
        outside = Path(tempfile.mkdtemp(dir=root.parent))
        (outside / "x.sh").write_text("#!/bin/sh\n")
        hook = root / "hooks/installer-trim.sh"
        hook.unlink()
        hook.symlink_to(outside / "x.sh")
        shutil.rmtree(root / "files/core")
        (root / "files/core").symlink_to(outside)
        _, problems = files.read_files(root, self.spec)
        self.assertEqual(
            problems,
            [
                "hooks/installer-trim.sh: leaves the definition's directory (through a symbolic link)",
                "files/core: leaves the definition's directory (through a symbolic link)",
            ],
        )

    def test_the_edge_names_what_it_cannot_read(self) -> None:
        root = self.tree()
        (root / "hooks/installer-trim.sh").unlink()
        shutil.rmtree(root / "files")
        _, problems = files.read_files(root, self.spec)
        self.assertEqual(
            problems,
            [
                "hooks/installer-trim.sh: a hook or module script must be a regular file",
                "files/core: a file tree must be a directory",
            ],
        )

    def test_a_hook_that_is_a_symbolic_link_is_refused(self) -> None:
        root = self.tree()
        hook = root / "hooks/installer-trim.sh"
        real = root / "hooks/real.sh"
        hook.rename(real)
        hook.symlink_to(real)
        _, problems = files.read_files(root, self.spec)
        self.assertEqual(problems, ["hooks/installer-trim.sh: a hook or module script must be a regular file"])

    def test_a_symbolic_link_inside_a_tree_enters_by_its_target(self) -> None:
        root = self.tree()
        (root / "files/core/etc/link").symlink_to("motd")
        found, problems = files.read_files(root, self.spec)
        self.assertEqual(problems, [])
        self.assertEqual(found["files/core/etc/link"], FileFact(None, "0777", link="motd"))
        before = compute(as_lock(example_lock_data()), self.spec, packages_for(), files=found)
        (root / "files/core/etc/link").unlink()
        (root / "files/core/etc/link").symlink_to("issue")
        found, _ = files.read_files(root, self.spec)
        after = compute(as_lock(example_lock_data()), self.spec, packages_for(), files=found)
        self.assertEqual(changed_names(before, after), ALL)

    def test_fact_json(self) -> None:
        self.assertEqual(identity.fact_json(FileFact("a" * 64, "0644")), {"mode": "0644", "sha256": "a" * 64})
        self.assertEqual(
            identity.fact_json(FileFact(None, "0755", directory=True)), {"directory": True, "mode": "0755"}
        )
        self.assertEqual(identity.fact_json(FileFact(None, "0777", link="x")), {"link": "x"})


if __name__ == "__main__":
    unittest.main()
