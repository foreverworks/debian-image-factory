import copy
import unittest

import input_lock
from input_lock import JsonValue

from debian_image_factory import lockrules
from debian_image_factory.definition import Definition
from tests.support.definitions import (
    as_lock,
    child,
    entries_of,
    entry_of,
    example_definition,
    example_lock,
    example_lock_data,
    small,
)

SHA1 = "a" * 40


def problems_of(data: dict[str, JsonValue], spec: Definition | None = None) -> list[str]:
    return lockrules.problems(data, spec or example_definition())


class ExampleLockTest(unittest.TestCase):
    def test_the_example_lock_passes(self) -> None:
        self.assertEqual(problems_of(example_lock_data()), [])

    def test_check_returns_the_lock(self) -> None:
        lock = lockrules.check(example_lock_data(), example_definition())
        self.assertEqual(lock["debian_snapshot"], "20261121T004329Z")
        self.assertIn("node-26", lock["inputs"])

    def test_check_names_every_problem_one_per_line(self) -> None:
        data = example_lock_data()
        del data["debian_snapshot"]
        del entry_of(data, "node-26")["used_by"]
        entry_of(data, "node-release-keys")["module"] = None
        with self.assertRaises(input_lock.LockError) as caught:
            lockrules.check(data, example_definition())
        self.assertEqual(len(str(caught.exception).splitlines()), 2)

    def test_a_lock_is_a_json_object(self) -> None:
        self.assertEqual(lockrules.problems([], example_definition()), ["a lock is a JSON object"])


class EntryRulesTest(unittest.TestCase):
    def test_a_normal_entry_without_used_by_fails(self) -> None:
        data = example_lock_data()
        del entry_of(data, "node-26")["used_by"]
        found = [line for line in problems_of(data) if "builtin:node-tarball" not in line]
        self.assertEqual(len(found), 1)
        self.assertIn("inputs.node-26: no used_by: name the images that install it", found[0])

    def test_used_by_on_a_reserved_entry_fails(self) -> None:
        for name in lockrules.RESERVED:
            with self.subTest(name=name):
                data = example_lock_data()
                entry_of(data, name)["used_by"] = ["os"]
                self.assertIn(f"inputs.{name}: a reserved entry names no images (no used_by)", problems_of(data))

    def test_a_reserved_entry_has_no_module(self) -> None:
        data = example_lock_data()
        entry_of(data, "debian-image-factory")["module"] = "node"
        self.assertIn("inputs.debian-image-factory: a reserved entry has no module", problems_of(data))

    def test_a_null_module_on_a_reserved_entry_is_fine(self) -> None:
        data = example_lock_data()
        entry_of(data, "debian-image-factory")["module"] = None
        self.assertEqual(problems_of(data), [])

    def test_a_module_the_definition_does_not_declare_fails(self) -> None:
        data = example_lock_data()
        entry_of(data, "node-26")["module"] = "nodejs"
        self.assertIn("inputs.node-26.module names 'nodejs', which the definition does not declare", problems_of(data))

    def test_a_null_module_is_the_images_own_hooks(self) -> None:
        data = example_lock_data()
        entry_of(data, "node-26")["module"] = None
        entry_of(data, "node-release-keys")["module"] = None
        self.assertEqual(problems_of(data), [])

    def test_used_by_naming_an_unknown_image_fails_through_input_lock(self) -> None:
        data = example_lock_data()
        entry_of(data, "node-26")["used_by"] = ["ghost"]
        found = [line for line in problems_of(data) if "builtin:node-tarball" not in line and "signed_by" not in line]
        self.assertEqual(len(found), 1)
        self.assertIn("inputs.node-26.used_by names ['ghost'], which are not among", found[0])

    def test_input_locks_own_checks_still_run(self) -> None:
        data = example_lock_data()
        entry_of(data, "node-26")["sha256"] = "xyz"
        self.assertIn("inputs.node-26.sha256 is not 64 lowercase hex digits", problems_of(data))

    def test_the_factory_adds_nothing_to_a_malformed_entry(self) -> None:
        data = example_lock_data()
        entry = entry_of(data, "node-26")
        del entry["used_by"]
        entry["sha256"] = "xyz"
        self.assertEqual(len([line for line in problems_of(data) if "no used_by" in line]), 0)


class SnapshotRulesTest(unittest.TestCase):
    def test_debian_snapshot_is_required(self) -> None:
        data = example_lock_data()
        del data["debian_snapshot"]
        found = problems_of(data)
        self.assertEqual(len(found), 1)
        self.assertIn("debian_snapshot is required", found[0])

    def test_debian_snapshot_must_be_an_id(self) -> None:
        data = example_lock_data()
        data["debian_snapshot"] = "yesterday"
        self.assertIn("is not a snapshot.debian.org ID", " ".join(problems_of(data)))


class BaselineRulesTest(unittest.TestCase):
    def test_required_when_an_image_does_not_use_live_sources(self) -> None:
        data = example_lock_data()
        del entries_of(data)["debian-baseline"]
        found = problems_of(data)
        self.assertEqual(len(found), 1)
        self.assertIn("inputs.debian-baseline is required: ['os'] write apt sources at the baseline snapshot", found[0])

    def test_every_image_with_snapshot_sources_is_named(self) -> None:
        spec = small(
            child("a", "incus", "core", 'apt_sources = "baseline"\n'),
            child("b", "os", "core", 'apt_sources = "baseline-except-security"\n'),
            child("c", "installer", "core"),
        )
        self.assertTrue(lockrules.needs_baseline(spec))
        data = example_lock_data()
        data["inputs"] = {}
        self.assertIn("['a', 'b'] write apt sources", " ".join(problems_of(data, spec)))

    def test_not_required_when_every_image_keeps_live_sources(self) -> None:
        spec = small(child("a", "oci", "core"), child("b", "incus", "core"))
        self.assertFalse(lockrules.needs_baseline(spec))
        data = example_lock_data()
        data["inputs"] = {}
        self.assertEqual(problems_of(data, spec), [])

    def test_a_baseline_entry_is_still_checked_when_no_image_needs_it(self) -> None:
        spec = small(child("a", "oci", "core"))
        data = example_lock_data()
        entries = entries_of(data)
        data["inputs"] = {"debian-baseline": entries["debian-baseline"]}
        self.assertEqual(problems_of(data, spec), [])
        entry_of(data, "debian-baseline")["version"] = "soon"
        self.assertIn(
            "inputs.debian-baseline.version must be a snapshot.debian.org ID", " ".join(problems_of(data, spec))
        )

    def test_the_version_is_a_snapshot_id(self) -> None:
        data = example_lock_data()
        entry_of(data, "debian-baseline")["version"] = "20261108"
        self.assertIn(
            "inputs.debian-baseline.version must be a snapshot.debian.org ID (YYYYMMDDTHHMMSSZ)", problems_of(data)
        )

    def test_the_url_is_the_archives_in_release_for_the_suite(self) -> None:
        self.assertEqual(
            lockrules.baseline_url("trixie"),
            "https://snapshot.debian.org/archive/debian/{version}/dists/trixie/InRelease",
        )
        data = example_lock_data()
        entry_of(data, "debian-baseline")["url"] = (
            "https://snapshot.debian.org/archive/debian/{version}/dists/bookworm/InRelease"
        )
        self.assertIn(f"inputs.debian-baseline.url must be {lockrules.baseline_url('trixie')!r}", problems_of(data))

    def test_the_url_is_checked_against_the_definitions_suite(self) -> None:
        spec = small(
            child("a", "os", "core", 'apt_sources = "baseline"\n'),
            header='schema = 1\n[debian]\nsuite = "forky"\nsource_date_epoch = 5\n',
        )
        data = example_lock_data()
        data["inputs"] = {"debian-baseline": entries_of(example_lock_data())["debian-baseline"]}
        self.assertIn(
            f"inputs.debian-baseline.url must be {lockrules.baseline_url('forky')!r}", problems_of(data, spec)
        )

    def test_a_sha256_is_needed_even_when_another_checksum_is_there(self) -> None:
        data = example_lock_data()
        entry = entry_of(data, "debian-baseline")
        del entry["sha256"]
        entry["sha1"] = SHA1
        self.assertIn(
            "inputs.debian-baseline: needs the sha256 of that InRelease (`lock baseline --id` writes it)",
            problems_of(data),
        )

    def test_no_checksum_at_all_is_input_locks_complaint(self) -> None:
        data = example_lock_data()
        del entry_of(data, "debian-baseline")["sha256"]
        self.assertTrue(any("no checksum" in line for line in problems_of(data)))

    def test_baseline_reads_the_version(self) -> None:
        self.assertEqual(lockrules.baseline(example_lock()), "20261108T000000Z")
        data = example_lock_data()
        del entries_of(data)["debian-baseline"]
        self.assertIsNone(lockrules.baseline(as_lock(data)))


class ModuleSwitchTest(unittest.TestCase):
    def test_modules_without_enabled_by_are_always_on(self) -> None:
        spec = example_definition()
        self.assertTrue(lockrules.module_enabled(spec, None, {}))
        self.assertTrue(lockrules.module_enabled(spec, "node", {"vendor_tools": False}))

    def test_enabled_by_follows_the_parameter(self) -> None:
        spec = example_definition()
        self.assertFalse(lockrules.module_enabled(spec, "vendor-deb", {"vendor_tools": False}))
        self.assertTrue(lockrules.module_enabled(spec, "vendor-deb", {"vendor_tools": True}))
        self.assertFalse(lockrules.module_enabled(spec, "vendor-deb", {}))


class ImageEntriesTest(unittest.TestCase):
    def test_entries_of_a_switched_off_module_are_dropped(self) -> None:
        spec, lock = example_definition(), example_lock()
        self.assertEqual(lockrules.image_entries(lock, spec, "os", {"vendor_tools": False}), {})
        on = lockrules.image_entries(lock, spec, "os", {"vendor_tools": True})
        self.assertEqual(sorted(on), ["example-tool"])

    def test_an_image_gets_only_its_own_entries(self) -> None:
        spec, lock = example_definition(), example_lock()
        own = lockrules.image_entries(lock, spec, "node-26", {"vendor_tools": False})
        self.assertEqual(sorted(own), ["node-26", "node-release-keys"])
        self.assertEqual(lockrules.image_entries(lock, spec, "core", {"vendor_tools": False}), {})
        self.assertEqual(lockrules.image_entries(lock, spec, "oci-base", {"vendor_tools": True}), {})

    def test_reserved_entries_are_never_an_images_inputs(self) -> None:
        data = example_lock_data()
        entry_of(data, "debian-baseline")["used_by"] = ["os"]
        entry_of(data, "debian-image-factory")["used_by"] = ["os"]
        lock = as_lock(data)  # input-lock accepts it; the factory's own rules refuse it, image_entries ignores it
        self.assertEqual(lockrules.image_entries(lock, example_definition(), "os", {"vendor_tools": False}), {})

    def test_an_entry_without_a_module_is_always_installed(self) -> None:
        data = example_lock_data()
        entry = entry_of(data, "node-26")
        entry["module"] = None
        lock = as_lock(copy.deepcopy(data))
        got = lockrules.image_entries(lock, example_definition(), "node-26", {"vendor_tools": False})
        self.assertIn("node-26", got)

    def test_module_of(self) -> None:
        self.assertEqual(lockrules.module_of({"module": "node"}), "node")
        self.assertIsNone(lockrules.module_of({"module": None}))
        self.assertIsNone(lockrules.module_of({}))


class ReservedNamesTest(unittest.TestCase):
    def test_the_reserved_entries(self) -> None:
        self.assertEqual(sorted(lockrules.RESERVED), ["debian-baseline", "debian-image-factory"])


if __name__ == "__main__":
    unittest.main()
