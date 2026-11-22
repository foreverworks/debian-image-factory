"""plan.build_plan from Decisions (DESIGN 7.3, 7.4, 7.6): states, forced rebuilds, and what moved since a plan."""

import hashlib
import json
import unittest
from collections.abc import Mapping, Sequence

from input_lock import JsonValue, Package

from debian_image_factory import ENGINE, definition, plan
from debian_image_factory.definition import KIND_DEFAULTS, Definition
from debian_image_factory.identity import FileFact, ImageInputs
from debian_image_factory.published import Decision
from tests.support.definitions import (
    as_lock,
    child,
    compute,
    entry_of,
    example_definition,
    example_lock_data,
    jsonable,
    parse_definition,
)

CORE_SET: tuple[Package, ...] = (("base-files", "1.0", "amd64"), ("dpkg", "1.0", "amd64"))
FACTS = {"files/core/etc/motd": FileFact("1" * 64, "0644"), "files/core": FileFact(None, "0755", directory=True)}
FACTS = {**FACTS, "hooks/installer-trim.sh": FileFact("2" * 64, "0755", text="x")}
SNAPSHOT = "20261101T000000Z"
BASELINE = "20261108T000000Z"


def sets(**more: Sequence[Package]) -> dict[str, tuple[Package, ...]]:
    one: dict[str, tuple[Package, ...]] = {
        "core": CORE_SET,
        "oci-base": CORE_SET,
        "node-26": CORE_SET,
        "incus-base": (*CORE_SET, ("openssh-server", "1.0", "amd64")),
        "installer": (*CORE_SET, ("linux-image-fixture", "1.0", "amd64")),
        "os": (*CORE_SET, ("linux-image-fixture", "1.0", "amd64")),
    }
    one.update({name: tuple(value) for name, value in more.items()})
    return one


def inputs_for(
    spec: Definition | None = None,
    packages: Mapping[str, Sequence[Package]] | None = None,
    lock_data: dict[str, JsonValue] | None = None,
    **options: object,
) -> dict[str, ImageInputs]:
    spec = spec or example_definition()
    params = options.get("params")
    return compute(
        as_lock(lock_data or example_lock_data()),
        spec,
        packages or sets(),
        files=FACTS,
        params=params if isinstance(params, dict) else None,
    )


def make(
    inputs: Mapping[str, ImageInputs],
    decisions: Mapping[str, Decision] | None = None,
    spec: Definition | None = None,
    **options: object,
) -> dict[str, JsonValue]:
    spec = spec or example_definition()
    return plan.build_plan(
        spec,
        snapshot=SNAPSHOT,
        baseline=BASELINE,
        params=spec.params,
        inputs=inputs,
        decisions=decisions or {},
        **options,  # type: ignore[arg-type]  # keyword options of build_plan, passed through by the tests
    )


def images_of(document: Mapping[str, JsonValue]) -> dict[str, dict[str, JsonValue]]:
    found = document["images"]
    assert isinstance(found, dict)
    return {name: jsonable(entry) for name, entry in found.items()}


def listed(entry: Mapping[str, JsonValue], key: str) -> list[JsonValue]:
    value = entry[key]
    assert isinstance(value, list)
    return value


def digest_of(name: str) -> str:
    """A made-up artifact digest in hex for `name`."""
    return hashlib.sha256(name.encode()).hexdigest()


def reuse_all(spec: Definition) -> dict[str, Decision]:
    return {name: Decision("reuse", artifact=digest_of(name)) for name in spec.images}


class StatesTest(unittest.TestCase):
    spec = example_definition()
    inputs = inputs_for()

    def test_everything_reusable_is_reused_and_nothing_changes(self) -> None:
        document = make(self.inputs, reuse_all(self.spec))
        for name, entry in images_of(document).items():
            self.assertEqual(entry["state"], "reuse", name)
            self.assertEqual(entry["artifact"], f"sha256:{digest_of(name)}")
            self.assertNotIn("because", entry)
        self.assertEqual(plan.changed(document), [])

    def test_an_image_without_a_decision_builds(self) -> None:
        decisions = reuse_all(self.spec)
        del decisions["installer"]
        entry = images_of(make(self.inputs, decisions))["installer"]
        self.assertEqual(entry["state"], "build")
        self.assertEqual(entry["because"], [{"published": "no artifact with this identity"}])

    def test_a_build_decision_builds(self) -> None:
        decisions = {**reuse_all(self.spec), "os": Decision("build")}
        document = make(self.inputs, decisions)
        self.assertEqual(plan.changed(document), ["os"])

    def test_a_build_after_a_failed_check_says_which(self) -> None:
        decisions = {**reuse_all(self.spec), "os": Decision("build", failed=("os-boot", "package-set"))}
        entry = images_of(make(self.inputs, decisions))["os"]
        self.assertEqual(entry["because"], [{"failed": ["os-boot", "package-set"]}])

    def test_a_wait_names_the_artifact_and_the_checks_it_waits_for(self) -> None:
        decisions = {
            **reuse_all(self.spec),
            "incus-base": Decision("wait", artifact=digest_of("cand"), waiting_for=("incus-boot",)),
        }
        entry = images_of(make(self.inputs, decisions))["incus-base"]
        self.assertEqual(entry["state"], "wait")
        self.assertEqual(entry["artifact"], f"sha256:{digest_of('cand')}")
        self.assertEqual(entry["waiting_for"], ["incus-boot"])

    def test_a_parent_build_forces_its_children_to_build_even_when_they_could_be_reused(self) -> None:
        decisions = {**reuse_all(self.spec), "oci-base": Decision("build")}
        document = make(self.inputs, decisions)
        self.assertEqual(plan.changed(document), ["node-26", "oci-base"])
        self.assertEqual(listed(images_of(document)["node-26"], "because")[0], {"parent": "oci-base", "state": "build"})

    def test_a_core_build_rebuilds_every_image(self) -> None:
        decisions = {**reuse_all(self.spec), "core": Decision("build")}
        self.assertEqual(plan.changed(make(self.inputs, decisions)), sorted(self.spec.images))

    def test_a_waiting_parent_makes_a_child_that_is_not_reusable_wait(self) -> None:
        decisions = {
            **reuse_all(self.spec),
            "oci-base": Decision("wait", artifact=digest_of("cand"), waiting_for=("oci-run",)),
            "node-26": Decision("build"),
        }
        entry = images_of(make(self.inputs, decisions))["node-26"]
        self.assertEqual(entry["state"], "wait")
        self.assertEqual(entry["waiting_for"], [])
        self.assertEqual(entry["because"], [{"parent": "oci-base", "state": "wait"}])
        self.assertNotIn("artifact", entry)

    def test_a_child_that_is_itself_waiting_under_a_waiting_parent_keeps_its_artifact_and_checks(self) -> None:
        decisions = {
            **reuse_all(self.spec),
            "oci-base": Decision("wait", artifact=digest_of("parent"), waiting_for=("oci-run",)),
            "node-26": Decision("wait", artifact=digest_of("child"), waiting_for=("locked-inputs",)),
        }
        entry = images_of(make(self.inputs, decisions))["node-26"]
        self.assertEqual(entry["state"], "wait")
        self.assertEqual(entry["artifact"], f"sha256:{digest_of('child')}")
        self.assertEqual(entry["waiting_for"], ["locked-inputs"])
        self.assertEqual(entry["because"], [{"parent": "oci-base", "state": "wait"}])

    def test_a_waiting_parent_leaves_a_reusable_child_reused(self) -> None:
        decisions = {
            **reuse_all(self.spec),
            "oci-base": Decision("wait", artifact=digest_of("cand"), waiting_for=("x",)),
        }
        entry = images_of(make(self.inputs, decisions))["node-26"]
        self.assertEqual(entry["state"], "reuse")

    def test_waiting_passes_down_to_grandchildren(self) -> None:
        decisions = {
            "core": Decision("reuse", artifact=digest_of("a")),
            "oci-base": Decision("wait", artifact=digest_of("b"), waiting_for=("x",)),
            "node-26": Decision("build"),
        }
        document = images_of(make(self.inputs, decisions))
        self.assertEqual(document["node-26"]["state"], "wait")

    def test_a_build_parent_beats_a_waiting_grandparent(self) -> None:
        spec = parse_definition(
            "[images.core]\nkind = 'core'\n"
            + child("a", "oci", "core")
            + child("b", "oci", "a")
            + child("c", "oci", "b")
        )
        inputs = inputs_for(
            spec, dict.fromkeys(("core", "a", "b", "c"), CORE_SET), {"debian_snapshot": SNAPSHOT, "inputs": {}}
        )
        decisions = {
            "core": Decision("wait", artifact=digest_of("x"), waiting_for=("p",)),
            "a": Decision("build"),
            "b": Decision("reuse", artifact=digest_of("y")),
            "c": Decision("reuse", artifact=digest_of("z")),
        }
        got = {name: entry["state"] for name, entry in images_of(make(inputs, decisions, spec)).items()}
        self.assertEqual(got, {"core": "wait", "a": "wait", "b": "reuse", "c": "reuse"})

    def test_rebuild_forces_a_build_with_the_reason_whatever_the_targets_hold(self) -> None:
        document = make(self.inputs, reuse_all(self.spec), rebuild={"installer": "archive key rotation"})
        self.assertEqual(plan.changed(document), ["installer"])
        self.assertEqual(images_of(document)["installer"]["because"], [{"rebuild": "archive key rotation"}])
        self.assertEqual(images_of(document)["os"]["state"], "reuse")

    def test_rebuild_of_a_parent_rebuilds_its_children_by_inheritance(self) -> None:
        document = make(self.inputs, reuse_all(self.spec), rebuild={"oci-base": "why not"})
        self.assertEqual(plan.changed(document), ["node-26", "oci-base"])
        self.assertEqual(images_of(document)["oci-base"]["because"], [{"rebuild": "why not"}])
        self.assertEqual(images_of(document)["node-26"]["because"], [{"parent": "oci-base", "state": "build"}])

    def test_rebuild_beats_a_waiting_parent(self) -> None:
        decisions = {**reuse_all(self.spec), "oci-base": Decision("wait", artifact=digest_of("c"), waiting_for=("x",))}
        document = make(self.inputs, decisions, rebuild={"node-26": "r"})
        self.assertEqual(images_of(document)["node-26"]["state"], "build")

    def test_rejected_artifacts_are_listed_for_the_image(self) -> None:
        document = make(self.inputs, reuse_all(self.spec), rejected={"os": ["x.tar: no records file"], "core": []})
        found = images_of(document)
        self.assertEqual(found["os"]["rejected"], ["x.tar: no records file"])
        self.assertNotIn("rejected", found["core"])

    def test_changed_lists_builds_sorted(self) -> None:
        document = make(self.inputs, {})
        self.assertEqual(plan.changed(document), sorted(self.spec.images))

    def test_changed_tolerates_a_plan_without_images(self) -> None:
        self.assertEqual(plan.changed({}), [])
        self.assertEqual(plan.changed({"images": 3}), [])
        self.assertEqual(plan.changed({"images": {"a": "build", "b": {"state": "build"}}}), ["b"])


class DocumentTest(unittest.TestCase):
    spec = example_definition()
    inputs = inputs_for()

    def test_the_header(self) -> None:
        document = make(self.inputs, reuse_all(self.spec))
        self.assertEqual(document["schema"], 1)
        self.assertEqual(document["engine"], ENGINE)
        self.assertEqual(document["snapshot"], SNAPSHOT)
        self.assertEqual(document["baseline"], BASELINE)
        self.assertEqual(document["debian"], {"suite": "trixie", "components": ["main"], "architecture": "amd64"})
        self.assertEqual(document["params"], {"vendor_tools": False})
        self.assertIsInstance(document["factory"], str)

    def test_the_document_is_json(self) -> None:
        document = make(self.inputs, {})
        self.assertEqual(json.loads(json.dumps(document)), document)

    def test_every_image_is_listed_with_its_inputs(self) -> None:
        found = images_of(make(self.inputs, {}))
        self.assertEqual(sorted(found), sorted(self.spec.images))
        node = found["node-26"]
        self.assertEqual(node["kind"], "oci")
        self.assertEqual(node["parent"], "oci-base")
        self.assertEqual(node["identity"], self.inputs["node-26"].identity)
        self.assertEqual(node["parent_identity"], self.inputs["oci-base"].identity)
        self.assertEqual(node["modules"], ["node"])
        self.assertEqual(
            node["trust"],
            {
                "node-26": {
                    "signed_by": "node-release-keys",
                    "sums_url": "https://nodejs.org/dist/v26.13.1/SHASUMS256.txt.asc",
                }
            },
        )
        self.assertEqual(found["core"]["trust"], {})
        self.assertIsNone(found["core"]["parent"])
        self.assertIsNone(found["core"]["parent_identity"])

    def test_inputs_are_the_build_fields_with_the_url_rendered(self) -> None:
        listed = images_of(make(self.inputs, {}))["node-26"]["inputs"]
        assert isinstance(listed, dict)
        entry = listed["node-26"]
        assert isinstance(entry, dict)
        self.assertEqual(entry["url"], "https://nodejs.org/dist/v26.13.1/node-v26.13.1-linux-x64.tar.xz")
        for hint in ("datasource", "depName", "used_by", "description"):
            self.assertNotIn(hint, entry)

    def test_core_requests_its_own_packages_and_children_add_the_kind_defaults(self) -> None:
        found = images_of(make(self.inputs, {}))
        self.assertEqual(found["core"]["request"], ["apt", "ca-certificates", "locales", "tzdata"])
        self.assertEqual(found["oci-base"]["request"], [])
        self.assertEqual(
            found["incus-base"]["request"], sorted({*KIND_DEFAULTS["incus"], "openssh-server", "sudo", "curl"})
        )

    def test_request_is_sorted_and_without_repeats(self) -> None:
        spec = parse_definition(
            "[images.core]\nkind = 'core'\n" + child("k", "installer", "core", 'packages = ["udev", "zz", "aa"]\n')
        )
        self.assertEqual(plan.request(spec, "k", ()), ["aa", "iproute2", "netbase", "systemd-sysv", "udev", "zz"])

    def test_a_module_adds_the_packages_its_install_needs_at_run_time(self) -> None:
        spec = parse_definition(
            "[modules.node]\nuse = 'builtin:node-tarball'\n[modules.f]\nuse = 'builtin:file'\npath = '/opt/f'\n"
            "[images.core]\nkind = 'core'\n" + child("k", "oci", "core", 'packages = ["zz"]\n')
        )
        self.assertEqual(plan.request(spec, "k", ("f", "node")), ["libatomic1", "zz"])
        self.assertEqual(plan.request(spec, "k", ("f",)), ["zz"])
        found = images_of(make(self.inputs, {}))
        self.assertEqual(found["node-26"]["request"], ["libatomic1"])

    def test_checks_come_from_the_definition_with_locked_inputs_for_images_with_entries(self) -> None:
        found = images_of(make(self.inputs, {}))
        self.assertIn("locked-inputs", listed(found["node-26"], "checks"))
        self.assertNotIn("locked-inputs", listed(found["oci-base"], "checks"))
        self.assertIn("install-on-test-vm", listed(found["os"], "checks"))

    def test_the_params_an_image_reads_are_listed(self) -> None:
        found = images_of(make(self.inputs, {}))
        self.assertEqual(found["os"]["params"], {"vendor_tools": False})
        self.assertEqual(found["core"]["params"], {})

    def test_the_package_list_is_name_version_architecture(self) -> None:
        found = images_of(make(self.inputs, {}))
        self.assertEqual(found["core"]["packages"], [[n, v, a] for n, v, a in sorted(CORE_SET)])


class PreviousPlanTest(unittest.TestCase):
    """`previous` says what moved: package from/to, input from/to, and any other part of the identity."""

    spec = example_definition()
    before = inputs_for()
    plan_before = make(before, reuse_all(spec))

    def after(
        self, previous: object, inputs: Mapping[str, ImageInputs], build: Sequence[str] = ("installer",)
    ) -> Mapping[str, JsonValue]:
        """A plan where only `build` have no artifact, against `previous` as written to disk and read back."""
        decisions = {name: one for name, one in reuse_all(self.spec).items() if name not in build}
        return make(inputs, decisions, previous=json.loads(json.dumps(previous)))

    def because(self, document: Mapping[str, JsonValue], name: str) -> list[JsonValue]:
        because = images_of(document)[name]["because"]
        assert isinstance(because, list)
        return because

    def test_a_package_moved(self) -> None:
        packages = sets(installer=(*CORE_SET, ("linux-image-fixture", "1.1", "amd64")))
        document = self.after(self.plan_before, inputs_for(packages=packages))
        self.assertEqual(plan.changed(document), ["installer"])
        self.assertIn(
            {"package": "linux-image-fixture", "from": "1.0", "to": "1.1"}, self.because(document, "installer")
        )

    def test_a_package_added_and_one_removed(self) -> None:
        packages = sets(installer=(*CORE_SET, ("kexec-tools", "2.0", "amd64")))
        because = self.because(self.after(self.plan_before, inputs_for(packages=packages)), "installer")
        self.assertIn({"package": "kexec-tools", "from": None, "to": "2.0"}, because)
        self.assertIn({"package": "linux-image-fixture", "from": "1.0", "to": None}, because)

    def test_an_input_version_moved(self) -> None:
        data = example_lock_data()
        entry_of(data, "node-26")["version"] = "26.14.0"
        because = self.because(self.after(self.plan_before, inputs_for(lock_data=data), ("node-26",)), "node-26")
        self.assertIn({"input": "node-26", "from": "26.13.1", "to": "26.14.0"}, because)

    def test_an_input_field_moved_without_a_version_change_names_the_field(self) -> None:
        data = example_lock_data()
        entry_of(data, "node-26")["sha256"] = "3" * 64
        because = self.because(self.after(self.plan_before, inputs_for(lock_data=data), ("node-26",)), "node-26")
        self.assertIn({"input": "node-26", "fields": ["sha256"]}, because)

    def test_an_input_added_to_an_image(self) -> None:
        data = example_lock_data()
        entry_of(data, "node-26")["used_by"] = ["node-26", "os"]
        because = self.because(self.after(self.plan_before, inputs_for(lock_data=data), ("os",)), "os")
        self.assertIn({"input": "node-26", "from": None, "to": "26.13.1"}, because)

    def test_a_parent_that_moved_is_named_with_its_old_and_new_identity(self) -> None:
        newer = (("base-files", "1.1", "amd64"), CORE_SET[1])
        packages = {
            name: tuple(p for p in pkgs if p[0] not in ("base-files", "dpkg")) + newer for name, pkgs in sets().items()
        }
        after = inputs_for(packages=packages)
        document = self.after(self.plan_before, after, ("core",))
        because = self.because(document, "oci-base")
        self.assertEqual(because[0], {"parent": "core", "state": "build"})
        self.assertIn(
            {"parent_identity": {"from": self.before["core"].identity, "to": after["core"].identity}}, because
        )
        self.assertIn({"package": "base-files", "from": "1.0", "to": "1.1"}, because)

    def test_a_param_that_moved(self) -> None:
        document = self.after(self.plan_before, inputs_for(params={"vendor_tools": True}), ("os",))
        because = self.because(document, "os")
        self.assertIn({"params": {"from": {"vendor_tools": False}, "to": {"vendor_tools": True}}}, because)

    def test_a_recipe_that_moved(self) -> None:
        facts_changed = dict(FACTS)
        facts_changed["hooks/installer-trim.sh"] = FileFact("9" * 64, "0755", text="x")
        after = compute(as_lock(example_lock_data()), self.spec, sets(), files=facts_changed)
        because = self.because(self.after(self.plan_before, after), "installer")
        self.assertEqual([next(iter(item)) for item in because if isinstance(item, dict)], ["published", "recipe"])
        recipe = because[1]
        assert isinstance(recipe, dict)
        self.assertEqual(
            recipe["recipe"], {"from": self.before["installer"].recipe_digest, "to": after["installer"].recipe_digest}
        )

    def test_an_image_whose_identity_did_not_move_has_no_diff(self) -> None:
        document = self.after(self.plan_before, self.before, ("core", "installer"))
        self.assertEqual(self.because(document, "core"), [{"published": "no artifact with this identity"}])

    def test_a_previous_plan_without_the_image_or_in_any_shape_adds_nothing(self) -> None:
        previous: object
        for previous in (
            None,
            [],
            {},
            {"images": []},
            {"images": {"core": 3}},
            {"images": {"core": {"identity": "x"}}},
        ):
            with self.subTest(previous=previous):
                document = make(
                    self.before, {n: d for n, d in reuse_all(self.spec).items() if n != "installer"}, previous=previous
                )
                self.assertEqual(self.because(document, "installer"), [{"published": "no artifact with this identity"}])

    def test_a_previous_plan_with_odd_packages_and_inputs_is_read_leniently(self) -> None:
        odd = {"identity": "x", "packages": [["only-two", "1"], "nope", [1, 2, 3]], "inputs": "text"}
        document = make(self.before, {}, previous={"images": {"installer": odd}})
        because = self.because(document, "installer")
        self.assertIn({"package": "linux-image-fixture", "from": None, "to": "1.0"}, because)

    def test_only_builds_are_explained(self) -> None:
        packages = sets(installer=(*CORE_SET, ("linux-image-fixture", "1.1", "amd64")))
        after = inputs_for(packages=packages)
        decisions = {**reuse_all(self.spec), "installer": Decision("reuse", artifact=digest_of("installer"))}
        document = make(after, decisions, previous=json.loads(json.dumps(self.plan_before)))
        self.assertNotIn("because", images_of(document)["installer"])

    def test_package_changes_and_input_changes_directly(self) -> None:
        self.assertEqual(
            plan.package_changes(None, (("a", "1", "amd64"),)), [{"package": "a", "from": None, "to": "1"}]
        )
        self.assertEqual(plan.package_changes([["a", "1", "amd64"]], (("a", "1", "amd64"),)), [])
        self.assertEqual(plan.input_changes({"x": {"version": "1"}}, {}), [{"input": "x", "from": "1", "to": None}])
        self.assertEqual(
            plan.input_changes(
                {"x": {"version": "1", "url": "a", "sha256": "b"}}, {"x": {"version": "1", "url": "c", "sha256": "d"}}
            ),
            [{"input": "x", "fields": ["sha256", "url"]}],
        )
        self.assertEqual(plan.input_changes("junk", {}), [])


class SmallDefinitionTest(unittest.TestCase):
    def test_a_core_alone(self) -> None:
        spec = parse_definition("[images.core]\nkind = 'core'\n")
        inputs = inputs_for(spec, {"core": CORE_SET}, {"debian_snapshot": SNAPSHOT, "inputs": {}})
        document = make(inputs, {"core": Decision("reuse", artifact=digest_of("a"))}, spec)
        self.assertEqual(images_of(document)["core"]["state"], "reuse")
        self.assertEqual(definition.top_down(spec), ["core"])


if __name__ == "__main__":
    unittest.main()
