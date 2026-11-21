import unittest

from debian_image_factory import definition
from debian_image_factory.definition import BUILTIN_CHECKS, DefinitionError, Param
from tests.support.definitions import CORE, HEADER, child, example_definition, parse_definition, small


def refusal(body: str, header: str = HEADER) -> str:
    """The message of the DefinitionError a definition raises (fails when it parses)."""
    with unittest.TestCase().assertRaises(DefinitionError) as caught:
        definition.parse(header + body)
    return str(caught.exception)


class ExampleTest(unittest.TestCase):
    def test_the_example_parses(self) -> None:
        spec = example_definition()
        self.assertEqual(sorted(spec.images), ["core", "incus-base", "installer", "node-26", "oci-base", "os"])
        self.assertEqual(spec.debian.suite, "trixie")
        self.assertEqual(spec.debian.source_date_epoch, 1754697600)
        self.assertEqual(dict(spec.params), {"vendor_tools": False})
        self.assertEqual(sorted(spec.modules), ["node", "vendor-deb"])
        self.assertEqual(spec.modules["vendor-deb"].enabled_by, "vendor_tools")
        self.assertEqual(spec.images["os"].apt_sources, "baseline-except-security")
        self.assertEqual(spec.images["core"].apt_sources, "live")
        self.assertEqual(spec.images["node-26"].kind_table, {"cmd": ["node"]})

    def test_a_minimal_definition_takes_the_defaults(self) -> None:
        spec = parse_definition(CORE)
        self.assertEqual(spec.debian.components, ("main",))
        self.assertEqual(spec.debian.architectures, ("amd64",))
        self.assertEqual(spec.debian.source_date_epoch, 1754697600)
        self.assertEqual(spec.images["core"].compression, "gzip")
        self.assertEqual(dict(spec.checks), {"default": ("builtin",)})

    def test_the_images_keep_their_whole_section(self) -> None:
        spec = parse_definition(CORE + 'packages = ["tzdata"]\n')
        self.assertEqual(spec.images["core"].section, {"kind": "core", "packages": ["tzdata"]})
        self.assertEqual(spec.images["core"].packages, ("tzdata",))


class RefusalTest(unittest.TestCase):
    def test_not_toml(self) -> None:
        self.assertIn("not TOML", refusal("[images\n"))

    def test_schema_is_required(self) -> None:
        with self.assertRaises(DefinitionError) as caught:
            definition.parse('[debian]\nsuite = "trixie"\n' + CORE)
        self.assertIn("schema = 1 is required", str(caught.exception))

    def test_unknown_top_level_key(self) -> None:
        self.assertIn(
            "unknown top-level keys ['colour']", refusal(CORE, 'schema = 1\ncolour = 1\n[debian]\nsuite = "trixie"\n')
        )

    def test_a_cycle(self) -> None:
        message = refusal(CORE + child("a", "oci", "b") + child("b", "oci", "a"))
        self.assertIn("images.a: its parents form a cycle (a -> b -> a)", message)
        self.assertIn("images.b: its parents form a cycle (b -> a -> b)", message)

    def test_a_missing_parent(self) -> None:
        self.assertIn(
            "images.lost.parent names 'nowhere', which is not an image", refusal(CORE + child("lost", "oci", "nowhere"))
        )

    def test_a_non_core_image_needs_a_parent(self) -> None:
        self.assertIn("images.lost.parent is required for a oci image", refusal(CORE + '[images.lost]\nkind = "oci"\n'))

    def test_a_core_has_no_parent(self) -> None:
        self.assertIn("a core image has no parent", refusal(CORE + 'parent = "core"\n'))

    def test_no_core(self) -> None:
        self.assertIn("exactly one core image, not 0", refusal(""))

    def test_two_cores(self) -> None:
        message = refusal(CORE + '[images.other]\nkind = "core"\n')
        self.assertIn("exactly one core image, not 2 (['core', 'other'])", message)

    def test_a_kind_that_cannot_derive_from_its_parents_kind(self) -> None:
        message = refusal(CORE + child("box", "incus", "core") + child("layer", "oci", "box"))
        self.assertIn("images.layer: a oci image cannot derive from incus image 'box'", message)

    def test_every_kind_derives_from_core_and_from_itself_only(self) -> None:
        for kind in ("oci", "incus", "installer", "os"):
            with self.subTest(kind=kind):
                small(child("a", kind, "core"), child("b", kind, "a"))
                other = "oci" if kind != "oci" else "os"
                self.assertIn("cannot derive", refusal(CORE + child("a", kind, "core") + child("b", other, "a")))

    def test_a_kernel_package_in_core(self) -> None:
        self.assertIn(
            "core never installs a kernel (linux-image-amd64)", refusal(CORE + 'packages = ["linux-image-amd64"]\n')
        )

    def test_a_kernel_package_outside_core_is_fine(self) -> None:
        small(child("kit", "installer", "core", 'packages = ["linux-image-amd64"]\n'))

    def test_unknown_image_key(self) -> None:
        self.assertIn("images.core: unknown keys ['colour']", refusal(CORE + 'colour = "red"\n'))

    def test_another_kinds_table_is_an_unknown_key(self) -> None:
        self.assertIn("unknown keys ['oci']", refusal(CORE + "oci = { cmd = [] }\n"))

    def test_unknown_debian_key(self) -> None:
        self.assertIn("debian: unknown keys ['mirror']", refusal(CORE, HEADER + 'mirror = "x"\n'))

    def test_unknown_oci_key(self) -> None:
        message = refusal(CORE + child("a", "oci", "core", "oci = { colour = 1 }\n"))
        self.assertIn("images.a.oci: unknown key 'colour'", message)

    def test_oci_values_are_typed(self) -> None:
        message = refusal(CORE + child("a", "oci", "core", 'oci = { user = 0, cmd = "sh", env = { A = 1 } }\n'))
        self.assertIn("images.a.oci.user must be a string", message)
        self.assertIn("images.a.oci.cmd must be a list of strings", message)
        self.assertIn("images.a.oci.env must be a table of strings", message)

    def test_a_bad_kind(self) -> None:
        self.assertIn("images.core.kind must be one of", refusal('[images.core]\nkind = "vm"\n'))

    def test_bad_apt_sources(self) -> None:
        message = refusal(CORE + child("box", "incus", "core", 'apt_sources = "mirror"\n'))
        self.assertIn("images.box.apt_sources must be one of ['live', 'baseline', 'baseline-except-security']", message)

    def test_snapshot_sources_only_on_kinds_that_boot(self) -> None:
        for source in ("baseline", "baseline-except-security"):
            with self.subTest(source=source, kind="core"):
                self.assertIn("a core image keeps live sources", refusal(CORE + f'apt_sources = "{source}"\n'))
            with self.subTest(source=source, kind="oci"):
                message = refusal(CORE + child("a", "oci", "core", f'apt_sources = "{source}"\n'))
                self.assertIn("a oci image keeps live sources", message)
            for kind in ("incus", "installer", "os"):
                with self.subTest(source=source, kind=kind):
                    small(child("a", kind, "core", f'apt_sources = "{source}"\n'))

    def test_enabled_by_names_an_undeclared_parameter(self) -> None:
        message = refusal(CORE + '[modules.m]\nuse = "builtin:file"\nenabled_by = "flag"\n')
        self.assertIn("modules.m.enabled_by names 'flag', which [params] does not declare", message)

    def test_enabled_by_names_a_parameter_that_is_not_boolean(self) -> None:
        for declared in ('flag = "yes"', "flag = 3"):
            with self.subTest(declared=declared):
                message = refusal(
                    f'[params]\n{declared}\n[modules.m]\nuse = "builtin:file"\nenabled_by = "flag"\n' + CORE
                )
                self.assertIn("modules.m.enabled_by names 'flag', which is not a boolean parameter", message)

    def test_a_module_that_is_not_builtin_needs_a_relative_path(self) -> None:
        for use in ("/etc/passwd", "../up.sh", "a//b.sh", "./x.sh", "a/../b.sh"):
            with self.subTest(use=use):
                message = refusal(CORE + f'[modules.m]\nuse = "{use}"\n')
                self.assertIn("modules.m.use: a script path is relative to the definition and stays inside it", message)

    def test_an_unknown_builtin_module(self) -> None:
        self.assertIn(
            "modules.m.use: 'builtin:nope' is not one of", refusal(CORE + '[modules.m]\nuse = "builtin:nope"\n')
        )

    def test_a_module_needs_use(self) -> None:
        self.assertIn("modules.m.use is required", refusal(CORE + "[modules.m]\nprefix = '/x'\n"))

    def test_module_names_are_lowercase_dashes(self) -> None:
        self.assertIn("a module name is lowercase", refusal(CORE + '[modules.Bad_Name]\nuse = "builtin:file"\n'))

    def test_a_module_script_path_and_builtins_are_accepted(self) -> None:
        spec = small(extra='[modules.a]\nuse = "hooks/sdk.sh"\n[modules.b]\nuse = "builtin:deb"\n')
        self.assertEqual(spec.modules["a"].use, "hooks/sdk.sh")

    def test_dates_are_refused(self) -> None:
        message = refusal(CORE + "[modules.m]\nuse = 'builtin:file'\nwhen = 2025-08-09\n")
        self.assertIn("modules.m.when: dates and times are not allowed in a definition", message)

    def test_times_are_refused_too(self) -> None:
        self.assertIn("dates and times are not allowed", refusal(CORE + "[params]\nat = 2025-08-09T10:00:00Z\n"))

    def test_hook_and_files_paths_stay_inside_the_definition(self) -> None:
        message = refusal(CORE + 'files = "/abs"\nhooks = ["../x.sh"]\n')
        self.assertIn("images.core.files: a path relative to the definition, inside it", message)
        self.assertIn("images.core.hooks: '../x.sh' is not a path relative", message)

    def test_package_names_never_carry_versions(self) -> None:
        self.assertIn("'tool=1.0' is not a Debian package name", refusal(CORE + 'packages = ["tool=1.0"]\n'))

    def test_a_package_name_may_not_end_in_a_dash(self) -> None:
        # apt reads `name-` as "remove name"
        self.assertIn("'tool-' is not a Debian package name", refusal(CORE + 'packages = ["tool-"]\n'))
        for name in ("g++", "libc6", "a2", "tool-b", "python3.13"):
            with self.subTest(name=name):
                parse_definition(CORE + f'packages = ["{name}"]\n')

    def test_a_package_listed_twice(self) -> None:
        self.assertIn("images.core.packages lists a name twice", refusal(CORE + 'packages = ["tzdata", "tzdata"]\n'))

    def test_packages_must_be_a_list_of_strings(self) -> None:
        self.assertIn("images.core.packages must be a list of strings", refusal(CORE + "packages = [1]\n"))

    def test_compression(self) -> None:
        self.assertIn("images.core.compression must be one of", refusal(CORE + 'compression = "bz2"\n'))
        self.assertEqual(parse_definition(CORE + 'compression = "zstd"\n').images["core"].compression, "zstd")

    def test_image_names(self) -> None:
        self.assertIn(
            "an image name is lowercase letters, digits and dashes", refusal(CORE + '[images.Bad]\nkind = "oci"\n')
        )

    def test_debian_section(self) -> None:
        self.assertIn("debian.suite is required", refusal(CORE, "schema = 1\n"))
        self.assertIn("has no known release date", refusal(CORE, 'schema = 1\n[debian]\nsuite = "forky"\n'))
        self.assertIn("is not one of", refusal(CORE, HEADER + 'components = ["games"]\n'))
        self.assertIn("this release builds ['amd64'] only", refusal(CORE, HEADER + 'architectures = ["arm64"]\n'))
        self.assertIn("non-negative integer", refusal(CORE, HEADER + 'source_date_epoch = "now"\n'))
        self.assertEqual(
            parse_definition(
                CORE, 'schema = 1\n[debian]\nsuite = "forky"\nsource_date_epoch = 5\n'
            ).debian.source_date_epoch,
            5,
        )

    def test_every_problem_is_named_one_per_line(self) -> None:
        message = refusal(CORE + "colour = 1\n" + '[images.x]\nkind = "vm"\n')
        self.assertGreaterEqual(len(message.splitlines()), 2)

    def test_checks_name_images_or_default(self) -> None:
        self.assertIn("checks.nothing: not an image", refusal(CORE + '[checks]\nnothing = ["builtin"]\n'))


class ParamTest(unittest.TestCase):
    PARAMS = '[params]\nflag = true\ncount = 3\nname = "x"\n'

    def spec(self) -> definition.Definition:
        return parse_definition(self.PARAMS + CORE)

    def test_defaults(self) -> None:
        self.assertEqual(definition.resolve_params(self.spec(), {}), {"count": 3, "flag": True, "name": "x"})

    def test_overrides_are_typed_like_the_declared_default(self) -> None:
        got = definition.resolve_params(self.spec(), {"flag": "false", "count": "7", "name": "y"})
        self.assertEqual(got, {"count": 7, "flag": False, "name": "y"})
        self.assertIs(got["flag"], False)
        self.assertIsInstance(got["count"], int)

    def test_a_boolean_is_true_or_false_only(self) -> None:
        with self.assertRaisesRegex(ValueError, "parameter flag is a boolean: true or false, not 'yes'"):
            definition.resolve_params(self.spec(), {"flag": "yes"})

    def test_an_integer_is_digits_with_an_optional_minus(self) -> None:
        for raw, want in (("-4", -4), ("007", 7)):
            with self.subTest(raw=raw):
                self.assertEqual(definition.resolve_params(self.spec(), {"count": raw})["count"], want)
        for raw in ("+4", " 4", "4 ", "1_0", "", "-", "4.0", "\u0664"):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "is an integer"):
                definition.resolve_params(self.spec(), {"count": raw})

    def test_an_integer_must_be_one(self) -> None:
        with self.assertRaisesRegex(ValueError, "parameter count is an integer, not 'many'"):
            definition.resolve_params(self.spec(), {"count": "many"})

    def test_unknown_names_are_refused_with_the_declared_ones(self) -> None:
        with self.assertRaisesRegex(
            ValueError, r"unknown parameters \['other'\]: \[params\] declares \['count', 'flag', 'name'\]"
        ):
            definition.resolve_params(self.spec(), {"other": "1"})

    def test_declared_types(self) -> None:
        for declared, bad in (("flag = 1.5", "float"), ("flag = [1]", "list")):
            with self.subTest(bad=bad):
                self.assertIn(
                    "params.flag must be a string, an integer or a boolean", refusal(f"[params]\n{declared}\n" + CORE)
                )

    def test_parameter_names(self) -> None:
        self.assertIn(
            "a parameter name is lowercase letters, digits and _", refusal('[params]\n"Bad-Name" = true\n' + CORE)
        )

    def test_parse_param_value_directly(self) -> None:
        default: Param = True
        self.assertIs(definition.parse_param_value("a", "true", default), True)
        self.assertEqual(definition.parse_param_value("a", "5", 1), 5)
        self.assertEqual(definition.parse_param_value("a", "5", "s"), "5")


class TreeTest(unittest.TestCase):
    def test_top_down_puts_each_image_after_its_parent_and_siblings_by_name(self) -> None:
        self.assertEqual(
            definition.top_down(example_definition()),
            ["core", "incus-base", "installer", "oci-base", "os", "node-26"],
        )

    def test_top_down_is_stable_whatever_the_file_order(self) -> None:
        spec = parse_definition(child("z", "oci", "core") + child("a", "oci", "z") + child("m", "oci", "core") + CORE)
        self.assertEqual(definition.top_down(spec), ["core", "m", "z", "a"])

    def test_ancestry_and_children(self) -> None:
        spec = example_definition()
        self.assertEqual(definition.ancestry(spec, "node-26"), ["core", "oci-base", "node-26"])
        self.assertEqual(definition.ancestry(spec, "core"), ["core"])
        self.assertEqual(definition.children(spec, "core"), ["incus-base", "installer", "oci-base", "os"])
        self.assertEqual(definition.children(spec, "node-26"), [])


class RequiredChecksTest(unittest.TestCase):
    def test_builtin_expands_to_the_kinds_set(self) -> None:
        spec = example_definition()
        self.assertEqual(definition.required_checks(spec, "core", False), tuple(sorted(BUILTIN_CHECKS["core"])))
        self.assertEqual(definition.required_checks(spec, "oci-base", False), tuple(sorted(BUILTIN_CHECKS["oci"])))
        self.assertEqual(
            definition.required_checks(spec, "installer", False), tuple(sorted(BUILTIN_CHECKS["installer"]))
        )

    def test_locked_inputs_joins_builtin_only_for_images_with_entries(self) -> None:
        spec = example_definition()
        self.assertNotIn("locked-inputs", definition.required_checks(spec, "node-26", False))
        with_entries = definition.required_checks(spec, "node-26", True)
        self.assertIn("locked-inputs", with_entries)
        self.assertEqual(with_entries, tuple(sorted({*BUILTIN_CHECKS["oci"], "locked-inputs"})))

    def test_locked_inputs_is_not_added_without_builtin(self) -> None:
        spec = parse_definition(CORE + '[checks]\ndefault = ["mine"]\n')
        self.assertEqual(definition.required_checks(spec, "core", True), ("mine",))

    def test_an_image_override_replaces_the_default_list(self) -> None:
        spec = example_definition()
        checks = definition.required_checks(spec, "os", False)
        self.assertIn("install-on-test-vm", checks)
        self.assertIn("os-boot", checks)
        self.assertNotIn("install-on-test-vm", definition.required_checks(spec, "installer", False))

    def test_an_override_without_builtin_drops_the_kinds_set(self) -> None:
        spec = parse_definition(CORE + child("a", "oci", "core") + '[checks]\na = ["only-this"]\n')
        self.assertEqual(definition.required_checks(spec, "a", True), ("only-this",))
        self.assertIn("package-set", definition.required_checks(spec, "core", False))

    def test_the_result_is_sorted_and_without_repeats(self) -> None:
        spec = parse_definition(CORE + '[checks]\ndefault = ["zeta", "builtin", "package-set", "alpha"]\n')
        got = definition.required_checks(spec, "core", False)
        self.assertEqual(got, tuple(sorted(set(got))))
        self.assertIn("alpha", got)


if __name__ == "__main__":
    unittest.main()
