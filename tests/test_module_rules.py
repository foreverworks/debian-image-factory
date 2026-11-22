"""`builtin:deb` and `builtin:file` without a network: their tables, their lock rules, the build lines they add and
the probes `locked-inputs` runs (DESIGN 6.4, 11)."""

import subprocess
import unittest
from collections.abc import Mapping

from input_lock import JsonValue

from debian_image_factory import definition, filemodule, lockrules, modules, planfile
from debian_image_factory.build import core, run
from debian_image_factory.build import oci as oci_build
from debian_image_factory.checks import inputs
from debian_image_factory.definition import DefinitionError, Module
from debian_image_factory.modules import Probe
from tests.support.definitions import HEADER, child

DEB_URL = "https://packages.example.com/debian/pool/main/e/example-tool/example-tool_{version}_amd64.deb"
REGISTRY = "https://packages.example.com/debian?suite=trixie&components=main&binaryArch=amd64"
SHA = "1" * 64
KEYS: dict[str, JsonValue] = {
    "module": "vendor",
    "sha256": "2" * 64,
    "url": "https://packages.example.com/debian/keys.pgp",
    "used_by": ["app"],
    "version": "1",
}
TOOL: dict[str, JsonValue] = {
    "apt": "example-tool",
    "datasource": "deb",
    "depName": "example-tool",
    "module": "vendor",
    "registryUrl": REGISTRY,
    "sha256": SHA,
    "signed_by": "vendor-keys",
    "url": DEB_URL,
    "used_by": ["app"],
    "version": "2.4.0-1",
}
BLOB: dict[str, JsonValue] = {
    "module": "blob",
    "sha256": SHA,
    "url": "https://downloads.example.com/tool-{version}.tar.gz",
    "used_by": ["app"],
    "version": "3.1",
}


def spec_text(modules_: str) -> str:
    return (
        HEADER
        + modules_
        + '[images.core]\nkind = "core"\n'
        + child("app", "oci", "core")
        + child("other", "oci", "core")
    )


def parse(modules_: str) -> definition.Definition:
    return definition.parse(spec_text(modules_))


def refusal(modules_: str) -> str:
    """The definition's refusal, every problem one per line."""
    try:
        parse(modules_)
    except DefinitionError as error:
        return str(error)
    raise AssertionError("the definition was accepted")


DEB = '[params]\nvendor = true\n[modules.vendor]\nuse = "builtin:deb"\nenabled_by = "vendor"\n'


def lock(**entries: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    inputs: dict[str, JsonValue] = {name: dict(entry) for name, entry in entries.items()}
    return {"schema": 2, "debian_snapshot": "20261101T000000Z", "inputs": inputs}


def lock_problems(modules_: str, data: dict[str, JsonValue]) -> list[str]:
    return lockrules.problems(data, parse(modules_))


class TableTest(unittest.TestCase):
    def test_a_deb_module_takes_only_its_switch(self) -> None:
        self.assertEqual(parse(DEB).modules["vendor"].enabled_by, "vendor")
        message = refusal('[modules.vendor]\nuse = "builtin:deb"\nprefix = "/opt"\nsuite = "x"\n')
        self.assertIn("modules.vendor: unknown key 'prefix': this module takes only enabled_by", message)
        self.assertIn("modules.vendor: unknown key 'suite'", message)

    def test_a_file_module_needs_an_absolute_normalised_path(self) -> None:
        self.assertIn("modules.f: path is required", refusal('[modules.f]\nuse = "builtin:file"\n'))
        for path in ("opt/tool", "/opt/../etc", "/opt//tool", "/", "/opt/tool/", "/opt/to ol", "/opt/$x"):
            with self.subTest(path=path):
                self.assertIn("modules.f: path ", refusal(f'[modules.f]\nuse = "builtin:file"\npath = "{path}"\n'))

    def test_a_file_module_s_keys_are_checked(self) -> None:
        cases = {
            'mode = "644"': "mode must be an octal string",
            'mode = "4755"': "mode must be an octal string",
            "mode = 420": "mode must be an octal string",
            'unpack = true\nmode = "0755"': "mode is for a file placed as it is",
            "strip_components = 1": "strip_components needs unpack = true",
            "unpack = true\nstrip_components = -1": "strip_components must be a whole number",
            "unpack = true\nstrip_components = true": "strip_components must be a whole number",
            'unpack = "yes"': "unpack must be true or false",
            "links = false": "unknown key 'links'",
        }
        for extra, expected in cases.items():
            with self.subTest(extra=extra):
                text = f'[modules.f]\nuse = "builtin:file"\npath = "/opt/tool"\n{extra}\n'
                self.assertIn(expected, refusal(text))

    def test_a_file_module_s_defaults(self) -> None:
        table = parse('[modules.f]\nuse = "builtin:file"\npath = "/usr/local/bin/tool"\n').modules["f"].table
        self.assertEqual(
            (filemodule.mode_of(table), filemodule.unpacks(table), filemodule.strip_of(table)), ("0644", False, 0)
        )
        spec = parse('[modules.f]\nuse = "builtin:file"\npath = "/opt/t"\nunpack = true\nstrip_components = 2\n')
        self.assertEqual(filemodule.strip_of(spec.modules["f"].table), 2)


class DebLockTest(unittest.TestCase):
    def test_a_signed_apt_entry_and_its_keyring_pass(self) -> None:
        self.assertEqual(lock_problems(DEB, lock(**{"example-tool": TOOL, "vendor-keys": KEYS})), [])

    def test_an_apt_entry_without_signed_by_is_named(self) -> None:
        unsigned = {key: value for key, value in TOOL.items() if key != "signed_by"}
        found = lock_problems(DEB, lock(**{"example-tool": unsigned, "vendor-keys": KEYS}))
        self.assertIn(
            "inputs.example-tool: an entry of a builtin:deb module needs signed_by "
            "(the keyring entry that repository signs with)",
            found,
        )

    def test_a_plain_download_in_the_module_is_named_with_every_field(self) -> None:
        plain = {key: TOOL[key] for key in ("module", "sha256", "url", "used_by", "version")}
        found = lock_problems(DEB, lock(**{"example-tool": plain}))
        for field in ("apt", "registryUrl", "signed_by"):
            with self.subTest(field=field):
                self.assertIn(
                    f"inputs.example-tool: an entry of a builtin:deb module needs {field} (", "\n".join(found)
                )

    def test_a_keyring_of_the_module_needs_none_of_them(self) -> None:
        found = lock_problems(DEB, lock(**{"example-tool": TOOL, "vendor-keys": KEYS}))
        self.assertFalse([line for line in found if "vendor-keys" in line])


FILE = '[modules.blob]\nuse = "builtin:file"\npath = "/opt/tool"\nunpack = true\n'


class FileLockTest(unittest.TestCase):
    def test_one_entry_per_image_passes(self) -> None:
        self.assertEqual(lock_problems(FILE, lock(blob=BLOB, other={**BLOB, "used_by": ["other"]})), [])

    def test_several_entries_for_one_image_fail_naming_it(self) -> None:
        found = lock_problems(FILE, lock(blob=BLOB, again={**BLOB, "url": "https://downloads.example.com/b.tar"}))
        self.assertEqual(
            found,
            [
                "images.app: module blob (builtin:file): places exactly one lock entry per image, "
                "found ['again', 'blob']"
            ],
        )

    def test_an_image_with_only_a_keyring_fails_naming_it(self) -> None:
        signed = {**BLOB, "signed_by": "keys", "sums_url": "https://downloads.example.com/SHA256SUMS.asc"}
        keys: dict[str, JsonValue] = {**KEYS, "module": "blob", "used_by": ["app", "other"]}
        found = lock_problems(FILE, lock(blob=signed, keys=keys))
        self.assertEqual(
            found, ["images.other: module blob (builtin:file): places exactly one lock entry per image, found []"]
        )

    def test_an_unpacked_entry_must_be_a_tarball(self) -> None:
        found = lock_problems(FILE, lock(blob={**BLOB, "url": "https://downloads.example.com/tool.zip"}))
        self.assertEqual(len(found), 1)
        self.assertIn("entry blob is unpacked, so its url must end in one of ['.tar', '.tar.gz', '.tar.xz']", found[0])

    def test_a_placed_file_may_be_anything(self) -> None:
        placed = '[modules.blob]\nuse = "builtin:file"\npath = "/usr/local/bin/tool"\nmode = "0755"\n'
        self.assertEqual(lock_problems(placed, lock(blob={**BLOB, "url": "https://downloads.example.com/tool"})), [])


def file_module(**table: JsonValue) -> Module:
    return Module("blob", "builtin:file", None, {"use": "builtin:file", "path": "/opt/tool", **table})


FIELDS = {"blob": {"module": "blob", "sha256": SHA, "url": "https://downloads.example.com/tool-3.1.tar.gz"}}


class InstallLinesTest(unittest.TestCase):
    def test_a_placed_file_is_copied_with_its_mode(self) -> None:
        lines = modules.install_lines(
            file_module(mode="0755"), FIELDS, inputs="/factory/run/inputs", source_date_epoch=9
        )
        self.assertEqual(
            lines[1],
            f'python3 -I {core.WORK}/file_install.py "$root" '
            "/factory/run/inputs/blob/tool-3.1.tar.gz /opt/tool 9 --mode 0755",
        )

    def test_an_unpacked_tarball_strips_its_components(self) -> None:
        lines = modules.install_lines(
            file_module(unpack=True, strip_components=1), FIELDS, inputs="/i", source_date_epoch=9
        )
        self.assertTrue(lines[1].endswith("/i/blob/tool-3.1.tar.gz /opt/tool 9 --unpack 1"), lines[1])
        self.assertIn("unpacked into /opt/tool", lines[0])

    def test_the_helper_is_the_file_install_script(self) -> None:
        helpers = modules.helper_files(file_module())
        self.assertEqual(sorted(helpers), ["file_install.py"])
        self.assertNotIn("debian_image_factory", helpers["file_install.py"])

    def test_a_deb_module_adds_no_lines_of_its_own(self) -> None:
        lines = modules.install_lines(Module("vendor", "builtin:deb", None, {}), {}, inputs="/i", source_date_epoch=9)
        self.assertEqual([line for line in lines if not line.startswith("#")], [])

    def test_two_entries_are_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one lock entry"):
            modules.install_lines(file_module(), {**FIELDS, "b": FIELDS["blob"]}, inputs="/i", source_date_epoch=9)


DEB_PATH = "/factory/run/inputs/example-tool/example-tool_2.4.0-1_amd64.deb"


class AptLinesTest(unittest.TestCase):
    def test_debs_join_the_packages_in_one_transaction(self) -> None:
        lines = oci_build.install_lines(["zz", "aa"], [DEB_PATH])
        installs = [line for line in lines if "apt-get --yes" in line]
        self.assertEqual(
            installs,
            [
                'chroot "$root" apt-get --yes --no-install-recommends install aa zz '
                "/run/factory/debs/example-tool_2.4.0-1_amd64.deb"
            ],
        )
        self.assertIn(f'install -m 0644 {DEB_PATH} "$root"/run/factory/debs/example-tool_2.4.0-1_amd64.deb', lines)
        self.assertLess(lines.index('mkdir -p "$root/run/factory/debs"'), lines.index(installs[0]))
        self.assertEqual(lines[-1], 'rm -rf "$root/run/factory/debs"')

    def test_a_deb_name_reaches_the_shell_quoted(self) -> None:
        lines = oci_build.install_lines(["aa"], ["/factory/run/inputs/x/a$(id).deb"])
        quoted = "install -m 0644 '/factory/run/inputs/x/a$(id).deb' \"$root\"'/run/factory/debs/a$(id).deb'"
        self.assertIn(quoted, lines)

    def test_without_debs_the_lines_are_as_before(self) -> None:
        self.assertEqual(
            oci_build.install_lines(["b", "a"]),
            [
                "# the image's packages, from the mirror, with the image's own apt",
                'chroot "$root" apt-get update',
                'chroot "$root" apt-get --yes --no-install-recommends install a b',
            ],
        )

    def test_debs_alone_set_apt_up(self) -> None:
        text = oci_build.build_script(
            layers=1,
            request=[],
            source_date_epoch=9,
            owner=None,
            files=False,
            module_lines=[],
            hooks=[],
            debs=[DEB_PATH],
        )
        self.assertIn(f'mount --bind {core.MIRROR} "$root{oci_build.CHILD_MIRROR}"', text)
        self.assertIn("install /run/factory/debs/example-tool_2.4.0-1_amd64.deb", text)
        self.assertIn("apt-get clean", text)
        self.assertEqual(subprocess.run(["sh", "-n"], input=text, text=True, check=False).returncode, 0)
        bare = oci_build.build_script(
            layers=1, request=[], source_date_epoch=9, owner=None, files=False, module_lines=[], hooks=[]
        )
        self.assertNotIn("apt-get", bare)


def plan_entry(**fields: object) -> planfile.ImageEntry:
    value: dict[str, object] = {
        "kind": "oci",
        "parent": "core",
        "identity": "i",
        "parent_identity": "p",
        "recipe": "r",
        "apt_sources": "live",
        "request": [],
        "packages": [],
        "inputs": {},
        "modules": [],
        "trust": {},
        "debs": {},
        "params": {},
        "checks": [],
        "state": "build",
        **fields,
    }
    return planfile.parse_image("app", value)


class RunTest(unittest.TestCase):
    def test_the_deb_paths_are_the_staged_inputs(self) -> None:
        entry = plan_entry(
            inputs={
                "example-tool": {
                    "apt": "example-tool",
                    "module": "vendor",
                    "url": DEB_URL.replace("{version}", "2.4.0-1"),
                },
                "vendor-keys": {"module": "vendor", "url": "https://packages.example.com/debian/keys.pgp"},
            },
            trust={"example-tool": {"signed_by": "vendor-keys"}},
            debs={"example-tool": {"package": "example-tool", "version": "2.4.0-1", "registry_url": REGISTRY}},
        )
        self.assertEqual(run.deb_paths(entry), [DEB_PATH])

    def test_a_deb_outside_the_inputs_is_not_a_plan(self) -> None:
        with self.assertRaisesRegex(ValueError, r"images\.app\.debs\.ghost must be one of the image's inputs"):
            plan_entry(debs={"ghost": {"package": "g", "version": "1", "registry_url": REGISTRY}})
        with self.assertRaisesRegex(ValueError, "registry_url must be an https:// URL"):
            plan_entry(
                inputs={"t": {"apt": "t"}},
                trust={"t": {"signed_by": "k"}},
                debs={"t": {"package": "t", "version": "1", "registry_url": "http://x.example/"}},
            )

    def test_module_lines_leave_the_keyrings_out(self) -> None:
        spec = parse(FILE.replace("unpack = true\n", ""))
        entry = plan_entry(
            inputs={"blob": FIELDS["blob"], "keys": {"module": "blob", "url": "https://downloads.example.com/k"}},
            trust={"blob": {"signed_by": "keys", "sums_url": "https://downloads.example.com/SUMS.asc"}},
            modules=["blob"],
        )
        lines = run.module_lines(spec, entry, 9)
        self.assertEqual(len([line for line in lines if line.startswith("python3")]), 1)


class ProbeTest(unittest.TestCase):
    def test_a_placed_file_is_probed_by_its_sha256(self) -> None:
        self.assertEqual(
            modules.probes(file_module(), FIELDS),
            [Probe("blob", ("sha256sum", "/opt/tool"), f"{SHA}  /opt/tool")],
        )

    def test_an_unpacked_tarball_is_probed_as_a_directory(self) -> None:
        self.assertEqual(
            modules.probes(file_module(unpack=True), FIELDS), [Probe("blob", ("test", "-d", "/opt/tool"), "")]
        )

    def test_a_deb_module_has_no_probe(self) -> None:
        self.assertEqual(modules.probes(Module("vendor", "builtin:deb", None, {}), {}), [])

    def test_locked_inputs_runs_the_file_probe(self) -> None:
        seen: list[Probe] = []

        def runner(output: str) -> inputs.Runner:
            def run_(probe: Probe) -> tuple[int, str]:
                seen.append(probe)
                return 0, output

            return run_

        mods = {"blob": file_module()}
        good = inputs.locked_inputs(FIELDS, mods, None, runner(f"{SHA}  /opt/tool\n"))
        self.assertEqual((good.passed, good.failed), (("blob",), ()))
        bad = inputs.locked_inputs(FIELDS, mods, None, runner(f"{'9' * 64}  /opt/tool\n"))
        self.assertEqual(len(bad.failed), 1)
        self.assertIn("`sha256sum /opt/tool` printed", bad.failed[0])

    def test_a_deb_entry_is_read_from_the_dpkg_status(self) -> None:
        fields = {"example-tool": {"apt": "example-tool", "version": "2.4.0-1", "module": "vendor"}}
        mods = {"vendor": Module("vendor", "builtin:deb", None, {})}
        status = b"Package: example-tool\nStatus: install ok installed\nVersion: 2.4.0-1\nArchitecture: amd64\n"
        found = inputs.locked_inputs(fields, mods, status, lambda probe: (1, ""), trust_roots=("vendor-keys",))
        self.assertEqual((found.passed, found.failed), (("example-tool",), ()))
        missing = inputs.locked_inputs(fields, mods, b"", lambda probe: (1, ""))
        self.assertEqual(missing.failed, ("example-tool: example-tool 2.4.0-1 is not installed",))
