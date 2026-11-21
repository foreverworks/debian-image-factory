"""The build definition, `factory.toml` (DESIGN 6.2 to 6.4): parsed, checked, and nothing else.

Everything here is pure: `parse` takes the file's text and returns a `Definition` or raises
`DefinitionError` naming every problem, one per line. Whether the files a definition names exist
is the edge's question (`files.py`).
"""

import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from input_lock import JsonValue

SCHEMA: Final = 1

KINDS: Final = ("core", "oci", "incus", "installer", "os")

CHILD_KINDS: Final[Mapping[str, frozenset[str]]] = {
    "core": frozenset(("oci", "incus", "installer", "os")),
    "oci": frozenset(("oci",)),
    "incus": frozenset(("incus",)),
    "installer": frozenset(("installer",)),
    "os": frozenset(("os",)),
}
"""Which kinds may derive from an image of each kind. An `oci` child of an `incus` image is refused."""

KIND_DEFAULTS: Final[Mapping[str, tuple[str, ...]]] = {
    "core": (),
    "oci": (),
    "incus": ("cloud-init", "dbus", "iproute2", "netbase", "systemd-resolved", "systemd-sysv", "udev"),
    "installer": ("iproute2", "netbase", "systemd-sysv", "udev"),
    "os": ("dbus", "iproute2", "netbase", "systemd-sysv", "udev"),
}
"""The packages each kind installs on top of the definition's own (DESIGN 5.3). The plan lists them.

They are resolved like any other package, so their versions enter every identity through the
package set; changing this table changes identities through the packages it adds."""

APT_SOURCES: Final = ("live", "baseline", "baseline-except-security")
COMPRESSION: Final = ("gzip", "zstd")
BUILTIN_MODULES: Final = ("builtin:deb", "builtin:node-tarball", "builtin:file")
COMPONENTS: Final = ("main", "contrib", "non-free", "non-free-firmware")
ARCHITECTURES: Final = ("amd64",)
"""Architectures this release builds. Others are designed for (the architecture is in every identity)."""

RELEASE_DATES: Final[Mapping[str, int]] = {"trixie": 1754697600}
"""source_date_epoch defaults: the suite's release date (2025-08-09 for Debian 13)."""

OCI_KEYS: Final[Mapping[str, str]] = {
    "user": "string",
    "cmd": "list",
    "entrypoint": "list",
    "env": "table",
    "workdir": "string",
    "labels": "table",
}

NAME: Final = re.compile(r"[a-z0-9][a-z0-9-]*")
PARAM: Final = re.compile(r"[a-z][a-z0-9_]*")
PACKAGE: Final = re.compile(r"[a-z0-9][a-z0-9+.-]+")
KERNEL: Final = re.compile(r"linux-image-.*")
IMAGE_KEYS: Final = frozenset(("kind", "parent", "packages", "files", "hooks", "apt_sources", "compression"))
TOP_LEVEL: Final = frozenset(("schema", "debian", "params", "modules", "images", "checks"))

type Param = str | int | bool


class DefinitionError(ValueError):
    """The definition is not one the factory can build: its message names every problem, one per line."""


@dataclass(frozen=True, slots=True)
class Debian:
    suite: str
    components: tuple[str, ...]
    architectures: tuple[str, ...]
    source_date_epoch: int


@dataclass(frozen=True, slots=True)
class Module:
    name: str
    use: str
    enabled_by: str | None
    table: Mapping[str, JsonValue]
    """The whole [modules.<name>] table, parsed: it enters the recipe digest of every image that uses it."""


@dataclass(frozen=True, slots=True)
class Image:
    name: str
    kind: str
    parent: str | None
    packages: tuple[str, ...]
    files: str | None
    hooks: tuple[str, ...]
    apt_sources: str
    compression: str
    kind_table: Mapping[str, JsonValue]
    section: Mapping[str, JsonValue]
    """The whole [images.<name>] section, parsed: it enters the image's recipe digest."""


@dataclass(frozen=True, slots=True)
class Definition:
    schema: int
    debian: Debian
    params: Mapping[str, Param]
    modules: Mapping[str, Module]
    images: Mapping[str, Image]
    checks: Mapping[str, tuple[str, ...]]


# ---- reading TOML into checked values ---------------------------------------------------------


def json_value(value: object, where: str, found: list[str]) -> JsonValue:
    """A TOML value as plain JSON data. Dates and times are refused: nothing in a definition needs one."""
    if value is None or isinstance(value, str | bool | int | float):
        return value
    if isinstance(value, list):
        return [json_value(item, f"{where}[{index}]", found) for index, item in enumerate(value)]
    if isinstance(value, dict):
        return {str(key): json_value(item, f"{where}.{key}", found) for key, item in value.items()}
    found.append(f"{where}: dates and times are not allowed in a definition")
    return None


def table(data: Mapping[str, JsonValue], key: str, where: str, found: list[str]) -> dict[str, JsonValue]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        found.append(f"{where}{key} must be a table")
        return {}
    return value


def text(
    data: Mapping[str, JsonValue], key: str, where: str, found: list[str], default: str | None = None
) -> str | None:
    value = data.get(key, default)
    if value is not None and not isinstance(value, str):
        found.append(f"{where}.{key} must be a string")
        return default
    return value


def strings(data: Mapping[str, JsonValue], key: str, where: str, found: list[str]) -> tuple[str, ...]:
    value = data.get(key, [])
    if not (isinstance(value, list) and all(isinstance(item, str) for item in value)):
        found.append(f"{where}.{key} must be a list of strings")
        return ()
    items = tuple(item for item in value if isinstance(item, str))
    if len(set(items)) != len(items):
        found.append(f"{where}.{key} lists a name twice")
    return items


# ---- sections ---------------------------------------------------------------------------------


def parse_debian(data: Mapping[str, JsonValue], found: list[str]) -> Debian:
    section = table(data, "debian", "", found)
    unknown = sorted(set(section) - {"suite", "components", "architectures", "source_date_epoch"})
    if unknown:
        found.append(f"debian: unknown keys {unknown}")
    suite = text(section, "suite", "debian", found) or ""
    if not suite:
        found.append('debian.suite is required (for example "trixie")')
    components = strings(section, "components", "debian", found) if "components" in section else ("main",)
    for component in components:
        if component not in COMPONENTS:
            found.append(f"debian.components: {component!r} is not one of {list(COMPONENTS)}")
    if not components:
        found.append("debian.components must name at least one component")
    architectures = strings(section, "architectures", "debian", found) if "architectures" in section else ("amd64",)
    for arch in architectures:
        if arch not in ARCHITECTURES:
            found.append(f"debian.architectures: this release builds {list(ARCHITECTURES)} only, not {arch!r}")
    if not architectures:
        found.append("debian.architectures must name at least one architecture")
    epoch = section.get("source_date_epoch", RELEASE_DATES.get(suite))
    if not (isinstance(epoch, int) and not isinstance(epoch, bool) and epoch >= 0):
        if epoch is None:
            found.append(f"debian.source_date_epoch is required for suite {suite!r} (it has no known release date)")
        else:
            found.append("debian.source_date_epoch must be a non-negative integer")
        epoch = 0
    return Debian(suite, components, architectures, epoch)


def parse_params(data: Mapping[str, JsonValue], found: list[str]) -> dict[str, Param]:
    params: dict[str, Param] = {}
    for name, value in table(data, "params", "", found).items():
        if not PARAM.fullmatch(name):
            found.append(f"params.{name}: a parameter name is lowercase letters, digits and _")
        elif isinstance(value, str | bool | int) and not isinstance(value, float):
            params[name] = value
        else:
            found.append(f"params.{name} must be a string, an integer or a boolean")
    return params


def parse_modules(data: Mapping[str, JsonValue], params: Mapping[str, Param], found: list[str]) -> dict[str, Module]:
    modules: dict[str, Module] = {}
    for name, raw in table(data, "modules", "", found).items():
        where = f"modules.{name}"
        if not NAME.fullmatch(name):
            found.append(f"{where}: a module name is lowercase letters, digits and dashes")
            continue
        if not isinstance(raw, dict):
            found.append(f"{where} must be a table")
            continue
        use = text(raw, "use", where, found) or ""
        if not use:
            found.append(f"{where}.use is required: one of {list(BUILTIN_MODULES)} or a script path")
        elif use.startswith("builtin:") and use not in BUILTIN_MODULES:
            found.append(f"{where}.use: {use!r} is not one of {list(BUILTIN_MODULES)}")
        elif not use.startswith("builtin:") and not relative_path(use):
            found.append(f"{where}.use: a script path is relative to the definition and stays inside it")
        enabled_by = text(raw, "enabled_by", where, found)
        if enabled_by is not None:
            if enabled_by not in params:
                found.append(f"{where}.enabled_by names {enabled_by!r}, which [params] does not declare")
            elif not isinstance(params[enabled_by], bool):
                found.append(f"{where}.enabled_by names {enabled_by!r}, which is not a boolean parameter")
        modules[name] = Module(name, use, enabled_by, raw)
    return modules


def relative_path(path: str) -> bool:
    """A path inside the definition's directory: relative, no `..`, no empty part."""
    parts = path.split("/")
    return bool(path) and not path.startswith("/") and all(part not in ("", ".", "..") for part in parts)


def parse_image(name: str, raw: Mapping[str, JsonValue], found: list[str]) -> Image | None:
    where = f"images.{name}"
    kind = text(raw, "kind", where, found) or ""
    if kind not in KINDS:
        found.append(f"{where}.kind must be one of {list(KINDS)}")
        return None
    unknown = sorted(set(raw) - IMAGE_KEYS - {kind})
    if unknown:
        found.append(f"{where}: unknown keys {unknown}")
    parent = text(raw, "parent", where, found)
    if kind == "core" and parent is not None:
        found.append(f"{where}: a core image has no parent")
    if kind != "core" and parent is None:
        found.append(f"{where}.parent is required for a {kind} image")
    packages = strings(raw, "packages", where, found)
    for package in packages:
        if not PACKAGE.fullmatch(package):
            found.append(f"{where}.packages: {package!r} is not a Debian package name (versions never go here)")
        elif kind == "core" and KERNEL.fullmatch(package):
            found.append(f"{where}.packages: core never installs a kernel ({package})")
    files = text(raw, "files", where, found)
    if files is not None and not relative_path(files):
        found.append(f"{where}.files: a path relative to the definition, inside it")
    hooks = strings(raw, "hooks", where, found)
    for hook in hooks:
        if not relative_path(hook):
            found.append(f"{where}.hooks: {hook!r} is not a path relative to the definition, inside it")
    apt_sources = text(raw, "apt_sources", where, found, "live") or "live"
    if apt_sources not in APT_SOURCES:
        found.append(f"{where}.apt_sources must be one of {list(APT_SOURCES)}")
    if kind in ("core", "oci") and apt_sources != "live":
        found.append(
            f"{where}.apt_sources: a {kind} image keeps live sources (snapshot sources are for kinds that boot)"
        )
    compression = text(raw, "compression", where, found, "gzip") or "gzip"
    if compression not in COMPRESSION:
        found.append(f"{where}.compression must be one of {list(COMPRESSION)}")
    kind_table = raw.get(kind, {})
    if not isinstance(kind_table, dict):
        found.append(f"{where}.{kind} must be a table")
        kind_table = {}
    if kind == "oci":
        found.extend(oci_problems(f"{where}.oci", kind_table))
    return Image(name, kind, parent, packages, files, hooks, apt_sources, compression, kind_table, raw)


def oci_problems(where: str, config: Mapping[str, JsonValue]) -> list[str]:
    found = []
    for key, value in config.items():
        shape = OCI_KEYS.get(key)
        if shape is None:
            found.append(f"{where}: unknown key {key!r} (known: {sorted(OCI_KEYS)})")
        elif shape == "string" and not isinstance(value, str):
            found.append(f"{where}.{key} must be a string")
        elif shape == "list" and not (isinstance(value, list) and all(isinstance(item, str) for item in value)):
            found.append(f"{where}.{key} must be a list of strings")
        elif shape == "table" and not (isinstance(value, dict) and all(isinstance(v, str) for v in value.values())):
            found.append(f"{where}.{key} must be a table of strings")
    return found


def tree_problems(images: Mapping[str, Image]) -> list[str]:
    """Exactly one core, every parent exists, kinds derive as CHILD_KINDS allows, no cycle."""
    found: list[str] = []
    cores = sorted(name for name, image in images.items() if image.kind == "core")
    if len(cores) != 1:
        found.append(f"a definition has exactly one core image, not {len(cores)} ({cores})")
    for name, image in sorted(images.items()):
        if image.parent is None:
            continue
        parent = images.get(image.parent)
        if parent is None:
            found.append(f"images.{name}.parent names {image.parent!r}, which is not an image")
        elif image.kind not in CHILD_KINDS[parent.kind]:
            found.append(f"images.{name}: a {image.kind} image cannot derive from {parent.kind} image {parent.name!r}")
    for name in sorted(images):
        seen = [name]
        current = images[name].parent
        while current is not None and current in images:
            if current in seen:
                found.append(f"images.{name}: its parents form a cycle ({' -> '.join([*seen, current])})")
                break
            seen.append(current)
            current = images[current].parent
    return found


def parse_checks(
    data: Mapping[str, JsonValue], images: Mapping[str, Image], found: list[str]
) -> dict[str, tuple[str, ...]]:
    checks: dict[str, tuple[str, ...]] = {}
    for key in table(data, "checks", "", found):
        if key != "default" and key not in images:
            found.append(f'checks.{key}: not an image (keys are "default" or image names)')
        checks[key] = strings(table(data, "checks", "", found), key, "checks", found)
    checks.setdefault("default", ("builtin",))
    return checks


def parse(text_: str) -> Definition:
    """The definition in `text_`, checked. Raises DefinitionError naming every problem."""
    try:
        raw = tomllib.loads(text_)
    except tomllib.TOMLDecodeError as error:
        raise DefinitionError(f"not TOML: {error}") from None
    found: list[str] = []
    data = json_value(raw, "", found)
    if not isinstance(data, dict):  # tomllib always returns a table; this narrows the type
        raise DefinitionError("a definition is a TOML table")
    unknown = sorted(set(data) - TOP_LEVEL)
    if unknown:
        found.append(f"unknown top-level keys {unknown}: a definition holds {sorted(TOP_LEVEL)}")
    schema = data.get("schema")
    if schema != SCHEMA:
        found.append(f"schema = {SCHEMA} is required (found {schema!r})")
    debian = parse_debian(data, found)
    params = parse_params(data, found)
    modules = parse_modules(data, params, found)
    images: dict[str, Image] = {}
    for name, raw_image in table(data, "images", "", found).items():
        if not NAME.fullmatch(name):
            found.append(f"images.{name}: an image name is lowercase letters, digits and dashes")
        elif not isinstance(raw_image, dict):
            found.append(f"images.{name} must be a table")
        else:
            image = parse_image(name, raw_image, found)
            if image is not None:
                images[name] = image
    if not found:
        found.extend(tree_problems(images))
    checks = parse_checks(data, images, found)
    if found:
        raise DefinitionError("\n".join(found))
    return Definition(SCHEMA, debian, params, modules, images, checks)


# ---- questions the plan asks ------------------------------------------------------------------


def ancestry(definition: Definition, name: str) -> list[str]:
    """The image's chain from core down to it: [core, ..., name]."""
    chain = [name]
    parent = definition.images[name].parent
    while parent is not None:
        chain.append(parent)
        parent = definition.images[parent].parent
    return chain[::-1]


def top_down(definition: Definition) -> list[str]:
    """Every image, each after its parent; siblings by name, so the order is stable."""
    return sorted(definition.images, key=lambda name: (len(ancestry(definition, name)), ancestry(definition, name)))


def children(definition: Definition, name: str) -> list[str]:
    return sorted(child for child, image in definition.images.items() if image.parent == name)


def parse_param_value(name: str, raw: str, default: Param) -> Param:
    """A `--param NAME=VALUE` value, typed like the parameter's declared default."""
    if isinstance(default, bool):
        if raw not in ("true", "false"):
            raise ValueError(f"parameter {name} is a boolean: true or false, not {raw!r}")
        return raw == "true"
    if isinstance(default, int):
        try:
            return int(raw)
        except ValueError:
            raise ValueError(f"parameter {name} is an integer, not {raw!r}") from None
    return raw


def resolve_params(definition: Definition, given: Mapping[str, str]) -> dict[str, Param]:
    """The declared parameters with the given overrides applied. Raises ValueError on an unknown one."""
    unknown = sorted(set(given) - set(definition.params))
    if unknown:
        raise ValueError(f"unknown parameters {unknown}: [params] declares {sorted(definition.params)}")
    return {
        name: parse_param_value(name, given[name], default) if name in given else default
        for name, default in sorted(definition.params.items())
    }


BUILTIN_CHECKS: Final[Mapping[str, tuple[str, ...]]] = {
    "core": (
        "no-build-snapshot",
        "no-machine-identity",
        "package-set",
        "same-resolution",
        "sbom-complete",
        "two-clones",
    ),
    "oci": (
        "ancestry",
        "no-build-snapshot",
        "no-machine-identity",
        "oci-run",
        "package-set",
        "sbom-complete",
        "two-clones",
    ),
    "incus": (
        "ancestry",
        "incus-boot",
        "no-build-snapshot",
        "no-machine-identity",
        "package-set",
        "sbom-complete",
        "two-clones",
    ),
    "installer": (
        "ancestry",
        "installer-boot",
        "no-build-snapshot",
        "no-machine-identity",
        "package-set",
        "sbom-complete",
        "two-clones",
    ),
    "os": (
        "ancestry",
        "no-build-snapshot",
        "no-machine-identity",
        "os-boot",
        "package-set",
        "sbom-complete",
        "two-clones",
    ),
}
"""DESIGN 11: the kind's own set; `locked-inputs` joins it for images that install lock entries."""


def required_checks(definition: Definition, name: str, has_lock_entries: bool) -> tuple[str, ...]:
    """The checks that make a build of `name` good: its [checks] list, `builtin` expanded."""
    listed: Sequence[str] = definition.checks.get(name, definition.checks["default"])
    found: set[str] = set()
    for check in listed:
        if check == "builtin":
            found.update(BUILTIN_CHECKS[definition.images[name].kind])
            if has_lock_entries:
                found.add("locked-inputs")
        else:
            found.add(check)
    return tuple(sorted(found))
