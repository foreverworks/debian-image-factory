"""Reading `plan.json` back (DESIGN 7.3): every field the plan command writes, checked before anything uses it.

`fetch`, `build` and `test` read the plan alone. `parse_plan` takes whatever `json.loads` returned and
returns a `Plan` (typed dictionaries) or raises ValueError naming the first field that is not of the
shape `plan.build_plan` writes. Pure; `read_plan` is the one edge, for a file.
"""

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Final, NotRequired, TypedDict

from input_lock import TRUST, JsonValue, Package, Value

from .definition import Param
from .snapshots import ARCHIVES

SCHEMA: Final = 2
SNAPSHOT_ID: Final = re.compile(r"[0-9]{8}T[0-9]{6}Z")
NAME: Final = re.compile(r"[a-z0-9][a-z0-9.+-]*")
"""What a suite, component or architecture looks like: they enter URLs and paths, so nothing else passes."""
STATES: Final = ("build", "reuse", "wait")
DEB_FIELDS: Final = ("package", "registry_url", "version")
ARTIFACT: Final = re.compile(r"sha256:[0-9a-f]{64}")
"""How the plan names the artifact it reuses or waits for: `sha256:<hex>`, as every digest is written."""


class Debian(TypedDict):
    suite: str
    components: tuple[str, ...]
    architecture: str


class Deb(TypedDict):
    """A vendor .deb an image installs: its package, version and repository (the entry's `registryUrl`)."""

    package: str
    version: str
    registry_url: str


class ImageEntry(TypedDict):
    kind: str
    parent: str | None
    identity: str
    parent_identity: str | None
    recipe: str
    apt_sources: str
    request: tuple[str, ...]
    packages: tuple[Package, ...]
    inputs: dict[str, dict[str, Value]]
    """Lock entry name -> its `build_fields` (`url` rendered; a field is text, a list of names or null)."""
    modules: tuple[str, ...]
    trust: dict[str, dict[str, str]]
    """Entry name -> `signed_by` (the keyring entry) and the rendered `sums_url` and `sums_sig_url` when it has
    them: the signed checksum list `fetch` verifies the entry's checksum against."""
    debs: dict[str, Deb]
    """Entry name -> the vendor .deb it installs (`plan.debs_of`): verified again by `fetch` through the
    repository's signed InRelease, installed by the build in the same apt transaction as `request`."""
    params: dict[str, Param]
    checks: tuple[str, ...]
    state: str
    artifact: NotRequired[JsonValue]
    because: NotRequired[JsonValue]
    waiting_for: NotRequired[JsonValue]
    rejected: NotRequired[JsonValue]


class Plan(TypedDict):
    schema: int
    factory: str
    engine: int
    snapshots: dict[str, str]
    """Archive name -> the exact ID that archive lists, one for each of `snapshots.ARCHIVES`."""
    baseline: str | None
    debian: Debian
    params: dict[str, Param]
    images: dict[str, ImageEntry]


def _object(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be an object")
    found: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{where} has a key that is not text")
        found[key] = item
    return found


def _list(value: object, where: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{where} must be a list")
    return list(value)


def _text(value: object, where: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where} must be non-empty text")
    if pattern is not None and not pattern.fullmatch(value):
        raise ValueError(f"{where} is {value!r}, which is not a valid value")
    return value


def _optional_text(value: object, where: str) -> str | None:
    return None if value is None else _text(value, where)


def _integer(value: object, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{where} must be a whole number")
    return value


def _member(parent: Mapping[str, object], key: str, where: str) -> object:
    if key not in parent:
        raise ValueError(f"{where}.{key} is missing" if where else f"{key} is missing")
    return parent[key]


def _texts(value: object, where: str) -> tuple[str, ...]:
    return tuple(_text(item, f"{where}[{index}]") for index, item in enumerate(_list(value, where)))


def _package(value: object, where: str) -> Package:
    items = _list(value, where)
    if len(items) != 3:
        raise ValueError(f"{where} must be [name, version, architecture]")
    name, version, arch = (_text(item, f"{where}[{index}]") for index, item in enumerate(items))
    return (name, version, arch)


def _params(value: object, where: str) -> dict[str, Param]:
    found: dict[str, Param] = {}
    for name, item in _object(value, where).items():
        if not isinstance(item, str | int | bool):
            raise ValueError(f"{where}.{name} must be text, a number or true/false")
        found[name] = item
    return found


def _fields(value: object, where: str) -> dict[str, Value]:
    found: dict[str, Value] = {}
    for name, item in _object(value, where).items():
        if item is None or isinstance(item, str):
            found[name] = item
        elif isinstance(item, list) and all(isinstance(part, str) for part in item):
            found[name] = [str(part) for part in item]
        else:
            raise ValueError(f"{where}.{name} must be text, a list of text or null")
    return found


def _trust(value: object, where: str) -> dict[str, dict[str, str]]:
    found: dict[str, dict[str, str]] = {}
    for name, raw in _object(value, where).items():
        fields = _object(raw, f"{where}.{name}")
        unknown = sorted(set(fields) - set(TRUST))
        if unknown:
            raise ValueError(f"{where}.{name} has fields {unknown}, which are not among {list(TRUST)}")
        found[name] = {field: _text(item, f"{where}.{name}.{field}") for field, item in fields.items()}
        if "signed_by" not in found[name]:
            raise ValueError(f"{where}.{name}.signed_by is missing")
        if "sums_sig_url" in found[name] and "sums_url" not in found[name]:
            raise ValueError(f"{where}.{name}.sums_sig_url needs a sums_url")
    return found


def _debs(value: object, where: str, inputs: Mapping[str, object], trust: Mapping[str, object]) -> dict[str, Deb]:
    found: dict[str, Deb] = {}
    for name, raw in _object(value, where).items():
        fields = _object(raw, f"{where}.{name}")
        unknown = sorted(set(fields) - set(DEB_FIELDS))
        if unknown:
            raise ValueError(f"{where}.{name} has fields {unknown}, which are not among {list(DEB_FIELDS)}")
        if name not in inputs or name not in trust:
            raise ValueError(f"{where}.{name} must be one of the image's inputs, with its trust (signed_by)")
        registry_url = _text(_member(fields, "registry_url", f"{where}.{name}"), f"{where}.{name}.registry_url")
        if not registry_url.startswith("https://"):
            raise ValueError(f"{where}.{name}.registry_url must be an https:// URL, not {registry_url!r}")
        found[name] = {
            "package": _text(_member(fields, "package", f"{where}.{name}"), f"{where}.{name}.package"),
            "version": _text(_member(fields, "version", f"{where}.{name}"), f"{where}.{name}.version"),
            "registry_url": registry_url,
        }
    return found


def parse_image(name: str, value: object) -> ImageEntry:
    """One `images.<name>` entry of a plan, every field checked."""
    where = f"images.{name}"
    entry = _object(value, where)

    def member(key: str) -> object:
        return _member(entry, key, where)

    state = _text(member("state"), f"{where}.state")
    if state not in STATES:
        raise ValueError(f"{where}.state is {state!r}, not one of {list(STATES)}")
    inputs = {
        entry_name: _fields(fields, f"{where}.inputs.{entry_name}")
        for entry_name, fields in _object(member("inputs"), f"{where}.inputs").items()
    }
    trust = _trust(member("trust"), f"{where}.trust")
    image: ImageEntry = {
        "kind": _text(member("kind"), f"{where}.kind"),
        "parent": _optional_text(member("parent"), f"{where}.parent"),
        "identity": _text(member("identity"), f"{where}.identity"),
        "parent_identity": _optional_text(member("parent_identity"), f"{where}.parent_identity"),
        "recipe": _text(member("recipe"), f"{where}.recipe"),
        "apt_sources": _text(member("apt_sources"), f"{where}.apt_sources"),
        "request": _texts(member("request"), f"{where}.request"),
        "packages": tuple(
            _package(item, f"{where}.packages[{index}]")
            for index, item in enumerate(_list(member("packages"), f"{where}.packages"))
        ),
        "inputs": inputs,
        "modules": _texts(member("modules"), f"{where}.modules"),
        "trust": trust,
        "debs": _debs(member("debs"), f"{where}.debs", inputs, trust),
        "params": _params(member("params"), f"{where}.params"),
        "checks": _texts(member("checks"), f"{where}.checks"),
        "state": state,
    }
    if "artifact" in entry:
        image["artifact"] = _text(entry["artifact"], f"{where}.artifact", ARTIFACT)
    for key in ("because", "waiting_for", "rejected"):
        if key in entry:
            image[key] = _json(entry[key], f"{where}.{key}")
    return image


def _json(value: object, where: str) -> JsonValue:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, list):
        return [_json(item, f"{where}[{index}]") for index, item in enumerate(value)]
    return {key: _json(item, f"{where}.{key}") for key, item in _object(value, where).items()}


def _snapshots(value: object) -> dict[str, str]:
    """`snapshots`: exactly one snapshot ID for each archive a build reads."""
    found = _object(value, "snapshots")
    if set(found) != set(ARCHIVES):
        raise ValueError(
            f"snapshots must name exactly {', '.join(ARCHIVES)}, not {', '.join(sorted(found)) or 'nothing'}"
        )
    return {archive: _text(found[archive], f"snapshots.{archive}", SNAPSHOT_ID) for archive in ARCHIVES}


def parse_plan(data: object) -> Plan:
    """The plan in `data` (parsed JSON). ValueError names the first field that is missing or of the wrong shape."""
    plan = _object(data, "the plan")
    if plan.get("schema") == 1:
        raise ValueError(
            f"this plan is schema 1, which names one snapshot for both archives: schema {SCHEMA} names one per "
            "archive (`snapshots`), so make the plan again with `plan`"
        )
    if plan.get("schema") != SCHEMA or isinstance(plan.get("schema"), bool):
        raise ValueError(f"schema must be {SCHEMA}, this plan has {plan.get('schema')!r}")
    debian = _object(_member(plan, "debian", ""), "debian")
    components = tuple(
        _text(item, f"debian.components[{index}]", NAME)
        for index, item in enumerate(_list(_member(debian, "components", "debian"), "debian.components"))
    )
    if not components:
        raise ValueError("debian.components must name at least one component")
    images = _object(_member(plan, "images", ""), "images")
    return {
        "schema": SCHEMA,
        "factory": _text(_member(plan, "factory", ""), "factory"),
        "engine": _integer(_member(plan, "engine", ""), "engine"),
        "snapshots": _snapshots(_member(plan, "snapshots", "")),
        "baseline": _optional_text(_member(plan, "baseline", ""), "baseline"),
        "debian": {
            "suite": _text(_member(debian, "suite", "debian"), "debian.suite", NAME),
            "components": components,
            "architecture": _text(_member(debian, "architecture", "debian"), "debian.architecture", NAME),
        },
        "params": _params(_member(plan, "params", ""), "params"),
        "images": {name: parse_image(name, value) for name, value in images.items()},
    }


def read_plan(path: Path) -> Plan:
    """`parse_plan` of the JSON file at `path`. OSError when it cannot be read, ValueError when it is not a plan."""
    try:
        data: object = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"not JSON: {error}") from None
    return parse_plan(data)
