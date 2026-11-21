"""Helpers the core tests share: the example definition and lock, and small definitions made on the spot."""

import copy
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, cast

import input_lock
from input_lock import JsonValue, Lock, Package

from debian_image_factory import definition
from debian_image_factory.definition import Definition, Param
from debian_image_factory.identity import FileFact, ImageInputs, image_inputs

EXAMPLES: Final = Path(__file__).resolve().parents[2] / "examples"

HEADER: Final = 'schema = 1\n[debian]\nsuite = "trixie"\n'
CORE: Final = '[images.core]\nkind = "core"\n'

TOOLS: Final[tuple[Package, ...]] = (("dpkg", "1.0", "amd64"), ("mmdebstrap", "1.0", "all"))


def example_text() -> str:
    return (EXAMPLES / "factory.toml").read_text()


def example_definition() -> Definition:
    return definition.parse(example_text())


def example_lock_data() -> dict[str, JsonValue]:
    """A fresh copy of examples/lock.json as plain JSON (safe to change)."""
    data: JsonValue = json.loads((EXAMPLES / "lock.json").read_text())
    assert isinstance(data, dict)
    return data


def entries_of(data: dict[str, JsonValue]) -> dict[str, JsonValue]:
    inputs = data["inputs"]
    assert isinstance(inputs, dict)
    return inputs


def entry_of(data: dict[str, JsonValue], name: str) -> dict[str, JsonValue]:
    entry = entries_of(data)[name]
    assert isinstance(entry, dict)
    return entry


def as_lock(data: Mapping[str, JsonValue]) -> Lock:
    """`data` as a checked Lock (input-lock's own parse, so the shape is the real one)."""
    return input_lock.parse(input_lock.dump(copy.deepcopy(dict(data))))


def example_lock() -> Lock:
    return as_lock(example_lock_data())


def parse_definition(body: str, header: str = HEADER) -> Definition:
    return definition.parse(header + body)


def small(*images: str, header: str = HEADER, extra: str = "") -> Definition:
    """A definition of a core and the given `[images.*]` sections (each a full TOML snippet)."""
    return definition.parse(header + CORE + "".join(images) + extra)


def child(name: str, kind: str, parent: str, extra: str = "") -> str:
    return f'[images.{name}]\nkind = "{kind}"\nparent = "{parent}"\n{extra}'


def files_for(*paths: str, text: str = "") -> dict[str, FileFact]:
    """Facts for hook files: content is the path plus `text`, so each file differs."""
    return {path: FileFact(path.encode().hex().ljust(64, "0")[:64], "0644", text=text) for path in paths}


def compute(
    lock: Lock,
    spec: Definition,
    packages: Mapping[str, Sequence[Package]],
    *,
    tools: Sequence[Package] = TOOLS,
    files: Mapping[str, FileFact] | None = None,
    params: Mapping[str, Param] | None = None,
    baseline: str | None = "20261108T000000Z",
) -> dict[str, ImageInputs]:
    """Every image's inputs and identity, top down, from made-up package sets (nothing resolved)."""
    chosen = dict(spec.params) if params is None else dict(params)
    result: dict[str, ImageInputs] = {}
    for name in definition.top_down(spec):
        parent = spec.images[name].parent
        result[name] = image_inputs(
            lock,
            spec,
            name,
            packages=packages.get(name, ()),
            tools=tools,
            files=files or {},
            params=chosen,
            baseline=baseline,
            parent_identity=None if parent is None else result[parent].identity,
        )
    return result


def identities(inputs: Mapping[str, ImageInputs]) -> dict[str, str]:
    return {name: one.identity for name, one in inputs.items()}


def changed_names(before: Mapping[str, ImageInputs], after: Mapping[str, ImageInputs]) -> list[str]:
    return sorted(name for name in before if before[name].identity != after[name].identity)


def jsonable(value: object) -> dict[str, JsonValue]:
    """Narrow a parsed JSON object (the CLI's plan output) for the type checker."""
    assert isinstance(value, dict)
    return cast(dict[str, JsonValue], value)
