"""Input identity (DESIGN 7.1): what each image is built from, as one digest, computed before building.

The identity itself is input-lock's `input_identity` (tag 2: package set, the lock entries the
image installs projected through `build_fields`, the recipe digest, the parent's identity). The
factory defines only the recipe: everything else that decides the bytes it writes. Pure functions.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import input_lock
from input_lock import JsonValue, Lock, Package, Value

from . import ENGINE
from .definition import Definition, Param
from .lockrules import RESERVED, image_entries, module_of


@dataclass(frozen=True, slots=True)
class FileFact:
    """One file a recipe references, as the edge read it."""

    sha256: str | None
    """Content digest of a regular file; None for a symbolic link."""
    mode: str
    """Permission bits in octal, `0755`: an executable bit that flips rebuilds."""
    link: str | None = None
    """The target of a symbolic link."""
    text: str = ""
    """Hook and module script text (empty for file trees), searched for the parameters it reads."""

    def as_json(self) -> dict[str, JsonValue]:  # plain data out; no behaviour beyond the projection
        if self.link is not None:
            return {"link": self.link, "mode": self.mode}
        return {"mode": self.mode, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class ImageInputs:
    """Everything one image's identity is computed from, and the identity."""

    name: str
    packages: tuple[Package, ...]
    entries: Mapping[str, Mapping[str, Value]]
    params: Mapping[str, Param]
    modules: tuple[str, ...]
    recipe: Mapping[str, JsonValue]
    recipe_digest: str
    parent: str | None
    parent_identity: str | None
    identity: str


def param_env(name: str) -> str:
    """FACTORY_PARAM_<NAME>, the variable a hook reads a parameter from (DESIGN 6.3)."""
    return "FACTORY_PARAM_" + re.sub(r"[^A-Z0-9]", "_", name.upper())


def script_paths(definition: Definition, image: str, modules: Sequence[str]) -> list[str]:
    """The hooks and module scripts an image runs, in the order they run."""
    own = list(definition.images[image].hooks)
    scripts = [definition.modules[name].use for name in modules if not definition.modules[name].use.startswith("builtin:")]
    return [*scripts, *own]


def referenced(definition: Definition, image: str, modules: Sequence[str], files: Mapping[str, FileFact]) -> dict[str, FileFact]:
    """The files the image's recipe covers: its hooks, its module scripts, and its file tree."""
    paths = set(script_paths(definition, image, modules))
    tree = definition.images[image].files
    chosen = {path: fact for path, fact in files.items() if path in paths}
    if tree is not None:
        chosen.update({path: fact for path, fact in files.items() if path == tree or path.startswith(tree + "/")})
    missing = sorted(paths - set(files))
    if missing:
        raise ValueError(f"images.{image}: files not read: {missing}")
    return chosen


def modules_used(lock: Lock, definition: Definition, image: str, params: Mapping[str, Param]) -> tuple[str, ...]:
    """The switched-on modules whose lock entries list this image."""
    return tuple(
        sorted(
            {
                module
                for entry in image_entries(lock, definition, image, params).values()
                if (module := module_of(entry)) is not None
            }
        )
    )


def params_read(
    lock: Lock, definition: Definition, image: str, params: Mapping[str, Param], scripts: Mapping[str, FileFact]
) -> dict[str, Param]:
    """The parameters an image reads: the switches of every module its entries name (on or off), and
    every FACTORY_PARAM_<NAME> its hooks and module scripts mention."""
    names: set[str] = set()
    for name, entry in input_lock.entries_for(lock, image).items():
        module = module_of(entry)
        if name not in RESERVED and module is not None and definition.modules[module].enabled_by is not None:
            names.add(str(definition.modules[module].enabled_by))
    for fact in scripts.values():
        names.update(name for name in params if param_env(name) in fact.text)
    return {name: params[name] for name in sorted(names)}


def recipe(
    definition: Definition,
    image: str,
    *,
    tools: Sequence[Package],
    files: Mapping[str, FileFact],
    params: Mapping[str, Param],
    modules: Sequence[str],
    baseline: str | None,
) -> dict[str, JsonValue]:
    """The recipe (DESIGN 7.1): every setting and file that decides the bytes, nothing about Renovate.

    `files` is the image's own referenced files; `params` the parameters it reads; `baseline` the
    lock's baseline snapshot (entered only when the image's apt sources point at it)."""
    spec = definition.images[image]
    debian = definition.debian
    return {
        "engine": ENGINE,
        "tools": [list(tool) for tool in sorted(set(tools))],
        "kind": {"kind": spec.kind, spec.kind: dict(spec.kind_table)},
        "image": dict(spec.section),
        "modules": {name: dict(definition.modules[name].table) for name in sorted(modules)},
        "files": {path: fact.as_json() for path, fact in sorted(files.items())},
        "params": dict(sorted(params.items())),
        "debian": {
            "suite": debian.suite,
            "components": list(debian.components),
            "architecture": debian.architectures[0],
            "source_date_epoch": debian.source_date_epoch,
        },
        "baseline": baseline if spec.apt_sources != "live" else None,
    }


def image_inputs(
    lock: Lock,
    definition: Definition,
    image: str,
    *,
    packages: Sequence[Package],
    tools: Sequence[Package],
    files: Mapping[str, FileFact],
    params: Mapping[str, Param],
    baseline: str | None,
    parent_identity: str | None,
) -> ImageInputs:
    """One image's inputs and identity. `params` are all the resolved parameters; the image keeps
    the ones it reads. `files` are every file the definition references, as the edge read them."""
    modules = modules_used(lock, definition, image, params)
    own_files = referenced(definition, image, modules, files)
    scripts = {path: own_files[path] for path in script_paths(definition, image, modules)}
    reads = params_read(lock, definition, image, params, scripts)
    entries = image_entries(lock, definition, image, params)
    the_recipe = recipe(
        definition, image, tools=tools, files=own_files, params=reads, modules=modules, baseline=baseline
    )
    recipe_digest = input_lock.digest(the_recipe)
    package_set = tuple(sorted(set(packages)))
    identity = input_lock.input_identity(package_set, entries, recipe_digest, parent_identity)
    return ImageInputs(
        name=image,
        packages=package_set,
        entries=entries,
        params=reads,
        modules=modules,
        recipe=the_recipe,
        recipe_digest=recipe_digest,
        parent=definition.images[image].parent,
        parent_identity=parent_identity,
        identity=identity,
    )
