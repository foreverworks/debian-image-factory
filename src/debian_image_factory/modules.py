"""Built-in modules: what each installs and how its version is probed afterwards (DESIGN 6.4, 11). Pure.

The build calls `install_lines` for every switched-on module an image uses; the `locked-inputs`
check runs every `Probe` in the built image and compares what it prints.
"""

import importlib.resources
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import unquote, urlparse

from input_lock import Value

from . import nodejs
from .build import core
from .definition import Module

type Fields = Mapping[str, Value]
"""A lock entry as input-lock's `build_fields` gives it (the plan's `inputs`), url rendered."""


NODE_INSTALL: Final = "node_install.py"
"""The file name of the node-tarball module's install script in the build's work directory."""


@dataclass(frozen=True, slots=True)
class Probe:
    """Run `argv` in the image; the entry counts as installed at its locked version when the command
    exits 0 and its standard output, stripped, equals `expected`."""

    entry: str
    argv: tuple[str, ...]
    expected: str


def input_file_name(fields: Fields) -> str:
    """The file name the build stages a locked input under: the last segment of its rendered URL (the same
    rule as `build.run.input_file_name`)."""
    url = fields.get("url")
    name = unquote(urlparse(url).path.rsplit("/", 1)[-1]) if isinstance(url, str) else ""
    unsafe = name in ("", ".", "..") or any(character in name for character in "/\\\0")
    return "file" if unsafe else name


def node_install_text() -> str:
    """The text of the install script the build copies into its work directory as `NODE_INSTALL`."""
    return importlib.resources.files("debian_image_factory.build").joinpath(NODE_INSTALL).read_text(encoding="utf-8")


def helper_files(module: Module) -> dict[str, str]:
    """Files `install_lines` of `module` runs from the build's work directory: file name to text."""
    return {NODE_INSTALL: node_install_text()} if module.use == nodejs.MODULE else {}


def node_tarball(entries: Mapping[str, Fields]) -> tuple[str, Fields]:
    """The release tarball among a node-tarball module's entries (name, fields), told by its rendered url.

    Raises ValueError unless there is exactly one: the lock rules check it before a build ever gets here."""
    found = [
        (name, fields) for name, fields in sorted(entries.items()) if nodejs.is_tarball(str(fields.get("url", "")))
    ]
    if len(found) != 1:
        raise ValueError(f"a node-tarball module needs exactly one release tarball entry, not {[n for n, _ in found]}")
    return found[0]


def install_lines(module: Module, entries: Mapping[str, Fields], *, inputs: str, source_date_epoch: int) -> list[str]:
    """Shell lines the child build runs in the builder, with `"$root"` the image's root directory, to
    install `module`'s `entries` (entry name to fields). `inputs` is the builder path holding each
    entry's verified file at `<inputs>/<entry name>/<file name>` (build.run.input_file_name).

    The files in `helper_files(module)` must be in the work directory (`build.core.WORK`) first.
    Raises NotImplementedError for a module this release does not install."""
    if module.use != nodejs.MODULE:
        raise NotImplementedError(module.use)
    name, fields = node_tarball(entries)
    tarball = f"{inputs.rstrip('/')}/{name}/{input_file_name(fields)}"
    prefix = nodejs.prefix_of(module.table)
    arguments = " ".join((shlex.quote(tarball), shlex.quote(prefix), str(int(source_date_epoch))))
    return [
        f"# {module.name}: {name} into {prefix}, unpacked by the builder's python3 (the image has none)",
        f'python3 {core.WORK}/{NODE_INSTALL} "$root" {arguments}',
    ]


def probes(module: Module, entries: Mapping[str, Fields]) -> list[Probe]:
    """How the `locked-inputs` check sees each of `entries` installed by `module`.

    The release tarball is probed with `<prefix>/bin/node --version`. The keyring has no probe: it is a trust
    root fetch used to verify the checksums, and nothing of it is installed."""
    if module.use != nodejs.MODULE:
        raise NotImplementedError(module.use)
    name, fields = node_tarball(entries)
    version = fields.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"{name}: a node-tarball entry needs a version to probe")
    return [Probe(name, (f"{nodejs.prefix_of(module.table)}/bin/node", "--version"), f"v{version}")]
