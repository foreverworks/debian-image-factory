"""Built-in modules: what each installs and how its version is probed afterwards (DESIGN 6.4, 11). Pure.

The build calls `install_lines` for every switched-on module an image uses; the `locked-inputs`
check runs every `Probe` in the built image and compares what it prints. A `builtin:deb` module's files
are installed by apt with the image's packages (`build.oci.install_lines`), so it adds no lines here, and
its entries are seen in the image's dpkg status, so it has no probe.
"""

import importlib.resources
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import unquote, urlparse

from input_lock import Value

from . import filemodule, nodejs, vendordeb
from .build import core
from .definition import Module

type Fields = Mapping[str, Value]
"""A lock entry as input-lock's `build_fields` gives it (the plan's `inputs`), url rendered."""


NODE_INSTALL: Final = "node_install.py"
"""The file name of the node-tarball module's install script in the build's work directory."""

FILE_INSTALL: Final = "file_install.py"
"""The file name of the file module's install script in the build's work directory."""


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


def helper_text(name: str) -> str:
    """The text of an install script the build copies into its work directory."""
    return importlib.resources.files("debian_image_factory.build").joinpath(name).read_text(encoding="utf-8")


def node_install_text() -> str:
    """The text of the install script the build copies into its work directory as `NODE_INSTALL`."""
    return helper_text(NODE_INSTALL)


HELPERS: Final[Mapping[str, str]] = {nodejs.MODULE: NODE_INSTALL, filemodule.MODULE: FILE_INSTALL}
"""The install script each builtin module runs from the build's work directory, by `use`."""


def helper_files(module: Module) -> dict[str, str]:
    """Files `install_lines` of `module` runs from the build's work directory: file name to text."""
    name = HELPERS.get(module.use)
    return {} if name is None else {name: helper_text(name)}


def placed(entries: Mapping[str, Fields]) -> tuple[str, Fields]:
    """The one entry a file module places (name, fields); `entries` hold no keyring.

    Raises ValueError unless there is exactly one: the lock rules check it before a build ever gets here."""
    if len(entries) != 1:
        raise ValueError(f"a file module places exactly one lock entry per image, not {sorted(entries)}")
    ((name, fields),) = entries.items()
    return name, fields


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

    The files in `helper_files(module)` must be in the work directory (`build.core.WORK`) first; `entries`
    hold no keyring (a trust root, never installed). Raises NotImplementedError for a module this release
    does not install."""
    if module.use == vendordeb.MODULE:
        return [f"# {module.name}: its .deb files were installed by apt, with the image's packages"]
    if module.use == filemodule.MODULE:
        return file_lines(module, entries, inputs=inputs, source_date_epoch=source_date_epoch)
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


def file_lines(module: Module, entries: Mapping[str, Fields], *, inputs: str, source_date_epoch: int) -> list[str]:
    """A file module's one entry, placed at its `path` or unpacked into it by the builder's python3."""
    name, fields = placed(entries)
    source = f"{inputs.rstrip('/')}/{name}/{input_file_name(fields)}"
    path = filemodule.path_of(module.table)
    how = (
        ("--unpack", str(filemodule.strip_of(module.table)))
        if filemodule.unpacks(module.table)
        else ("--mode", filemodule.mode_of(module.table))
    )
    arguments = " ".join((shlex.quote(source), shlex.quote(path), str(int(source_date_epoch)), *how))
    verb = "unpacked into" if filemodule.unpacks(module.table) else "placed at"
    return [
        f"# {module.name}: {name} {verb} {path}, by the builder's python3 (the image may have no tar or python)",
        f'python3 -I {core.WORK}/{FILE_INSTALL} "$root" {arguments}',
    ]


def probes(module: Module, entries: Mapping[str, Fields]) -> list[Probe]:
    """How the `locked-inputs` check sees each of `entries` installed by `module`.

    The release tarball is probed with `<prefix>/bin/node --version`. A file module's placed file is probed with
    `sha256sum <path>`, which prints its locked sha256 and the path; an unpacked tarball, whose members have no
    checksum in the lock, with `test -d <path>`, which prints nothing. A deb module's entries are read from the
    dpkg status instead and have no probe. A keyring has no probe: it is a trust root fetch used to verify the
    checksums, and nothing of it is installed."""
    if module.use == vendordeb.MODULE:
        return []
    if module.use == filemodule.MODULE:
        return [file_probe(module, entries)]
    if module.use != nodejs.MODULE:
        raise NotImplementedError(module.use)
    name, fields = node_tarball(entries)
    version = fields.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"{name}: a node-tarball entry needs a version to probe")
    return [Probe(name, (f"{nodejs.prefix_of(module.table)}/bin/node", "--version"), f"v{version}")]


def file_probe(module: Module, entries: Mapping[str, Fields]) -> Probe:
    name, fields = placed(entries)
    path = filemodule.path_of(module.table)
    if filemodule.unpacks(module.table):
        return Probe(name, ("test", "-d", path), "")
    sha256 = fields.get("sha256")
    if not isinstance(sha256, str) or not sha256:
        raise ValueError(f"{name}: a file entry needs a sha256 to probe")
    return Probe(name, ("sha256sum", path), f"{sha256}  {path}")
