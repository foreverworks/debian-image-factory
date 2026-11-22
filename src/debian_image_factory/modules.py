"""Built-in modules: what each installs and how its version is probed afterwards (DESIGN 6.4, 11). Pure.

The build calls `install_lines` for every switched-on module an image uses; the `locked-inputs`
check runs every `Probe` in the built image and compares what it prints.
"""

from collections.abc import Mapping
from dataclasses import dataclass

from input_lock import Value

from .definition import Module

type Fields = Mapping[str, Value]
"""A lock entry as input-lock's `build_fields` gives it (the plan's `inputs`), url rendered."""


@dataclass(frozen=True, slots=True)
class Probe:
    """Run `argv` in the image; the entry counts as installed at its locked version when the command
    exits 0 and its standard output, stripped, equals `expected`."""

    entry: str
    argv: tuple[str, ...]
    expected: str


def install_lines(module: Module, entries: Mapping[str, Fields], *, inputs: str, source_date_epoch: int) -> list[str]:
    """Shell lines the child build runs in the builder, with `"$root"` the image's root directory, to
    install `module`'s `entries` (entry name to fields). `inputs` is the builder path holding each
    entry's verified file at `<inputs>/<LOCK_NAME>/<file name>` (build.run.input_file_name)."""
    raise NotImplementedError(module.use)


def probes(module: Module, entries: Mapping[str, Fields]) -> list[Probe]:
    """How the `locked-inputs` check sees each of `entries` installed by `module`."""
    raise NotImplementedError(module.use)
