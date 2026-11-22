"""The byte-writing tools of the builder image, and the versions this factory release pins (DESIGN 5.4).

Only packages that decide the bytes the factory writes are listed: tools that merely fetch, verify,
sign or push never enter an identity. The versions are read from a file generated from the real
builder image (`scripts/builder tools`), so a changed snapshot shows up as a changed file.
"""

import json
from importlib import resources
from typing import Final

TOOL_PACKAGES: Final = (
    "mmdebstrap",
    "apt",
    "dpkg",
    "tar",
    "gzip",
    "cpio",
    "squashfs-tools",
    "python3",
    "python3.13",
    "python3.13-minimal",
    "libpython3.13-stdlib",
    "libpython3.13-minimal",
    "zlib1g",
    "liblzma5",
)
"""The binary packages whose versions decide the bytes the factory writes."""

BUILDER_SNAPSHOT: Final = "20261121T004329Z"
"""The archive snapshot the builder image is built from: the `debian_snapshot` of the factory's own
lock.json (a unit test keeps them equal)."""

BUILDER_IMAGE: Final = f"debian-image-factory-builder:{BUILDER_SNAPSHOT}"
"""The builder image a build runs in unless `--builder-image` names another: the tag `scripts/builder
build` gives the image it builds at that snapshot."""

VM_IMAGE: Final = f"debian-image-factory-vm:{BUILDER_SNAPSHOT}"
"""The boot checks' image (QEMU, OVMF and the disk tools, `builder/vm.Dockerfile`), from the builder's base
and snapshot: the tag `scripts/builder vm` gives it. It writes no artifact's bytes, so it enters no identity."""

type Tool = tuple[str, str, str]
"""One installed package: name, version, architecture."""


def parse_tools(data: object) -> tuple[Tool, ...]:
    """Check the JSON shape of a tools list: a sorted list of [name, version, architecture] strings
    whose names are exactly TOOL_PACKAGES. Raises ValueError otherwise."""
    if not isinstance(data, list):
        raise ValueError("tools: expected a list")
    tools: list[Tool] = []
    for index, entry in enumerate(data):
        if not isinstance(entry, list) or len(entry) != 3:
            raise ValueError(f"tools[{index}]: expected [name, version, architecture]")
        name, version, architecture = entry
        if not (isinstance(name, str) and isinstance(version, str) and isinstance(architecture, str)):
            raise ValueError(f"tools[{index}]: name, version and architecture must be strings")
        if not (name and version and architecture):
            raise ValueError(f"tools[{index}]: name, version and architecture must not be empty")
        tools.append((name, version, architecture))
    if tools != sorted(tools):
        raise ValueError("tools: entries must be sorted")
    names = [name for name, _, _ in tools]
    if sorted(names) != sorted(TOOL_PACKAGES):
        missing = sorted(set(TOOL_PACKAGES) - set(names))
        extra = sorted(set(names) - set(TOOL_PACKAGES))
        raise ValueError(f"tools: names must be exactly the tool packages (missing {missing}, unexpected {extra})")
    return tuple(tools)


def builder_tools() -> tuple[Tool, ...]:
    """The tool versions of the builder image this release pins, from the packaged builder/tools.json."""
    text = resources.files("debian_image_factory").joinpath("builder", "tools.json").read_text(encoding="utf-8")
    return parse_tools(json.loads(text))
