"""Reading the layers of an OCI image as one filesystem (DESIGN 11): whiteouts applied, every byte scanned.

Each layer is a gzip tar read in one streaming pass by `tarball.scan_tarball`, so memory stays bounded by
one layer's member list plus the few small files a check asked for. `merge` then lays the layers on each
other the way a container runtime does (image-spec `layer.md`):

- `.wh.<name>` in a directory removes `<name>` (a file, or a directory and all it holds) from the layers
  below it; `.wh..wh..opq` makes the directory itself empty of everything the layers below put in it.
  Both act on lower layers only: what the same layer holds beside them stays.
- Any other name starting `.wh..wh.` is reserved by the spec and is not a file of the image.
- A layer entry that is not a directory replaces a directory of the same name from below, with its content.

What the merged view hides still ships: the private-key and snapshot-ID findings of every layer count, so a
secret a later layer deletes is found all the same.
"""

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import tarball
from .scanning import Needle
from .tarball import Hit, Member

WHITEOUT: Final = ".wh."
OPAQUE: Final = ".wh..wh..opq"
RESERVED: Final = ".wh..wh."


@dataclass(frozen=True, slots=True)
class Placed:
    """A member of the merged view and the layer (0 is the first) it comes from."""

    member: Member
    layer: int


def parent_of(path: str) -> str:
    return path.rsplit("/", 1)[0] or "/"


def under(path: str, ancestors: frozenset[str]) -> bool:
    """Whether `path` is one of `ancestors` or lies below one."""
    while True:
        if path in ancestors:
            return True
        if path == "/":
            return False
        path = parent_of(path)


def strictly_under(path: str, ancestors: frozenset[str]) -> bool:
    return path != "/" and under(parent_of(path), ancestors)


def whiteouts(members: Iterable[Member]) -> tuple[frozenset[str], frozenset[str], list[Member]]:
    """(paths a layer removes with their descendants, directories it empties, its own entries).

    The entries are everything that is not a whiteout marker, in archive order."""
    gone: set[str] = set()
    emptied: set[str] = set()
    entries: list[Member] = []
    for member in members:
        name = member.path.rsplit("/", 1)[-1]
        directory = parent_of(member.path)
        if name == OPAQUE:
            emptied.add(directory)
        elif name.startswith(RESERVED):
            continue
        elif name.startswith(WHITEOUT) and len(name) > len(WHITEOUT):
            gone.add(directory.rstrip("/") + "/" + name[len(WHITEOUT) :])
        else:
            entries.append(member)
    return frozenset(gone), frozenset(emptied), entries


def merge(scans: Iterable[tarball.Scan]) -> tarball.Scan:
    """The merged view of layers given base first, as one `Scan`: the members that survive, the contents
    of the wanted files that survive, and the key files and needle hits of every layer (hidden ones too).

    Layers are consumed one at a time, so a lazy iterator keeps memory to one layer's scan.
    """
    placed: dict[str, Placed] = {}
    contents: dict[str, bytes] = {}
    key_files: set[str] = set()
    hits: list[Hit] = []
    for index, scan in enumerate(scans):
        gone, emptied, entries = whiteouts(scan.members)
        replaced = frozenset(
            member.path
            for member in entries
            if member.kind != "dir" and (below := placed.get(member.path)) is not None and below.member.kind == "dir"
        )
        if gone or emptied or replaced:
            for path in [
                p for p in placed if under(p, gone) or strictly_under(p, emptied) or strictly_under(p, replaced)
            ]:
                del placed[path]
                contents.pop(path, None)
        for member in entries:
            placed[member.path] = Placed(member, index)
            if member.kind == "file" and member.path in scan.contents:
                contents[member.path] = scan.contents[member.path]
            else:
                contents.pop(member.path, None)
        key_files.update(scan.key_files)
        hits.extend(scan.needle_hits)
    return tarball.Scan(
        tuple(one.member for one in placed.values()),
        contents,
        tuple(sorted(key_files)),
        tuple(hits[: tarball.HITS_LIMIT]),
    )


def scan_layers(paths: Sequence[Path], wanted: frozenset[str], needle: Needle, keys: bool) -> Iterator[tarball.Scan]:
    """The layers' scans, base first, one pass each and none held after it is yielded.

    Raises tarfile.TarError, EOFError or OSError when a layer cannot be read, at the point it is reached."""
    for path in paths:
        yield tarball.scan_tarball(path, wanted, needle, keys)


def scan_image(paths: Sequence[Path], wanted: frozenset[str], needle: Needle, keys: bool) -> tarball.Scan:
    """The merged view of the layer files `paths` (base first) with what `tarball.scan_tarball` finds in each."""
    return merge(scan_layers(paths, wanted, needle, keys))
