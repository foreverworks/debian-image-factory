"""Publishing built artifacts and their records to targets (DESIGN 7.4, 8.2). This release writes `dir://`.

A `dir://` target is a plain directory: each artifact keeps its name, and its records live beside it
in `<digest>.intoto.jsonl`. Publishing the same artifact again adds only the record lines the target
does not hold yet, so test results attached later (or by someone else) are never lost, and nothing
already published is rewritten. Artifacts are copied under a temporary name and renamed into place,
so a reader never sees half a file.
"""

import hashlib
import os
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from . import commands, published


def sha256_of(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def merged_lines(present: str, new: str) -> str:
    """The records `present` holds, followed by every line of `new` it does not hold yet, in order."""
    held = [line for line in present.splitlines() if line.strip()]
    seen = set(held)
    for line in new.splitlines():
        if line.strip() and line not in seen:
            held.append(line)
            seen.add(line)
    return "".join(line + "\n" for line in held)


def write_atomically(path: Path, data: bytes) -> None:
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".publish-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(temp, 0o644)
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def copy_atomically(source: Path, path: Path) -> None:
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".publish-")
    os.close(fd)
    try:
        shutil.copyfile(source, temp)
        os.chmod(temp, 0o644)
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def artifacts_in(out_dir: Path) -> list[tuple[Path, str]]:
    """Every artifact file in a build's output directory, with its sha256: files named as artifacts
    whose content matches the digest in their name and that have a records file beside them."""
    found: list[tuple[Path, str]] = []
    for path in sorted(out_dir.iterdir()):
        name = published.parse_artifact_name(path.name)
        if name is None or not path.is_file():
            continue
        digest = sha256_of(path)
        if not digest.startswith(name.digest12):
            raise commands.Failed(f"{path}: its sha256 {digest} does not match the digest in its name")
        if not (out_dir / published.records_name_for(digest)).is_file():
            raise commands.Failed(f"{path}: no records file {published.records_name_for(digest)} beside it")
        found.append((path, digest))
    return found


def publish_dir(out_dir: Path, target: Path, out: TextIO) -> None:
    """Copy every artifact of `out_dir` and merge its records into the directory `target`."""
    target.mkdir(parents=True, exist_ok=True)
    for path, digest in artifacts_in(out_dir):
        destination = target / path.name
        if destination.is_file() and sha256_of(destination) == digest:
            state = "already there"
        else:
            copy_atomically(path, destination)
            state = "copied"
        records_name = published.records_name_for(digest)
        new = (out_dir / records_name).read_text(encoding="utf-8")
        held = target / records_name
        present = held.read_text(encoding="utf-8") if held.is_file() else ""
        merged = merged_lines(present, new)
        added = len(merged.splitlines()) - len([line for line in present.splitlines() if line.strip()])
        if merged != present:
            write_atomically(held, merged.encode("utf-8"))
        print(f"{target}: {path.name} {state}, {added} record lines added", file=out)


def publish_command(out_dir: Path, targets: Sequence[str], sign: str, out: TextIO) -> int:
    if sign != "none":
        raise commands.Usage("signing arrives in a later release; this release publishes unsigned records")
    if not targets:
        raise commands.Usage("publish needs at least one --to TARGET")
    try:
        parsed = [published.parse_target(target) for target in targets]
    except ValueError as error:
        raise commands.Usage(str(error)) from None
    for one in parsed:
        if not isinstance(one, published.DirTarget):
            raise commands.Usage("oci:// and github-release:// targets arrive in a later release; use dir://")
    if not out_dir.is_dir():
        raise commands.Failed(f"{out_dir}: no such directory (build writes it)")
    if not artifacts_in(out_dir):
        raise commands.Failed(f"{out_dir}: no artifacts to publish")
    for one in parsed:
        assert isinstance(one, published.DirTarget)  # checked above: only dir:// gets here
        publish_dir(out_dir, Path(one.path), out)
    return 0
