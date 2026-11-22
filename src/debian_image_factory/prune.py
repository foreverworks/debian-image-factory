"""`prune`: delete the builds a target holds beyond what retention keeps (DESIGN 9.1, 9.3, 11).

`retention` decides, purely, from the builds a target lists, the definition's required checks and the
consumer's pins. This module reads each target, prints one line per artifact (kept or deleted, with the
reason), and deletes unless `--dry-run`:

- `dir://`: the artifact's file or files (an Incus image's metadata and rootfs) and its
  `<digest>.intoto.jsonl`.
- `github-release://`: the same files, as assets.
- `oci://`: the image's manifest by digest, then the records attached to it (the referrers, or the index
  of the referrers tag under the tag schema), and the `identity-<identity>` tag if it still names the
  manifest. The image goes first: when a registry refuses the delete, nothing else was touched and the
  artifact is reported, never left without its records. Layers and blobs are the registry's to
  collect.

An artifact is deleted before its records, so a failure in between leaves records without an artifact
(harmless) and never an artifact without records (which no lookup accepts). Records shared with a kept
artifact of the same digest stay. A failure on one artifact is reported and the others go on; the exit
status is then 1. Files that look like an artifact but do not count (no records, a digest that does not match
its name, an unfinished upload) are listed as ignored and never deleted.
"""

import urllib.error
from collections.abc import Callable, Collection, Sequence
from pathlib import Path
from typing import TextIO

from input_lock.identity import HEX64

from . import commands, definition, github, incus, oci, published, registry, retention, targets
from .published import Artifact, DirTarget, OciTarget, ReleaseTarget, Target
from .retention import Verdict

Deleter = Callable[[Artifact], None]
"""Deletes one artifact and what belongs to it; raises OSError when it cannot."""


def pin_digest(text: str) -> str:
    """A pin as full lowercase hex: `sha256:<hex>` or plain hex. Raises Usage for anything else."""
    digest = text.removeprefix("sha256:").lower()
    if not HEX64.fullmatch(digest):
        raise commands.Usage(f"--pin {text}: a sha256 digest in full (64 hex characters, `sha256:` optional)")
    return digest


def required_checks_of(loaded: definition.Definition) -> retention.RequiredChecks:
    def required(image: str, locked: bool) -> Sequence[str] | None:
        return definition.required_checks(loaded, image, locked) if image in loaded.images else None

    return required


def files_of(artifact: Artifact) -> list[str]:
    """The files of a file artifact, the one its name is first: an Incus image is two."""
    rootfs = incus.rootfs_of(artifact.name)
    return [artifact.name] if rootfs is None else [artifact.name, rootfs]


def describe(error: OSError) -> str:
    if isinstance(error, urllib.error.URLError):
        return str(error.reason)
    return error.strerror or str(error)


# ---- deleting ----------------------------------------------------------------------------------


def delete_from_dir(directory: Path, artifact: Artifact, with_records: bool) -> None:
    names = files_of(artifact)
    if with_records:
        names.append(published.records_name_for(artifact.digest))
    for name in names:
        (directory / name).unlink(missing_ok=True)


def delete_from_release(
    client: github.Client, held: dict[str, github.Asset], artifact: Artifact, with_records: bool
) -> None:
    """Delete the assets of `artifact`; `held` is the release's assets by name and follows the deletions."""
    names = files_of(artifact)
    if with_records:
        names.append(published.records_name_for(artifact.digest))
    for name in names:
        asset = held.pop(name, None)
        if asset is not None:
            github.delete_asset(client, asset)


def delete_from_registry(client: registry.Client, artifact: Artifact) -> None:
    """Delete the image `artifact` (its manifest digest) and what hangs on it. Everything that hangs on
    it is listed first, then the image goes: a registry that refuses raises before anything else is
    touched. A referrer already gone is not an error."""
    digest = artifact.digest
    attached = registry.referrer_descriptors(client, digest)
    index_tag = oci.referrers_tag(digest)
    index = registry.manifest_digest(client, index_tag)
    registry.delete_reference(client, oci.digest_text(digest))
    for one in attached:
        registry.delete_reference(client, oci.digest_text(one.digest))
    if index is not None:
        registry.delete_reference(client, oci.digest_text(index))
    tag = oci.identity_tag(artifact.identity)
    if registry.manifest_digest(client, tag) == digest:  # a registry that kept the tag of a deleted image
        registry.delete_reference(client, tag)


# ---- one target --------------------------------------------------------------------------------


def deleter_for(
    target: Target, verdicts: Sequence[Verdict], connect: Callable[[OciTarget], registry.Client]
) -> Deleter:
    """What deletes an artifact of `target`. Records shared with a kept artifact (the same digest) stay."""
    kept = {one.artifact.digest for one in verdicts if one.keep}
    match target:
        case DirTarget(path):
            return lambda artifact: delete_from_dir(Path(path), artifact, artifact.digest not in kept)
        case OciTarget():
            client = connect(target)
            return lambda artifact: delete_from_registry(client, artifact)
        case ReleaseTarget():
            release_client = github.connect(target)
            release = github.release_by_tag(release_client)
            held = {} if release is None else {one["name"]: one for one in github.list_assets(release_client, release)}
            return lambda artifact: delete_from_release(release_client, held, artifact, artifact.digest not in kept)


def prune_target(
    target: Target,
    required: retention.RequiredChecks,
    pins: Collection[str],
    keep_good: int,
    keep_candidates: int,
    dry_run: bool,
    out: TextIO,
    connect: Callable[[OciTarget], registry.Client],
) -> tuple[list[str], set[str]]:
    """Read `target`, print a line for each artifact and delete the ones retention does not keep. The
    problems found (nothing is raised for them), and the digests seen."""
    label = published.format_target(target)
    problems: list[str] = []
    try:
        held = targets.list_artifacts(target, connect)
    except OSError as error:
        return [f"{label}: cannot be read: {describe(error)}"], set()
    verdicts = retention.retain(held.artifacts, required, pins, keep_good, keep_candidates)
    delete: Deleter | None = None
    for verdict in verdicts:
        shown = verdict.artifact.name
        if verdict.keep:
            print(f"{label}: {shown} kept, {verdict.reason}", file=out)
        elif dry_run:
            print(f"{label}: {shown} would be deleted, {verdict.reason}", file=out)
        else:
            try:
                delete = delete or deleter_for(target, verdicts, connect)
                delete(verdict.artifact)
            except OSError as error:
                problems.append(f"{label}: {shown}: the delete failed: {describe(error)}")
                print(f"{label}: {shown} delete failed, {describe(error)} ({verdict.reason})", file=out)
            else:
                print(f"{label}: {shown} deleted, {verdict.reason}", file=out)
    for one in held.rejected:
        print(f"{label}: {one.name} ignored, {one.reason}", file=out)
    return problems, {one.artifact.digest for one in verdicts}


def prune_command(
    against: Sequence[str],
    pins: Sequence[str],
    keep_good: int,
    keep_candidates: int,
    dry_run: bool,
    definition_path: Path,
    out: TextIO,
    connect: Callable[[OciTarget], registry.Client] = registry.connect,
) -> int:
    """Prune every target. Each is judged on its own: the newest `keep_good` good builds and
    `keep_candidates` candidates of each image stay in each; a pin keeps its artifact in every target."""
    if not against:
        raise commands.Usage("prune needs at least one --against TARGET")
    if keep_good < 0 or keep_candidates < 0:
        raise commands.Usage("--keep-good and --keep-candidates are not negative")
    pinned = frozenset(pin_digest(text) for text in pins)
    parsed = commands.parse_targets(against)
    try:
        loaded = definition.parse(commands.read_text(definition_path))
    except definition.DefinitionError as error:
        raise commands.Failed("\n".join(f"{definition_path}: {line}" for line in str(error).splitlines())) from None
    required = required_checks_of(loaded)
    problems: list[str] = []
    seen: set[str] = set()
    for target in parsed:
        found, digests = prune_target(target, required, pinned, keep_good, keep_candidates, dry_run, out, connect)
        problems.extend(found)
        seen |= digests
    for digest in sorted(pinned - seen):
        print(f"pin sha256:{digest} matches no artifact in these targets", file=out)
    if problems:
        raise commands.Failed("\n".join(problems))
    return 0
