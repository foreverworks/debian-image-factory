"""Publishing built artifacts and their records to targets (DESIGN 7.4, 8.2). This release writes `dir://`,
`oci://` and `github-release://`.

A `dir://` target is a plain directory: each artifact keeps its name, and its records live beside it
in `<digest>.intoto.jsonl`. Publishing the same artifact again adds only the record lines the target
does not hold yet, so test results attached later (or by someone else) are never lost, and nothing
already published is rewritten. Artifacts are copied under a temporary name and renamed into place,
so a reader never sees half a file. A `dir://` target takes files only.

An `oci://` target takes OCI image layouts (`<name>.oci/` directories) only. Each is pushed with
`push_layout`, which knows nothing about the factory: blobs the registry lacks, the manifest by digest,
the tags it is given, then each record (a line of `<manifest digest>.intoto.jsonl`, byte for byte) as
a referrer of the manifest. A record the registry already holds, found by the digest of its envelope,
is skipped, so publishing again adds only what is new.

A `github-release://` target takes files only, as a `dir://` target does, with the release's assets as
its files: the release is created when the tag has none, a file is uploaded unless an asset of that name
already holds the same bytes (a different digest fails, naming both, and nothing is overwritten), and the
records asset `<digest>.intoto.jsonl` is merged as a directory's is. An asset is uploaded as
`<name>.partial-<token>`, checked and renamed (`github.store_asset`), so an interrupted upload never
leaves half of a file under its real name; the records asset goes last, after its artifact is in place, and
a leftover `.partial-` asset from an earlier run is deleted first.
"""

import hashlib
import os
import secrets
import shutil
import tempfile
import urllib.error
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Literal, TextIO

from input_lock.identity import HEX64

from . import commands, fileartifacts, github, oci, ocilayout, published, registry


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


def artifacts_in(out_dir: Path) -> list[fileartifacts.FileArtifact]:
    """Every file artifact in a build's output directory: files named as artifacts whose digest matches
    the one in their name (an Incus image's two files by their fingerprint) and that have a records file
    beside them."""
    found, rejected = fileartifacts.file_artifacts(out_dir)
    if rejected:
        raise commands.Failed(f"{out_dir / rejected[0].name}: {rejected[0].reason}")
    for one in found:
        if not (out_dir / published.records_name_for(one.digest)).is_file():
            raise commands.Failed(
                f"{out_dir / one.name}: no records file {published.records_name_for(one.digest)} beside it"
            )
    return found


def publish_dir(out_dir: Path, artifacts: Sequence[fileartifacts.FileArtifact], target: Path, out: TextIO) -> None:
    """Copy `artifacts` of `out_dir` (each of its files) and merge their records into the directory `target`."""
    target.mkdir(parents=True, exist_ok=True)
    for artifact in artifacts:
        states: list[str] = []
        for path in artifact.files:
            destination = target / path.name
            if destination.is_file() and sha256_of(destination) == sha256_of(path):
                states.append("already there")
            else:
                copy_atomically(path, destination)
                states.append("copied")
        state = "already there" if set(states) == {"already there"} else "copied"
        records_name = published.records_name_for(artifact.digest)
        new = (out_dir / records_name).read_text(encoding="utf-8")
        held = target / records_name
        present = held.read_text(encoding="utf-8") if held.is_file() else ""
        merged = merged_lines(present, new)
        added = len(merged.splitlines()) - len([line for line in present.splitlines() if line.strip()])
        if merged != present:
            write_atomically(held, merged.encode("utf-8"))
        print(f"{target}: {artifact.name} {state}, {added} record lines added", file=out)


# ---- github-release:// -------------------------------------------------------------------------


def release_conflicts(
    client: github.Client,
    out_dir: Path,
    artifacts: Sequence[fileartifacts.FileArtifact],
    held: Mapping[str, github.Asset],
) -> None:
    """Fail when a release asset has the name of a file to publish but other bytes. Nothing has been
    written when this runs, so the release is left as it was."""
    for artifact in artifacts:
        for path in artifact.files:
            asset = held.get(path.name)
            if asset is None:
                continue
            theirs, ours = github.asset_sha256(client, asset), sha256_of(path)
            if theirs != ours:
                raise commands.Failed(
                    f"{client.name}: the asset {path.name} holds sha256 {theirs}, but {out_dir / path.name} "
                    f"is sha256 {ours}; nothing was overwritten"
                )


def publish_release(
    out_dir: Path, artifacts: Sequence[fileartifacts.FileArtifact], target: published.ReleaseTarget, out: TextIO
) -> None:
    """Upload `artifacts` of `out_dir` (each of its files) to the release `target`, create the release
    when the tag has none, and merge each artifact's records into its records asset.

    Assets are never overwritten: a file whose name is already an asset is skipped when the digest
    matches, and a different one fails before anything is written. Unfinished uploads of an earlier run
    are deleted before the new ones start. The records asset is read, merged
    with `merged_lines` and, when that changed it, deleted and uploaded again (an asset cannot be
    changed in place), so a reader can find it missing for a moment, and two publishers at the same
    moment can lose a line; publishing again restores it."""
    try:
        client = github.connect(target)
        release = github.release_by_tag(client)
        held = {one["name"]: one for one in github.list_assets(client, release)} if release else {}
        release_conflicts(client, out_dir, artifacts, held)
        if release is None:
            release = github.create_release(client)
            print(f"{client.name}: release created", file=out)
        remove_partials(client, held, out)
        for artifact in artifacts:
            states: list[str] = []
            for path in artifact.files:
                if path.name in held:
                    states.append("already there")
                else:
                    held[path.name] = github.store_asset(client, release, path.name, path, secrets.token_hex(8))
                    states.append("uploaded")
            state = "already there" if set(states) == {"already there"} else "uploaded"
            added = merge_records(client, release, held, artifact.digest, out_dir)
            print(f"{client.name}: {artifact.name} {state}, {added} record lines added", file=out)
    except github.AlreadyExistsError as error:
        raise commands.Failed(f"{error}; nothing was overwritten") from None
    except github.GitHubError as error:
        raise commands.Failed(str(error)) from None
    except OSError as error:
        raise commands.Failed(f"{target}: {describe(error)}") from None


def remove_partials(client: github.Client, held: dict[str, github.Asset], out: TextIO) -> None:
    """Delete the unfinished uploads (`<name>.partial-<token>`) an earlier publish left on the release.
    Publishers of one release must not run at the same moment, which the records merge already asks."""
    for name in sorted(held):
        if published.partial_of(name) is not None:
            github.delete_asset(client, held.pop(name))
            print(f"{client.name}: {name} is an unfinished upload of an earlier run, deleted", file=out)


def merge_records(
    client: github.Client, release: github.Release, held: dict[str, github.Asset], digest: str, out_dir: Path
) -> int:
    """Merge the records file of `out_dir` for `digest` into the release's records asset; the number of
    lines added. `held` follows the release's assets."""
    name = published.records_name_for(digest)
    new = (out_dir / name).read_text(encoding="utf-8")
    present = ""
    if name in held:
        try:
            present = github.read_asset(client, held[name]).decode("utf-8")
        except UnicodeDecodeError:
            raise commands.Failed(f"{client.name}: the records asset {name} is not UTF-8") from None
    merged = merged_lines(present, new)
    if merged == present:
        return 0
    if name in held:
        github.delete_asset(client, held.pop(name))
    with tempfile.TemporaryDirectory(prefix="debian-image-factory-publish-") as scratch:
        source = Path(scratch) / name
        source.write_bytes(merged.encode("utf-8"))
        held[name] = github.store_asset(client, release, name, source, secrets.token_hex(8))
    return len(merged.splitlines()) - len([line for line in present.splitlines() if line.strip()])


# ---- oci:// ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PushReport:
    """What `push_layout` did: the image's manifest digest (hex), whether anything was pushed for the
    image itself (blobs, manifest or a tag) or it was all there, how many blobs went up, the records
    attached now and the ones already attached, and how the registry lists referrers."""

    digest: str
    state: Literal["pushed", "already there"]
    blobs_pushed: int
    records_added: int
    records_present: int
    via: Literal["api", "tag"]


def envelope_predicate(envelope: bytes) -> str:
    """The predicate type of the in-toto statement in a DSSE envelope (the referrer's annotation)."""
    try:
        return published.parse_envelope(envelope.decode("utf-8")).predicate_type
    except (UnicodeDecodeError, published.RecordsError) as error:
        raise oci.OciError(f"a record is not a DSSE envelope of an in-toto statement: {error}") from None


def ensure_blob(client: registry.Client, digest: str, size: int, source: bytes | Path, known: set[str]) -> int:
    """Upload a blob unless the registry has it (or this run just put it); 1 when it was uploaded."""
    if digest in known or registry.blob_exists(client, digest):
        known.add(digest)
        return 0
    registry.put_blob(client, digest, size, source)
    known.add(digest)
    return 1


def attach_to_tag(client: registry.Client, subject: str, referrer: oci.Descriptor) -> None:
    """The tag schema (DESIGN 8.2): add `referrer` to the index tagged `sha256-<subject>`. One
    read-modify-write, the tag read right before it is written; the caller attaches one record at a time."""
    present = registry.tag_index(client, subject)
    merged = oci.merged_referrers(present, referrer)
    if merged != present:
        registry.put_manifest(client, oci.referrers_tag(subject), merged, oci.INDEX)


def attach_time(start: datetime, position: int) -> str:
    """The oci.CREATED of the record attached `position`th (from 0) in a push that started at `start`:
    one microsecond apart, so records attached in one push read back in the order they were given."""
    return (start + timedelta(microseconds=position)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def push_layout(
    client: registry.Client,
    layout: ocilayout.Layout,
    tags: Sequence[str],
    envelopes: Sequence[bytes],
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> PushReport:
    """Push the image `layout` holds to the client's repository, tag it, and attach `envelopes` (DSSE
    envelopes, the exact bytes of each record) as referrers of its manifest.

    Blobs the registry has are skipped, and so is everything for an image whose manifest is already
    there. The manifest goes by digest first; each tag in `tags` is then pointed at it (moved when it
    named another manifest). A record whose envelope digest is already attached, listed by the referrers
    API or by the tag index, is skipped. A manifest PUT that answers `OCI-Subject` is indexed by the
    registry; otherwise the referrers tag is updated. Nothing here reads the image's annotations or
    records: the layout is any single-image OCI layout, a `docker save` of the builder image included."""
    digest = layout.descriptor.digest
    known: set[str] = set()
    pushed = 0
    present = registry.manifest_digest(client, f"sha256:{digest}") == digest
    changed = not present
    if not present:
        pushed += ensure_blob(
            client, layout.manifest.config.digest, layout.manifest.config.size, layout.config_bytes, known
        )
        for descriptor, path in zip(layout.manifest.layers, layout.layers, strict=True):
            pushed += ensure_blob(client, descriptor.digest, descriptor.size, path, known)
        registry.put_manifest(client, f"sha256:{digest}", layout.manifest_bytes, layout.descriptor.media_type)
    for tag in tags:
        if registry.manifest_digest(client, tag) != digest:
            registry.put_manifest(client, tag, layout.manifest_bytes, layout.descriptor.media_type)
            changed = True
    held = registry.referrers_of(client, digest)
    attached = {one.envelope.digest for one in held.attached}
    subject = layout.descriptor
    added = skipped = 0
    start = now()
    for envelope in envelopes:
        envelope_digest = oci.sha256_hex(envelope)
        if envelope_digest in attached:
            skipped += 1
            continue
        manifest_bytes, blob = oci.referrer_manifest(
            envelope, envelope_predicate(envelope), subject, attach_time(start, added)
        )
        pushed += ensure_blob(client, blob.digest, blob.size, envelope, known)
        pushed += ensure_blob(client, oci.EMPTY_DIGEST, len(oci.EMPTY_BLOB), oci.EMPTY_BLOB, known)
        sent = registry.put_manifest(client, f"sha256:{oci.sha256_hex(manifest_bytes)}", manifest_bytes, oci.MANIFEST)
        if sent.subject is None:
            attach_to_tag(client, digest, oci.referrer_descriptor(manifest_bytes))
        attached.add(envelope_digest)
        added += 1
    return PushReport(digest, "pushed" if changed else "already there", pushed, added, skipped, held.via)


def layouts_in(out_dir: Path) -> list[Path]:
    """Every OCI image layout in a build's output directory: the directories named as artifacts with
    the `.oci` extension."""
    found: list[Path] = []
    for path in sorted(out_dir.iterdir()):
        name = published.parse_artifact_name(path.name)
        if name is not None and name.ext == oci.LAYOUT_EXT and path.is_dir():
            found.append(path)
    return found


def checked_layout(out_dir: Path, path: Path) -> tuple[ocilayout.Layout, str, list[bytes]]:
    """A layout of `out_dir` ready to push: read and checked, with its identity (the manifest's
    annotation, which its provenance must name too) and its records, one per line, as exact bytes."""
    name = published.parse_artifact_name(path.name)
    assert name is not None  # layouts_in only returns named layouts
    try:
        layout = ocilayout.read_layout(path)
    except (oci.OciError, OSError) as error:
        raise commands.Failed(f"{path}: {error}") from None
    digest = layout.descriptor.digest
    if not digest.startswith(name.digest12):
        raise commands.Failed(f"{path}: its manifest digest {digest} does not match the digest in its name")
    identity = layout.manifest.annotations.get(oci.IDENTITY, "")
    if not HEX64.fullmatch(identity) or not identity.startswith(name.identity16):
        raise commands.Failed(f"{path}: its manifest has no identity annotation that matches the identity in its name")
    records = out_dir / published.records_name_for(digest)
    if not records.is_file():
        raise commands.Failed(f"{path}: no records file {records.name} beside it")
    data = records.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise commands.Failed(f"{records}: not UTF-8") from None
    checked = published.artifact_from_records(path.name, digest, name.image, identity, text)
    if isinstance(checked, published.Rejected):
        raise commands.Failed(f"{path}: {checked.reason}")
    lines = [line for line in data.split(b"\n") if line.strip()]
    for number, line in enumerate(lines, start=1):
        if all(subject.sha256 != digest for subject in published.parse_envelope(line.decode("utf-8")).subjects):
            raise commands.Failed(f"{records}: record {number} is not about this image (sha256:{digest})")
    return layout, identity, lines


def describe(error: OSError) -> str:
    if isinstance(error, urllib.error.URLError):
        return str(error.reason)
    return error.strerror or str(error)


def publish_oci(
    out_dir: Path,
    target: published.OciTarget,
    layouts: Sequence[Path],
    out: TextIO,
    connect: Callable[[published.OciTarget], registry.Client],
) -> None:
    """Push every layout of `out_dir` to the repository `target`, tagging each `identity-<identity>`."""
    client = connect(target)
    for path in layouts:
        layout, identity, lines = checked_layout(out_dir, path)
        try:
            report = push_layout(client, layout, [oci.identity_tag(identity)], lines)
        except oci.OciError as error:
            raise commands.Failed(f"{path}: {error}") from None
        except OSError as error:
            raise commands.Failed(f"{client.name}: {describe(error)}") from None
        print(f"{client.name}: {path.name} {report.state}, {report.records_added} records added", file=out)


def target_scheme(target: published.Target) -> str:
    return "dir://" if isinstance(target, published.DirTarget) else "github-release://"


IMAGE_PLACEHOLDER: Final = "{image}"
"""In the repository of an `oci://` target: replaced by the name of the image each layout is, so one
publish can send `debian` to one repository and `node-26` to another."""


@dataclass(frozen=True, slots=True)
class Destination:
    """One `--to` as given: `text` is what the user wrote, `target` what it parses to (a repository with
    `{image}` parses with the image name `image`, to check the template), `per_image` that it has the placeholder."""

    text: str
    target: published.Target
    per_image: bool


def destination_of(text: str) -> Destination:
    """`text` as a destination. Raises Usage for a target that does not parse, or that has `{image}` but is
    not an `oci://` target (a directory or a release holds each artifact under its own name already)."""
    per_image = IMAGE_PLACEHOLDER in text
    if per_image and not text.startswith("oci://"):
        raise commands.Usage(f"{text}: {IMAGE_PLACEHOLDER} belongs in the repository of an oci:// target")
    try:
        return Destination(text, published.parse_target(text.replace(IMAGE_PLACEHOLDER, "image")), per_image)
    except ValueError as error:
        raise commands.Usage(str(error)) from None


def image_of(name: str) -> str:
    parts = published.parse_artifact_name(name)
    assert parts is not None  # artifacts_in and layouts_in only return named artifacts
    return parts.image


def selected(
    images: Sequence[str], files: Sequence[fileartifacts.FileArtifact], layouts: Sequence[Path]
) -> tuple[list[fileartifacts.FileArtifact], list[Path]]:
    """The artifacts of the images `--image` names, or all of them when it names none. Raises Usage for a
    name that is not an image of this build."""
    if not images:
        return list(files), list(layouts)
    held = sorted({image_of(one.name) for one in files} | {image_of(one.name) for one in layouts})
    for name in images:
        if name not in held:
            raise commands.Usage(f"--image {name}: the build holds no such image (it holds {', '.join(held)})")
    wanted = set(images)
    return [one for one in files if image_of(one.name) in wanted], [
        one for one in layouts if image_of(one.name) in wanted
    ]


def oci_targets_for(destination: Destination, layouts: Sequence[Path]) -> list[tuple[published.OciTarget, list[Path]]]:
    """The repositories `layouts` go to for an `oci://` destination: the one, or with `{image}` one per image,
    each with its own layouts. Raises Usage when an image's name does not make a valid repository."""
    if not destination.per_image:
        assert isinstance(destination.target, published.OciTarget)
        return [(destination.target, list(layouts))]
    found: list[tuple[published.OciTarget, list[Path]]] = []
    for image in sorted({image_of(one.name) for one in layouts}):
        text = destination.text.replace(IMAGE_PLACEHOLDER, image)
        try:
            target = published.parse_target(text)
        except ValueError as error:
            raise commands.Usage(f"{destination.text}: the image {image} makes no repository ({error})") from None
        assert isinstance(target, published.OciTarget)
        found.append((target, [one for one in layouts if image_of(one.name) == image]))
    return found


def publish_command(
    out_dir: Path,
    targets: Sequence[str],
    sign: str,
    out: TextIO,
    connect: Callable[[published.OciTarget], registry.Client] = registry.connect,
    images: Sequence[str] = (),
) -> int:
    if sign != "none":
        raise commands.Usage("signing arrives in a later release; this release publishes unsigned records")
    if not targets:
        raise commands.Usage("publish needs at least one --to TARGET")
    destinations = [destination_of(target) for target in targets]
    if not out_dir.is_dir():
        raise commands.Failed(f"{out_dir}: no such directory (build writes it)")
    files, layouts = selected(images, artifacts_in(out_dir), layouts_in(out_dir))
    if not files and not layouts:
        raise commands.Failed(f"{out_dir}: no artifacts to publish")
    routes = [
        (one.target, oci_targets_for(one, layouts) if isinstance(one.target, published.OciTarget) else [])
        for one in destinations
    ]
    for one, _ in routes:  # every target is checked before anything is written
        if isinstance(one, published.DirTarget | published.ReleaseTarget) and not files:
            raise commands.Failed(
                f"{out_dir}: holds OCI images only ({', '.join(p.name for p in layouts)}); "
                f"they publish to oci:// targets, a {target_scheme(one)} target takes files"
            )
        if isinstance(one, published.OciTarget) and not layouts:
            raise commands.Failed(
                f"{out_dir}: holds files only ({', '.join(artifact.name for artifact in files)}); "
                "oci:// targets take OCI images, publish these to dir:// or github-release://"
            )
    for one, repositories in routes:
        if isinstance(one, published.DirTarget):
            for path in layouts:
                print(f"{one.path}: {path.name} not published here, OCI images publish to oci:// targets", file=out)
            publish_dir(out_dir, files, Path(one.path), out)
        elif isinstance(one, published.OciTarget):
            for artifact in files:
                print(
                    f"{one.registry}/{one.repository}: {artifact.name} not published here, "
                    "files publish to dir:// or github-release://",
                    file=out,
                )
            for repository, group in repositories:
                publish_oci(out_dir, repository, group, out, connect)
        else:
            for path in layouts:
                print(
                    f"github-release://{one.owner}/{one.repo}@{one.tag}: {path.name} not published here, "
                    "OCI images publish to oci:// targets",
                    file=out,
                )
            publish_release(out_dir, files, one, out)
    return 0
