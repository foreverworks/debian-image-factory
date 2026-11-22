"""The edge that asks a target what it holds for one identity (DESIGN 7.4): `dir://`, `oci://` and
`github-release://` targets."""

import hashlib
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from input_lock.identity import HEX64

from . import fileartifacts, github, incus, oci, registry
from .published import (
    Artifact,
    ArtifactName,
    DirTarget,
    Lookup,
    OciTarget,
    RecordsError,
    Rejected,
    ReleaseTarget,
    Target,
    artifact_from_records,
    described_artifact,
    parse_artifact_name,
    parse_envelope,
    parse_envelopes,
    partial_of,
    records_digest,
    records_name_for,
    statements_cover,
)


def sha256_of(path: Path) -> str:
    """The sha256 of a file, read in full."""
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def lookup(target: Target, image: str, suite: str, arch: str, identity: str) -> Lookup:
    """The artifacts `target` holds for this image and identity that count, and the files that look
    like one but do not (with the reason)."""
    if not HEX64.fullmatch(identity):
        raise ValueError(f"identity is not 64 lowercase hex characters: {identity!r}")
    match target:
        case DirTarget(path):
            return lookup_dir(Path(path), image, suite, arch, identity)
        case OciTarget():
            return lookup_oci(registry.connect(target), image, identity)
        case ReleaseTarget():
            return lookup_release(github.connect(target), image, suite, arch, identity)


def list_artifacts(target: Target, connect: Callable[[OciTarget], registry.Client] = registry.connect) -> Lookup:
    """Every artifact `target` holds that counts, whatever its image and identity, and the files that look
    like one but do not (with the reason): what `prune` reads, each checked as `lookup` checks one."""
    match target:
        case DirTarget(path):
            return list_dir(Path(path))
        case OciTarget():
            return list_oci(connect(target))
        case ReleaseTarget():
            return list_release(github.connect(target))


type Judge = Callable[[str, str, str], Artifact | Rejected]
"""Judges an artifact's records: (artifact name, real digest, records text) to the artifact or why not."""


def lookup_dir(directory: Path, image: str, suite: str, arch: str, identity: str) -> Lookup:
    """List `directory`, keep the artifacts named for this image, suite, architecture and identity, and
    verify each: its digest (a file's sha256, an Incus image's fingerprint) must match its name, its
    records file must exist and be well formed, and its provenance must name the image and the full
    identity. A missing directory holds nothing."""
    prefix = f"{image}-{suite}-{arch}-{identity[:16]}-"

    def judge(name: str, digest: str, text: str) -> Artifact | Rejected:
        return artifact_from_records(name, digest, image, identity, text)

    return read_dir(
        directory, prefix, judge, lambda parts: (parts.image, parts.suite, parts.arch) == (image, suite, arch)
    )


def list_dir(directory: Path) -> Lookup:
    """Every artifact `directory` holds that counts, whatever its image and identity (what `prune` reads):
    each is verified as `lookup_dir` does, with the image and the identity taken from its provenance, which
    the name's image and identity prefix must agree with. A missing directory holds nothing."""

    def judge(name: str, digest: str, text: str) -> Artifact | Rejected:
        parts = parse_artifact_name(name)
        assert parts is not None  # only named files reach a judge
        found = described_artifact(name, digest, text, parts.identity16)
        if isinstance(found, Artifact) and found.image != parts.image:
            return Rejected(name, f"provenance names image {found.image!r}, not {parts.image!r}")
        return found

    return read_dir(directory, "", judge, lambda parts: True)


def read_dir(directory: Path, prefix: str, judge: Judge, wanted: Callable[[ArtifactName], bool]) -> Lookup:
    try:
        held, rejected = fileartifacts.file_artifacts(directory, prefix)
    except FileNotFoundError:
        return Lookup((), ())
    found: list[Artifact] = []
    for one in held:
        if not wanted(one.parts):
            continue
        records = directory / records_name_for(one.digest)
        if not records.is_file():
            rejected.append(Rejected(one.name, f"no records file {records.name} beside it"))
            continue
        try:
            text = records.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            rejected.append(Rejected(one.name, f"records file {records.name} is not UTF-8"))
            continue
        checked = judge(one.name, one.digest, text)
        if isinstance(checked, Rejected):
            rejected.append(checked)
        else:
            found.append(checked)
    return Lookup(tuple(found), tuple(rejected))


def list_oci(client: registry.Client) -> Lookup:
    """Every image the repository holds under an `identity-<identity>` tag that counts (what `prune` reads),
    each read as `lookup_oci` reads one, with the image taken from its provenance. Images no such tag
    names (older builds a moved tag left behind, the consumer's own tags) are not listed: a registry's
    own garbage collection keeps those."""
    found: list[Artifact] = []
    rejected: list[Rejected] = []
    for tag in registry.list_tags(client):
        identity = oci.identity_of_tag(tag)
        if identity is None:
            continue
        one = lookup_oci(client, None, identity)
        found.extend(one.artifacts)
        rejected.extend(one.rejected)
    return Lookup(tuple(found), tuple(rejected))


def lookup_oci(client: registry.Client, image: str | None, identity: str) -> Lookup:
    """What the registry holds for `identity`: the manifest tagged `identity-<identity>`, accepted when
    it is an OCI image manifest whose identity annotation is `identity`, with the records attached to it
    (the referrers API, or the tag schema when the registry has none), each envelope checked against its
    digest, read as the lines of a records file. A registry without the tag holds nothing. A referrer
    that cannot be read, or an image that does not count, goes to `rejected` with the reason; the
    artifact's name is `oci://<registry>/<repository>@sha256:<manifest digest>`. With no `image` (`list_oci`)
    the provenance names it."""
    tag = oci.identity_tag(identity)
    fetched = registry.get_manifest(client, tag)
    if fetched is None:
        return Lookup((), ())
    name = f"{client.name}@sha256:{fetched.digest}"
    try:
        manifest = oci.parse_manifest(fetched.data)
    except oci.OciError as error:
        return Lookup((), (Rejected(name, f"its manifest is not an image: {error}"),))
    if manifest.annotations.get(oci.IDENTITY) != identity:
        found = manifest.annotations.get(oci.IDENTITY)
        return Lookup((), (Rejected(name, f"its identity annotation is {found!r}, not {identity}"),))
    held = registry.referrers_of(client, fetched.digest)
    envelopes, unread = registry.fetch_envelopes(client, held.attached)
    rejected = [Rejected(name, problem) for problem in (*held.problems, *unread)]
    lines: list[str] = []
    for envelope in envelopes:
        try:
            text = envelope.decode("utf-8").strip()
            if "\n" in text:
                raise RecordsError("it spans several lines")
            parse_envelope(text)
        except (UnicodeDecodeError, RecordsError) as error:
            rejected.append(Rejected(name, f"a record is not a one-line DSSE envelope: {error}"))
            continue
        lines.append(text)
    text = "".join(f"{line}\n" for line in lines)
    if image is None:
        checked = described_artifact(name, fetched.digest, text, identity)
    else:
        checked = artifact_from_records(name, fetched.digest, image, identity, text)
    if isinstance(checked, Rejected):
        return Lookup((), (*rejected, checked))
    return Lookup((checked,), tuple(rejected))


def lookup_release(client: github.Client, image: str, suite: str, arch: str, identity: str) -> Lookup:
    """What the release holds for this image and identity, read as `lookup_dir` reads a directory with the
    release's assets as its files. A tag without a release holds nothing. Each asset named
    `<image>-<suite>-<arch>-<identity16>-` is verified: its sha256 (GitHub's `digest` for it when the
    listing has one, else the hash of a download) must match its name, its records asset
    `<sha256>.intoto.jsonl` must exist and be well formed, and its provenance must name the image and
    the full identity. An artifact's name is its asset's name.

    An Incus image is the metadata asset and its `.rootfs.squashfs` companion, which must be listed too.
    Its fingerprint is not recomputed here (that would download both files): it is the digest of the
    records asset whose name starts with the image's 12 hex and whose subjects carry the sha256 of both
    files, as the build wrote them. `verify` and Incus's own import check the fingerprint itself."""

    def judge(name: str, digest: str, text: str) -> Artifact | Rejected:
        return artifact_from_records(name, digest, image, identity, text)

    return read_release(
        client,
        f"{image}-{suite}-{arch}-{identity[:16]}-",
        judge,
        lambda parts: (parts.image, parts.suite, parts.arch) == (image, suite, arch),
    )


def list_release(client: github.Client) -> Lookup:
    """Every artifact the release holds that counts, whatever its image and identity (what `prune` reads),
    verified as `lookup_release` does, with the image and identity taken from the provenance, which the
    asset's name must agree with."""

    def judge(name: str, digest: str, text: str) -> Artifact | Rejected:
        parts = parse_artifact_name(name)
        assert parts is not None  # only named assets reach a judge
        found = described_artifact(name, digest, text, parts.identity16)
        if isinstance(found, Artifact) and found.image != parts.image:
            return Rejected(name, f"provenance names image {found.image!r}, not {parts.image!r}")
        return found

    return read_release(client, "", judge, lambda parts: True)


def read_release(client: github.Client, prefix: str, judge: Judge, wanted: Callable[[ArtifactName], bool]) -> Lookup:
    """The release's assets whose name starts with `prefix` and parses as an artifact's that `wanted` accepts,
    each checked against its records and `judge`. An unfinished upload (`<name>.partial-<token>`, see
    `publish`) is listed as rejected, never read."""
    release = github.release_by_tag(client)
    if release is None:
        return Lookup((), ())
    assets = github.list_assets(client, release)
    by_name = {one["name"]: one for one in assets}
    found: list[Artifact] = []
    rejected: list[Rejected] = []
    for asset in github.named_like(assets, prefix):
        parts = parse_artifact_name(asset["name"])
        if parts is None:
            if partial_of(asset["name"]) is not None:
                rejected.append(Rejected(asset["name"], "an unfinished upload, left by a publish that did not end"))
            continue
        if fileartifacts.is_companion(parts) or not wanted(parts):
            continue
        checked = release_artifact(client, asset, by_name, assets, parts.digest12, parts.ext, judge)
        if isinstance(checked, Rejected):
            rejected.append(checked)
        else:
            found.append(checked)
    return Lookup(tuple(found), tuple(rejected))


def release_artifact(
    client: github.Client,
    asset: github.Asset,
    by_name: Mapping[str, github.Asset],
    assets: Sequence[github.Asset],
    digest12: str,
    ext: str,
    judge: Judge,
) -> Artifact | Rejected:
    """One asset checked against its records, or why it does not count."""
    name = asset["name"]
    if ext == incus.METADATA_EXT:
        rootfs_name = incus.rootfs_of(name)
        rootfs = by_name.get(rootfs_name) if rootfs_name is not None else None
        if rootfs is None:
            return Rejected(name, f"no rootfs {rootfs_name} asset beside it")
        sums = [github.asset_sha256(client, asset), github.asset_sha256(client, rootfs)]
        return incus_artifact(client, name, sums, assets, digest12, judge)
    digest = github.asset_sha256(client, asset)
    if not digest.startswith(digest12):
        return Rejected(name, f"its sha256 {digest} does not match the digest in its name")
    records = by_name.get(records_name_for(digest))
    if records is None:
        return Rejected(name, f"no records asset {records_name_for(digest)} beside it")
    text = read_records(client, records)
    if isinstance(text, Rejected):
        return Rejected(name, text.reason)
    return judge(name, digest, text)


def read_records(client: github.Client, asset: github.Asset) -> str | Rejected:
    """A records asset as text, or why it cannot be."""
    try:
        return github.read_asset(client, asset).decode("utf-8")
    except UnicodeDecodeError:
        return Rejected(asset["name"], f"records asset {asset['name']} is not UTF-8")


def incus_artifact(
    client: github.Client,
    name: str,
    sums: Sequence[str],
    assets: Sequence[github.Asset],
    digest12: str,
    judge: Judge,
) -> Artifact | Rejected:
    """An Incus image whose two files have the sha256 `sums`: the records asset that starts with its
    12 hex and covers both names the fingerprint."""
    problems: list[str] = []
    for records in assets:
        fingerprint = records_digest(records["name"])
        if fingerprint is None or not fingerprint.startswith(digest12):
            continue
        text = read_records(client, records)
        if isinstance(text, Rejected):
            problems.append(text.reason)
            continue
        try:
            statements = parse_envelopes(text)
        except RecordsError as error:
            problems.append(f"records asset {records['name']} is malformed, {error}")
            continue
        if statements_cover(statements, sums):
            return judge(name, fingerprint, text)
    reason = f"no records asset starting {digest12} lists the sha256 of both of its files"
    return Rejected(name, "; ".join([reason, *problems]))
