"""The edge that asks a target what it holds for one identity (DESIGN 7.4): `dir://` and `oci://` targets."""

import hashlib
from pathlib import Path

from input_lock.identity import HEX64

from . import fileartifacts, oci, registry
from .published import (
    Artifact,
    DirTarget,
    Lookup,
    OciTarget,
    RecordsError,
    Rejected,
    ReleaseTarget,
    Target,
    artifact_from_records,
    parse_envelope,
    records_name_for,
)


def sha256_of(path: Path) -> str:
    """The sha256 of a file, read in full."""
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def lookup(target: Target, image: str, suite: str, arch: str, identity: str) -> Lookup:
    """The artifacts `target` holds for this image and identity that count, and the files that look
    like one but do not (with the reason). Raises NotImplementedError for a target kind not read yet."""
    if not HEX64.fullmatch(identity):
        raise ValueError(f"identity is not 64 lowercase hex characters: {identity!r}")
    match target:
        case DirTarget(path):
            return lookup_dir(Path(path), image, suite, arch, identity)
        case OciTarget():
            return lookup_oci(registry.connect(target), image, identity)
        case ReleaseTarget():
            pass
    raise NotImplementedError(
        "github-release targets arrive in a later release; this release reads dir:// and oci:// targets"
    )


def lookup_dir(directory: Path, image: str, suite: str, arch: str, identity: str) -> Lookup:
    """List `directory`, keep the artifacts named for this image, suite, architecture and identity, and
    verify each: its digest (a file's sha256, an Incus image's fingerprint) must match its name, its
    records file must exist and be well formed, and its provenance must name the image and the full
    identity. A missing directory holds nothing."""
    prefix = f"{image}-{suite}-{arch}-{identity[:16]}-"
    try:
        held, rejected = fileartifacts.file_artifacts(directory, prefix)
    except FileNotFoundError:
        return Lookup((), ())
    found: list[Artifact] = []
    for one in held:
        if (one.parts.image, one.parts.suite, one.parts.arch) != (image, suite, arch):
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
        checked = artifact_from_records(one.name, one.digest, image, identity, text)
        if isinstance(checked, Rejected):
            rejected.append(checked)
        else:
            found.append(checked)
    return Lookup(tuple(found), tuple(rejected))


def lookup_oci(client: registry.Client, image: str, identity: str) -> Lookup:
    """What the registry holds for `identity`: the manifest tagged `identity-<identity>`, accepted when
    it is an OCI image manifest whose identity annotation is `identity`, with the records attached to it
    (the referrers API, or the tag schema when the registry has none), each envelope checked against its
    digest, read as the lines of a records file. A registry without the tag holds nothing. A referrer
    that cannot be read, or an image that does not count, goes to `rejected` with the reason; the
    artifact's name is `oci://<registry>/<repository>@sha256:<manifest digest>`."""
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
    checked = artifact_from_records(name, fetched.digest, image, identity, "".join(f"{line}\n" for line in lines))
    if isinstance(checked, Rejected):
        return Lookup((), (*rejected, checked))
    return Lookup((checked,), tuple(rejected))
