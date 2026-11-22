"""`verify`: do an artifact's records match its bits, and are its checks complete (DESIGN 9.1).

The pure half, `inspect`, takes the artifact's digest, what is known about its name and identity, and
the text of its records, and names every problem it finds. The edges read an artifact (a registry, an
OCI layout directory or a file) and its records and hand them to it.

What passes:

- the bits match their digest: for an image the manifest's digest (every blob read from a registry is
  checked as it is read; a layout read from disk is checked in full, layers too), for a file its sha256;
- every record is a DSSE envelope of an in-toto Statement v1 that names the artifact's digest as a subject;
- there is exactly one provenance, with a build type of this factory, naming the image and an identity
  equal to the one the artifact carries (the manifest's annotation, or the name of the file);
- its resolved dependencies name `lock.json` by sha256, equal to the sha256 of `--lock` when given;
- there is exactly one SBOM, whose document namespace ends in the digest and whose `SPDXRef-Image`
  has the version `sha256:<digest>`;
- with `--require-checks`, every check the definition requires for the image has a passing last result,
  by the rules of `published.decide`; without it the results present are listed.
"""

import contextlib
import hashlib
import re
import urllib.error
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TextIO

import input_lock
from input_lock.identity import HEX64
from input_lock.records import PROVENANCE_PREDICATE, SPDX_PREDICATE, TestOutcome

from . import commands, definition, fileartifacts, incus, oci, ocilayout, published, records, registry

BUILD_TYPE: Final = re.compile(re.escape(records.REPOSITORY) + r"/blob/v[0-9][0-9A-Za-z.+-]*/docs/build-type-v1\.md")
"""The `buildType` of any release of this factory: the document names its release, so a verifier of one
release still reads what another built."""


@dataclass(frozen=True, slots=True)
class Subject:
    """What is verified: its label, the digest its bits have (hex), the identity it carries (an OCI
    manifest's annotation; None for a file, whose name carries a prefix), the parts of its file name
    when it has one, the lines of its records, and the problems met while reading it."""

    label: str
    digest: str
    identity: str | None
    name: published.ArtifactName | None
    lines: tuple[str, ...]
    problems: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Findings:
    """The result of `inspect`: every problem, and what a summary says."""

    problems: tuple[str, ...]
    image: str | None
    identity: str | None
    lock_sha256: str | None
    has_lock_entries: bool
    results: Mapping[str, TestOutcome]
    counts: Mapping[str, int]


def object_of(value: object) -> dict[str, object]:
    return {str(key): item for key, item in value.items()} if isinstance(value, dict) else {}


def list_of(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def lock_digests(text: str) -> frozenset[str]:
    """The sha256 digests a `--lock` file may be named by in a provenance: of its bytes, and of its
    canonical form (what input-lock's `lock_digest` writes), which are one for a formatted lock."""
    found = {hashlib.sha256(text.encode("utf-8")).hexdigest()}
    with contextlib.suppress(input_lock.LockError):
        found.add(input_lock.lock_digest(input_lock.parse(text)))
    return frozenset(found)


def provenance_problems(
    raw: Mapping[str, object], claim: published.BuildClaim, subject: Subject, lock: frozenset[str] | None
) -> tuple[list[str], str | None, bool]:
    """What is wrong with the provenance statement `raw`; the sha256 it gives for `lock.json`; whether
    it lists locked inputs (dependencies with both a name and a uri)."""
    problems: list[str] = []
    predicate = object_of(raw.get("predicate"))
    build = object_of(predicate.get("buildDefinition"))
    build_type = build.get("buildType")
    if not isinstance(build_type, str) or not BUILD_TYPE.fullmatch(build_type):
        problems.append(f"provenance: buildType {build_type!r} is not a build type of this factory")
    if subject.identity is not None and claim.identity != subject.identity:
        problems.append(f"provenance names identity {claim.identity}, but the artifact carries {subject.identity}")
    if subject.name is not None:
        if subject.name.image != claim.image:
            problems.append(
                f"provenance names image {claim.image!r}, but the artifact's name says {subject.name.image!r}"
            )
        if not claim.identity.startswith(subject.name.identity16):
            problems.append(f"provenance names identity {claim.identity}, which the artifact's name does not carry")
    dependencies = [object_of(one) for one in list_of(build.get("resolvedDependencies"))]
    locks = [one for one in dependencies if one.get("name") == "lock.json"]
    lock_sha: str | None = None
    if len(locks) != 1:
        problems.append(f"provenance: resolvedDependencies names lock.json {len(locks)} times, expected once")
    else:
        found = object_of(locks[0].get("digest")).get("sha256")
        if not isinstance(found, str) or not HEX64.fullmatch(found):
            problems.append("provenance: lock.json has no sha256 in resolvedDependencies")
        else:
            lock_sha = found
            if lock is not None and found not in lock:
                problems.append(f"provenance: lock.json is sha256:{found}, which is not the sha256 of the --lock file")
    has_entries = any(
        isinstance(one.get("name"), str) and isinstance(one.get("uri"), str) and one.get("name") != "lock.json"
        for one in dependencies
    )
    return problems, lock_sha, has_entries


def sbom_problems(raw: Mapping[str, object], subject: Subject, image: str | None) -> list[str]:
    problems: list[str] = []
    document = object_of(raw.get("predicate"))
    namespace = document.get("documentNamespace")
    if not isinstance(namespace, str) or not namespace.endswith(f"/sha256-{subject.digest}"):
        problems.append(f"SBOM: documentNamespace does not end in /sha256-{subject.digest}")
    roots = [
        object_of(one) for one in list_of(document.get("packages")) if object_of(one).get("SPDXID") == "SPDXRef-Image"
    ]
    if len(roots) != 1:
        problems.append(f"SBOM: {len(roots)} packages are SPDXRef-Image, expected one")
    else:
        if roots[0].get("versionInfo") != f"sha256:{subject.digest}":
            problems.append(
                f"SBOM: SPDXRef-Image versionInfo is {roots[0].get('versionInfo')!r}, not sha256:{subject.digest}"
            )
        if image is not None and roots[0].get("name") != image:
            problems.append(f"SBOM: SPDXRef-Image is named {roots[0].get('name')!r}, the provenance names {image!r}")
    return problems


def inspect(subject: Subject, lock: frozenset[str] | None) -> Findings:
    """Every problem with the records of `subject` (those found reading it are `subject.problems`), and
    what the records say about it."""
    problems: list[str] = []
    parsed: list[tuple[int, published.Record, dict[str, object]]] = []
    for number, line in enumerate(subject.lines, start=1):
        try:
            record = published.parse_envelope(line)
            statement = records.decode_statements(line)[0]
        except (published.RecordsError, records.RecordsError) as error:
            problems.append(f"record {number}: {error}")
            continue
        if all(one.sha256 != subject.digest for one in record.subjects):
            problems.append(
                f"record {number} ({record.predicate_type}): sha256:{subject.digest} is not one of its subjects"
            )
            continue
        parsed.append((number, record, statement))
    provenances = [(record, raw) for _, record, raw in parsed if record.predicate_type == PROVENANCE_PREDICATE]
    sboms = [raw for _, record, raw in parsed if record.predicate_type == SPDX_PREDICATE]
    image: str | None = None
    identity: str | None = None
    lock_sha: str | None = None
    has_entries = False
    if len(provenances) != 1:
        problems.append(f"{len(provenances)} provenance records, expected exactly one")
    for record, raw in provenances[:1]:
        assert record.build is not None  # parse_envelope sets `build` for every provenance
        image, identity = record.build.image, record.build.identity
        found, lock_sha, has_entries = provenance_problems(raw, record.build, subject, lock)
        problems.extend(found)
    if len(sboms) != 1:
        problems.append(f"{len(sboms)} SBOM records, expected exactly one")
    for raw in sboms[:1]:
        problems.extend(sbom_problems(raw, subject, image))
    results = published.last_results([record for _, record, _ in parsed])  # the latest run, then file order
    counts = {
        "records": len(subject.lines),
        "provenance": len(provenances),
        "SBOM": len(sboms),
        "test results": sum(1 for _, record, _ in parsed if record.check is not None),
    }
    return Findings(tuple(problems), image, identity, lock_sha, has_entries, results, counts)


def required_problems(subject: Subject, found: Findings, required: Sequence[str]) -> list[str]:
    """The required checks without a passing last result (`published.decide`'s rules)."""
    if found.image is None or found.identity is None:
        return []  # no provenance: already a problem
    artifact = published.Artifact(found.image, found.identity, subject.digest, subject.label, None, found.results)
    if published.decide([artifact], required).state == "reuse":
        return []
    return [
        f"required check {check}: "
        + ("no result" if check not in found.results else f"its last result is {found.results[check]}")
        for check in sorted(set(required))
        if found.results.get(check) not in published.PASSING
    ]


# ---- the edges --------------------------------------------------------------------------------


def split_lines(data: bytes, where: str) -> tuple[list[str], list[str]]:
    """The non-blank lines of a records file, and a problem when it is not UTF-8."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [], [f"{where}: records are not UTF-8"]
    return [line for line in text.splitlines() if line.strip()], []


def remote_subject(reference: registry.Reference, connect: Callable[[published.OciTarget], registry.Client]) -> Subject:
    client = connect(reference.target)
    problems: list[str] = []
    label = f"{client.name}@sha256:{reference.digest}" if reference.digest else f"{client.name}:{reference.tag}"
    try:
        fetched = registry.get_manifest(
            client, f"sha256:{reference.digest}" if reference.digest else str(reference.tag)
        )
        if fetched is None:
            raise commands.Failed(f"{label}: no such manifest")
        manifest = oci.parse_manifest(fetched.data)
        for blob in (manifest.config, *manifest.layers):
            if not registry.blob_exists(client, blob.digest):
                problems.append(f"{label}: blob sha256:{blob.digest} is not in the registry")
        registry.fetch_blob(client, manifest.config, registry.MANIFEST_LIMIT)
        identity = manifest.annotations.get(oci.IDENTITY)
        if identity is None:
            problems.append(f"{label}: its manifest has no identity annotation")
        elif (
            reference.tag is not None
            and reference.tag.startswith("identity-")
            and reference.tag != oci.identity_tag(identity)
        ):
            problems.append(f"{label}: the tag names another identity than the manifest's {identity}")
        held = registry.referrers_of(client, fetched.digest)
        envelopes, unread = registry.fetch_envelopes(client, held.attached)
    except oci.OciError as error:
        raise commands.Failed(f"{label}: {error}") from None
    except registry.RegistryError as error:
        raise commands.Failed(str(error)) from None  # it names the registry already
    except OSError as error:
        raise commands.Failed(f"{label}: {describe(error)}") from None
    lines: list[str] = []
    for envelope in envelopes:
        try:
            lines.append(envelope.decode("utf-8").strip())
        except UnicodeDecodeError:
            problems.append(f"{label}: a record is not UTF-8")
    problems.extend((*held.problems, *unread))
    return Subject(
        f"{client.name}@sha256:{fetched.digest}", fetched.digest, identity, None, tuple(lines), tuple(problems)
    )


def describe(error: OSError) -> str:
    if isinstance(error, urllib.error.URLError):
        return str(error.reason)
    return error.strerror or str(error)


def local_records(directory: Path, digest: str, label: str) -> tuple[list[str], list[str]]:
    path = directory / published.records_name_for(digest)
    try:
        return split_lines(path.read_bytes(), str(path))
    except OSError:
        return [], [f"{label}: no records file {path.name} beside it"]


def layout_subject(path: Path) -> Subject:
    try:
        layout = ocilayout.read_layout(path)
    except oci.OciError as error:
        raise commands.Failed(str(error)) from None  # it names the layout already
    except OSError as error:
        raise commands.Failed(f"{path}: {describe(error)}") from None
    digest = layout.descriptor.digest
    name = published.parse_artifact_name(path.name)
    problems: list[str] = []
    if name is not None and not digest.startswith(name.digest12):
        problems.append(f"{path}: its manifest digest is sha256:{digest}, which its name does not carry")
    identity = layout.manifest.annotations.get(oci.IDENTITY)
    if identity is None:
        problems.append(f"{path}: its manifest has no identity annotation")
    lines, bad = local_records(path.parent, digest, str(path))
    return Subject(str(path), digest, identity, name, tuple(lines), tuple((*problems, *bad)))


def file_subject(path: Path) -> Subject:
    """A file artifact: its sha256, or for an Incus image (its metadata tarball, or its rootfs) the
    fingerprint of the two files."""
    name = published.parse_artifact_name(path.name)
    if name is not None and name.ext == incus.ROOTFS_EXT:
        path = path.with_name(path.name.removesuffix(incus.ROOTFS_EXT) + incus.METADATA_EXT)
        name = published.parse_artifact_name(path.name)
    rootfs = incus.rootfs_of(path.name)
    what = "sha256" if rootfs is None else "Incus fingerprint"
    try:
        if rootfs is None:
            digest = fileartifacts.sha256_of(path)
        else:
            digest = fileartifacts.fingerprint_of(path, path.parent / rootfs)
    except OSError as error:
        raise commands.Failed(f"{path}: {describe(error)}") from None
    problems: list[str] = []
    if name is not None and not digest.startswith(name.digest12):
        problems.append(f"{path}: its {what} is {digest}, which its name does not carry")
    lines, bad = local_records(path.parent, digest, str(path))
    return Subject(str(path), digest, None, name, tuple(lines), tuple((*problems, *bad)))


def subject_of(ref: str, connect: Callable[[published.OciTarget], registry.Client]) -> Subject:
    if ref.startswith("oci://"):
        reference = registry.parse_reference(ref)
        if reference is None:
            raise commands.Usage(
                f"{ref!r} is not an image reference: oci://<registry>/<repository>@sha256:<hex> or oci://<registry>/<repository>:<tag>"
            )
        return remote_subject(reference, connect)
    path = Path(ref)
    if path.is_dir():
        return layout_subject(path)
    if path.is_file():
        return file_subject(path)
    raise commands.Failed(f"{ref}: not an oci:// reference, an OCI layout directory or a file")


def summary(subject: Subject, found: Findings, required: Sequence[str] | None) -> list[str]:
    lines = [f"{subject.label}: verified"]
    counts = ", ".join(f"{number} {what}" for what, number in found.counts.items() if what != "records")
    lines.append(f"  {found.image} identity {found.identity}: {found.counts['records']} records ({counts})")
    if found.lock_sha256 is not None:
        lines.append(f"  lock.json sha256:{found.lock_sha256}")
    results = ", ".join(f"{check} {outcome}" for check, outcome in sorted(found.results.items())) or "none"
    lines.append(
        f"  required checks all passing: {', '.join(sorted(set(required)))}"
        if required is not None
        else f"  checks: {results}"
    )
    return lines


def verify_command(
    ref: str,
    require_checks: bool,
    lock_path: Path | None,
    definition_path: Path,
    out: TextIO,
    connect: Callable[[published.OciTarget], registry.Client] = registry.connect,
) -> int:
    """Check `ref` and print a short summary (0), or raise Failed naming every problem (exit 1)."""
    expected = lock_digests(commands.read_text(lock_path)) if lock_path is not None else None
    parsed = commands.read_text(definition_path) if require_checks else None
    subject = subject_of(ref, connect)
    found = inspect(subject, expected)
    problems = [f"{subject.label}: {problem}" for problem in found.problems]
    required: tuple[str, ...] | None = None
    if parsed is not None and found.image is not None:
        try:
            loaded = definition.parse(parsed)
        except definition.DefinitionError as error:
            raise commands.Failed("\n".join(f"{definition_path}: {line}" for line in str(error).splitlines())) from None
        if found.image not in loaded.images:
            problems.append(f"{subject.label}: the definition {definition_path} has no image {found.image!r}")
        else:
            required = definition.required_checks(loaded, found.image, found.has_lock_entries)
            problems.extend(f"{subject.label}: {problem}" for problem in required_problems(subject, found, required))
    problems = [*subject.problems, *problems]
    if problems:
        raise commands.Failed("\n".join(problems))
    print("\n".join(summary(subject, found, required)), file=out)
    return 0
