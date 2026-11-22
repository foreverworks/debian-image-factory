"""Records about artifacts (DESIGN 8.2): in-toto statements in DSSE envelopes, one per line of
`<digest>.intoto.jsonl`.

input-lock assembles the standard shapes (`input_lock.records`); this module holds what the factory
adds on top: the build type, the normalised definition source, the builder identity, the SPDX
identifier collision rule, and the SBOM and provenance of a build. Every function is pure: the caller
supplies times, identities and digests, and nothing here reads the machine it runs on.
"""

import base64
import binascii
import hashlib
import json
import re
import urllib.parse
from collections.abc import Mapping, Sequence
from copy import copy
from dataclasses import dataclass
from typing import Final

from input_lock import JsonValue, Lock, Package
from input_lock.identity import HEX64
from input_lock.records import (
    DSSE_PAYLOAD_TYPE,
    PROVENANCE_PREDICATE,
    BuildMetadata,
    Envelope,
    ResourceDescriptor,
    SpdxDocument,
    SpdxPackage,
    Statement,
    deb_packages,
    envelope,
    input_packages,
    jsonl,
    lock_dependencies,
    provenance,
    spdx_document,
    spdx_id,
    statement,
)

from . import __version__

REPOSITORY: Final = "https://github.com/foreverworks/debian-image-factory"


def build_type(version: str) -> str:
    """The document that says what a build's parameters mean, as of a factory release (docs/build-type-v1.md)."""
    return f"{REPOSITORY}/blob/v{version}/docs/build-type-v1.md"


BUILD_TYPE: Final = build_type(__version__)
"""The `buildType` of every provenance this release writes."""

CHECKS_DOC: Final = f"{REPOSITORY}/blob/v{__version__}/docs/checks.md"
"""The document that explains every check; a test result links to `CHECKS_DOC#<check id>`."""

NO_NAMESPACE_BASE: Final = "urn:debian-image-factory"
"""The SBOM namespace base when the definition's repository has no public https address."""

PURPOSES: Final[Mapping[str, str]] = {
    "core": "OPERATING_SYSTEM",
    "os": "OPERATING_SYSTEM",
    "oci": "CONTAINER",
    "incus": "CONTAINER",
    "installer": "INSTALL",
}
"""SPDX `primaryPackagePurpose` of the root package, by image kind. The JSON schema of SPDX 2.3 spells the
operating system value with an underscore (`OPERATING_SYSTEM`), unlike the specification text."""

_SPDX_TIME: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_REVISION: Final = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SCP: Final = re.compile(r"(?:(?P<user>[^@/\\\s:]+)@)?(?P<host>[A-Za-z0-9][A-Za-z0-9.-]*):(?!//)(?P<path>[^\\\s].*)")


class RecordsError(ValueError):
    """A records file that cannot be read as DSSE envelopes of in-toto statements."""


def decode_statements(text: str) -> list[dict[str, object]]:
    """Every statement in a records file, decoded from its envelope, in file order. Blank lines are
    skipped; a line that is not a DSSE envelope of a JSON object raises RecordsError naming it.
    Nothing here checks a statement's shape: `published.parse_envelopes` does that for lookups."""
    found: list[dict[str, object]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            envelope: object = json.loads(line)
            if not isinstance(envelope, dict) or envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
                raise RecordsError(f"line {number}: not a DSSE envelope of type {DSSE_PAYLOAD_TYPE}")
            payload = envelope.get("payload")
            if not isinstance(payload, str):
                raise RecordsError(f"line {number}: the envelope has no payload")
            statement: object = json.loads(base64.b64decode(payload, validate=True))
        except (json.JSONDecodeError, binascii.Error, UnicodeDecodeError):
            raise RecordsError(f"line {number}: not an envelope holding base64 of a JSON statement") from None
        if not isinstance(statement, dict):
            raise RecordsError(f"line {number}: the statement is not a JSON object")
        found.append({str(key): value for key, value in statement.items()})
    return found


# ---- where a build came from ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DefinitionSource:
    """The repository, commit and file a definition was read from, as a record states them."""

    uri: str
    revision: str
    path: str


@dataclass(frozen=True, slots=True)
class Remote:
    """A file fetched from the network that a build depended on: its address and sha256 (an InRelease)."""

    uri: str
    sha256: str


@dataclass(frozen=True, slots=True)
class Parent:
    """An artifact a child image descends from: the image's name and the artifact's sha256 (a core
    tarball's, or an OCI image's manifest digest)."""

    name: str
    sha256: str


def definition_uri(remote: str) -> str | None:
    """A git remote URL as a record states it, or None when it has no place in a record.

    - `https://[user[:token]@]host/path` becomes `git+https://host/path`.
    - `[user@]host:path` (scp style) and `ssh://[user@]host[:port]/path` become `git+ssh://host[/:port]/path`.
    - The user, any token, the query and the fragment are dropped, a trailing `.git` is kept as given.
    - Anything else (a local path, `file:`, `http:`, `git:`) is None: a path on the builder's disk must never
      reach a record, and a record without a definition says less but leaks nothing.
    """
    remote = remote.strip()
    if "://" in remote:
        parts = urllib.parse.urlsplit(remote)
        host = parts.netloc.rpartition("@")[2]
        if parts.scheme not in ("https", "ssh") or not host or not parts.path.strip("/"):
            return None
        return f"git+{parts.scheme}://{host}{parts.path}"
    found = _SCP.fullmatch(remote)
    if found is None or not (found["user"] or "." in found["host"]):
        return None
    path = found["path"].lstrip("/")
    return f"git+ssh://{found['host']}/{path}" if path else None


def namespace_base(source_uri: str | None) -> str:
    """The base of an SBOM's documentNamespace, picked from the definition's `definition_uri`.

    A definition on an https remote has a public address, so its namespace is that repository's URL
    (`https://github.com/example/images`, no `git+`, no `.git`): a namespace must be unique and an address
    its owner controls says whose it is. Without a definition, or on ssh (whose address is not a web
    address), the base is `urn:debian-image-factory`. The caller passes the same value for every image of one run."""
    if source_uri is None or not source_uri.startswith("git+https://"):
        return NO_NAMESPACE_BASE
    base = source_uri.removeprefix("git+")
    return base.removesuffix(".git").rstrip("/")


def run_details(env: Mapping[str, str], version: str) -> tuple[str, str | None]:
    """The builder id and the invocation id of this run, read from the CI's environment variables only.

    Under GitHub Actions (GITHUB_ACTIONS=true and the server, workflow ref, repository, run id and
    attempt all present) the id is `<server>/<workflow ref>` and the invocation is
    `<server>/<repository>/actions/runs/<run id>/attempts/<attempt>`. Anywhere else the id is the build
    type's address plus `#local` and there is no invocation. The machine's name, user and paths are never read."""
    names = ("GITHUB_SERVER_URL", "GITHUB_WORKFLOW_REF", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    values = {name: env.get(name, "") for name in names}
    if (
        env.get("GITHUB_ACTIONS") == "true"
        and all(values.values())
        and values["GITHUB_RUN_ID"].isdecimal()
        and values["GITHUB_RUN_ATTEMPT"].isdecimal()
    ):
        server = values["GITHUB_SERVER_URL"].rstrip("/")
        invocation = (
            f"{server}/{values['GITHUB_REPOSITORY']}/actions/runs/"
            f"{values['GITHUB_RUN_ID']}/attempts/{values['GITHUB_RUN_ATTEMPT']}"
        )
        return f"{server}/{values['GITHUB_WORKFLOW_REF']}", invocation
    return f"{build_type(version)}#local", None


# ---- the SBOM ---------------------------------------------------------------------------------


def spdx_packages(packages: Sequence[Package], lock: Lock, entries: Sequence[str], suite: str) -> list[SpdxPackage]:
    """The installed Debian packages (distro `suite`), then the locked inputs named by `entries`, as SPDX
    packages, with DESIGN 8.2's collision rule on top of input-lock's sanitising.

    input-lock turns every character outside letters, digits, `.` and `-` into `-`, so `a+b` and `a-b`
    would share one SPDXID. When that happens both get `-<first 8 hex of the sha256 of the label>` appended,
    the label being the text input-lock sanitised (`Package-a+b-amd64`), so the IDs differ and stay stable."""
    rows = sorted({(str(name), str(version), str(arch)) for name, version, arch in packages})
    names = sorted(set(entries))
    found = [*deb_packages(rows, suite), *input_packages(lock, names)]
    labels = [f"Package-{name}-{arch}" for name, _, arch in rows] + [f"Input-{name}" for name in names]
    pairs = list(zip(labels, found, strict=True))
    if any(spdx_id(label) != one["SPDXID"] for label, one in pairs):
        raise ValueError("input-lock names its SPDX packages differently than the factory expects")
    taken = [one["SPDXID"] for one in found]
    result: list[SpdxPackage] = []
    for label, one in pairs:
        if taken.count(one["SPDXID"]) > 1:
            one = copy(one)
            one["SPDXID"] = f"{one['SPDXID']}-{hashlib.sha256(label.encode()).hexdigest()[:8]}"
        result.append(one)
    return result


def _require_time(value: str, what: str) -> str:
    if not _SPDX_TIME.fullmatch(value):
        raise ValueError(f"{what} is not a UTC time like 2026-11-21T02:31:12Z: {value!r}")
    return value


def _require_sha256(value: str, what: str) -> str:
    if not HEX64.fullmatch(value):
        raise ValueError(f"{what} is not 64 lowercase hex characters: {value!r}")
    return value


def sbom(
    *,
    image: str,
    kind: str,
    suite: str,
    arch: str,
    artifact_digest: str,
    packages: Sequence[Package],
    lock: Lock,
    entries: Sequence[str],
    namespace_base: str,
    created: str,
    version: str,
) -> SpdxDocument:
    """The SPDX 2.3 document of one artifact (DESIGN 8.2).

    `packages` are read from the image's own dpkg status after the build, never from the plan; `entries`
    are the lock entries the image uses, each named as the lock names it. The namespace is
    `<namespace_base>/sbom/<image>/sha256-<artifact_digest>` (see `namespace_base`), so it differs for every
    artifact and an artifact has one SBOM. `kind` decides the root package's purpose."""
    if kind not in PURPOSES:
        raise ValueError(f"no SPDX purpose for image kind {kind!r}: {sorted(PURPOSES)}")
    digest = _require_sha256(artifact_digest, "the artifact digest")
    root: SpdxPackage = {
        "SPDXID": "SPDXRef-Image",
        "name": image,
        "versionInfo": f"sha256:{digest}",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "primaryPackagePurpose": PURPOSES[kind],
    }
    return spdx_document(
        f"{image}-{suite}-{arch}",
        f"{namespace_base.rstrip('/')}/sbom/{image}/sha256-{digest}",
        _require_time(created, "created"),
        f"Tool: debian-image-factory-{version}",
        root,
        spdx_packages(packages, lock, entries, suite),
    )


# ---- the provenance ---------------------------------------------------------------------------


def provenance_statement(
    *,
    subjects: Sequence[ResourceDescriptor],
    image: str,
    params: Mapping[str, str | int | bool],
    definition: DefinitionSource | None,
    identity: str,
    engine: int,
    build_snapshot: str,
    architecture: str,
    reason: str | None,
    lock: Lock,
    entries: Sequence[str],
    recipe_digest: str,
    in_releases: Sequence[Remote],
    builder_image: str,
    builder_digest: str,
    ancestors: Sequence[Parent],
    builder_id: str,
    invocation_id: str | None,
    version: str,
    started_on: str,
    finished_on: str,
    removed_from_parent: Sequence[str] | None = None,
) -> Statement:
    """The SLSA v1 provenance of one artifact, as an in-toto Statement (DESIGN 8.2, docs/build-type-v1.md).

    resolvedDependencies come in this order: the definition's commit (when known), `lock.json` and each locked
    download of `entries`, `recipe of <image>`, each InRelease, the builder image, then the ancestors,
    nearest first: `parent: <name>` for the first, `ancestor: <name>` for each further one up to core (none
    for core itself). `reason` is recorded only when there is one. Every value is the caller's: nothing here
    reads a clock, an environment or a file. `removed_from_parent`, for an Incus image, an OS root or an
    installer kit, is the parent's paths the artifact does not hold, sorted (internalParameters
    `removedFromParent`), which `ancestry` holds the artifact to."""
    external: dict[str, JsonValue] = {"image": image}
    dependencies: list[ResourceDescriptor] = []
    if definition is not None:
        _require_revision(definition.revision)
        external["definition"] = {"uri": definition.uri, "revision": definition.revision, "path": definition.path}
        commit = {"gitCommit": definition.revision}
        dependencies.append({"uri": f"{definition.uri}@{definition.revision}", "digest": commit})
    external["params"] = dict(params)
    internal: dict[str, JsonValue] = {
        "identity": _require_sha256(identity, "the identity"),
        "engine": engine,
        "buildSnapshot": build_snapshot,
        "architecture": architecture,
    }
    if reason:
        internal["reason"] = reason
    if removed_from_parent is not None:
        removed: list[JsonValue] = [str(path) for path in sorted(removed_from_parent)]
        internal["removedFromParent"] = removed
    dependencies.extend(lock_dependencies(lock, entries))
    dependencies.append({"name": f"recipe of {image}", "digest": _sha256_of(recipe_digest, "the recipe digest")})
    dependencies.extend({"uri": one.uri, "digest": _sha256_of(one.sha256, one.uri)} for one in in_releases)
    dependencies.append({"uri": f"oci://{builder_image}", "digest": _sha256_of(builder_digest, "the builder digest")})
    for position, ancestor in enumerate(ancestors):
        label = "parent" if position == 0 else "ancestor"
        dependencies.append(
            {"name": f"{label}: {ancestor.name}", "digest": _sha256_of(ancestor.sha256, f"the {label} digest")}
        )
    metadata: BuildMetadata = {}
    if invocation_id:
        metadata["invocationId"] = invocation_id
    metadata["startedOn"] = _require_time(started_on, "startedOn")
    metadata["finishedOn"] = _require_time(finished_on, "finishedOn")
    predicate = provenance(
        build_type(version),
        external,
        dependencies,
        builder_id,
        internal,
        {"debian-image-factory": version},
        metadata,
    )
    return statement(subjects, PROVENANCE_PREDICATE, predicate)


def _sha256_of(value: str, what: str) -> dict[str, str]:
    return {"sha256": _require_sha256(value, what)}


def _require_revision(value: str) -> str:
    if not _REVISION.fullmatch(value):
        raise ValueError(f"the definition revision is not a full git commit id: {value!r}")
    return value


# ---- the records file -------------------------------------------------------------------------


def record_lines(statements: Sequence[Statement]) -> str:
    """The text of a `<digest>.intoto.jsonl` file: one unsigned DSSE envelope per statement, one per line."""
    envelopes: list[Envelope] = [envelope(one) for one in statements]
    return jsonl(envelopes)
