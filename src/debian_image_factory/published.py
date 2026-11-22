"""What is already published, and the reuse / wait / build state of one image (DESIGN 4, 7.4, 8.1, 8.2).

Pure functions: text and values in, values out. Reading a directory or a registry is `targets`' job.

Rules this module fixes:

- A record counts for an artifact only when one of its statement's subjects carries the artifact's
  sha256. Records about other digests in the same file are ignored.
- Several test results for one check: the last one wins. A result is later than another when its run
  finished later (`finishedOn` in the `run` entry of its `configuration`, DESIGN 8.2), a result without
  a time is older than any with one, and file order breaks a tie. A FAILED followed by a later PASSED
  (or WARNED) is passing; a PASSED followed by a later FAILED is failing. PASSED and WARNED both count
  as passing.
- Among artifacts of one state, the newest `finished_on` wins, an artifact without a time is older
  than any with one, and a tie goes to the smallest digest, so the choice never depends on the
  order a target listed them in.
- The order of results is only as trustworthy as the records that claim it (unsigned by default: DESIGN 7.4).
  A result stamped later than the time the reader runs, plus `FUTURE_ALLOWANCE` for clocks that differ, is
  never the last: it does not count, and the reader lists it as rejected ("finished in the future").
"""

import base64
import binascii
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final, Literal

from input_lock.identity import HEX64
from input_lock.records import (
    DSSE_PAYLOAD_TYPE,
    PROVENANCE_PREDICATE,
    STATEMENT_TYPE,
    TEST_RESULT_PREDICATE,
    TestOutcome,
)

OUTCOMES: Final[tuple[TestOutcome, ...]] = ("PASSED", "WARNED", "FAILED")
PASSING: Final[frozenset[str]] = frozenset({"PASSED", "WARNED"})
FUTURE_ALLOWANCE: Final = timedelta(minutes=5)
"""How far past the reader's clock a result's `finishedOn` may be before it is not believed."""
RUN_ENTRY: Final = "run"
"""The name of the `configuration` entry of a test result that says which run made it (DESIGN 8.2)."""

type State = Literal["reuse", "wait", "build"]


# ---- artifacts and the decision -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Artifact:
    """One published build of one image, as its records describe it."""

    image: str
    identity: str
    digest: str
    name: str
    finished_on: str | None
    results: Mapping[str, TestOutcome] = field(default_factory=dict[str, TestOutcome])
    has_locked_inputs: bool = False
    """Whether its provenance lists locked inputs, which adds `locked-inputs` to the checks it needs."""
    future_results: tuple[tuple[str, str], ...] = ()
    """(check, `finishedOn`) of the results its records hold that are stamped in the future and so do not count."""


@dataclass(frozen=True, slots=True)
class Rejected:
    """A file that looked like an artifact but does not count, and why (so the plan can show it)."""

    name: str
    reason: str


@dataclass(frozen=True, slots=True)
class Lookup:
    """What a target holds for one identity: the artifacts that count and the files that do not."""

    artifacts: tuple[Artifact, ...]
    rejected: tuple[Rejected, ...]


@dataclass(frozen=True, slots=True)
class Decision:
    """`artifact` is the digest of the artifact reused or waited for; `waiting_for` names the checks
    without a result yet; `failed` names the required checks seen failing when everything must be built."""

    state: State
    artifact: str | None = None
    waiting_for: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()


def instant(value: str | None) -> datetime:
    """A finish time as a comparable instant; none, or one that does not parse, is older than any."""
    if value is None:
        return datetime.min.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _newest(artifacts: Sequence[Artifact]) -> Artifact:
    """The artifact with the latest finish time; a tie goes to the smallest digest."""
    return min(artifacts, key=lambda one: (-instant(one.finished_on).timestamp(), one.digest))


def sort_newest_first(artifacts: Sequence[Artifact]) -> list[Artifact]:
    """The artifacts newest first, by the same order `_newest` picks by: a tie goes to the smallest digest."""
    return sorted(artifacts, key=lambda one: (-instant(one.finished_on).timestamp(), one.digest))


def failed_and_missing(one: Artifact, required: Sequence[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The required checks whose last result is FAILED, and the ones with no result yet, each sorted."""
    needed = sorted(set(required))
    bad = tuple(check for check in needed if one.results.get(check) == "FAILED")
    missing = tuple(check for check in needed if check not in one.results)
    return bad, missing


def decide(artifacts: Sequence[Artifact], required: Sequence[str]) -> Decision:
    """reuse, wait or build for one image, from the artifacts found for its identity (the caller
    passes only those; a target's lookup does). `required` is the image's check set."""
    good: list[Artifact] = []
    candidates: list[tuple[Artifact, tuple[str, ...]]] = []
    failed: set[str] = set()
    for one in artifacts:
        bad, missing = failed_and_missing(one, required)
        failed |= set(bad)
        if bad:
            continue
        if missing:
            candidates.append((one, missing))
        else:
            good.append(one)
    if good:
        return Decision("reuse", artifact=_newest(good).digest)
    if candidates:
        chosen = _newest([one for one, _ in candidates])
        waiting = next(missing for one, missing in candidates if one is chosen)
        return Decision("wait", artifact=chosen.digest, waiting_for=waiting)
    return Decision("build", failed=tuple(sorted(failed)))


# ---- names --------------------------------------------------------------------------------------

_NAME: Final = re.compile(
    r"(?P<image>[a-z0-9][a-z0-9._-]*)-(?P<suite>[a-z0-9.]+)-(?P<arch>[a-z0-9_]+)"
    r"-(?P<identity16>[0-9a-f]{16})-(?P<digest12>[0-9a-f]{12})\.(?P<ext>[a-z0-9]+(?:\.[a-z0-9]+)*)"
)
_PART: Final = re.compile(r"[a-z0-9][a-z0-9._-]*")


@dataclass(frozen=True, slots=True)
class ArtifactName:
    """An artifact file name taken apart. The identity and digest are the prefixes the name carries."""

    image: str
    suite: str
    arch: str
    identity16: str
    digest12: str
    ext: str


def artifact_name(image: str, suite: str, arch: str, identity: str, digest: str, ext: str) -> str:
    """`<image>-<suite>-<arch>-<first 16 hex of identity>-<first 12 hex of digest>.<ext>` (DESIGN 7.4)."""
    for label, value in (("identity", identity), ("digest", digest)):
        if not HEX64.fullmatch(value):
            raise ValueError(f"{label} is not 64 lowercase hex characters: {value!r}")
    name = f"{image}-{suite}-{arch}-{identity[:16]}-{digest[:12]}.{ext}"
    parsed = parse_artifact_name(name)
    if parsed is None or (parsed.image, parsed.suite, parsed.arch, parsed.ext) != (image, suite, arch, ext):
        raise ValueError(f"these parts do not make an artifact name: {name!r}")
    return name


def parse_artifact_name(name: str) -> ArtifactName | None:
    """The parts of an artifact file name, or None when the name is not one. The image may hold
    hyphens (`node-26`); the suite and the architecture may not."""
    found = _NAME.fullmatch(name)
    if found is None:
        return None
    return ArtifactName(**found.groupdict())


def records_name_for(digest: str) -> str:
    """The records file beside an artifact: `<full sha256>.intoto.jsonl`."""
    if not HEX64.fullmatch(digest):
        raise ValueError(f"digest is not 64 lowercase hex characters: {digest!r}")
    return f"{digest}.intoto.jsonl"


_RECORDS_NAME: Final = re.compile(r"(?P<digest>[0-9a-f]{64})\.intoto\.jsonl")


def records_digest(name: str) -> str | None:
    """The digest (full hex) a records file name carries, or None when the name is not `<digest>.intoto.jsonl`."""
    found = _RECORDS_NAME.fullmatch(name)
    return found["digest"] if found else None


_PARTIAL: Final = re.compile(r"(?P<name>.+)\.partial-(?P<token>[0-9a-f]{16})")


def partial_name(name: str, token: str) -> str:
    """The temporary name an asset is uploaded under before it is renamed to `name`: `<name>.partial-<token>`
    (16 lowercase hex). The hyphen is not allowed in an artifact's extension and the `.partial-` tail
    is not a records file's, so no lookup reads such an asset as an artifact or as records."""
    if not re.fullmatch(r"[0-9a-f]{16}", token):
        raise ValueError(f"a partial token is 16 lowercase hex characters: {token!r}")
    return f"{name}.partial-{token}"


def partial_of(name: str) -> str | None:
    """The final name an unfinished upload `name` was going to get, or None when `name` is not one."""
    found = _PARTIAL.fullmatch(name)
    return found["name"] if found else None


# ---- targets ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DirTarget:
    path: str


@dataclass(frozen=True, slots=True)
class OciTarget:
    registry: str
    repository: str


@dataclass(frozen=True, slots=True)
class ReleaseTarget:
    owner: str
    repo: str
    tag: str


type Target = DirTarget | OciTarget | ReleaseTarget

_REGISTRY: Final = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?")
_REPOSITORY: Final = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*")
_OWNER: Final = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_REPO: Final = re.compile(r"[A-Za-z0-9._-]{1,100}")
_TAG: Final = re.compile(r"[^\s/@]+")


def parse_target(text: str) -> Target:
    """`dir://<path>`, `oci://<registry>/<repository>` or `github-release://<owner>/<repo>@<tag>`.
    Raises ValueError saying what is wrong."""
    scheme, separator, rest = text.partition("://")
    if not separator:
        raise ValueError(f"not a target (expected dir://, oci:// or github-release://): {text!r}")
    if scheme == "dir":
        if not rest or "\0" in rest:
            raise ValueError(f"a dir:// target needs a path: {text!r}")
        return DirTarget(rest)
    if scheme == "oci":
        registry, slash, repository = rest.partition("/")
        if not slash or not _REGISTRY.fullmatch(registry) or not _REPOSITORY.fullmatch(repository):
            raise ValueError(f"an oci:// target is oci://<registry>/<repository>, lowercase repository: {text!r}")
        return OciTarget(registry, repository)
    if scheme == "github-release":
        place, at, tag = rest.partition("@")
        owner, slash, repo = place.partition("/")
        if not (at and slash and _OWNER.fullmatch(owner) and _REPO.fullmatch(repo) and _TAG.fullmatch(tag)):
            raise ValueError(f"a github-release:// target is github-release://<owner>/<repo>@<tag>: {text!r}")
        if repo in (".", ".."):
            raise ValueError(f"a github-release:// target names a repository, not {repo!r}: {text!r}")
        return ReleaseTarget(owner, repo, tag)
    raise ValueError(f"unknown target scheme {scheme + '://'!r} (expected dir://, oci:// or github-release://)")


IMAGE_PLACEHOLDER: Final = "{image}"
"""In the repository of an `oci://` target: the name of the image the target is for. One target string then
names a repository per image (`oci://ghcr.io/example/{image}`), and every command that takes a target reads
it the same way: the target as it resolves for the image being looked up, published or pruned."""


@dataclass(frozen=True, slots=True)
class TargetTemplate:
    """A target as given: `text` is what the user wrote, `target` what it parses to (a repository with
    `{image}` parses with the image name `image`, to check the template), `per_image` that it has the
    placeholder."""

    text: str
    target: Target
    per_image: bool


def parse_template(text: str) -> TargetTemplate:
    """A target that may carry `{image}` in the repository of an `oci://` target. Raises ValueError saying what
    is wrong: a target that does not parse, or `{image}` anywhere but in an `oci://` repository (a directory or
    a release holds each artifact under its own name already; a registry host is not per image)."""
    if IMAGE_PLACEHOLDER not in text:
        return TargetTemplate(text, parse_target(text), False)
    scheme, _, rest = text.partition("://")
    registry, slash, _ = rest.partition("/")
    if scheme != "oci" or not slash or IMAGE_PLACEHOLDER in registry:
        raise ValueError(f"{text}: {IMAGE_PLACEHOLDER} belongs in the repository of an oci:// target")
    return TargetTemplate(text, parse_target(text.replace(IMAGE_PLACEHOLDER, "image")), True)


def resolve_template(template: TargetTemplate, image: str) -> Target:
    """The target `template` is for the image `image`: the template's own target, or with `{image}` the
    repository named after the image. Raises ValueError when the image's name makes no repository."""
    if not template.per_image:
        return template.target
    try:
        return parse_target(template.text.replace(IMAGE_PLACEHOLDER, image))
    except ValueError as error:
        raise ValueError(f"{template.text}: the image {image} makes no repository ({error})") from None


def resolve_registry(template: TargetTemplate, image: str) -> OciTarget:
    """`resolve_template` for a template known to be an `oci://` target (one a command took as a registry)."""
    target = resolve_template(template, image)
    if not isinstance(target, OciTarget):
        raise ValueError(f"{template.text}: not an oci:// target")
    return target


def format_target(target: Target) -> str:
    """A target as `parse_target` takes it."""
    match target:
        case DirTarget(path):
            return f"dir://{path}"
        case OciTarget(registry, repository):
            return f"oci://{registry}/{repository}"
        case ReleaseTarget(owner, repo, tag):
            return f"github-release://{owner}/{repo}@{tag}"


# ---- records ------------------------------------------------------------------------------------


class RecordsError(ValueError):
    """A records file that cannot be read as DSSE envelopes of in-toto statements."""


@dataclass(frozen=True, slots=True)
class Subject:
    name: str
    sha256: str


@dataclass(frozen=True, slots=True)
class BuildClaim:
    """What a provenance record says about its build."""

    image: str
    identity: str
    finished_on: str | None
    ancestors: tuple[tuple[str, str], ...] = ()
    """(image, sha256) of the `parent: <image>` and `ancestor: <image>` resolved dependencies, nearest first."""
    has_locked_inputs: bool = False
    """Whether it lists locked inputs: resolved dependencies other than `lock.json` with both a name and a uri."""


@dataclass(frozen=True, slots=True)
class CheckClaim:
    """What a test-result record says: one check and its outcome, and the run that made the claim
    (`run`, `finished_on` are None for a record from before runs were recorded)."""

    check: str
    outcome: TestOutcome
    run: str | None = None
    finished_on: str | None = None


@dataclass(frozen=True, slots=True)
class Record:
    """A checked statement. `build` is set for provenance, `check` for a test result, neither for
    any other predicate type (an SBOM), which only has to be well formed."""

    predicate_type: str
    subjects: tuple[Subject, ...]
    build: BuildClaim | None = None
    check: CheckClaim | None = None


def _object(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise RecordsError(f"{where} is not an object")
    return {str(key): item for key, item in value.items()}


def _text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise RecordsError(f"{where} is not a non-empty string")
    return value


def _array(value: object, where: str) -> list[object]:
    if not isinstance(value, list):
        raise RecordsError(f"{where} is not an array")
    return list(value)


def _finish_time(value: object, where: str) -> str:
    stamp = _text(value, where)
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        raise RecordsError(f"{where} is not an RFC 3339 time: {stamp!r}") from None
    if parsed.tzinfo is None:
        raise RecordsError(f"{where} has no time zone: {stamp!r}")
    return stamp


def _subjects(value: object) -> tuple[Subject, ...]:
    found: list[Subject] = []
    for index, raw in enumerate(_array(value, "subject")):
        one = _object(raw, f"subject[{index}]")
        digest = _text(_object(one.get("digest"), f"subject[{index}].digest").get("sha256"), f"subject[{index}] sha256")
        if not HEX64.fullmatch(digest):
            raise RecordsError(f"subject[{index}] sha256 is not 64 lowercase hex characters")
        name = one.get("name", "")
        found.append(Subject(name if isinstance(name, str) else "", digest))
    if not found:
        raise RecordsError("a statement has no subject")
    return tuple(found)


def _provenance(predicate: object) -> BuildClaim:
    body = _object(predicate, "provenance predicate")
    definition = _object(body.get("buildDefinition"), "buildDefinition")
    parameters = _object(definition.get("externalParameters"), "buildDefinition.externalParameters")
    internal = _object(definition.get("internalParameters"), "buildDefinition.internalParameters")
    image = _text(parameters.get("image"), "externalParameters.image")
    identity = _text(internal.get("identity"), "internalParameters.identity")
    if not HEX64.fullmatch(identity):
        raise RecordsError("internalParameters.identity is not 64 lowercase hex characters")
    finished: str | None = None
    details = body.get("runDetails")
    if details is not None:
        metadata = _object(details, "runDetails").get("metadata")
        times = _object(metadata, "runDetails.metadata") if metadata is not None else {}
        if "finishedOn" in times:
            finished = _finish_time(times["finishedOn"], "finishedOn")
    dependencies = definition.get("resolvedDependencies")
    return BuildClaim(
        image,
        identity,
        finished,
        _ancestors(dependencies),
        has_locked_inputs=isinstance(dependencies, list) and any(_is_locked_input(one) for one in dependencies),
    )


def _is_locked_input(dependency: object) -> bool:
    """A resolved dependency that is a locked input: it has a name and a uri, and is not `lock.json` itself."""
    return (
        isinstance(dependency, dict)
        and isinstance(dependency.get("name"), str)
        and isinstance(dependency.get("uri"), str)
        and dependency.get("name") != "lock.json"
    )


def _ancestors(value: object) -> tuple[tuple[str, str], ...]:
    """The images a build descends from, as its resolved dependencies name them (`parent: core`, then
    `ancestor: <image>` for each further one). Other dependencies are not read here."""
    if not isinstance(value, list):
        return ()
    found: list[tuple[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name, digest = item.get("name"), item.get("digest")
        if not isinstance(name, str) or not name.startswith(("parent: ", "ancestor: ")):
            continue
        sha256 = digest.get("sha256") if isinstance(digest, dict) else None
        if not isinstance(sha256, str) or not HEX64.fullmatch(sha256):
            raise RecordsError(f"resolvedDependencies {name!r} has no sha256 digest")
        found.append((name.split(": ", 1)[1], sha256))
    return tuple(found)


def _run_of(entries: Sequence[object]) -> tuple[str | None, str | None]:
    """(run id, finish time) from the `configuration` entry named `run`, or (None, None) when there is none.
    A `run` entry whose annotations do not hold a text `runId` and an RFC 3339 `finishedOn` is malformed."""
    for index, raw in enumerate(entries, start=1):
        entry = _object(raw, f"configuration[{index}]")
        if entry.get("name") != RUN_ENTRY:
            continue
        where = f"configuration[{index}].annotations"
        notes = _object(entry.get("annotations"), where)
        return _text(notes.get("runId"), f"{where}.runId"), _finish_time(notes.get("finishedOn"), f"{where}.finishedOn")
    return None, None


def _test_result(predicate: object) -> CheckClaim:
    body = _object(predicate, "test-result predicate")
    outcome = body.get("result")
    if outcome == "PASSED" or outcome == "WARNED" or outcome == "FAILED":
        configuration = _array(body.get("configuration"), "configuration")
        if not configuration:
            raise RecordsError("configuration is empty: the first entry names the check")
        check = _text(_object(configuration[0], "configuration[0]").get("name"), "configuration[0].name")
        run, finished = _run_of(configuration[1:])
        return CheckClaim(check, outcome, run, finished)
    raise RecordsError(f"result is not PASSED, WARNED or FAILED: {outcome!r}")


def _statement(value: object) -> Record:
    body = _object(value, "statement")
    if body.get("_type") != STATEMENT_TYPE:
        raise RecordsError(f"statement _type is not {STATEMENT_TYPE}")
    subjects = _subjects(body.get("subject"))
    kind = _text(body.get("predicateType"), "predicateType")
    if kind == PROVENANCE_PREDICATE:
        return Record(kind, subjects, build=_provenance(body.get("predicate")))
    if kind == TEST_RESULT_PREDICATE:
        return Record(kind, subjects, check=_test_result(body.get("predicate")))
    return Record(kind, subjects)


def parse_envelope(line: str) -> Record:
    """One line of a records file: a DSSE envelope whose payload is a statement. Raises RecordsError."""
    try:
        envelope = _object(json.loads(line), "envelope")
    except json.JSONDecodeError as error:
        raise RecordsError(f"not JSON ({error.msg})") from None
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        raise RecordsError(f"payloadType is not {DSSE_PAYLOAD_TYPE}")
    try:
        payload = base64.b64decode(_text(envelope.get("payload"), "payload"), validate=True)
        return _statement(json.loads(payload))
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
        raise RecordsError("payload is not base64 of a JSON statement") from None


def parse_envelopes(text: str) -> list[Record]:
    """Every statement in a records file, in file order. Blank lines are skipped; a malformed line
    raises RecordsError naming its line number."""
    found: list[Record] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            found.append(parse_envelope(line))
        except RecordsError as error:
            raise RecordsError(f"line {number}: {error}") from None
    return found


def statements_cover(statements: Sequence[Record], digests: Sequence[str]) -> bool:
    """Whether one statement lists every one of `digests` among its subjects' sha256."""
    return any(set(digests) <= {subject.sha256 for subject in one.subjects} for one in statements)


def counted_results(
    records: Sequence[Record], now: datetime | None
) -> tuple[dict[str, TestOutcome], tuple[tuple[str, str], ...]]:
    """The last result of each check in `records` (in file order): the one whose run finished latest, a
    result without a time older than any with one, and the later line winning a tie; and the (check,
    `finishedOn`) of every result that does not count because it finished later than `now` plus
    `FUTURE_ALLOWANCE`. `now` None counts every result."""
    last: dict[str, tuple[tuple[datetime, int], TestOutcome]] = {}
    future: list[tuple[str, str]] = []
    for position, one in enumerate(records):
        if one.check is None:
            continue
        moment = instant(one.check.finished_on)
        if now is not None and one.check.finished_on is not None and moment > now + FUTURE_ALLOWANCE:
            future.append((one.check.check, one.check.finished_on))
            continue
        key = (moment, position)
        held = last.get(one.check.check)
        if held is None or key > held[0]:
            last[one.check.check] = (key, one.check.outcome)
    return {check: outcome for check, (_, outcome) in last.items()}, tuple(future)


def last_results(records: Sequence[Record], now: datetime | None = None) -> dict[str, TestOutcome]:
    """`counted_results`' first part: the last result of each check, ignoring any stamped after `now`."""
    return counted_results(records, now)[0]


def future_notes(artifacts: Sequence[Artifact]) -> tuple[Rejected, ...]:
    """A rejected line for each result of `artifacts` that does not count for finishing in the future."""
    return tuple(
        Rejected(one.name, f"its test result for {check} finished in the future ({stamp}), so it does not count")
        for one in artifacts
        for check, stamp in one.future_results
    )


def artifact_from_records(
    name: str, digest: str, image: str, identity: str, records: str, now: datetime | None = None
) -> Artifact | Rejected:
    """The artifact file `name` whose real sha256 is `digest`, as its records file `records` describes
    it for `image` and `identity` (full hex), or the reason it does not count. Results stamped later than
    `now` (default: the present) plus `FUTURE_ALLOWANCE` do not count and are named in `future_results`."""
    try:
        statements = parse_envelopes(records)
    except RecordsError as error:
        return Rejected(name, f"records file is malformed, {error}")
    about = [one for one in statements if any(subject.sha256 == digest for subject in one.subjects)]
    builds = [one.build for one in about if one.build is not None]
    if not builds:
        return Rejected(name, "no provenance record is about this file's sha256")
    for build in builds:
        if build.image != image:
            return Rejected(name, f"provenance names image {build.image!r}, not {image!r}")
        if build.identity != identity:
            return Rejected(name, f"provenance names identity {build.identity}, not {identity}")
    finished = max((build.finished_on for build in builds if build.finished_on), key=instant, default=None)
    locked = any(build.has_locked_inputs for build in builds)
    results, future = counted_results(about, now or datetime.now(UTC))
    return Artifact(image, identity, digest, name, finished, results, locked, future)


def described_artifact(
    name: str, digest: str, records: str, identity_prefix: str, now: datetime | None = None
) -> Artifact | Rejected:
    """The artifact file `name` whose real sha256 is `digest`, as its records file `records` describes it,
    when nothing is known about it but the start of its identity (a file name carries 16 hex, a registry tag
    all 64). The image and the full identity are the provenance's; every provenance about the digest must
    agree on both, and the identity must start with `identity_prefix`. Else the reason it does not count.
    `now` is as for `artifact_from_records`."""
    try:
        statements = parse_envelopes(records)
    except RecordsError as error:
        return Rejected(name, f"records file is malformed, {error}")
    builds = [
        one.build
        for one in statements
        if one.build is not None and any(subject.sha256 == digest for subject in one.subjects)
    ]
    if not builds:
        return Rejected(name, "no provenance record is about this file's sha256")
    claims = {(build.image, build.identity) for build in builds}
    if len(claims) != 1:
        return Rejected(name, "its provenance records name different images or identities")
    image, identity = next(iter(claims))
    if not identity.startswith(identity_prefix):
        return Rejected(name, f"provenance names identity {identity}, which does not start with {identity_prefix}")
    return artifact_from_records(name, digest, image, identity, records, now)
