"""`debian-image-factory test OUT`: run the built-in checks on the artifacts in OUT and attest each result.

OUT is what a build left: `plan.json`, the artifacts named by `published.artifact_name`, and
`<digest>.intoto.jsonl` beside each. Each check that ran appends one in-toto test-result statement to its
artifact's records file; a check that could not run is listed and writes nothing.
"""

import hashlib
import tarfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

import input_lock.records as rec

from .. import records
from ..commands import Failed, Sources, Usage
from ..planfile import ImageEntry, Plan, read_plan
from ..published import ArtifactName, parse_artifact_name, records_name_for
from . import clones, machine_identity, packages, resolution, snapshot, tarball
from .model import (
    CORE_CHECKS,
    NO_BUILD_SNAPSHOT,
    NO_MACHINE_IDENTITY,
    PACKAGE_SET,
    SAME_RESOLUTION,
    SBOM_COMPLETE,
    TWO_CLONES,
    CheckOutcome,
    NotRun,
    Result,
)

CHUNK = 1024 * 1024

type TwoClones = Callable[[Path], CheckOutcome]


# ---- finding artifacts -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Found:
    path: Path
    image: str
    digest: str


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def image_of(name: ArtifactName, plan: Plan) -> str | None:
    """The plan image an artifact name belongs to: the same image name and the identity's first 16 hex."""
    entry = plan["images"].get(name.image)
    return name.image if entry is not None and entry["identity"].startswith(name.identity16) else None


def find_artifacts(out_dir: Path, plan: Plan) -> tuple[list[Found], list[str]]:
    """The core artifacts in `out_dir` the plan knows, and a line for each file skipped, with its reason."""
    found: list[Found] = []
    skipped: list[str] = []
    for path in sorted(out_dir.iterdir()):
        name = parse_artifact_name(path.name)
        if name is None or not path.is_file():
            continue
        if name.ext != "tar.gz":
            skipped.append(f"skipped {path.name}: only core tarballs are tested by this release")
            continue
        image = image_of(name, plan)
        if image is None:
            skipped.append(f"skipped {path.name}: no image of the plan has this name and identity")
            continue
        if plan["images"][image]["kind"] != "core":
            skipped.append(f"skipped {path.name}: kind {plan['images'][image]['kind']} is not tested by this release")
            continue
        digest = sha256_of(path)
        if not digest.startswith(name.digest12):
            skipped.append(f"skipped {path.name}: its sha256 is {digest}, which its name does not say")
            continue
        found.append(Found(path, image, digest))
    return found, skipped


# ---- records ---------------------------------------------------------------------------------------


def sbom_of(records_text: str | None, digest: str) -> Mapping[str, object] | str:
    """The predicate of the one SBOM statement about `digest`, or why there is not exactly one."""
    if records_text is None:
        return "there is no records file for this artifact"
    try:
        statements = records.decode_statements(records_text)
    except records.RecordsError as error:
        return f"the records file cannot be read: {error}"
    documents: list[Mapping[str, object]] = []
    for one in statements:
        subjects, predicate = one.get("subject"), one.get("predicate")
        about = isinstance(subjects, list) and any(
            isinstance(s, dict) and isinstance(s.get("digest"), dict) and s["digest"].get("sha256") == digest
            for s in subjects
        )
        if about and one.get("predicateType") == rec.SPDX_PREDICATE and isinstance(predicate, dict):
            documents.append({str(key): value for key, value in predicate.items()})
    if len(documents) != 1:
        return f"the records hold {len(documents)} SBOM statements about this artifact, not one"
    return documents[0]


def test_result_line(found: Found, outcome: Result, url: str = "") -> str:
    """One DSSE envelope line (with its newline) attesting `outcome` for the artifact."""
    predicate = rec.test_result(
        outcome.outcome,
        [{"name": outcome.check, "uri": f"{records.CHECKS_DOC}#{outcome.check}"}],
        url=url,
        passed=outcome.passed,
        warned=outcome.warned,
        failed=outcome.failed,
    )
    statement = rec.statement([rec.subject(found.path.name, found.digest)], rec.TEST_RESULT_PREDICATE, predicate)
    return rec.jsonl([rec.envelope(statement)])


def append_records(path: Path, lines: Sequence[str]) -> None:
    """Add lines to a records file, leaving what it holds as it is (a missing final newline is completed)."""
    if not lines:
        return
    existing = path.read_bytes() if path.exists() else b""
    prefix = b"\n" if existing and not existing.endswith(b"\n") else b""
    with path.open("ab") as handle:
        handle.write(prefix + "".join(lines).encode())


# ---- running ---------------------------------------------------------------------------------------


def run_checks(
    found: Found,
    names: Sequence[str],
    plan: Plan,
    records_text: str | None,
    sources: Sources,
    clones_check: TwoClones,
) -> list[CheckOutcome]:
    """The named checks on one core artifact, in the order given. One pass reads the tarball."""
    entry = plan["images"][found.image]
    wanted = frozenset(machine_identity.WANTED | {packages.STATUS_PATH})
    looking = NO_BUILD_SNAPSHOT in names and not snapshot.cannot_tell(plan["snapshot"], plan["baseline"])
    needle = plan["snapshot"] if looking else None
    keys = NO_MACHINE_IDENTITY in names
    scanned = tarball.scan_tarball(found.path, wanted, needle, keys) if set(names) - {TWO_CLONES} else tarball.EMPTY
    status = scanned.contents.get(packages.STATUS_PATH)
    outcomes: list[CheckOutcome] = []
    for name in names:
        if name == PACKAGE_SET:
            outcomes.append(packages.package_set(status, entry["packages"]))
        elif name == NO_MACHINE_IDENTITY:
            outcomes.append(machine_identity.no_machine_identity(scanned.members, scanned.contents, scanned.key_files))
        elif name == SBOM_COMPLETE:
            outcomes.append(
                packages.sbom_complete(
                    status, sbom_of(records_text, found.digest), packages.locked_versions(entry["inputs"])
                )
            )
        elif name == NO_BUILD_SNAPSHOT:
            outcomes.append(snapshot.no_build_snapshot(plan["snapshot"], plan["baseline"], scanned.needle_hits))
        elif name == SAME_RESOLUTION:
            outcomes.append(
                resolution.same_resolution(
                    snapshot=plan["snapshot"],
                    suite=plan["debian"]["suite"],
                    components=plan["debian"]["components"],
                    arch=plan["debian"]["architecture"],
                    request=entry["request"],
                    planned=entry["packages"],
                    status=status,
                    keyring=sources.keyring,
                    cache=sources.cache,
                    service=sources.service,
                )
            )
        elif name == TWO_CLONES:
            outcomes.append(clones_check(found.path))
    return outcomes


def describe(image: str, outcome: CheckOutcome) -> str:
    if isinstance(outcome, NotRun):
        return f"{image}: {outcome.check} not run: {outcome.reason}"
    detail = [*outcome.failed, *outcome.warned]
    return f"{image}: {outcome.check} {outcome.outcome}" + (": " + "; ".join(detail) if detail else "")


def choose(requested: Sequence[str], entry: ImageEntry) -> tuple[list[str], list[NotRun]]:
    """(the checks to run, the required checks this release has no code for) for one image."""
    if requested:
        return [str(name) for name in CORE_CHECKS if name in requested], []
    runnable = [str(name) for name in CORE_CHECKS if name in entry["checks"]]
    others = [
        NotRun(name, "not a built-in check this release runs (a consumer's own check is attested with `attest`)")
        for name in entry["checks"]
        if name not in CORE_CHECKS
    ]
    return runnable, others


def test_command(
    out_dir: Path,
    requested: Sequence[str],
    sources: Sources,
    out: TextIO,
    clones_check: TwoClones = clones.two_clones,
    url: str = "",
) -> int:
    """Run the plan's required checks (or only `requested`) on every core artifact in `out_dir`.

    Returns 1 when any check FAILED, else 0; raises Usage for a name that is not a check of core and Failed
    when plan.json or an artifact cannot be read.
    """
    unknown = sorted(set(requested) - set(CORE_CHECKS))
    if unknown:
        raise Usage(f"--check {', '.join(unknown)}: not a check of a core image (one of {', '.join(CORE_CHECKS)})")
    try:
        plan = read_plan(out_dir / "plan.json")
        found, skipped = find_artifacts(out_dir, plan)
    except ValueError as error:
        raise Failed(f"plan.json cannot be read: {error}") from None
    except OSError as error:
        raise Failed(f"{error.filename}: {error.strerror or error}") from None
    for line in skipped:
        out.write(line + "\n")
    status = 0
    for one in found:
        names, others = choose(requested, plan["images"][one.image])
        records_path = out_dir / records_name_for(one.digest)
        try:
            records_text = records_path.read_text(encoding="utf-8") if records_path.exists() else None
            outcomes = run_checks(one, names, plan, records_text, sources, clones_check)
            append_records(records_path, [test_result_line(one, o, url) for o in outcomes if isinstance(o, Result)])
        except (OSError, EOFError, UnicodeDecodeError) as error:
            raise Failed(f"{one.path.name}: cannot be tested: {error}") from None
        except tarfile.TarError as error:
            raise Failed(f"{one.path.name}: is not a readable tarball: {error}") from None
        for outcome in [*outcomes, *others]:
            out.write(describe(one.image, outcome) + "\n")
            if isinstance(outcome, Result) and outcome.outcome == "FAILED":
                status = 1
    return status
