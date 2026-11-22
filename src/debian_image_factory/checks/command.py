"""`debian-image-factory test OUT`: run the built-in checks on the artifacts in OUT and attest each result.

OUT is what a build left: `plan.json`, the artifacts named by `published.artifact_name` (a core tarball, or
an OCI image layout directory), and `<digest>.intoto.jsonl` beside each. Each check that ran appends one
in-toto test-result statement to its artifact's records file; a check that could not run is listed and
writes nothing.
"""

import contextlib
import hashlib
import subprocess
import tarfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

import input_lock.records as rec

from .. import oci, ocilayout, records
from ..commands import Failed, Sources, Usage
from ..planfile import ImageEntry, Plan, read_plan
from ..published import ArtifactName, parse_artifact_name, records_name_for
from . import ancestry, clones, container, layers, machine_identity, packages, resolution, snapshot, tarball
from .container import ProbeRunner
from .dockerio import DOCKER, Docker
from .model import (
    ANCESTRY,
    CHECKS_OF_KIND,
    LOCKED_INPUTS,
    NO_BUILD_SNAPSHOT,
    NO_MACHINE_IDENTITY,
    OCI_RUN,
    PACKAGE_SET,
    SAME_RESOLUTION,
    SBOM_COMPLETE,
    TWO_CLONES,
    CheckOutcome,
    NotRun,
    Result,
)

CHUNK = 1024 * 1024

ARTIFACT_KINDS = {"tar.gz": "core", oci.LAYOUT_EXT: "oci"}
"""The artifact name extensions `test` reads, and the kind of image each one is."""

type TwoClones = Callable[[Path], CheckOutcome]
type LockedInputs = Callable[[ImageEntry, bytes | None, ProbeRunner], CheckOutcome]
"""The `locked-inputs` check: the plan entry, the image's dpkg status (None when it has none) and a runner
that runs a `modules.Probe` in the image and gives (exit status, standard output)."""


def locked_inputs_result(entry: ImageEntry, status: bytes | None, run: ProbeRunner) -> CheckOutcome:
    """The seam the node module fills: `locked-inputs` for `entry` (DESIGN 11). Until its logic arrives
    the check is not run, which writes no record."""
    return NotRun(LOCKED_INPUTS, "locked-inputs logic arrives with the node module")


@dataclass(frozen=True, slots=True)
class Effects:
    """What the checks reach outside the process through, so a test can stand in for any of it."""

    clones_check: TwoClones = clones.two_clones
    docker: Docker = DOCKER
    locked_inputs: LockedInputs = locked_inputs_result


# ---- finding artifacts -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Found:
    """An artifact `test` can run checks on. `digest` is the core tarball's sha256, or the OCI image's
    manifest digest; `layout` is the image read from an OCI layout directory (None for a tarball)."""

    path: Path
    image: str
    digest: str
    layout: ocilayout.Layout | None = field(default=None)


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


def read_artifact(path: Path, name: ArtifactName) -> tuple[str, ocilayout.Layout | None] | str:
    """(the artifact's digest, its layout when it is an OCI image), or why it cannot be read."""
    if name.ext != oci.LAYOUT_EXT:
        return sha256_of(path), None
    try:
        layout = ocilayout.read_layout(path)
    except (oci.OciError, OSError) as error:
        return f"it is not a readable OCI image layout: {error}"
    return layout.descriptor.digest, layout


def find_artifacts(out_dir: Path, plan: Plan) -> tuple[list[Found], list[str]]:
    """The core tarballs and OCI image layouts in `out_dir` the plan knows, and a line for each one skipped,
    with its reason. A layout is a directory whose name an artifact name parses and whose manifest digest
    is the one the name says."""
    found: list[Found] = []
    skipped: list[str] = []
    for path in sorted(out_dir.iterdir()):
        name = parse_artifact_name(path.name)
        if name is None:
            continue
        kind = ARTIFACT_KINDS.get(name.ext)
        if kind is None or path.is_dir() != (name.ext == oci.LAYOUT_EXT):
            if path.is_file():
                skipped.append(
                    f"skipped {path.name}: only core tarballs and OCI image layouts are tested by this release"
                )
            continue
        image = image_of(name, plan)
        if image is None:
            skipped.append(f"skipped {path.name}: no image of the plan has this name and identity")
            continue
        if plan["images"][image]["kind"] != kind:
            skipped.append(f"skipped {path.name}: image {image} is of kind {plan['images'][image]['kind']}, not {kind}")
            continue
        read = read_artifact(path, name)
        if isinstance(read, str):
            skipped.append(f"skipped {path.name}: {read}")
            continue
        digest, layout = read
        if not digest.startswith(name.digest12):
            skipped.append(f"skipped {path.name}: its digest is {digest}, which its name does not say")
            continue
        found.append(Found(path, image, digest, layout))
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


def run_core_checks(
    found: Found, names: Sequence[str], plan: Plan, records_text: str | None, sources: Sources, effects: Effects
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
            outcomes.append(effects.clones_check(found.path))
    return outcomes


def planned_digest(entry: ImageEntry | None) -> str | None:
    """The hex digest of the artifact the plan names for an image (`sha256:<hex>`), when it names one."""
    artifact = entry.get("artifact") if entry is not None else None
    try:
        return oci.parse_digest(artifact) if isinstance(artifact, str) else None
    except oci.OciError:
        return None


def find_parent(found: Found, layout: ocilayout.Layout, plan: Plan, others: Sequence[Found]) -> ancestry.Parent | str:
    """The parent artifact of an OCI image as `ancestry` needs it, or why it is not available.

    The parent is the artifact of the plan's parent image among `others` (the artifacts of this run); when
    the same image has several, the one the manifest's `base.digest` names. A parent not in the output is
    known by the digest the plan names for it: for a core parent that is its first layer's digest, which
    is all `ancestry` needs; for an OCI parent its layers stay unknown.
    """
    entry = plan["images"][found.image]
    parent = entry["parent"]
    if parent is None:
        return "the image has no parent"
    local = [one for one in others if one.image == parent]
    if local:
        declared = layout.manifest.annotations.get(oci.BASE_DIGEST, "")
        chosen = next((one for one in local if f"sha256:{one.digest}" == declared), local[0])
        if chosen.layout is None:
            return ancestry.Parent(chosen.digest, (chosen.digest,))
        return ancestry.Parent(chosen.digest, tuple(one.digest for one in chosen.layout.manifest.layers))
    parent_entry = plan["images"].get(parent)
    digest = planned_digest(parent_entry)
    if digest is None:
        return f"the parent {parent} is not in the output and the plan names no artifact for it"
    if parent_entry is not None and parent_entry["kind"] == "core":
        return ancestry.Parent(digest, (digest,))
    return ancestry.Parent(digest, None)


def blob_hits(needle: str, layout: ocilayout.Layout) -> list[tarball.Hit]:
    """Where the snapshot ID is in the image's config or manifest bytes."""
    data = needle.encode()
    return [
        tarball.Hit("content", where)
        for where, blob in (("the image config", layout.config_bytes), ("the image manifest", layout.manifest_bytes))
        if data in blob
    ]


def run_oci_checks(
    found: Found,
    layout: ocilayout.Layout,
    names: Sequence[str],
    plan: Plan,
    records_text: str | None,
    effects: Effects,
    others: Sequence[Found],
) -> list[CheckOutcome]:
    """The named checks on one OCI image, in the order given.

    One pass reads each layer once (`layers.scan_image`), for the checks that look inside; the image is
    loaded into docker once, for the checks that run it, and removed afterwards by its ID.
    """
    entry = plan["images"][found.image]
    looking = NO_BUILD_SNAPSHOT in names and not snapshot.cannot_tell(plan["snapshot"], plan["baseline"])
    needle = plan["snapshot"] if looking else None
    inside = {PACKAGE_SET, NO_MACHINE_IDENTITY, SBOM_COMPLETE, NO_BUILD_SNAPSHOT, LOCKED_INPUTS}
    wanted = frozenset(machine_identity.WANTED | {packages.STATUS_PATH})
    scanned = (
        layers.scan_image(layout.layers, wanted, needle, NO_MACHINE_IDENTITY in names)
        if inside & set(names)
        else tarball.EMPTY
    )
    status = scanned.contents.get(packages.STATUS_PATH)
    running = bool({OCI_RUN, TWO_CLONES, LOCKED_INPUTS} & set(names))
    outcomes: list[CheckOutcome] = []
    with container.loaded(layout.path, effects.docker) if running else contextlib.nullcontext(None) as image:
        for name in names:
            if name == PACKAGE_SET:
                outcomes.append(packages.package_set(status, entry["packages"]))
            elif name == NO_MACHINE_IDENTITY:
                outcomes.append(
                    machine_identity.no_machine_identity(scanned.members, scanned.contents, scanned.key_files)
                )
            elif name == SBOM_COMPLETE:
                outcomes.append(
                    packages.sbom_complete(
                        status, sbom_of(records_text, found.digest), packages.locked_versions(entry["inputs"])
                    )
                )
            elif name == NO_BUILD_SNAPSHOT:
                hits = [*scanned.needle_hits, *(blob_hits(needle, layout) if needle else [])]
                outcomes.append(
                    snapshot.no_build_snapshot(plan["snapshot"], plan["baseline"], hits[: tarball.HITS_LIMIT])
                )
            elif name == ANCESTRY:
                outcomes.append(
                    ancestry.ancestry(
                        [one.digest for one in layout.manifest.layers],
                        layout.manifest.annotations,
                        find_parent(found, layout, plan, others),
                    )
                )
            elif name in (OCI_RUN, TWO_CLONES, LOCKED_INPUTS):
                outcomes.append(run_in_container(name, image, layout, entry, status, effects))
    return outcomes


def run_in_container(
    name: str,
    image: container.Loaded | str | None,
    layout: ocilayout.Layout,
    entry: ImageEntry,
    status: bytes | None,
    effects: Effects,
) -> CheckOutcome:
    """One check that needs the image running: not run, with docker's reason, when it could not be loaded."""
    if not isinstance(image, container.Loaded):
        return NotRun(name, image or "the image was not loaded")
    try:
        if name == OCI_RUN:
            return container.oci_run(layout.config, image, effects.docker)
        if name == TWO_CLONES:
            return container.two_clones(image, effects.docker)
        return effects.locked_inputs(entry, status, container.run_probe(image.image, effects.docker))
    except (OSError, subprocess.SubprocessError) as error:
        return NotRun(name, f"docker failed: {error}")


def run_checks(
    found: Found,
    names: Sequence[str],
    plan: Plan,
    records_text: str | None,
    sources: Sources,
    effects: Effects,
    others: Sequence[Found] = (),
) -> list[CheckOutcome]:
    """The named checks on one artifact, in the order given; `others` are the run's other artifacts, where
    an image's parent is looked for."""
    if found.layout is None:
        return run_core_checks(found, names, plan, records_text, sources, effects)
    return run_oci_checks(found, found.layout, names, plan, records_text, effects, others)


def describe(image: str, outcome: CheckOutcome) -> str:
    if isinstance(outcome, NotRun):
        return f"{image}: {outcome.check} not run: {outcome.reason}"
    detail = [*outcome.failed, *outcome.warned]
    return f"{image}: {outcome.check} {outcome.outcome}" + (": " + "; ".join(detail) if detail else "")


def choose(requested: Sequence[str], entry: ImageEntry) -> tuple[list[str], list[NotRun]]:
    """(the checks to run, the required checks this release has no code for) for one image."""
    runs = CHECKS_OF_KIND.get(entry["kind"], ())
    if requested:
        return [str(name) for name in runs if name in requested], []
    runnable = [str(name) for name in runs if name in entry["checks"]]
    others = [
        NotRun(name, "not a built-in check this release runs (a consumer's own check is attested with `attest`)")
        for name in entry["checks"]
        if name not in runs
    ]
    return runnable, others


def test_command(
    out_dir: Path,
    requested: Sequence[str],
    sources: Sources,
    out: TextIO,
    effects: Effects = Effects(),
    url: str = "",
) -> int:
    """Run the plan's required checks (or only `requested`) on every core tarball and OCI image layout in `out_dir`.

    Returns 1 when any check FAILED, else 0; raises Usage for a name that is not a check of core or oci and
    Failed when plan.json or an artifact cannot be read.
    """
    known = sorted({name for names in CHECKS_OF_KIND.values() for name in names})
    unknown = sorted(set(requested) - set(known))
    if unknown:
        raise Usage(f"--check {', '.join(unknown)}: not a check of a core or OCI image (one of {', '.join(known)})")
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
            outcomes = run_checks(one, names, plan, records_text, sources, effects, found)
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
