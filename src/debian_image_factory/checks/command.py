"""`debian-image-factory test OUT`: run the built-in checks on the artifacts in OUT and attest each result.

OUT is what a build left: `plan.json`, the artifacts named by `published.artifact_name` (a core or OS root
tarball, an installer kit, or an OCI image layout directory), and `<digest>.intoto.jsonl` beside each. Each
check that ran appends one in-toto test-result statement to its artifact's records file; a check that could
not run is listed and writes nothing. A boot check that failed leaves each boot's serial log beside its
artifact.
"""

import contextlib
import hashlib
import subprocess
import tarfile
import uuid
import zlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, TextIO, cast

import input_lock.records as rec

from .. import fileartifacts, incus, oci, ocilayout, published, records, squashfs
from ..commands import Failed, Sources, Usage
from ..definition import Module
from ..planfile import ImageEntry, Plan, read_plan
from ..published import ArtifactName, parse_artifact_name, records_name_for
from . import (
    ancestry,
    clones,
    container,
    incus_host,
    inputs,
    kit,
    layers,
    machine_identity,
    newc,
    packages,
    resolution,
    snapshot,
    squashfs_scan,
    tarball,
    vm,
    vmrun,
)
from .container import ProbeRunner
from .dockerio import DOCKER, Docker
from .model import (
    ANCESTRY,
    CHECKS_OF_KIND,
    INCUS_BOOT,
    INSTALLER_BOOT,
    LOCKED_INPUTS,
    NO_BUILD_SNAPSHOT,
    NO_MACHINE_IDENTITY,
    OCI_RUN,
    OS_BOOT,
    PACKAGE_SET,
    SAME_RESOLUTION,
    SBOM_COMPLETE,
    TWO_CLONES,
    CheckOutcome,
    NotRun,
    Result,
    result,
    split,
)

CHUNK = 1024 * 1024

ARTIFACT_KINDS: dict[str, tuple[str, ...]] = {
    "tar.gz": ("core", "os"),
    "tar": ("installer",),
    oci.LAYOUT_EXT: ("oci",),
    incus.METADATA_EXT: ("incus",),
}
"""The artifact name extensions `test` reads, and the kinds of image each can be: a core and an OS root are
both a `.tar.gz`, so the plan entry's kind tells them apart."""
BOOT_KINDS: Final = ("installer", "os")

type Clock = Callable[[], datetime]
type TwoClones = Callable[[Path], CheckOutcome]
type BootInstaller = Callable[[Path, int, vmrun.Vm], list[vm.Boot] | vmrun.Unready]
type BootOs = Callable[[Path, vmrun.RootFacts, int, vmrun.Vm], list[vm.Boot] | vmrun.Unready]
type LockedInputs = Callable[[ImageEntry, bytes | None, ProbeRunner, Mapping[str, Module] | None], CheckOutcome]
"""The `locked-inputs` check: the plan entry, the image's dpkg status (None when it has none), a runner
that runs a `modules.Probe` in the image and gives (exit status, standard output), and the definition's
modules (None when `test` was given no definition)."""


def locked_inputs_result(
    entry: ImageEntry, status: bytes | None, run: ProbeRunner, modules: Mapping[str, Module] | None
) -> CheckOutcome:
    """`locked-inputs` for `entry` (DESIGN 11): apt entries by the dpkg status, module entries by their
    module's probes, keyrings named by the plan's `trust` as trust roots. A module's probe needs its table
    (a node prefix, say), which only the definition has: without one the check is not run."""
    used = {str(fields.get("module")) for fields in entry["inputs"].values() if fields.get("module")}
    if modules is None and used:
        return NotRun(LOCKED_INPUTS, "the image's modules are probed with their tables: pass --definition")
    trust_roots = {signer["signed_by"] for signer in entry["trust"].values() if "signed_by" in signer}
    return inputs.locked_inputs(entry["inputs"], modules or {}, status, run, trust_roots)


@dataclass(frozen=True, slots=True)
class Effects:
    """What the checks reach outside the process through, so a test can stand in for any of it."""

    clones_check: TwoClones = clones.two_clones
    docker: Docker = DOCKER
    incus: incus_host.Runner = incus_host.run_incus
    locked_inputs: LockedInputs = locked_inputs_result
    modules: Mapping[str, Module] | None = None
    """The definition's modules, for the probes of `locked-inputs`; None when `test` has no definition."""
    parents: tuple[Path, ...] = ()
    """Parent artifacts outside OUT, for `ancestry` of an OS or installer child (`test --parent`)."""
    vm: vmrun.Vm = vmrun.VM
    boot_installer: BootInstaller = vmrun.boot_installer
    boot_os: BootOs = vmrun.boot_os
    clock: Clock = lambda: datetime.now(UTC)
    new_run_id: Callable[[], str] = lambda: uuid.uuid4().hex
    """The time and the run ids `test` stamps on its results (DESIGN 8.2)."""


# ---- finding artifacts -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Found:
    """An artifact `test` can run checks on. `digest` is a tarball's sha256 (core, OS root, installer kit),
    or the OCI image's manifest digest; `layout` is the image read from an OCI layout directory (None for a
    tarball); `kind` is the plan entry's."""

    path: Path
    image: str
    digest: str
    layout: ocilayout.Layout | None = field(default=None)
    kind: str = "core"


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
    """(the artifact's digest, its layout when it is an OCI image), or why it cannot be read. An Incus
    image's digest is the fingerprint of its metadata tarball (`path`) and the rootfs beside it."""
    if name.ext == incus.METADATA_EXT:
        read = fileartifacts.read_artifact(path, name)
        return read.reason if isinstance(read, published.Rejected) else (read.digest, None)
    if name.ext != oci.LAYOUT_EXT:
        return sha256_of(path), None
    try:
        layout = ocilayout.read_layout(path)
    except (oci.OciError, OSError) as error:
        return f"it is not a readable OCI image layout: {error}"
    return layout.descriptor.digest, layout


def find_artifacts(out_dir: Path, plan: Plan) -> tuple[list[Found], list[str]]:
    """The core and OS tarballs, installer kits and OCI image layouts in `out_dir` the plan knows, and a line
    for each one skipped, with its reason. A layout is a directory whose name an artifact name parses and
    whose manifest digest is the one the name says."""
    found: list[Found] = []
    skipped: list[str] = []
    for path in sorted(out_dir.iterdir()):
        name = parse_artifact_name(path.name)
        if name is None or fileartifacts.is_companion(name):
            continue  # an Incus rootfs is tested with its metadata tarball
        kinds = ARTIFACT_KINDS.get(name.ext)
        if kinds is None or path.is_dir() != (name.ext == oci.LAYOUT_EXT):
            if path.is_file():
                skipped.append(
                    f"skipped {path.name}: only core and OS tarballs, installer kits, OCI image layouts and"
                    " Incus images are tested by this release"
                )
            continue
        image = image_of(name, plan)
        if image is None:
            skipped.append(f"skipped {path.name}: no image of the plan has this name and identity")
            continue
        kind = plan["images"][image]["kind"]
        if kind not in kinds:
            skipped.append(f"skipped {path.name}: image {image} is of kind {kind}, not {' or '.join(kinds)}")
            continue
        read = read_artifact(path, name)
        if isinstance(read, str):
            skipped.append(f"skipped {path.name}: {read}")
            continue
        digest, layout = read
        if not digest.startswith(name.digest12):
            skipped.append(f"skipped {path.name}: its digest is {digest}, which its name does not say")
            continue
        found.append(Found(path, image, digest, layout, kind))
    return found, skipped


# ---- records ---------------------------------------------------------------------------------------


def sbom_statement_of(
    records_text: str | None, digest: str
) -> tuple[Mapping[str, object], list[tuple[str, str]]] | str:
    """(the predicate, the subjects as (name, sha256)) of the one SBOM statement about `digest`, or why there
    is not exactly one."""
    if records_text is None:
        return "there is no records file for this artifact"
    try:
        statements = records.decode_statements(records_text)
    except records.RecordsError as error:
        return f"the records file cannot be read: {error}"
    documents: list[tuple[Mapping[str, object], list[tuple[str, str]]]] = []
    for one in statements:
        subjects, predicate = one.get("subject"), one.get("predicate")
        named = [
            (str(s.get("name", "")), str(s["digest"].get("sha256", "")))
            for s in (subjects if isinstance(subjects, list) else [])
            if isinstance(s, dict) and isinstance(s.get("digest"), dict)
        ]
        about = any(sha == digest for _, sha in named)
        if about and one.get("predicateType") == rec.SPDX_PREDICATE and isinstance(predicate, dict):
            documents.append(({str(key): value for key, value in predicate.items()}, named))
    if len(documents) != 1:
        return f"the records hold {len(documents)} SBOM statements about this artifact, not one"
    return documents[0]


def sbom_of(records_text: str | None, digest: str) -> Mapping[str, object] | str:
    """The predicate of the one SBOM statement about `digest`, or why there is not exactly one."""
    found = sbom_statement_of(records_text, digest)
    return found if isinstance(found, str) else found[0]


@dataclass(frozen=True, slots=True)
class Run:
    """The identity of one run of checks: what `test` or `attest` stamps on each result it records, so that
    two runs never write the same line and "the last result wins" (DESIGN 7.4) has a time to go by."""

    run_id: str
    started_on: str
    finished_on: str


def rfc3339(moment: datetime) -> str:
    """`moment` as an RFC 3339 UTC time with microseconds, which sorts as text and as an instant."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def run_entry(run: Run) -> rec.ResourceDescriptor:
    """The `configuration` entry that says which run made a result: in-toto's ResourceDescriptor, named
    `run`, with the run's id and times in its `annotations` (DESIGN 8.2)."""
    notes = {"runId": run.run_id, "startedOn": run.started_on, "finishedOn": run.finished_on}
    # `annotations` is in-toto's ResourceDescriptor v1, not in input-lock's TypedDict
    return cast(rec.ResourceDescriptor, {"name": published.RUN_ENTRY, "annotations": notes})


def test_result_line(found: Found, outcome: Result, url: str, run: Run) -> str:
    """One DSSE envelope line (with its newline) attesting `outcome` for the artifact, as made by `run`."""
    predicate = rec.test_result(
        outcome.outcome,
        [{"name": outcome.check, "uri": f"{records.CHECKS_DOC}#{outcome.check}"}, run_entry(run)],
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
        return effects.locked_inputs(entry, status, container.run_probe(image.image, effects.docker), effects.modules)
    except (OSError, subprocess.SubprocessError) as error:
        return NotRun(name, f"docker failed: {error}")


def file_parent(found: Found, plan: Plan, others: Sequence[Found]) -> Found | str:
    """The parent artifact of an Incus image among the run's artifacts, or why it is not available here
    (none, or several builds of the parent image, which leave the comparison ambiguous)."""
    parent = plan["images"][found.image]["parent"]
    if parent is None:
        return "the image has no parent"
    local = [one for one in others if one.image == parent]
    if not local:
        return f"the parent {parent} is not in the output, so its files cannot be compared"
    return local[0] if len(local) == 1 else f"the output holds {len(local)} builds of the parent {parent}"


def parent_named(records_text: str | None, digest: str) -> str | None:
    """The parent digest the artifact's provenance names (its `parent: <image>` dependency), when its
    provenance records (several, after a rebuild of the same bytes) are readable and all name the same one."""
    if records_text is None:
        return None
    try:
        builds = [
            one.build
            for one in published.parse_envelopes(records_text)
            if one.build is not None and any(subject.sha256 == digest for subject in one.subjects)
        ]
    except published.RecordsError:
        return None
    parents = {build.ancestors[0][1] if build.ancestors else None for build in builds}
    return parents.pop() if len(parents) == 1 else None  # every record of a rebuild must agree


def scan_parent(parent: Found, wanted: frozenset[str]) -> tarball.Scan:
    if parent.path.name.endswith(f".{incus.METADATA_EXT}"):
        rootfs = parent.path.with_name(incus.rootfs_of(parent.path.name) or "")
        return squashfs_scan.scan_squashfs(rootfs, wanted, None, False)
    return tarball.scan_tarball(parent.path, wanted, None, False)


def run_incus_checks(
    found: Found,
    names: Sequence[str],
    plan: Plan,
    records_text: str | None,
    effects: Effects,
    others: Sequence[Found],
) -> list[CheckOutcome]:
    """The named checks on one Incus image, in the order given. One pass reads the rootfs, and the
    metadata tarball is searched for the snapshot ID too; the image is imported into Incus once for the
    checks that launch it, and deleted afterwards."""
    entry = plan["images"][found.image]
    rootfs = found.path.with_name(incus.rootfs_of(found.path.name) or "")
    looking = NO_BUILD_SNAPSHOT in names and not snapshot.cannot_tell(plan["snapshot"], plan["baseline"])
    needle = plan["snapshot"] if looking else None
    inside = {PACKAGE_SET, NO_MACHINE_IDENTITY, SBOM_COMPLETE, NO_BUILD_SNAPSHOT, ANCESTRY}
    wanted = frozenset(machine_identity.WANTED | {packages.STATUS_PATH})
    keys = NO_MACHINE_IDENTITY in names
    scanned = squashfs_scan.scan_squashfs(rootfs, wanted, needle, keys) if inside & set(names) else tarball.EMPTY
    status = scanned.contents.get(packages.STATUS_PATH)
    outcomes: list[CheckOutcome] = []
    hosted = [name for name in names if name in (INCUS_BOOT, TWO_CLONES)]
    imported: incus_host.Imported | str = "not needed"
    if hosted:
        problem = incus_host.incus_problem(effects.incus)
        try:
            imported = problem or incus_host.import_image(found.path, rootfs, found.digest, effects.incus)
        except (OSError, subprocess.SubprocessError) as error:
            imported = f"incus image import failed: {error}"
    try:
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
                meta = tarball.scan_tarball(found.path, frozenset(), needle, False) if needle else tarball.EMPTY
                hits = [*scanned.needle_hits, *(tarball.Hit(h.where, f"metadata {h.path}") for h in meta.needle_hits)]
                outcomes.append(
                    snapshot.no_build_snapshot(plan["snapshot"], plan["baseline"], hits[: tarball.HITS_LIMIT])
                )
            elif name == ANCESTRY:
                parent = file_parent(found, plan, others)
                if isinstance(parent, str):
                    outcomes.append(NotRun(ANCESTRY, parent))
                else:
                    held = scan_parent(parent, frozenset())
                    outcomes.append(
                        ancestry.root_ancestry(
                            scanned.members,
                            held.members,
                            parent.digest,
                            parent_named(records_text, found.digest),
                            recorded_removals(records_text, found.digest),
                        )
                    )
            elif name in hosted:
                if not isinstance(imported, incus_host.Imported):
                    outcomes.append(NotRun(name, imported))
                elif name == INCUS_BOOT:
                    outcomes.append(incus_host.incus_boot(imported, effects.incus))
                else:
                    ssh = any(package[0] == "openssh-server" for package in entry["packages"])
                    outcomes.append(incus_host.two_clones(imported, ssh=ssh, run=effects.incus))
    finally:
        if isinstance(imported, incus_host.Imported):
            incus_host.forget_image(imported, effects.incus)
    return outcomes


# ---- installer kits and OS roots --------------------------------------------------------------------


def scan_root(
    path: Path, kind: str, wanted: frozenset[str], needle: str | None, keys: bool, keep: tarball.Keep
) -> tarball.Scan:
    """One pass over the root filesystem an artifact holds: an installer kit's initrd, or a tarball's members."""
    if kind == "installer":
        return kit.scan_kit(path, wanted, needle, keys, keep)
    return tarball.scan_tarball(path, wanted, needle, keys, keep)


def parent_candidates(parent: str, plan: Plan, others: Sequence[Found], given: Sequence[Path]) -> list[Found]:
    """The artifacts of image `parent` in this run's output and among the `--parent` files (whose names say
    their image and digest; one whose bytes do not match its name is left out)."""
    found = [one for one in others if one.image == parent]
    entry = plan["images"].get(parent)
    for path in given:
        name = parse_artifact_name(path.name)
        if name is None or name.image != parent or entry is None or path.is_dir():
            continue
        digest = sha256_of(path)
        if digest.startswith(name.digest12) and all(one.digest != digest for one in found):
            found.append(Found(path, parent, digest, None, entry["kind"]))
    return found


def root_parent(
    found: Found, plan: Plan, others: Sequence[Found], given: Sequence[Path]
) -> tuple[str, tuple[tarball.Member, ...]] | str:
    """The parent's root filesystem for `ancestry` of an OS root or an installer kit (an Incus image's is
    `file_parent`'s), or why it is not available. When there are several artifacts of the parent image,
    the one the plan names is taken."""
    parent = plan["images"][found.image]["parent"]
    if parent is None:
        return "the image has no parent"
    candidates = parent_candidates(parent, plan, others, given)
    planned = planned_digest(plan["images"].get(parent))
    chosen = next((one for one in candidates if one.digest == planned), None)
    if chosen is None and len(candidates) == 1:
        chosen = candidates[0]
    if chosen is None:
        if candidates:
            return f"there are {len(candidates)} artifacts of the parent {parent} and the plan names none of them"
        return f"the parent {parent} is not in the output and not given with --parent"
    scanned = scan_root(chosen.path, chosen.kind, frozenset(), None, False, tarball.keep_none)
    return chosen.digest, scanned.members


def recorded_removals(records_text: str | None, digest: str) -> list[str] | str:
    """The paths the artifact's provenance says its build removed from the parent (`removedFromParent`), or
    why they cannot be read. Several provenance records (a rebuild of the same bytes) must agree."""
    if records_text is None:
        return "there is no records file for this artifact"
    try:
        statements = records.decode_statements(records_text)
    except records.RecordsError as error:
        return f"the records file cannot be read: {error}"
    found: list[list[str]] = []
    for one in statements:
        subjects, predicate = one.get("subject"), one.get("predicate")
        if one.get("predicateType") != rec.PROVENANCE_PREDICATE or not isinstance(predicate, dict):
            continue
        if not isinstance(subjects, list) or not any(
            isinstance(s, dict) and isinstance(s.get("digest"), dict) and s["digest"].get("sha256") == digest
            for s in subjects
        ):
            continue
        definition_ = predicate.get("buildDefinition")
        internal = definition_.get("internalParameters") if isinstance(definition_, dict) else None
        paths = internal.get("removedFromParent") if isinstance(internal, dict) else None
        if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
            return "the provenance records no removedFromParent list"
        found.append([str(path) for path in paths])
    if not found:
        return "there is no provenance for this artifact"
    if any(paths != found[0] for paths in found):
        return "the provenance records disagree on what the build removed from the parent"
    return found[0]


def uses_module_probes(entry: ImageEntry) -> bool:
    """Whether `locked-inputs` must run a module's probe in the image: an entry a module installs that is
    neither an apt package nor a trust root."""
    roots = {signer["signed_by"] for signer in entry["trust"].values() if "signed_by" in signer}
    return any(
        fields.get("module") and not fields.get("apt") and name not in roots for name, fields in entry["inputs"].items()
    )


def no_probes(probe: object) -> tuple[int, str]:
    raise AssertionError("no module entry, so no probe runs")


def boot_kind_locked_inputs(found: Found, entry: ImageEntry, status: bytes | None, effects: Effects) -> CheckOutcome:
    """`locked-inputs` for an OS root or an installer: apt entries by the dpkg status; module entries by their
    probes, run in a container imported from the OS root. An installer's initrd is not made into a container
    image by this release, so its module entries are not probed and the check is not run."""
    if not uses_module_probes(entry) or effects.modules is None:
        return effects.locked_inputs(entry, status, no_probes, effects.modules)
    if found.kind == "installer":
        return NotRun(
            LOCKED_INPUTS,
            "an installer's modules are probed in its root, which this release does not run as a container",
        )
    try:
        with container.imported(found.path, effects.docker) as image:
            if not isinstance(image, container.Loaded):
                return NotRun(LOCKED_INPUTS, image)
            return effects.locked_inputs(
                entry, status, container.run_probe(image.image, effects.docker), effects.modules
            )
    except (OSError, subprocess.SubprocessError) as error:
        return NotRun(LOCKED_INPUTS, f"docker failed: {error}")


def boots_for(
    found: Found, names: Sequence[str], effects: Effects
) -> tuple[list[vm.Boot] | vmrun.Unready | None, vmrun.RootFacts | None]:
    """The boots the checks need (two when `two-clones` runs, which also serve the boot check), and for an
    OS root what its tarball says about /boot; (None, None) when no check boots."""
    boot_check = INSTALLER_BOOT if found.kind == "installer" else OS_BOOT
    count = 2 if TWO_CLONES in names else 1 if boot_check in names else 0
    if count == 0:
        return None, None
    if found.kind == "installer":
        return effects.boot_installer(found.path, count, effects.vm), None
    facts = vmrun.root_facts(found.path)
    return effects.boot_os(found.path, facts, count, effects.vm), facts


def boot_outcome(
    name: str,
    found: Found,
    boots: list[vm.Boot] | vmrun.Unready | None,
    facts: vmrun.RootFacts | None,
    the_kit: kit.Kit | None,
    status: bytes | None,
) -> CheckOutcome:
    """`installer-boot`, `os-boot` or `two-clones` from the boots that ran. Boots that did not happen because
    of this machine are not run; because of the artifact (an OS without GRUB for UEFI), failed."""
    if boots is None:
        return NotRun(name, "no boot ran")
    if isinstance(boots, vmrun.Unready):
        if not boots.artifact_fault:
            return NotRun(name, boots.reason)
        return result(name, [], failed=[f"bootable: {boots.reason}"])
    artifact = found.path.name
    if name == TWO_CLONES:
        return vm.two_clones(boots, artifact)
    if name == INSTALLER_BOOT:
        assert the_kit is not None
        return vm.installer_boot(the_kit.kernel, the_kit.problems, boots[0], artifact)
    installed = packages.installed(status)
    wants_ssh = not isinstance(installed, str) and any(p[0] == "openssh-server" for p in installed)
    kernels = facts.kernels if facts is not None else ()
    return vm.os_boot(kernels[0] if len(kernels) == 1 else kernels, wants_ssh, boots[0], artifact)


def keep_serial_logs(
    found: Found, boots: list[vm.Boot] | vmrun.Unready | None, outcomes: Sequence[CheckOutcome]
) -> None:
    """When a check on the boots failed, each boot's serial log goes beside the artifact (vm.log_name)."""
    booting = {INSTALLER_BOOT, OS_BOOT, TWO_CLONES}
    failed = any(isinstance(o, Result) and o.check in booting and o.outcome == "FAILED" for o in outcomes)
    if not failed or not isinstance(boots, list):
        return
    for n, boot in enumerate(boots, 1):
        (found.path.parent / vm.log_name(found.path.name, n)).write_text(boot.serial, encoding="utf-8")


def run_boot_kind_checks(
    found: Found,
    names: Sequence[str],
    plan: Plan,
    records_text: str | None,
    effects: Effects,
    others: Sequence[Found],
) -> list[CheckOutcome]:
    """The named checks on an OS root tarball or an installer kit, in the order given. One pass reads the
    root (the kit's initrd); the boots run once for every check that boots."""
    entry = plan["images"][found.image]
    looking = NO_BUILD_SNAPSHOT in names and not snapshot.cannot_tell(plan["snapshot"], plan["baseline"])
    needle = plan["snapshot"] if looking else None
    inside = {PACKAGE_SET, NO_MACHINE_IDENTITY, SBOM_COMPLETE, NO_BUILD_SNAPSHOT, LOCKED_INPUTS, ANCESTRY, OS_BOOT}
    wanted = frozenset(machine_identity.WANTED | {packages.STATUS_PATH})
    the_kit = kit.read_kit(found.path) if found.kind == "installer" else None
    scanned = (
        scan_root(found.path, found.kind, wanted, needle, NO_MACHINE_IDENTITY in names, tarball.keep_none)
        if inside & set(names)
        else tarball.EMPTY
    )
    status = scanned.contents.get(packages.STATUS_PATH)
    boots, facts = boots_for(found, names, effects)
    outcomes: list[CheckOutcome] = []
    for name in names:
        if name == PACKAGE_SET:
            outcomes.append(packages.package_set(status, entry["packages"]))
        elif name == NO_MACHINE_IDENTITY:
            outcomes.append(machine_identity.no_machine_identity(scanned.members, scanned.contents, scanned.key_files))
        elif name == SBOM_COMPLETE:
            outcomes.append(kit_sbom_complete(found, status, records_text, entry, the_kit))
        elif name == NO_BUILD_SNAPSHOT:
            outcomes.append(snapshot.no_build_snapshot(plan["snapshot"], plan["baseline"], scanned.needle_hits))
        elif name == ANCESTRY:
            parent_root = root_parent(found, plan, others, effects.parents)
            digest, members = ("", ()) if isinstance(parent_root, str) else parent_root
            outcomes.append(
                ancestry.root_ancestry(
                    scanned.members,
                    parent_root if isinstance(parent_root, str) else members,
                    digest,
                    parent_named(records_text, found.digest),
                    recorded_removals(records_text, found.digest),
                )
            )
        elif name == LOCKED_INPUTS:
            outcomes.append(boot_kind_locked_inputs(found, entry, status, effects))
        elif name in (INSTALLER_BOOT, OS_BOOT, TWO_CLONES):
            outcomes.append(boot_outcome(name, found, boots, facts, the_kit, status))
    keep_serial_logs(found, boots, outcomes)
    return outcomes


def kit_sbom_complete(
    found: Found, status: bytes | None, records_text: str | None, entry: ImageEntry, the_kit: kit.Kit | None
) -> Result:
    """`sbom-complete`, and for an installer kit also its subjects: the kit, then `vmlinuz` and `initrd.img`."""
    statement = sbom_statement_of(records_text, found.digest)
    document = statement if isinstance(statement, str) else statement[0]
    base = packages.sbom_complete(status, document, packages.locked_versions(entry["inputs"]))
    if the_kit is None or isinstance(statement, str):
        return base
    ok, bad = split(
        "subjects-are-the-kit-files", kit.subjects_problems(statement[1], found.path.name, found.digest, the_kit)
    )
    return result(SBOM_COMPLETE, [*base.passed, *ok], base.warned, [*base.failed, *bad])


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
    kind = plan["images"][found.image]["kind"]
    if kind == "incus":
        return run_incus_checks(found, names, plan, records_text, effects, others)
    if found.layout is not None:
        return run_oci_checks(found, found.layout, names, plan, records_text, effects, others)
    if found.kind in BOOT_KINDS:
        return run_boot_kind_checks(found, names, plan, records_text, effects, others)
    return run_core_checks(found, names, plan, records_text, sources, effects)


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
    """Run the plan's required checks (or only `requested`) on every artifact in `out_dir` (core and OS
    tarballs, installer kits, OCI image layouts, Incus images).

    Returns 1 when any check FAILED, else 0; raises Usage for a name that is not a check of any kind and
    Failed when plan.json or an artifact cannot be read.
    """
    known = sorted({name for names in CHECKS_OF_KIND.values() for name in names})
    unknown = sorted(set(requested) - set(known))
    if unknown:
        raise Usage(f"--check {', '.join(unknown)}: not a check this release runs (one of {', '.join(known)})")
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
    run_id = effects.new_run_id()
    for one in found:
        names, others = choose(requested, plan["images"][one.image])
        records_path = out_dir / records_name_for(one.digest)
        try:
            records_text = records_path.read_text(encoding="utf-8") if records_path.exists() else None
            started = rfc3339(effects.clock())
            outcomes = run_checks(one, names, plan, records_text, sources, effects, found)
            run = Run(run_id, started, rfc3339(effects.clock()))
            lines = [test_result_line(one, o, url, run) for o in outcomes if isinstance(o, Result)]
            append_records(records_path, lines)
        except (OSError, EOFError, UnicodeDecodeError, zlib.error) as error:
            raise Failed(f"{one.path.name}: cannot be tested: {error}") from None
        except tarfile.TarError as error:
            raise Failed(f"{one.path.name}: is not a readable tarball: {error}") from None
        except squashfs.SquashfsError as error:
            raise Failed(f"{one.path.name}: its rootfs is not a readable squashfs: {error}") from None
        except newc.NewcError as error:
            raise Failed(f"{one.path.name}: its initrd is not a readable newc archive: {error}") from None
        for outcome in [*outcomes, *others]:
            out.write(describe(one.image, outcome) + "\n")
            if isinstance(outcome, Result) and outcome.outcome == "FAILED":
                status = 1
    return status
