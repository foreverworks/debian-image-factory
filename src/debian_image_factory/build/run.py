"""The build edge (DESIGN 5.3, 5.4, 8): run the builder container on a plan, write artifacts and records.

`build PLAN --out OUT` rebuilds nothing the plan does not ask for. Before it builds an image it
recomputes the image's identity from the lock, the definition and its files with the plan's package
set; a plan that no longer matches them is refused, so an artifact's records always describe what it
was built from. The builder runs with `--network none` and reads only the partial mirror `fetch` laid
out and the files of this build's work directory.
"""

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Final, TextIO

import input_lock
from input_lock import Lock, Package
from input_lock.records import Statement, statement, subject

from .. import (
    ENGINE,
    __version__,
    commands,
    debian,
    definition,
    fetch,
    fileartifacts,
    identity,
    incus,
    modules,
    oci,
    ocilayout,
    planfile,
    published,
    records,
    registry,
    resolve,
    squashfs,
)
from .. import plan as plan_module
from .. import tools as builder
from ..identity import FileFact
from ..published import artifact_name, records_name_for
from . import boot, core, parents
from . import incus as incus_build
from . import oci as oci_build

SUPPORTED_KINDS: Final = ("core", "oci", "incus")
"""The kinds this release builds; the others arrive with their milestones."""
EXTENSIONS: Final[Mapping[str, str]] = {"core": "tar.gz", "oci": oci.LAYOUT_EXT, "incus": incus.METADATA_EXT}
LAYER_PROGRAM: Final = "layer.py"
"""The layer writer's file name in the package and in the work directory."""
PLAN_COPY: Final = "plan.json"
"""The plan a build ran from, copied byte for byte into the output directory for `test`."""


@dataclass(frozen=True, slots=True)
class Builder:
    """The builder image a build runs in: its reference, its digest and how its root maps to the host."""

    reference: str
    digest: str
    """The image ID (`sha256:<hex>`), recorded in provenance."""
    owner: str | None
    """`uid:gid` to hand the artifact back to, when the container's root is the host's."""


# ---- the builder container ----------------------------------------------------------------------


def docker(*args: str) -> str:
    """Run a docker command and return its standard output. Raises Failed with docker's own message."""
    try:
        done = subprocess.run(["docker", *args], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise commands.Failed("docker is needed to build, and none is on PATH") from None
    if done.returncode != 0:
        raise commands.Failed(f"docker {args[0]} failed: {done.stderr.strip() or done.stdout.strip()}")
    return done.stdout


def open_builder(reference: str) -> Builder:
    """The builder image, after checking that its byte-writing tools are exactly the ones this release
    pins (tools.json): another version would write other bytes under the same identities."""
    digest = docker("image", "inspect", "--format", "{{.Id}}", reference).strip()
    if not digest.startswith("sha256:"):
        raise commands.Failed(f"docker image inspect {reference}: unexpected image ID {digest!r}")
    listing = docker(
        "run", "--rm", "--network", "none", reference,
        "dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Architecture}\n", *builder.TOOL_PACKAGES,
    )  # fmt: skip
    found = sorted(tuple(line.split("\t")) for line in listing.splitlines() if line.strip())
    expected = sorted(builder.builder_tools())
    if found != expected:
        moved = sorted(set(map(str, found)) ^ set(map(str, expected)))
        raise commands.Failed(
            f"builder {reference}: its tools are not the ones this release pins ({', '.join(moved)}); "
            "build it with scripts/builder build at the snapshot of the factory's own lock"
        )
    security = docker("info", "--format", "{{json .SecurityOptions}}")
    owner = None if "rootless" in security else f"{os.getuid()}:{os.getgid()}"
    return Builder(reference, digest, owner)


def run_builder(builder_: Builder, work: Path, mirror: Path, log: Path) -> None:
    """Run build.sh in the builder with no network, the mirror read-only; its output goes to `log`."""
    args = [
        "docker", "run", "--rm", "--privileged", "--network", "none",
        "-v", f"{mirror.resolve()}:{core.MIRROR}:ro",
        "-v", f"{work.resolve()}:{core.WORK}",
        builder_.reference, "sh", f"{core.WORK}/build.sh",
    ]  # fmt: skip
    with log.open("wb") as handle:
        done = subprocess.run(args, stdout=handle, stderr=subprocess.STDOUT, check=False)
    if done.returncode != 0:
        tail = log.read_text(encoding="utf-8", errors="replace").splitlines()[-15:]
        raise commands.Failed(f"the builder failed (exit {done.returncode}); the end of {log}:\n" + "\n".join(tail))


# ---- the work directory -------------------------------------------------------------------------


def files_tar(root: Path, tree: str, facts: Mapping[str, FileFact], source_date_epoch: int) -> bytes:
    """The definition's file tree as a tar to unpack over the image's root: owned by root, modes as
    the identity saw them (0755 or 0644), time stamps at source_date_epoch, entries sorted."""
    buffer = io.BytesIO()
    prefix = f"{tree.rstrip('/')}/"
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for relative, fact in sorted(facts.items()):
            if not relative.startswith(prefix):
                continue
            info = tarfile.TarInfo("./" + relative.removeprefix(prefix))
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = source_date_epoch
            info.mode = int(fact.mode, 8)
            if fact.directory:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif fact.link is not None:
                info.type = tarfile.SYMTYPE
                info.linkname = fact.link
                info.mode = 0o777
                archive.addfile(info)
            else:
                data = (root / relative).read_bytes()
                if hashlib.sha256(data).hexdigest() != fact.sha256:
                    raise commands.Failed(f"{relative} changed while the build read it: plan again")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def input_file_name(fields: Mapping[str, input_lock.Value]) -> str:
    """The file name a hook finds a locked input under: the last segment of its rendered URL."""
    return modules.input_file_name(fields)


def stage_run(
    work: Path,
    *,
    loaded: commands.Loaded,
    lock: Lock,
    image: str,
    entry: planfile.ImageEntry,
    cache: Path,
    scripts: Sequence[str],
) -> None:
    """The hooks, the verified file of every lock entry the image uses, and build.env, under `work/run`:
    whatever a hook or a module reads. Inputs are staged whenever the image has lock entries, for hooks
    and modules alike."""
    if not scripts and not entry["inputs"]:
        return
    run = work / "run"
    (run / "hooks").mkdir(parents=True)
    for index, hook in enumerate(scripts, start=1):
        target = run / "hooks" / core.hook_name(index, hook)
        shutil.copyfile(loaded.root / hook, target)
        target.chmod(0o755)
    pairs: list[tuple[str, str]] = [("LOCK_ENTRIES", " ".join(sorted(entry["inputs"])))]
    for name in sorted(entry["inputs"]):
        pairs.extend(input_lock.entry_env(name, lock["inputs"][name]))
        source = fetch.input_path(cache, entry["inputs"][name])
        if not source.is_file():
            raise commands.Failed(f"images.{image}: input {name} is not in the cache: run fetch first")
        folder = run / "inputs" / name
        folder.mkdir(parents=True)
        shutil.copyfile(source, folder / input_file_name(entry["inputs"][name]))
    pairs.extend(core.param_env(entry["params"]))
    (run / "build.env").write_text(input_lock.shell(pairs))


def prepare_work(
    work: Path,
    *,
    loaded: commands.Loaded,
    lock: Lock,
    image: str,
    entry: planfile.ImageEntry,
    plan: planfile.Plan,
    keyring: Path,
    cache: Path,
    owner: str | None,
    base: parents.Base | None = None,
) -> None:
    """Write everything the builder reads for one image into `work`. An OCI image (`base` is its parent's
    layers) gets the layer program and its parent's layers instead of core's sources and mmdebstrap."""
    spec = loaded.definition.images[image]
    suite = plan["debian"]["suite"]
    components = plan["debian"]["components"]
    epoch = loaded.definition.debian.source_date_epoch
    work.mkdir(parents=True)
    shutil.copyfile(keyring, work / "keyring.pgp")
    if spec.files is not None:
        (work / "files.tar").write_bytes(files_tar(loaded.root, spec.files, loaded.files, epoch))
    if base is None:
        (work / "build.list").write_text(core.build_sources(suite, components))
        (work / "debian.sources").write_text(
            core.image_sources(entry["apt_sources"], suite, components, plan["baseline"])
        )
        stage_run(work, loaded=loaded, lock=lock, image=image, entry=entry, cache=cache, scripts=spec.hooks)
        (work / "customize.sh").write_text(core.customize_script(files=spec.files is not None, hooks=spec.hooks))
        (work / "build.sh").write_text(
            core.build_script(suite=suite, request=entry["request"], source_date_epoch=epoch, owner=owner)
        )
        return
    (work / "build.list").write_text(
        core.build_sources(suite, components, mirror=oci_build.CHILD_MIRROR, keyring=oci_build.CHILD_KEYRING)
    )
    scripts = identity.script_paths(loaded.definition, image, entry["modules"])
    stage_run(work, loaded=loaded, lock=lock, image=image, entry=entry, cache=cache, scripts=scripts)
    for name in entry["modules"]:
        for helper, text in modules.helper_files(loaded.definition.modules[name]).items():
            (work / helper).write_text(text)
    (work / LAYER_PROGRAM).write_text(
        resources.files("debian_image_factory.build").joinpath(LAYER_PROGRAM).read_text(encoding="utf-8")
    )
    (work / "layers").mkdir()
    for index, (path, _, _) in enumerate(base.layers):
        place(path, work / "layers" / oci_build.layer_name(index))
    (work / "build.sh").write_text(
        oci_build.build_script(
            layers=len(base.layers),
            request=entry["request"],
            source_date_epoch=epoch,
            owner=owner,
            files=spec.files is not None,
            module_lines=module_lines(loaded.definition, entry, epoch),
            hooks=scripts,
        )
    )


def vouched(cache: Path, entry: planfile.ImageEntry) -> list[records.Remote]:
    """The vendor's signed checksum lists (and detached signatures) `fetch` verified the image's inputs
    against, as provenance names them beside the archive's InRelease files (DESIGN 8.2)."""
    found: list[records.Remote] = []
    for name in sorted(entry["inputs"]):
        sha256 = entry["inputs"][name].get("sha256")
        if isinstance(sha256, str):
            found.extend(fetch.vouched_by(cache, sha256))
    return found


def place(source: Path, target: Path) -> None:
    """`source` at `target`: hard-linked when the file system allows, copied otherwise."""
    try:
        os.link(source, target)
    except OSError:
        shutil.copyfile(source, target)


def module_lines(spec: definition.Definition, entry: planfile.ImageEntry, source_date_epoch: int) -> list[str]:
    """What every switched-on built-in module the image uses runs in the builder (modules.install_lines),
    each module with its own lock entries, in module-name order."""
    lines: list[str] = []
    for name in entry["modules"]:
        module = spec.modules[name]
        if not module.use.startswith("builtin:"):
            continue  # a script: it runs as a hook, before the image's own (identity.script_paths)
        own = {entry_name: fields for entry_name, fields in entry["inputs"].items() if fields.get("module") == name}
        lines.append(f"# module {name} ({module.use})")
        lines += modules.install_lines(
            module, own, inputs=f"{core.WORK}/run/inputs", source_date_epoch=source_date_epoch
        )
    return lines


# ---- what the artifact holds --------------------------------------------------------------------


def installed(artifact: Path) -> list[Package]:
    """The packages the built root's own dpkg status lists as installed (the SBOM's source, DESIGN 8.2)."""
    with tarfile.open(artifact, mode="r:gz") as archive:
        for member in archive:
            if member.name in ("./var/lib/dpkg/status", "var/lib/dpkg/status") and member.isfile():
                handle = archive.extractfile(member)
                if handle is None:
                    break
                return debian.installed_packages(handle.read().decode("utf-8"))
    raise commands.Failed(f"{artifact.name} holds no var/lib/dpkg/status")


def sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def check_gzip(path: Path) -> None:
    """The packed root must be a complete gzip stream: a truncated one would publish broken bits."""
    try:
        with gzip.open(path, "rb") as handle:
            while handle.read(1 << 20):
                pass
    except (OSError, EOFError) as error:
        raise commands.Failed(f"{path.name}: the builder's output is not a complete gzip stream: {error}") from None


# ---- records ------------------------------------------------------------------------------------


def now() -> str:
    """The current time in RFC 3339 UTC, to the second: real build times live in provenance only."""
    return datetime.fromtimestamp(time.time(), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def git(root: Path, *args: str) -> str | None:
    try:
        done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None
    return done.stdout.strip() if done.returncode == 0 and done.stdout.strip() else None


def definition_source(definition_path: Path) -> records.DefinitionSource | None:
    """The definition's repository, commit and path, when it lives in a clean git checkout with a
    remote a record may name. A local path never reaches a record, and a directory with uncommitted
    changes records no commit, since that commit would not be what the build read."""
    folder = definition_path.resolve().parent
    top = git(folder, "rev-parse", "--show-toplevel")
    revision = git(folder, "rev-parse", "HEAD")
    remote = git(folder, "config", "--get", "remote.origin.url")
    uri = records.definition_uri(remote) if remote is not None else None
    if top is None or revision is None or uri is None:
        return None
    changed = git(folder, "status", "--porcelain", "--", ".")
    if changed is not None:
        return None  # uncommitted changes: the commit does not describe what was built from
    try:
        relative = definition_path.resolve().relative_to(top).as_posix()
    except ValueError:
        return None  # the checkout git names does not hold the resolved path
    return records.DefinitionSource(uri, revision, relative)


def reason_text(because: object) -> str | None:
    """One line for provenance saying why the image was built, from the plan's `because`."""
    if not isinstance(because, list):
        return None
    parts: list[str] = []
    for item in because:
        if not isinstance(item, dict):
            continue
        if "rebuild" in item:
            return f"rebuild: {item['rebuild']}"
        if "package" in item:
            parts.append(f"package {item['package']} {item.get('from')} -> {item.get('to')}")
        elif "input" in item and "from" in item:
            parts.append(f"input {item['input']} {item.get('from')} -> {item.get('to')}")
        elif "parent" in item:
            parts.append(f"parent {item['parent']} {item.get('state')}")
        elif "failed" in item:
            parts.append(f"required checks failed: {item['failed']}")
        elif "published" in item:
            parts.append(str(item["published"]))
    return "; ".join(parts) or None


def repository_of(reference: str) -> str:
    """An image reference without its tag or digest: `ghcr.io/owner/builder` of `ghcr.io/owner/builder:tag`."""
    name = reference.split("@", 1)[0]
    head, colon, tail = name.rpartition(":")
    return head if colon and "/" not in tail else name


def in_releases(mirror: Path, plan: planfile.Plan) -> list[records.Remote]:
    """(snapshot.debian.org URL, sha256) of every suite's InRelease the build read from the mirror."""
    found: list[records.Remote] = []
    for one in debian.suites(plan["debian"]["suite"]):
        path = mirror / one.archive / "dists" / one.dist / "InRelease"
        if not path.is_file():
            raise commands.Failed(f"{path} is missing: run fetch on this plan first")
        url = f"{resolve.SNAPSHOT_SERVICE}/archive/{one.archive}/{plan['snapshot']}/dists/{one.dist}/InRelease"
        found.append(records.Remote(url, sha256_file(path)))
    return found


def image_records(
    *,
    image: str,
    entry: planfile.ImageEntry,
    plan: planfile.Plan,
    lock: Lock,
    name: str,
    digest: str,
    packages: Sequence[Package],
    source: records.DefinitionSource | None,
    releases: Sequence[records.Remote],
    builder_: Builder,
    started: str,
    finished: str,
    ancestors: Sequence[records.Parent] = (),
    files: Sequence[tuple[str, str]] = (),
) -> list[Statement]:
    """Provenance and SBOM of one artifact (DESIGN 8.2). `ancestors` are the images it descends from,
    nearest first (none for core). The artifact is the first subject, under `name` and `digest`; `files`
    adds the (name, sha256) of each file an artifact of several files is made of (an Incus image's two)."""
    builder_id, invocation = records.run_details(os.environ, __version__)
    entries = sorted(entry["inputs"])
    subjects = [subject(name, digest), *(subject(file_name, sha256) for file_name, sha256 in files)]
    provenance = records.provenance_statement(
        subjects=subjects,
        image=image,
        params=dict(entry["params"]),
        definition=source,
        identity=entry["identity"],
        engine=ENGINE,
        build_snapshot=plan["snapshot"],
        architecture=plan["debian"]["architecture"],
        reason=reason_text(entry.get("because")),
        lock=lock,
        entries=entries,
        recipe_digest=entry["recipe"],
        in_releases=releases,
        builder_image=repository_of(builder_.reference),
        builder_digest=builder_.digest.removeprefix("sha256:"),
        ancestors=ancestors,
        builder_id=builder_id,
        invocation_id=invocation,
        version=__version__,
        started_on=started,
        finished_on=finished,
    )
    sbom = records.sbom(
        image=image,
        kind=entry["kind"],
        suite=plan["debian"]["suite"],
        arch=plan["debian"]["architecture"],
        artifact_digest=digest,
        packages=packages,
        lock=lock,
        entries=entries,
        namespace_base=records.namespace_base(source.uri if source is not None else None),
        created=finished,
        version=__version__,
    )
    return [provenance, statement(subjects, input_lock.records.SPDX_PREDICATE, sbom)]


# ---- the command --------------------------------------------------------------------------------


def selected(plan: planfile.Plan, wanted: Sequence[str], out: TextIO) -> list[str]:
    """The images to build: the named ones, else every image the plan says to build, top-down."""
    images = plan["images"]
    unknown = sorted(set(wanted) - set(images))
    if unknown:
        raise commands.Usage(f"--image names {unknown}, which the plan does not have")
    for name in wanted:
        if images[name]["kind"] not in SUPPORTED_KINDS:
            raise commands.Usage(f"{name}: the {images[name]['kind']} kind is built from a later release on")
    chosen = list(wanted) or [name for name, entry in images.items() if entry["state"] == "build"]
    order = [name for name in plan_order(plan) if name in chosen]
    for name in order:
        if images[name]["kind"] not in SUPPORTED_KINDS:
            print(f"{name}: not built, the {images[name]['kind']} kind is built from a later release on", file=out)
    return [name for name in order if images[name]["kind"] in SUPPORTED_KINDS]


def plan_order(plan: planfile.Plan) -> list[str]:
    """Images parents first, as the plan's parent links give them."""
    images = plan["images"]
    order: list[str] = []
    remaining = sorted(images)
    while remaining:
        ready = [name for name in remaining if images[name]["parent"] is None or images[name]["parent"] in order]
        if not ready:
            raise commands.Failed(f"the plan's parent links form a cycle among {remaining}")
        order.extend(ready)
        remaining = [name for name in remaining if name not in ready]
    return order


def verify_identity(
    lock: Lock, loaded: commands.Loaded, plan: planfile.Plan, image: str, params: Mapping[str, definition.Param]
) -> None:
    """The plan's entry for `image` must still be what the lock, the definition and its files give.

    Not only the identity: the build reads the entry's request, sources, inputs and parameters, so every
    field the plan command derives is derived again here and compared. Only the package set is taken from
    the plan as it stands, since it is what the identity is computed over."""
    resolved = {name: tuple(entry["packages"]) for name, entry in plan["images"].items()}
    try:
        inputs = commands.compute_inputs(lock, loaded, resolved, params)
        if image not in inputs:
            raise ValueError(f"the definition has no image {image}")
        given = plan["images"][image]
        expected = planfile.parse_image(
            image, {**plan_module.image_entry(loaded.definition, inputs[image]), "state": given["state"]}
        )
    except (KeyError, ValueError) as error:
        raise commands.Failed(f"images.{image}: the plan does not match the lock and the definition: {error}") from None
    moved = sorted(key for key in expected if expected[key] != given.get(key))  # type: ignore[literal-required]  # keys come from expected itself
    if moved:
        raise commands.Failed(
            f"images.{image}: the lock, the definition or its files changed since this plan was made"
            f" ({', '.join(moved)} differ): plan again"
        )


def pull_parent(target: published.OciTarget, digest: str, dest: Path) -> Path:
    """Pull the image with manifest digest `digest` (hex) from `target` into `dest` as an OCI image layout
    (every byte checked against its digest) and return the layout's directory."""
    try:
        return registry.pull_layout(registry.connect(target), digest, dest)
    except (OSError, oci.OciError) as error:
        raise commands.Failed(f"oci://{target.registry}/{target.repository}@sha256:{digest}: {error}") from None


@dataclass(frozen=True, slots=True)
class Run:
    """What every image of one `build` run shares."""

    plan: planfile.Plan
    lock: Lock
    loaded: commands.Loaded
    sources: commands.Sources
    mirror: Path
    releases: Sequence[records.Remote]
    builder_: Builder
    source: records.DefinitionSource | None
    out_dir: Path
    directories: Sequence[Path]
    """The `dir://` targets given as --parents."""
    registries: Sequence[published.OciTarget]
    """The `oci://` targets given as --parents."""


@dataclass(frozen=True, slots=True)
class Result:
    artifact: parents.ParentArtifact
    packages: int


def build_core(run: Run, image: str, scratch: Path) -> Result:
    """One core image: mmdebstrap in the builder, then the tarball and its records."""
    entry = run.plan["images"][image]
    work = scratch / "factory"
    prepare_work(
        work,
        loaded=run.loaded,
        lock=run.lock,
        image=image,
        entry=entry,
        plan=run.plan,
        keyring=run.sources.keyring,
        cache=run.sources.cache,
        owner=run.builder_.owner,
    )
    started = now()
    run_builder(run.builder_, work, run.mirror, run.out_dir / f"{image}.build.log")
    finished = now()
    packed = work / Path(core.ROOTFS).name
    check_gzip(packed)
    digest = sha256_file(packed)
    debian_ = run.plan["debian"]
    name = artifact_name(
        image, debian_["suite"], debian_["architecture"], entry["identity"], digest, EXTENSIONS[entry["kind"]]
    )
    packages = installed(packed)
    statements = image_records(
        image=image,
        entry=entry,
        plan=run.plan,
        lock=run.lock,
        name=name,
        digest=digest,
        packages=packages,
        source=run.source,
        releases=[*run.releases, *vouched(run.sources.cache, entry)],
        builder_=run.builder_,
        started=started,
        finished=finished,
    )
    # Records first: an interrupted build leaves at most records without an artifact, which
    # nothing reads, never an artifact that publish would refuse for lack of records.
    (run.out_dir / records_name_for(digest)).write_text(records.record_lines(statements))
    os.replace(packed, run.out_dir / name)
    return Result(parents.ParentArtifact(image, "core", name, digest, run.out_dir / name), len(packages))


def adds_layer(spec: definition.Image, entry: planfile.ImageEntry) -> bool:
    """Whether an OCI image changes its parent's filesystem: it installs packages, modules or lock entries,
    lays down a file tree or runs hooks. An image that only sets `oci` config adds no layer."""
    return bool(entry["request"] or entry["inputs"] or entry["modules"] or spec.files is not None or spec.hooks)


def find_by_name(run: Run, built: Mapping[str, parents.ParentArtifact]) -> parents.Finder:
    """Where an artifact is, by its name: built in this run, in the output directory, or in a `dir://` parent target."""

    def find(name: str) -> Path | None:
        for one in built.values():
            if one.name == name and one.path is not None:
                return one.path
        for directory in (run.out_dir, *run.directories):
            if (directory / name).exists():
                return directory / name
        return None

    return find


def build_oci(run: Run, image: str, scratch: Path, built: Mapping[str, parents.ParentArtifact]) -> Result:
    """One OCI image: its parent's layers, plus one layer when it changes the filesystem, a config, and
    the layout with its records (DESIGN 5.3, 8.1)."""
    entry = run.plan["images"][image]
    spec = run.loaded.definition.images[image]
    debian_ = run.plan["debian"]
    suite, arch = debian_["suite"], debian_["architecture"]
    parent_name = entry["parent"]
    if parent_name is None:
        raise commands.Failed(f"images.{image}: an OCI image needs a parent")
    parent = parents.locate_parent(
        image,
        parent_name,
        run.plan["images"][parent_name],
        suite=suite,
        arch=arch,
        built=built,
        out_dir=run.out_dir,
        directories=run.directories,
        registries=run.registries,
        pull=pull_parent,
        scratch=scratch / "pulled",
    )
    ancestry = parents.lineage(parent, find_by_name(run, built))
    base = parents.base_of(parent)
    try:
        config = oci.merged_config(base.config, spec.kind_table)
    except oci.OciError as error:
        raise commands.Failed(f"images.{image}: {error}") from None
    started = now()
    layers = list(base.layers)
    diff_ids = list(base.diff_ids)
    if adds_layer(spec, entry):
        work = scratch / "factory"
        prepare_work(
            work,
            loaded=run.loaded,
            lock=run.lock,
            image=image,
            entry=entry,
            plan=run.plan,
            keyring=run.sources.keyring,
            cache=run.sources.cache,
            owner=run.builder_.owner,
            base=base,
        )
        run_builder(run.builder_, work, run.mirror, run.out_dir / f"{image}.build.log")
        status = (work / Path(oci_build.STATUS).name).read_text(encoding="utf-8")
        added = work / Path(oci_build.LAYER).name
        if added.is_file():
            diff_id = (work / Path(oci_build.DIFF_ID).name).read_text(encoding="ascii").strip()
            if parents.gunzip_sha256(added) != diff_id:
                raise commands.Failed(f"{image}: the builder's layer does not match its diff_id")
            layers.append((added, sha256_file(added), added.stat().st_size))
            diff_ids.append(diff_id)
    else:
        status = parents.dpkg_status([path for path, _, _ in base.layers])
    finished = now()
    try:
        config_bytes = oci.image_config(config, diff_ids, arch)
        annotations = oci.image_annotations(
            identity=entry["identity"],
            base_digest=parent.digest,
            base_name=parent.name,
            source=None if run.source is None else run.source.uri.removeprefix("git+"),
            revision=None if run.source is None else run.source.revision,
        )
        layout = scratch / "layout"
        descriptor = ocilayout.write_layout(layout, config=config_bytes, layers=layers, annotations=annotations)
    except oci.OciError as error:
        raise commands.Failed(f"images.{image}: {error}") from None
    digest = descriptor.digest
    name = artifact_name(image, suite, arch, entry["identity"], digest, EXTENSIONS[entry["kind"]])
    packages = debian.installed_packages(status)
    statements = image_records(
        image=image,
        entry=entry,
        plan=run.plan,
        lock=run.lock,
        name=name,
        digest=digest,
        packages=packages,
        source=run.source,
        releases=[*run.releases, *vouched(run.sources.cache, entry)],
        builder_=run.builder_,
        started=started,
        finished=finished,
        ancestors=[records.Parent(one.image, one.digest) for one in ancestry],
    )
    # Records first, as for core: the layout directory is renamed into place only once they are written.
    (run.out_dir / records_name_for(digest)).write_text(records.record_lines(statements))
    target = run.out_dir / name
    if target.exists():
        shutil.rmtree(target)
    os.replace(layout, target)
    return Result(parents.ParentArtifact(image, "oci", name, digest, target), len(packages))


def device_lines(parent: parents.ParentArtifact) -> list[str]:
    """mksquashfs pseudo definitions of every device node in the parent's root: they cannot be made in the
    builder's user namespace, so the root's packer adds them from this listing (build/incus.py)."""
    if parent.path is None:
        raise commands.Failed(f"{parent.name}: its files are needed to build on it")
    lines: list[str] = []
    if parent.kind == "core":
        with tarfile.open(parent.path, mode="r:gz") as archive:
            for member in archive:
                if member.ischr() or member.isblk():
                    path = "/" + member.name.removeprefix("./").strip("/")
                    kind = "char" if member.ischr() else "block"
                    lines.append(
                        incus_build.device_pseudo(
                            path, kind, member.mode, member.uid, member.gid, member.devmajor, member.devminor
                        )
                    )
        return lines
    rootfs = parents.incus_rootfs(parent)
    try:
        with rootfs.open("rb") as handle:
            for one in squashfs.entries(handle):
                if one.kind in ("char", "block"):
                    lines.append(
                        incus_build.device_pseudo(one.path, one.kind, one.mode, one.uid, one.gid, one.major, one.minor)
                    )
    except squashfs.SquashfsError as error:
        raise commands.Failed(f"{rootfs.name}: {error}") from None
    return lines


def prepare_incus_work(work: Path, run: Run, image: str, parent: parents.ParentArtifact) -> None:
    """Everything the builder reads for one Incus image: the parent's root and its device nodes, the
    layer program, and what every child reads (sources, the file tree, modules, hooks and their inputs)."""
    entry = run.plan["images"][image]
    spec = run.loaded.definition.images[image]
    debian_ = run.plan["debian"]
    epoch = run.loaded.definition.debian.source_date_epoch
    if parent.path is None:
        raise commands.Failed(f"images.{image}: its parent {parent.name} has no files to build on")
    work.mkdir(parents=True)
    shutil.copyfile(run.sources.keyring, work / "keyring.pgp")
    if spec.files is not None:
        (work / "files.tar").write_bytes(files_tar(run.loaded.root, spec.files, run.loaded.files, epoch))
    (work / "build.list").write_text(
        core.build_sources(
            debian_["suite"], debian_["components"], mirror=oci_build.CHILD_MIRROR, keyring=oci_build.CHILD_KEYRING
        )
    )
    scripts = identity.script_paths(run.loaded.definition, image, entry["modules"])
    stage_run(
        work, loaded=run.loaded, lock=run.lock, image=image, entry=entry, cache=run.sources.cache, scripts=scripts
    )
    for name in entry["modules"]:
        for helper, text in modules.helper_files(run.loaded.definition.modules[name]).items():
            (work / helper).write_text(text)
    (work / LAYER_PROGRAM).write_text(
        resources.files("debian_image_factory.build").joinpath(LAYER_PROGRAM).read_text(encoding="utf-8")
    )
    devices = device_lines(parent)
    (work / Path(incus_build.DEVICES_PSEUDO).name).write_text("".join(devices))
    (work / Path(incus_build.DEVICES_LIST).name).write_text(
        "".join(line.split(" ", 1)[0].lstrip("/") + "\n" for line in devices)
    )
    if parent.kind == "core":
        place(parent.path, work / Path(incus_build.PARENT_TARBALL).name)
    else:
        place(parents.incus_rootfs(parent), work / Path(incus_build.PARENT_SQUASHFS).name)
    (work / "build.sh").write_text(
        incus_build.build_script(
            parent=parent.kind,
            request=entry["request"],
            source_date_epoch=epoch,
            owner=run.builder_.owner,
            files=spec.files is not None,
            module_lines=module_lines(run.loaded.definition, entry, epoch),
            hooks=scripts,
            boot_lines=boot.boot_lines(),
        )
    )


def build_incus(run: Run, image: str, scratch: Path, built: Mapping[str, parents.ParentArtifact]) -> Result:
    """One Incus image: its parent's root with the kind's packages and the image's own, packed as a
    squashfs, a metadata tarball beside it, both named by their fingerprint, and their records (DESIGN 8.1)."""
    entry = run.plan["images"][image]
    debian_ = run.plan["debian"]
    suite, arch = debian_["suite"], debian_["architecture"]
    parent_name = entry["parent"]
    if parent_name is None:
        raise commands.Failed(f"images.{image}: an Incus image needs a parent")
    parent = parents.locate_parent(
        image,
        parent_name,
        run.plan["images"][parent_name],
        suite=suite,
        arch=arch,
        built=built,
        out_dir=run.out_dir,
        directories=run.directories,
        registries=(),
        pull=pull_parent,
        scratch=scratch / "pulled",
    )
    ancestry = parents.incus_lineage(parent)
    work = scratch / "factory"
    prepare_incus_work(work, run, image, parent)
    started = now()
    run_builder(run.builder_, work, run.mirror, run.out_dir / f"{image}.build.log")
    finished = now()
    rootfs = work / Path(incus_build.ROOTFS).name
    metadata = work / "metadata.tar.gz"
    metadata.write_bytes(
        incus.metadata_tarball(
            image=image,
            suite=suite,
            arch=arch,
            identity=entry["identity"],
            source_date_epoch=run.loaded.definition.debian.source_date_epoch,
        )
    )
    fingerprint = fileartifacts.fingerprint_of(metadata, rootfs)
    names = incus.names(image, suite, arch, entry["identity"], fingerprint)
    packages = debian.installed_packages((work / Path(incus_build.STATUS).name).read_text(encoding="utf-8"))
    statements = image_records(
        image=image,
        entry=entry,
        plan=run.plan,
        lock=run.lock,
        name=names.image,
        digest=fingerprint,
        packages=packages,
        source=run.source,
        releases=[*run.releases, *vouched(run.sources.cache, entry)],
        builder_=run.builder_,
        started=started,
        finished=finished,
        ancestors=ancestry,
        files=[(names.metadata, sha256_file(metadata)), (names.rootfs, sha256_file(rootfs))],
    )
    # Records first, as for core; then the rootfs, and the metadata tarball last: it is the file that
    # makes the pair an artifact (fileartifacts), so an interrupted build never leaves a half.
    (run.out_dir / records_name_for(fingerprint)).write_text(records.record_lines(statements))
    os.replace(rootfs, run.out_dir / names.rootfs)
    os.replace(metadata, run.out_dir / names.metadata)
    artifact = parents.ParentArtifact(image, "incus", names.metadata, fingerprint, run.out_dir / names.metadata)
    return Result(artifact, len(packages))


def split_parent_targets(texts: Sequence[str]) -> tuple[list[Path], list[published.OciTarget]]:
    """The `--parents` targets: where parents not built in this run may be, `dir://` and `oci://`."""
    directories: list[Path] = []
    registries: list[published.OciTarget] = []
    for text in texts:
        try:
            target = published.parse_target(text)
        except ValueError as error:
            raise commands.Usage(str(error)) from None
        if isinstance(target, published.DirTarget):
            directories.append(Path(target.path))
        elif isinstance(target, published.OciTarget):
            registries.append(target)
        else:
            raise commands.Usage(f"--parents {text}: a github-release:// target holds no parents; use dir:// or oci://")
    return directories, registries


def build_command(
    plan_path: Path,
    lock_path: Path,
    definition_path: Path,
    sources: commands.Sources,
    *,
    out_dir: Path,
    images: Sequence[str],
    builder_image: str,
    out: TextIO,
    parent_targets: Sequence[str] = (),
) -> int:
    plan_bytes = commands.read_text(plan_path)
    try:
        plan = planfile.parse_plan(json.loads(plan_bytes))
    except ValueError as error:
        raise commands.Failed(f"{plan_path}: {error}") from None
    loaded = commands.load(lock_path, definition_path)
    lock = commands.checked_lock(loaded)
    missing = sorted(set(plan["images"]) ^ set(loaded.definition.images))
    if missing:
        raise commands.Failed(f"{plan_path}: the plan and {definition_path.name} name different images: {missing}")
    try:
        params = definition.resolve_params(
            loaded.definition, {k: core.param_text(v) for k, v in plan["params"].items()}
        )
    except ValueError as error:
        raise commands.Failed(f"{plan_path}: {error}") from None
    directories, registries = split_parent_targets(parent_targets)
    chosen = selected(plan, images, out)
    if not chosen:
        print("nothing to build", file=out)
        return 0
    for image in chosen:
        verify_identity(lock, loaded, plan, image, params)
    mirror = fetch.mirror_dir(sources.cache, plan["snapshot"])
    releases = in_releases(mirror, plan)
    builder_ = open_builder(builder_image)
    source = definition_source(definition_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / PLAN_COPY).write_text(plan_bytes)
    run = Run(plan, lock, loaded, sources, mirror, releases, builder_, source, out_dir, directories, registries)
    built: dict[str, parents.ParentArtifact] = {}
    for image in chosen:
        with tempfile.TemporaryDirectory(prefix=f".work-{image}-", dir=out_dir) as scratch:
            kind = plan["images"][image]["kind"]
            if kind == "core":
                result = build_core(run, image, Path(scratch))
            elif kind == "incus":
                result = build_incus(run, image, Path(scratch), built)
            else:
                result = build_oci(run, image, Path(scratch), built)
        built[image] = result.artifact
        print(f"{image}: {result.artifact.name} ({result.packages} packages)", file=out)
    return 0
