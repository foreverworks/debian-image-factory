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
from pathlib import Path
from typing import Final, TextIO
from urllib.parse import unquote, urlparse

import input_lock
from input_lock import Lock, Package
from input_lock.lock import entry_env
from input_lock.records import Statement, statement, subject

from .. import ENGINE, __version__, commands, debian, definition, fetch, planfile, records, resolve
from .. import plan as plan_module
from .. import tools as builder
from ..identity import FileFact
from ..published import artifact_name, records_name_for
from . import core

SUPPORTED_KINDS: Final = ("core",)
"""The kinds this release builds; the others arrive with their milestones."""
EXTENSIONS: Final[Mapping[str, str]] = {"core": "tar.gz"}
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


@dataclass(frozen=True, slots=True)
class Built:
    image: str
    name: str
    digest: str


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
    url = fields.get("url")
    name = unquote(urlparse(url).path.rsplit("/", 1)[-1]) if isinstance(url, str) else ""
    unsafe = name in ("", ".", "..") or any(character in name for character in "/\\\0")
    return "file" if unsafe else name


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
) -> None:
    """Write everything the builder reads for one image into `work`."""
    spec = loaded.definition.images[image]
    suite = plan["debian"]["suite"]
    components = plan["debian"]["components"]
    work.mkdir(parents=True)
    shutil.copyfile(keyring, work / "keyring.pgp")
    (work / "build.list").write_text(core.build_sources(suite, components))
    (work / "debian.sources").write_text(core.image_sources(entry["apt_sources"], suite, components, plan["baseline"]))
    if spec.files is not None:
        (work / "files.tar").write_bytes(
            files_tar(loaded.root, spec.files, loaded.files, loaded.definition.debian.source_date_epoch)
        )
    if spec.hooks:
        run = work / "run"
        (run / "hooks").mkdir(parents=True)
        for index, hook in enumerate(spec.hooks, start=1):
            target = run / "hooks" / core.hook_name(index, hook)
            shutil.copyfile(loaded.root / hook, target)
            target.chmod(0o755)
        pairs: list[tuple[str, str]] = [("LOCK_ENTRIES", " ".join(sorted(entry["inputs"])))]
        for name in sorted(entry["inputs"]):
            pairs.extend(entry_env(name, lock["inputs"][name]))
            source = fetch.input_path(cache, entry["inputs"][name])
            if not source.is_file():
                raise commands.Failed(f"images.{image}: input {name} is not in the cache: run fetch first")
            folder = run / "inputs" / name
            folder.mkdir(parents=True)
            shutil.copyfile(source, folder / input_file_name(entry["inputs"][name]))
        pairs.extend(core.param_env(entry["params"]))
        (run / "build.env").write_text(input_lock.shell(pairs))
    (work / "customize.sh").write_text(core.customize_script(files=spec.files is not None, hooks=spec.hooks))
    (work / "build.sh").write_text(
        core.build_script(
            suite=suite,
            request=entry["request"],
            source_date_epoch=loaded.definition.debian.source_date_epoch,
            owner=owner,
        )
    )


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
) -> list[Statement]:
    """Provenance and SBOM of one artifact (DESIGN 8.2)."""
    builder_id, invocation = records.run_details(os.environ, __version__)
    entries = sorted(entry["inputs"])
    subjects = [subject(name, digest)]
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
        parent=None,
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
    for image in chosen:
        entry = plan["images"][image]
        with tempfile.TemporaryDirectory(prefix=f".work-{image}-", dir=out_dir) as scratch:
            work = Path(scratch) / "factory"
            prepare_work(
                work,
                loaded=loaded,
                lock=lock,
                image=image,
                entry=entry,
                plan=plan,
                keyring=sources.keyring,
                cache=sources.cache,
                owner=builder_.owner,
            )
            started = now()
            run_builder(builder_, work, mirror, out_dir / f"{image}.build.log")
            finished = now()
            packed = work / Path(core.ROOTFS).name
            check_gzip(packed)
            digest = sha256_file(packed)
            debian_ = plan["debian"]
            name = artifact_name(
                image, debian_["suite"], debian_["architecture"], entry["identity"], digest, EXTENSIONS[entry["kind"]]
            )
            packages = installed(packed)
            statements = image_records(
                image=image,
                entry=entry,
                plan=plan,
                lock=lock,
                name=name,
                digest=digest,
                packages=packages,
                source=source,
                releases=releases,
                builder_=builder_,
                started=started,
                finished=finished,
            )
            # Records first: an interrupted build leaves at most records without an artifact, which
            # nothing reads, never an artifact that publish would refuse for lack of records.
            (out_dir / records_name_for(digest)).write_text(records.record_lines(statements))
            os.replace(packed, out_dir / name)
        print(f"{image}: {name} ({len(packages)} packages)", file=out)
    return 0
