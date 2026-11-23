"""Replay from an inputs bundle (DESIGN 7.7, 9.1): the bundle unpacked as a download cache, and checked.

`build --offline --bundle FILE` is the normal build reading a different directory, not a separate mode. This
module only makes that directory: it unpacks the bundle into a scratch cache, checks every member against the
manifest (`bundle.unpack`), checks the manifest against the plan it carries, and checks that the cache holds
what the image's build reads. The build itself then runs on that cache with `Sources(cache=...)`.
"""

import datetime
import json
from dataclasses import dataclass
from pathlib import Path

from . import archive, bundle, debian, fetch, planfile
from .commands import Failed


@dataclass(frozen=True, slots=True)
class Replay:
    """A bundle ready to build from."""

    image: str
    plan: bytes
    """The bundle's plan.json, byte for byte."""
    cache: Path
    """The cache the bundle was unpacked into."""
    verified_at: datetime.datetime | None
    """When `fetch` verified the image's vendor repositories, if it has any, and never later than the replay's own
    time: their Releases' Valid-Until is judged at this time (DESIGN 7.7)."""


def check(unpacked: bundle.Unpacked, plan: planfile.Plan, source: Path) -> None:
    """Failed unless the manifest and the plan agree and the cache holds what building the image reads.

    The identity is the one the plan computed for the image, so a bundle can only be built into the artifact
    whose identity it was fetched for; the signed indices of every suite and every locked input of the image
    must be there. Pool files are not listed: apt checks every one against the signed indices as it installs."""
    manifest = unpacked.manifest
    entry = plan["images"].get(manifest["image"])
    if entry is None:
        raise Failed(f"{source}: its plan has no image {manifest['image']}")
    debian_ = plan["debian"]
    differs = [
        name
        for name, ours, theirs in (
            ("identity", manifest["identity"], entry["identity"]),
            ("snapshots", manifest["snapshots"], plan["snapshots"]),
            ("suite", manifest["suite"], debian_["suite"]),
            ("architecture", manifest["architecture"], debian_["architecture"]),
        )
        if ours != theirs
    ]
    if differs:
        raise Failed(f"{source}: the manifest and the plan it carries disagree on {', '.join(differs)}")
    present = {one["path"] for one in manifest["files"]}
    wanted: list[str] = []
    stem = fetch.mirror_dir(Path(bundle.CACHE), plan["snapshots"]).as_posix()
    for suite in debian.suites(debian_["suite"]):
        wanted.append(f"{stem}/{suite.archive}/dists/{suite.dist}/InRelease")
    for name, fields in sorted(entry["inputs"].items()):
        sha256 = fields.get("sha256")
        if not isinstance(sha256, str):
            raise Failed(f"{source}: input {name} of {manifest['image']} has no sha256")
        wanted.append(archive.cache_path(Path(bundle.CACHE), sha256).as_posix())
    lacking = [name for name in wanted if name not in present]
    if lacking:
        raise Failed(f"{source}: the bundle lacks {len(lacking)} files its image's build reads, such as {lacking[0]}")


def open_replay(
    bundle_path: Path, scratch: Path, plan_path: Path | None, now: datetime.datetime | None = None
) -> Replay:
    """Unpack `bundle_path` into the new directory `scratch` and check it; `plan_path`, when given, must be the
    very plan the bundle carries (a replay builds what was fetched, never a plan that moved since). The
    bundle's `verified_at` is only ever as late as `now` (default: the present): a manifest claiming a later
    time cannot make an expired Release look valid (DESIGN 7.7)."""
    unpacked = bundle.unpack(bundle_path, scratch)
    try:
        plan = planfile.parse_plan(json.loads(unpacked.plan.decode("utf-8")))
    except ValueError as error:  # JSON, UTF-8 and the plan's own checks
        raise Failed(f"{bundle_path}: its {bundle.PLAN}: {error}") from None
    check(unpacked, plan, bundle_path)
    if plan_path is not None:
        try:
            given = plan_path.read_bytes()
        except OSError as error:
            raise Failed(f"{plan_path}: {error.strerror or error}") from None
        if given != unpacked.plan:
            raise Failed(f"{plan_path} is not the plan {bundle_path} was fetched from: build it from the bundle's own")
    text = unpacked.manifest.get("verified_at")
    verified = min(datetime.datetime.fromisoformat(text), now or datetime.datetime.now(datetime.UTC)) if text else None
    return Replay(unpacked.manifest["image"], unpacked.plan, unpacked.cache, verified)
