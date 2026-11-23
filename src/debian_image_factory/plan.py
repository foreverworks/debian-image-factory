"""The plan (DESIGN 7.3, 7.4): per image its inputs, identity, and state, `reuse`, `wait` or `build`.

Pure. The edge resolves package sets, reads files and looks identities up at the targets; this
module turns those answers into `plan.json`. A rebuilt parent rebuilds every image below it; a
parent still waiting on its checks makes its children wait, unless a child is itself reusable.
"""

from collections.abc import Mapping, Sequence
from typing import Final

import input_lock
from input_lock import TRUST, Entry, JsonValue
from input_lock.lock import render  # not in input-lock's __all__: renders any url template field of an entry

from . import ENGINE, __version__
from .definition import KIND_DEFAULTS, MODULE_PACKAGES, Definition, Param, required_checks, top_down
from .identity import ImageInputs
from .oci import digest_text
from .published import Decision
from .vendordeb import MODULE as VENDOR_DEB

SCHEMA: Final = 2


def request(definition: Definition, image: str, modules: Sequence[str]) -> list[str]:
    """What a child asks apt for: its kind's defaults, its own packages and what the modules it uses
    (`modules`, by name) need at run time (DESIGN 7.2)."""
    spec = definition.images[image]
    needed = (package for name in modules for package in MODULE_PACKAGES.get(definition.modules[name].use, ()))
    return sorted({*KIND_DEFAULTS[spec.kind], *spec.packages, *needed})


def core_request(packages: Sequence[str]) -> list[str]:
    """What core's second transaction asks for; the first is the suite's Essential set (DESIGN 7.2)."""
    return sorted({"apt", *packages})


def package_changes(old: object, new: Sequence[input_lock.Package]) -> list[dict[str, JsonValue]]:
    """Packages added, removed or moved, by name, against a previous plan's list."""
    before: dict[str, str] = {}
    if isinstance(old, list):
        for item in old:
            if isinstance(item, list) and len(item) == 3 and all(isinstance(part, str) for part in item):
                before[str(item[0])] = str(item[1])
    after = {name: version for name, version, _ in new}
    changes: list[dict[str, JsonValue]] = []
    for name in sorted(set(before) | set(after)):
        if before.get(name) != after.get(name):
            changes.append({"package": name, "from": before.get(name), "to": after.get(name)})
    return changes


def input_changes(old: object, new: Mapping[str, JsonValue]) -> list[dict[str, JsonValue]]:
    before = old if isinstance(old, dict) else {}
    changes: list[dict[str, JsonValue]] = []
    for name in sorted(set(before) | set(new)):
        was, now = before.get(name), new.get(name)
        if was == now:
            continue
        version_was = was.get("version") if isinstance(was, dict) else None
        version_now = now.get("version") if isinstance(now, dict) else None
        if version_was != version_now:
            changes.append({"input": name, "from": version_was, "to": version_now})
        else:
            fields = sorted(
                key
                for key in {*(was if isinstance(was, dict) else {}), *(now if isinstance(now, dict) else {})}
                if (was.get(key) if isinstance(was, dict) else None)
                != (now.get(key) if isinstance(now, dict) else None)
            )
            changes.append({"input": name, "fields": list(fields)})
    return changes


def changes(previous: object, entry: Mapping[str, JsonValue]) -> list[dict[str, JsonValue]]:
    """Why an image's identity moved since a previous plan's entry for it (empty when unknown)."""
    if not isinstance(previous, dict) or previous.get("identity") == entry["identity"]:
        return []
    found = package_changes(previous.get("packages"), packages_of(entry))
    inputs = entry["inputs"]
    found.extend(input_changes(previous.get("inputs"), inputs if isinstance(inputs, dict) else {}))
    for key in ("params", "recipe", "parent_identity"):
        if previous.get(key) != entry.get(key):
            found.append({key: {"from": previous.get(key), "to": entry.get(key)}})
    return found


def packages_of(entry: Mapping[str, JsonValue]) -> list[tuple[str, str, str]]:
    packages = entry.get("packages")
    if not isinstance(packages, list):
        return []
    return [(str(p[0]), str(p[1]), str(p[2])) for p in packages if isinstance(p, list) and len(p) == 3]


def as_json(fields: Mapping[str, input_lock.Value]) -> dict[str, JsonValue]:
    return {key: [*value] if isinstance(value, list) else value for key, value in fields.items()}


def trust_of(entry: Entry) -> dict[str, JsonValue]:
    """How an entry's checksum is vouched for, for `fetch`: its `signed_by` keyring entry and the rendered
    `sums_url` and `sums_sig_url`. input-lock keeps these out of `build_fields`, so out of every identity:
    a signature is checked, it does not change the bytes."""
    found: dict[str, JsonValue] = {}
    for field in TRUST:
        if field in entry:
            found[field] = str(entry[field]) if field == "signed_by" else render(entry, field)
    return found


def debs_of(definition: Definition, inputs: ImageInputs) -> dict[str, JsonValue]:
    """The vendor .deb entries the image installs (its `builtin:deb` module's apt entries), with what `fetch`
    needs to verify each through its repository's signed InRelease again and the build to install it: the
    package, its version and the repository (`registryUrl`, a Renovate hint kept out of `build_fields`). The
    package is in the image's `packages` and not in its `request`: the build installs the verified file."""
    found: dict[str, JsonValue] = {}
    for name, entry in sorted(inputs.entries.items()):
        module = entry.get("module")
        if not (isinstance(module, str) and definition.modules[module].use == VENDOR_DEB and "apt" in entry):
            continue
        found[name] = {
            "package": str(entry["apt"]),
            "version": str(entry.get("version")),
            "registry_url": str(entry.get("registryUrl")),
        }
    return found


def image_entry(definition: Definition, inputs: ImageInputs) -> dict[str, JsonValue]:
    spec = definition.images[inputs.name]
    requested: list[JsonValue] = [
        *(request(definition, inputs.name, inputs.modules) if spec.kind != "core" else core_request(spec.packages))
    ]
    return {
        "kind": spec.kind,
        "parent": inputs.parent,
        "identity": inputs.identity,
        "parent_identity": inputs.parent_identity,
        "recipe": inputs.recipe_digest,
        "apt_sources": spec.apt_sources,
        "request": requested,
        "packages": [[name, version, arch] for name, version, arch in inputs.packages],
        "inputs": {name: as_json(input_lock.build_fields(entry)) for name, entry in sorted(inputs.entries.items())},
        "modules": [*inputs.modules],
        "trust": {name: trust_of(entry) for name, entry in sorted(inputs.entries.items()) if "signed_by" in entry},
        "debs": debs_of(definition, inputs),
        "params": dict(inputs.params),
        "checks": [*required_checks(definition, inputs.name, bool(inputs.entries))],
    }


def named(artifact: str | None) -> str | None:
    """How plan.json names an artifact: `sha256:<hex>`, the form of every digest the factory writes. An Incus
    image's fingerprint is a sha256 too."""
    return None if artifact is None else digest_text(artifact)


def state_of(
    image: str,
    parent_state: str | None,
    parent: str | None,
    decision: Decision,
    rebuild: Mapping[str, str],
) -> dict[str, JsonValue]:
    """An image's state from its own lookup and its parent's state."""
    if image in rebuild:
        return {"state": "build", "because": [{"rebuild": rebuild[image]}]}
    if parent_state == "build":
        return {"state": "build", "because": [{"parent": parent, "state": "build"}]}
    if parent_state == "wait" and decision.state != "reuse":
        state: dict[str, JsonValue] = {
            "state": "wait",
            "waiting_for": [*decision.waiting_for] if decision.state == "wait" else [],
            "because": [{"parent": parent, "state": "wait"}],
        }
        if decision.state == "wait":
            state["artifact"] = named(decision.artifact)
        return state
    if decision.state == "reuse":
        return {"state": "reuse", "artifact": named(decision.artifact)}
    if decision.state == "wait":
        return {"state": "wait", "artifact": named(decision.artifact), "waiting_for": list(decision.waiting_for)}
    if decision.failed:
        return {"state": "build", "because": [{"failed": list(decision.failed)}]}
    return {"state": "build", "because": [{"published": "no artifact with this identity"}]}


def build_plan(
    definition: Definition,
    *,
    snapshots: Mapping[str, str],
    baseline: str | None,
    params: Mapping[str, Param],
    inputs: Mapping[str, ImageInputs],
    decisions: Mapping[str, Decision],
    rejected: Mapping[str, Sequence[str]] | None = None,
    rebuild: Mapping[str, str] | None = None,
    previous: object = None,
) -> dict[str, JsonValue]:
    """plan.json. `decisions` are the targets' answers per image (an image missing from them was not
    looked up anywhere, so it builds); `previous` an earlier plan.json, to say what moved."""
    previous_images = previous.get("images") if isinstance(previous, dict) else None
    images: dict[str, JsonValue] = {}
    states: dict[str, str] = {}
    for name in top_down(definition):
        entry = image_entry(definition, inputs[name])
        parent = definition.images[name].parent
        state = state_of(
            name,
            None if parent is None else states[parent],
            parent,
            decisions.get(name, Decision("build")),
            rebuild or {},
        )
        if state["state"] == "build":
            moved = changes(previous_images.get(name) if isinstance(previous_images, dict) else None, entry)
            because = state["because"]
            if isinstance(because, list):
                because.extend(moved)
        if rejected and rejected.get(name):
            state["rejected"] = list(rejected[name])
        states[name] = str(state["state"])
        images[name] = {**entry, **state}
    return {
        "schema": SCHEMA,
        "factory": __version__,
        "engine": ENGINE,
        "snapshots": dict(snapshots),
        "baseline": baseline,
        "debian": {
            "suite": definition.debian.suite,
            "components": list(definition.debian.components),
            "architecture": definition.debian.architectures[0],
        },
        "params": dict(params),
        "images": images,
    }


def changed(plan: Mapping[str, JsonValue]) -> list[str]:
    """The images a plan builds (the Action's `changed` output)."""
    images = plan.get("images")
    if not isinstance(images, dict):
        return []
    return sorted(name for name, entry in images.items() if isinstance(entry, dict) and entry.get("state") == "build")
