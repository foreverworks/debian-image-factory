"""`locked-inputs` (DESIGN 11), pure: every lock entry an image installs is there at its locked version.

An entry with an `apt` field is a package: its version is read from the image's dpkg status. An entry
a module installs is run through the module's probes (`modules.probes`): each probe is a command run in
the image, and the entry counts as installed when it exits 0 and prints the version the lock names. An
entry with neither is not installed as a file, and no probe can see it: the Node.js release keyring is a
trust root `fetch` used to verify the checksums (the plan names it: it is what an entry's `signed_by` names), and
the check lists it as passed, saying so.

Running a probe is the edge's job (the OCI checks run it in a container): it is passed in as `Runner`.
"""

from collections.abc import Callable, Collection, Mapping

from input_lock import Value

from .. import modules as modules_
from ..definition import Module
from ..modules import Fields, Probe
from .model import LIMIT, Result, result
from .packages import installed

LOCKED_INPUTS = "locked-inputs"

TRUST_ROOT = "trust root, not installed"
NO_MODULE = "no module installs it: the image's own hooks use it, and the check has nothing to probe"

type Runner = Callable[[Probe], tuple[int, str]]
"""Runs a probe's command in the built image: (exit code, standard output)."""


def text(value: Value) -> str | None:
    return value if isinstance(value, str) and value else None


def apt_problem(name: str, fields: Fields, found: list[tuple[str, str, str]] | str) -> str | None:
    """Why the dpkg status does not hold the package an `apt` entry names at its version; None when it does."""
    package, version = text(fields.get("apt")), text(fields.get("version"))
    if package is None or version is None:
        return f"{name}: an apt entry needs its package name and a version"
    if isinstance(found, str):
        return f"{name}: {found}"
    versions = sorted(version_ for name_, version_, _arch in found if name_ == package)
    if version in versions:
        return None
    if versions:
        return f"{name}: {package} is installed at {', '.join(versions)}, the lock says {version}"
    return f"{name}: {package} {version} is not installed"


def probe_problem(name: str, probe: Probe, run: Runner) -> str | None:
    """Run one probe; why it does not show the entry installed at the expected output, or None."""
    code, output = run(probe)
    command = " ".join(probe.argv)
    if code != 0:
        return f"{name}: `{command}` exited {code}"
    if output.strip() != probe.expected:
        return f"{name}: `{command}` printed {output.strip()!r}, expected {probe.expected!r}"
    return None


def module_probes(module_name: str, modules: Mapping[str, Module], entries: Mapping[str, Fields]) -> list[Probe] | str:
    """The probes of a module's entries, or why it has none (the module is unknown or not probed yet)."""
    module = modules.get(module_name)
    if module is None:
        return f"module {module_name} is not in the definition"
    try:
        return modules_.probes(module, entries)
    except NotImplementedError:
        return f"module {module_name} ({module.use}) has no version probe in this release"
    except ValueError as error:
        return str(error)


def locked_inputs(
    inputs: Mapping[str, Fields],
    modules: Mapping[str, Module],
    status: bytes | None,
    run: Runner,
    trust_roots: Collection[str] = (),
) -> Result:
    """Every entry of `inputs` (the plan's, entry name to `build_fields`) is installed at its locked version.

    `modules` are the definition's modules, `status` the image's `/var/lib/dpkg/status` (None when it has
    none), `trust_roots` the entries a plan's `trust` names as `signed_by`: keyrings, never installed."""
    found = None
    by_module: dict[str, dict[str, Fields]] = {}
    for name, fields in sorted(inputs.items()):
        module = text(fields.get("module"))
        if text(fields.get("apt")) is None and module is not None and name not in trust_roots:
            by_module.setdefault(module, {})[name] = fields
    probes: dict[str, list[Probe] | str] = {m: module_probes(m, modules, group) for m, group in by_module.items()}
    passed: list[str] = []
    failed: list[str] = []
    for name, fields in sorted(inputs.items()):
        module = text(fields.get("module"))
        if name in trust_roots:
            passed.append(f"{name} ({TRUST_ROOT})")
            continue
        if text(fields.get("apt")) is not None:
            found = found if found is not None else installed(status)
            problem = apt_problem(name, fields, found)
            problems = [] if problem is None else [problem]
        elif module is None:
            passed.append(f"{name} ({NO_MODULE})")
            continue
        else:
            listed = probes[module]
            if isinstance(listed, str):
                problems = [f"{name}: {listed}"]
            else:
                own = [probe for probe in listed if probe.entry == name]
                if not own:  # a keyring is a trust root, handled above; anything else must be seen installed
                    failed.append(f"{name}: module {module} has no probe that sees it installed")
                    continue
                problems = [problem for probe in own if (problem := probe_problem(name, probe, run)) is not None]
        if problems:
            failed.extend(problems)
        else:
            passed.append(name)
    more = [f"and {len(failed) - LIMIT} more"] if len(failed) > LIMIT else []
    return result(LOCKED_INPUTS, passed, failed=[*failed[:LIMIT], *more])
