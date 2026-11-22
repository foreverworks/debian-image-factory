"""Run the shell steps of the repository's composite action (action.yml) on this machine, the way the runner
does: each `run:` step is a bash script with `-e -o pipefail`, its `env:` evaluated, its `if:` honoured, and
what it writes to `$GITHUB_OUTPUT` read back for the steps after it. `uses:` steps are skipped (the runner
provides them). It also loads scripts/action-support, which is not a module name.

Only the expressions the Action uses are understood: `inputs.X`, `steps.ID.outputs.NAME`, `github.action_path`
and `runner.temp`, and `if:` conditions of `==` and `!=` comparisons joined by `&&`.
"""

import importlib.machinery
import importlib.util
import os
import re
import subprocess
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Final, cast

ROOT: Final = Path(__file__).resolve().parents[2]
ACTION: Final = ROOT / "action.yml"
SUPPORT: Final = ROOT / "scripts" / "action-support"

type Node = str | list[Node] | dict[str, Node]

EXPRESSION: Final = re.compile(r"\$\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}")
COMPARISON: Final = re.compile(r"\s*([A-Za-z0-9_.-]+)\s*(==|!=)\s*'([^']*)'\s*")


def load_support() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("action_support", str(SUPPORT))
    spec = importlib.util.spec_from_loader("action_support", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


support = load_support()


def parse_yaml(text: str) -> Node:
    return cast(Node, support.parse_yaml(text))


@dataclass(frozen=True, slots=True)
class Step:
    id: str
    name: str
    condition: str
    uses: str
    env: dict[str, str]
    run: str


def mapping(node: Node | None) -> dict[str, Node]:
    assert isinstance(node, dict)
    return node


def text_of(node: Node | None) -> str:
    return node if isinstance(node, str) else ""


def read_action(path: Path = ACTION) -> dict[str, Node]:
    return mapping(parse_yaml(path.read_text(encoding="utf-8")))


def read_steps(path: Path = ACTION) -> list[Step]:
    steps = mapping(read_action(path)["runs"])["steps"]
    assert isinstance(steps, list)
    found = []
    for raw in steps:
        step = mapping(raw)
        env = step.get("env")
        found.append(
            Step(
                id=text_of(step.get("id")),
                name=text_of(step.get("name")),
                condition=text_of(step.get("if")),
                uses=text_of(step.get("uses")),
                env={key: text_of(value) for key, value in mapping(env).items()} if env is not None else {},
                run=text_of(step.get("run")),
            )
        )
    return found


def input_defaults(path: Path = ACTION) -> dict[str, str]:
    inputs = mapping(read_action(path)["inputs"])
    return {name: text_of(mapping(spec).get("default")) for name, spec in inputs.items()}


@dataclass(slots=True)
class Result:
    """What running the Action did: whether every step passed, each step's outputs by id, and the log."""

    ok: bool = True
    outputs: dict[str, dict[str, str]] = field(default_factory=dict)
    log: str = ""
    failed: str = ""


def evaluate(text: str, context: Mapping[str, str]) -> str:
    """`text` with its `${{ name }}` expressions replaced; an output no step wrote is empty, as on the runner."""

    def value(found: re.Match[str]) -> str:
        name = found[1]
        if name in context:
            return context[name]
        if name.startswith("steps."):
            return ""
        raise KeyError(f"the Action reads {name}, which this runner does not know")

    return EXPRESSION.sub(value, text)


def holds(condition: str, context: Mapping[str, str]) -> bool:
    if not condition:
        return True
    for part in condition.split("&&"):
        found = COMPARISON.fullmatch(part)
        if found is None:
            raise ValueError(f"cannot evaluate the condition {condition!r}")
        left = context.get(found[1], "")
        if (left == found[3]) != (found[2] == "=="):
            return False
    return True


def outputs_of(path: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            found[key] = value
    return found


def run_action(
    inputs: Mapping[str, str],
    *,
    scratch: Path,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    skip: Collection[str] = (),
    until: str | None = None,
) -> Result:
    """Run the Action's shell steps in order with `inputs` (the others at their defaults), from `cwd`, with
    `scratch` as the runner's temp directory. Steps named in `skip` (by id) are left out, and the run stops after
    the step `until` names. Stops at the first step that fails."""
    steps = read_steps()
    context: dict[str, str] = {
        **{f"inputs.{name}": value for name, value in input_defaults().items()},
        **{f"inputs.{name}": value for name, value in inputs.items()},
        "github.action_path": str(ROOT),
        "runner.temp": str(scratch),
    }
    result = Result()
    environment = {
        **os.environ,
        "GITHUB_SERVER_URL": "https://github.example.com",
        "GITHUB_REPOSITORY": "example/images",
        "GITHUB_RUN_ID": "1",
        **(env or {}),
    }
    scratch.mkdir(parents=True, exist_ok=True)
    for number, step in enumerate(steps, start=1):
        label = step.id or step.name or f"step {number}"
        if step.uses or step.id in skip or not holds(step.condition, context):
            continue
        script = scratch / f"step-{number:02d}.sh"
        script.write_text(evaluate(step.run, context), encoding="utf-8")
        output = scratch / f"step-{number:02d}.out"
        output.write_text("")
        step_env = {key: evaluate(value, context) for key, value in step.env.items()}
        done = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", str(script)],
            cwd=cwd,
            env={**environment, **step_env, "GITHUB_OUTPUT": str(output)},
            capture_output=True,
            text=True,
            check=False,
        )
        result.log += f"== {label}\n{done.stdout}{done.stderr}"
        written = outputs_of(output)
        result.outputs[step.id] = written
        context.update({f"steps.{step.id}.outputs.{key}": value for key, value in written.items()})
        if done.returncode != 0:
            result.ok, result.failed = False, label
            return result
        if until is not None and step.id == until:
            return result
    return result
