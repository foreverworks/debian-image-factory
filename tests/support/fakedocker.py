"""A stand-in for docker: it records every command and answers the ones the OCI checks send."""

import base64
import json
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

from debian_image_factory.checks.dockerio import Docker

IMAGE_ID = "sha256:" + "1" * 64


def reading(files: Mapping[str, bytes]) -> str:
    return "".join(f"{path} {base64.b64encode(value).decode()}\n" for path, value in files.items())


class FakeDocker:
    """`config` is what `docker image inspect` reports for the loaded image; `exit_code` what the image's
    own run exits with; `identities` the output of each instance two-clones starts, in turn."""

    def __init__(
        self,
        config: Mapping[str, object] | None = None,
        exit_code: int = 0,
        identities: Sequence[str] = ("", ""),
        probes: Mapping[str, tuple[int, str]] | None = None,
        failing: str | None = None,
        load_output: str | None = None,
        timeout_on_run: bool = False,
        missing: bool = False,
    ) -> None:
        self.config = dict(config if config is not None else {"User": "0:0", "Cmd": ["/bin/sh", "-c", "exit 0"]})
        self.exit_code = exit_code
        self.identities = list(identities)
        self.probes = dict(probes or {})
        self.failing = failing
        self.load_output = f"Loaded image ID: {IMAGE_ID}\n" if load_output is None else load_output
        self.timeout_on_run = timeout_on_run
        self.missing = missing
        self.commands: list[list[str]] = []
        self.loaded: list[Path] = []

    def docker(self) -> Docker:
        return Docker(run=self.run, run_limited=self.run_limited, load=self.load)

    def verbs(self) -> list[str]:
        return [command[0] if command[0] != "image" else f"image {command[1]}" for command in self.commands]

    def done(
        self, args: Sequence[str], out: str = "", code: int = 0, err: str = ""
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, code, out, err)

    def run(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if self.missing:
            raise FileNotFoundError("docker")
        self.commands.append(list(args))
        if args[0] == self.failing:
            return self.done(args, code=1, err=f"{args[0]} refused")
        if args[:2] == ["image", "inspect"]:
            return self.done(args, json.dumps(self.config))
        if args[0] == "run":
            return self.done(args, self.identities.pop(0))
        return self.done(args)

    def run_limited(self, args: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.commands.append(list(args))
        if self.timeout_on_run:
            raise subprocess.TimeoutExpired(list(args), timeout)
        if "--entrypoint" in args:
            program = args[args.index("--entrypoint") + 1]
            code, out = self.probes.get(program, (127, ""))
            return self.done(args, out, code)
        return self.done(args, "", self.exit_code, "boom" if self.exit_code else "")

    def load(self, layout: Path) -> subprocess.CompletedProcess[str]:
        self.loaded.append(layout)
        self.commands.append(["load"])
        if self.failing == "load":
            return self.done(["docker", "load"], code=1, err="load refused")
        return self.done(["docker", "load"], self.load_output)
