"""Docker as the container checks reach it: the one edge, so every check can be tested with a stand-in.

`Docker` holds three effects: run a docker command, run one with its own time limit, and load an OCI image
layout (a tar of the layout directory streamed into `docker load`, which Docker 29 reads as an image archive).
"""

import contextlib
import subprocess
import tarfile
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

DEFAULT_TIMEOUT: Final = 900.0
LOAD_TIMEOUT: Final = 900.0

type Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
type LimitedRunner = Callable[[Sequence[str], float], subprocess.CompletedProcess[str]]
type Loader = Callable[[Path], subprocess.CompletedProcess[str]]


def run_docker_limited(args: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """`docker <args>` with standard input closed. subprocess.TimeoutExpired when it takes longer than `timeout`."""
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False, timeout=timeout, stdin=subprocess.DEVNULL
    )


def run_docker(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return run_docker_limited(args, DEFAULT_TIMEOUT)


def layout_files(layout: Path) -> list[Path]:
    """Every file under the layout directory, in a stable order."""
    return sorted(path for path in layout.rglob("*") if path.is_file())


def load_layout(layout: Path) -> subprocess.CompletedProcess[str]:
    """`docker load` of the OCI image layout directory `layout`, fed a tar of it on standard input.

    The tar holds the layout's own files at its root (`oci-layout`, `index.json`, `blobs/sha256/...`),
    each as a plain regular file owned by root. Docker's answers are written to temporary files so a long
    reply never blocks the writer. subprocess.TimeoutExpired when docker does not finish in LOAD_TIMEOUT."""
    command = ["docker", "load"]
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err) as process:
            assert process.stdin is not None
            try:
                with tarfile.open(fileobj=process.stdin, mode="w|") as archive:
                    for path in layout_files(layout):
                        info = archive.gettarinfo(str(path), arcname=path.relative_to(layout).as_posix())
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mode = 0o644
                        with path.open("rb") as handle:
                            archive.addfile(info, handle)
            except BrokenPipeError:
                pass  # docker stopped reading: its own answer says why
            finally:
                with contextlib.suppress(BrokenPipeError):
                    process.stdin.close()
            try:
                code = process.wait(timeout=LOAD_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                raise
        out.seek(0)
        err.seek(0)
        return subprocess.CompletedProcess(
            command, code, out.read().decode(errors="replace"), err.read().decode(errors="replace")
        )


@dataclass(frozen=True, slots=True)
class Docker:
    """The effects a container check has. Replace any of them in a test."""

    run: Runner = run_docker
    run_limited: LimitedRunner = run_docker_limited
    load: Loader = load_layout


DOCKER: Final = Docker()
