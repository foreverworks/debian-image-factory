"""The command line (DESIGN 9.1). Exit codes: 0 done, 1 a check or validation failed, 2 usage."""

import argparse
import sys
from collections.abc import Sequence

from . import __version__


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="debian-image-factory", description=__doc__)
    top.add_argument("--version", action="version", version=f"debian-image-factory {__version__}")
    top.add_subparsers(dest="command", metavar="<command>")
    return top


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.command is None:
        parser().print_usage(sys.stderr)
        return 2
    return 0
