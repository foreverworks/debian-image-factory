"""The command line (DESIGN 9.1). Exit codes: 0 done, 1 a check or validation failed, 2 usage.

This release has `lock check`, `lock snapshot`, `lock baseline`, `plan` and `test`; the build stages
arrive in later releases.
"""

import argparse
import io
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__, checks, commands, resolve


def sources_options(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--mirror",
        default=resolve.SNAPSHOT_SERVICE,
        metavar="URL",
        help="read snapshots through a server serving snapshot.debian.org's paths (trusted by signature only)",
    )
    command.add_argument("--keyring", type=Path, default=resolve.DEFAULT_KEYRING, help="the Debian archive keyring")
    command.add_argument(
        "--cache", type=Path, help="the content-addressed download cache (default ~/.cache/debian-image-factory)"
    )


def files_options(command: argparse.ArgumentParser, definition: bool = True) -> None:
    command.add_argument("--lock", type=Path, default=Path("lock.json"), help="the lock (default lock.json)")
    if definition:
        command.add_argument(
            "--definition", type=Path, default=Path("factory.toml"), help="the build definition (default factory.toml)"
        )


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(
        prog="debian-image-factory",
        description="Debian images from one archive snapshot, rebuilt only when their inputs change.",
    )
    top.add_argument("--version", action="version", version=f"debian-image-factory {__version__}")
    commands_ = top.add_subparsers(dest="command", metavar="<command>")

    lock = commands_.add_parser("lock", help="check and move the lock").add_subparsers(
        dest="lock_command", metavar="<lock command>"
    )
    check = lock.add_parser("check", help="the lock and the definition agree; snapshot IDs re-resolved")
    files_options(check)
    sources_options(check)
    check.add_argument("--offline", action="store_true", help="skip re-resolving the snapshot IDs")

    snapshot = lock.add_parser("snapshot", help="move the build snapshot")
    files_options(snapshot, definition=False)
    sources_options(snapshot)
    which = snapshot.add_mutually_exclusive_group(required=True)
    which.add_argument("--latest", action="store_true", help="the newest completed snapshot ID")
    which.add_argument("--id", metavar="ID", help="a given snapshot ID (it must be completed)")

    baseline = lock.add_parser("baseline", help="move the baseline snapshot")
    files_options(baseline)
    sources_options(baseline)
    baseline.add_argument("--id", metavar="ID", required=True, help="the new baseline snapshot ID")

    plan = commands_.add_parser("plan", help="resolve every image, compute identities, look them up")
    files_options(plan)
    sources_options(plan)
    plan.add_argument(
        "--snapshot", default="lock", metavar="lock|latest|ID", help="the build snapshot (default: the lock's)"
    )
    plan.add_argument("--param", action="append", default=[], metavar="NAME=VALUE", help="a parameter value (repeat)")
    plan.add_argument("--params", type=Path, metavar="FILE", help="parameter values as a JSON object")
    plan.add_argument(
        "--against", action="append", default=[], metavar="TARGET", help="look identities up here (repeat)"
    )
    plan.add_argument(
        "--rebuild", action="append", default=[], metavar="IMAGE", help="build this image whatever it finds"
    )
    plan.add_argument("--reason", help="why --rebuild is needed (required with it)")
    plan.add_argument("--previous", type=Path, metavar="PLAN", help="an earlier plan.json, to say what moved")
    plan.add_argument("--out", type=Path, metavar="FILE", help="write plan.json here instead of standard output")

    test = commands_.add_parser("test", help="run the built-in checks on the artifacts in OUT and attest each result")
    test.add_argument("out", type=Path, metavar="OUT", help="a build's output directory (plan.json and the artifacts)")
    sources_options(test)
    test.add_argument(
        "--check", action="append", default=[], metavar="NAME", help="run only this check (repeat); default: the plan's"
    )
    test.add_argument("--url", default="", help="the URL of this run, recorded in each test result")
    return top


def sources_of(arguments: argparse.Namespace) -> commands.Sources:
    cache = arguments.cache if arguments.cache is not None else commands.default_cache()
    return commands.Sources(service=arguments.mirror, keyring=arguments.keyring, cache=cache)


def dispatch(arguments: argparse.Namespace) -> int:
    if arguments.command == "lock":
        if arguments.lock_command == "check":
            return commands.lock_check(
                arguments.lock, arguments.definition, sources_of(arguments), arguments.offline, sys.stdout
            )
        if arguments.lock_command == "snapshot":
            choice = "latest" if arguments.latest else arguments.id
            return commands.lock_snapshot(arguments.lock, choice, sources_of(arguments), sys.stdout)
        if arguments.lock_command == "baseline":
            return commands.lock_baseline(
                arguments.lock, arguments.definition, arguments.id, sources_of(arguments), sys.stdout
            )
        raise commands.Usage("lock needs a command: check, snapshot or baseline")
    if arguments.command == "plan":
        if arguments.rebuild and not arguments.reason:
            raise commands.Usage('--rebuild needs --reason "<why>": the reason is recorded')
        reason = str(arguments.reason or "")
        buffer = io.StringIO()
        status = commands.plan_command(
            arguments.lock,
            arguments.definition,
            sources_of(arguments),
            snapshot_choice=arguments.snapshot,
            param_pairs=arguments.param,
            params_file=arguments.params,
            against=arguments.against,
            rebuild=dict.fromkeys(arguments.rebuild, reason),
            previous_path=arguments.previous,
            out=buffer,
        )
        if arguments.out is None:
            sys.stdout.write(buffer.getvalue())
        else:
            try:
                Path(arguments.out).write_text(buffer.getvalue())
            except OSError as error:
                raise commands.Failed(f"{arguments.out}: {error.strerror or error}") from None
        return status
    if arguments.command == "test":
        return checks.test_command(arguments.out, arguments.check, sources_of(arguments), sys.stdout, url=arguments.url)
    raise commands.Usage("a command is needed: lock, plan or test")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        return dispatch(arguments)
    except commands.Usage as error:
        print(f"debian-image-factory: {error}", file=sys.stderr)
        return 2
    except commands.Failed as error:
        print(str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
