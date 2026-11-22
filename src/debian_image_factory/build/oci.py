"""What an OCI image's child build runs in the builder (DESIGN 5.3), as text. Pure.

The builder container sees `/mirror` (read-only) and `/factory`, this build's work directory, as for
core, and has no network. The work directory holds the parent's layers (`layers/NNN.tar.gz`, base
first), the layer program (`layer.py`), and what core's build reads: the keyring, the file tree, the
hooks with their inputs and build.env. `build.sh` then:

1. unpacks the parent's layers into `/factory/root` and records the state of every path;
2. enters that root with proc, a minimal /dev and the mirror mounted, installs the image's packages with
   the image's own apt from the mirror (its own sources set aside, a policy-rc.d that refuses service
   starts, start-stop-daemon replaced, as mmdebstrap does), then lays down the file tree, the modules
   and the hooks;
3. removes every machine identity and the traces of the build (what mmdebstrap's cleanup removes: apt
   lists, caches and logs, ldconfig's cache, the build's own apt options, /run and /tmp), puts the image's
   apt sources back, and unmounts;
4. writes the one layer that turns the parent into the result (see `layer.py`).

The work directory's root is deleted when the script ends, so that files owned by other users of the
container's user namespace never stay behind on the host.
"""

import shlex
from collections.abc import Sequence
from typing import Final

from . import core

ROOT: Final = f"{core.WORK}/root"
LAYER_PROGRAM: Final = f"{core.WORK}/layer.py"
LAYERS: Final = f"{core.WORK}/layers"
STATE: Final = f"{core.WORK}/parent.state.json"
LAYER: Final = f"{core.WORK}/layer.tar.gz"
DIFF_ID: Final = f"{core.WORK}/layer.diff_id"
STATUS: Final = f"{core.WORK}/dpkg-status"
"""dpkg's status of the finished root, copied out for the SBOM."""
ASIDE: Final = f"{core.WORK}/aside"
"""Where the image's own apt sources and policy-rc.d wait while the build uses its own."""

RUN: Final = "/run/factory"
CHILD_MIRROR: Final = f"{RUN}/mirror"
"""Where the mirror is bind-mounted inside the image's root, so that the image's own apt can read it."""
CHILD_KEYRING: Final = f"{RUN}/keyring.pgp"
DEBS: Final = f"{RUN}/debs"
"""Where an image's vendor .deb files wait inside its root while apt installs them."""

DEV_NODES: Final = ("null", "zero", "full", "random", "urandom", "tty")
"""The devices a maintainer script may open. Bound from the builder's own /dev onto a tmpfs over the
root's /dev, so nothing changes in the root and nothing needs mknod."""

LOGS: Final = (
    "var/log/dpkg.log",
    "var/log/apt/history.log",
    "var/log/apt/term.log",
    "var/log/alternatives.log",
    "var/log/apt/eipp.log.xz",
    "var/cache/ldconfig/aux-cache",
)
"""What mmdebstrap removes so that its output is reproducible (`cleanup/reproducible`)."""

ENVIRONMENT: Final = (
    "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "export LC_ALL=C.UTF-8 LANG=C.UTF-8 LANGUAGE=C.UTF-8",
    "export DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true",
)
"""What mmdebstrap exports before it runs anything."""

APT_OPTIONS: Final = (
    ("00factory-build", 'APT::Install-Recommends "false";\\nAcquire::Languages "none";\\n'),
    ("99factory-build", "#clear DPkg::Pre-Install-Pkgs;\\n"),
)
"""mmdebstrap's `00mmdebstrap` and `99debconf`: no recommends or translations, and no dpkg-preconfigure
(which would need debconf prompts answered). The second sorts after Debian's own 70debconf, which would
add the preconfigure hook back."""

FAKE_POLICY: Final = "#!/bin/sh\\nexit 101\\n"
FAKE_START_STOP: Final = '#!/bin/sh\\necho "Warning: Fake start-stop-daemon called, doing nothing" >&2\\n'


def layer_name(index: int) -> str:
    """The work directory's name for the parent's layer number `index` (from 0, base first)."""
    return f"{index:03d}.tar.gz"


def unpack_lines(count: int, source_date_epoch: int) -> list[str]:
    """Unpack the parent's layers and record the state of every path."""
    layers = " ".join(f"{LAYERS}/{layer_name(index)}" for index in range(count))
    return [
        "# the parent's filesystem, layer by layer, and the state of every path in it",
        'mkdir -p "$root"',
        f'python3 -I {LAYER_PROGRAM} unpack --root "$root" --state {STATE} --epoch {int(source_date_epoch)} {layers}',
    ]


def mount_lines() -> list[str]:
    """proc and a minimal /dev (the devices a maintainer script opens, and a devpts for apt's terminal log)."""
    lines = [
        "# proc and the devices a maintainer script opens; the root's own /dev is left untouched under a tmpfs",
        'mount -t proc proc "$root/proc" 2>/dev/null || mount -o rbind /proc "$root/proc"',
        'mount -t tmpfs -o mode=0755 tmpfs "$root/dev"',
    ]
    for node in DEV_NODES:
        lines += [f'touch "$root/dev/{node}"', f'mount --bind /dev/{node} "$root/dev/{node}"']
    lines += [
        'mkdir "$root/dev/pts"',
        'mount -t devpts -o noexec,nosuid,uid=5,mode=620,ptmxmode=666 devpts "$root/dev/pts" 2>/dev/null'
        ' || mount --bind /dev/pts "$root/dev/pts"',
        'ln -s pts/ptmx "$root/dev/ptmx"',
        'ln -s /proc/self/fd "$root/dev/fd"',
        'ln -s /proc/self/fd/0 "$root/dev/stdin"',
        'ln -s /proc/self/fd/1 "$root/dev/stdout"',
        'ln -s /proc/self/fd/2 "$root/dev/stderr"',
    ]
    return lines


def unmount_lines(*, mirror: bool, quiet: bool = False) -> list[str]:
    """Undo `mount_lines` and, when `mirror`, the mirror mount, in reverse. With `quiet`, a failure is not one."""
    tail = " 2>/dev/null || true" if quiet else ""
    lines = [f'umount "$root{CHILD_MIRROR}"{tail}'] if mirror else []
    lines += [f'umount "$root/dev/{node}"{tail}' for node in reversed(DEV_NODES)]
    lines += [f'umount "$root/dev/pts"{tail}', f'umount "$root/dev"{tail}', f'umount -R "$root/proc"{tail}']
    return lines


def apt_setup_lines() -> list[str]:
    """Make the root's apt read the mirror, and keep its maintainer scripts from starting services."""
    sources = f"{ASIDE}/sources.list.d"
    lines = [
        "# the mirror and its keyring, where the image's own apt can read them",
        f'mkdir -p "$root{CHILD_MIRROR}"',
        f'mount --bind {core.MIRROR} "$root{CHILD_MIRROR}"',
        f'install -m 0644 {core.WORK}/keyring.pgp "$root{CHILD_KEYRING}"',
        "# the image's own apt sources wait while the build's are used",
        f"mkdir -p {sources}",
        f'if [ -e "$root/etc/apt/sources.list" ]; then mv "$root/etc/apt/sources.list" {ASIDE}/sources.list; fi',
        f'find "$root/etc/apt/sources.list.d" -mindepth 1 -maxdepth 1 -exec mv -t {sources} {{}} +',
        f'install -m 0644 {core.WORK}/build.list "$root/etc/apt/sources.list"',
        "# the build's own apt options, as mmdebstrap sets them",
    ]
    lines += [f"printf '{text}' > \"$root/etc/apt/apt.conf.d/{name}\"" for name, text in APT_OPTIONS]
    lines += [
        "# no service starts: a policy-rc.d that refuses, and a start-stop-daemon that does nothing",
        f'if [ -e "$root/usr/sbin/policy-rc.d" ]; then mv "$root/usr/sbin/policy-rc.d" {ASIDE}/policy-rc.d; fi',
        f"printf '{FAKE_POLICY}' > \"$root/usr/sbin/policy-rc.d\"",
        'chmod 0755 "$root/usr/sbin/policy-rc.d"',
        'if [ -f "$root/usr/sbin/start-stop-daemon" ]; then',
        '    mv "$root/usr/sbin/start-stop-daemon" "$root/usr/sbin/start-stop-daemon.REAL"',
        f"    printf '{FAKE_START_STOP}' > \"$root/usr/sbin/start-stop-daemon\"",
        '    chmod 0755 "$root/usr/sbin/start-stop-daemon"',
        "fi",
    ]
    return lines


def install_lines(request: Sequence[str], debs: Sequence[str] = ()) -> list[str]:
    """apt from the mirror, inside the root, with no recommends: the `request` packages and the vendor .deb
    files at the builder paths `debs` (each verified by fetch through its repository's signature), in one
    transaction, so the .deb's dependencies come from the snapshot as apt resolves them with the rest.

    The files are copied into the root under `DEBS` for the transaction and removed after it."""
    names = [shlex.quote(name) for name in sorted(set(request))]
    lines = ["# the image's packages, from the mirror, with the image's own apt"]
    if debs:
        lines += [
            "# the image's vendor .deb files, verified by fetch, installed in the same transaction",
            f'mkdir -p "$root{DEBS}"',
            *(f'install -m 0644 {shlex.quote(path)} "$root{DEBS}/{deb_name(path)}"' for path in sorted(set(debs))),
        ]
        names += [shlex.quote(f"{DEBS}/{deb_name(path)}") for path in sorted(set(debs))]
    lines += [
        'chroot "$root" apt-get update',
        f'chroot "$root" apt-get --yes --no-install-recommends install {" ".join(names)}',
    ]
    if debs:
        lines.append(f'rm -rf "$root{DEBS}"')
    return lines


def deb_name(path: str) -> str:
    """The file name a vendor .deb has inside the root: its own, which apt reads as a file because of the path."""
    return path.rstrip("/").rsplit("/", 1)[-1]


def apt_cleanup_lines() -> list[str]:
    """Empty apt's lists and caches as mmdebstrap does, put the image's apt sources and everything the
    build replaced back, and remove the build's apt options."""
    sources = f"{ASIDE}/sources.list.d"
    lines = [
        "# apt's lists and caches emptied, as mmdebstrap's cleanup does",
        'chroot "$root" apt-get -o Dir::Etc::SourceList=/dev/null -o Dir::Etc::SourceParts=/dev/null update',
        'chroot "$root" apt-get clean',
        'rm -rf "$root/var/lib/apt/lists/auxfiles"',
    ]
    lines += [f'rm -f "$root/etc/apt/apt.conf.d/{name}"' for name, _ in APT_OPTIONS]
    lines += [
        "# what the build replaced goes back, the very files, so that nothing about them changes",
        'rm -f "$root/etc/apt/sources.list" "$root/usr/sbin/policy-rc.d"',
        f'if [ -e {ASIDE}/sources.list ]; then mv {ASIDE}/sources.list "$root/etc/apt/sources.list"; fi',
        f"if [ -d {sources} ]; then",
        f'    find {sources} -mindepth 1 -maxdepth 1 -exec mv -t "$root/etc/apt/sources.list.d" {{}} +',
        "fi",
        f'if [ -e {ASIDE}/policy-rc.d ]; then mv {ASIDE}/policy-rc.d "$root/usr/sbin/policy-rc.d"; fi',
        'if [ -e "$root/usr/sbin/start-stop-daemon.REAL" ]; then',
        '    mv "$root/usr/sbin/start-stop-daemon.REAL" "$root/usr/sbin/start-stop-daemon"',
        "fi",
    ]
    return lines


def trace_lines() -> list[str]:
    """Logs and caches whose bytes would differ from build to build."""
    return ["# logs and caches whose bytes differ from build to build", *(f'rm -f "$root/{path}"' for path in LOGS)]


def run_cleanup_lines() -> list[str]:
    """/run and /tmp emptied once nothing is mounted in them, as mmdebstrap's cleanup does."""
    return [
        "# /run and /tmp hold nothing in an image",
        f'rm -rf --one-file-system "$root{RUN}"',
        'find "$root/run" -mindepth 1 -maxdepth 1 ! -name lock -exec rm -rf --one-file-system {} +',
        'find "$root/tmp" -mindepth 1 -maxdepth 1 -exec rm -rf --one-file-system {} +',
    ]


def pack_lines(source_date_epoch: int, owner: str | None) -> list[str]:
    """Write the layer, and hand the outputs to the invoking user where the container's root is the host's."""
    lines = [
        "# the one layer that turns the parent into this root",
        f'python3 -I {LAYER_PROGRAM} pack --root "$root" --state {STATE} --epoch {int(source_date_epoch)}'
        f" --out {LAYER} --diff-id {DIFF_ID} --status-out {STATUS}",
    ]
    if owner is not None:
        lines += [
            f"for output in {LAYER} {DIFF_ID} {STATUS}; do",
            f'    if [ -e "$output" ]; then chown {shlex.quote(owner)} "$output"; fi',
            "done",
        ]
    return lines


def prologue_lines(source_date_epoch: int, *, mirror: bool) -> list[str]:
    """How every child build starts: strict shell, what mmdebstrap exports, `$root`, and a trap that
    unmounts (the mirror too, when `mirror`) and deletes the root whatever happens."""
    return [
        "set -eu",
        f"export SOURCE_DATE_EPOCH={int(source_date_epoch)}",
        *ENVIRONMENT,
        "umask 022",
        f'root="{ROOT}"',
        "cleanup() {",
        "    status=$?",
        *(f"    {line}" for line in unmount_lines(mirror=mirror, quiet=True)),
        f'    rm -rf --one-file-system "$root" {ASIDE}',
        '    exit "$status"',
        "}",
        "trap cleanup EXIT",
    ]


def child_lines(
    *,
    request: Sequence[str],
    files: bool,
    module_lines: Sequence[str],
    hooks: Sequence[str],
    debs: Sequence[str] = (),
    sources: Sequence[str] = (),
    finish: Sequence[str] = (),
) -> list[str]:
    """What every child build does to its unpacked root `$root`, whatever it packs: the mounts; apt from the
    mirror when `request` names packages or `debs` vendor .deb files; the file tree, the modules' lines and
    the hooks; apt's cleanup; `sources` (lines that replace the image's apt sources, for kinds that carry
    their own); the build's traces and every machine identity removed; `finish` (a booting kind's
    `boot.boot_lines`); the unmounts; /run and /tmp emptied."""
    apt = bool(request or debs)
    lines = [*mount_lines()]
    if apt:
        lines += [*apt_setup_lines(), *install_lines(request, debs)]
    if files:
        lines += core.files_lines()
    lines += list(module_lines)
    if hooks:
        lines += [
            *core.hook_lines(hooks),
            *(f'rm -rf "$root{core.HOOK_DIR}/{name}"' for name in ("hooks", "inputs", "build.env")),
        ]
    if apt:
        lines += apt_cleanup_lines()
    lines += [
        *sources,
        *trace_lines(),
        *core.identity_lines(),
        *finish,
        *unmount_lines(mirror=apt),
        *run_cleanup_lines(),
    ]
    return lines


def build_script(
    *,
    layers: int,
    request: Sequence[str],
    source_date_epoch: int,
    owner: str | None,
    files: bool,
    module_lines: Sequence[str],
    hooks: Sequence[str],
    debs: Sequence[str] = (),
) -> str:
    """The builder's entry point for one OCI child: `layers` parent layers in, one layer out.

    `request` is what the image installs with apt and `debs` the builder paths of its vendor .deb files,
    installed in the same transaction (neither: no apt setup), `module_lines` what the switched-on builtin
    modules run in the builder with the root as `$root`, `hooks` the scripts that run in the chroot after
    them. `owner` (`uid:gid`) hands the outputs back where the container's root is the host's."""
    lines = [
        *prologue_lines(source_date_epoch, mirror=bool(request or debs)),
        *unpack_lines(layers, source_date_epoch),
        *child_lines(request=request, files=files, module_lines=module_lines, hooks=hooks, debs=debs),
        *pack_lines(source_date_epoch, owner),
        "",
    ]
    return "\n".join(lines)
