"""What a core build runs in the builder (DESIGN 5.3), as text. Pure.

The builder container sees two directories: `/mirror`, the partial mirror `fetch` laid out
(read-only), and `/factory`, this build's work directory. It has no network. The
mirror is mounted at a path that holds no snapshot ID, and the sources mmdebstrap used are replaced
by the image's own before it is packed, so the build snapshot never reaches the bytes.
"""

import shlex
from collections.abc import Mapping, Sequence
from typing import Final

from input_lock import JsonValue

from ..debian import Suite, suites

MIRROR: Final = "/mirror"
"""Where the partial mirror is mounted inside the builder."""
WORK: Final = "/factory"
"""Where the build's work directory is mounted inside the builder."""
BUILD_KEYRING: Final = f"{WORK}/keyring.pgp"
"""The archive keyring apt verifies the mirror with during the build."""
IMAGE_KEYRING: Final = "/usr/share/keyrings/debian-archive-keyring.pgp"
"""The keyring the image's own apt sources name (debian-archive-keyring installs it)."""
ROOTFS: Final = f"{WORK}/rootfs.tar.gz"
"""What the build leaves in the work directory: the packed root filesystem."""
HOOK_DIR: Final = "/run/factory"
"""Where hooks find their inputs and build.env inside the image; removed before packing (DESIGN 6.5)."""

LIVE_URIS: Final[Mapping[str, str]] = {
    "debian": "http://deb.debian.org/debian",
    "debian-security": "http://security.debian.org/debian-security",
}
"""Where an image's own apt sources point (DESIGN 6.2). http, as Debian's own images do: apt verifies
the signed indices, and an image need not carry CA certificates."""

IDENTITY_FILES: Final = (
    "etc/hostname",
    "etc/resolv.conf",
    "var/lib/dbus/machine-id",
    "var/lib/systemd/random-seed",
    "var/lib/urandom/random-seed",
    "etc/apt/apt.conf.d/99mmdebstrap",
)
"""Removed from every root: identities, the build container's network settings, and apt options
that only the build needed. SSH host keys and cloud-init state are removed by pattern below."""


def grouped(suite: str) -> list[tuple[str, list[Suite]]]:
    """The suites of a snapshot by archive, in order: (`debian`, [trixie, trixie-updates]), ..."""
    found: dict[str, list[Suite]] = {}
    for one in suites(suite):
        found.setdefault(one.archive, []).append(one)
    return list(found.items())


def build_sources(suite: str, components: Sequence[str], *, mirror: str = MIRROR, keyring: str = BUILD_KEYRING) -> str:
    """The one-line apt sources mmdebstrap reads, one line per suite: the partial mirror, copied in
    with apt's `copy:` method (a `file:` mirror outside the chroot is refused) and verified with the
    archive keyring. `mirror` and `keyring` are where the reader of the sources sees them: the
    defaults are the builder's, a child build reads them from inside the image's root.

    Valid-Until is not checked: security Release files expire, and the snapshot ID pins the content
    (DESIGN 7.7); signatures and hashes are still verified."""
    return "".join(
        f"deb [signed-by={keyring} check-valid-until=no] copy://{mirror}/{one.archive} {one.dist} "
        f"{' '.join(components)}\n"
        for one in suites(suite)
    )


def image_sources(mode: str, suite: str, components: Sequence[str], baseline: str | None) -> str:
    """The deb822 `debian.sources` written into the image (DESIGN 6.2's `apt_sources`).

    `live` points at deb.debian.org and security.debian.org; `baseline` pins every suite to the
    baseline snapshot with apt's `Snapshot:` field; `baseline-except-security` pins main and updates
    and leaves security live. The build snapshot never appears here."""
    if mode not in ("live", "baseline", "baseline-except-security"):
        raise ValueError(f"apt_sources {mode!r} is not live, baseline or baseline-except-security")
    if mode != "live" and baseline is None:
        raise ValueError(f"apt_sources {mode!r} needs the baseline snapshot, and the plan has none")
    paragraphs: list[str] = []
    for archive, dists in grouped(suite):
        pinned = mode == "baseline" or (mode == "baseline-except-security" and archive != "debian-security")
        lines = [
            "Types: deb",
            f"URIs: {LIVE_URIS[archive]}",
            f"Suites: {' '.join(one.dist for one in dists)}",
            f"Components: {' '.join(components)}",
            f"Signed-By: {IMAGE_KEYRING}",
        ]
        if pinned:
            lines.append(f"Snapshot: {baseline}")
        paragraphs.append("\n".join(lines) + "\n")
    return "\n".join(paragraphs)


def param_text(value: JsonValue) -> str:
    """A parameter as a hook reads it: booleans as `true` / `false`, everything else as written."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def param_env(params: Mapping[str, JsonValue]) -> list[tuple[str, str]]:
    """`FACTORY_PARAM_<NAME>` for every parameter the image reads (DESIGN 6.3, 6.5)."""
    return [(f"FACTORY_PARAM_{env_suffix(name)}", param_text(value)) for name, value in sorted(params.items())]


def env_suffix(name: str) -> str:
    """A name as an environment variable suffix: upper case, every other character `_`."""
    return "".join(char if char.isascii() and char.isalnum() else "_" for char in name.upper())


def hook_name(index: int, path: str) -> str:
    """Where hook number `index` (from 1) is copied: its order and its file name."""
    return f"{index:02d}-{path.rsplit('/', 1)[-1]}"


def files_lines() -> list[str]:
    """The definition's file tree, over the root `$root`: modes as git keeps them, owned by root."""
    return [
        "# the definition's file tree, modes as git keeps them, owned by root",
        f'tar -C "$root" --no-overwrite-dir -xpf {WORK}/files.tar',
    ]


def hook_lines(hooks: Sequence[str]) -> list[str]:
    """Copy the staged inputs and build.env into the root, then run each hook in the chroot, in order,
    with no network and reading only what fetch verified. The caller removes what it copied."""
    lines = [
        "# hooks run in the chroot, with no network, reading only what fetch verified",
        f'mkdir -p "$root{HOOK_DIR}"',
        f'cp -a {WORK}/run/. "$root{HOOK_DIR}/"',
    ]
    for index, hook in enumerate(hooks, start=1):
        target = f"{HOOK_DIR}/hooks/{hook_name(index, hook)}"
        inner = f'set -a; . {HOOK_DIR}/build.env; set +a; exec "$0"'
        lines.append(f'chroot "$root" /bin/sh -c {shlex.quote(inner)} {shlex.quote(target)}')
    return lines


def identity_lines() -> list[str]:
    """Remove every machine identity and everything only the build needed from the root `$root`
    (DESIGN 5.3). Core and every child build end with exactly these lines."""
    return [
        "# no machine identity, and nothing only the build needed (DESIGN 5.3)",
        'if [ -e "$root/etc/machine-id" ]; then : > "$root/etc/machine-id"; fi',
        *(f'rm -f "$root/{path}"' for path in IDENTITY_FILES),
        'rm -f "$root"/etc/ssh/ssh_host_*',
        'rm -rf "$root/var/lib/cloud/instance" "$root/var/lib/cloud/instances"',
    ]


def customize_script(*, files: bool, hooks: Sequence[str]) -> str:
    """The script mmdebstrap runs as its customize hook, with the root directory as `$1`.

    In order: the image's own apt sources replace the build's; the definition's file tree is copied
    over the root; each hook runs in the chroot with its inputs and build.env under /run/factory;
    then every machine identity and build-only file is removed (DESIGN 5.3)."""
    lines = [
        "set -eu",
        'root="$1"',
        "# the image's own apt sources replace the ones the build read the mirror with",
        'rm -f "$root/etc/apt/sources.list"',
        'find "$root/etc/apt/sources.list.d" -mindepth 1 -delete',
        f'install -m 0644 {WORK}/debian.sources "$root/etc/apt/sources.list.d/debian.sources"',
    ]
    if files:
        lines += files_lines()
    if hooks:
        lines += [*hook_lines(hooks), f'rm -rf "$root{HOOK_DIR}"']
    lines += [*identity_lines(), ""]
    return "\n".join(lines)


def build_script(*, suite: str, request: Sequence[str], source_date_epoch: int, owner: str | None) -> str:
    """The builder's entry point: mmdebstrap's apt variant in root mode, packed as a tar, then gzip
    without a name or time stamp, so the same inputs give the same bytes.

    `owner` (`uid:gid`) hands the artifact back to the invoking user where the container's root is
    the host's (rootful docker); rootless docker needs none."""
    include = ",".join(sorted(set(request)))
    lines = [
        "set -eu",
        f"export SOURCE_DATE_EPOCH={int(source_date_epoch)}",
        "mmdebstrap --mode=root --variant=apt --format=tar"
        + (f" --include={shlex.quote(include)}" if include else "")
        + f" --customize-hook={shlex.quote(f'sh {WORK}/customize.sh "$1"')}"
        + f" {shlex.quote(suite)} {WORK}/rootfs.tar {WORK}/build.list",
        f"gzip -n -9 < {WORK}/rootfs.tar > {ROOTFS}",
        f"rm -f {WORK}/rootfs.tar",
    ]
    if owner is not None:
        lines.append(f"chown {shlex.quote(owner)} {ROOTFS}")
    return "\n".join(lines) + "\n"
