"""What every kind that boots (incus, installer, os) does to its root last (DESIGN 5.3), as shell text. Pure.

A booting image's `/etc/machine-id` holds `uninitialized`, so systemd treats its first boot as a first
boot: it creates the machine ID then, and runs every unit with `ConditionFirstBoot=yes`. That is also how
the image gets its SSH host keys. Debian 13's openssh-server (1:10.0p1-7) ships `sshd-keygen.service`
(`ConditionFirstBoot=yes`, `ExecStart=ssh-keygen -A`, ordered before ssh.service and enabled for
ssh.service and ssh.socket), so the factory adds no unit of its own: the identity removal in
`core.identity_lines` deletes the keys the package's postinst made, and the first boot makes new ones.
"""

from typing import Final

UNINITIALIZED: Final = "uninitialized"
"""What `/etc/machine-id` holds in a booting image (machine-id(5): the first boot has not happened)."""


def boot_lines() -> list[str]:
    """Shell lines over the root `$root`, run after `core.identity_lines`: the machine ID waits for the
    first boot. An image without systemd's /etc/machine-id gets one, since a booting kind always boots
    systemd (its kind defaults install systemd-sysv)."""
    return [
        "# a booting image's first boot is a first boot: systemd creates the machine ID and SSH host keys then",
        f"printf '{UNINITIALIZED}\\n' > \"$root/etc/machine-id\"",
        'chmod 0444 "$root/etc/machine-id"',
    ]
