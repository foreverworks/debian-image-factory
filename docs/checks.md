# Checks

A check runs on the exact artifact a build made and writes one test result: an in-toto statement
about the artifact's sha256, kept in the artifact's records file. A test result links here, to the
section named after the check (`docs/checks.md#no-machine-identity`), so a person who sees a failed
check can learn what it proves and what to do about it.

## How a result is decided

A check is made of tests, small yes or no questions with a stable name. The result lists the names
that passed, warned and failed.

- **PASSED**: every test passed.
- **FAILED**: at least one test failed. The artifact stays a candidate: it is not reused, and pins do
  not move to it.
- **WARNED**: no test failed and at least one warned. Only `byte-equal` warns; every other check
  has two outcomes.

A check that is not required for an image has no say in whether the image is good. A good build is
one whose required checks all PASSED or WARNED. When a build has several results for one check, the
last one in the file wins.

Where a check below names a later milestone (M3 brings oci, M4 incus, M5 the installer and the OS
image), the factory does not build that kind yet, and its checks arrive with it.

## package-set

Kinds: all. Brought by: core in M2, oci in M3, incus in M4, installer and os in M5.

It proves that the image holds exactly the packages the plan resolved. The check reads the image's
own dpkg status and compares it with the plan's resolved set, so a package that was pulled in
unplanned, or one that is missing, is caught.

PASSED when the two sets are equal. FAILED when they differ, naming the extra and the missing
packages. It reports one test, named like the check.

## locked-inputs

Kinds: all that use lock entries. Brought by: core in M2 (a core has no lock entries, so it has
nothing to ask there), oci in M3, incus in M4, installer and os in M5.

It proves that every lock entry the image uses is installed at its locked version. An entry that is
a Debian package is looked up in dpkg; any other entry is asked through its module's own version
probe.

PASSED when every entry is at its locked version. FAILED when one is missing or at another version.
It reports one test, named like the check.

## no-machine-identity

Kinds: all. Brought by: core in M2, oci in M3, incus in M4, installer and os in M5; the same tests apply to every kind.

It proves that the artifact carries nothing that belongs to the machine that built it. An image
with a machine ID, SSH host keys or a hostname baked in would give every clone the same identity,
which is the reason to check before anything else. The build removes the copies that mmdebstrap
takes from the build container; this check confirms it did.

PASSED when every test passes, FAILED when any fails; it never warns. The tests it reports:

- `machine-id-empty-or-uninitialized`: `/etc/machine-id` is absent, empty or holds `uninitialized`,
  so the first boot creates the identity.
- `no-dbus-machine-id`: there is no `/var/lib/dbus/machine-id`.
- `no-ssh-host-keys`: there are no SSH host keys (`/etc/ssh/ssh_host_*`).
- `no-private-keys`: no file matches the patterns of private keys and tokens.
- `no-random-seed`: there is no saved random seed, which would make two clones start from the
  same entropy.
- `no-cloud-init-state`: there is no cloud-init instance state, so cloud-init runs as a first boot
  on every clone.
- `no-hostname`: `/etc/hostname` is absent or empty.
- `no-resolver-config`: `/etc/resolv.conf` is absent or a symbolic link, not the build
  container's own copy.

## two-clones

Kinds: all. Brought by: core and oci in M3, incus in M4, installer and os in M5.

It proves that two instances of the artifact share no identity: their machine IDs and SSH host
keys, where they have them, differ. A core and an OCI image run as two rootless containers, an Incus
image as two instances, the installer and the OS image as two virtual machines.

PASSED when every identity that exists differs between the two. FAILED when any is equal.

## sbom-complete

Kinds: all. Brought by: core in M2, oci in M3, incus in M4, installer and os in M5.

It proves that the SBOM lists every installed package and every locked input, so the SBOM can be
trusted as the inventory. The check compares the SBOM's packages with the image's dpkg status and
the lock entries the image uses.

PASSED when nothing is missing and nothing is listed that is not there. FAILED otherwise, naming the
differences.

## ancestry

Kinds: children. Brought by: oci in M3, incus in M4, installer and os in M5.

It proves that a child really is built on its parent. For an OCI image, the parent's layers are
the first layers, by digest. For the other kinds, the parent's files are present unless the child's
own records say it removed them.

PASSED when the parent's content is the base. FAILED when it is not.

## same-resolution

Kinds: core. Brought by: core in M2.

It proves that the resolution is repeatable: a second resolution of the same lock, against the same
snapshot, gives the same package set. If it did not, the identity would name something that cannot
be rebuilt.

PASSED when the two sets are equal. FAILED when they differ.

## no-build-snapshot

Kinds: all. Brought by: core in M2, oci in M3, incus in M4, installer and os in M5.

It proves that the build snapshot's timestamp appears nowhere in the artifact's bytes, including the
build-time `file://` source, which the `apt_sources` rendering replaces before the image is packed.
The snapshot belongs in the record, not in the bytes: otherwise two builds of one package set would
differ only by when they ran. When the baseline snapshot's ID equals the build snapshot's, the
check cannot tell the two apart and is skipped with a note.

PASSED when the ID is found nowhere. FAILED when it is found, naming the files.

## byte-equal

Kinds: all, optional. Brought by: core in M2.

It reports whether two builds from the same inputs give the same digest. A difference is not a
fault of the artifact, so this check never fails: it is WARNED when the digests differ, and the
difference is for a person to look at.

PASSED when the digests are equal. WARNED when they differ.

## oci-run

Kinds: oci. Brought by: M3.

It proves that the image runs under rootless Docker with its declared user and entrypoint, and that
its `cmd` exits 0.

PASSED when it does. FAILED when it does not start or `cmd` exits with another status.

## incus-boot

Kinds: incus. Brought by: M4.

It proves that the image boots and is usable in an Incus host inside a virtual machine: cloud-init
finishes through NoCloud from both `cloud-init.user-data` and the older `user.user-data`, creates the
user, runs the given commands, and an IPv4 address is reported; all of it is still true after a
restart.

PASSED when every step succeeds. FAILED when one does not.

## installer-boot

Kinds: installer. Brought by: M5.

It proves that QEMU boots the kit from RAM to a serial marker, and that the running kernel is the
packaged one.

PASSED when the marker appears with that kernel. FAILED otherwise.

## os-boot

Kinds: os. Brought by: M5.

It proves that the root filesystem boots as a system: the test harness lays it onto a scratch disk,
QEMU boots it to multi-user, the installed and the running kernel match, and the first boot creates
the machine's identity.

PASSED when it does. FAILED when it does not.
