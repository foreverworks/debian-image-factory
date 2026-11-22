# Debian Image Factory: design

Status: the first milestone (M1, the contract) is implemented: the definition, the lock rules on
top of input-lock, identities, `lock check`, `lock snapshot`, `lock baseline`, `plan` and the pinned
builder image. Everything from M2 on is design only. Written 2026-11-21 and revised the same day
while M1 was built; every version this document names was read that day at the source listed in
[Versions](#versions-read-for-this-design).

## 1. The problem

Teams that run Debian in more than one shape (containers, Incus instances, bare-metal installers,
installed hosts) usually build each shape on its own: a Dockerfile that starts from a public image
and runs `apt-get upgrade`, an Incus image pulled from a public image server and upgraded in place,
an installer built with a different bootstrap tool against the live mirror, an OS image built by a
fourth script. Each one sees the Debian archive at a different moment. The result:

- Nobody can say which package versions are inside which image, or whether a security fix is in
  all of them, without logging into each one.
- Rebuilding "just in case" on a schedule spends hours and still drifts, because every rebuild
  reads a different archive state.
- External downloads (a language runtime, a vendor `.deb`, an SDK) are fetched as "latest" at
  build time, so two builds of the same recipe can differ for reasons nobody wrote down.
- There is no record, attached to the exact bits, of what produced them, what is inside, and which
  tests they passed.

## 2. Goals

1. **One archive state per generation.** Every image of a generation resolves its Debian packages
   from one snapshot ID on snapshot.debian.org, covering main, updates and security.
2. **One core, many shapes.** A minimal core filesystem is built once from that snapshot; the OCI,
   Incus, installer and OS artifacts are derived from it, each adding only what it needs.
3. **Every external input is locked.** A lock file names every download by version and checksum.
   No build resolves a version or downloads anything the lock does not name.
4. **Rebuild only when the inputs change.** Each image has an input identity computed before
   building; an image is built only when its identity differs from what is already published.
5. **Records on every artifact.** Each artifact carries an SPDX 2.3 SBOM, SLSA v1 provenance and
   one in-toto test result per check, all bound to its content digest, in standard formats any
   tool can read.
6. **Generic.** Anyone can run it with their own lock and build definition. Nothing about a
   particular organisation, registry, host or network lives in the factory.
7. **Runs without root.** Rootless Docker (or a Debian host with user namespaces) is enough to
   build everything; VM checks need KVM, nothing more.

## 3. Non-goals

- **Byte-for-byte reproducibility as a promise.** The goal is replaying the same declared inputs.
  The factory keeps the build snapshot out of the bytes, clamps timestamps, and a check measures
  whether two builds match, but no artifact is claimed to be bit-identical unless that check passes
  for it.
- **Promotion and deployment.** The factory produces candidates and their records. Deciding which
  candidate runs (a pin, a tag move, a rollout) is the consumer's job.
- **Patching running systems.** Persistent hosts keep their own update policy. The factory builds
  images; it does not run on, or report on, machines that use them.
- **Installing onto disks.** The installer kit and the OS root filesystem are artifacts. Partitioning,
  filesystems, bootloader installation on real hardware and machine identity stay in the consumer's
  install flow.
- **Shapes without a consumer.** Incus VM images, ready-to-boot disk images, ISO images and
  architectures other than amd64 are designed for (the architecture is part of every identity,
  kinds are pluggable) but not built until someone consumes them.
- **Application images.** An application's own Dockerfile builds `FROM` the factory's OCI base by
  digest, in the application's repository. Upstream applications that publish an official image
  are consumed as that image, pinned by digest, never rebuilt here.
- **Other distributions.** Debian only. Derivatives may work; nothing is promised.

## 4. Vocabulary

| Term | Meaning |
|---|---|
| snapshot ID | A snapshot.debian.org timestamp, `YYYYMMDDTHHMMSSZ`. snapshot.debian.org serves an ID as each archive's newest snapshot at or before that time; apt 3.0's `Snapshot:` option builds the URLs for it. |
| build snapshot | The snapshot ID a generation's package sets are resolved from. It moves as often as the consumer likes (nightly, typically) and never enters an image's bytes or identity. |
| baseline snapshot | A second snapshot ID, moved deliberately (at Debian point releases, typically), used only for apt sources written into images that ask for snapshot sources. |
| generation | The images resolved at one build snapshot. An unchanged image carries over into the next generation as the same artifact. |
| lock | `lock.json`: the snapshot IDs and every external input with its version and checksum. Machine-maintained. Its format and library are [input-lock](https://github.com/foreverworks/input-lock). |
| build definition | `factory.toml`: which images exist, their kind, parent, packages, modules, hooks and outputs. Human-written. |
| image | A node of the build tree, named in the definition (`core`, `oci-base`, `node-26`, ...). |
| kind | What an image is built as: `core`, `oci`, `incus`, `installer`, `os`. A kind decides the build steps and the artifact format. |
| module | Shared recipe that installs lock entries into an image (`node`, a vendor `.deb`, your own script). |
| input identity | sha256 over what an image is built from (section 7). Equal identity, no rebuild. |
| engine revision | An integer in the factory's source, raised only when a change can alter the bytes the factory writes. |
| artifact | The published bits of one build of one image, addressed by content digest. |
| record | An in-toto statement about one artifact digest: provenance, SBOM or test result. |
| candidate | An artifact whose required checks have not all finished. |
| good build | An artifact with a passing test result for every check its image requires. Derived from its records at the time it is asked, never stored. |

## 5. Architecture

### 5.1 The tree

```text
lock.json: build snapshot (main + updates + security), baseline snapshot, every external input
  |
  plan: resolve every image's package set, compute identities, look them up where they are published
  |
  fetch: download and verify every file the plan names (content-addressed cache)
  |
  core: minimal userland, no kernel, no machine identity
  |
  +-- oci       core as a single-layer OCI image
  |     +-- oci children (one added layer each), e.g. a Node runtime from the node module
  |
  +-- incus     core + cloud-init + NoCloud templates, a split Incus container image
  |     +-- incus children (package, module and hook additions)
  |
  +-- installer core + kernel + firmware + disk and network tools, packed as a RAM boot kit
  |
  +-- os        core + kernel + bootloader packages + host tools, as a root filesystem tarball
        +-- os children
  |
  test: built-in checks per kind, plus the consumer's own; one test result per check
  |
  publish: OCI registry (records as referrers) and file targets (records as .intoto.jsonl)
```

"One core" means shared filesystem ancestry and shared declared inputs, not one archive format.
Every child starts from its parent's exact filesystem and adds to it; nothing is bootstrapped twice.
The OCI artifacts carry no init system, cloud-init, templates or kernel: each branch adds only its
own requirements.

### 5.2 Stages: what each takes and emits

| Stage | Takes | Emits |
|---|---|---|
| `plan` | lock, definition, params, the published state (looked up live by identity) | `plan.json`: per image its resolved package set, identity, state (`reuse`, `wait` or `build`) and the reasons |
| `fetch` | `plan.json` | every `.deb`, index and external file the plan names, verified, in the cache; optionally an inputs bundle per image |
| `core` | snapshot indices, the core package list, hooks, files | rootfs tarball, SBOM, provenance |
| `oci` | parent rootfs (core or an OCI parent), packages, modules, OCI config | OCI image layout (one layer for the base, one added layer per child), SBOM, provenance |
| `incus` | parent rootfs, packages, modules, the factory's NoCloud templates | `metadata` tarball plus `rootfs.squashfs`, their Incus fingerprint, SBOM, provenance |
| `installer` | parent rootfs, kernel and tool packages, hooks | boot kit: kernel, initrd holding the whole system, `kit.json`; SBOM, provenance |
| `os` | parent rootfs, kernel, bootloader and host packages, apt sources policy, hooks | OS root filesystem tarball, SBOM, provenance |
| `test` | an artifact and the checks its image requires | one in-toto test result per check, on the artifact digest |
| `publish` | built artifacts and their records, targets | pushed images and files, identity tags or names, records attached |
| `prune` | the published state, the consumer's pins, a retention rule | the list of artifacts to delete (and, without `--dry-run`, the deletions) |

### 5.3 How a stage builds

- **Core** is `mmdebstrap --variant=apt` with the definition's packages, files and hooks, reading
  the snapshot through the local partial mirror the fetch stage built (7.7). It then removes every
  machine identity: `/etc/machine-id` emptied, `/var/lib/dbus/machine-id`, SSH host keys, systemd's
  random seed, apt lists and caches and logs removed, and the `/etc/hostname` and `/etc/resolv.conf`
  mmdebstrap copies from the build container, with the apt options only the build needed. The
  sources it read the mirror with are replaced by the image's own (`apt_sources`). The root is packed
  by mmdebstrap as a tar and compressed with `gzip -n`, so the same inputs give the same bytes; the
  M2 integration test builds the example core twice and compares. Kernel packages are refused in core.
- **Children** unpack their parent's exact rootfs, enter it in a user-namespace chroot (the same
  mechanism mmdebstrap's unshare mode uses), install their packages with apt from the same local
  mirror, run their modules and hooks, and clean up identity again. A child never upgrades a package
  its parent installed: the plan refuses such a resolution, because it means the parent must be
  rebuilt first.
- **Hooks and modules run with no network.** Everything they may use was fetched and verified
  before the build started and is handed to them as files plus `LOCK_*` environment variables
  (6.5). A hook that tries to download fails.
- **Nothing is booted to build.** An image that needs a running system to produce its content is a
  consumer stage that starts from a factory artifact.
- **Kind defaults are explicit.** Each kind installs a documented package set (for `incus`:
  systemd-sysv, udev, dbus, iproute2, netbase, systemd-resolved, cloud-init and what NoCloud needs)
  and, for kinds that boot, writes `uninitialized` into `/etc/machine-id` so systemd treats the
  first boot as a first boot, plus a first-boot unit that creates SSH host keys when
  `openssh-server` is present. The plan lists the defaults, so nothing arrives silently.
- **Timestamps come from the definition, not the clock.** `SOURCE_DATE_EPOCH` is
  `[debian] source_date_epoch`, by default the suite's release date (2025-08-09 for Debian 13).
  mmdebstrap and the factory's own writers clamp every timestamp to it. When an artifact was really
  built is in its provenance, never in its bytes.

### 5.4 The builder

Builds run in a builder environment whose tools come from Debian itself, at a snapshot the factory
release fixes: mmdebstrap, apt, dpkg, tar, gzip, cpio, squashfs-tools and python3, as Debian 13
ships them, plus the tools that only move or check bytes (gnupg, gpgv, oras, util-linux). Its
recipe is `builder/Dockerfile`; its snapshot is the `debian_snapshot` of the repository's own
`lock.json`, which also pins input-lock.
A later release publishes that builder image through `publish.push_layout`, pinned by digest, from
the layout `docker save` writes; `push_layout` takes any single-image OCI layout and assumes none of
the factory's annotations.

- **In CI and by default locally**, the builder is a container image the factory release pins by
  digest. From the first milestone it is built by the factory's own release pipeline from a fixed
  snapshot and published with its own records; the very first one is bootstrapped from Debian's
  official `debian:trixie` image pinned by digest. It runs with `--privileged`, which under rootless
  Docker grants nothing beyond the invoking user's own namespace, and mmdebstrap runs in root mode
  inside it. Under rootful Docker (GitHub-hosted runners among them) `--privileged` is real host
  root: a definition's hooks then run as root on the host with no network, so build only
  definitions you trust there.
- **On a Debian host** (`--builder host`), mmdebstrap runs in unshare mode. That mode needs
  `newuidmap`, so it does not work where `NoNewPrivileges` is set; use the container there.
- **Only tools that write bytes enter identities.** The package set of mmdebstrap, apt, dpkg, tar,
  gzip, cpio, squashfs-tools and python3 (whose `tarfile` and `zlib` write OCI layers) is part of
  every recipe digest: exactly the binary packages `tools.py` names (python3.13, its minimal and
  stdlib packages, zlib1g and liblzma5 included), at the versions in the packaged `tools.json`,
  which an integration test compares with the built image. Tools that only fetch, verify, sign or push (gnupg, oras, curl, cosign) are
  not: a new oras never rebuilds an image.
- **Planning needs apt and gpgv, not the builder.** `plan` runs apt-get and gpgv as an ordinary
  user, so it works on any Debian or Ubuntu machine as well as inside the builder; the plan's bytes
  are the same on each (an integration test plans on the host and in the builder and compares).
  apt in Debian 13 verifies with sqv, which is why the builder installs gpgv explicitly.

## 6. The input contract

A consumer writes two files and nothing else: the lock and the build definition. Parameters
(feature flags) come from the command line or a file the consumer already owns.

### 6.1 The lock: `lock.json`, through input-lock

The lock's format, its checks, URL rendering, checksum refresh and the identity projection of its
entries are not implemented here. They belong to
[input-lock](https://github.com/foreverworks/input-lock), a small standard-library-only, typed
Python library for exactly this kind of file. The factory depends on input-lock at a pinned version
and bundles it into its `.pyz` at build time, so a user still installs one file. What the factory
adds on top (`lockrules.py`) is everything that needs the build definition, applied after
input-lock's own `problems()`:

- `used_by` is optional in input-lock and required here: every entry names the images that install
  it, and only images the definition has (input-lock checks the names when given the image list).
  The two reserved entries below name none.
- `module`, when not null, names a module the definition declares.
- `debian_snapshot` is present, and the snapshot IDs are usable (7.5).
- An entry's `signed_by` keyring is `used_by` every image the entry is, so each image's plan carries it
  (the keyring is a trust root `fetch` reads for that image).
- input-lock 0.2.0 owns the rest of the trust fields' rules (`signed_by` names an entry of the lock, a
  keyring pinned by sha256 or sha512 and itself unsigned; `sums_url` needs `signed_by`; both are https).
  The lock is `"schema": 2` as soon as an entry uses one, and the factory reads schema 2.
- The baseline snapshot is the reserved entry `debian-baseline`, required when any image's
  `apt_sources` points at it. input-lock reads exactly three top-level fields (`schema`,
  `debian_snapshot`, `inputs`), so a second snapshot cannot be a top-level field. As an entry it is
  also a pin in its own right: `version` is the snapshot ID, `url` the debian archive's `InRelease`
  for the suite at that ID, and `sha256` that file's checksum, written by `lock baseline` after the
  signature is verified and checked again by `lock check`.

The factory pins input-lock 0.2.0 by version and sha256 in its own repository's `lock.json` (the
same format, so Renovate moves it), unpacks it for development with `scripts/vendor-input-lock`,
and bundles it into the `.pyz`.

```json
{
  "schema": 2,
  "debian_snapshot": "20261121T004329Z",
  "inputs": {
    "debian-baseline": {
      "description": "The baseline snapshot: apt sources written into images that ask for them point here.",
      "sha256": "<sha256 of that InRelease>",
      "url": "https://snapshot.debian.org/archive/debian/{version}/dists/trixie/InRelease",
      "version": "20261108T000000Z"
    },
    "debian-image-factory": {
      "datasource": "github-releases",
      "depName": "foreverworks/debian-image-factory",
      "extractVersion": "^v(?<version>.+)$",
      "module": null,
      "sha256": "<sha256 of the .pyz>",
      "url": "https://github.com/foreverworks/debian-image-factory/releases/download/v{version}/debian-image-factory-{version}.pyz",
      "version": "0.1.0"
    },
    "example-tool": {
      "apt": "example-tool",
      "datasource": "deb",
      "depName": "example-tool",
      "module": "vendor-deb",
      "registryUrl": "https://packages.example.com/debian?suite=trixie&components=main&binaryArch=amd64",
      "sha256": "<sha256 of the .deb>",
      "url": "https://packages.example.com/debian/pool/main/e/example-tool/example-tool_{version_noepoch}_amd64.deb",
      "used_by": ["os"],
      "version": "2.4.0-1"
    },
    "node-26": {
      "datasource": "node-version",
      "depName": "node",
      "module": "node",
      "sha256": "5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864",
      "signed_by": "node-release-keys",
      "sums_url": "https://nodejs.org/dist/v{version}/SHASUMS256.txt.asc",
      "url": "https://nodejs.org/dist/v{version}/node-v{version}-linux-x64.tar.xz",
      "used_by": ["node-26"],
      "version": "26.13.1"
    },
    "node-release-keys": {
      "description": "A trust root: moved by hand, as a reviewed diff.",
      "module": "node",
      "sha256": "140f2ad5260fd62773b6243ce8e1d3009645d558f121b8262c55e383dc285932",
      "url": "https://raw.githubusercontent.com/nodejs/release-keys/{version}/gpg-only-active-keys/pubring.kbx",
      "used_by": ["node-26"],
      "version": "481637f813e912c4aa3622d7964ab426c97b8e8d"
    }
  }
}
```

The Node checksum is the real one for 26.13.1 (from nodejs.org's `SHASUMS256.txt`), and the
keyring entry pins a real commit of nodejs/release-keys; the values in angle brackets are
placeholders. `examples/lock.json` is this lock with real values where they exist. The keyring is
pinned by commit in `version` and has no Renovate datasource: input-lock requires the url of an
entry Renovate moves to be built from `{version}`, so a git-refs entry that keeps a ref in
`version` and the commit in `digest` is refused, and a trust root is better moved by hand anyway.

What each field means to the factory:

| Field | Meaning |
|---|---|
| `schema` | The lock format version, owned by input-lock: 1, or 2 once an entry uses a trust field (below); `input-lock format` and the `lock` commands write the one that is needed. |
| `debian_snapshot` | The build snapshot (vocabulary). Resolution input only. |
| `inputs.debian-baseline` | Reserved: the baseline snapshot (`version`) and its `InRelease` (`url`, `sha256`). Enters only the images whose `apt_sources` point at it. No `used_by`. |
| `inputs.<name>` | Lowercase letters, digits and dashes. One entry per downloaded file. |
| `version`, `digest` | The pin. Renovate or `lock` commands move them, never a build. |
| `url` | `https://` only. A template over `{version}`, `{version_noepoch}` (Debian epoch dropped), `{version_underscore}` (`+` as `_`), `{version_urlquoted}`, `{major}` and any other string field of the entry (`{digest}`, `{build}`). |
| `sha256`, `sha512`, `sha1` | At least one. `lock checksums` (input-lock's `refresh`) writes the checksums of the entries a bump moved, or of the entries named, and adds a sha256 to an entry that only has sha1 (some SDK repositories publish nothing stronger), so every file is also checked by sha256. |
| `apt` | For a vendor `.deb`: its package name; its sha256 must match the vendor's own `Packages` index for that version. input-lock reads that index over HTTPS and does not check its signature (the vendor's `InRelease`); see section 16. |
| `signed_by`, `sums_url`, `sums_sig_url` | How the checksum is vouched for (input-lock 0.2.0). `signed_by` names the keyring entry (a trust root pinned by sha256 or sha512); `sums_url` is the vendor's checksum list, clear-signed or, with `sums_sig_url`, signed apart (Node.js's `SHASUMS256.txt.asc`). `fetch` verifies the list with `gpgv`, fails closed, and requires the list's checksum for the file to equal the lock's. They are trust fields: out of `build_fields`, `build.env` and every identity, since a signature is checked and does not change the bytes. The plan carries them (`trust`) for `fetch`. |
| `module` | The module that installs it (declared in the definition), or `null` when the image's own hooks use it. |
| `used_by` | A sorted, non-empty list of images from the definition, required on every entry but the reserved ones. The only place that says which image installs which input. |
| `datasource`, `depName`, `packageName`, `extractVersion`, `versioning`, `registryUrl` | Renovate's lookup hints. They never enter an identity. |
| `description` | For people. Never enters an identity or `build.env`. |
| `debian-image-factory` | Reserved: the factory release itself, used by the Action to fetch the right `.pyz`. No `used_by`. Its version enters no identity; the engine revision does (7.1). |

Two rules keep the lock honest:

- **One home per version.** If something else in the consumer's world installs the same file (a
  host role, a developer setup script), it reads the version from this lock. Nothing pins it twice.
- **Trust roots are inputs.** A signing keyring that an entry's `signed_by` names (the Node.js release
  keys above) is itself a lock entry with a checksum, so a key change is a reviewed diff. The
  factory verifies the signature at `fetch`, and a signature that fails, a list that does not name the
  file or one that gives another checksum fails the fetch, naming the list's URL.

### 6.2 The build definition: `factory.toml`

TOML, written by people. Versions never appear here; package names do.

```toml
schema = 1

[debian]
suite = "trixie"                  # Debian 13
components = ["main"]
architectures = ["amd64"]
source_date_epoch = 1754697600    # 2025-08-09, Debian 13's release; the default for trixie

[params]
vendor_tools = true               # a feature flag; images that read it carry its value in their identity

[modules.node]
use = "builtin:node-tarball"      # nodejs.org tarball, checked against the signed SHASUMS256.txt
prefix = "/usr/local"

[modules.vendor-deb]
use = "builtin:deb"               # a vendor .deb from the lock, dependencies from the snapshot
enabled_by = "vendor_tools"       # off: its entries are installed nowhere and leave every identity

[images.core]
kind = "core"
packages = ["ca-certificates", "tzdata", "locales"]
files = "files/core"              # copied over the root filesystem, mode and owner from the tree

[images.oci-base]
kind = "oci"
parent = "core"
oci = { user = "0:0", cmd = ["/bin/bash"], env = { LANG = "C.UTF-8" } }

[images.node-26]
kind = "oci"
parent = "oci-base"
oci = { cmd = ["node"] }

[images.incus-base]
kind = "incus"
parent = "core"
packages = ["openssh-server", "sudo", "curl"]

[images.installer]
kind = "installer"
parent = "core"
packages = ["linux-image-amd64", "kexec-tools", "gdisk", "dosfstools", "openssh-server"]
hooks = ["hooks/installer-trim.sh"]   # runs in the chroot, no network

[images.os]
kind = "os"
parent = "core"
packages = ["linux-image-amd64", "grub-efi-amd64", "openssh-server", "sudo"]
apt_sources = "baseline-except-security"   # main and updates at the baseline snapshot, security live

[checks]
# Which checks make a build "good". "builtin" is the kind's own set (section 11).
default = ["builtin"]
os = ["builtin", "install-on-test-vm"]    # a check the consumer runs and attests itself
```

Keys per image: `kind`, `parent` (required except for core), `packages`, `files`, `hooks`,
`apt_sources`, `compression`, and the kind's own table (`oci`, `incus`, `installer`, `os`). The plan
rejects a definition whose tree has a cycle, a child whose kind cannot derive from its parent's (an
`oci` child of an `incus` image, for example), or a lock entry whose `used_by` names an image the
definition lacks.

`apt_sources` decides what the image's own apt configuration points at:

| Value | Sources written into the image | Snapshot in its identity |
|---|---|---|
| `live` (the default for every kind) | `deb.debian.org` and `security.debian.org` for the suite, no `Snapshot:` | none |
| `baseline` | every suite at the baseline snapshot | the baseline |
| `baseline-except-security` | main and updates at the baseline, security live | the baseline |

The build snapshot is never written into an image: it is how the factory chose the packages, not
something the image needs afterwards.

### 6.3 Parameters

A parameter is a named value the consumer already decides somewhere else (a feature flag in its
configuration, say). It reaches the factory as `--param vendor_tools=true` or `--params
params.json`, never copied into the definition. A module's `enabled_by`, or a hook that reads
`FACTORY_PARAM_<NAME>`, declares that an image reads it; only the parameters an image reads enter
its identity, so switching a flag rebuilds exactly the images it touches. Both values of a flag are
buildable and testable from the same definition.

### 6.4 Modules

| Module | Installs | Verification |
|---|---|---|
| `builtin:deb` | a vendor `.deb` from the lock, with `apt-get install ./file.deb`; its dependencies come from the snapshot. The vendor's repository is never added to the image's apt sources. | lock sha256, which `lock checksums` cross-checked against the vendor's index (read over HTTPS; its signature is not checked yet, section 16) |
| `builtin:node-tarball` | a nodejs.org release tarball into a prefix, plus `node`, `npm`, `npx` links | lock sha256, and the tarball's checksum in `SHASUMS256.txt.asc`, verified by `fetch` with gpgv against the pinned release keyring (the entry's `signed_by`) |
| `builtin:file` | any locked download, placed at a path the definition names, optionally unpacked | lock checksums |
| a path (`hooks/sdk.sh`) | whatever the script does, in the chroot, with no network | the factory has already verified every file the script receives |

A module is shared source invoked on whichever images use its entries; it is never an image with
two parents.

**`builtin:node-tarball`** takes one key besides `use` and `enabled_by`: `prefix`, an absolute
normalised path of plain parts (letters, digits and `. _ + -`), `/usr/local` by default; any other
key is refused by the definition, naming it. Among the module's lock entries an image uses there is
exactly one release tarball, told by its rendered url ending in `.tar.xz` or `.tar.gz`, and it must
carry `signed_by` and `sums_url` (`plan` and `lock check` name an image that lacks one). The keyring
is the entry `signed_by` names and is not installed: it is a trust root used at fetch time.

- *Verification.* At `fetch`, for every entry that has `signed_by` and `sums_url` (Node's is the first
  case), the factory reads the keyring from the cache (checked against the lock's checksum there),
  downloads `SHASUMS256.txt.asc` (and `sums_sig_url` when the list is signed apart) through its own
  reader, verifies the signature with `gpgv` (input-lock's `gpgv`: only `VALIDSIG` counts, an expired
  or revoked key or a second signed message in the file fails), and requires the list's line for the
  tarball's file name to carry the lock's sha256. The list is kept in the content cache by its sha256
  and a note keyed by the tarball's sha256 records it, so provenance can name the signed list as a
  resolved dependency and a later fetch verifies the cached copy again instead of trusting it.
- *Install.* The builder's `python3` unpacks the tarball (`tarfile`, with `lzma`: the builder has no
  `xz-utils` and the image has no python), by a self-contained script the build copies into its work
  directory and runs as `python3 node_install.py "$root" <tarball> <prefix> <source_date_epoch>`. It
  strips the top directory and skips the top-level `CHANGELOG.md` and `README.md` (`LICENSE`, the
  licence of what ships, stays); refuses absolute names, `..`, devices and fifos, and a symlink or
  hard link whose target is not inside the prefix; never follows a symlink already in the image;
  writes everything owned by root:root, with the tarball's permission bits minus setuid, setgid and
  sticky, and every modification time the older of the member's and `source_date_epoch`; a directory
  that exists keeps its mode, and every directory the unpack touches has its time put back, so the
  same inputs give the same bytes. When the prefix is not `/usr/local`, `/usr/local/bin/node`, `npm`
  and `npx` are symlinks to `<prefix>/bin/<name>`; for `/usr/local` the tarball's own `bin/` is there
  already.
- *Probe.* `locked-inputs` runs `<prefix>/bin/node --version` in the image and expects `v<version>`;
  the keyring has no probe (11).

In M1, `plan` refuses an image that installs a switched-on `builtin:deb` entry, naming it: resolving
a vendor `.deb`'s dependencies needs the vendor's index stanza, which arrives with the `deb` module
in M5. With the switch off (as in `examples/`), the entries leave every identity and the plan runs.

### 6.5 What a hook sees

Inside the chroot a hook gets `/run/factory/inputs/<entry>/` holding each verified file it may use,
and a `build.env` with, per entry, `LOCK_<NAME>_VERSION`, `LOCK_<NAME>_URL` (rendered),
`LOCK_<NAME>_SHA256` (and the entry's other checksum and string fields), plus `LOCK_ENTRIES` and
`FACTORY_PARAM_<NAME>`. `<NAME>` is the entry name in upper case with every other character as `_`
(`node-26` is `LOCK_NODE_26_VERSION`). The rendering is input-lock's, so a script written against a
plain input-lock setup reads the same names inside the factory.

### 6.6 Adopting an existing lock

If you already keep versions and checksums in a JSON file (many repositories do, often bumped by
Renovate), you can usually adopt it without changing your update flow:

1. Run `debian-image-factory lock check` on it. Every problem is named with the entry and the
   field, so the first run is a to-do list rather than a wall of errors.
2. Add `schema`, and the two snapshot fields if your builds did not use snapshot.debian.org yet.
3. Make every entry name a URL template and at least one checksum. For sha1-only entries,
   `lock checksums` adds the sha256.
4. Point `used_by` at the image names of your `factory.toml`, and declare every `module` you use.
5. Keep your Renovate configuration. Its lookup hints are ignored by identities, so tuning Renovate
   never rebuilds an image.
6. If your build scripts already read `LOCK_*` variables, they keep working as hooks (6.5); a script
   that downloads must be changed to read its file from `/run/factory/inputs/`, since hooks have no
   network.

## 7. Input identity: rebuilding only what changed

### 7.1 Definition

```text
identity(image) = sha256(canonical_json({
  "identity": 2,
  "packages": sorted set of (name, version, architecture) installed in the image,
  "lock":     { entry: the entry minus the excluded fields } for the lock entries this image itself installs,
  "recipe":   recipe digest,
  "parent":   identity(parent), or null for core
}))

recipe digest = sha256(canonical_json({
  "engine":     the engine revision,
  "tools":      sorted (name, version, architecture) of the builder's byte-writing tools,
  "kind":       the kind and its own table from the definition, parsed,
  "image":      the image's definition section, parsed,
  "modules":    { name: its [modules.*] table, parsed } for every module the image uses,
  "files":      { path: {sha256, mode} } of every hook, module script and file in the trees it references,
  "params":     { name: value } of the parameters it reads,
  "debian":     suite, components, architecture, source_date_epoch,
  "baseline":   the baseline snapshot, only when apt_sources points at it, else null
}))
```

- **A deny-list, not an allow-list.** A lock entry enters the identity with every field except
  Renovate's lookup hints (`datasource`, `depName`, `packageName`, `extractVersion`, `versioning`,
  `registryUrl`) and bookkeeping (`used_by`, `description`), with `url` rendered: input-lock's
  `build_fields`, and the identity itself is input-lock's `input_identity`. Any other field, known today or added later, enters:
  an unknown field fails toward a rebuild, never toward a stale image. The projection is tagged
  `"identity": 2` so a future change to it is visible in every identity.
- **The engine revision, not the release version.** A factory release that only touches the
  command line, publishing or documentation rebuilds nothing. A change that can alter the bytes the
  factory writes raises the engine revision, and the tests enforce it (section 12).
- **The build snapshot is not an input.** It decides which versions the resolver picks, and those
  versions are in `packages`. It never reaches the bytes (5.3, 6.2), so it has no reason to be in
  the identity.
- **File modes are what git keeps.** A file enters as its sha256 and `0755` or `0644` (executable
  or not), a directory as `0755`, a symbolic link as its target, so a checkout's umask never moves
  an identity. A file that needs another mode or an owner gets it from a hook.
- **The parameters an image reads** are the `enabled_by` switches of every module its entries name
  (on or off) and every `FACTORY_PARAM_<NAME>` its hooks and module scripts mention.
- **Canonical JSON** is sorted keys, no whitespace, UTF-8. The definition enters parsed, not as
  bytes, so reformatting `factory.toml` or reordering its keys never rebuilds anything; the
  referenced files enter by content. Lists that are sets (`packages`, `components`) enter sorted, so
  reordering them rebuilds nothing either; `hooks` keep their order, which is the order they run in.

### 7.2 Resolving before building

The plan computes each package set without building anything and without privileges:

1. Download the build snapshot's `InRelease` and `Packages` indices for every suite (by hash, since
   Debian's archives set `Acquire-By-Hash: yes`), verify them with `debian-archive-keyring`
   (`--keyring`), and lay them out as a partial mirror that apt reads through `file:` sources,
   verifying the signature and hashes again.
2. For each image, prepare a synthetic apt root: a scratch directory with sources at the snapshot,
   the verified indices, and a dpkg status file. For core the status is empty; for a child it is the
   parent's resolved set, written from the same `Packages` stanzas.
3. Run `apt-get --simulate install` in that root with the image's request, Recommends off. Core is
   resolved the way mmdebstrap's `apt` variant installs it, in two transactions: first every
   `Essential: yes` package of the suite itself (not of -updates or -security; mmdebstrap selects
   them with `?narrow` on the suite and sets `pkgCacheGen::ForceEssential ","`), then `apt` and the
   definition's packages on top of that result (the plan's `request` for core lists `apt` and the
   packages). A child's request is its packages, its kind defaults and its modules' dependencies
   (none in M1: `node-tarball` and `file` need no packages, and `deb` arrives with M5), against a
   status holding its parent's set; an `Inst`
   line that upgrades a parent's package, or any `Remv`, is refused. apt's own solver answers, one
   `Inst` line per package, and this runs as an ordinary user.
4. Compute identities top-down and look each one up where it would be published (7.4).

`mmdebstrap --simulate` is not used for planning: it prints its solution only with `--verbose`, and
reports two transactions (the essential set, then the rest) that would have to be merged. The
resolver runs the same two transactions itself instead.

**The M1 spike.** `tests/integration/test_spike_plan.py` plans `examples/` at the example lock's
snapshot, builds core for real with mmdebstrap 1.5.7 in the builder at the same snapshot
(`scripts/spike-core`), and compares the built root's dpkg status with the plan's set. At
`20261121T004329Z`, with `ca-certificates`, `tzdata` and `locales`, both are the same 74 packages,
versions and architectures. The kind defaults of `incus`, `installer` and `os` are resolved the
same way but are not yet compared with a real build: that comparison is the `package-set` check,
which arrives with each kind's build.

### 7.3 Plan output

A night when Debian published a new kernel and Renovate moved Node, abridged:

```json
{
  "schema": 1,
  "snapshot": "20261121T004329Z",
  "engine": 1,
  "images": {
    "core":       {"identity": "<core identity>", "state": "reuse", "artifact": "sha256:<core tarball>"},
    "oci-base":   {"identity": "<oci-base identity>", "state": "reuse", "artifact": "sha256:<oci-base manifest>"},
    "node-26": {
      "identity": "<new node-26 identity>",
      "state": "build",
      "because": [{"input": "node-26", "from": "26.12.0", "to": "26.13.1"}]
    },
    "incus-base": {"identity": "<incus-base identity>", "state": "wait", "artifact": "<incus-base fingerprint>",
                   "waiting_for": ["incus-boot"]},
    "installer": {
      "identity": "<new installer identity>",
      "state": "build",
      "because": [{"package": "linux-image-6.12.120+deb13-amd64", "from": null, "to": "6.12.120-1"},
                  {"package": "linux-image-6.12.119+deb13-amd64", "from": "6.12.119-1", "to": null}]
    },
    "os": {"identity": "<new os identity>", "state": "build",
           "because": [{"package": "linux-image-6.12.120+deb13-amd64", "from": null, "to": "6.12.120-1"}]}
  }
}
```

A child's identity contains its parent's, so a rebuilt parent always rebuilds every image below it:
had core changed, every image would read `build`. Package versions here are illustrative.

Each image's entry also carries what its identity was computed from, so `fetch` and `build` read
the plan alone: `kind`, `parent`, `parent_identity`, `recipe` (the recipe digest), `request` (what
apt was asked for), `packages` (the resolved set), `inputs` (the lock entries it installs, as
`build_fields`), `modules`, `trust` (for each input with `signed_by`: the keyring entry and the
rendered `sums_url` and `sums_sig_url`, which `fetch` verifies and which enter no identity), `params` (the ones it reads), `apt_sources` and `checks` (the required
ones). `because` says why an image builds: no artifact with this identity, a failed required check,
the parent builds, or `--rebuild`; with `--previous <plan.json>` it also lists what moved since
that plan (packages, inputs, parameters, recipe). Files that look like an artifact but do not count
are listed under `rejected`, with the reason.

### 7.4 Published state: reuse, wait, build

The plan never keeps a list of what was built. It asks the targets, by identity:

- **OCI targets:** every published image carries a tag `identity-<identity in full hex>` (73
  characters, within the registry limit), besides any tag the consumer moves. One manifest request
  answers whether that identity exists (404: nothing). The manifest must be an OCI image manifest
  whose identity annotation is the identity; its records are then gathered from the registry
  (the referrers API, or the tag schema when the registry answers 404 there), each envelope read
  from its blob and checked against its digest, and joined as the lines of a records file that the
  provenance rules below apply to. The artifact is named `oci://<registry>/<repository>@sha256:<manifest
  digest>`. A referrer that cannot be read, or an image that does not count, is listed under
  `rejected` with the reason. The tag names the latest image pushed for the identity: a build that
  replaces a failed one moves it, and the older manifest stays reachable by digest. The records are
  read in the order they were attached (each referrer's `org.opencontainers.image.created`, 8.2),
  which decides a check's last result, whatever order the registry lists them in.
- **File targets** (`github-release://`, `dir://`): artifact files are named
  `<image>-<suite>-<arch>-<first 16 hex of the identity>-<first 12 hex of the digest>.<ext>`. A
  listing filtered by the image and identity prefix answers; the provenance in the
  `<digest>.intoto.jsonl` beside it must name the full identity before the artifact counts.

Each image then gets one of three states:

| State | When | What happens |
|---|---|---|
| `reuse` | an artifact with this identity exists and is good | nothing is built; the plan names the artifact |
| `wait` | an artifact with this identity exists and is still a candidate (a required check has no result yet) | nothing is built for it, and its children wait too |
| `build` | no artifact with this identity exists, or the only ones that exist have a failed required check | it is built, and so is every image below it |

A child whose parent waits waits too, unless the child itself is reusable. Several results for one
check count in file order, the last one wins; when several artifacts qualify, the newest
`finishedOn` wins, ties by the smallest digest. The provenance names the image in
`externalParameters.image` and the identity in `internalParameters.identity` (8.2), and a records
file counts only when a statement's subject is the file's real sha256. `dir://` and `oci://`
lookups are live; `github-release://` arrives with its publisher.

### 7.5 Choosing the build snapshot ID

snapshot.debian.org keeps separate timelines per archive (`debian`, `debian-security`) and lists
them at `https://snapshot.debian.org/mr/timestamp/?archive=<name>`. An ID is **completed** when
every archive in use lists a snapshot strictly later than it: the snapshot that ID serves in each
archive can then no longer change, assuming the service lists a snapshot only after its import ends
and imports each archive in order.

**The M1 spike** (`scripts/spike-listing`, run 2026-11-21) confirmed what can be seen from outside:
both listings are strictly ascending; for the newest completed ID each suite's `InRelease` is
served, its `Date` is not later than the snapshot it serves, and two reads give the same bytes; an
unlisted ID between two listed ones serves the earlier one; and the newest listed snapshot of each
archive, not yet completed, was already fully served (`InRelease` and the by-hash `Packages.xz` it
lists, by size and sha256). It cannot show that a snapshot is never listed mid-import, which would
take catching one; the "completed IDs only" rule is what protects against it, and the redirect for
an ID is cacheable for a day, one more reason never to use an ID that is not completed. The
security archive's newest snapshot often lags the main one by hours, so it usually decides the
newest completed ID.

- `lock snapshot --latest` picks the newest timestamp listed in any archive in use that is earlier
  than every archive's newest snapshot, which is the newest completed ID.
- `lock check` re-resolves the lock's IDs every time it runs: it fails an ID that is not completed,
  and reports, per archive, which snapshot the ID serves.
- `plan --snapshot latest` uses the newest completed ID without editing the lock, for a nightly run
  whose consumer writes the new ID into the lock only once its builds pass.
- `lock baseline --id <ID>` moves the baseline. It is a deliberate step, typically at a Debian point
  release, and rebuilds only the images whose apt sources point at the baseline.

### 7.6 What does and does not rebuild

| Change | Rebuilds |
|---|---|
| A new build snapshot with no new version of any installed package | nothing |
| A security upload of a package core installs | core and every image below it |
| A new version of a package only the installer installs | the installer only |
| The baseline snapshot moved | the images with `baseline` or `baseline-except-security` sources, and their children |
| A lock entry's version, digest, checksum or URL | the images in its `used_by` and their children |
| A field added to a lock entry, even one the factory does not know | the images in its `used_by` and their children |
| A Renovate hint | nothing |
| Another image added to an entry's `used_by` | nothing for the images already listed; the added image, which now installs the entry, and its children |
| A module's table (`use`, `prefix` or any other key) | the images that use the module and their children |
| A hook file's content | that image and its children |
| `factory.toml` reformatted, comments edited, keys reordered | nothing |
| A parameter flipped | the images that read it and their children |
| A factory release without an engine change, a new oras or cosign | nothing |
| An engine revision raised, or a new version of a byte-writing builder tool | everything, once |
| A core rebuilt with the same inputs gets a new digest | nothing: a digest is not an input |

`plan --rebuild <image> --reason "<text>"` forces a build and records the reason in provenance, for
the rare case inputs cannot see (an archive key rotation, say).

### 7.7 Fetching, the cache and replay without snapshot.debian.org

- **Fetch, then build offline.** `fetch` downloads every index, `.deb` and external file the plan
  names into a content-addressed cache (`~/.cache/debian-image-factory/sha256/...`), checking each
  against its signed index or lock checksum. It then lays out a partial Debian mirror (signed
  `InRelease`, the indices, the pool files needed) at `<cache>/mirror/<snapshot>/<archive>/`,
  pool files hard-linked from the cache. The builder mounts it read-only at `/mirror`, a path with
  no snapshot ID in it, and apt reads it with its `copy:` method (mmdebstrap refuses a `file:` mirror
  outside the chroot). apt verifies the archive signature, index hashes and file hashes as it
  always does.
- **A cache is never an authority.** `--mirror https://cache.example.com/snapshot/` sends reads
  through any HTTP cache that serves snapshot.debian.org paths; what it returns is accepted only by
  checksum. This also keeps a nightly build within snapshot.debian.org's rate limits.
- **Valid-Until.** Security archive `Release` files expire. Reads of a snapshot set
  `Acquire::Check-Valid-Until=false`; signatures and hashes are still verified, and the snapshot ID
  pins the content.
- **Inputs bundle.** With `--bundle`, fetch also writes the partial mirror and external files per
  image as `<artifact digest>.inputs.tar`. `build --offline --bundle <file>` rebuilds that image
  from it with snapshot.debian.org unreachable. A replay is the normal build path reading a
  different directory, not a separate mode.

## 8. Artifacts and records

### 8.1 Artifacts

| Kind | Files | Digest that names it | Default compression |
|---|---|---|---|
| core | `core-trixie-amd64-<identity16>-<digest12>.tar.gz` | sha256 of the file | gzip |
| oci | OCI image layout, pushed to a registry | image manifest digest | layers `application/vnd.oci.image.layer.v1.tar+gzip` |
| incus | `<name>.incus.tar.gz` (metadata.yaml, templates) and `<name>.rootfs.squashfs` | Incus fingerprint: sha256 of the metadata file followed by the rootfs file | gzip tarball, squashfs with its gzip compressor |
| installer | `installer-trixie-amd64-<identity16>-<digest12>.tar`, a kit holding `vmlinuz`, `initrd.img`, `kit.json` | sha256 of the kit tarball; kernel and initrd are listed as subjects too | initrd gzip, kit tarball uncompressed |
| os | `os-trixie-amd64-<identity16>-<digest12>.tar.gz` | sha256 of the file | gzip |

Compression is gzip, or the format the target ecosystem reads by default, for everything published.
zstd is supported per image (`compression = "zstd"`) for consumers who control every reader. The
OS image's own initramfs keeps whatever its Debian packages configure, since the installed system
regenerates it.

An OCI image carries standard annotations: `org.opencontainers.image.base.digest` and
`org.opencontainers.image.base.name` (its parent), `org.opencontainers.image.source` and
`org.opencontainers.image.revision` (the definition's repository and commit), and
`io.github.foreverworks.debian-image-factory.identity` (its input identity). The image config
carries no build time.

An Incus image's `metadata.yaml`:

```yaml
architecture: x86_64
creation_date: 1754697600        # source_date_epoch, never the build time
properties:
  os: debian
  release: trixie
  variant: incus-base
  serial: "<first 16 hex of the identity>"
  description: "Debian 13 (trixie) incus-base"
templates:
  /var/lib/cloud/seed/nocloud-net/meta-data:
    when: [create, copy]
    template: cloud-init-meta.tpl
  /var/lib/cloud/seed/nocloud-net/user-data:
    when: [create, copy]
    template: cloud-init-user.tpl
  # vendor-data, network-config, /etc/hostname and /etc/hosts the same way
```

The templates are the factory's own, written from Incus's template documentation and versioned
with it. Without them cloud-init disables itself in an Incus container and no network or user data
arrives. The user-data template reads `cloud-init.user-data` and falls back to the older
`user.user-data` key, which some tooling still sets.

### 8.2 Records

Every record is an in-toto Statement v1 whose subjects are the artifact's files and digests, wrapped
in a DSSE envelope (`payloadType: application/vnd.in-toto+json`).

| Record | Predicate type | One per |
|---|---|---|
| provenance | `https://slsa.dev/provenance/v1` (SLSA 1.2) | artifact |
| SBOM | `https://spdx.dev/Document/v2.3`, SPDX 2.3 JSON | artifact |
| test result | `https://in-toto.io/attestation/test-result/v0.1` | check |

Where they live:

- **OCI images:** each envelope is pushed as an OCI 1.1 artifact whose `subject` is the image
  manifest. Registries with the referrers API list them there. Registries without it (GHCR answers
  404 on the referrers endpoint) get the distribution spec's referrers tag schema: a tag
  `sha256-<subject digest>` holding an index of the referrers. Updating that index is a
  read-modify-write, so the factory serializes attaches per subject: one attach at a time per image,
  re-reading the index before each write.

  How the tag schema is used, exactly. A record is attached in this order: the envelope blob (the
  line's bytes without its newline), the empty config blob, then the artifact manifest above, pushed
  by digest. If that PUT answers `OCI-Subject`, the registry has indexed the referrer and nothing more
  is done. Otherwise the factory reads the tag `sha256-<subject digest in hex>` (404: no index yet),
  appends the referrer's descriptor to its `manifests` unless a descriptor with the same digest is
  there, and PUTs the result as an image index (`application/vnd.oci.image.index.v1+json`) under that
  tag. The index is canonical JSON (sorted keys, no whitespace) and lists referrers in attach order,
  each as `mediaType`, `digest`, `size`, `artifactType` (`application/vnd.in-toto+json`) and the
  `in-toto.io/predicate-type` annotation of its record. The tag is read again right before each
  write and records are attached one at a time, so a publisher never overwrites what it has just
  read; two publishers attaching to one image at the same moment can still lose an entry, and
  publishing again restores it. Readers ask the referrers API first and read the tag only on a 404.
  A record counts as already attached when a referrer of the subject carries an envelope with the
  same digest, so publishing again adds only the records that are new.
- **Files:** one `<digest>.intoto.jsonl` beside the artifact, one envelope per line, where
  `<digest>` is the sha256 (or Incus fingerprint) in full hex.

Provenance for a core build:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "core-trixie-amd64-<identity16>-<digest12>.tar.gz", "digest": {"sha256": "<core tarball sha256>"}}],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://github.com/foreverworks/debian-image-factory/blob/v0.1.0/docs/build-type-v1.md",
      "externalParameters": {
        "image": "core",
        "definition": {"uri": "git+https://github.com/example/images", "revision": "<definition commit>", "path": "factory.toml"},
        "params": {}
      },
      "internalParameters": {
        "identity": "<core identity>",
        "engine": 1,
        "buildSnapshot": "20261121T004329Z",
        "architecture": "amd64",
        "reason": "package libssl3t64 3.5.1-1+deb13u1 -> 3.5.1-1+deb13u2"
      },
      "resolvedDependencies": [
        {"uri": "git+https://github.com/example/images@<definition commit>", "digest": {"gitCommit": "<definition commit>"}},
        {"name": "lock.json", "digest": {"sha256": "<lock sha256>"}},
        {"name": "recipe of core", "digest": {"sha256": "<core recipe digest>"}},
        {"uri": "https://snapshot.debian.org/archive/debian/20261121T004329Z/dists/trixie/InRelease", "digest": {"sha256": "<debian InRelease sha256>"}},
        {"uri": "https://snapshot.debian.org/archive/debian-security/20261121T004329Z/dists/trixie-security/InRelease", "digest": {"sha256": "<security InRelease sha256>"}},
        {"uri": "oci://ghcr.io/foreverworks/debian-image-factory-builder", "digest": {"sha256": "<builder digest>"}}
      ]
    },
    "runDetails": {
      "builder": {"id": "https://github.com/example/images/.github/workflows/images.yml@refs/heads/main",
                  "version": {"debian-image-factory": "0.1.0"}},
      "metadata": {"invocationId": "https://github.com/example/images/actions/runs/<run id>/attempts/1",
                   "startedOn": "2026-11-21T02:17:05Z", "finishedOn": "2026-11-21T02:19:41Z"}
    }
  }
}
```

The build snapshot is recorded here, in the record, because it explains the choice of versions; it
is not in the artifact. A child adds `{"name": "parent: core", "digest": {"sha256": "<core tarball
sha256>"}}` and its locked downloads (`{"uri": "<rendered url>", "digest": {"sha256": "..."}}`), so
ancestry and every input are provable from the record alone.

SBOM, abridged:

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "node-26-trixie-amd64",
  "documentNamespace": "https://github.com/example/images/sbom/node-26/sha256-<node-26 manifest digest>",
  "creationInfo": {"created": "2026-11-21T02:31:12Z", "creators": ["Tool: debian-image-factory-0.1.0"]},
  "packages": [
    {"SPDXID": "SPDXRef-Image", "name": "node-26", "versionInfo": "sha256:<node-26 manifest digest>",
     "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
     "primaryPackagePurpose": "CONTAINER"},
    {"SPDXID": "SPDXRef-Package-libstdc--6-amd64", "name": "libstdc++6", "versionInfo": "14.2.0-19",
     "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                       "referenceLocator": "pkg:deb/debian/libstdc%2B%2B6@14.2.0-19?arch=amd64&distro=trixie"}]},
    {"SPDXID": "SPDXRef-Input-node-26", "name": "node-26", "versionInfo": "26.13.1",
     "downloadLocation": "https://nodejs.org/dist/v26.13.1/node-v26.13.1-linux-x64.tar.xz", "filesAnalyzed": false,
     "checksums": [{"algorithm": "SHA256", "checksumValue": "5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864"}],
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                       "referenceLocator": "pkg:generic/node-26@26.13.1"}]}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Image"},
    {"spdxElementId": "SPDXRef-Image", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Package-libstdc--6-amd64"},
    {"spdxElementId": "SPDXRef-Image", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Input-node-26"}
  ]
}
```

- **The namespace is unique per document**: it ends in the artifact's digest, and an artifact has
  exactly one SBOM.
- **SPDXIDs are sanitised**: every character outside letters, digits, `.` and `-` becomes `-`
  (`libstdc++6` is `SPDXRef-Package-libstdc--6-amd64`); when two names would collide, both get the
  first 8 hex of the sha256 of their original name appended.
- The package list comes from the image's own dpkg status after the build, not from the plan, and a
  check compares the two. The library version above is illustrative.
- **Locked inputs are named by their lock entry** (`node-26`, not `node`), as input-lock's
  `input_packages` writes them: the entry name is the one name that is unique in the lock.

Test result, one per check:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "core-trixie-amd64-<identity16>-<digest12>.tar.gz", "digest": {"sha256": "<core tarball sha256>"}}],
  "predicateType": "https://in-toto.io/attestation/test-result/v0.1",
  "predicate": {
    "result": "PASSED",
    "configuration": [{"name": "no-machine-identity",
                       "uri": "https://github.com/foreverworks/debian-image-factory/blob/v0.1.0/docs/checks.md#no-machine-identity"}],
    "url": "https://github.com/example/images/actions/runs/<run id>",
    "passedTests": ["machine-id-empty-or-uninitialized", "no-ssh-host-keys", "no-private-keys", "no-random-seed"],
    "warnedTests": [],
    "failedTests": []
  }
}
```

The first `configuration` entry's `name` is the check's ID; "good build" is computed from it. A
consumer's own check attests the same way: `debian-image-factory attest test-result --artifact
<digest> --check install-on-test-vm --result PASSED --passed install,reboot --url <run url>`.

A line of `<digest>.intoto.jsonl`:

```json
{"payload":"<base64 of the statement>","payloadType":"application/vnd.in-toto+json","signatures":[]}
```

And the OCI artifact that carries one record as a referrer:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.in-toto+json",
  "config": {"mediaType": "application/vnd.oci.empty.v1+json",
             "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2},
  "layers": [{"mediaType": "application/vnd.dsse.envelope.v1+json", "digest": "sha256:<envelope digest>", "size": 4127,
              "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"}}],
  "subject": {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:<oci-base manifest digest>", "size": 1043},
  "annotations": {"org.opencontainers.image.created": "2026-11-21T02:33:08.120004Z"}
}
```

(The config digest is the real one of the two-byte empty JSON object `{}`, as the OCI spec defines
it.) `org.opencontainers.image.created` is when the record was attached, one microsecond apart
within one publish. Records of an OCI image are read in that order, whatever order the referrers API
lists them in, so "the last result wins" (7.4) means the same on every registry; a referrer without
the annotation reads first. Records never hold secrets, private keys, tokens or machine identities. They describe bits;
what is actually running somewhere is for the consumer to read back from the running system.

### 8.3 Signing

Envelopes are unsigned by default (`"signatures": []`); the registry's or release host's
authentication is then the trust boundary. `--sign keyless` signs each envelope with Sigstore
through the CI's OIDC identity (cosign 3.1.4); `--sign key:<path or KMS URI>` uses a key the
consumer holds. The factory never holds a key, and nothing in a record changes shape when signing is
switched on.

Either way this is **SLSA Build L1** provenance, signed or not: the factory writes it as part of the
build itself. Build L2 requires provenance that the build platform generates and signs on its own.
A consumer whose CI platform offers that can attach the platform's statement beside the factory's;
that statement carries whatever level the platform claims. Build L3 needs a hardened, isolated build
platform, which the factory is not.

### 8.4 Build type

`buildType` names a versioned document in this repository describing the build: which
`externalParameters` exist (the image, the definition's repository, revision and path, the
parameters), what `internalParameters` mean (identity, engine, build snapshot, architecture,
reason) and which `resolvedDependencies` every build lists. A verifier pins the build types it
accepts.

## 9. Running it

### 9.1 The command line

One file, `debian-image-factory-<version>.pyz` (a Python zipapp with input-lock bundled and no other
dependency outside the standard library), published as a release asset with its own provenance.

```text
debian-image-factory lock check [--offline]              the lock and the definition agree; snapshot IDs re-resolved
debian-image-factory lock snapshot --latest | --id ID    move the build snapshot
debian-image-factory lock baseline --id ID               move the baseline snapshot (the debian-baseline entry)
debian-image-factory lock checksums [--entry NAME]       fill checksums of entries whose version moved; verify vendor indices and signatures
debian-image-factory plan [--against TARGET]... [--snapshot lock|latest|ID] [--param K=V]... [--params FILE]
                          [--rebuild IMAGE --reason TEXT] [--previous PLAN] [--out FILE] > plan.json
debian-image-factory fetch plan.json [--mirror URL] [--bundle]
debian-image-factory build plan.json --out out/ [--image NAME]... [--builder-image REF] [--offline] [--builder container|host]
debian-image-factory test out/ [--check NAME]...
debian-image-factory attest test-result --artifact DIGEST --check NAME --result PASSED|WARNED|FAILED ...
debian-image-factory publish out/ --to TARGET... [--sign none|keyless|key:REF]
debian-image-factory verify REF [--require-checks] [--lock FILE] [--definition FILE]
                                                         records match the bits, provenance names the lock, checks complete
debian-image-factory prune --against TARGET... --pin DIGEST... [--keep-good 5] [--keep-candidates 1] [--dry-run]
```

`lock`, `plan` and `fetch` read snapshots from snapshot.debian.org, or through `--mirror URL`, any
server that serves its paths (`/archive/...` and `/mr/timestamp/`); `--keyring` and `--cache` say
where the archive keyring and the download cache are. M1 shipped `lock check`, `lock snapshot`,
`lock baseline` and `plan`; M2 adds `fetch`, `build` for core, `test` with the core checks and
`publish` to `dir://` targets. Each later command arrives with its milestone, `fetch --bundle`
with M6, and `lock checksums` with M5 (it is input-lock's `refresh` run against the definition).

`build` reads the plan, and also the lock and the definition (`--lock`, `--definition`, as `plan`
does): hooks and file trees live beside the definition, and provenance names the lock. Before it
builds an image it recomputes the identity from them with the plan's package set and refuses a
plan they no longer match, so records always describe what was built. `--builder-image REF` names
the builder; the default is the tag `scripts/builder build` gives, until a release pins the
published builder by digest. Images of kinds a release cannot build yet are listed as not built. `--offline` (a replay from an inputs bundle) arrives with M6 and `--builder host` later;
every build already runs with no network.

Targets are `oci://<registry>/<repository>`, `github-release://<owner>/<repo>@<tag>` and
`dir://<path>`. `plan --against` looks identities up live in those targets (7.4); nothing about
the published state is stored in the consumer's repository.

`publish` writes `dir://` targets (files only: an OCI image layout is refused there) and `oci://`
targets (OCI images only: a core tarball is refused there; when `out/` holds both, each target
takes its kind and the command names what it left). An OCI image is pushed with its tag
`identity-<identity>`, its records are attached as referrers (8.2), and publishing again pushes and
attaches only what the registry lacks. Credentials come from the Docker config (`$DOCKER_CONFIG`
or `~/.docker`: `auths`, `credHelpers`, `credsStore`); registries on `localhost`, `127.0.0.1` and
`[::1]` are spoken to over http, all others over https.

`verify REF` takes `oci://<registry>/<repository>@sha256:<hex>`, `oci://<registry>/<repository>:<tag>`,
a local `.oci` layout directory, or an artifact file with its `<digest>.intoto.jsonl` beside it,
and names every problem it finds (exit 1) or prints a short summary (exit 0). It checks that:

- the bits match their digest: an image's manifest digest (a registry's blobs are checked as they
  are read, a layout on disk in full, layers included; from a registry the layers are checked when
  pulled), a file's sha256;
- every record is a DSSE envelope of an in-toto Statement v1 that names the artifact's digest as a
  subject;
- there is exactly one provenance, whose build type is a release of this factory's, naming the
  image and an identity equal to the artifact's (an image's identity annotation; a file's name
  carries its first 16 hex);
- its resolved dependencies name `lock.json` by sha256, and that is the sha256 of `--lock` when given;
- there is exactly one SBOM, whose document namespace ends in `sha256-<digest>` and whose
  `SPDXRef-Image` has the version `sha256:<digest>`;
- with `--require-checks`, every check the definition (`--definition`, default `factory.toml`)
  requires for the image has a passing last result, by the rules of 7.4 (`has_lock_entries` comes
  from the provenance's locked inputs); without it the checks present are listed.

Exit codes: 0 done, 1 a check or validation failed (with every problem named), 2 usage. `plan`
exits 0 whether or not anything needs building; `plan.json` and the Action's `changed` output say.

### 9.2 The GitHub Action

A composite action at the repository root, `foreverworks/debian-image-factory@<commit>`. It reads
the factory version from the consumer's lock (`debian-image-factory` entry), downloads that `.pyz`,
checks its sha256 against the lock, and runs the requested steps in the release's pinned builder
container. The Action's own ref changes only when its bootstrap logic does; the factory version has
one home, the lock.

```yaml
name: images
on:
  schedule: [{cron: "17 2 * * *"}]
  push: {branches: [main], paths: ["images/**"]}
jobs:
  images:
    runs-on: ubuntu-latest
    permissions: {contents: write, packages: write, id-token: write}
    steps:
      - uses: actions/checkout@<commit> # v7.0.1
      - id: factory
        uses: foreverworks/debian-image-factory@<commit> # v0.6.0
        with:
          definition: images/factory.toml
          lock: images/lock.json
          snapshot: latest
          against: |
            oci://ghcr.io/example/debian
            github-release://example/images@images
          publish: true
    outputs:
      changed: ${{ steps.factory.outputs.changed }}
      plan: ${{ steps.factory.outputs.plan }}
```

Inputs: `definition`, `lock`, `params`, `snapshot`, `against`, `steps` (default
`plan,fetch,build,test`), `publish`, `sign`, `mirror`. Outputs: `changed`, `plan` (path),
`artifacts` (JSON: image to digest). VM checks run where `/dev/kvm` exists; elsewhere they are
reported as not run, never as passed, and the build stays a candidate until they run.

### 9.3 Pinning the factory in your own pipeline

1. **Pin.** Add the `debian-image-factory` entry to your lock; Renovate's github-releases datasource
   opens the bump and `lock checksums` fills the sha256. Pin the Action by commit, with its version
   as a comment, and let Renovate bump that too.
2. **Define** your images in `factory.toml`; pass the flags you decide elsewhere with `--params`.
3. **Plan on a schedule** with `--snapshot latest` against where you publish. A night with no
   relevant upload builds nothing and costs a few index downloads.
4. **Build, test and publish candidates** on whatever runners you use.
5. **Run your own checks** (a boot in your environment, a full install of the OS image onto a test
   VM, your workloads) and attach each result with `attest`.
6. **Approve your way.** Move your pins or tags once every required check is good, and write the new
   build snapshot into the lock in the same change, so the lock never runs ahead of a verified
   build. Move the baseline at point releases, through the gate your persistent systems use.
7. **Prune** with your pins: by default the newest 5 good builds and 1 candidate per image stay,
   and a pinned artifact is never pruned.

## 10. What stays with the consumer, what lives in the factory

| The consumer keeps | The factory provides |
|---|---|
| Its lock: every version and checksum, both snapshot IDs | The lock contract through input-lock, `lock` commands, Renovate guidance |
| Its definition: package lists, children, hooks, module scripts, files | The engine, the five kinds, the built-in modules, the NoCloud templates |
| Parameters (feature flags) and where they are decided | Parameter plumbing into identities and hooks |
| Registries, release names, repository names | Publish adapters for OCI registries, GitHub releases, directories |
| Credentials, tokens, signing keys, OIDC trust | Signing hooks that use them without storing them |
| Hostnames, users, machine and network identities (all supplied at run time, never baked in) | Checks that prove an image carries none |
| Pins, promotion, approval, rollout, rollback | `verify`, the "good build" rule, `prune --pin` |
| Its own acceptance checks | `attest test-result` and the built-in checks |
| Installing onto disks, the machine stage, real hardware | The installer kit and the OS root filesystem |
| Its cache or mirror server | `--mirror` and checksum-only acceptance |
| Its CI runners and schedule | The CLI, the Action, an example workflow |

## 11. Built-in checks

Each runs on the exact artifact and emits one test result.

| Check | Kinds | Proves |
|---|---|---|
| `package-set` | all | the image's dpkg status equals the plan's resolved set |
| `locked-inputs` | all with lock entries | every entry the image uses is installed at its locked version (dpkg for `apt` entries, the module's own version probe otherwise); a keyring a `signed_by` names is a trust root, listed as passed and not installed |
| `no-machine-identity` | all | `/etc/machine-id` absent, empty or `uninitialized`; no `/var/lib/dbus/machine-id`, no SSH host keys, no private key block and no credential token of a documented shape (GitHub, AWS, Slack, npm, PyPI, GitLab) in any plain file, `/usr/share/doc`, `man` and `info` included (only compressed documentation is skipped; executables are searched for keys only), no random seed, no cloud-init instance state, no `/etc/hostname` content, no `/etc/resolv.conf` file (a symlink, as systemd-resolved makes, is fine). For OCI the files are those of the layers merged with whiteouts applied, except that a private key or token in a layer counts even when a later layer deletes it, because it still ships |
| `two-clones` | all | two instances of the artifact share no identity: machine IDs and SSH host keys, where present, differ. Core and OCI run as two rootless containers, Incus as two instances, the installer and OS as two VMs |
| `sbom-complete` | all | the SBOM lists every installed package and locked input |
| `ancestry` | children | the parent's filesystem is the base: for OCI, the parent's layers are the first layers by digest; elsewhere, the parent's files are present unless the child's own records say it removed them |
| `same-resolution` | core | a second resolution of the same lock gives the same package set |
| `no-build-snapshot` | all | the build snapshot ID appears nowhere in the artifact's bytes, including the build-time `file://` source, which the `apt_sources` rendering replaces before the image is packed; skipped with a note when the baseline ID equals the build ID. A release test also builds one package set at two different build snapshots and compares the bytes |
| `byte-equal` | all, optional | two builds from the same inputs give the same digest; WARNED, never FAILED, when they differ |
| `oci-run` | oci | runs under rootless Docker: declared user and entrypoint, `cmd` exits 0 |
| `incus-boot` | incus | in an Incus host inside a VM: cloud-init finishes through NoCloud from both `cloud-init.user-data` and `user.user-data`, creates the user, runs commands, an IPv4 address is reported, all still true after a restart |
| `installer-boot` | installer | QEMU boots the kit from RAM to a serial marker; the running kernel is the packaged one |
| `os-boot` | os | the test harness lays the root filesystem onto a scratch disk, QEMU boots it to multi-user, installed and running kernel match, first boot creates its identity |

Failed, cancelled or incomplete checks leave the artifact a candidate; the consumer's pins do not
move, and `prune` deletes it once its checks end.

## 12. Test plan

The rule: per-push CI never gets slower. Fast checks run on every push; the full Python matrix runs
weekly; the matrix and the slow integration tests gate a release. Every tier can be run locally with
one command, so nobody waits on CI to learn what a change broke.

**Supported Python.** Upstream sets the window: the factory supports the Python versions upstream
still supports, from 3.13 (Debian 13's python3, the floor) to the newest stable (3.15.2 today).

**Every push and pull request: one job, one runtime, no matrix.** It runs on the newest stable
Python and checks the floor statically in the same job:

- `ruff check` and `ruff format --check` (ruff 0.17.6) with `target-version = "py313"`.
- `mypy --strict --python-version 3.13` (mypy 2.4.1) with `disallow_any_explicit = true`,
  `warn_unused_ignores = true` and `enable_error_code = ["ignore-without-code"]`, over the package
  and the tests. A repository check fails any `# type: ignore[...]` whose line does not also carry a
  reason.
- `shellcheck` on the example hooks and the Action's shell steps.
- The unit tests and the fixture-archive tests below (`python3 -m unittest`), seconds in total.
- `pre-commit` 4.7.0 runs the same static checks locally before each commit.

**Weekly, scheduled, allowed to fail:** the full matrix (3.13, 3.14, 3.15) plus the next Python
pre-release (3.16.0a2 today), so a coming break is seen weeks before it matters.

**On a release tag, gating the publish:** the full matrix, and the slow integration tests below
(real image builds and VM boots). A tag whose integration tests fail publishes nothing.

**Unit, seconds, no network, no root**

- Definition: tree validation, kind compatibility, `used_by` against images, parameters.
- The lock contract as the factory uses it: definition cross-checks, the snapshot rules of 7.5
  against recorded listings. The lock format's own tests live in input-lock.
- Identity: order and formatting never change it; every field that should change it does; the
  deny-list ignores exactly the Renovate hints and `used_by`; an unknown entry field changes it; the
  baseline enters only images whose sources point at it; the build snapshot never does.
- Plan: every row of the table in 7.6; the reuse, wait and build states; refusal of a child that
  would upgrade its parent.
- Records: SPDX documents validated against SPDX's published 2.3 JSON schema, vendored as a test
  fixture. SLSA provenance and in-toto statements have no official JSON schema, so the tests check
  their required fields: `_type`, `subject` with `name` and `digest`, `predicateType`;
  `buildDefinition.buildType`, `externalParameters`, `runDetails.builder.id`; the test result's
  `result` and `configuration`. DSSE encoding, `.intoto.jsonl` naming, SPDXID sanitising and
  collisions, namespace uniqueness.
- OCI layout: manifest, config and layer digests; annotations; identity tags; referrer manifests
  and the serialized tag-schema index update.
- Incus fingerprint and `metadata.yaml`.
- Retention: a run of failed nights never pushes out a good build; pins are never pruned; at most
  `keep_good + keep_candidates` per image plus pins.

**Fixture archive, seconds**

A tiny Debian-format archive generated by the tests (a handful of packages made with `dpkg-deb`,
indexed and signed with a throwaway key) at two timestamps, laid out the way snapshot.debian.org
serves it, with a recorded `/mr/timestamp/` listing. It exercises resolution, identities and the
plan without the network: a new version of one package at the second timestamp changes exactly the
identities of the images that install it, and nothing else.

**Integration, minutes (release tag, and locally while developing)**

- Rootless Docker: core, OCI, Incus rootfs, installer and OS builds from the fixture archive and from
  the real snapshot; `package-set`, `locked-inputs`, `no-machine-identity`, `two-clones` for core and
  OCI, `sbom-complete`, `ancestry`, `same-resolution`, `no-build-snapshot`, `byte-equal`, `oci-run`;
  offline replay from an inputs bundle with `--network none`; publishing to a throwaway local
  registry container, then `verify` and `plan --against` it.
- **Two registries, one with the referrers API and one without** (`tests/integration/test_registries.py`,
  rootless Docker on 127.0.0.1): zot v2.1.23 (`ghcr.io/project-zot/zot`), which answers the referrers
  endpoint with 200 and answers `OCI-Subject` on a referrer's manifest, and the CNCF distribution
  registry 3.1.2 (`docker.io/library/registry`), which has no referrers handler and answers 404 there,
  as GHCR does in production. The test asks each for the referrers of an unknown digest before it
  relies on that. A synthetic one-layer image with records shaped like the factory's is published to
  each, published again (no second copy of a blob, manifest or record), found by `plan`'s lookup,
  pulled back byte for byte and verified; a changed layer then fails `verify`. The registry client's
  unit tests run against an in-process server (authentication challenges, uploads, `OCI-Subject`,
  the tag schema).
- **The engine revision guard.** For every kind whose fixture build is byte-equal, the expected
  digest is recorded beside the engine revision. A change that alters those bytes without raising
  the revision fails here. A kind not yet byte-equal relies on review: any change to its build code
  raises the revision.
- QEMU with KVM: `installer-boot`, `os-boot`, `two-clones` for the installer and OS, and
  `incus-boot` in a Debian 13 VM with Incus from the same snapshot (6.0.4 in Debian 13).

**Where it runs.** While the repository is private, its jobs run on the project's own self-hosted
runners, picked by capability label (`debian-image-factory`, and `debian-image-factory-kvm` for jobs
that boot a VM); they start bare, so each job installs what it needs. Once it is public, the same
jobs run on GitHub's hosted runners, free for public repositories. Either way a pull request from a
fork skips every job, so it never reaches anyone's own machines. Consumers run their own checks in
their own CI.

## 13. Code: language and style

**Python, standard library only at run time.** The factory runs inside a Debian builder, and Debian
ships python3, so no runtime has to be downloaded outside the snapshot, and apt and dpkg tooling is
at home there. The one library it uses, input-lock, is standard-library-only Python too and is
bundled into the `.pyz`. TypeScript was considered and rejected: it would put Node.js into the
builder only to run the factory.

- Python 3.13 and newer, per the window in section 12.
- Pure functions and explicit state; effects (subprocesses, network, files) at the edges, in a thin
  layer the pure core never imports. No classes with behaviour.
- Fully typed: every function, argument and return annotated, `mypy --strict` with no explicit
  `Any`, no unexplained `type: ignore`. Data is `TypedDict` (JSON shapes: records, the plan) or
  `@dataclass(frozen=True, slots=True)` (internal values). JSON enters through parse functions that
  take `object` and return a `TypedDict` only after checking every field, so nothing downstream sees
  an unchecked value.
- `argparse` for the command line, `tomllib` for the definition, `json` for everything machines
  write, `unittest` for tests. Development tools (mypy, ruff, pre-commit) are pinned with hashes in
  a development requirements file and never become run-time dependencies.
- Layout: `src/debian_image_factory/` with one module per concern (`definition`, `identity`,
  `resolve`, `plan`, `fetch`, `records`, `retention`, `publish`, `cli`), growing into a package
  (`build/`, `checks/`) when a module needs helpers of its own.

## 14. Milestones

Each milestone ends in a tagged release that anyone can pin.

| | Milestone | Starts when | Done when |
|---|---|---|---|
| M1 | **The contract**: repository skeleton (typed package, pre-commit, CI), input-lock pinned and bundled, definition parsing and checks, identity, `lock check` with snapshot re-resolution, `plan` with the reuse, wait and build states. A minimal pinned builder image (Debian 13 from a fixed snapshot with mmdebstrap, apt, dpkg and python3). The resolver spike: a real core build at the same snapshot, compared with the plan. | the lock format is frozen: input-lock's first release | a sample lock and definition covering every kind pass `lock check`; plan identities are stable across runs and machines; the spike's dpkg status equals the plan's set; the snapshot listing behaves as 7.5 assumes. Release v0.1.0. |
| M2 | **Core**: fetch, partial mirror, offline core build, SBOM, provenance, `.intoto.jsonl`, core checks, `dir://` target | M1 | two builds from one lock resolve the same set; no machine identity; no build snapshot in the bytes; SBOM complete. v0.2.0. |
| M3 | **OCI**: OCI kind with child layers, `oci://` publish with identity tags and referrers (tag schema included), `node-tarball` module, `oci-run`, `verify` | M2 | a Node runtime image's provenance names core's digest; its Node version equals the lock's; records attach on a registry without the referrers API. v0.3.0. |
| M4 | **Incus**: Incus kind, NoCloud templates, `incus-boot` and `two-clones` in a VM, `github-release://` publish | M2 | the boot contract passes for the base and for a child. v0.4.0. |
| M5 | **Installer and OS**: both kinds, `deb` and `file` modules, parameters, `apt_sources`, `installer-boot`, `os-boot` | M2 | both boot in QEMU; a flag off removes its module from both and changes both identities; moving the baseline rebuilds the OS and nothing else. v0.5.0. |
| M6 | **Nightly**: `plan --against` on every target, `--snapshot latest`, the Action, `prune`, inputs bundles, offline replay | M3 to M5 | a night with no relevant upload builds nothing; one with a single upload rebuilds exactly its chain; a bundle rebuilds with snapshot.debian.org unreachable. v0.6.0. |
| M7 | **1.0**: optional signing, docs for strangers, a full example repository | M6, and at least one real deployment has run every kind through its own promotion | the README's quick start works on a clean machine. v1.0.0. |

M3, M4 and M5 are independent once M2 lands and can run side by side.

## 15. Decisions

1. **Python, standard library only, strictly typed** (`mypy --strict`, floor checked with
   `--python-version 3.13`, no explicit `Any`, every ignore explained, in pre-commit and CI). The
   builder is Debian and already has python3; strict types catch shape errors in a tool whose whole
   job is moving structured records around.
2. **The lock is input-lock's, the definition is the factory's.** One library owns the lock format,
   its checks and the identity projection of its entries, for every tool that uses such a lock; the
   factory depends on it at a pinned version and bundles it. The lock is JSON (machines write it);
   the definition is TOML (people write it, with comments, read by the standard library).
3. **One home for every fact.** Versions live only in the lock, which image uses an input only in
   `used_by`, the factory's version only in the lock's reserved entry, published state only at the
   targets (looked up live by identity). Nothing is stored twice, so nothing goes stale.
4. **Two snapshots with two jobs.** The build snapshot chooses versions and moves freely; it never
   enters bytes or identities. The baseline snapshot is what images' apt sources may point at; it
   moves deliberately and enters only the images that use it. Every kind defaults to live apt
   sources, so a nightly snapshot never makes an image differ.
5. **Identity over inputs, failing toward a rebuild.** Package set, every lock field except Renovate
   hints and bookkeeping, the recipe digest and the parent's identity. An unknown field rebuilds; a
   new digest from the same inputs does not.
6. **The engine revision and the byte-writing tools, not the release version.** A release that
   cannot change bytes rebuilds nothing; one that can raises the revision, and a test guards it.
   Tools that only fetch, check or push never enter an identity.
7. **Fetch, then build offline.** Hooks run with no network and receive verified files. A build can
   only consume what the lock and the snapshot named, and a replay is the same code path.
8. **The cache is a performance layer, never an authority.** Content is accepted only by signed
   index or lock checksum.
9. **Children build in a chroot from their parent's exact filesystem.** Shared ancestry is real and
   provable, and nothing needs a running instance or root on the host.
10. **A pinned builder from the first milestone**, so identities computed in M1 already include the
    tools that will write the bytes, and do not all change when the builder arrives later.
11. **Only shapes with a consumer.** Core, OCI, Incus container, installer kit, OS root filesystem.
    Incus VMs, disk images, ISOs and arm64 are designed for and added when someone needs them.
12. **Published artifacts default to gzip, or the format their ecosystem expects; zstd is an
    option.** Anyone who pulls an artifact can read gzip, whatever their runtime, Incus or unpacker
    version. Consumers who control every reader can opt into zstd per image.
13. **Standard records, attached by digest.** in-toto Statement v1 in DSSE, SLSA provenance v1, SPDX
    2.3 JSON, in-toto test-result v0.1; OCI 1.1 referrers (with the tag schema where a registry lacks
    the API) and `.intoto.jsonl` beside files. SPDX 2.3 rather than 3.0.1 because 2.3 is what most
    SBOM tooling reads today, and the only one of these formats with an official JSON schema.
14. **Unsigned by default, signing pluggable, claims kept honest.** Signing needs a key or an OIDC
    identity, which only the consumer has; the record shape does not change when it is turned on, and
    the factory claims SLSA Build L1, signed or not.
15. **The factory never approves.** It emits candidates and records; pins, promotion and rollout are
    the consumer's. "Good build" is derived from test results whenever it is asked, never stored.
16. **Retention is a pure function** of the published builds, their results and the consumer's
    pins: the newest 5 good builds and 1 candidate per image by default, pins never pruned, failed
    builds deleted when their checks end.
17. **Names carry identity and digest.** Every artifact is found by its identity and told apart by
    its digest, so two builds never collide and a name alone says which bits it means.
18. **Distribution as a zipapp and an Action.** One `.pyz` file needs nothing beyond python3; the
    Action is a thin bootstrap that reads the version from the lock.
19. **The NoCloud templates are written here.** Copying another project's templates would bring
    their license terms into an MIT repository; the templates are small enough to write from the
    Incus documentation.
20. **Timestamps from the definition.** `source_date_epoch` defaults to the suite's release date, so
    no clock and no build snapshot reaches the bytes; real build times live in provenance.
21. **Per-push CI stays one fast job.** The floor is checked statically; the matrix and the slow
    builds run weekly and on release tags, where they gate the publish.

## 16. Questions settled, and the one still open

Each was raised as an open question with a recommendation; all but the last are now decided, and
each says what would change had it gone the other way.

1. **Builder tools come from the Debian snapshot** (decided 2026-11-21): mmdebstrap 1.5.7 and oras
   1.2.0 as Debian 13 ships them, not upstream's 1.7.0 and 1.4.0. The builder is one more image
   from one snapshot, locked, reproducible and recorded like every other, and its tools change only
   when a factory release moves its snapshot. This is a deliberate exception to taking the newest
   upstream release, for these tools only. Upstream fixes and features arrive with the next Debian
   release or a deliberate backport.
2. **No ready-made public images from this repository before 1.0** (decided): it publishes the
   tool and its builder image, and its release tests build the example definition into a throwaway
   registry. Strangers build their own images, and nobody depends on images this project would then
   have to patch forever. Ready-made images, if any, live in a repository of their own.
3. **The factory's own releases are signed** (decided): the `.pyz` and the builder image are signed
   with Sigstore keyless from v0.1, while consumer artifacts stay unsigned by default. Strangers
   can verify the tool they run, at no cost to consumers.
4. **Inputs bundles are off by default** (decided; `--bundle` turns them on). Where they are off,
   replay depends on snapshot.debian.org or the consumer's cache; where they are on, they cost
   hundreds of megabytes per retained good build.
5. **Still open: making the repository public.** It stays private until its maintainers decide.
   Before that, every file passes a scan for private data, and the examples use example.com names
   only.
6. **Open: the baseline as a top-level lock field.** M1 keeps the baseline in the reserved entry
   `debian-baseline` because input-lock refuses unknown top-level fields. Recommendation:
   keep the entry. It pins the archive state by checksum, needs no change to input-lock, and any
   other tool reading the lock sees an ordinary entry. If input-lock gains a `debian_baseline` field
   later, moving to it is a one-line lock edit and an identity-neutral change (the recipe carries
   the ID either way).
7. **Settled: vendor index signatures** (decided 2026-11-22). input-lock 0.2.0 checks a vendor's
   signature before it trusts a checksum: an entry's `signed_by` names a keyring entry, and its
   `sums_url` (and `sums_sig_url`) a clear-signed or detached-signed checksum list, verified with
   `gpgv` and failing closed; the lock is `"schema": 2` once it uses them. The factory takes that
   route for Node.js (`SHASUMS256.txt.asc`, checked at `fetch`, 6.4) and for any other entry that has
   the fields. The vendor `.deb` index follows the same route in M5: an apt entry with `signed_by`
   reads only a `Packages` index its repository's signed `InRelease` vouches for. Until M5 builds
   vendor `.deb` files nothing reads one, so no unsigned vendor index is trusted.
8. **Open: git-refs entries.** input-lock refuses an entry Renovate moves whose url is not built
   from `{version}`, so the git-refs pattern (`version` the ref, `digest` the commit, url from
   `{digest}`) does not pass. Recommendation: pin such files by commit in `version` without a
   datasource, as the keyring above does; ask input-lock to accept `{digest}` for git-refs entries
   only if a consumer needs Renovate to move one.

## Versions read for this design

All read on 2026-11-21.

| What | Version | Source |
|---|---|---|
| Debian stable | 13.8 "trixie", released 2025-08-09 as 13.0 | `deb.debian.org/debian/dists/stable/Release`; debian.org news |
| apt in Debian 13 | 3.0 (3.0.3) | sources.debian.org |
| mmdebstrap | 1.5.7 in Debian 13; upstream 1.7.0 | sources.debian.org; upstream tags |
| python3 in Debian 13 | 3.13.5 | sources.debian.org (python3-defaults) |
| Python, newest stable and next pre-release | 3.15.2; 3.16.0a2 | python.org downloads API |
| Node.js, active LTS | 26.13.1 "Lithium"; linux-x64 tarball sha256 from `SHASUMS256.txt` | `nodejs.org/dist/index.json`, `nodejs.org/dist/v26.13.1/SHASUMS256.txt` |
| Incus | 6.0.4 in Debian 13; upstream 7.6.0 | sources.debian.org; GitHub releases |
| oras | 1.2.0 in Debian 13; upstream 1.4.0 | sources.debian.org; GitHub releases |
| squashfs-tools, util-linux, qemu, gnupg, dpkg, cloud-init in Debian 13 | 4.6.1, 2.41.5, 10.0.13, 2.4.7, 1.22.22, 25.1.4 | sources.debian.org |
| cosign | 3.1.4 | GitHub releases |
| actions/checkout, actions/setup-python, sigstore/cosign-installer | 7.0.1, 7.1.0, 4.1.3 (pinned by commit) | GitHub releases |
| input-lock | 0.2.0, `.pyz` sha256 `d352b388...108b` | GitHub releases |
| Builder snapshot, base image | `20261121T004329Z`; `debian:trixie@sha256:9c6e3814...a8a6` | snapshot.debian.org listings; Docker Hub |
| mypy, ruff, pre-commit | 2.4.1, 0.17.6, 4.7.0 | PyPI |
| SLSA | spec 1.2, predicate `https://slsa.dev/provenance/v1` | slsa.dev |
| in-toto attestation | framework 1.2.0, Statement v1, test-result predicate 0.1 | GitHub releases, the predicate spec |
| SPDX | 2.3 used; 3.0.1 newest | spdx-spec releases |
| OCI image spec | 1.1.1 | GitHub releases |
| snapshot.debian.org timestamp listing | `/mr/timestamp/?archive=<name>` | read live |
