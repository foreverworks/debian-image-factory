# Debian Image Factory: design

Status: design only, nothing here is implemented yet. Written 2026-11-21. Every version this
document names was read that day at the source listed in [Versions](#versions-read-for-this-design).

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
  random seed, apt lists and caches and logs removed. Kernel packages are refused in core.
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
ships them, plus the tools that only move or check bytes (gnupg, oras, util-linux).

- **In CI and by default locally**, the builder is a container image the factory release pins by
  digest. From the first milestone it is built by the factory's own release pipeline from a fixed
  snapshot and published with its own records; the very first one is bootstrapped from Debian's
  official `debian:trixie` image pinned by digest. It runs with `--privileged`, which under rootless
  Docker grants nothing beyond the invoking user's own namespace, and mmdebstrap runs in root mode
  inside it.
- **On a Debian host** (`--builder host`), mmdebstrap runs in unshare mode. That mode needs
  `newuidmap`, so it does not work where `NoNewPrivileges` is set; use the container there.
- **Only tools that write bytes enter identities.** The package set of mmdebstrap, apt, dpkg, tar,
  gzip, cpio, squashfs-tools and python3 (whose `tarfile` and `zlib` write OCI layers) is part of
  every recipe digest. Tools that only fetch, verify, sign or push (gnupg, oras, curl, cosign) are
  not: a new oras never rebuilds an image.

## 6. The input contract

A consumer writes two files and nothing else: the lock and the build definition. Parameters
(feature flags) come from the command line or a file the consumer already owns.

### 6.1 The lock: `lock.json`, through input-lock

The lock's format, its checks, URL rendering, checksum refresh and the identity projection of its
entries are not implemented here. They belong to
[input-lock](https://github.com/foreverworks/input-lock), a small standard-library-only, typed
Python library for exactly this kind of file. The factory depends on input-lock at a pinned version
and bundles it into its `.pyz` at build time, so a user still installs one file. What the factory
adds on top is everything that needs the build definition: `used_by` must name images that exist,
`module` must name a declared module, and the snapshot IDs must be usable (7.5).

input-lock is being written at the same time as this design. The examples below show the fields
the factory relies on; names and details follow input-lock's API once it is released, and this
section is updated then.

```json
{
  "schema": 1,
  "debian_snapshot": "20261121T005332Z",
  "debian_baseline": "20261108T000000Z",
  "inputs": {
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
      "url": "https://nodejs.org/dist/v{version}/node-v{version}-linux-x64.tar.xz",
      "used_by": ["node-26"],
      "version": "26.13.1"
    },
    "node-release-keys": {
      "datasource": "git-refs",
      "depName": "https://github.com/nodejs/release-keys",
      "digest": "<commit sha>",
      "module": "node",
      "sha256": "<sha256 of pubring.kbx>",
      "url": "https://raw.githubusercontent.com/nodejs/release-keys/{digest}/gpg-only-active-keys/pubring.kbx",
      "used_by": ["node-26"],
      "version": "main"
    }
  }
}
```

The Node checksum is the real one for 26.13.1 (from nodejs.org's `SHASUMS256.txt`); the other
values in angle brackets are placeholders. A `git-refs` entry tracks a ref (`version`) and pins the
commit it pointed at (`digest`), which is what Renovate's git-refs datasource updates.

What each field means to the factory:

| Field | Meaning |
|---|---|
| `schema` | The lock format version, owned by input-lock. |
| `debian_snapshot` | The build snapshot (vocabulary). Resolution input only. |
| `debian_baseline` | The baseline snapshot. Enters only the images whose `apt_sources` point at it. |
| `inputs.<name>` | Lowercase letters, digits and dashes. One entry per downloaded file. |
| `version`, `digest` | The pin. Renovate or `lock` commands move them, never a build. |
| `url` | `https://` only. A template over `{version}`, `{version_noepoch}` (Debian epoch dropped), `{version_underscore}` (`+` as `_`), `{version_urlquoted}`, `{major}` and any other string field of the entry (`{digest}`, `{build}`). |
| `sha256`, `sha512`, `sha1` | At least one. `lock checksums` adds a sha256 to an entry that only has sha1 (some SDK repositories publish nothing stronger), so every file is also checked by sha256. |
| `apt` | For a vendor `.deb`: its package name; its sha256 must match the vendor's own `Packages` index for that version. |
| `module` | The module that installs it (declared in the definition), or `null` when the image's own hooks use it. |
| `used_by` | A sorted, non-empty list of images from the definition. The only place that says which image installs which input. |
| `datasource`, `depName`, `packageName`, `extractVersion`, `versioning`, `registryUrl` | Renovate's lookup hints. They never enter an identity. |
| `debian-image-factory` | Reserved: the factory release itself, used by the Action to fetch the right `.pyz`. No `used_by`. Its version enters no identity; the engine revision does (7.1). |

Two rules keep the lock honest:

- **One home per version.** If something else in the consumer's world installs the same file (a
  host role, a developer setup script), it reads the version from this lock. Nothing pins it twice.
- **Trust roots are inputs.** A signing keyring a module verifies against (the Node.js release keys
  above) is itself a lock entry with a checksum, so a key change is a reviewed diff.

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
| `builtin:deb` | a vendor `.deb` from the lock, with `apt-get install ./file.deb`; its dependencies come from the snapshot. The vendor's repository is never added to the image's apt sources. | lock sha256, which `lock checksums` cross-checked against the vendor's signed index |
| `builtin:node-tarball` | a nodejs.org release tarball into a prefix, plus `node`, `npm`, `npx` links | lock sha256, and `SHASUMS256.txt` verified with gpgv against the pinned release keyring |
| `builtin:file` | any locked download, placed at a path the definition names, optionally unpacked | lock checksums |
| a path (`hooks/sdk.sh`) | whatever the script does, in the chroot, with no network | the factory has already verified every file the script receives |

A module is shared source invoked on whichever images use its entries; it is never an image with
two parents.

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
  "files":      { path: sha256 } of every hook, module script and file tree it references,
  "params":     { name: value } of the parameters it reads,
  "debian":     suite, components, architecture, source_date_epoch,
  "baseline":   the baseline snapshot, only when apt_sources points at it, else null
}))
```

- **A deny-list, not an allow-list.** A lock entry enters the identity with every field except
  Renovate's lookup hints (`datasource`, `depName`, `packageName`, `extractVersion`, `versioning`,
  `registryUrl`) and bookkeeping (`used_by`). Any other field, known today or added later, enters:
  an unknown field fails toward a rebuild, never toward a stale image. The projection is tagged
  `"identity": 2` so a future change to it is visible in every identity.
- **The engine revision, not the release version.** A factory release that only touches the
  command line, publishing or documentation rebuilds nothing. A change that can alter the bytes the
  factory writes raises the engine revision, and the tests enforce it (section 12).
- **The build snapshot is not an input.** It decides which versions the resolver picks, and those
  versions are in `packages`. It never reaches the bytes (5.3, 6.2), so it has no reason to be in
  the identity.
- **Canonical JSON** is sorted keys, no whitespace, UTF-8. The definition enters parsed, not as
  bytes, so reformatting `factory.toml` or reordering its keys never rebuilds anything; the
  referenced files enter by content.

### 7.2 Resolving before building

The plan computes each package set without building anything and without privileges:

1. Download the build snapshot's `InRelease` and `Packages` indices for every suite (by hash, since
   Debian's archives set `Acquire-By-Hash: yes`), and verify them with the builder's
   `debian-archive-keyring`.
2. For each image, prepare a synthetic apt root: a scratch directory with sources at the snapshot,
   the verified indices, and a dpkg status file. For core the status is empty; for a child it is the
   parent's resolved set, written from the same `Packages` stanzas.
3. Run `apt-get --simulate install` in that root with the image's request. Core's request is what
   mmdebstrap's `apt` variant installs: every `Essential: yes` package, apt, and the definition's
   packages. A child's request is its packages, its kind defaults and its modules' dependencies.
   apt's own solver answers, one `Inst` line per package, and this runs as an ordinary user.
4. Compute identities top-down and look each one up where it would be published (7.4).

`mmdebstrap --simulate` is not used for planning: it prints its solution only with `--verbose`, and
reports two transactions (the essential set, then the rest) that would have to be merged. The first
milestone includes a spike that builds core for real at the same snapshot and compares its dpkg
status with the plan's set; any difference changes the resolver before anything depends on it.

### 7.3 Plan output

A night when Debian published a new kernel and Renovate moved Node, abridged:

```json
{
  "schema": 1,
  "snapshot": "20261121T005332Z",
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

### 7.4 Published state: reuse, wait, build

The plan never keeps a list of what was built. It asks the targets, by identity:

- **OCI targets:** every published image carries a tag `identity-<identity in full hex>` (73
  characters, within the registry limit), besides any tag the consumer moves. One manifest request
  answers whether that identity exists; the annotation and provenance on the manifest confirm it.
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

### 7.5 Choosing the build snapshot ID

snapshot.debian.org keeps separate timelines per archive (`debian`, `debian-security`) and lists
them at `https://snapshot.debian.org/mr/timestamp/?archive=<name>`. An ID is **completed** when
every archive in use lists a snapshot strictly later than it: the snapshot that ID serves in each
archive can then no longer change, assuming the service lists a snapshot only after its import ends
and imports each archive in order (the first milestone's spike checks this against the live
service).

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
  `InRelease`, the indices, the pool files needed) that the build reads through `file://`. apt
  verifies the archive signature, index hashes and file hashes as it always does.
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
        "buildSnapshot": "20261121T005332Z",
        "architecture": "amd64",
        "reason": "package libssl3t64 3.5.1-1+deb13u1 -> 3.5.1-1+deb13u2"
      },
      "resolvedDependencies": [
        {"uri": "git+https://github.com/example/images@<definition commit>", "digest": {"gitCommit": "<definition commit>"}},
        {"name": "lock.json", "digest": {"sha256": "<lock sha256>"}},
        {"name": "recipe of core", "digest": {"sha256": "<core recipe digest>"}},
        {"uri": "https://snapshot.debian.org/archive/debian/20261121T005332Z/dists/trixie/InRelease", "digest": {"sha256": "<debian InRelease sha256>"}},
        {"uri": "https://snapshot.debian.org/archive/debian-security/20261121T005332Z/dists/trixie-security/InRelease", "digest": {"sha256": "<security InRelease sha256>"}},
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
    {"SPDXID": "SPDXRef-Input-node-26", "name": "node", "versionInfo": "26.13.1",
     "downloadLocation": "https://nodejs.org/dist/v26.13.1/node-v26.13.1-linux-x64.tar.xz", "filesAnalyzed": false,
     "checksums": [{"algorithm": "SHA256", "checksumValue": "5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864"}],
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                       "referenceLocator": "pkg:generic/node@26.13.1"}]}
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
  "subject": {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:<oci-base manifest digest>", "size": 1043}
}
```

(The config digest is the real one of the two-byte empty JSON object `{}`, as the OCI spec defines
it.) Records never hold secrets, private keys, tokens or machine identities. They describe bits;
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
debian-image-factory lock check                          the lock and the definition agree; snapshot IDs re-resolved
debian-image-factory lock snapshot --latest | --id ID    move the build snapshot
debian-image-factory lock baseline --id ID               move the baseline snapshot
debian-image-factory lock checksums [--entry NAME]       fill checksums of entries whose version moved; verify vendor indices and signatures
debian-image-factory plan [--against TARGET]... [--snapshot lock|latest|ID] [--param K=V]... > plan.json
debian-image-factory fetch plan.json [--mirror URL] [--bundle]
debian-image-factory build plan.json --out out/ [--image NAME]... [--offline] [--builder container|host]
debian-image-factory test out/ [--check NAME]...
debian-image-factory attest test-result --artifact DIGEST --check NAME --result PASSED|WARNED|FAILED ...
debian-image-factory publish out/ --to TARGET... [--sign none|keyless|key:REF]
debian-image-factory verify REF [--require-checks]       records match the bits, provenance names the lock, checks complete
debian-image-factory prune --against TARGET... --pin DIGEST... [--keep-good 5] [--keep-candidates 1] [--dry-run]
```

Targets are `oci://<registry>/<repository>`, `github-release://<owner>/<repo>@<tag>` and
`dir://<path>`. `plan --against` looks identities up live in those targets (7.4); nothing about
the published state is stored in the consumer's repository.

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
| `locked-inputs` | all with lock entries | every entry the image uses is installed at its locked version (dpkg for `apt` entries, the module's own version probe otherwise) |
| `no-machine-identity` | all | `/etc/machine-id` absent, empty or `uninitialized`; no `/var/lib/dbus/machine-id`, no SSH host keys, no private keys or tokens by pattern, no random seed, no cloud-init instance state |
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
- **The engine revision guard.** For every kind whose fixture build is byte-equal, the expected
  digest is recorded beside the engine revision. A change that alters those bytes without raising
  the revision fails here. A kind not yet byte-equal relies on review: any change to its build code
  raises the revision.
- QEMU with KVM: `installer-boot`, `os-boot`, `two-clones` for the installer and OS, and
  `incus-boot` in a Debian 13 VM with Incus from the same snapshot (6.0.4 in Debian 13).

**Where it runs.** This repository will be public, so its CI runs only on GitHub's hosted runners:
free for public repositories, and a pull request from a fork never reaches anyone's own machines.
Consumers run their own checks in their own CI.

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

## 16. Open questions

Each has a recommendation, which the design above already follows, and what changes if it is
decided the other way.

1. **Builder tools from the Debian snapshot, or upstream's newest.** mmdebstrap 1.5.7 and oras
   1.2.0 as Debian 13 ships them, against upstream's 1.7.0 and 1.4.0. Recommendation: Debian's. The
   builder is then one more image from one snapshot, locked, reproducible and recorded like every
   other, and its tools change only when a factory release moves its snapshot. Consequence: upstream
   fixes and features arrive with the next Debian release or a deliberate backport; choosing upstream
   means a second, unlocked source of tools inside every identity.
2. **Does this repository publish ready-made public images** (a core OCI base, a Node runtime)?
   Recommendation: not before 1.0; the repository publishes the tool and its builder image, and its
   release tests build the example definition into a throwaway registry. Consequence: strangers
   build their own images; nobody depends on images this project would then have to patch forever.
3. **Signing the factory's own releases.** Recommendation: sign the `.pyz` and the builder image
   with Sigstore keyless from v0.1, even though consumer artifacts stay unsigned by default.
   Consequence: strangers can verify the tool they run, at no cost to consumers.
4. **Inputs bundles: on or off by default.** Recommendation: off (`--bundle` turns them on).
   Consequence: hundreds of megabytes per retained good build where they are on; dependence on
   snapshot.debian.org (or the consumer's cache) for replay where they are off.
5. **Making the repository public.** It stays private until its maintainers decide. Before that:
   every file passes a scan for private data, and the examples use example.com names only.

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
| actions/checkout | 7.0.1 | GitHub releases |
| mypy, ruff, pre-commit | 2.4.1, 0.17.6, 4.7.0 | PyPI |
| SLSA | spec 1.2, predicate `https://slsa.dev/provenance/v1` | slsa.dev |
| in-toto attestation | framework 1.2.0, Statement v1, test-result predicate 0.1 | GitHub releases, the predicate spec |
| SPDX | 2.3 used; 3.0.1 newest | spdx-spec releases |
| OCI image spec | 1.1.1 | GitHub releases |
| snapshot.debian.org timestamp listing | `/mr/timestamp/?archive=<name>` | read live |
