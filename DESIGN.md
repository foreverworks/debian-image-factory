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

- **Byte-for-byte reproducibility.** The goal is replaying the same declared inputs. The factory
  sets `SOURCE_DATE_EPOCH` and clamps timestamps, and a check measures whether two builds match,
  but no artifact is claimed to be bit-identical unless that check passes for it.
- **Promotion and deployment.** The factory produces candidates and their records. Deciding which
  candidate runs (a pin, a tag move, a rollout) is the consumer's job.
- **Patching running systems.** Persistent hosts keep their own update policy. The factory builds
  images; it does not run on, or report on, machines that use them.
- **Installing onto disks.** The installer kit and the OS root filesystem are artifacts. Partitioning,
  filesystems (ZFS or otherwise), bootloader installation on real hardware and machine identity stay
  in the consumer's install flow.
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
| snapshot ID | A snapshot.debian.org timestamp, `YYYYMMDDTHHMMSSZ`. apt 3.0 resolves it per archive to the newest snapshot at or before that time. |
| generation | The images resolved at one snapshot ID. An unchanged image carries over into the next generation as the same artifact. |
| lock | `lock.json`: the snapshot ID and every external input with its version and checksum. Machine-maintained. |
| build definition | `factory.toml`: which images exist, their kind, parent, packages, modules, hooks and outputs. Human-written. |
| image | A node of the build tree, named in the definition (`core`, `oci-base`, `node-26`, ...). |
| kind | What an image is built as: `core`, `oci`, `incus`, `installer`, `os`. A kind decides the build steps and the artifact format. |
| module | Shared recipe that installs lock entries into an image (`node`, a vendor `.deb`, your own script). |
| input identity | sha256 over what an image is built from (section 7). Equal identity, no rebuild. |
| artifact | The published bits of one build of one image, addressed by content digest. |
| record | An in-toto statement about one artifact digest: provenance, SBOM or test result. |
| candidate | An artifact whose checks have not all finished. |
| good build | An artifact with a passing test result for every check its image requires. Derived from its records at the time it is asked, never stored. |

## 5. Architecture

### 5.1 The tree

```text
lock.json: one snapshot ID (main + updates + security) and every external input
  |
  plan: resolve every image's package set, compute identities, compare with what is published
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
| `plan` | lock, definition, params, the published state (read live from the targets) | `plan.json`: per image its resolved package set, identity, `reuse` or `build`, and the reasons |
| `fetch` | `plan.json` | every `.deb`, index and external file the plan names, verified, in the cache; optionally an inputs bundle per image |
| `core` | snapshot indices, the core package list, hooks, files | rootfs tarball, its dpkg status, SBOM, provenance |
| `oci` | parent rootfs (core or an OCI parent), packages, modules, OCI config | OCI image layout (one layer for the base, one added layer per child), SBOM, provenance |
| `incus` | parent rootfs, packages, modules, the factory's NoCloud templates | `metadata` tarball plus `rootfs.squashfs`, their Incus fingerprint, SBOM, provenance |
| `installer` | parent rootfs, kernel and tool packages, hooks | boot kit: kernel, initrd holding the whole system, `kit.json`; SBOM, provenance |
| `os` | parent rootfs, kernel, bootloader and host packages, apt sources policy, hooks | OS root filesystem tarball, SBOM, provenance |
| `test` | an artifact and the checks its image requires | one in-toto test result per check, on the artifact digest |
| `publish` | built artifacts and their records, targets | pushed images and files, records attached |
| `prune` | the published state, the consumer's pins, a retention rule | the list of artifacts to delete (and, without `--dry-run`, the deletions) |

### 5.3 How a stage builds

- **Core** is `mmdebstrap --variant=apt` from the snapshot (through the local partial mirror the
  fetch stage built, see 7.5), with the definition's packages, files and hooks. It then removes
  every machine identity: `/etc/machine-id` emptied, `/var/lib/dbus/machine-id`, SSH host keys,
  systemd's random seed, apt lists and caches removed. The kernel packages are refused in core.
- **Children** unpack their parent's exact rootfs, enter it in a user-namespace chroot (the same
  mechanism mmdebstrap's unshare mode uses), install their packages with apt from the same local
  mirror, run their modules and hooks, and clean up identity again. A child never upgrades a package
  its parent installed: the plan refuses such a resolution, because it means the parent must be
  rebuilt first.
- **Hooks and modules run with no network.** Everything they may use was fetched and verified
  before the build started and is handed to them as files plus `LOCK_*` environment variables
  (section 6.5). A hook that tries to download fails.
- **Nothing is booted to build.** An image that needs a running system to produce its content (a
  warmed emulator snapshot, say) is a consumer stage that starts from a factory artifact.
- **Kind defaults are explicit.** Each kind installs a documented package set (for `incus`:
  systemd-sysv, udev, dbus, iproute2, netbase, systemd-resolved, cloud-init and what NoCloud needs)
  and a first-boot unit that creates SSH host keys when `openssh-server` is present. The plan lists
  them, so nothing arrives silently. They are part of the factory's version, and therefore of the
  identity.

### 5.4 The builder

Builds run in a builder environment whose tools come from Debian itself: mmdebstrap, apt, dpkg,
python3, squashfs-tools, gnupg, qemu-utils, oras and util-linux, as Debian 13 ships them.

- **In CI and by default locally**, the builder is a container image the factory release pins by
  digest. It is built by the factory itself from a snapshot fixed at release time and published
  with its own records; the very first one is bootstrapped from Debian's official `debian:trixie`
  image pinned by digest. It runs with `--privileged`, which under rootless Docker grants nothing
  beyond the invoking user's own namespace, and mmdebstrap runs in root mode inside it.
- **On a Debian host** (`--builder host`), mmdebstrap runs in unshare mode. That mode needs
  `newuidmap`, so it does not work where `NoNewPrivileges` is set; use the container there.
- **The builder is part of the identity.** The builder's package set (the tools above, name,
  version, architecture) enters every recipe digest. With the pinned container it changes only with
  a factory release, so upgrading the factory rebuilds everything once, on purpose. On a host it
  changes when the host's tools change.

## 6. The input contract

A consumer writes two files and nothing else: the lock and the build definition. Parameters
(feature flags) come from the command line or a file the consumer already owns.

### 6.1 The lock: `lock.json`

JSON, written by tools (the factory's `lock` commands and Renovate), read by people in review.
Sorted keys, two-space indent, trailing newline, so diffs stay small.

```json
{
  "schema": 1,
  "debian_snapshot": "20261121T005332Z",
  "inputs": {
    "debian-image-factory": {
      "datasource": "github-releases",
      "depName": "foreverworks/debian-image-factory",
      "extractVersion": "^v(?<version>.+)$",
      "module": null,
      "sha256": "6b1f...c09e",
      "url": "https://github.com/foreverworks/debian-image-factory/releases/download/v{version}/debian-image-factory-{version}.pyz",
      "version": "0.1.0"
    },
    "docker-ce": {
      "apt": "docker-ce",
      "datasource": "deb",
      "depName": "docker-ce",
      "module": "vendor-deb",
      "registryUrl": "https://download.docker.com/linux/debian?suite=trixie&components=stable&binaryArch=amd64",
      "sha256": "7fea...fe9d",
      "url": "https://download.docker.com/linux/debian/dists/trixie/pool/stable/amd64/docker-ce_{version_noepoch}_amd64.deb",
      "used_by": ["incus-docker"],
      "version": "5:29.10.0-1~debian.13~trixie"
    },
    "node-26": {
      "datasource": "node-version",
      "depName": "node",
      "module": "node",
      "sha256": "48cc...af75",
      "url": "https://nodejs.org/dist/v{version}/node-v{version}-linux-x64.tar.xz",
      "used_by": ["node-26"],
      "version": "26.13.1"
    },
    "node-release-keys": {
      "datasource": "git-refs",
      "depName": "https://github.com/nodejs/release-keys",
      "module": "node",
      "sha256": "0d3a...91b2",
      "url": "https://raw.githubusercontent.com/nodejs/release-keys/{version}/gpg-only-active-keys/pubring.kbx",
      "used_by": ["node-26"],
      "version": "<commit sha>"
    }
  }
}
```

(Digests are shortened here; real entries hold the full lowercase hex.)

Rules the factory checks (`lock check`):

| Field | Rule |
|---|---|
| `schema` | `1`. A lock without it is read as schema 1, so an existing lock needs no edit. |
| `debian_snapshot` | A snapshot ID. One ID for every archive (section 7.4 says how it is chosen). |
| `inputs.<name>` | Lowercase letters, digits and dashes. One entry per downloaded file. |
| `version` | The pin. Renovate or `lock` commands move it, never a build. |
| `url` | `https://` only. A template over `{version}`, `{version_noepoch}` (Debian epoch dropped), `{version_underscore}` (`+` as `_`), `{version_urlquoted}`, `{major}` and any other string field of the entry. When Renovate moves the version, the URL must be built from it. |
| `sha256`, `sha512`, `sha1` | At least one. `lock checksums` adds a sha256 to an entry that only has sha1 (some SDK repositories publish nothing stronger), so every file is also checked by sha256. |
| `apt` | For a vendor `.deb`: its package name. Requires `datasource: deb`, a `registryUrl` with `suite` and `components`, and a sha256 that matches the vendor's own `Packages` index for that version. One entry per apt package name. |
| `module` | The module that installs it (declared in the definition), or `null` when the image's own hooks use it. |
| `used_by` | A sorted, non-empty list of images from the definition. This is the only place that says which image installs which input. |
| `datasource`, `depName`, `packageName`, `extractVersion`, `versioning`, `registryUrl` | Renovate's lookup hints. The factory checks they come in valid pairs and otherwise ignores them: they never enter an identity. |
| `debian-image-factory` | Reserved: the factory release itself. No `used_by`: it applies to every image, through the recipe digest. |

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

[params]
docker = true                     # a feature flag; images that read it carry its value in their identity

[modules.node]
use = "builtin:node-tarball"      # nodejs.org tarball, checked against the signed SHASUMS256.txt
prefix = "/usr/local"

[modules.vendor-deb]
use = "builtin:deb"               # a vendor .deb from the lock, dependencies from the snapshot
enabled_by = "docker"             # off: its entries are installed nowhere and leave every identity

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

[images.incus-docker]
kind = "incus"
parent = "incus-base"
hooks = ["hooks/docker-daemon.sh"]  # runs in the chroot, no network

[images.installer]
kind = "installer"
parent = "core"
packages = ["linux-image-amd64", "kexec-tools", "gdisk", "dosfstools", "openssh-server"]
hooks = ["hooks/installer-trim.sh"]

[images.os]
kind = "os"
parent = "core"
packages = ["linux-image-amd64", "grub-efi-amd64", "openssh-server", "sudo"]
apt_sources = "snapshot-except-security"   # main and updates at the snapshot, security live

[checks]
# Which checks make a build "good". "builtin" is the kind's own set (section 11).
default = ["builtin"]
incus-docker = ["builtin", "nested-workload"]   # a check the consumer runs and attests itself
```

Keys per image: `kind`, `parent` (required except for core), `packages`, `files`, `hooks`,
`apt_sources` (`snapshot`, the default, `snapshot-except-security` or `live`), `compression`, and the
kind's own table (`oci`, `incus`, `installer`, `os`). The plan rejects a definition whose tree has a
cycle, a child whose kind cannot derive from its parent's (an `oci` child of an `incus` image, for
example), or a lock entry whose `used_by` names an image the definition lacks.

### 6.3 Parameters

A parameter is a named value the consumer already decides somewhere else (a feature flag in its
inventory, say). It reaches the factory as `--param docker=true` or `--params params.json`, never
copied into the definition. A module's `enabled_by`, or a hook that reads `FACTORY_PARAM_<NAME>`,
declares that an image reads it; only the parameters an image reads enter its identity, so
switching a flag rebuilds exactly the images it touches. Both values of a flag are buildable and
testable from the same definition.

### 6.4 Modules

| Module | Installs | Verification |
|---|---|---|
| `builtin:deb` | a vendor `.deb` from the lock, with `apt-get install ./file.deb`; its dependencies come from the snapshot. The vendor's repository is never added to the image's apt sources. | lock sha256, which `lock checksums` cross-checked against the vendor's signed index |
| `builtin:node-tarball` | a nodejs.org release tarball into a prefix, plus `node`, `npm`, `npx` links | lock sha256, and `SHASUMS256.txt` verified with gpgv against the pinned release keyring |
| `builtin:file` | any locked download, placed at a path the definition names, optionally unpacked | lock checksums |
| a path (`hooks/android.sh`) | whatever the script does, in the chroot, with no network | the factory has already verified every file the script receives |

A module is shared source invoked on whichever images use its entries; it is never an image with
two parents.

### 6.5 What a hook sees

Inside the chroot a hook gets `/run/factory/inputs/<entry>/` holding each verified file it may use,
and a `build.env` with, per entry, `LOCK_<NAME>_VERSION`, `LOCK_<NAME>_URL` (rendered),
`LOCK_<NAME>_SHA256` (and the other checksum and string fields), plus `LOCK_DEBIAN_SNAPSHOT`,
`LOCK_ENTRIES` and `FACTORY_PARAM_<NAME>`. These are the same `LOCK_*` names the first consumer's
build scripts already read, so its recipes move without a rename.

### 6.6 The first consumer's lock, and where its format still moves

The factory is being carved out of a private infrastructure repository, whose own lock (landing
there now) is the factory's first real input. The contract above was written so that lock fits
as it is: same top level, same entry fields, same URL placeholders, same `LOCK_*` names, same
record formats. Where it still has to move, and the factory's answer:

1. **`used_by` is checked against a fixed list of images in the consumer's own code.** The factory
   checks it against the build definition instead. Nothing changes in the file.
2. **`module` is a closed set of three names there.** The factory accepts any module the
   definition declares. Nothing changes in the file.
3. **No format version.** The top level there is exactly `debian_snapshot` and `inputs`. The
   factory reads that as schema 1. Recommended: add `"schema": 1` before the lock lands, while it
   costs one line. (Open question 6.)
4. **The identity function takes whole lock entries,** so Renovate hints and `used_by` would enter
   identities: adding an image to an entry's `used_by` would rebuild every other image that uses
   it. The factory hashes only the fields a build reads (`version`, the rendered `url`, `apt`,
   `sdk`, `build`, `workload_set` and the checksums), the same projection the consumer's `build.env`
   already exports. Recommended: align the consumer's identity function before it is wired into
   its nightly build. (Open question 7.)
5. **The factory's own release is not in that lock yet.** It becomes the reserved
   `debian-image-factory` entry, and the consumer's lock check must accept that one entry without
   `used_by`.
6. **Architecture is implicit** (amd64 in URLs, `binaryArch` in registry URLs). Fine while amd64
   is the only consumer. A second architecture will need an `{arch}` placeholder and checksums per
   architecture; that is a schema 2 change, made when a consumer needs it.
7. **Records name the consumer's own build script** as SLSA `buildType` and SBOM creator. Under the
   factory they name the factory's build type and version (section 8.4).
8. **Multi-file artifacts.** The consumer's statement helper takes one subject; an Incus split
   image and an installer kit need several (section 8.2).
9. **SBOM relationships.** The consumer's SPDX documents list packages only. The factory adds a
   root package for the artifact with `DESCRIBES` and `CONTAINS` relationships, and the locked
   external inputs as packages with their download location and checksum, which SBOM tools expect.

## 7. Input identity: rebuilding only what changed

### 7.1 Definition

```text
identity(image) = sha256(canonical_json({
  "identity": 1,
  "packages": sorted set of (name, version, architecture) installed in the image,
  "lock":     { entry: build-relevant fields } for the lock entries this image itself installs,
  "recipe":   recipe digest,
  "parent":   identity(parent), or null for core
}))

recipe digest = sha256(canonical_json({
  "factory":    the factory release version,
  "builder":    the builder's package set,
  "kind":       the kind and its own table from the definition, parsed,
  "image":      the image's definition section, parsed,
  "files":      { path: sha256 } of every hook, module script and file tree it references,
  "params":     { name: value } of the parameters it reads,
  "suite":      suite, components, architecture
}))
```

Canonical JSON is sorted keys, no whitespace, UTF-8. The definition enters parsed, not as bytes, so
reformatting `factory.toml` or reordering its keys never rebuilds anything; the referenced files
enter by content. This is the same function shape as the first consumer's
`input_identity(packages, lock_entries, recipe_digest, parent_identity)`: everything the factory
adds lives inside the recipe digest.

### 7.2 Resolving before building

The plan computes each package set without building anything:

1. Download the snapshot's `InRelease` and `Packages` indices for every suite (by hash, since
   Debian's archives set `Acquire-By-Hash: yes`), and verify them with the builder's
   `debian-archive-keyring`.
2. For core, run mmdebstrap in `--simulate` mode with the core package list: apt's own solver,
   no downloads.
3. For each child, run `apt-get install --simulate` with the parent's resolved set as the installed
   status (synthesised from the same `Packages` stanzas), and the child's packages and module
   dependencies as the request.
4. Add the kind defaults, compute identities top-down, and compare each with the identities already
   published.

Plan output for a night when Debian published a new kernel and Renovate moved Node, abridged:

```json
{
  "schema": 1,
  "snapshot": "20261121T005332Z",
  "factory": "0.1.0",
  "images": {
    "core":         {"identity": "5d1c2b3a...", "action": "reuse", "artifact": "sha256:3f9a1c2e4b5d..."},
    "oci-base":     {"identity": "a07e44f1...", "action": "reuse", "artifact": "sha256:a07e..."},
    "node-26": {
      "identity": "c3b9e012...",
      "action": "build",
      "because": [{"input": "node-26", "from": "26.12.0", "to": "26.13.1"}]
    },
    "incus-base":   {"identity": "19d4aa30...", "action": "reuse", "artifact": "sha256:7c1e..."},
    "incus-docker": {"identity": "2be07d19...", "action": "reuse", "artifact": "sha256:d84f..."},
    "installer": {
      "identity": "e81f0c77...",
      "action": "build",
      "because": [{"package": "linux-image-6.12.120+deb13-amd64", "from": null, "to": "6.12.120-1"},
                  {"package": "linux-image-6.12.119+deb13-amd64", "from": "6.12.119-1", "to": null}]
    },
    "os": {"identity": "40c9e6d2...", "action": "build", "because": [{"package": "linux-image-6.12.120+deb13-amd64", "from": null, "to": "6.12.120-1"}]}
  }
}
```

A child's identity contains its parent's, so a rebuilt parent always rebuilds every image below it:
had core changed, every line above would read `build`. Package versions in this example are
illustrative.

### 7.3 What does and does not rebuild

| Change | Rebuilds |
|---|---|
| A new snapshot ID with no new version of any installed package | nothing |
| A security upload of a package core installs | core and every image below it |
| A new version of a package only the installer installs | the installer only |
| A lock entry's version or checksum | the images in its `used_by` and their children |
| A Renovate hint, or another image added to an entry's `used_by` | nothing |
| A hook file's content | that image and its children |
| `factory.toml` reformatted, comments edited, keys reordered | nothing |
| A parameter flipped | the images that read it and their children |
| A factory upgrade (new release, new builder) | everything, once |
| A core rebuilt with the same inputs gets a new digest | nothing: a digest is not an input |

`plan --rebuild <image> --reason "<text>"` forces a build and records the reason in provenance, for
the rare case inputs cannot see (an archive key rotation, say).

### 7.4 Choosing the snapshot ID

snapshot.debian.org keeps separate timelines for the `debian` and `debian-security` archives, and
apt 3.0's `Snapshot:` option resolves one ID against each to its newest snapshot at or before that
time. `lock snapshot --latest` picks the newest ID that every archive in use has already completed,
so the same ID always resolves to the same indices, whenever it is read. `plan --snapshot latest`
does the same without editing the lock, for a nightly run that should only write the new ID once
its builds pass (the consumer's promotion commits it, together with whatever it approves).

### 7.5 Fetching, the cache and replay without snapshot.debian.org

- **Fetch, then build offline.** `fetch` downloads every index, `.deb` and external file the plan
  names into a content-addressed cache (`~/.cache/debian-image-factory/sha256/...`), checking
  each against its signed index or lock checksum. It then lays out a partial Debian mirror (signed
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

Names are content-addressed: `<image>-<suite>-<arch>-<first 12 hex of the digest>.<ext>`, so two
builds never collide. The digest of each kind:

| Kind | Files | Digest that names it | Default compression |
|---|---|---|---|
| core | `core-trixie-amd64-3f9a1c2e4b5d.tar.gz` | sha256 of the file | gzip |
| oci | OCI image layout, pushed to a registry | image manifest digest | layers `application/vnd.oci.image.layer.v1.tar+gzip` |
| incus | `<name>.incus.tar.gz` (metadata.yaml, templates) and `<name>.rootfs.squashfs` | Incus fingerprint: sha256 of the metadata file followed by the rootfs file | gzip tarball, squashfs with its gzip compressor |
| installer | `installer-trixie-amd64-<12 hex>.tar`, a kit holding `vmlinuz`, `initrd.img`, `kit.json` | sha256 of the kit tarball; kernel and initrd are listed as subjects too | initrd gzip, kit tarball uncompressed |
| os | `os-trixie-amd64-....tar.gz` | sha256 of the file | gzip |

Compression is gzip, or the format the target ecosystem reads by default, for everything published.
zstd is supported per image (`compression = "zstd"`) for consumers who control every reader. The
OS image's own initramfs keeps whatever its Debian packages configure, since the installed system
regenerates it.

An OCI image carries standard annotations: `org.opencontainers.image.base.digest` and
`org.opencontainers.image.base.name` (its parent), `org.opencontainers.image.source` and
`org.opencontainers.image.revision` (the definition's repository and commit),
`org.opencontainers.image.created` (the snapshot time, not the build time), and
`io.github.foreverworks.debian-image-factory.identity` (its input identity, so a plan can read it
with one manifest request).

An Incus image's `metadata.yaml`:

```yaml
architecture: x86_64
creation_date: 1795222412        # the snapshot time
properties:
  os: debian
  release: trixie
  variant: incus-base
  serial: "20261121T005332Z"
  description: "Debian 13 (trixie) incus-base, identity 19d4aa30"
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
`user.user-data` key, which some runner managers still set.

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
  manifest, found through the registry's referrers API. Where a registry has no referrers API,
  oras uses the referrers tag schema of the distribution spec, which every registry can store.
- **Files:** one `<digest>.intoto.jsonl` beside the artifact, one envelope per line, where
  `<digest>` is the sha256 (or Incus fingerprint) in full hex.

Provenance for a core build:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "core-trixie-amd64-3f9a1c2e4b5d.tar.gz", "digest": {"sha256": "3f9a1c2e4b5d..."}}],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://github.com/foreverworks/debian-image-factory/blob/v0.1.0/docs/build-type-v1.md",
      "externalParameters": {
        "image": "core",
        "definition": {"uri": "git+https://github.com/example/images", "revision": "<commit>", "path": "factory.toml"},
        "params": {}
      },
      "internalParameters": {
        "identity": "5d1c2b3a...",
        "snapshot": "20261121T005332Z",
        "architecture": "amd64",
        "reason": "package libssl3t64 3.5.1-1+deb13u1 -> 3.5.1-1+deb13u2"
      },
      "resolvedDependencies": [
        {"uri": "git+https://github.com/example/images@<commit>", "digest": {"gitCommit": "<commit>"}},
        {"name": "lock.json", "digest": {"sha256": "b71d..."}},
        {"name": "recipe of core", "digest": {"sha256": "0e9c..."}},
        {"uri": "https://snapshot.debian.org/archive/debian/20261121T005332Z/dists/trixie/InRelease", "digest": {"sha256": "a3f0..."}},
        {"uri": "https://snapshot.debian.org/archive/debian-security/20261121T005332Z/dists/trixie-security/InRelease", "digest": {"sha256": "55c2..."}},
        {"uri": "oci://ghcr.io/foreverworks/debian-image-factory-builder", "digest": {"sha256": "9d42..."}}
      ]
    },
    "runDetails": {
      "builder": {"id": "https://github.com/example/images/.github/workflows/images.yml@refs/heads/main",
                  "version": {"debian-image-factory": "0.1.0"}},
      "metadata": {"invocationId": "https://github.com/example/images/actions/runs/1234567890/attempts/1",
                   "startedOn": "2026-11-21T02:17:05Z", "finishedOn": "2026-11-21T02:19:41Z"}
    }
  }
}
```

A child adds `{"name": "parent: core", "digest": {"sha256": "<parent artifact digest>"}}` and its
locked downloads (`{"uri": "<rendered url>", "digest": {"sha256": "..."}}`), so ancestry and every
input are provable from the record alone.

SBOM, abridged:

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "node-26-trixie-amd64",
  "documentNamespace": "https://github.com/example/images/sbom/c3b9e012...",
  "creationInfo": {"created": "2026-11-21T00:53:32Z", "creators": ["Tool: debian-image-factory-0.1.0"]},
  "packages": [
    {"SPDXID": "SPDXRef-Image", "name": "node-26", "versionInfo": "sha256:c3b9...",
     "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
     "primaryPackagePurpose": "CONTAINER"},
    {"SPDXID": "SPDXRef-Package-libssl3t64-amd64", "name": "libssl3t64", "versionInfo": "3.5.1-1+deb13u2",
     "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                       "referenceLocator": "pkg:deb/debian/libssl3t64@3.5.1-1%2Bdeb13u2?arch=amd64&distro=trixie"}]},
    {"SPDXID": "SPDXRef-Input-node-26", "name": "node", "versionInfo": "26.13.1",
     "downloadLocation": "https://nodejs.org/dist/v26.13.1/node-v26.13.1-linux-x64.tar.xz", "filesAnalyzed": false,
     "checksums": [{"algorithm": "SHA256", "checksumValue": "48cc..."}],
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                       "referenceLocator": "pkg:generic/node@26.13.1"}]}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Image"},
    {"spdxElementId": "SPDXRef-Image", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Package-libssl3t64-amd64"},
    {"spdxElementId": "SPDXRef-Image", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Input-node-26"}
  ]
}
```

The package list comes from the image's own dpkg status after the build, not from the plan, and a
check compares the two.

Test result, one per check:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "core-trixie-amd64-3f9a1c2e4b5d.tar.gz", "digest": {"sha256": "3f9a1c2e4b5d..."}}],
  "predicateType": "https://in-toto.io/attestation/test-result/v0.1",
  "predicate": {
    "result": "PASSED",
    "configuration": [{"name": "no-machine-identity",
                       "uri": "https://github.com/foreverworks/debian-image-factory/blob/v0.1.0/docs/checks.md#no-machine-identity"}],
    "url": "https://github.com/example/images/actions/runs/1234567890",
    "passedTests": ["machine-id-empty", "no-ssh-host-keys", "no-private-keys", "no-random-seed"],
    "warnedTests": [],
    "failedTests": []
  }
}
```

The first `configuration` entry's `name` is the check's ID; "good build" is computed from it. A
consumer's own check attests the same way: `debian-image-factory attest test-result --artifact
<digest> --check nested-workload --result PASSED --passed boot,workload --url <run url>`.

A line of `<digest>.intoto.jsonl`:

```json
{"payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLC4uLn0=","payloadType":"application/vnd.in-toto+json","signatures":[]}
```

And the OCI artifact that carries one record as a referrer:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.in-toto+json",
  "config": {"mediaType": "application/vnd.oci.empty.v1+json",
             "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2},
  "layers": [{"mediaType": "application/vnd.dsse.envelope.v1+json", "digest": "sha256:e0a1...", "size": 4127,
              "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"}}],
  "subject": {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:a07e...", "size": 1043}
}
```

Records never hold secrets, private keys, tokens or machine identities. They describe bits; what is
actually running somewhere is for the consumer to read back from the running system.

### 8.3 Signing

Envelopes are unsigned by default (`"signatures": []`): the registry's or release host's
authentication is then the trust boundary, which is SLSA Build L1. `--sign keyless` signs each
envelope with Sigstore through the CI's OIDC identity (cosign 3.1.4), which with a hosted CI is
SLSA Build L2. `--sign key:<path or KMS URI>` uses a key the consumer holds. The factory never holds
a key; nothing in its records changes shape when signing is switched on. Build L3 needs a hardened,
isolated build platform, which the factory does not claim to be.

### 8.4 Build type

`buildType` names a versioned document in this repository describing the build: which
`externalParameters` exist (the image, the definition's repository, revision and path, the
parameters), what `internalParameters` mean (identity, snapshot, architecture, reason) and which
`resolvedDependencies` every build lists. A verifier pins the build types it accepts.

## 9. Running it

### 9.1 The command line

One file, `debian-image-factory-<version>.pyz` (a Python zipapp with no dependencies outside the
standard library), published as a release asset with its own provenance.

```text
debian-image-factory lock check                          the lock and the definition agree
debian-image-factory lock snapshot --latest | --id ID    move the snapshot ID
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
`dir://<path>`. `plan --against` reads the published identities live from those targets (OCI
annotations, provenance in `.intoto.jsonl`); nothing about the published state is stored in the
consumer's repository.

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
        uses: foreverworks/debian-image-factory@<commit> # v0.5.0
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
reported as not run, never as passed, and the build is not good until they run.

### 9.3 How a private consumer runs a pinned release

The first consumer is a private infrastructure repository. It keeps everything that is its own and
takes the factory as a pinned tool:

1. **Pin.** Its lock gains the `debian-image-factory` entry; Renovate (github-releases datasource)
   opens the bump and the consumer's checksum tooling, or `lock checksums`, fills the sha256. The
   Action is pinned by commit, with the version as a comment, and Renovate bumps it too.
2. **Define.** Its `factory.toml` holds its package lists, its children of the Incus and OCI bases,
   its module scripts, and the parameters its inventory decides (a feature flag that adds a vendor
   module to the installer and OS images, say), passed with `--params`.
3. **Plan nightly** with `--snapshot latest` against its own registry and release. A night with no
   relevant upload builds nothing.
4. **Build, test, publish candidates** on its own runners.
5. **Run its own checks** (boot in its own environment, nested workloads, a full install of the OS
   image through its own installer onto a test VM) and attach each result with `attest`.
6. **Approve in its own way.** Its promotion moves its pins after every required check is good,
   and commits the new snapshot ID with the pins it produced, so the lock never runs ahead of a
   verified build. The factory has no notion of pins beyond `prune --pin`.
7. **Prune** with its pins and its retention rule (it keeps 5 good builds and 1 candidate per
   image, which are the factory's defaults).

## 10. What stays with the consumer, what lives in the factory

| The consumer keeps | The factory provides |
|---|---|
| Its lock: every version and checksum, the snapshot ID | The lock format, its checks, `lock` commands, Renovate guidance |
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
| `no-machine-identity` | all | empty or absent machine IDs, no SSH host keys, no private keys or tokens by pattern, no random seed, no cloud-init instance state |
| `sbom-complete` | all | the SBOM lists every installed package and locked input |
| `ancestry` | children | the parent's filesystem is the base: for OCI, the parent's layers are the first layers by digest; elsewhere, the parent's files are present unless the child's own records say it removed them |
| `same-resolution` | core | a second resolution of the same lock gives the same package set |
| `byte-equal` | all, optional | two builds from the same inputs give the same digest; WARNED, never FAILED, when they differ |
| `oci-run` | oci | runs under rootless Docker: declared user and entrypoint, `cmd` exits 0 |
| `incus-boot` | incus | in an Incus host inside a VM: cloud-init finishes through NoCloud from both `cloud-init.user-data` and `user.user-data`, creates the user, runs commands, an IPv4 address is reported, all still true after a restart |
| `two-clones` | incus, os | two instances get distinct machine IDs and SSH host keys |
| `installer-boot` | installer | QEMU boots the kit from RAM to a serial marker; the running kernel is the packaged one |
| `os-boot` | os | the test harness lays the root filesystem onto a scratch disk, QEMU boots it to multi-user, installed and running kernel match, first boot creates its identity |

Failed, cancelled or incomplete checks leave the artifact a candidate; the consumer's pins do not
move, and `prune` deletes it once its checks end.

## 12. Test plan

The factory's own tests, from fastest to slowest. Each tier runs where it answers in minutes; CI
runs the same commands as the final gate, never as the first place a failure is seen.

**Static, on every commit (pre-commit, and in CI as failing checks)**

- `ruff check` and `ruff format --check` (ruff 0.17.6).
- `mypy --strict` (mypy 2.4.1) with `disallow_any_explicit = true`, `warn_unused_ignores = true`
  and `enable_error_code = ["ignore-without-code"]`, over the package and the tests. A repository
  check fails any `# type: ignore[...]` whose line does not also carry a reason.
- `shellcheck` on the example hooks and the Action's shell steps.
- `pre-commit` 4.7.0 runs all of the above locally; CI runs the identical configuration.

**Unit, seconds, no network, no root (`python3 -m unittest`)**

- Lock: every rule of 6.1 with a good and a bad fixture each, URL templates, the schema-1 default.
- Definition: tree validation, kind compatibility, `used_by` against images, parameters.
- Identity: order and formatting never change it; each field that should change it does; the lock
  projection ignores Renovate hints and `used_by`.
- Plan: reasons for each row of the table in 7.3, refusal of a child that would upgrade its parent.
- Records: statements, provenance, SPDX and test results validated against the published JSON
  schemas, which are vendored as test fixtures; DSSE encoding; `.intoto.jsonl` naming.
- OCI layout: manifest, config and layer digests; annotations; referrer manifests.
- Incus fingerprint and `metadata.yaml`.
- Retention: a run of failed nights never pushes out a good build; pins are never pruned; at most
  `keep_good + keep_candidates` per image plus pins.

**Fixture archive, seconds to a minute**

A tiny Debian-format archive generated by the tests (a handful of packages made with `dpkg-deb`,
indexed and signed with a throwaway key) at two timestamps, served from a directory in the layout
snapshot.debian.org uses. It exercises resolve, fetch, offline build and replay without the network,
and proves "rebuild only what changed": a new version of one package at the second timestamp
rebuilds exactly the images that install it.

**Rootless Docker, minutes**

- Core, OCI, Incus rootfs, installer and OS builds from the fixture archive on every commit, and
  from the real snapshot nightly.
- `package-set`, `locked-inputs`, `no-machine-identity`, `sbom-complete`, `ancestry`,
  `same-resolution`, `byte-equal`, `oci-run`.
- Offline replay from an inputs bundle with `--network none`.
- Publishing to a throwaway local registry container, then `verify` and `plan --against` it.

**VM (QEMU with KVM), minutes**

- `installer-boot`, `os-boot`, `two-clones`.
- `incus-boot`: a Debian 13 VM with Incus from the same snapshot (6.0.4 in Debian 13) imports the
  candidate and runs the boot contract.
- Nightly and before each release, on hosted runners with `/dev/kvm`.

**Where it runs.** This repository will be public, so its CI runs only on GitHub's hosted runners:
free for public repositories, and a pull request from a fork never reaches anyone's own machines.
Consumers run their own checks in their own CI.

## 13. Code: language and style

**Python, standard library only at run time.** The factory runs inside a Debian builder, and Debian
ships python3, so no runtime has to be downloaded outside the snapshot. apt and dpkg tooling is at
home there, and the first consumer's lock library is already Python in the same style. TypeScript
was considered and rejected: it would put Node.js into the builder only to run the factory.

- Supported interpreter: the python3 of the Debian release the builder runs (3.13 in Debian 13),
  and CI also runs the current stable Python (3.15.2) so nothing breaks on the next Debian.
  (Open question 1.)
- Pure functions and explicit state; effects (subprocesses, network, files) at the edges, in a thin
  layer the pure core never imports. No classes with behaviour.
- Fully typed: every function, argument and return annotated, `mypy --strict` with no explicit
  `Any`, no unexplained `type: ignore`. Data is `TypedDict` (JSON shapes: the lock, records, the
  plan) or `@dataclass(frozen=True, slots=True)` (internal values). JSON enters through parse
  functions that take `object` and return a `TypedDict` only after checking every field, so nothing
  downstream sees an unchecked value.
- `argparse` for the command line, `tomllib` for the definition, `json` for everything machines
  write, `unittest` for tests. Development tools (mypy, ruff, pre-commit) are pinned with hashes in
  a development requirements file and never become run-time dependencies.
- Layout: `src/debian_image_factory/` with one module per concern (`lock`, `definition`,
  `identity`, `resolve`, `plan`, `fetch`, `records`, `retention`, `publish`, `cli`), growing into
  a package (`build/`, `checks/`) when a module needs helpers of its own.

## 14. Milestones

Each milestone ends in a tagged release that a consumer can pin.

| | Milestone | Starts when | Done when |
|---|---|---|---|
| M1 | **The contract**: repository skeleton (typed package, pre-commit, CI), lock and definition parsing and checks, identity, `lock check`, `plan` against the fixture archive and real snapshot indices. No builds. | the first consumer's lock is on its main branch, because its format is then fixed | the consumer's real lock and a definition for its tree pass `lock check` in the consumer's own CI; plan identities are stable across runs; static and unit tiers green. Release v0.1.0. |
| M2 | **Core**: fetch, partial mirror, offline core build, SBOM, provenance, `.intoto.jsonl`, core checks, `dir://` target | M1 | two builds from one lock resolve the same set; no machine identity; SBOM complete. v0.2.0. |
| M3 | **OCI**: OCI kind with child layers, `oci://` publish with referrers, `node-tarball` module, `oci-run`, `verify` | M2 | a Node runtime image's provenance names core's digest; its Node version equals the lock's. v0.3.0. |
| M4 | **Incus**: Incus kind, NoCloud templates, `incus-boot` and `two-clones` in a VM, `github-release://` publish | M2 | the boot contract passes for the base and for a child. v0.4.0. |
| M5 | **Installer and OS**: both kinds, `deb` and `file` modules, parameters, `installer-boot`, `os-boot` | M2 | both boot in QEMU; a flag off removes its module from both and changes both identities. v0.5.0. |
| M6 | **Nightly**: `plan --against`, `--snapshot latest`, the Action, `prune`, inputs bundles, offline replay, the builder image | M3 to M5 | a night with no relevant upload builds nothing; one with a single upload rebuilds exactly its chain; a bundle rebuilds with snapshot.debian.org unreachable. v0.6.0. |
| M7 | **1.0**: optional signing, docs for strangers, a full example repository | M6, and the first consumer has promoted every kind from the factory | the README's quick start works on a clean machine. v1.0.0. |

M3, M4 and M5 are independent once M2 lands and can run side by side.

## 15. Decisions

1. **Python, standard library only, strictly typed** (`mypy --strict`, no explicit `Any`, every
   ignore explained, in pre-commit and CI). The builder is Debian and already has python3; strict
   types catch shape errors in a tool whose whole job is moving structured records around.
2. **The lock is JSON, the definition is TOML.** Machines write the lock (Renovate's JSON manager,
   sorted output, small diffs); people write the definition, and TOML has comments and a reader in
   the standard library.
3. **One home for every fact.** Versions live only in the lock, which image uses an input only in
   `used_by`, the factory's version only in the lock's reserved entry, published state only at the
   targets (read live). Nothing is stored twice, so nothing goes stale.
4. **Identity over inputs, not outputs.** Package set, the build-relevant lock fields, the recipe
   digest and the parent's identity; never the snapshot ID or a previous digest. A night with no
   relevant upload builds nothing, and a non-reproducible byte never forces a rebuild.
5. **The factory version and the builder are part of every identity.** A new mmdebstrap or apt can
   change what lands in an image; a factory upgrade therefore rebuilds everything once, deliberately.
6. **Fetch, then build offline.** Hooks run with no network and receive verified files. A build can
   only consume what the lock and the snapshot named, and a replay is the same code path.
7. **The cache is a performance layer, never an authority.** Content is accepted only by signed
   index or lock checksum.
8. **Children build in a chroot from their parent's exact filesystem.** Shared ancestry is real and
   provable, and nothing needs a running instance or root on the host.
9. **Tools from Debian stable, not upstream latest.** mmdebstrap 1.5.7, apt 3.0, oras 1.2.0 as
   Debian 13 ships them: the builder is itself a Debian image from a snapshot, so its tools are
   locked like everything else. Upstream releases (mmdebstrap 1.7.0, oras 1.4.0) arrive with the
   next Debian release or a deliberate builder change.
10. **Only shapes with a consumer.** Core, OCI, Incus container, installer kit, OS root filesystem.
    Incus VMs, disk images, ISOs and arm64 are designed for and added when someone needs them.
11. **Published artifacts default to gzip, or the format their ecosystem expects; zstd is an
    option.** Anyone who pulls an artifact can read gzip, whatever their runtime, Incus or unpacker
    version. Consumers who control every reader can opt into zstd per image.
12. **Standard records, attached by digest.** in-toto Statement v1 in DSSE, SLSA provenance v1, SPDX
    2.3 JSON, in-toto test-result v0.1; OCI 1.1 referrers for images and `.intoto.jsonl` beside files.
    SPDX 2.3 rather than 3.0.1 because 2.3 is what SBOM scanners and the first consumer read today.
13. **Unsigned by default, signing pluggable.** Signing needs a key or an OIDC identity, which only
    the consumer has; the record shape does not change when it is turned on.
14. **The factory never approves.** It emits candidates and records; pins, promotion and rollout are
    the consumer's. "Good build" is derived from test results whenever it is asked, never stored.
15. **Retention is a pure function** of the published builds, their results and the consumer's
    pins: the newest 5 good builds and 1 candidate per image by default, pins never pruned, failed
    builds deleted when their checks end.
16. **Content-addressed names.** Every artifact and record file is named by its digest, so two
    builds never collide and a name alone proves which bits it means.
17. **Distribution as a zipapp and an Action.** One `.pyz` file needs nothing beyond python3; the
    Action is a thin bootstrap that reads the version from the lock.
18. **The NoCloud templates are written here.** Copying another project's templates would bring
    their license terms into an MIT repository; the templates are small enough to write from the
    Incus documentation.
19. **`apt_sources` per image.** The image's own apt configuration (all at the snapshot, security
    live, or plain live mirrors) is a consumer policy, so the definition states it per image; the
    default keeps everything at the snapshot, so a downstream `apt-get install` stays reproducible.

## 16. Open questions

Each has a recommendation, which the design above already follows, and what changes if it is
decided the other way.

1. **Python floor: Debian's 3.13 or the current stable 3.15.** Recommendation: 3.13 as the floor,
   CI also on 3.15.2. Consequence: the builder needs nothing outside Debian; the code cannot use
   3.14 or 3.15 features until Debian ships them. Choosing 3.15 means downloading a Python into
   every builder, an input outside the snapshot.
2. **Does this repository publish ready-made public images** (a core OCI base, a Node runtime)?
   Recommendation: not before 1.0; the repository publishes the tool and its builder image, and CI
   builds its example definition into a throwaway registry. Consequence: strangers build their own
   images; nobody depends on images this project would then have to patch forever.
3. **Signing the factory's own releases.** Recommendation: sign the `.pyz` and the builder image
   with Sigstore keyless from v0.1, even though consumer artifacts stay unsigned by default.
   Consequence: strangers can verify the tool they run, at no cost to consumers.
4. **Which of the first consumer's Incus children move into its `factory.toml`.** Recommendation:
   every child whose recipe is packages, locked files and hooks; children that need a booted system
   (a warmed emulator snapshot) stay in the consumer's pipeline, starting from a factory artifact.
   Consequence: most children gain records and skip-when-unchanged; the rest keep their current path.
5. **Inputs bundles: on or off by default.** Recommendation: off in the factory (`--bundle`), on in
   a consumer that wants offline replay of its retained generations. Consequence: hundreds of
   megabytes per retained good build where it is on; snapshot.debian.org dependence where it is off.
6. **A `schema` key in the first consumer's lock before it lands.** Recommendation: add
   `"schema": 1` now. Consequence: a later format change is detected instead of guessed; if it
   lands without it, the factory reads a missing key as 1 and nothing breaks.
7. **The consumer's identity function hashes whole lock entries.** Recommendation: hash only the
   fields a build reads, before identities are wired into its nightly build. Consequence: no
   spurious rebuilds from Renovate hints or `used_by` edits; otherwise the factory and the consumer
   would compute different identities for the same image.
8. **Making the repository public.** It stays private until its maintainers decide. Before that: every
   file passes a scan for private data, no private repository or issue is referenced, and the
   example definitions use example.com names only.

## Versions read for this design

All read on 2026-11-21.

| What | Version | Source |
|---|---|---|
| Debian stable | 13.8 "trixie" | `deb.debian.org/debian/dists/stable/Release` |
| apt in Debian 13 | 3.0 (3.0.3) | sources.debian.org |
| mmdebstrap | 1.5.7 in Debian 13; upstream 1.7.0 | sources.debian.org; upstream tags |
| python3 in Debian 13 | 3.13.5 | sources.debian.org (python3-defaults) |
| Python, current stable | 3.15.2 | python.org downloads API |
| Node.js, active LTS | 26.13.1 "Lithium" | `nodejs.org/dist/index.json` |
| Incus | 6.0.4 in Debian 13; upstream 7.6.0, LTS 7.0.2 | sources.debian.org; GitHub releases |
| oras | 1.2.0 in Debian 13; upstream 1.4.0 | sources.debian.org; GitHub releases |
| squashfs-tools, util-linux, qemu, gnupg, dpkg, cloud-init in Debian 13 | 4.6.1, 2.41.5, 10.0.13, 2.4.7, 1.22.22, 25.1.4 | sources.debian.org |
| cosign | 3.1.4 | GitHub releases |
| actions/checkout | 7.0.1 | GitHub releases |
| mypy, ruff, pre-commit | 2.4.1, 0.17.6, 4.7.0 | PyPI |
| SLSA | spec 1.2, predicate `https://slsa.dev/provenance/v1` | slsa.dev |
| in-toto attestation | framework 1.2.0, Statement v1, test-result predicate 0.1 | GitHub releases, the predicate spec |
| SPDX | 2.3 used; 3.0.1 newest | spdx-spec releases |
| OCI image spec | 1.1.1 | GitHub releases |
