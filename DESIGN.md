# Debian Image Factory: design

Status: milestones M1 to M6 are implemented (the contract, core, OCI, Incus, installer and OS images,
and the nightly loop); version 1.0 (M7) is still to come. This document is the design they follow and
is revised as they land. Written 2026-11-21; every version this document names was read that day at
the source listed in
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
| `fetch` | `plan.json` | every `.deb`, index and external file the plan names, verified, in the cache; only for the images that build; optionally an inputs bundle per image |
| `core` | snapshot indices, the core package list, hooks, files | rootfs tarball, SBOM, provenance |
| `oci` | parent rootfs (core or an OCI parent), packages, modules, OCI config | OCI image layout (one layer for the base, one added layer per child), SBOM, provenance |
| `incus` | parent rootfs, packages, modules, the factory's NoCloud templates | `metadata` tarball plus `rootfs.squashfs`, their Incus fingerprint, SBOM, provenance |
| `installer` | parent rootfs, kernel and tool packages, hooks | boot kit: kernel, initrd holding the whole system, `kit.json`; SBOM, provenance |
| `os` | parent rootfs, kernel, bootloader and host packages, apt sources policy, hooks | OS root filesystem tarball, SBOM, provenance |
| `test` | an artifact and the checks its image requires | one in-toto test result per check, on the artifact digest |
| `publish` | built artifacts and their records, targets | pushed images and files, identity tags or names, records attached |
| `prune` | the published state, the definition's required checks, the consumer's pins, a retention rule | one line per artifact, kept or deleted with its reason (and, without `--dry-run`, the deletions) |

### 5.3 How a stage builds

- **Core** is `mmdebstrap --variant=apt` with the definition's packages, files and hooks, reading
  the snapshot through the local partial mirror the fetch stage built (7.7). It then removes every
  machine identity: `/etc/machine-id` emptied, `/var/lib/dbus/machine-id`, SSH host keys, systemd's
  random seed, apt lists and caches and logs removed, and the `/etc/hostname` and `/etc/resolv.conf`
  mmdebstrap copies from the build container, with the apt options only the build needed. The
  sources it read the mirror with are replaced by the image's own (`apt_sources`). The root is packed
  by mmdebstrap as a tar and compressed with `gzip -n`, so the same inputs give the same bytes; the
  M2 integration test builds the example core twice and compares. Kernel packages are refused in core.
- **Children** unpack their parent's exact filesystem, enter it in a chroot inside the builder
  container (proc, a minimal `/dev` and the mirror mounted in it), install their packages with the
  image's own apt from the same local mirror, run their modules and hooks, and clean up identity
  again. A child never upgrades a package its parent installed: the plan refuses such a resolution,
  because it means the parent must be rebuilt first.
- **An OCI child's filesystem is its parent's layers, applied in order** with whiteouts honoured and
  numeric owners, modes, times and xattrs kept. The image's own apt sources are set aside while the
  build reads the mirror, a `policy-rc.d` refuses service starts and `start-stop-daemon` does
  nothing, as under mmdebstrap; afterwards apt's lists, caches and logs are emptied, ldconfig's cache
  and the build's own apt options removed, the image's sources put back, and then every machine
  identity removed exactly as for core. The image then adds one layer holding every path that
  differs from what was unpacked (type, mode, owner, time, content, link target, device, xattrs) and
  a whiteout for every path that is gone (one for a removed directory); a directory whose own state
  did not change is left out, and hard links inside the layer stay hard links. The layer is a PAX tar
  with numeric owners, no owner names and whole-second times clamped to `SOURCE_DATE_EPOCH`, sorted by
  path with parents first, compressed with gzip level 9 with no name and a zero time stamp. The
  writer is a standard-library Python program run by the builder's own python3. An image that only
  sets `oci` config adds no layer and runs no container; when its parent is core, the base layer is
  core's tarball itself, so an image's first layer digest is the tarball's sha256.
- **The definition's commit is a byte input, not an identity input.** An OCI image's manifest
  carries `org.opencontainers.image.source` and `org.opencontainers.image.revision` (8.1), read at the
  build from the definition's git checkout when it is clean and has a remote (otherwise the
  annotations are left out), so the commit is in the manifest's bytes and in the image's digest. The
  identity holds no commit (7.1): the definition enters it parsed, so a new commit that changes
  nothing the identity reads rebuilds nothing, and `plan` reuses the artifact an earlier commit
  built, whose annotation names that earlier commit. The annotation therefore says which commit
  built the artifact, never which commits could have. It follows that two builds are byte-equal only
  when built from one commit (or with the two annotations set aside), which is how every byte
  comparison here is made: the `byte-equal` check (11) builds twice in one run, and the engine
  revision guard (12) is of core. Core, Incus, installer and OS artifacts hold no commit in their
  bytes; for them it is only in provenance (8.2).
- **Installer and os children build as an OCI child does**, on a filesystem that is one file: a core
  or os parent's tarball, unpacked as a single layer, or an installer parent's `initrd.img`. A kernel
  package's postinst runs in the chroot with proc and the minimal `/dev` mounted, so initramfs-tools
  writes `/boot/initrd.img-<kver>`. Before the identity removal the image's own apt sources
  (`apt_sources`) replace the parent's, where core writes them, so an image pinned to the baseline
  carries it and the build snapshot never appears; the root then ends as a booting root (below) and
  is packed whole, not as a layer. An os image is every path of the root in one tarball, written by
  the layer writer against an empty parent state. An installer is a kit (8.1): its one kernel, the
  whole root as a newc initrd with `/init` linking to `/sbin/init`, and `kit.json`, written by a
  second standard-library program run by the builder's python3, which the package also imports to
  read an initrd back. These artifacts name nothing of their own ancestry, so a child reads its
  parent's ancestors from the parent's provenance.
- **Hooks and modules run with no network.** Everything they may use was fetched and verified
  before the build started and is handed to them as files plus `LOCK_*` environment variables
  (6.5). A hook that tries to download fails.
- **Nothing is booted to build.** An image that needs a running system to produce its content is a
  consumer stage that starts from a factory artifact.
- **Kind defaults are explicit.** Each kind installs a documented package set (for `incus`:
  systemd-sysv, udev, dbus, iproute2, netbase, systemd-resolved, cloud-init and what NoCloud needs)
  and, for kinds that boot, writes `uninitialized` into `/etc/machine-id` so systemd treats the
  first boot as a first boot. That is also when SSH host keys are made: Debian 13's openssh-server
  ships `sshd-keygen.service` (`ConditionFirstBoot=yes`), so the factory adds no unit of its own.
  The plan lists the defaults, so nothing arrives silently.
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
A release publishes that builder image to `ghcr.io/<owner>/debian-image-factory-builder` and signs it
(`release.yml` does both today); `push_layout` takes any single-image OCI layout and assumes none of
the factory's annotations. What is **planned** is that the `.pyz` pins
that image by digest, so a stranger's build uses exactly the builder the release published; the
subsection below is that design, and nothing in it is published yet.

#### The published builder (planned)

- **Where.** `ghcr.io/foreverworks/debian-image-factory-builder`, tagged with the release
  (`vX.Y.Z`, as `release.yml` pushes it now) and always used by digest: the tag only tells a reader
  which release it came from. The package is made public together with the repository (a package's
  visibility is its own setting, not the repository's), so that an anonymous `docker pull` works for
  every consumer and for the Action.
- **How the `.pyz` learns its digest.** The release builds the builder first, pushes it and reads
  the digest the registry gave the manifest (`docker image inspect` on the pushed tag, as the
  signing step does), and only then builds the `.pyz`, which `scripts/build-pyz` is given that
  reference (`--builder ghcr.io/foreverworks/debian-image-factory-builder@sha256:<digest>`). It
  writes it into the archive next to `builder/tools.json`, as `debian_image_factory/builder/image`.
  `release.yml` therefore swaps two steps (the builder before the `.pyz`); its signing steps stay as
  they are. The `.pyz` stays reproducible from the commit and the reference: the reference is an
  input of the build, named in the release notes beside the `.pyz`'s own sha256, and a builder image
  is not itself reproducible bit for bit (its layers carry build times), which is why its digest is
  recorded and signed rather than recomputed.
- **The default.** `--builder-image` defaults to the reference in the archive when it has one;
  a source checkout, a development build or a `.pyz` built without `--builder` has none and keeps
  the local tag `debian-image-factory-builder:<snapshot>` that `scripts/builder build` gives
  (`tools.BUILDER_IMAGE`). A reference with a digest is pulled when the image is not local, and the
  tools check (`open_builder`) runs on it exactly as on a local image: the pinned `tools.json`
  decides whether this release may use it.
- **What the identity holds: the builder's tools, never its digest.** The recipe digest (7.1) has
  the byte-writing packages and their versions, not the image's digest. Publishing the builder
  again, with a changed label or a rebuilt layer, must rebuild nothing, and only a change of the
  tools' versions can change bytes. The digest goes where a reader looks for what built an
  artifact: the provenance's `resolvedDependencies` (8.2), as `oci://<repository>` with the digest
  of the manifest the `.pyz` pinned (a local tag still records the image ID, as today). Both guards
  hold at once: the digest says which image ran, the tools check says that it may.
- **How the Action uses it.** The Action (9.2) reads the `.pyz`, takes the reference from it, pulls
  by digest, verifies the signature (below) before the first build and hands the reference to
  `build --builder-image`. Nothing about the builder is chosen in a workflow file: the factory
  version in the consumer's lock decides the builder, as it decides the `.pyz`.
- **How a consumer verifies it.** The signature is keyless Sigstore, made by the release workflow:

  ```sh
  cosign verify "$REF" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github.com/foreverworks/debian-image-factory/\.github/workflows/release\.yml@refs/tags/v[0-9]'
  ```

  where `$REF` is the digest reference read from the `.pyz` (`unzip -p <pyz>
  debian_image_factory/builder/image`). The certificate identity is the release workflow at a
  release tag, so an image pushed by any other workflow, ref or fork does not verify; the digest in
  an artifact's provenance is then the same reference, for anyone who wants to check what built it.
- **Until the `.pyz` pins it** nothing changes in what a build uses: the default is the local tag,
  built by `scripts/builder build` on the runner (as CI and the integration tier do). `release.yml`
  pushes the builder to the public package and signs it, and puts no reference in the `.pyz`; a
  consumer who wants the published one passes `--builder-image <reference>`. Provenance records the
  image ID. The two `release.yml` steps swapping places with `build-pyz --builder` are one release's
  work.

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
      "signed_by": "example-vendor-keys",
      "url": "https://packages.example.com/debian/pool/main/e/example-tool/example-tool_{version_noepoch}_amd64.deb",
      "used_by": ["installer", "os"],
      "version": "2.4.0-1"
    },
    "example-vendor-keys": {
      "description": "A trust root: the keyring the vendor signs its InRelease with, moved by hand.",
      "module": "vendor-deb",
      "sha256": "<sha256 of the keyring>",
      "url": "https://packages.example.com/debian/example-archive-keyring.pgp",
      "used_by": ["installer", "os"],
      "version": "2026.1"
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
| `apt` | For a vendor `.deb`: its package name. With `registryUrl` (the vendor's repository) and `signed_by` (the keyring it signs with), which a `builtin:deb` entry must have, `plan` and `fetch` read the repository's `InRelease`, verify it with `gpgv` against that keyring alone, check its suite and Valid-Until, read the `Packages` index the signed Release vouches for, and require the index's sha256 for that version to equal the lock's (6.4, section 16). |
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
| `builtin:deb` | a vendor `.deb` from the lock, by apt in the same transaction as the image's packages; its dependencies come from the snapshot. The vendor's repository is never added to the image's apt sources. | lock sha256, equal to the sha256 of the version's stanza in a `Packages` index the repository's `InRelease` vouches for, verified by `plan` and again by `fetch` with gpgv against the pinned keyring (the entry's `signed_by`) |
| `builtin:node-tarball` | a nodejs.org release tarball into a prefix, plus `node`, `npm`, `npx` links | lock sha256, and the tarball's checksum in `SHASUMS256.txt.asc`, verified by `fetch` with gpgv against the pinned release keyring (the entry's `signed_by`) |
| `builtin:file` | any locked download, placed at a path the definition names, optionally unpacked | lock checksums (and a vendor's signed list, when the entry has `signed_by` and `sums_url`) |
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
  that exists keeps its mode, a directory the tarball names takes its member's time (clamped the
  same way), and any other directory the unpack touches has its time put back, so the same inputs
  give the same bytes. When the prefix is not `/usr/local`, `/usr/local/bin/node`, `npm`
  and `npx` are symlinks to `<prefix>/bin/<name>`; for `/usr/local` the tarball's own `bin/` is there
  already.
- *Probe.* `locked-inputs` runs `<prefix>/bin/node --version` in the image and expects `v<version>`;
  the keyring has no probe (11).

**`builtin:deb`** takes no key besides `use` and `enabled_by`; any other is refused by the definition,
naming it. Every entry of the module is an `apt` entry with a `registryUrl` and a `signed_by`, except a
keyring that an entry's `signed_by` names (`plan` and `lock check` name the entry and the field it
lacks), so every vendor `.deb` is signature-checked and the lock is schema 2. A core image cannot use the
module: mmdebstrap builds core, and `plan` names the image.

- *Verification.* For each image that installs switched-on entries, `plan` reads, through its own reader:
  the keyring entry's file, checked against the lock's checksums; the repository's
  `dists/<suite>/InRelease` (or, only when there is none, `Release` with `Release.gpg`), verified with
  input-lock's `gpgv` against that keyring alone; the Release's suite and Valid-Until, checked against the
  current time (input-lock's `release_sums`); the `Packages` index (plain, `.gz` or `.xz`) the signed
  Release lists, by its sha256; and the index's stanza for `apt` at `version`. The stanza's `SHA256` must
  be the lock's sha256, and its `Filename` must end in the file name of the entry's url (input-lock's
  `same_file`). Any link that does not hold fails the plan, naming its URL. `fetch` walks the same chain
  again from the plan alone (the plan's `debs` names each entry's package, version and repository), with
  the keyring from the cache, keeps the signed file and the index in the content cache with a note keyed
  by the `.deb`'s sha256, as for Node's list, and a later fetch verifies the cached copies again. Provenance
  names the `InRelease` and the index as resolved dependencies. `build` walks the chain once more,
  from the cache alone, before it builds the image (section 15, decision 8).
- *Resolution.* The verified stanza is offered to the image that installs it and to no other: its
  resolution runs in an apt root of its own, which also holds a local flat repository with the verified
  stanzas (`[trusted=yes]`, since apt has nothing to check there: every stanza in it was verified as
  above before it was written), and `apt-get --simulate install` asks for `name=version` in the same
  transaction as the image's other packages, so the `.deb`'s dependencies come from the snapshot as apt
  resolves them. The vendor package is in the image's resolved `packages` and its children's; it is not in
  the image's `request`, and `fetch` does not look for it in the snapshot's indices.
- *Install.* The build copies the verified `.deb` files into the root under `/run/factory/debs` and installs
  them with the image's packages in one `apt-get --no-install-recommends install` from the mirror, then
  removes them.
- *Probe.* `locked-inputs` reads the image's dpkg status: the package at its locked version; the keyring is
  a trust root and has no probe (11).

**`builtin:file`** takes, besides `use` and `enabled_by`: `path` (required), an absolute normalised path of
plain parts like node's `prefix`; `mode`, an octal string such as `"0755"` with no setuid, setgid or
sticky bit, `"0644"` by default, only for a file placed as it is; `unpack`, `false` by default; and
`strip_components`, a whole number, 0 by default, only with `unpack`. Any other key is refused, naming it.
Among the module's lock entries an image uses there is exactly one to place (a keyring an entry's
`signed_by` names is a trust root, not placed), and an unpacked one's url ends in `.tar`, `.tar.gz` or
`.tar.xz` (`plan` and `lock check` name an image with none or several).

- *Install.* The builder's `python3` runs a self-contained script the build copies into its work
  directory, `file_install.py "$root" <file> <path> <source_date_epoch>` with `--mode <mode>` or
  `--unpack <strip_components>`. A placed file is copied to `path` with its mode, owned by root, its time
  `source_date_epoch`. An unpacked tarball goes into the directory `path` with the leading parts of every
  member name stripped, under node_install's rules: absolute names, `..`, devices and fifos, and a link
  whose target is not inside `path` are refused; a symlink already in the image is never followed;
  everything is owned by root:root with the member's permission bits minus setuid, setgid and sticky, and
  every time the older of the member's and `source_date_epoch`. Missing parent directories are created
  0755, and an existing directory keeps its mode and gets its time back.
- *Probe.* `locked-inputs` runs `sha256sum <path>` for a placed file and expects the lock's sha256 and
  the path; an unpacked tarball, whose members the lock does not list, is probed with `test -d <path>`,
  which must succeed and print nothing.

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
- **The definition's commit is not an input.** A commit of the repository that holds the definition
  changes the identity only through what the definition says and the files it references (the
  `files` and `image` fields above). The commit itself is written into an OCI manifest's annotations
  (5.3), so it is a byte input and never an identity input.
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
   packages). A child's request is its packages, its kind defaults and its modules' run-time
   packages (`node-tarball` adds `libatomic1`, which nodejs.org's `node` links; `file` adds none;
   `deb` takes its dependencies from the .deb), against a
   status holding its parent's set. An image that installs a vendor `.deb` is resolved in an apt root of
   its own that also holds the `.deb`'s verified stanza, asking for `name=version` in the same transaction
   (6.4); the stanza stays available to its children's status files. An `Inst`
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
    "incus-base": {"identity": "<incus-base identity>", "state": "wait", "artifact": "sha256:<incus-base fingerprint>",
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
rendered `sums_url` and `sums_sig_url`, which `fetch` verifies and which enter no identity), `debs` (for each vendor
`.deb` it installs: the package, its version and the repository, for `fetch` and the build, 6.4), `params` (the ones it reads), `apt_sources` and `checks` (the required
ones). An image's `artifact`, when it has one (`reuse` or `wait`), is always `sha256:<hex>`, the form of every
digest the factory writes: a tarball's sha256, an OCI image's manifest digest, an Incus image's fingerprint. Every
reader takes that form and no other. `because` says why an image builds: no artifact with this identity, a failed required check,
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
  which is the file order that breaks a tie between results of one time, whatever order the registry
  lists them in.
- **File targets** (`github-release://`, `dir://`): artifact files are named
  `<image>-<suite>-<arch>-<first 16 hex of the identity>-<first 12 hex of the digest>.<ext>`. A
  listing filtered by the image and identity prefix answers; the provenance in the
  `<digest>.intoto.jsonl` beside it must name the full identity before the artifact counts. On a
  release, an asset is uploaded under `<name>.partial-<16 hex>`, which no lookup reads as an artifact
  or as records, and renamed to its final name only when whole (9.1); a lookup lists one it finds
  under `rejected`.

Each image then gets one of three states:

| State | When | What happens |
|---|---|---|
| `reuse` | an artifact with this identity exists and is good | nothing is built; the plan names the artifact |
| `wait` | an artifact with this identity exists and is still a candidate (a required check has no result yet) | nothing is built for it, and its children wait too |
| `build` | no artifact with this identity exists, or the only ones that exist have a failed required check | it is built, and so is every image below it |

A child whose parent waits waits too, unless the child itself is reusable. Several results for one
check count by time, the last one wins: the result whose run finished last (8.2), file order breaking a
tie, and a result without a time (one from before runs were recorded) is older than any with one; when
several artifacts qualify, the newest
`finishedOn` wins, ties by the smallest digest.

The order of results is only as trustworthy as the records that claim it. Records are unsigned by
default (8.2), so anyone who can write to a target can stamp a result with a late time and make it the
last. Two limits keep that small: a result stamped later than the time the reader runs, plus five
minutes for clocks that differ, does not count at all, and the lookup lists it under `rejected` with the
reason "finished in the future" (the artifact itself still counts, by its other results); and signed
records (`--sign`, 8.3; only `none` works today) will be the way to make the order trustworthy against a
writer, since a signature names who wrote a result. A result stamped in the past by someone who can
write records is not detectable and counts. Until then the target's own authentication is the trust
boundary. The provenance names the image in
`externalParameters.image` and the identity in `internalParameters.identity` (8.2), and a records
file counts only when a statement's subject is the file's real sha256. `dir://`, `oci://` and
`github-release://` lookups are live.

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
| A new commit of the definition's repository that changes nothing the identity reads | nothing: the artifact an earlier commit built is reused, and its `org.opencontainers.image.revision` names that commit (5.3) |
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
- **Only what builds.** `fetch` reads for the images whose state in the plan is `build`, and for nothing
  else: a `reuse` or `wait` image needs no index, package or input, and a plan where nothing builds fetches
  nothing and says so. A child's parent is an artifact, never an input (found in `out/` or through
  `--parents`, 9.1), so a child that builds needs from the mirror only the packages it adds to its parent's
  set (its resolved set minus the parent's, vendor `.deb` files left out: they are inputs), plus the signed
  indices apt reads, and from the cache its own locked inputs.
- **Inputs bundle.** With `--bundle`, fetch also writes one bundle per image that builds, into `--bundle-dir`
  (default `bundles/` beside the plan), named `<image>-<suite>-<arch>-<first 16 hex of identity>.inputs.tar`.
  It is named by what determines its content, not by the artifact digest: the digest of the artifact exists
  only after the build, and `fetch` runs before it. One identity is one set of inputs, as in an artifact's
  name (7.4). A bundle is a plain tar of `manifest.json` (first), `plan.json` (the plan fetched from, byte
  for byte) and the image's slice of the cache under `cache/`: the signed `InRelease` and the indices of
  every suite, the pool files the image adds, its locked inputs (keyrings, vendor `.deb` files, tarballs) by
  sha256, and the signed checksum lists, signatures and indices that vouched for them with their notes (what
  provenance names, 8.2). The manifest holds the schema, the image, its identity, the snapshot, the suite and
  the architecture, and every other member with its size and sha256; for an image that installs a vendor
  `.deb` it also holds `verified_at`, the time `fetch` verified the vendors' signed Release (the earliest of
  them, kept in each input's note beside the signed files). Members are sorted and every header has the same
  time (0), owner (uid and gid 0, no names) and mode (0644), so two fetches of one plan write byte-identical
  bundles; the one input that could differ is that time, which `fetch` keeps from the first verification in a
  cache, so a vendor image's bundle is identical across fetches into one cache and differs only in
  `verified_at` (and the note) across fresh ones. Bundles are off by default (16.4).
- **Replay.** `build --offline --bundle <file>` rebuilds the bundle's image from it with snapshot.debian.org
  unreachable. A replay is the normal build path reading a different directory, not a separate mode: the
  bundle is unpacked into a scratch cache under `out/` (every member checked against the manifest's size and
  sha256, a member the manifest does not list or a link refused), the manifest is checked against the plan it
  carries (the image's identity, the snapshot, the suite) and the cache against what the build reads (every
  suite's `InRelease`, every locked input of the image), and the ordinary build then runs with that cache. A
  vendor repository's Release expires (`Valid-Until`), and a replay is for later: the build's re-verification
  of the signed lists (15.8) judges that Release at the manifest's `verified_at`, not at the present,
  and never at a time later than the replay's own: a manifest whose `verified_at` is in the future is
  judged at the present, and one without a time zone offset is refused. Signatures, keyrings and hashes
  are checked in full all the same; only the clock is the fetch's. The manifest of a bundle is unsigned,
  so the freshness check of a replay rests on the bundle's integrity, as does the manifest's every other
  field: someone who can rewrite a bundle can backdate `verified_at` (up to now) and replay a vendor
  Release that has expired since. That is accepted (15.8): the `.deb` the replay installs is pinned by
  its sha256 in the lock and every signature is still verified, so the clock is the only thing that can
  be bent, and it cannot be bent forward. Unpacking writes a member only up to the size the manifest
  lists and fails as soon as a member goes past it, so a bundle cannot fill a disk with a member that
  claims more than it lists.  The
  plan comes from the bundle; a plan given beside it must be the same bytes. `--offline` also makes any
  network access of the factory process itself a hard error: no download, no registry pull (`--parents
  oci://` is refused, a parent is given as `dir://`), so nothing can fall back to a mirror. A bundle holds one
  image: its parent is built first or found as in any build.

## 8. Artifacts and records

### 8.1 Artifacts

| Kind | Files | Digest that names it | Default compression |
|---|---|---|---|
| core | `core-trixie-amd64-<identity16>-<digest12>.tar.gz` | sha256 of the file | gzip |
| oci | `oci-base-trixie-amd64-<identity16>-<digest12>.oci/`, an OCI image layout directory, pushed to a registry | image manifest digest | layers `application/vnd.oci.image.layer.v1.tar+gzip` |
| incus | `<name>.incus.tar.gz` (metadata.yaml, templates) and `<name>.rootfs.squashfs` | Incus fingerprint: sha256 of the metadata file followed by the rootfs file | gzip tarball, squashfs with its gzip compressor |
| installer | `installer-trixie-amd64-<identity16>-<digest12>.tar`, a kit: exactly `kit.json`, `vmlinuz`, `initrd.img`, in that order, mode 0644, owned by 0:0 with no names, time stamped `source_date_epoch` | sha256 of the kit tarball; `vmlinuz` and `initrd.img` follow it as subjects, by sha256 | initrd gzip -9 -n, kit tarball uncompressed |
| os | `os-trixie-amd64-<identity16>-<digest12>.tar.gz`, the whole root filesystem as a PAX tar sorted by path, parents first, numeric owners and no names, times clamped to `source_date_epoch` | sha256 of the file | gzip -9 -n |

A kit's `vmlinuz` is the image's one kernel, `/boot/vmlinuz-<kver>` (a root with none or several fails
the build, naming them). Its `initrd.img` is the whole root, `/boot` included, as a newc cpio: sorted
by path with parents first, numeric owners, times clamped, inode numbers assigned in order, hard links
kept as newc hard links, device nodes and symbolic links kept, no xattrs, and `/init` a link to
`/sbin/init`. `kit.json` is canonical JSON and a newline:
`{"files":{"initrd.img":{"sha256":"..","size":N},"vmlinuz":{..}},"image":"<image>","kernel":"<kver>","schema":1}`.

Compression is gzip, or the format the target ecosystem reads by default, for everything published.
zstd per image (`compression = "zstd"`), for consumers who control every reader, is planned; until a
release builds it, the definition check refuses it rather than build gzip in its place. The
OS image's own initramfs keeps whatever its Debian packages configure, since the installed system
regenerates it.

*Why zstd waits (decided in M6).* The OS root tarball is the first candidate, and building it is the small
part: `zstd -19 -T1 --no-check` of the uncompressed tar from the builder gives the same bytes for the same
tar, because the output depends on the zstd version (pinned by the builder's package list) and the level and
thread count (fixed). The rest is every reader, and none of it is free:

- the builder gains the `zstd` package, so `tools.json` and the builder identity move, and with them every
  recipe digest and every image's identity: that is one planned flag day, to be taken with a release that
  needs it, not alongside other work;
- Debian 13's python3 is 3.13, whose standard library has no zstd (`compression.zstd` arrives in 3.14, and
  the floor is 3.13), so every Python reader of an OS tarball shells out to `zstd -dc`: the builder's
  `layer.py unpack` of an OS parent, `checks/tarball.py`'s scan on the host that runs `test`, and
  the boot check's `tar -xpzf` in the VM image (which then needs `zstd` and `tar --zstd`). Consumers' own
  tools carry the same dependency, which is the point of making it opt-in;
- a `.tar.zst` is a new file extension: `parents.py` finds parents by extension, `checks` tells kinds by it,
  and `fetch`, `publish`, `verify` and the Action name artifacts by it, so each needs one more case and its
  tests;
- the squashfs reader already reads zstd, so an Incus rootfs is the cheap second case (`mksquashfs -comp
  zstd` with a fixed block size), but its fingerprint then covers a different file and the Incus images'
  `incus-boot` needs a host whose Incus reads it.

Until a consumer asks for zstd on one image, this cost buys nothing the gzip artifacts do not already give
(DESIGN 15.11: only shapes with a consumer). When one does, the order is: builder and VM image packages, the
shell-out reader, the extension, the OS build, then its byte-equal test beside the gzip one.

An OCI image carries standard annotations: `org.opencontainers.image.base.digest` and
`org.opencontainers.image.base.name` (its parent), `org.opencontainers.image.source` and
`org.opencontainers.image.revision` (the definition's repository and commit, when its checkout is
clean and has a remote), and `io.github.foreverworks.debian-image-factory.identity` (its input
identity). The image config carries no build time. The commit is a byte input but not an identity
input (5.3): an image reused for a later commit keeps the annotation of the commit that built it.

An OCI image is its parent's layers and, when it changes the filesystem, exactly one added layer. A
core parent's base layer is core's tarball byte for byte: its digest is the tarball's sha256 and its
diff_id the sha256 of the decompressed tar. `build` writes the layout into a temporary name in the
output directory and renames it into place after its records (`<manifest digest>.intoto.jsonl`)
are written.

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
ancestry and every input are provable from the record alone. An OCI image further down the tree
also adds `{"name": "ancestor: <image>", "digest": {"sha256": "..."}}` for every further ancestor up
to core, nearest first, read from each parent's manifest annotations, so a Node image's provenance
names core's tarball digest as well as its parent's.

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
                       "uri": "https://github.com/foreverworks/debian-image-factory/blob/v0.1.0/docs/checks.md#no-machine-identity"},
                      {"name": "run",
                       "annotations": {"runId": "3f0c9d2a41b84e6f9a7d5c1e8b2a6d40",
                                       "startedOn": "2026-11-21T02:19:41.120004Z",
                                       "finishedOn": "2026-11-21T02:19:42.350871Z"}}],
    "url": "https://github.com/example/images/actions/runs/<run id>",
    "passedTests": ["machine-id-empty-or-uninitialized", "no-ssh-host-keys", "no-private-keys", "no-random-seed"],
    "warnedTests": [],
    "failedTests": []
  }
}
```

The first `configuration` entry's `name` is the check's ID; "good build" is computed from it.

**Each result is one run's.** The in-toto test-result predicate (v0.1) has no field for a time or an
identity of a run, and input-lock's builder takes `result`, `configuration`, `url` and the three test
lists only. The spec's `configuration` is an array of ResourceDescriptors, and a ResourceDescriptor may
carry `annotations`, so the run goes there, as a second entry named `run`: `runId` (32 random hex
characters, one per invocation of `test` or `attest`), `startedOn` and `finishedOn` (RFC 3339 UTC with
microseconds; `startedOn` is when the checks of that artifact began, `finishedOn` when they ended).
Two runs of one check therefore never write the same line, which `publish` relies on: it adds a record
unless a byte-identical one is already there (a records file line, or an OCI referrer with the same
envelope digest) and keeps every distinct run. Readers go by the `finishedOn` of the `run` entry: for
each check, the result whose run finished last is its last result (7.4); a result without a `run` entry
(from before runs were recorded) is older than any with one, and a tie goes to the line that comes
later in the file (on OCI, the later attach time). A `run` entry whose annotations lack a text `runId`
or an RFC 3339 `finishedOn` makes the record malformed. `verify --require-checks` reads the same way. A
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
lists them in, so file order, which breaks a tie between results of one time (8.2, test result),
means the same on every registry; a referrer without the annotation reads first. The order of results
by `finishedOn` is a claim in an unsigned record (8.3): a result whose `finishedOn` is later than the time
the reader runs plus five minutes does not count, and is reported as rejected with the reason "finished
in the future" (7.4). Records never hold secrets, private keys, tokens or machine identities. They describe bits;
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
debian-image-factory fetch plan.json [--mirror URL] [--bundle [--bundle-dir DIR]]
debian-image-factory build [plan.json] --out out/ [--image NAME]... [--parents TARGET]... [--builder-image REF]
                           [--offline] [--bundle FILE] [--builder container|host]
debian-image-factory test out/ [--check NAME]... [--url URL] [--definition FILE] [--parent FILE]...
                           [--parents TARGET]... [--twin DIR]...
debian-image-factory attest test-result --artifact DIGEST --check NAME --result PASSED|WARNED|FAILED ...
debian-image-factory publish out/ --to TARGET... [--image NAME]... [--sign none|keyless|key:REF]
debian-image-factory verify REF [--pull [--artifact NAME|SHA256]] [--require-checks] [--lock FILE] [--definition FILE]
                                                         records match the bits, provenance names the lock, checks complete
debian-image-factory prune --against TARGET... --pin DIGEST... [--keep-good 5] [--keep-candidates 1] [--dry-run]
                           [--definition FILE]
```

A TARGET of `plan --against`, `build --parents`, `test --parents`, `prune --against` and `publish --to` may carry
`{image}` in the repository of an `oci://` target, with one meaning in all five (below).

`lock`, `plan` and `fetch` read snapshots from snapshot.debian.org, or through `--mirror URL`, any
server that serves its paths (`/archive/...` and `/mr/timestamp/`); `--keyring` and `--cache` say
where the archive keyring and the download cache are. M1 shipped `lock check`, `lock snapshot`,
`lock baseline` and `plan`; M2 adds `fetch`, `build` for core, `test` with the core checks and
`publish` to `dir://` targets; M3 adds `build` for the OCI kind with `--parents`, `plan --against
oci://`, the OCI checks and `locked-inputs` (`test --definition` gives it the module tables),
`publish` to `oci://` targets and `verify`; M4 adds `build` for the Incus kind (built on core or
on an Incus parent from `dir://`), its checks (`incus-boot` and `two-clones` run where an Incus host
answers, `scripts/incus-vm` gives one in a VM), and `publish` and `plan --against` for
`github-release://` targets (the API is `GITHUB_API_URL`, the token `GITHUB_TOKEN` or else `GH_TOKEN`).
M5 adds `build` for the installer and OS kinds,
their boot checks (`test --vm-image` names the image QEMU runs in, `scripts/builder vm` builds it;
`test --parent` names a parent artifact outside `out/` for `ancestry`), the `deb` and `file` modules
and `lock checksums`: input-lock's `refresh` on a lock the definition agrees with, for the entries
`--entry` names or those whose version moved since the git ref `--base`. It writes nothing unless every
entry verified (a `deb` entry through its vendor's signed `InRelease`), and checks the result against
the definition again. M6 adds `prune`, `fetch --bundle` and `build --offline --bundle`, with the rest of the
nightly loop.

`build` reads the plan, and also the lock and the definition (`--lock`, `--definition`, as `plan`
does): hooks and file trees live beside the definition, and provenance names the lock. Before it
builds an image it recomputes the identity from them with the plan's package set and refuses a
plan they no longer match, so records always describe what was built, and it verifies again, from the
cache alone, every signed checksum list or vendor chain the image's inputs rely on (15.8). `--builder-image REF` names
the builder; the default is the tag `scripts/builder build` gives. (Planned: a `.pyz` carries the digest reference of the builder its release published, signed, and that
is its default; 5.4.) A child whose parent this run does not build reads it from `out/` (by
artifact name: the identity prefix and the digest the plan names), then from each `--parents TARGET`
(`dir://` holding the core tarball or an `.oci` layout, or `oci://`, pulled by digest); a parent found
nowhere fails the build naming the image, the digest and the places looked in. Images of kinds a release cannot build yet are listed as not built. `--builder host` arrives later;
every build already runs with no network in the builder.

`fetch` reads only for the images the plan says to build (7.7); with `--bundle` it also writes one inputs
bundle for each, into `--bundle-dir` (default `bundles/` beside the plan). `build --offline` makes any use of
the network by the factory process itself a hard error. `build --bundle FILE` replays the bundle's image from
it alone (7.7) and implies `--offline`; the plan argument is then optional, since the bundle carries the plan,
and a plan given with it must be that plan. `--image` may name only the bundle's image, and `--parents oci://`
is refused offline (give the parent as `dir://`, or build it in the same run).

Targets are `oci://<registry>/<repository>`, `github-release://<owner>/<repo>@<tag>` and
`dir://<path>`. `plan --against` looks identities up live in those targets (7.4); nothing about
the published state is stored in the consumer's repository.

In the repository of an `oci://` target, `{image}` stands for the name of an image, and means the same in every
command that takes a target: the target, resolved with the name of the image being looked up, so one string
(`oci://ghcr.io/example/{image}`: image `debian` is `ghcr.io/example/debian`, `node-26` is `ghcr.io/example/node-26`)
serves the whole nightly. `plan --against` looks image X's identity up in the target resolved for X;
`build --parents` and `test --parents` pull or read a parent image P from the target resolved for P, the parent's
own name that the plan holds; `prune --against` runs each image's retention on the target resolved for that image
(an image of the definition, judged on its own artifacts there; the other images a repository might hold are not
looked at); `publish --to` sends each image to the target resolved for it. `{image}` anywhere but in the repository
of an `oci://` target (a `dir://` path, a release, the registry host) is refused with exit 2, and so is an image
whose name makes no valid repository. One resolver (`published.resolve_template`) serves all five commands.
`test` finds an image's parent in `out/`. A parent that is not there (a night on which only Node moved: Node
builds, its Debian-built parent is reused from the registry) is known by the digest the plan names for it. For a
core parent that digest is all `ancestry` needs. For an OCI parent `ancestry` also needs its layers, which
`test --parents oci://<registry>/<repository>` reads: the parent's manifest, nothing else, from the first of
the registries that holds it (for a target with `{image}`, the repository named for the parent). Without
`--parents`, or when no registry has the parent, `ancestry` is not run and says why, and a child whose required
checks lack a result stays a candidate; with it, the child passes. `--parents` takes registries only: for an OS
root or an installer kit `--parent FILE` gives the parent's file.

`publish` writes `dir://` targets (files only: an OCI image layout is refused there) and `oci://`
targets (OCI images only: a core tarball is refused there; when `out/` holds both, each target
takes its kind and the command names what it left). `--image NAME` (repeatable) publishes only the images it
names, the files and the layouts of each, and a NAME the build does not hold is refused (exit 2) before anything is
written; without it every image of `out/` goes, as before. In the repository of an `oci://` target `{image}` is
replaced by the name of each image, so one `publish` sends `debian` to `oci://ghcr.io/example/debian` and
`node-26` to `oci://ghcr.io/example/node-26` with `--to oci://ghcr.io/example/{image}`; `--image` and several
`--to` combine, each image going to every target. `{image}` belongs to `oci://` targets, and an image whose name
makes no valid repository is refused. An OCI image is pushed with its tag
`identity-<identity>`, its records are attached as referrers (8.2), and publishing again pushes and
attaches only what the registry lacks. Credentials come from the Docker config (`$DOCKER_CONFIG`
or `~/.docker`: `auths`, `credHelpers`, `credsStore`); registries on `localhost`, `127.0.0.1` and
`[::1]` are spoken to over http, all others over https.

A `github-release://` target takes the files, as a `dir://` target does, with the release's assets as
its files. GitHub keeps an asset under the name it was uploaded with from the first byte, so an upload
that is cut off would leave half a file under its final name, where a later plan could read it. Each
asset is therefore uploaded as `<name>.partial-<16 random hex>`, checked (the size the API reports
against the file's, and its `digest` against the file's sha256 where the API states one; a mismatch
deletes the asset and fails the publish), and only then renamed to `<name>` with a `PATCH` of the
asset's `name`. A name that was taken in the meantime fails the rename and nothing is overwritten.
The records asset `<digest>.intoto.jsonl` goes last, after its artifact is in place, by the same two
steps. A `.partial-` asset a crashed run left behind is deleted at the start of the next publish to the
release (publishers to one release must not run at the same moment, as for the records merge), and
every lookup lists it as rejected.

`verify REF` takes `oci://<registry>/<repository>@sha256:<hex>`, `oci://<registry>/<repository>:<tag>`,
a local `.oci` layout directory, or an artifact file with its `<digest>.intoto.jsonl` beside it,
and names every problem it finds (exit 1) or prints a short summary (exit 0). `--pull` makes it
download what the reference names, and `--artifact` says which artifact of a file target:

- `verify oci://... --pull` downloads the image (its config and every layer, each streamed through
  sha256 and held to its descriptor's size) into a scratch layout and reads that back in full, so a
  layer a registry lost or corrupted is named. Without `--pull` the layers are only looked for
  (every manifest, config and record blob is read and checked either way);
- `verify github-release://<owner>/<repo>@<tag> --pull --artifact NAME|SHA256` and
  `verify dir://<path> --pull --artifact NAME|SHA256` download the artifact (an Incus image: both
  its files) and its `<digest>.intoto.jsonl` to a scratch directory, then run the ordinary file
  verify there, so the checks below apply unchanged and the bytes checked are the bytes
  downloaded. `--artifact` is the file name the target holds (an Incus rootfs names its image), or
  the digest in full hex (`sha256:` optional), found through the 12 hex every artifact name carries;
  the digest the bytes have must then be the one asked for. A file target needs `--pull` and
  `--artifact`, and `--artifact` goes only with a file target (a usage error, exit 2, otherwise);
  `--pull` on a local layout or file has nothing to pull and is a usage error too. A release needs
  `GITHUB_TOKEN` (or `GH_TOKEN`) only when it is private; the scratch directory is removed on exit.

What it checks:

- the bits match their digest: an image's manifest digest (a registry's blobs are checked as they
  are read, a layout on disk in full, layers included; from a registry the layers are checked when
  pulled, which `--pull` does), a file's sha256;
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

`prune` reads what each `--against` target holds (every artifact that counts, whatever its image and
identity: 7.4's checks, with the image and identity taken from the provenance), asks the definition
(`--definition`, default `factory.toml`) which checks make each image's builds good, and applies the
retention rule (11) to each target on its own. It prints one line per artifact, `<target>: <name> kept,
<reason>` or `deleted, <reason>` (`would be deleted` with `--dry-run`, which deletes nothing and sends no
delete request), then one `ignored` line for each file that looks like an artifact but does not count
(no records, a digest that does not match its name, an unfinished upload): those are never deleted. A
`--pin` is a full sha256 digest (`sha256:` optional): an artifact's file digest, an Incus image's
fingerprint, an image's manifest digest. It keeps that artifact in every target and does not count
against the two limits; a pin that matches nothing is noted. A build of an image the definition does
not name is kept, since nothing says which checks make it good. What a delete removes:

- `dir://`: the artifact file (an Incus image's two, the rootfs first and then the metadata, the file a
  listing finds the image by) and its `<digest>.intoto.jsonl`. A delete that fails therefore never leaves
  a rootfs nothing lists: when the rootfs delete failed, both files stay and a later prune retries; when
  only the metadata delete failed, the listing names it as ignored (no rootfs beside it) for the person
  to remove.
- `github-release://`: the same files, in the same order, as assets.
- `oci://`: the image's manifest by digest, the records attached to it (referrers, or the index of the
  `sha256-<digest>` tag under the tag schema), and the `identity-<identity>` tag unless a lookup shows
  it names another manifest (a registry that kept the tag of a deleted manifest answers 404 for it, and
  the tag is deleted too: no later prune would list it). Only manifests an `identity-` tag names are listed: older manifests a moved tag left behind
  and the consumer's own tags are not seen, and a consumer's tag that names a deleted manifest is
  dropped with it by the registry, so such an image is protected by `--pin`, not by its tag. Layers and
  blobs are the registry's to collect. A registry must allow `DELETE` on manifests: zot and the official
  distribution image's default configuration do; a distribution registry with `storage.delete.enabled`
  false (`REGISTRY_STORAGE_DELETE_ENABLED=false`) answers 405, and prune reports each artifact.

An artifact goes before its records, and an image before the records attached to it, so a failure in
between leaves records without an artifact (harmless) and never an artifact without records (which no
lookup accepts). Records a kept artifact of the same digest shares stay. A delete that fails, a registry
that refuses `DELETE` included, is reported for that artifact on standard error, the others go on, and
the exit status is 1; it is never silent.

### 9.2 The GitHub Action

A composite action at the repository root, `foreverworks/debian-image-factory@<commit>` (`action.yml`).
It reads the factory version from the consumer's lock, downloads that release's `.pyz`, checks its
sha256 against the lock, and runs the requested steps with it. The Action's own ref changes only when
its bootstrap logic does; the factory version has one home, the lock.

The lock entry is the reserved `debian-image-factory` one (6.1), which `lock checksums --entry
debian-image-factory` fills once the release exists. The Action reads three of its fields and renders
`{version}` in the url:

```json
"debian-image-factory": {
  "datasource": "github-releases",
  "depName": "foreverworks/debian-image-factory",
  "extractVersion": "^v(?<version>.+)$",
  "sha256": "<sha256 of the .pyz>",
  "url": "https://github.com/foreverworks/debian-image-factory/releases/download/v{version}/debian-image-factory-{version}.pyz",
  "version": "0.6.2"
}
```

It refuses the placeholder checksum of an unreleased lock, a url that is not https, a download whose
sha256 is not the lock's, and a `.pyz` that does not report the lock's version. `scripts/action-support`
(standard library only) reads the entry and the plan, so the Action holds no logic the factory does not:
`changed` is the factory's own `plan.changed`.

```yaml
name: images
on:
  schedule: [{cron: "17 2 * * *"}]
  push: {branches: [main], paths: ["images/**"]}
jobs:
  images:
    runs-on: ubuntu-latest
    permissions: {contents: write, packages: write, id-token: write}
    concurrency: {group: "images-${{ github.ref }}", cancel-in-progress: false}
    steps:
      - uses: actions/checkout@<commit> # v7.0.1
      - uses: docker/login-action@8aa5831fb8d48d8f76594c7ddde61ae58019f550 # v4.8.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ github.token }}
      - id: factory
        uses: foreverworks/debian-image-factory@<commit> # v0.6.2
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

Inputs, every one passed to a script through `env:` (a `${{ }}` inside a `run:` script fails the static
tier):

| Input | Default | Meaning |
|---|---|---|
| `definition` | `factory.toml` | the build definition |
| `lock` | `lock.json` | the lock, whose `debian-image-factory` entry names the release |
| `params` | none | a JSON file of parameter values, `plan --params` |
| `snapshot` | `lock` | `plan --snapshot`: `lock`, `latest` or an ID |
| `against` | none | targets, one per line: `plan --against` each, and where `publish` writes; `build` gets each `oci://` and `dir://` one as `--parents` and `test` each `oci://` one, so a parent that was reused is found where it is published (a `github-release://` target holds no parents) |
| `steps` | `plan,fetch,build,test` | the steps to run; `plan` is required and `build` needs `fetch`, `test` needs `build` |
| `publish` | `false` | `true` publishes what was built to the `against` targets (needs `build`) |
| `sign` | `none` | `publish --sign` |
| `mirror` | none | `--mirror`, a server that serves snapshot.debian.org's paths |
| `pyz` | none | a local `.pyz` to run instead of the lock's release, unchecked: for testing the factory itself |
| `token` | `${{ github.token }}` | the GitHub token `plan` and `publish` get as `GITHUB_TOKEN` (through `env:`, never on a command line), for `github-release://` targets; no other step sees it |
| `keep-work` | `true` | the work directory (`plan.json`, the build output, the logs) stays after the run, so the `plan` output names a file later steps can read, and the runner empties `runner.temp` before each job; `false` makes the last step remove it, whether the run passed or failed |

Outputs: `changed` (`true` when the plan builds at least one image), `plan` (the path of `plan.json`)
and `artifacts` (JSON: image to digest, of what the plan reuses or waits for and what the run built).

**Credentials and permissions.** The Action logs in nowhere. A GitHub Actions step does not get the
workflow's token in its environment, and the factory reads `GITHUB_TOKEN` (else `GH_TOKEN`) for a
`github-release://` target, so the Action's `token` input, which defaults to `${{ github.token }}`,
hands it to the `plan` and `publish` steps and to none other. For an `oci://` target the factory reads
the Docker config (9.1), so the workflow logs in before the Action with `docker/login-action`, pinned by
commit with its version as a comment, as the example shows; on ghcr.io the workflow's token with
`packages: write` is enough. Publishing to a release needs `contents: write`; a job that only plans
needs read access (`contents: read`, and `packages: read` for a ghcr.io package). Without them `plan`
or `publish` fails with the registry's or GitHub's refusal, named in the error. The `build` and `test` steps read a
reused parent from a registry with the same Docker config, and need no token.

**One run per image and target at a time.** Two runs that publish the same image to the same target
race: both see `build`, both push, and on a registry without the referrers API both rewrite the tag
schema index, so one run's records can be lost. Give every job that publishes a concurrency group
that is never cancelled: one group for the whole definition, as above, or, when a consumer splits its
images over several jobs, one per image and target (`images-<image>-<target>`), so a slow OS build
never holds back an OCI one. A queued run plans again when it starts and reuses what the run before
it published. The nightly workflow in this repository does the same with one group.

**A quiet night costs a few index downloads.** After `plan`, when no image builds, `changed` is `false`
and fetch, build, test and publish do not run: no builder image is built, no package downloaded.

**Python and the runner.** The factory needs python3 3.13 or newer; when the runner has none the
Action installs one with `astral-sh/setup-uv` (setup-python has no Debian builds). Planning needs
apt, gpgv and Debian's archive keyring, which the Action installs with `sudo apt-get` when they are
missing; building needs Docker. Every action it uses is pinned by commit, with its version as a comment.

**The builder.** The steps run in the builder container (5.4). Today a release's `.pyz` carries no
builder reference, so the Action builds the image itself, with `scripts/builder build`, from the recipe at
the Action's own ref (`github.action_path`), at the snapshot of that ref's `lock.json`, and passes it with
`--builder-image`. `build` refuses a builder whose byte-writing tools are not the ones the release pins
(5.4), so an Action ref that does not match the release fails naming the tools that differ, and never
writes bytes under a wrong identity. Until the `.pyz` names the builder, pin the Action at the commit of the
release tag your lock names. Once it does (5.4):
the Action then verifies that image's signature with cosign and runs `build` with its default, pulling it
by digest, and the `scripts/builder` step goes; the Action's ref then stops mattering to the bytes.

**Boot checks.** A built installer or OS image runs `test` with the boot checks' image
(`scripts/builder vm`), which QEMU runs with `/dev/kvm` when it opens and emulated otherwise, slower
with the same result (12). The Incus checks run only where an Incus host answers; elsewhere they are
reported as not run, never as passed, and the image stays a candidate.

### 9.3 Pinning the factory in your own pipeline

1. **Pin.** Add the `debian-image-factory` entry to your lock (the one in 9.2); Renovate's
   github-releases datasource opens the bump and `lock checksums --entry debian-image-factory` fills
   the sha256. Pin the Action by commit, with its version as a comment, and let Renovate bump that
   too; until the builder is published, keep the Action's commit and the lock's release the same
   version (9.2).
2. **Define** your images in `factory.toml`; pass the flags you decide elsewhere with `--params`.
3. **Plan on a schedule** with `--snapshot latest` against where you publish (the Action's `snapshot:
   latest` and `against`). A night with no relevant upload builds nothing and costs a few index
   downloads: `changed` is `false`. This repository's own nightly workflow is the working example
   (12).
4. **Build, test and publish candidates** on whatever runners you use.
5. **Run your own checks** (a boot in your environment, a full install of the OS image onto a test
   VM, your workloads) and attach each result with `attest`.
6. **Approve your way.** Move your pins or tags once every required check is good, and write the new
   build snapshot into the lock in the same change, so the lock never runs ahead of a verified
   build. Move the baseline at point releases, through the gate your persistent systems use.
7. **Prune** with your pins: by default the newest 5 good builds and 1 candidate per image stay in
   each target, failed builds are deleted once their checks end, and a pinned artifact is never
   pruned. Pass every digest you still run or may roll back to as `--pin`. Run with `--dry-run` first,
   always after you change `[checks]` or the factory's version: a check you add does not demote the
   builds made before it (11), but only the list shows what a run would delete.

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
| `two-clones` | all | two instances of the artifact share no identity: machine IDs and SSH host keys, where present, differ. Core and OCI run as two rootless containers, Incus as two instances, the installer and OS as two VMs (the boots of `installer-boot` and `os-boot`, run at once), each reporting its machine ID and host key digest |
| `sbom-complete` | all | the SBOM lists every installed package and locked input |
| `ancestry` | children | the parent's filesystem is the base: for OCI, the parent's layers are the first layers by digest; elsewhere (Incus, OS root, installer kit), the parent's files are present unless the child's own records say it removed them (its provenance lists them, `removedFromParent`, written by the build from a comparison of the two roots), and the provenance names the parent |
| `same-resolution` | core | a second resolution of the same lock gives the same package set |
| `no-build-snapshot` | all | the build snapshot ID appears nowhere in the artifact's bytes, including the build-time `file://` source, which the `apt_sources` rendering replaces before the image is packed; skipped with a note when the baseline ID equals the build ID. A release test also builds one package set at two different build snapshots and compares the bytes |
| `byte-equal` | all, optional | two builds from the same inputs, in one run (so of one definition commit, which an OCI manifest's annotations carry, 5.3), give the same digest; WARNED, never FAILED, when they differ. The check does not rebuild: it compares the artifact with the same image built again, an output directory given with `test --twin DIR` (the artifacts whose names agree up to the digest). Without a twin it is not run, and an image lists it in its `[checks]` to require one. Proof that a kind is byte-equal is the release tier's integration tests (section 12), which build twice from one plan |
| `oci-run` | oci | runs under rootless Docker: declared user and entrypoint, `cmd` exits 0 |
| `incus-boot` | incus | in an Incus host inside a VM: cloud-init finishes through NoCloud from both `cloud-init.user-data` and `user.user-data`, creates the user, runs commands, an IPv4 address is reported, all still true after a restart |
| `installer-boot` | installer | kit.json matches the kit's files; QEMU boots `vmlinuz` with `initrd.img` from RAM (`console=ttyS0`) to a serial report; the running kernel is kit.json's |
| `os-boot` | os | the test harness lays the root filesystem onto a scratch GPT disk (an ESP with the OS's own `grub-mkstandalone` image, an ext4 root labelled `factory-root` from the tarball), OVMF boots it to multi-user (`degraded` warns), installed and running kernel match, first boot creates a machine ID and, with openssh-server, host keys |

Failed, cancelled or incomplete checks leave the artifact a candidate; the consumer's pins do not
move, and `prune` deletes it once its checks end. For `prune` a build is **good** when every required
check has a passing last result, **failed** when one failed and every required check has a result (its
checks have ended), and a **candidate** otherwise: it includes a build whose failed check left others
without a result, because a checker that stops at its first failure or is cancelled never ends them, and
it leaves through the candidate limit instead of staying forever or being deleted while a check may
still report.

**A check added later does not demote old builds.** Records do not say which checks were required when a
build was made, and judging every build by today's definition would make a new required check turn every
good build into a candidate, and `prune` would then delete all but the newest. So the results tell
which checks came after a build. A required check a build has no result for is not held against it when
(a) the oldest build of the image with a result for that check is newer than the build, or (b) no build
of the image has a result for the check at all and the build is not the image's newest (the newest may
still be being tested); and only for a build with a result for at least one required check, since
a build nothing was run on is not made good by it. A failed result always counts. The rule can only keep
more builds than judging by today's definition, never fewer: a build that was good before the change
stays good for the limits, and the one tested under the new check is held to it. The price is that a
required check that never ran anywhere (an Incus check on a runner without an Incus host) is not held
against builds older than the newest, which then count as good for the limits and stay up to
`keep_good`; the `plan` still waits for such a build, since it uses today's definition to decide reuse
(7.4). Run `prune --dry-run` before the first real `prune` after a change to `[checks]`, and after any
upgrade, to see the list.

The rules, per image and per target: a pinned digest is never deleted and takes no place in
the limits; the newest `keep_good` good builds stay; the newest `keep_candidates` candidates stay;
failed builds are deleted. The two counts are separate, so a run of failed nights never pushes out a good
build, and an image keeps at most `keep_good + keep_candidates` builds plus its pins. "Newest" is 7.4's
order (the latest `finishedOn`, none older than any, a tie to the smallest digest).

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
- `shellcheck` on the example hooks and the Action's shell steps: `scripts/action-support shell` writes
  each `run:` step of `action.yml` and the nightly workflow to a file, and fails a step that puts a
  `${{ }}` expression into its script (inputs reach a script through `env:`).
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
- Fetch and bundles: only the images that build are read for, a child only for what it adds to its parent,
  and a plan where nothing builds reads nothing; a bundle is byte-identical across fetches (a name too long
  for a plain tar header included); unpacking refuses a changed byte, an unlisted member, a missing one, a
  link, a manifest that is not first or names a path outside the bundle, and a manifest or plan that
  disagrees with the other; `--offline` refuses every URL and an `oci://` parent.
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
- Retention (`retention`, pure): the newest `keep_good` good builds and `keep_candidates` candidates
  stay and the rest go, by finish time with the smallest digest breaking a tie and listing order
  irrelevant; a failed build whose checks have ended is deleted, one whose other checks have no result
  is a candidate; a run of failed nights never pushes out a good build; pins are never pruned, whatever
  their standing, and take no place in the limits; at most `keep_good + keep_candidates` per image plus
  pins; an image the definition does not name is kept; `locked-inputs` is required only of a build whose
  provenance lists locked inputs; five good builds and a required check added to the definition are
  all kept, and a build newer than the first result of a check is held to it.
- Prune, against `dir://` on a temporary directory, a fake GitHub API and an in-process registry (with
  and without the referrers API, paged tag lists): the lines printed, `--dry-run` sending no delete,
  records and rootfs files removed with their artifact, shared records kept, ignored files untouched,
  the registry's records and tags removed with the image, a registry or release that refuses a delete
  reported per artifact with exit 1, and the exit codes. Integration: the same against zot and the
  distribution registry.
- Release publishing: every asset uploaded under a `.partial-` name and renamed, the records last, a
  failed rename or a short upload leaving nothing a lookup reads, a leftover deleted by the next publish.

**Fixture archive, seconds**

A tiny Debian-format archive generated by the tests (a handful of packages made with `dpkg-deb`,
indexed and signed with a throwaway key) at two timestamps, laid out the way snapshot.debian.org
serves it, with a recorded `/mr/timestamp/` listing. It exercises resolution, identities and the
plan without the network: a new version of one package at the second timestamp changes exactly the
identities of the images that install it, and nothing else.

**M6's nightly claims, on the fixture archive, seconds** (`tests/test_nightly.py`). The Action's own
plan and summary steps (`action.yml`, run for real by `tests/support/action.py`) call `plan --snapshot
latest --against dir://...` on a definition of every file kind (a core, an installer, an OS, an Incus
base and its child), against the fixture archive served over HTTP and a target holding each image as a
published artifact with a passing result for every required check. At the later snapshot with no new
version of a package any image installs, every image reads `reuse`, the plan carries the new snapshot
and the same identities, `changed` is `false` and fetch, build, test and publish do not run (the plan's
`changed` function has unit tests of its own). With one new upload of a package that only the Incus base
installs, exactly the base and its child read `build` and the other three read `reuse`. A required check
that failed on the published artifact builds it again. The Action's input checks (`steps`, `publish`)
and `scripts/action-support` (the release read from the lock, the summary, the artifacts, the YAML subset
and the shell extraction) have unit tests too, and a static one fails any `uses:` that is not pinned by
commit with its version.

**Integration, minutes (release tag, and locally while developing)**

- Rootless Docker: core, OCI, Incus rootfs, installer and OS builds from the fixture archive and from
  the real snapshot; `package-set`, `locked-inputs`, `no-machine-identity`, `two-clones` for core and
  OCI, `sbom-complete`, `ancestry`, `same-resolution`, `no-build-snapshot`, `byte-equal`, `oci-run`;
  offline replay from inputs bundles (`tests/integration/test_replay.py`): core, oci-base and a child that
  installs a package are fetched with `--bundle` (the example's other images marked `reuse`, so nothing is
  read for them), built once, and replayed with `build --offline --bundle` by a factory running inside a
  container started with `--network none` (the host's docker socket mounted, the work paths at the same
  paths), after a request to snapshot.debian.org from that container has failed; the replayed core must have
  the first build's digest and the OCI images their manifest digests, and a second fetch must write
  byte-identical bundles; publishing to a throwaway local
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
  the revision fails here. Core, the example `os` and the example `installer` are byte-equal (two builds
  of one plan, the second on the first's core, give the same sha256; `tests/integration/test_booting_build.py`
  records both digests and compares them with `test --check byte-equal --twin`), so all three are guarded,
  and their bytes hold no commit. The day an OCI image's digest is guarded, its fixture is built from a
  definition with no git remote, so the expected digest does not move with the repository's HEAD (5.3).
  A kind not yet byte-equal (OCI, Incus) relies on review: any change to its build code raises the revision.
- QEMU with KVM: `installer-boot`, `os-boot`, `two-clones` for the installer and OS, and
  `incus-boot` in a Debian 13 VM with Incus from the same snapshot (6.0.4 in Debian 13). QEMU runs in
  the boot checks' image (`builder/vm.Dockerfile`, built by `scripts/builder vm` from the builder's base
  and snapshot), with `--device /dev/kvm` when it opens and TCG otherwise, under a longer time limit;
  the harness never changes the artifact. The guest reports through two systemd credentials passed as
  SMBIOS type 11 OEM strings: an extra unit (`Type=simple`, so the boot can finish while it waits for
  `systemctl is-system-running --wait`) that writes one `FACTORY-REPORT` line to `/dev/ttyS0` and powers
  off, and a drop-in that makes `multi-user.target` want it. Both boots of `two-clones` run at once and
  also serve the boot check. A failed boot check keeps each boot's serial log beside the artifact and
  names its last lines in the result. `tests/integration/test_boot_checks.py` builds a small OS root and
  kit with mmdebstrap and boots both; under TCG each pair of boots takes under a minute.
- An Incus host for `incus-boot` and `two-clones` on Incus images: `scripts/incus-vm` boots Debian 13's
  genericcloud image (pinned by build directory and SHA512SUMS) under QEMU in a privileged docker
  container, KVM when `/dev/kvm` opens and TCG otherwise, installs Incus (6.0.4 in Debian 13) from
  the lock's snapshot, shares directories over virtiofs and runs one command as root. The prepared disk
  is cached under a key that digests every input of its state: the base image's SHA512, the snapshot ID,
  the whole prepare user-data (script, apt sources text and package list) and the disk size, so editing
  any of them prepares a fresh disk. Without `--snapshot` the guest installs from the live mirrors,
  which move, so the key also holds the UTC day: such a disk is at most a day old (a snapshot ID gives a
  disk that never ages, and is what `scripts/test incus` passes). `scripts/test incus` builds
  core, `incus-base` and an Incus child of it from the example definition, runs every check on all
  three (the Incus checks inside the VM), then requires each image's checks to pass with
  `verify --require-checks`: the boot contract for the base and for a child. The `incus` workflow
  runs that tier by hand on a runner with KVM, and a release tag runs the same workflow beside the
  integration tier, gating the publish.
- **The nightly path for real** (`tests/integration/test_action.py`): the Action's shell steps on the
  nightly workflow's definition, with the `.pyz` built from the checkout, against snapshot.debian.org
  and rootless Docker. The first night plans at the newest completed snapshot, fetches, builds the core
  and the Incus base in the builder the Action builds, tests, publishes to a `dir://` target and names
  both artifacts; the second night, a moment later, reads `changed=false` and runs nothing else.

**Where it runs.** Its jobs run on GitHub's hosted runners, free for public repositories; the jobs
that boot a VM use the hosted Linux runners' `/dev/kvm`. Each job installs what the runner image
lacks. A pull request from a fork skips every job. Consumers run their own checks in their own CI.

**The nightly** (`.github/workflows/nightly.yml`) runs the Action as `uses: ./` every night and on demand,
on the plain runner label (it boots nothing), one at a time (a concurrency group, never cancelled, so two
nights never race on the cache). It plans `.github/nightly/factory.toml` with `snapshot: latest` against a
`dir://` target kept in the Actions cache: the newest `nightly-` entry is restored, and a night that built
something prunes the directory (`prune`, the default retention, no pins) and saves a new one, so a quiet
night saves nothing. It publishes nowhere public (16.2). The
definition is the example's file kinds, a core and an Incus base: a `dir://` target holds files only, so
the example's OCI images, which need a registry, would read `build` every night and a quiet night would
not exist. Its Incus checks need an Incus host, which the runner lacks, so the base stays a candidate
(`wait`, never `build`). It runs the factory built from the checkout through the Action's `pyz` input,
until this repository's own lock names a release.

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
   index or lock checksum. That holds at the build too: `fetch`'s notes about what it verified are
   not trusted, and before it builds an image `build` verifies every signed list the image's inputs
   rely on again, from the cache alone (no network): each noted file (a Node-style checksum list and
   its detached signature, or a vendor repository's `InRelease` and `Packages` index) with `gpgv`
   against the keyring entry the plan's `trust` names, itself checked against its locked checksum, and
   against the locked sha256 of the input. A build whose lists do not verify fails before anything is
   built, naming each file. A vendor Release's Valid-Until is judged at the time of the build, so a
   cache older than that needs `fetch` again. A replay from a bundle judges it at the bundle's
   `verified_at` instead, capped at the present (7.7): the freshness check then rests on the bundle's
   integrity, which an unsigned bundle does not give, and that is accepted because the `.deb` is
   pinned by sha256 in the lock and every signature is still checked.
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
    builds deleted when their checks end (a failed build whose other checks have no result is still a
    candidate, 11).
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
5. **The repository is public** (decided). Every file passes a scan for private data before a push,
   and the examples use example.com names only.
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
   the fields. The vendor `.deb` index follows the same route: every `builtin:deb` entry has
   `signed_by`, and `plan` and `fetch` read only a `Packages` index its repository's signed `InRelease`
   (or `Release` with `Release.gpg`) vouches for, checked for its suite and Valid-Until, and require the
   version's sha256 there to equal the lock's (6.4). No unsigned vendor index is trusted.
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
