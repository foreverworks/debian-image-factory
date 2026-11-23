# Debian Image Factory

**Every Debian image you ship, built from pinned archive snapshots, rebuilt only when something in it
actually changed, and carrying standard records of what is inside and how it was made.**

> **Status: every kind of image builds, tests and publishes, and a nightly loop rebuilds only what
> changed.** The factory checks your lock and definition, resolves every image's exact package set
> from a snapshot, tells you what would be built and why, and builds core, OCI, Incus, installer and
> OS images with their SBOM, provenance and checks. Release 0.6.3 is the newest this page's commands were
> run on. Record signing and parallel builds are in 0.7.0 and later (0.6.3 and earlier have neither). The
> interface may still change before 1.0. The full design is in [DESIGN.md](DESIGN.md).

## The problem

If you run Debian in more than one shape, you probably build each shape its own way. A Dockerfile
starts from a public image and runs `apt-get upgrade`. An [Incus](https://linuxcontainers.org/incus/)
image (Incus runs system containers and VMs) comes from a public image server and is upgraded in
place. The installer you boot on new machines is bootstrapped by a different tool, and the installed
OS by yet another script. Each of them reads the Debian archive at a different moment.

Then a security advisory lands and someone asks a simple question: *which of our images have the
fix?* Answering it means logging into each image, or rebuilding everything and hoping. Weekly
"just in case" rebuilds burn hours and still drift, because every rebuild sees a different archive.
And the language runtime or vendor package your recipe fetches as "latest" means two builds of the
same recipe can differ for reasons nobody wrote down.

## What the factory does about it

- **One archive state for everything.** Every image in a generation resolves its packages from the same
  two [snapshot.debian.org](https://snapshot.debian.org) snapshots, one of the main archive (main and
  updates) and one of the security archive, each pinned on its own, so a security fix can be built with
  as soon as its own archive lists it. Your container base, your Incus image, your installer and your OS image agree on every shared package,
  by construction.
- **One core, many shapes.** A minimal Debian core is built once. The OCI (container) image, the
  Incus image, the RAM-booted installer and the OS root filesystem are all derived from that exact
  core, each adding only what it needs.
- **Every download locked.** One `lock.json` names the snapshots and every external file (a Node.js
  release, a vendor `.deb`, an SDK) with its version and checksum. Builds run with no network: they
  can only use what the lock names. Renovate can keep the lock current for you.
- **Rebuild only when it matters.** Before building, the factory computes each image's *input
  identity*: its exact package set, the locked files it uses, its recipe and its parent's identity.
  If that has not changed, nothing is built. A night with no relevant Debian upload builds nothing;
  a kernel update rebuilds the installer and OS images and leaves your containers alone.
- **Records attached to the bits.** Every artifact gets three kinds of record, each bound to its
  content digest:
  - an **SBOM** (software bill of materials) in [SPDX](https://spdx.dev) 2.3: every package and
    locked download inside, with versions, so a scanner can tell whether a fix is in;
  - **provenance** in [SLSA](https://slsa.dev) v1 format: which lock, snapshot, recipe, parent and
    builder produced these exact bits;
  - one **test result** per check, as an [in-toto](https://in-toto.io) attestation: which checks
    these exact bits passed.

  OCI images carry them in the registry, linked to the image; files carry them in a
  `<digest>.intoto.jsonl` beside them. Any tool that speaks these standards can read them. They are
  unsigned unless you switch signing on (`publish --sign keyless` or `--sign key:<path>`, from 0.7.0; see
  below).
- **No root needed.** Rootless Docker, or a Debian machine with user namespaces, is enough to build
  everything. Only the boot tests want KVM.

## Who it is for

- Teams that maintain their own base images and need to answer "is the fix in?" from records,
  not by logging in.
- Anyone who has to show auditors or customers an SBOM and provenance for what they ship.
- People who run bare metal or Incus alongside containers and want one Debian under all of it.
- People who are tired of weekly rebuilds that change everything and prove nothing.

If you only need one container image and the official `debian` image plus a Dockerfile serves you
well, keep doing that. The factory pays off when you have several shapes, or need the records.

## What you need first

- **To get it**: `git`, and `gh` or a browser to download the release files.
- **To plan** (`lock check`, `plan`): any Debian or Ubuntu machine with python3 3.13 or newer, `apt` and
  `gpgv`, and network access to snapshot.debian.org.
- **To build and test**: Docker, rootless is enough, and nothing from the network while it builds. The boot
  checks of the Incus, installer and OS images want QEMU in a container and use KVM when `/dev/kvm`
  opens.
- **To publish**: a directory, a container registry you can push to, or a GitHub release, with the
  credentials for it.
- **Cost**: the factory is free ([MIT](LICENSE)) and needs no account. Your registry and your CI runners are
  yours to pay for.

## Try it

The factory is one file. These commands pin v0.6.3, the release they were run on; later releases work the same
unless their notes say otherwise. Download the file with its checksum, check it, and put it on your PATH as
`debian-image-factory` (the commands below call it that; `python3 debian-image-factory-0.6.3.pyz` works too).
`~/.local/bin` must be on your PATH.
The release also carries a Sigstore bundle, `debian-image-factory-0.6.3.pyz.sigstore.json`.

```sh
gh release download v0.6.3 -R foreverworks/debian-image-factory     # or take the three files from the release page
sha256sum -c debian-image-factory-0.6.3.pyz.sha256                  # debian-image-factory-0.6.3.pyz: OK
install -Dm 755 debian-image-factory-0.6.3.pyz ~/.local/bin/debian-image-factory
git clone --branch v0.6.3 https://github.com/foreverworks/debian-image-factory && cd debian-image-factory/examples
debian-image-factory lock check
debian-image-factory plan > plan.json
```

`lock check` reports that the lock and the definition agree and that each snapshot ID is complete. The release
above has one `debian_snapshot` for both archives; a later release pins each archive on its own, and
`lock snapshot --latest` migrates a lock with one command (the output then names each archive's snapshot):

```text
lock.json and factory.toml agree: 6 images, 6 entries
debian_snapshot 20261121T004329Z: completed; debian serves 20261120T203430Z, debian-security serves 20261121T004329Z
inputs.debian-baseline 20261108T000000Z: completed; debian serves 20261107T205437Z, debian-security serves 20261107T192849Z
```

`plan.json` holds the six images of the example, a core, two OCI images, an Incus image, an installer and an OS
image, each with its exact package set and identity. Nothing is published yet, so every image has the state
`build`. Planning took about ten seconds here. Building all six took 5 minutes 16 seconds on a 16-CPU machine
with the 228 packages already downloaded; a first run also downloads them. The commands for it are under
"What using it will look like" below, run from `examples/`.

## How it works

```text
lock.json (snapshot IDs + every locked download)    factory.toml (your images)
                     \                                   /
                      plan: resolve package sets, compute identities, look them up where you publish
                                          |
                      fetch: download and verify only what changed
                                          |
                      core: minimal Debian, no kernel, no machine identity
                                          |
            +--------------+--------------+---------------+--------------+
            |              |              |               |              |
         OCI base     Incus base      installer          OS         (your children of each:
         (+ Node)     (cloud-init)    (RAM kit)      (root fs)       runtimes, tools, services)
                                          |
                      test: built-in checks plus your own, one test result each
                                          |
                      publish: registry or release, records attached by digest
```

Approval stays with you: the factory produces candidates and records, and your own pipeline
decides what gets pinned, rolled out or rolled back.

## What using it will look like

You write two files. The lock holds versions; the definition holds names.

`lock.json` (maintained by tools, reviewed by you). Every download has a checksum, and so does the
key that vouches for it: the Node.js release keyring is an entry of its own, so a key change shows
up as a diff you review. `signed_by` and `sums_url` tell `fetch` to check the checksum against
Node.js's own signed `SHASUMS256.txt.asc` before anything is built (they make it a schema 2 lock, and
`debian_snapshots` makes it schema 3).

```json
{
  "schema": 3,
  "debian_snapshots": {
    "debian": "20261123T084014Z",
    "debian-security": "20261123T141315Z"
  },
  "inputs": {
    "node-26": {
      "module": "node",
      "version": "26.13.1",
      "url": "https://nodejs.org/dist/v{version}/node-v{version}-linux-x64.tar.xz",
      "sha256": "5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864",
      "signed_by": "node-release-keys",
      "sums_url": "https://nodejs.org/dist/v{version}/SHASUMS256.txt.asc",
      "used_by": ["node-26"]
    },
    "node-release-keys": {
      "module": "node",
      "version": "481637f813e912c4aa3622d7964ab426c97b8e8d",
      "url": "https://raw.githubusercontent.com/nodejs/release-keys/{version}/gpg-only-active-keys/pubring.kbx",
      "sha256": "140f2ad5260fd62773b6243ce8e1d3009645d558f121b8262c55e383dc285932",
      "used_by": ["node-26"]
    }
  }
}
```

The checksums are real (Node.js 26.13.1, and the keyring at that commit of nodejs/release-keys).
The build snapshots move as often as you like, each archive on its own clock, and never end up inside an
image. `debian_snapshots` names the exact ID each archive lists (`debian-image-factory lock snapshot --latest`
writes it; an older lock with one `debian_snapshot` still works). If your images'
own apt sources should point at a snapshot too, that is a second, deliberate one, the baseline:
`debian-image-factory lock baseline --id <ID>` adds it as one more entry. The lock format is
shared with [input-lock](https://github.com/foreverworks/input-lock), a small library the factory
bundles.

`factory.toml` (written by you):

```toml
schema = 1

[debian]
suite = "trixie"                # Debian 13
architectures = ["amd64"]

[modules.node]
use = "builtin:node-tarball"    # checked against Node.js's signed checksums

[images.core]
kind = "core"
packages = ["ca-certificates", "tzdata"]

[images.oci-base]
kind = "oci"
parent = "core"

[images.node-26]
kind = "oci"
parent = "oci-base"

[images.incus-base]
kind = "incus"
parent = "core"
packages = ["openssh-server", "sudo"]
```

Then:

```sh
debian-image-factory lock check          # the lock and the definition agree; snapshot IDs still valid
debian-image-factory plan > plan.json    # every image's package set and identity, and what would be built
```

[examples/](examples/) has a lock and a definition covering every kind; the [v0.6.3 release](https://github.com/foreverworks/debian-image-factory/releases/tag/v0.6.3)
is the `.pyz` named in "Try it" above. To run the source instead: `scripts/vendor-input-lock` once, then
`PYTHONPATH=src:.vendor python3 -m debian_image_factory`.

Then build the images and check them:

```sh
../scripts/builder build                   # the pinned builder image, from the factory's own snapshot
debian-image-factory fetch plan.json       # the indices, packages and inputs of the images that build, verified, in the cache
debian-image-factory build plan.json --out out/    # every kind, offline, in the builder container
debian-image-factory test out/             # each kind's checks, recorded beside the artifact
debian-image-factory publish out/ --to dir:///srv/images
```

`build` needs Docker and nothing from the network: it reads the partial mirror
`fetch` laid out. `fetch` reads only for the images the plan says to build, and for a child only the
packages it adds to its parent, which is an artifact. Each artifact lands in `out/` with its records in `<digest>.intoto.jsonl`: SLSA
provenance, an SPDX SBOM and one test result per check. An OCI image lands as a directory
`<image>-<suite>-<arch>-<identity16>-<digest12>.oci`, an OCI image layout: its parent's layers (for
core's child, core's tarball itself) and at most one layer of its own. Plan again with `--against
dir:///srv/images` and the core you just published reads `reuse`.

What you see on the example: `publish` copies core, the Incus image, the installer and the OS image, and says
that the two OCI images publish only to `oci://` targets. In the second plan core reads `reuse`, the OCI images
`build` (nothing holds them yet), and the Incus image, the installer and the OS image `wait`: `test` reported
their boot checks as `not run` (no Incus host, and no boot image for QEMU, which `scripts/builder vm` builds),
so they are still candidates. A candidate becomes a good build when its required checks have passed (the boot checks are described below), and the plan reuses good builds.

To keep an image's exact inputs, `fetch plan.json --bundle` writes one `.inputs.tar` per image that
builds, into `bundles/` beside the plan (or `--bundle-dir DIR`). It holds the signed indices, the
packages and the locked inputs of that image, and a manifest of every file's sha256; two fetches of
one plan write the same bytes. `build --offline --bundle FILE --out out/` rebuilds that image from
the bundle alone, with the factory itself unable to use the network: the bundle carries its plan,
so the plan argument is optional. A child's parent is found in `out/` or through `--parents dir://`.

OCI images publish to a registry instead: `publish out/ --to oci://ghcr.io/example/debian` pushes
each image under the tag `identity-<identity>` and attaches its records as referrers, and `plan
--against` the same address finds it again. `debian-image-factory verify REF` checks an artifact
(an `oci://` reference, a layout directory or a file) against its records; `--pull` downloads first, so it
also reads every layer of a registry image, and with `--artifact NAME|SHA256` it verifies an artifact of a
`github-release://` or `dir://` target. Credentials come from your Docker config. Files publish to a GitHub release too: `publish out/ --to github-release://example/images@v1`
uploads them as assets (creating the release when the tag has none), and `plan --against` the same address
reads them back. It uses `GITHUB_TOKEN`, else `GH_TOKEN`, and `GITHUB_API_URL` when it is set.
Each asset is uploaded under a temporary `.partial-` name and renamed once it is whole, so a cut-off
upload never leaves half a file where `plan` could find it; the next `publish` deletes what a crashed run
left.

One build can hold several images that belong in different repositories. `publish out/ --image debian --to
oci://ghcr.io/example/debian` sends only the image `debian` (repeat `--image` for more; a name the build does not
hold is refused), and `{image}` in an `oci://` repository is replaced by each image's name, so `publish out/ --to
oci://ghcr.io/example/{image}` sends `debian` to `ghcr.io/example/debian` and `node-26` to `ghcr.io/example/node-26`.

`{image}` means the same in every command that takes a target, so you can give the same string to all of them:
`plan --against oci://ghcr.io/example/{image}` looks each image up in the repository named for it, `build --parents`
and `test --parents` read a parent image from the repository named for the parent, and `prune --against` judges each
image of your definition in its own repository. `{image}` is refused anywhere but in the repository of an `oci://`
target.

A night on which only Node moved builds only the Node images: their Debian-built parent is reused from the registry,
so `test` does not find it in `out/`. `test out/ --parents oci://ghcr.io/example/debian` reads the parent's manifest
from there, so the child's `ancestry` check runs and passes instead of staying unrun, which would leave the new
image a candidate that `plan` keeps waiting on. In the GitHub Action, the `build` step passes every `oci://` and
`dir://` target of `against` as `--parents`, and the `test` step every `oci://` one, so such a night needs nothing
more from you; the registry is read with the Docker config, like `plan`'s.

Published builds pile up, so `prune` clears them: `debian-image-factory prune --against
oci://ghcr.io/example/debian --pin sha256:<digest> --dry-run` lists, for every image, the newest 5 good builds and
the newest candidate it would keep (`--keep-good`, `--keep-candidates`) and the rest it would delete,
with the reason for each line. A build is good when every check your definition requires for its image
has passed; one with a failed check is deleted once its checks have ended, and a run of failed nights
never pushes out a good build, and a check you add to `[checks]` later does not demote the builds made
before it. Anything you still run or may roll back to goes in as `--pin`, an artifact digest that is never
deleted. Always run with `--dry-run` first, and again after you change `[checks]`: it shows what a run
would delete. Drop `--dry-run` to delete: the artifact and its records from a directory or a
release, the image, its records and its identity tag from a registry (which must allow deleting manifests; zot and
the official distribution image do, a distribution registry with `storage.delete.enabled` off does not). A delete that fails is reported for its
artifact and the exit status is 1.

An Incus image is two files named by their Incus fingerprint, `<name>.incus.tar.gz` (its metadata
and the factory's NoCloud templates) and `<name>.rootfs.squashfs`, ready for `incus image import
<name>.incus.tar.gz <name>.rootfs.squashfs`. An instance gets its user data from `cloud-init.user-data`
(or the older `user.user-data`), its hostname from its name, and its machine ID and SSH host keys at
its first boot. `test` proves that on an Incus host: `incus-boot` launches it with each key, and
`two-clones` launches two and compares their identities. Where no Incus host answers, both are reported
as not run, never as passed; `scripts/incus-vm -- <command>` runs a command on an Incus host in a
throwaway Debian 13 VM (KVM when the machine has it, emulated otherwise).

An installer is a kit, `<name>.tar`, holding `kit.json` (its kernel version and the files' sizes and
checksums), `vmlinuz` and `initrd.img`: the whole root as a RAM disk, for PXE or kexec. An OS image is a
root filesystem tarball, `<name>.tar.gz`, with its kernel and initrd in `/boot`, for your installer to lay
on a disk. Neither holds a machine ID or SSH host keys: both are made at the first boot. An OS image's
own apt sources come from `apt_sources` (`baseline-except-security` points main and updates at the
baseline and leaves security live), so moving the baseline rebuilds the OS images and nothing else.
`scripts/builder vm` gives the image `test` boots them in: `installer-boot` boots the kit's kernel and
initrd, `os-boot` the root on a disk by UEFI, and `two-clones` boots each twice and compares their
identities, all in QEMU (KVM when `/dev/kvm` opens, emulated otherwise).

Two more modules put files from the lock into images. `builtin:deb` installs a vendor's `.deb` with its
dependencies from the snapshot, after checking the vendor repository's signed `InRelease` against a
keyring the lock pins; the vendor's repository never enters the image's apt sources. `builtin:file`
places any locked download at a path, or unpacks a tarball there. A module with `enabled_by = "<param>"`
follows a flag of `[params]`: switched off, its entries leave every image and every identity. When a
vendor's version moves, `debian-image-factory lock checksums --entry <name>` fills its checksum from the
vendor's signed index.

### In GitHub Actions

One step plans, fetches, builds, tests and publishes, and reports `changed=false` on the nights when
there is nothing to do: then it downloads a few package indexes and stops. It runs the factory release
your lock pins, so add the `debian-image-factory` entry to your `lock.json` (Renovate bumps it, and
`debian-image-factory lock checksums --entry debian-image-factory` fills the sha256 of the release's `.pyz`):

```json
"debian-image-factory": {
  "datasource": "github-releases",
  "depName": "foreverworks/debian-image-factory",
  "extractVersion": "^v(?<version>.+)$",
  "sha256": "<sha256 of the .pyz>",
  "url": "https://github.com/foreverworks/debian-image-factory/releases/download/v{version}/debian-image-factory-{version}.pyz",
  "version": "0.6.3"
}
```

Then a nightly workflow, with every action pinned by commit and its version in a comment:

```yaml
name: images
on:
  schedule: [{cron: "17 2 * * *"}]
permissions:
  contents: read            # contents: write instead to publish to a github-release:// target
  packages: write           # publishing to ghcr.io
jobs:
  images:
    runs-on: ubuntu-latest
    concurrency:                # one publishing run at a time, never cancelled (DESIGN 9.2)
      group: images
      cancel-in-progress: false
    steps:
      - uses: actions/checkout@<commit> # v7.0.1
      - uses: docker/login-action@8aa5831fb8d48d8f76594c7ddde61ae58019f550 # v4.8.0
        with:                                   # the factory reads the Docker config for oci:// targets
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ github.token }}
      - id: factory
        uses: foreverworks/debian-image-factory@<commit> # v0.6.3
        with:
          definition: images/factory.toml
          lock: images/lock.json
          snapshot: latest                      # the newest snapshot each archive lists, without editing the lock
          against: |                            # where identities are looked up, and where publish writes
            oci://ghcr.io/example/debian
          publish: true
      - run: echo "changed=$CHANGED"
        env:
          CHANGED: ${{ steps.factory.outputs.changed }}
```

The Action reaches a target with the credentials you give it, and gives itself none. For an `oci://`
target the factory reads the Docker config, so log in to the registry in a step before the Action
(`docker/login-action`, as above; on ghcr.io the workflow's own token is enough with `packages: write`).
For a `github-release://` target it reads `GITHUB_TOKEN`: the Action's `token` input passes the workflow's
token to `plan` and `publish` and to no other step, and needs `contents: write` to publish. GitHub does not
put that token in a step's environment by itself, which is why the input exists.

The inputs are `definition`, `lock`, `params`, `snapshot`, `against`, `steps` (default
`plan,fetch,build,test`), `publish`, `sign` (`none`, `keyless` or `key:REF`; not `none` installs cosign 3.1.4, and `keyless` needs `id-token: write`), `mirror`, `jobs` (images built at a time, `build --jobs`; `sign` and `jobs` need factory 0.7.0 or newer, and the Action stops early with a message when your lock pins an older release), `token` (default the workflow's token) and
`keep-work` (default `true`, so later steps can read the `plan` output; `false` removes the work directory,
with the build output, when the run ends); the outputs are `changed`, `plan` (the path of
`plan.json`) and `artifacts` (JSON of image to digest). The runner needs Docker to build, and `apt`
and `gpgv` to plan (the Action installs the last two when they are missing). The release also
publishes the builder image to `ghcr.io/foreverworks/debian-image-factory-builder`, signed with Sigstore.
Until the `.pyz` pins it, the Action builds the builder from its own checkout: pin the Action at the
commit of the release your lock names. `.github/workflows/nightly.yml` is a working example, run on this
repository's own definition; the inputs, the steps and what happens when nothing changed are in
[DESIGN.md, section 9.2](DESIGN.md#92-the-github-action).

## What it is not

- **Not a byte-for-byte reproducible build system.** It replays the same declared inputs. It
  measures whether two builds come out identical, and says so, but it does not promise it.
- **Not a deployment tool.** Pins, rollouts and rollbacks are yours.
- **Not a patch manager for running machines.** It builds images; how your hosts take updates is
  your policy.
- **Not a disk installer.** It hands you an installer kit and an OS root filesystem. Partitioning,
  filesystems and bootloaders on real hardware stay in your own install flow.
- **Not a replacement for official application images.** If an application ships an official image,
  use it, pinned by digest. The factory is for the images you maintain yourself.

## How it compares

- **[debuerreotype](https://github.com/debuerreotype/debuerreotype)** is what Debian's official
  container images are built with, and it already does the hard part well: a reproducible Debian
  root filesystem from a snapshot.debian.org timestamp. If one reproducible container base is all
  you need, use it. The factory adds the shapes beyond containers (Incus, installer, OS), children
  derived from the same core, a lock for everything outside Debian, rebuilds decided by input
  identity, and the records.
- **[apko](https://github.com/chainguard-dev/apko) and [melange](https://github.com/chainguard-dev/melange)**
  build minimal, reproducible OCI images declaratively, with SBOMs built in, from apk packages
  (Wolfi, Alpine). They are excellent at that, and further along than this project. They are not
  Debian, and they build OCI images only; the factory is for teams whose world is Debian packages
  and more than one image format.
- **mkosi, debos, distrobuilder** each build one image from a recipe, and some of them support many
  formats. The factory stands on the same Debian tooling (it uses mmdebstrap) and adds the layer
  above: one pair of snapshots across every shape, locked external inputs, identity-based skipping and
  standard records on every artifact.

## Questions you will probably have

**Will snapshot.debian.org be a bottleneck?** It is a shared, rate-limited service. The factory
reads indices by hash, downloads only what changed, can go through any HTTP cache you point it at
(accepting content only by checksum), and can keep each image's exact inputs as a bundle, so a
retained build can be rebuilt with snapshot.debian.org unreachable.

**Do I need to trust the factory's builds?** You do not have to take its word. Every record names
the lock digest, the snapshot indices, the recipe, the parent and the builder, so you can check an
artifact against your own lock. Records are unsigned by default; from 0.7.0, Sigstore keyless
signing in CI, or your own key, can be switched on without changing anything else (next question).

**How do I sign records?** Signing needs 0.7.0 or newer; 0.6.3 and earlier accept only `--sign none`. `publish --sign keyless` signs each record with Sigstore through the CI's OIDC
identity (the job needs `permissions: id-token: write`; the signature goes to the public Rekor log), and
`--sign key:<path or KMS URI>` signs with a key you hold, which is never sent to a log. Both call cosign
3.1.4, which must be on PATH (the Action installs it when `sign` is not `none`). The factory never holds a
key, and a signed record has the same payload and shape as an unsigned one; only `signatures` is filled.
Check them with `verify REF --key cosign.pub`, or for keyless with the identity and issuer you expect:

    debian-image-factory verify oci://ghcr.io/example/app@sha256:... \
      --certificate-identity https://github.com/example/images/.github/workflows/nightly.yml@refs/heads/main \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com --require-signature

Without `--require-signature` an unsigned record still verifies, and signed ones are only checked when you
name who must have signed them.

**Does it put secrets or host identity into images?** No, and it checks. Images ship without
machine IDs, SSH host keys or credentials; each instance creates its own identity on first boot.
Anything secret is supplied by you at run time, never at build time.

**Which Debian and architectures?** Debian 13 "trixie" (13.8 at the time of writing) on amd64.
The architecture is part of every identity, so others can follow once someone needs them.

**What language is it in?** Python 3.13 or newer, using only the standard library at run time, so
it runs on the python3 Debian already ships. It is distributed as a single `.pyz` file.

## Status

Built, in v0.6.3 and later:

- the lock and definition checks, identities, `lock check`, `lock snapshot`, `lock baseline`, `lock
  checksums` and `plan`, with the pinned builder image;
- `fetch` and its partial mirror, and offline builds of core (the same bytes from the same inputs), OCI
  images (one added layer per child), Incus images, installer kits and OS root filesystems, each with its
  SBOM and provenance;
- `test` with every kind's checks, including the boot checks in an Incus host or QEMU;
- `publish` to a directory, a registry (records as referrers) and a GitHub release, and `verify`;
- the nightly loop: `plan --snapshot latest --against` every kind of target, the GitHub Action, `prune`
  with its retention rule, inputs bundles and offline replay, and the optional `byte-equal` check. A night
  with no relevant upload builds nothing.

Built, in 0.7.0 and later: record signing and parallel builds (`build --jobs`).
Built, in 0.8.0 and later: one Debian snapshot per archive, so a security fix is buildable as soon as its archive lists it.

Planned: the `.pyz` pinning the published builder image, `--builder host`, zstd compression, and for 1.0 a
full example repository, once a real deployment has run every kind through its own promotion. What is
planned and why is in [DESIGN.md, section 14](DESIGN.md#14-what-is-built-and-what-is-planned).

## Running the tests

`scripts/test static`, `scripts/test unit` and `scripts/test integration` run the same checks CI
does (the last needs Docker and network access to snapshot.debian.org); `scripts/test boot` runs only
the tests that boot images, and `scripts/test matrix` the unit tier on the oldest and newest Python.
The unit, integration and boot tiers run their test classes in parallel, one worker per CPU,
longest class first, never more workers than the free memory allows (0.5 GiB a worker for unit, 3 GiB for
integration, 6 GiB for boot; the count and the reason are printed). `-j N` or `DIF_JOBS=N` sets the number
of workers and `-j 1` runs serially. Each worker's
log is in `dist/test-<tier>/`, and the failures of all of them are printed together at the end.
`--shard I/N` runs one slice of a tier, which is how CI spreads the integration tier over several
runners, and `--measure` refreshes `tests/durations.json`, the timings the schedule is built from.

## Where to ask

Open an [issue](https://github.com/foreverworks/debian-image-factory/issues) for a question, a bug or something unclear in
this page. Report a security problem privately, as [SECURITY.md](SECURITY.md) describes.

## License

[MIT](LICENSE).
