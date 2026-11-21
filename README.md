# Debian Image Factory

**Every Debian image you ship, built from one archive snapshot, rebuilt only when something in it
actually changed, and carrying proof of what is inside.**

> **Status: design, not yet usable.** There is no code in this repository yet. The full design is
> in [DESIGN.md](DESIGN.md); this README describes what the factory will do once its first
> releases land. If something here is unclear, that is a bug in the design: please open an issue.

## The problem

If you run Debian in more than one shape, you probably build each shape its own way. A Dockerfile
starts from a public image and runs `apt-get upgrade`. An Incus image comes from a public image
server and is upgraded in place. The installer you boot on new machines is bootstrapped by a
different tool, and the installed OS by yet another script. Each of them reads the Debian archive
at a different moment.

Then a security advisory lands and someone asks a simple question: *which of our images have the
fix?* Answering it means logging into each image, or rebuilding everything and hoping. Weekly
"just in case" rebuilds burn hours and still drift, because every rebuild sees a different archive.
And the language runtime or vendor package your recipe fetches as "latest" means two builds of the
same recipe can differ for reasons nobody wrote down.

## What the factory does about it

- **One snapshot for everything.** Every image in a generation resolves its packages from the same
  [snapshot.debian.org](https://snapshot.debian.org) ID, covering main, updates and security. Your
  container base, your Incus image, your installer and your OS image agree on every shared package,
  by construction.
- **One core, many shapes.** A minimal Debian core is built once. The OCI image, the Incus image,
  the RAM-booted installer and the OS root filesystem are all derived from that exact core, each
  adding only what it needs.
- **Every download locked.** One `lock.json` names the snapshot and every external file (a Node.js
  release, a vendor `.deb`, an SDK) with its version and checksum. Builds run with no network: they
  can only use what the lock names. Renovate can keep the lock current for you.
- **Rebuild only when it matters.** Before building, the factory computes each image's *input
  identity*: its exact package set, the locked files it uses, its recipe and its parent's identity.
  If that has not changed, nothing is built. A night with no relevant Debian upload builds nothing;
  a kernel update rebuilds the installer and OS images and leaves your containers alone.
- **Proof attached to the bits.** Every artifact gets an SPDX 2.3 SBOM, SLSA v1 provenance and one
  in-toto test result per check, bound to its content digest. OCI images carry them as registry
  referrers; files carry them in a `<digest>.intoto.jsonl` beside them. Any tool that speaks these
  standards can read them, and the factory's own `verify` can too.
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

## How it works

```text
lock.json (snapshot ID + every locked download)     factory.toml (your images)
                     \                                   /
                      plan: resolve package sets, compute identities, compare with what is published
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

`lock.json` (maintained by tools, reviewed by you):

```json
{
  "schema": 1,
  "debian_snapshot": "20261121T005332Z",
  "inputs": {
    "node-26": {
      "module": "node",
      "version": "26.13.1",
      "url": "https://nodejs.org/dist/v{version}/node-v{version}-linux-x64.tar.xz",
      "sha256": "48cc...af75",
      "used_by": ["node-26"]
    }
  }
}
```

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
debian-image-factory lock check          # the lock and the definition agree
debian-image-factory plan > plan.json    # what would be built, and exactly why
debian-image-factory fetch plan.json
debian-image-factory build plan.json --out out/
debian-image-factory test out/
debian-image-factory publish out/ --to oci://ghcr.io/example/debian
```

In GitHub Actions, one step runs the same thing nightly, and reports `changed=false` on the nights
when there is nothing to do. The planned interface is in [DESIGN.md, section 9](DESIGN.md#9-running-it).

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

## Questions you will probably have

**How is this different from mkosi, debos or distrobuilder?** Those are good tools for building one
image from a recipe, and the factory stands on the same Debian tooling (it uses mmdebstrap). What
it adds is the layer above: one snapshot shared by every shape, a lock for everything outside
Debian, rebuilds decided by input identity, and standard records on every artifact.

**Will snapshot.debian.org be a bottleneck?** It is a shared, rate-limited service. The factory
reads indices by hash, downloads only what changed, can go through any HTTP cache you point it at
(accepting content only by checksum), and can keep each image's exact inputs as a bundle, so a
retained build can be rebuilt with snapshot.debian.org unreachable.

**Do I need to trust the factory's builds?** You do not have to take its word. Every record names
the lock digest, the snapshot indices, the recipe, the parent and the builder, so you can check an
artifact against your own lock. Records are unsigned by default; Sigstore keyless signing in CI, or
your own key, can be switched on without changing anything else.

**Does it put secrets or host identity into images?** No, and it checks. Images ship without
machine IDs, SSH host keys or credentials; each instance creates its own identity on first boot.
Anything secret is supplied by you at run time, never at build time.

**Which Debian and architectures?** Debian 13 "trixie" (13.8 at the time of writing) on amd64.
The architecture is part of every identity, so others can follow once someone needs them.

**What language is it in?** Python, using only the standard library at run time, so it runs on the
python3 Debian already ships. It is distributed as a single `.pyz` file.

## Status and roadmap

Design. The first milestone (lock, definition, identities and `plan`, no builds yet) starts as soon
as the lock format it shares with its first user is settled. After that come core builds with
records, then OCI, Incus, installer and OS images, then the nightly "rebuild only what changed"
loop. The milestones are in [DESIGN.md, section 14](DESIGN.md#14-milestones).

Issues and questions about the design are welcome. Code contributions will be once there is code
to contribute to.

## License

[MIT](LICENSE).
