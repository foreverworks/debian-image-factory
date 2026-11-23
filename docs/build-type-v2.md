# Build type v2

Every artifact the factory builds comes with a provenance record, and the record's `buildType`
field is the address of this page. The page says what the other fields of the record mean, so that
someone who has never seen the factory can read a record, and so that a verifier can decide which
records to trust. A verifier pins the build types it accepts: it reads `buildType`, and if the value
is not one it knows, it does not interpret the rest.

The address carries the factory's release, for example
`https://github.com/foreverworks/debian-image-factory/blob/v<release>/docs/build-type-v2.md`. The
release says which version of this page applies; a change to the meaning of a field would be a new
page (`build-type-v3.md`), never a silent edit of this one.

The record is an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
carrying a [SLSA provenance v1](https://slsa.dev/spec/v1.2/provenance) predicate. Its subjects are
the artifact's files with their sha256 digests. It is stored in a DSSE envelope, one per line of
`<digest>.intoto.jsonl` beside a file artifact, or as an OCI referrer of an image.

## What changed from v1

One field. v1 recorded `internalParameters.buildSnapshot`, one timestamp for both Debian archives. v2 records
`internalParameters.buildSnapshots`, an object with a timestamp for each archive (`debian` and
`debian-security`), because the two archives are pinned apart: each can be built at a snapshot of its own, so a security
fix does not wait for the main archive, or the other way round. The two `InRelease` entries of `resolvedDependencies` carry their own archive's
timestamp in their address, which for v1 records was always the same one. Everything else means what it meant.
A verifier that pins build types adds this page's address, and keeps v1's for records already published.
[Build type v1](build-type-v1.md) stays as it was.

## What the build is

One build produces one artifact of one image (a core, an OCI image, an Incus image, an installer
kit or an OS root filesystem) from a definition, a lock file and one snapshot of each Debian archive it reads. The
build runs offline from a cache of files that were checked against their signed indexes or the
lock's checksums, so the record lists what the build read, and anything not listed was not read.

## externalParameters

These are what the person or the CI chose. A verifier can compare them with what it expected.

| Field | Meaning |
|---|---|
| `image` | The image's name in the definition (`core`, `node-26`). |
| `definition` | Where the definition came from: `uri` (the repository, as `git+https://host/path` or `git+ssh://host/path`, never with a user name, a token or a local path), `revision` (the full commit id) and `path` (the definition file in the repository). Absent when the build was not made from a repository checkout, because a local path must never reach a record. |
| `params` | The definition's parameters as the build ran them: a name and a string, an integer or a boolean. Empty when the build used the defaults. |

## internalParameters

These are values the factory worked out. They explain the build; a verifier does not choose them.

| Field | Meaning |
|---|---|
| `identity` | The image's input identity: 64 hex characters, the sha256 of everything that can change the artifact's bytes (its package set, the lock entries it installs, its recipe and its parent's identity). Two builds with the same identity are meant to be interchangeable, and a lookup finds a published artifact by it. |
| `engine` | The engine revision: an integer that rises only when a factory change can alter the bytes it writes. It is part of the recipe, so it is already inside `identity`; it is shown here so a reader can see which engine wrote the artifact. |
| `buildSnapshots` | The Debian archive snapshots the package versions were resolved against: an object with one `snapshot.debian.org` timestamp for each archive, `{"debian": "<timestamp>", "debian-security": "<timestamp>"}`. The two may differ, and each is a snapshot its own archive lists. |
| `architecture` | The CPU architecture, as Debian names it (`amd64`). |
| `reason` | Why this build happened when the identity alone does not say, for example a package version that moved. Present only when there is one. |
| `removedFromParent` | For an Incus image, an OS root and an installer kit: the absolute paths of the parent's root that this artifact's root does not hold, sorted (the root directory itself is never listed). Packages the child removed, the identity cleanup and the child's hooks all show here. The `ancestry` check holds the artifact to it. |

**The build snapshots are recorded here and nowhere else.** They decide which versions were picked,
and the picked versions are in the package list, so they are not an input and they are not in the
artifact's bytes (a check proves that). Putting them in the record keeps the answer to "why these
versions?" without making two builds of the same package set differ.

## resolvedDependencies

Everything the build read, in a fixed order. An entry has a `name` or a `uri`, and a `digest`.
Entries that do not apply to a build are left out; the ones that do apply never change their
position.

1. **The definition commit**, when the definition's repository is known:
   `{"uri": "git+https://host/path@<commit>", "digest": {"gitCommit": "<commit>"}}`.
2. **`lock.json`**: `{"name": "lock.json", "digest": {"sha256": ...}}`, the lock file's own digest.
3. **Each locked download the image uses**, in alphabetical order of the lock entry's name:
   `{"name": "<entry>", "uri": "<the rendered download address>", "digest": {...}}`. A verifier
   can fetch the address and compare the digest.
4. **`recipe of <image>`**: the sha256 of the image's recipe, the part of the identity made from
   the definition, the hooks, the modules, the parameters and the engine.
5. **Each suite's `InRelease`** (`uri` and sha256): the signed index the packages were resolved
   against, one per suite and archive (for example the main archive and the security archive), each
   at its own archive's snapshot, as `buildSnapshots` names it.
6. **The builder image**: `oci://<name>` with the sha256 of the container image the build ran in.
7. **`parent: <name>`**, for a child image only: the sha256 of the parent artifact the child was
   built on, so ancestry can be proved from the record alone.

## runDetails

| Field | Meaning |
|---|---|
| `builder.id` | Who ran the build. Under GitHub Actions it is `<server>/<workflow ref>`, for example `https://github.com/example/images/.github/workflows/images.yml@refs/heads/main`. Anywhere else (a laptop, another CI) it is this page's address followed by `#local`: the record says plainly that no CI platform stands behind it. Nothing about the machine, such as its name, its user or its paths, is ever recorded. |
| `builder.version` | `{"debian-image-factory": "<release>"}`: the factory release that ran. |
| `metadata.invocationId` | The CI run, as `<server>/<repository>/actions/runs/<run id>/attempts/<attempt>`. Absent for a local build. |
| `metadata.startedOn`, `metadata.finishedOn` | UTC times, `2026-11-21T02:17:05Z`. A lookup that finds several artifacts of one identity prefers the one that finished last. |

## What a record does and does not promise

This is SLSA Build L1 provenance: the factory writes it as part of the build, and it is complete and
machine readable. It is not signed by the build platform, so it does not by itself prove that the
build ran where it says. Envelopes are unsigned by default (`"signatures": []`); from 0.7.0, `--sign keyless`
or `--sign key:<...>` adds a signature without changing any field described here. A CI platform that
generates and signs its own attestation can add it beside this one, and that one carries whatever
level the platform claims.

A record never holds a secret, a private key, a token or a machine identity. It describes bits; what
is running somewhere is for the running system to say.
