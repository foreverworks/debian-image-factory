# Changelog

## Unreleased

- A release publishes the boot checks' container image (`builder/vm.Dockerfile`, what `scripts/builder vm` builds) to
  `ghcr.io/<owner>/debian-image-factory-vm`, tagged `vX.Y.Z`, signed by digest with the same keyless Sigstore
  identity as the builder image, and the release notes name it by digest. Pull it and run
  `test --vm-image ghcr.io/<owner>/debian-image-factory-vm:vX.Y.Z@sha256:<digest>`.
- When the boot checks' image is missing and `--vm-image` names a reference with a digest, the `not run` message now
  says to `docker pull` it (`scripts/builder vm` still builds the local one). `test` never pulls it for you.
- DESIGN 16.2 now says what it always meant: no ready-made Debian images before 1.0, while the builder and VM
  containers, which are tools, are published with each release.

## 0.8.0 (2026-11-23)

- The `debian` and `debian-security` archives are pinned separately, so a Debian security fix can be built with as
  soon as its own archive lists it, instead of after a later snapshot of the security archive (a median of 30
  minutes, and 42 hours at the worst, 1 September to 23 November 2026). A snapshot ID that an archive itself lists always serves itself
  and is complete, so each archive's ID only has to be listed by that archive.
- The lock has `debian_snapshots`, an exact ID per archive, which needs `"schema": 3` and input-lock 0.3.0 (the
  factory pins it now). `debian_snapshot`, one ID for both archives, is still read: each archive then serves the
  snapshot it lists at or before that ID, under the stricter rule that every archive lists a later one.
  **To migrate, run `lock snapshot --latest`**: it writes `debian_snapshots` and removes `debian_snapshot`.
  Release 0.7.0 refuses a schema 3 lock, so move the factory pin in the lock first (the Action reads it).
- `lock snapshot --id` takes a bare ID or `archive=ID` (repeat it to move several archives; an archive that is not
  named keeps what the lock holds, or what the old ID served). `plan --snapshot` takes `lock`, `latest` (now the
  newest ID each archive lists), a bare ID, or `debian=ID,debian-security=ID`; a missing or unknown archive is a
  usage error. `lock check` says per archive which snapshot it is and whether it is completed. The baseline is
  unchanged: one ID, under the stricter rule.
- An ID that the cached listing does not show yet (snapshot.debian.org caches a listing for ten minutes) is
  confirmed with a narrow read of just that ID before it is refused. An ID an archive does not list stops the
  command and names the archive, and a package that cannot be resolved names both IDs.
- `plan.json` is schema 2: `snapshots` (an ID per archive) replaces `snapshot`, and a schema 1 plan is refused with
  a message to plan again. The bundle manifest is schema 2 (`snapshots`); a bundle made by 0.7.0 or earlier is
  refused, so fetch again. The partial mirror is `<cache>/mirror/<debian ID>_<debian-security ID>/<archive>/`; what
  the builder sees, the artifacts' bytes and every identity are unchanged, and the engine revision does not move.
- Provenance is written under [build type v2](docs/build-type-v2.md): `internalParameters.buildSnapshots` replaces
  `buildSnapshot`, and each `InRelease` address carries its own archive's ID. `verify` accepts v1 and v2 records;
  0.7.0 and earlier accept v1 only, so a verifier moves to 0.8.0 before it meets records 0.8.0 wrote.
- `no-build-snapshot` looks for both build snapshot IDs. An ID equal to the baseline's still only warns, and the other
  ID is still searched.
- `scripts/spike-core` takes `--debian ID --debian-security ID` as well as `--snapshot ID`.

## 0.7.0 (2026-11-23)

- Laying out the shared mirror publishes every file by an atomic rename, so parallel builds and test processes sharing one
  snapshot directory no longer fail with "two different InRelease files" when one reads a file another is writing.
- The boot checks' guest writes its `FACTORY-REPORT` line to its own serial port (`ttyS1`) instead of the console, where a
  kernel message printed at the same moment could split the line and fail a boot that had worked. A boot with no
  report now names QEMU's exit status and any half-written report line.
- `publish --sign keyless` and `--sign key:<path or KMS URI>` sign each record with cosign 3.1.4 (DESIGN 8.3): the
  statement is signed as a DSSE payload with `cosign attest-blob --statement`, and the envelope keeps the payload
  and fills `signatures` with the signature and its Sigstore bundle's verification material. Keyless uses the CI's
  OIDC identity and the public Rekor log; a key's signature goes to no log. A record a target already holds is
  not signed again. `verify` checks signatures with `--key`, or `--certificate-identity` and
  `--certificate-oidc-issuer` (and their `-regexp` forms), and `--require-signature` refuses an unsigned record.
  The Action installs cosign (`sigstore/cosign-installer`, pinned) when `sign` is not `none`.
- `build` builds images that do not depend on each other at the same time: an image waits for its parent and
  siblings run together, as many as the CPUs allow, held back by free memory at 1 GiB a build (the test runner's
  sizing rule, now one function shared in `capacity.py`). `--jobs N` sets the pool, `--jobs 1` builds one image
  after another as before; the Action passes its `jobs` input as `--jobs`. Output lines start with the image's
  name; when images fail, nothing new starts, the running ones finish, and every failure is reported by name.
  Artifacts, digests and records are the same as a serial build's.
- A signed publish to a target that already holds some of the records unsigned prints a warning with their count and
  why they stay unsigned (a published record is never rewritten); `publish --require-signed-target` fails instead.
  A line in a target's records file or a registry referrer that is not a record is skipped with a warning naming its
  file and line, or its referrer digest, as an unsigned publish already leaves it alone, instead of failing the publish.
- Two images of one build whose artifacts have the same digest write their shared records file under a lock, through a
  temporary file renamed into place, and merge their records instead of the last writer winning.
- Ctrl-C during a build stops the running builder containers by their own ids, starts no other image, and exits non-zero
  with a message; the images that had finished keep their artifacts.
- The Action stops before it installs cosign, with a message, when `sign` is not `none` and the release your lock pins
  is older than 0.7.0, and stops the same way for `jobs`.

## 0.6.3 (2026-11-22)

- A workflow rewrites the checksum of the input-lock entry on Renovate's branches, so its pull requests no longer
  carry a stale `sha256`.
- `publish --image NAME` publishes only the images it names.
- `{image}` in the repository of an `oci://` target is the name of an image, and means the same in every command
  that takes a target. `publish --to`, `plan --against`, `build --parents`, `test --parents` and `prune --against`
  resolve the target with the name of the image they are looking at, so one string such as
  `oci://ghcr.io/example/{image}` works everywhere. It is refused outside the repository of an `oci://` target.
- `test --parents oci://REGISTRY/REPOSITORY` reads the manifest of an OCI parent that is not in `out/`, so the
  `ancestry` check of its child runs.
- `plan.json` names each artifact as `sha256:<hex>`.
- The Action's `build` step passes each `oci://` and `dir://` line of `against` as `--parents`, and its `test` step
  each `oci://` line, so a night on which only a child moved finds its reused parent.
