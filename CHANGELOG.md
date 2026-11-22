# Changelog

## 0.6.3 (not yet tagged)

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
