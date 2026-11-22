# Security policy

## Reporting a vulnerability

Please report it privately, through GitHub's private vulnerability reporting: open this repository's
**Security** tab, choose **Report a vulnerability**, and describe what you found. Please do not open a
public issue or pull request for it.

A report helps most when it says which release you ran (`debian-image-factory --version`), what you did,
what you expected and what happened, and, when you can, a minimal definition or lock that shows it.

We aim to reply within a week. This is a small project: that is a goal, not a promise of a fix date.

## What is in scope

- The `debian-image-factory` tool and its `.pyz` release: reading definitions, locks and archive data,
  resolving, fetching and verifying inputs, and the records it writes.
- Anything that lets a build, a mirror, a registry, a release listing or a downloaded file make the factory
  run code, write outside its work and output directories, skip a signature or checksum check, or put a
  secret or a machine identity into an image.
- The GitHub Action in `action.yml` and the workflows in `.github/workflows/`: for example a step that
  leaks a token or can be steered by a pull request from a fork.
- The release artifacts: the `.pyz`, its `.sha256`, its Sigstore bundle and the builder image, including
  a signature that does not verify as the documentation says it should.

## What is not

- Vulnerabilities in Debian packages, in the tools the builder image takes from Debian, or in other
  projects the factory calls (mmdebstrap, Docker, Incus, QEMU, a registry). Report those upstream. We do
  want to hear when the factory should refuse or flag something because of one.
- The contents of images you build: what you put in your definition is yours to review.
- Findings that need a machine you already control, or that depend on running the factory with
  untrusted input in a way its documentation says not to.

## Supported versions

Only the latest release gets fixes.
