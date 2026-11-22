# Changelog

## 0.6.3 (not yet tagged)

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
