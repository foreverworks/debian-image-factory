"""OCI images: descriptors, image configs, manifests, indexes and referrers (DESIGN 8.1, 8.2, 7.4). Pure.

Everything here is bytes and values in, bytes and values out; writing a layout directory or talking
to a registry is `ocilayout`'s and `registry`'s job.

Rules this module fixes:

- Manifests, configs and indexes are canonical JSON (sorted keys, no whitespace, UTF-8), so the same
  values always give the same digest.
- An image config carries no build time: no `created`, no `history`.
- A child's config is its parent's with the child's own `oci` table laid over it: `env` and
  `labels` merge key by key, `user`, `workdir`, `entrypoint` and `cmd` replace. Setting `entrypoint`
  without `cmd` clears the inherited `cmd`, as a Dockerfile's ENTRYPOINT does.
- Every published image carries the tag `identity-<identity>` (7.4); a registry without the
  referrers API holds an image's records in the index tagged `sha256-<manifest digest>` (8.2).
"""

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

from input_lock import JsonValue
from input_lock.identity import HEX64

# ---- media types and annotations ----------------------------------------------------------------

MANIFEST: Final = "application/vnd.oci.image.manifest.v1+json"
INDEX: Final = "application/vnd.oci.image.index.v1+json"
CONFIG: Final = "application/vnd.oci.image.config.v1+json"
LAYER_GZIP: Final = "application/vnd.oci.image.layer.v1.tar+gzip"
EMPTY: Final = "application/vnd.oci.empty.v1+json"
DSSE_ENVELOPE: Final = "application/vnd.dsse.envelope.v1+json"
IN_TOTO_ARTIFACT: Final = "application/vnd.in-toto+json"
"""The `artifactType` of a referrer that carries one record (DESIGN 8.2)."""

EMPTY_BLOB: Final = b"{}"
EMPTY_DIGEST: Final = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
"""sha256 of the two-byte empty JSON object, as the image spec defines it."""

BASE_DIGEST: Final = "org.opencontainers.image.base.digest"
BASE_NAME: Final = "org.opencontainers.image.base.name"
SOURCE: Final = "org.opencontainers.image.source"
REVISION: Final = "org.opencontainers.image.revision"
IDENTITY: Final = "io.github.foreverworks.debian-image-factory.identity"
PREDICATE_TYPE: Final = "in-toto.io/predicate-type"
"""The annotation on a referrer's layer naming the predicate type of the record it carries."""

LAYOUT_EXT: Final = "oci"
"""A built OCI image is the directory `<image>-<suite>-<arch>-<identity16>-<digest12>.oci/` in the
build's output, an OCI image layout whose `index.json` names one manifest; the digest in the name is
that manifest's. Its records sit beside it in `<manifest digest>.intoto.jsonl`, as for files."""

ARCHITECTURES: Final[Mapping[str, str]] = {
    "amd64": "amd64",
    "arm64": "arm64",
    "armhf": "arm",
    "i386": "386",
    "ppc64el": "ppc64le",
    "riscv64": "riscv64",
    "s390x": "s390x",
}
"""Debian architecture to the OCI `architecture` field (Go's GOARCH names)."""

_DIGEST: Final = re.compile(r"sha256:([0-9a-f]{64})")


class OciError(ValueError):
    """A manifest, config, index or descriptor that is not what this module writes or accepts."""


# ---- values -------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Descriptor:
    """An OCI content descriptor. `digest` is the sha256 in hex, without the `sha256:` prefix."""

    media_type: str
    digest: str
    size: int
    annotations: Mapping[str, str] = field(default_factory=dict[str, str])
    artifact_type: str | None = None


@dataclass(frozen=True, slots=True)
class OciConfig:
    """What an image runs as: the parts of an image config's `config` the definition can set."""

    user: str | None = None
    entrypoint: tuple[str, ...] | None = None
    cmd: tuple[str, ...] | None = None
    env: tuple[tuple[str, str], ...] = ()
    """In order of first appearance, parents first; a child's value replaces its parent's in place."""
    workdir: str | None = None
    labels: tuple[tuple[str, str], ...] = ()
    """Sorted by key."""


@dataclass(frozen=True, slots=True)
class Manifest:
    """An image manifest, or an artifact manifest carrying one record."""

    config: Descriptor
    layers: tuple[Descriptor, ...]
    annotations: Mapping[str, str] = field(default_factory=dict[str, str])
    subject: Descriptor | None = None
    artifact_type: str | None = None


# ---- small helpers ------------------------------------------------------------------------------


def canonical(value: object) -> bytes:
    """Sorted keys, no whitespace, UTF-8: the bytes every manifest, config and index is written as."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def descriptor_of(media_type: str, data: bytes, annotations: Mapping[str, str] | None = None) -> Descriptor:
    """The descriptor of `data`."""
    return Descriptor(media_type, sha256_hex(data), len(data), dict(annotations or {}))


def digest_text(hex_digest: str) -> str:
    """`sha256:<hex>`, checking the hex."""
    if not HEX64.fullmatch(hex_digest):
        raise OciError(f"not a sha256 in hex: {hex_digest!r}")
    return f"sha256:{hex_digest}"


def parse_digest(text: object) -> str:
    """The hex of a `sha256:<hex>` digest. Other algorithms are refused: everything here is sha256."""
    if not isinstance(text, str) or (found := _DIGEST.fullmatch(text)) is None:
        raise OciError(f"not a sha256 digest: {text!r}")
    return found.group(1)


def identity_tag(identity: str) -> str:
    """`identity-<identity in full hex>`, 73 characters (DESIGN 7.4)."""
    if not HEX64.fullmatch(identity):
        raise OciError(f"identity is not 64 lowercase hex characters: {identity!r}")
    return f"identity-{identity}"


def referrers_tag(digest: str) -> str:
    """`sha256-<subject digest>`: the distribution spec's referrers tag schema (DESIGN 8.2)."""
    if not HEX64.fullmatch(digest):
        raise OciError(f"digest is not 64 lowercase hex characters: {digest!r}")
    return f"sha256-{digest}"


def oci_architecture(debian_arch: str) -> str:
    try:
        return ARCHITECTURES[debian_arch]
    except KeyError:
        raise OciError(f"no OCI architecture for the Debian architecture {debian_arch!r}") from None


# ---- descriptors --------------------------------------------------------------------------------


def descriptor_json(one: Descriptor) -> dict[str, JsonValue]:
    found: dict[str, JsonValue] = {"mediaType": one.media_type, "digest": digest_text(one.digest), "size": one.size}
    if one.annotations:
        found["annotations"] = dict(one.annotations)
    if one.artifact_type is not None:
        found["artifactType"] = one.artifact_type
    return found


def _strings(value: object, where: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise OciError(f"{where} must be an object of strings")
    return {str(k): str(v) for k, v in value.items()}


def parse_descriptor(value: object, where: str = "descriptor") -> Descriptor:
    if not isinstance(value, dict):
        raise OciError(f"{where} must be an object")
    media_type, size, artifact_type = value.get("mediaType"), value.get("size"), value.get("artifactType")
    if not isinstance(media_type, str) or not media_type:
        raise OciError(f"{where}.mediaType must be a string")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise OciError(f"{where}.size must be a non-negative integer")
    if artifact_type is not None and not isinstance(artifact_type, str):
        raise OciError(f"{where}.artifactType must be a string")
    return Descriptor(
        media_type,
        parse_digest(value.get("digest")),
        size,
        _strings(value.get("annotations"), f"{where}.annotations"),
        artifact_type,
    )


# ---- configs ------------------------------------------------------------------------------------


def _strings_of(value: JsonValue, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise OciError(f"oci.{key} must be a list of strings")
    return tuple(str(item) for item in value)


def _pairs_of(value: JsonValue, key: str) -> dict[str, str]:
    if not isinstance(value, dict) or not all(isinstance(item, str) for item in value.values()):
        raise OciError(f"oci.{key} must be a table of strings")
    return {name: str(item) for name, item in value.items()}


def merged_config(parent: OciConfig | None, table: Mapping[str, JsonValue]) -> OciConfig:
    """The config of an image whose parent runs as `parent` (None for an image whose parent is core)
    and whose definition has the `oci` table `table` (already validated by `definition`)."""
    base = parent if parent is not None else OciConfig()
    user, workdir = base.user, base.workdir
    entrypoint, cmd = base.entrypoint, base.cmd
    env = dict(base.env)
    labels = dict(base.labels)
    for key, value in table.items():
        if key == "user" or key == "workdir":
            if not isinstance(value, str):
                raise OciError(f"oci.{key} must be a string")
            user, workdir = (value, workdir) if key == "user" else (user, value)
        elif key == "entrypoint":
            entrypoint = _strings_of(value, key)
            if "cmd" not in table:
                cmd = None
        elif key == "cmd":
            cmd = _strings_of(value, key)
        elif key == "env":
            env.update(_pairs_of(value, key))
        elif key == "labels":
            labels.update(_pairs_of(value, key))
        else:
            raise OciError(f"oci: unknown key {key!r}")
    return OciConfig(user, entrypoint, cmd, tuple(env.items()), workdir, tuple(sorted(labels.items())))


def config_json(config: OciConfig) -> dict[str, JsonValue]:
    """The image config's `config` object: only what is set."""
    found: dict[str, JsonValue] = {}
    if config.user is not None:
        found["User"] = config.user
    if config.entrypoint is not None:
        found["Entrypoint"] = list(config.entrypoint)
    if config.cmd is not None:
        found["Cmd"] = list(config.cmd)
    if config.env:
        found["Env"] = [f"{name}={value}" for name, value in config.env]
    if config.workdir is not None:
        found["WorkingDir"] = config.workdir
    if config.labels:
        found["Labels"] = dict(config.labels)
    return found


def image_config(config: OciConfig, diff_ids: Sequence[str], debian_arch: str) -> bytes:
    """The image config blob: architecture, os, what it runs as, and the uncompressed layer digests,
    base first. No build time."""
    return canonical(
        {
            "architecture": oci_architecture(debian_arch),
            "os": "linux",
            "config": config_json(config),
            "rootfs": {"type": "layers", "diff_ids": [digest_text(one) for one in diff_ids]},
        }
    )


def parse_config(data: bytes) -> tuple[OciConfig, tuple[str, ...]]:
    """What an image config says the image runs as, and its diff IDs in hex. Keys this module does not
    write are ignored, so a parent built elsewhere still reads."""
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OciError(f"image config is not JSON: {error}") from None
    if not isinstance(value, dict):
        raise OciError("image config must be an object")
    rootfs = value.get("rootfs")
    if not isinstance(rootfs, dict) or rootfs.get("type") != "layers" or not isinstance(rootfs.get("diff_ids"), list):
        raise OciError("image config rootfs must be {type: layers, diff_ids: [...]}")
    diff_ids = tuple(parse_digest(one) for one in rootfs["diff_ids"])
    inner = value.get("config") or {}
    if not isinstance(inner, dict):
        raise OciError("image config's config must be an object")

    def text(key: str) -> str | None:
        found = inner.get(key)
        if found is not None and not isinstance(found, str):
            raise OciError(f"image config {key} must be a string")
        return found or None

    def strings(key: str) -> tuple[str, ...] | None:
        found = inner.get(key)
        if found is None:
            return None
        if not isinstance(found, list) or not all(isinstance(item, str) for item in found):
            raise OciError(f"image config {key} must be a list of strings")
        return tuple(found)

    env: list[tuple[str, str]] = []
    for item in strings("Env") or ():
        name, _, rest = item.partition("=")
        env.append((name, rest))
    labels = _strings(inner.get("Labels"), "image config Labels")
    config = OciConfig(
        text("User"),
        strings("Entrypoint"),
        strings("Cmd"),
        tuple(env),
        text("WorkingDir"),
        tuple(sorted(labels.items())),
    )
    return config, diff_ids


# ---- manifests ----------------------------------------------------------------------------------


def manifest_json(manifest: Manifest) -> dict[str, JsonValue]:
    found: dict[str, JsonValue] = {
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": descriptor_json(manifest.config),
        "layers": [descriptor_json(one) for one in manifest.layers],
    }
    if manifest.annotations:
        found["annotations"] = dict(manifest.annotations)
    if manifest.subject is not None:
        found["subject"] = descriptor_json(manifest.subject)
    if manifest.artifact_type is not None:
        found["artifactType"] = manifest.artifact_type
    return found


def image_manifest(config: Descriptor, layers: Sequence[Descriptor], annotations: Mapping[str, str]) -> bytes:
    """An image manifest: its config, its layers base first, and the annotations of DESIGN 8.1."""
    return canonical(manifest_json(Manifest(config, tuple(layers), dict(annotations))))


def image_annotations(
    *,
    identity: str,
    base_digest: str | None,
    base_name: str | None,
    source: str | None,
    revision: str | None,
) -> dict[str, str]:
    """DESIGN 8.1's annotations. `base_digest` is the parent artifact's digest in hex (core's tarball
    sha256, or an OCI parent's manifest digest) and `base_name` its artifact name; `source` and
    `revision` are the definition's repository and commit, when it has them."""
    found = {IDENTITY: identity}
    if base_digest is not None:
        found[BASE_DIGEST] = digest_text(base_digest)
    if base_name is not None:
        found[BASE_NAME] = base_name
    if source is not None:
        found[SOURCE] = source
    if revision is not None:
        found[REVISION] = revision
    return found


def parse_manifest(data: bytes) -> Manifest:
    """An image or artifact manifest. An index or a Docker schema 2 manifest is refused by media type."""
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OciError(f"manifest is not JSON: {error}") from None
    if not isinstance(value, dict):
        raise OciError("manifest must be an object")
    if value.get("schemaVersion") != 2 or value.get("mediaType") != MANIFEST:
        raise OciError(f"not an OCI image manifest (mediaType {value.get('mediaType')!r})")
    layers = value.get("layers")
    if not isinstance(layers, list):
        raise OciError("manifest layers must be a list")
    artifact_type = value.get("artifactType")
    if artifact_type is not None and not isinstance(artifact_type, str):
        raise OciError("manifest artifactType must be a string")
    subject = value.get("subject")
    return Manifest(
        parse_descriptor(value.get("config"), "config"),
        tuple(parse_descriptor(one, f"layers[{index}]") for index, one in enumerate(layers)),
        _strings(value.get("annotations"), "annotations"),
        None if subject is None else parse_descriptor(subject, "subject"),
        artifact_type,
    )


# ---- referrers ----------------------------------------------------------------------------------


def referrer_manifest(envelope: bytes, predicate_type: str, subject: Descriptor) -> tuple[bytes, Descriptor]:
    """The artifact manifest that carries one record (a DSSE envelope) as a referrer of `subject`, and
    the descriptor of the envelope blob it names (DESIGN 8.2)."""
    blob = descriptor_of(DSSE_ENVELOPE, envelope, {PREDICATE_TYPE: predicate_type})
    manifest = Manifest(
        Descriptor(EMPTY, EMPTY_DIGEST, len(EMPTY_BLOB)),
        (blob,),
        subject=Descriptor(subject.media_type, subject.digest, subject.size),
        artifact_type=IN_TOTO_ARTIFACT,
    )
    return canonical(manifest_json(manifest)), blob


def referrer_descriptor(manifest_bytes: bytes) -> Descriptor:
    """How a referrer is listed in a referrers index: its digest, size, artifactType and the predicate
    type annotation of the record it carries."""
    manifest = parse_manifest(manifest_bytes)
    annotations = (
        {PREDICATE_TYPE: manifest.layers[0].annotations[PREDICATE_TYPE]}
        if (manifest.layers and PREDICATE_TYPE in manifest.layers[0].annotations)
        else {}
    )
    return Descriptor(
        MANIFEST,
        sha256_hex(manifest_bytes),
        len(manifest_bytes),
        annotations,
        manifest.artifact_type or manifest.config.media_type,
    )


def index(manifests: Sequence[Descriptor]) -> bytes:
    """An image index listing `manifests` in order."""
    return canonical({"schemaVersion": 2, "mediaType": INDEX, "manifests": [descriptor_json(one) for one in manifests]})


def parse_index(data: bytes) -> tuple[Descriptor, ...]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OciError(f"index is not JSON: {error}") from None
    if not isinstance(value, dict) or value.get("schemaVersion") != 2:
        raise OciError("not an OCI image index")
    media_type = value.get("mediaType")
    if media_type is not None and media_type != INDEX:
        raise OciError(f"not an OCI image index (mediaType {media_type!r})")
    manifests = value.get("manifests")
    if not isinstance(manifests, list):
        raise OciError("index manifests must be a list")
    return tuple(parse_descriptor(one, f"manifests[{position}]") for position, one in enumerate(manifests))


def merged_referrers(present: bytes | None, added: Descriptor) -> bytes:
    """The referrers tag index after attaching `added`: what `present` lists (nothing when the tag does
    not exist yet), then `added` unless it is already listed. One step of the serialized
    read-modify-write of DESIGN 8.2: the caller re-reads `present` right before each write."""
    held = list(parse_index(present)) if present is not None else []
    if all(one.digest != added.digest for one in held):
        held.append(added)
    return index(held)
