"""The registry edge: the OCI distribution API, version 1.1, over urllib (DESIGN 7.4, 8.2).

Nothing else in the package talks to a registry. What this module guarantees to its callers:

- **Every byte read is checked.** A manifest is hashed and a blob is streamed through sha256 against
  the digest the caller asked for; a mismatch raises `DigestMismatchError`. Reads are bounded (a manifest
  or an index to `MANIFEST_LIMIT`, a blob to the size its descriptor states), and every request has a
  timeout.
- **http only for the machine itself.** `localhost`, `127.0.0.1` and `[::1]` are spoken to over http,
  every other registry over https; a token realm or an upload location that leaves that rule or the
  registry's own host is refused.
- **Credentials stay in this module.** They come from the Docker config (`$DOCKER_CONFIG/config.json`
  or `~/.docker/config.json`: an `auths` entry, a `credHelpers` entry or `credsStore`), a bearer token
  is fetched from the challenge's realm, and neither is printed, logged or put in an error message.
  Authorization is sent as an unredirected header, so a redirect to a blob store never carries it.
- **A registry without the referrers API still works.** `referrers_of` asks the API and, when the
  registry answers 404, reads the referrers tag `sha256-<digest>` (the distribution spec's tag schema);
  writing is `publish`'s: it updates that index when a manifest PUT does not answer `OCI-Subject`.
"""

import base64
import binascii
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Final, Literal

from . import oci, ocilayout
from .published import OciTarget, parse_target

MANIFEST_LIMIT: Final = 4 * 1024 * 1024
"""The largest manifest or index read: the size every registry must accept (distribution spec)."""

ENVELOPE_LIMIT: Final = 64 * 1024 * 1024
"""The largest record (DSSE envelope) read into memory; an SBOM of a big image is a few megabytes."""

TIMEOUT: Final = 60.0
"""Seconds a request may wait for its next byte, set on every one."""

MAX_PAGES: Final = 100
USER_AGENT: Final = "debian-image-factory"
LOCAL_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "[::1]"})
DOCKER_HUB: Final = ("docker.io", "index.docker.io", "registry-1.docker.io")
ACCEPT_MANIFESTS: Final = f"{oci.MANIFEST}, {oci.INDEX}"

_PARAM: Final = re.compile(r'([A-Za-z_]+)="([^"]*)"')
_NEXT: Final = re.compile(r'<([^>]*)>\s*;\s*rel="?next"?')
_HELPER: Final = re.compile(r"[A-Za-z0-9._-]+")
_PORT: Final = re.compile(r":[0-9]+$")
_REFERENCE: Final = re.compile(
    r"oci://(?P<registry>[^/@]+)/(?P<repository>[^@:]+)(?:@sha256:(?P<digest>[0-9a-f]{64})|:(?P<tag>[^\s/@:]+))"
)


class RegistryError(OSError):
    """A registry that cannot be reached or answered something this module cannot accept. It is an
    OSError so a command reports it the way it reports an unreadable directory."""


class DigestMismatchError(RegistryError):
    """Bytes a registry served that do not hash to the digest they were asked for."""


# ---- references -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Reference:
    """`oci://<registry>/<repository>@sha256:<hex>` (`digest`) or `oci://<registry>/<repository>:<tag>`."""

    registry: str
    repository: str
    digest: str | None
    tag: str | None

    @property
    def target(self) -> OciTarget:
        return OciTarget(self.registry, self.repository)


def parse_reference(text: str) -> Reference | None:
    """The parts of an `oci://` image reference, or None when `text` is not one."""
    found = _REFERENCE.fullmatch(text)
    if found is None:
        return None
    try:
        parse_target(f"oci://{found['registry']}/{found['repository']}")
    except ValueError:
        return None
    return Reference(found["registry"], found["repository"], found["digest"], found["tag"])


def registry_host(registry: str) -> str:
    """The host of `registry` without its port, brackets kept for IPv6 (`[::1]`)."""
    if registry.startswith("["):
        return registry.partition("]")[0] + "]"
    return _PORT.sub("", registry)


def is_local(registry: str) -> bool:
    return registry_host(registry) in LOCAL_HOSTS


def base_url(registry: str) -> str:
    """Where the registry's API lives: http on this machine, https everywhere else."""
    if is_local(registry):
        return f"http://{registry}"
    if registry in DOCKER_HUB:
        return "https://registry-1.docker.io"
    return f"https://{registry}"


# ---- credentials ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Credentials:
    username: str
    password: str = field(repr=False)


def config_keys(registry: str) -> tuple[str, ...]:
    """The names a Docker config may list `registry` under."""
    if registry in DOCKER_HUB:
        return ("https://index.docker.io/v1/", "index.docker.io", "docker.io", "registry-1.docker.io")
    return (registry, f"https://{registry}", f"http://{registry}")


def _credentials_of(entry: object) -> Credentials | None:
    if not isinstance(entry, dict):
        return None
    auth = entry.get("auth")
    if isinstance(auth, str) and auth:
        try:
            user, colon, password = base64.b64decode(auth, validate=True).decode("utf-8").partition(":")
        except (binascii.Error, UnicodeDecodeError):
            return None
        return Credentials(user, password) if colon else None
    name, secret = entry.get("username"), entry.get("password")
    if isinstance(name, str) and isinstance(secret, str) and name:
        return Credentials(name, secret)
    return None


def credential_plan(config: object, registry: str) -> tuple[Credentials | None, str | None]:
    """What a parsed Docker config says about `registry`: credentials it holds itself, or the name of
    the credential helper that holds them (`credHelpers`, then `credsStore`)."""
    if not isinstance(config, dict):
        return None, None
    keys = config_keys(registry)
    auths = config.get("auths")
    if isinstance(auths, dict):
        for key in keys:
            found = _credentials_of(auths.get(key))
            if found is not None:
                return found, None
    helpers = config.get("credHelpers")
    if isinstance(helpers, dict):
        for key in keys:
            helper = helpers.get(key)
            if isinstance(helper, str) and _HELPER.fullmatch(helper):
                return None, helper
    store = config.get("credsStore")
    if isinstance(store, str) and _HELPER.fullmatch(store):
        return None, store
    return None, None


def docker_config_path(env: Mapping[str, str]) -> Path:
    directory = env.get("DOCKER_CONFIG")
    if directory:
        return Path(directory) / "config.json"
    return Path(env.get("HOME") or Path.home()) / ".docker" / "config.json"


def docker_credentials(registry: str, environ: Mapping[str, str] | None = None) -> Credentials | None:
    """The credentials the Docker config holds for `registry`, asking `docker-credential-<name> get`
    when it points at a helper. None when there are none (an anonymous request is then made)."""
    env = dict(os.environ if environ is None else environ)
    try:
        config: object = json.loads(docker_config_path(env).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    direct, helper = credential_plan(config, registry)
    if direct is not None or helper is None:
        return direct
    program = shutil.which(f"docker-credential-{helper}", path=env.get("PATH"))
    if program is None:
        return None
    try:
        run = subprocess.run(
            [program, "get"],
            input=config_keys(registry)[0],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=env,
        )
        answer: object = json.loads(run.stdout) if run.returncode == 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if isinstance(answer, dict):
        user, secret = answer.get("Username"), answer.get("Secret")
        if isinstance(user, str) and isinstance(secret, str) and user and user != "<token>":
            return Credentials(user, secret)
    return None


def basic_header(credentials: Credentials) -> str:
    return "Basic " + base64.b64encode(f"{credentials.username}:{credentials.password}".encode()).decode("ascii")


# ---- challenges -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Challenge:
    scheme: Literal["bearer", "basic"]
    params: Mapping[str, str]


def pick_challenge(headers: Sequence[str]) -> Challenge | None:
    """The `WWW-Authenticate` challenge to answer: a Bearer one when offered, else Basic."""
    bearer: Challenge | None = None
    basic: Challenge | None = None
    for header in headers:
        scheme, _, rest = header.strip().partition(" ")
        params = dict(_PARAM.findall(rest))
        if scheme.lower() == "bearer" and bearer is None:
            bearer = Challenge("bearer", params)
        elif scheme.lower() == "basic" and basic is None:
            basic = Challenge("basic", params)
    return bearer or basic


# ---- the client -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Client:
    """One registry and repository, and what has been learned about authenticating to it. The two
    dictionaries are the only state: `grants` holds authorization headers (never printed) and
    `cache` the credentials, looked up at most once."""

    registry: str
    repository: str
    base: str
    credentials_for: Callable[[str], Credentials | None] = field(repr=False)
    timeout: float
    grants: dict[str, str] = field(default_factory=dict[str, str], repr=False)
    cache: dict[str, Credentials | None] = field(default_factory=dict[str, Credentials | None], repr=False)

    @property
    def name(self) -> str:
        return f"oci://{self.registry}/{self.repository}"


def connect(
    target: OciTarget,
    *,
    credentials: Callable[[str], Credentials | None] = docker_credentials,
    timeout: float = TIMEOUT,
) -> Client:
    return Client(target.registry, target.repository, base_url(target.registry), credentials, timeout)


def _credentials(client: Client) -> Credentials | None:
    if client.registry not in client.cache:
        client.cache[client.registry] = client.credentials_for(client.registry)
    return client.cache[client.registry]


def _same_origin(client: Client, url: str) -> bool:
    return urllib.parse.urlsplit(url).netloc == urllib.parse.urlsplit(client.base).netloc


def _opener(url: str) -> urllib.request.OpenerDirector:
    """The default opener (which honours the proxy variables), without a proxy for this machine."""
    if is_local(urllib.parse.urlsplit(url).netloc):
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener()


type Body = bytes | BinaryIO | None
type Answer = http.client.HTTPResponse | urllib.error.HTTPError


def _grant(client: Client, write: bool) -> str | None:
    if "basic" in client.grants:
        return client.grants["basic"]
    if write:
        return client.grants.get("push")
    return client.grants.get("pull") or client.grants.get("push")


def _token(client: Client, challenge: Challenge, write: bool) -> str | None:
    """Answer a Bearer challenge: the token from its realm, fetched with the Docker config's credentials
    when there are any, anonymously otherwise. None when the realm is not one this client may ask."""
    realm = challenge.params.get("realm", "")
    parts = urllib.parse.urlsplit(realm)
    if not (parts.scheme == "https" or (parts.scheme == "http" and is_local(parts.netloc))):
        return None
    query: dict[str, str] = {}
    if "service" in challenge.params:
        query["service"] = challenge.params["service"]
    query["scope"] = challenge.params.get("scope") or (
        f"repository:{client.repository}:{'pull,push' if write else 'pull'}"
    )
    url = realm + ("&" if parts.query else "?") + urllib.parse.urlencode(query)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    found = _credentials(client)
    if found is not None:
        request.add_unredirected_header("Authorization", basic_header(found))
    try:
        with closing(_opener(url).open(request, timeout=client.timeout)) as response:
            answer: object = json.loads(response.read(MANIFEST_LIMIT))
    except urllib.error.HTTPError as error:
        raise RegistryError(f"{client.registry}: its token service answered HTTP {error.code}") from None
    except ValueError:
        raise RegistryError(f"{client.registry}: its token service did not answer JSON") from None
    if isinstance(answer, dict):
        for key in ("token", "access_token"):
            value = answer.get(key)
            if isinstance(value, str) and value:
                return value
    raise RegistryError(f"{client.registry}: its token service gave no token")


def _authenticate(client: Client, challenge: Challenge, write: bool) -> bool:
    if challenge.scheme == "basic":
        found = _credentials(client)
        if found is None:
            return False
        client.grants["basic"] = basic_header(found)
        return True
    token = _token(client, challenge, write)
    if token is None:
        return False
    client.grants["push" if write else "pull"] = f"Bearer {token}"
    return True


def _open(client: Client, method: str, url: str, headers: Mapping[str, str], body: Body, write: bool) -> Answer:
    """Send one request, answering one 401 challenge. The response is returned whatever its status;
    a network failure raises OSError."""
    for attempt in (0, 1):
        request = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": USER_AGENT, **headers})
        grant = _grant(client, write)
        if grant is not None:
            request.add_unredirected_header("Authorization", grant)
        try:
            response: Answer = _opener(url).open(request, timeout=client.timeout)
        except urllib.error.HTTPError as error:
            response = error
        if response.status == 401 and attempt == 0:
            challenge = pick_challenge(response.headers.get_all("WWW-Authenticate") or [])
            if challenge is not None and _authenticate(client, challenge, write):
                response.close()
                if body is not None and not isinstance(body, bytes):
                    body.seek(0)
                continue
        return response
    raise AssertionError("unreachable")  # pragma: no cover


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    headers: Mapping[str, str]
    """Lower-case names."""
    body: bytes


def _call(
    client: Client,
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: Body = None,
    write: bool = False,
    limit: int = MANIFEST_LIMIT,
) -> Response:
    """One request, its body read in full up to `limit` bytes."""
    response = _open(client, method, url, headers or {}, body, write)
    with closing(response):
        data = response.read(limit + 1)
        if len(data) > limit:
            raise RegistryError(f"{client.registry}: an answer to {method} was larger than {limit} bytes")
        status = response.status
        assert status is not None  # a response that came back has a status line
        return Response(status, {name.lower(): value for name, value in response.headers.items()}, data)


def _refusal(client: Client, what: str, response: Response) -> RegistryError:
    detail = ""
    try:
        answer: object = json.loads(response.body)
        errors = answer.get("errors") if isinstance(answer, dict) else None
        if isinstance(errors, list) and errors and isinstance(errors[0], dict):
            code, message = errors[0].get("code"), errors[0].get("message")
            detail = f" ({code}: {message})" if isinstance(code, str) and isinstance(message, str) else ""
    except ValueError:
        pass
    return RegistryError(f"{client.name}: {what}: HTTP {response.status}{detail}")


def _url(client: Client, tail: str) -> str:
    return f"{client.base}/v2/{client.repository}/{tail}"


# ---- blobs ------------------------------------------------------------------------------------


def blob_exists(client: Client, digest: str) -> bool:
    response = _call(client, "HEAD", _url(client, f"blobs/{oci.digest_text(digest)}"), limit=0)
    if response.status == 200:
        return True
    if response.status == 404:
        return False
    raise _refusal(client, f"blob {digest[:12]} lookup", response)


def put_blob(client: Client, digest: str, size: int, source: bytes | Path) -> None:
    """Upload one blob monolithically: POST for an upload location, then PUT the bytes to it with
    `?digest=`. The location may be relative or absolute but must stay on the registry's host."""
    started = _call(client, "POST", _url(client, "blobs/uploads/"), headers={"Content-Length": "0"}, write=True)
    if started.status != 202 or "location" not in started.headers:
        raise _refusal(client, "starting an upload", started)
    location = urllib.parse.urljoin(_url(client, "blobs/uploads/"), started.headers["location"])
    if not _same_origin(client, location):
        raise RegistryError(f"{client.name}: it answered an upload location on another host")
    parts = urllib.parse.urlsplit(location)
    query = urllib.parse.urlencode([*urllib.parse.parse_qsl(parts.query), ("digest", oci.digest_text(digest))])
    url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    headers = {"Content-Type": "application/octet-stream", "Content-Length": str(size)}
    if isinstance(source, bytes):
        finished = _call(client, "PUT", url, headers=headers, body=source, write=True)
    else:
        with source.open("rb") as handle:
            finished = _call(client, "PUT", url, headers=headers, body=handle, write=True)
    if finished.status != 201:
        raise _refusal(client, f"uploading blob {digest[:12]}", finished)


def fetch_blob(client: Client, descriptor: oci.Descriptor, limit: int) -> bytes:
    """A blob in memory, at most `limit` bytes, checked against the descriptor's size and digest."""
    if descriptor.size > limit:
        raise RegistryError(f"{client.name}: blob sha256:{descriptor.digest} is {descriptor.size} bytes, over {limit}")
    url = _url(client, f"blobs/{oci.digest_text(descriptor.digest)}")
    response = _call(client, "GET", url, limit=descriptor.size)
    if response.status != 200:
        raise _refusal(client, f"reading blob {descriptor.digest[:12]}", response)
    if len(response.body) != descriptor.size or oci.sha256_hex(response.body) != descriptor.digest:
        raise DigestMismatchError(f"{client.name}: blob sha256:{descriptor.digest} does not match its digest")
    return response.body


def download_blob(client: Client, descriptor: oci.Descriptor, destination: Path) -> None:
    """Stream a blob to `destination` (a new file), through sha256, refusing more bytes than its
    descriptor says and a result that does not match; nothing is left behind on a failure."""
    url = _url(client, f"blobs/{oci.digest_text(descriptor.digest)}")
    response = _open(client, "GET", url, {}, None, False)
    temporary = destination.with_name(destination.name + ".partial")
    try:
        with closing(response), temporary.open("wb") as handle:
            if response.status != 200:
                raise RegistryError(f"{client.name}: reading blob {descriptor.digest[:12]}: HTTP {response.status}")
            hasher = hashlib.sha256()
            seen = 0
            while chunk := response.read(1024 * 1024):
                seen += len(chunk)
                if seen > descriptor.size:
                    raise DigestMismatchError(f"{client.name}: blob sha256:{descriptor.digest} is larger than its size")
                hasher.update(chunk)
                handle.write(chunk)
        if seen != descriptor.size or hasher.hexdigest() != descriptor.digest:
            raise DigestMismatchError(f"{client.name}: blob sha256:{descriptor.digest} does not match its digest")
        temporary.replace(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


# ---- manifests --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Fetched:
    """A manifest or index as served: the sha256 of its bytes in hex, the bytes and the media type."""

    digest: str
    data: bytes
    media_type: str


@dataclass(frozen=True, slots=True)
class Put:
    """What a manifest PUT answered: the digest of what was sent and, when the registry indexed the
    manifest as a referrer, the subject's digest (`OCI-Subject`)."""

    digest: str
    subject: str | None


def _reference_path(reference: str) -> str:
    """A tag, or a `sha256:<hex>` digest, as it goes into a manifest URL."""
    if reference.startswith("sha256:"):
        oci.parse_digest(reference)
    return urllib.parse.quote(reference, safe=":")


def get_manifest(client: Client, reference: str) -> Fetched | None:
    """The manifest or index at a tag or digest, None when the registry has none (404). Its digest is
    computed here and compared with what the caller asked for and what the registry claims."""
    url = _url(client, f"manifests/{_reference_path(reference)}")
    response = _call(client, "GET", url, headers={"Accept": ACCEPT_MANIFESTS})
    if response.status == 404:
        return None
    if response.status != 200:
        raise _refusal(client, f"reading manifest {reference[:19]}", response)
    digest = oci.sha256_hex(response.body)
    claimed = response.headers.get("docker-content-digest")
    if (reference.startswith("sha256:") and reference != f"sha256:{digest}") or (
        claimed is not None and claimed != f"sha256:{digest}"
    ):
        raise DigestMismatchError(f"{client.name}: manifest {reference[:19]} does not match its digest")
    media_type = response.headers.get("content-type", "").partition(";")[0].strip()
    return Fetched(digest, response.body, media_type)


def manifest_digest(client: Client, reference: str) -> str | None:
    """The digest (hex) a tag or digest names in the registry, None when there is no such manifest."""
    url = _url(client, f"manifests/{_reference_path(reference)}")
    response = _call(client, "HEAD", url, headers={"Accept": ACCEPT_MANIFESTS}, limit=0)
    if response.status == 404:
        return None
    if response.status != 200:
        raise _refusal(client, f"looking up manifest {reference[:19]}", response)
    claimed = response.headers.get("docker-content-digest")
    if claimed is not None:
        return oci.parse_digest(claimed)
    found = get_manifest(client, reference)
    return None if found is None else found.digest


def put_manifest(client: Client, reference: str, data: bytes, media_type: str) -> Put:
    url = _url(client, f"manifests/{_reference_path(reference)}")
    headers = {"Content-Type": media_type, "Content-Length": str(len(data))}
    response = _call(client, "PUT", url, headers=headers, body=data, write=True)
    if response.status not in (200, 201):
        raise _refusal(client, f"pushing manifest {reference[:19]}", response)
    claimed = response.headers.get("docker-content-digest")
    if claimed is not None and claimed != f"sha256:{oci.sha256_hex(data)}":
        raise DigestMismatchError(f"{client.name}: it stored manifest {reference[:19]} under another digest")
    subject = response.headers.get("oci-subject")
    return Put(oci.sha256_hex(data), None if subject is None else oci.parse_digest(subject))


# ---- referrers --------------------------------------------------------------------------------


def _referrers_api(client: Client, digest: str) -> tuple[oci.Descriptor, ...] | None:
    """The referrers API's answer, None when the registry has no such endpoint (404, or an answer that
    is not an image index) and so keeps its referrers under the tag schema."""
    url = _url(client, f"referrers/{oci.digest_text(digest)}")
    found: list[oci.Descriptor] = []
    for _ in range(MAX_PAGES):
        response = _call(client, "GET", url, headers={"Accept": oci.INDEX})
        if response.status == 404 and not found:
            return None
        if response.status != 200:
            raise _refusal(client, f"listing referrers of {digest[:12]}", response)
        try:
            found.extend(oci.parse_index(response.body))
        except oci.OciError:
            if not found:
                return None
            raise RegistryError(f"{client.name}: a page of referrers is not an image index") from None
        link = _NEXT.search(response.headers.get("link", ""))
        if link is None:
            return tuple(found)
        url = urllib.parse.urljoin(url, link.group(1))
        if not _same_origin(client, url):
            raise RegistryError(f"{client.name}: its referrers link leaves the registry")
    raise RegistryError(f"{client.name}: more than {MAX_PAGES} pages of referrers")


def tag_index(client: Client, digest: str) -> bytes | None:
    """The bytes of the referrers tag `sha256-<digest>` (the tag schema's index), None when it does
    not exist yet."""
    found = get_manifest(client, oci.referrers_tag(digest))
    if found is None:
        return None
    return found.data


@dataclass(frozen=True, slots=True)
class Attached:
    """One record attached to an image: the referrer manifest that lists it and the envelope blob."""

    referrer: oci.Descriptor
    envelope: oci.Descriptor


@dataclass(frozen=True, slots=True)
class Referrers:
    """What is attached to a manifest, how the registry told (`api`, or the `tag` schema), and every
    referrer that could not be read as a record, with the reason."""

    attached: tuple[Attached, ...]
    via: Literal["api", "tag"]
    problems: tuple[str, ...]


def referrers_of(client: Client, digest: str) -> Referrers:
    """The in-toto records attached to the manifest `digest`: the referrers API first, the referrers tag
    when the registry has no API. Each referrer's manifest is fetched and checked; one that is not a
    single DSSE envelope on the manifest it claims goes to `problems`."""
    listed = _referrers_api(client, digest)
    via: Literal["api", "tag"] = "api"
    if listed is None:
        via = "tag"
        held = tag_index(client, digest)
        try:
            listed = oci.parse_index(held) if held is not None else ()
        except oci.OciError as error:
            raise RegistryError(f"{client.name}: the tag {oci.referrers_tag(digest)}: {error}") from None
    attached: list[Attached] = []
    problems: list[str] = []
    seen: set[str] = set()
    for one in listed:
        if one.artifact_type != oci.IN_TOTO_ARTIFACT or one.digest in seen:
            continue
        seen.add(one.digest)
        where = f"{client.name}@sha256:{one.digest}"
        fetched = get_manifest(client, f"sha256:{one.digest}")
        if fetched is None:
            problems.append(f"{where}: listed as a referrer but not found")
            continue
        try:
            manifest = oci.parse_manifest(fetched.data)
        except oci.OciError as error:
            problems.append(f"{where}: {error}")
            continue
        if manifest.subject is None or manifest.subject.digest != digest:
            problems.append(f"{where}: its subject is not sha256:{digest}")
        elif len(manifest.layers) != 1 or manifest.layers[0].media_type != oci.DSSE_ENVELOPE:
            problems.append(f"{where}: it does not carry exactly one DSSE envelope")
        else:
            attached.append(Attached(one, manifest.layers[0]))
    return Referrers(tuple(attached), via, tuple(problems))


def fetch_envelopes(client: Client, attached: Sequence[Attached]) -> tuple[tuple[bytes, ...], tuple[str, ...]]:
    """The envelope of each attached record, in listing order, each checked against its digest, and
    the reasons for the ones that could not be read."""
    found: list[bytes] = []
    problems: list[str] = []
    for one in attached:
        try:
            found.append(fetch_blob(client, one.envelope, ENVELOPE_LIMIT))
        except DigestMismatchError as error:
            problems.append(f"{client.name}@sha256:{one.referrer.digest}: {error}")
    return tuple(found), tuple(problems)


# ---- pulling an image -------------------------------------------------------------------------


def pull_layout(client: Client, digest: str, destination: Path) -> Path:
    """Write the image whose manifest digest is `digest` (hex) as a one-image layout at `destination`
    (which must not exist): the manifest, its config and its layers, every byte checked, the layers
    streamed to disk. Nothing is left at `destination` unless the whole image arrived."""
    if destination.exists():
        raise FileExistsError(f"{destination} already exists")
    fetched = get_manifest(client, oci.digest_text(digest))
    if fetched is None:
        raise RegistryError(f"{client.name}: no manifest sha256:{digest}")
    try:
        manifest = oci.parse_manifest(fetched.data)
    except oci.OciError as error:
        raise RegistryError(f"{client.name}@sha256:{digest}: {error}") from None
    partial = destination.with_name(destination.name + ".partial")
    shutil.rmtree(partial, ignore_errors=True)
    try:
        partial.mkdir(parents=True)
        ocilayout.write_blob(partial, fetched.data)
        ocilayout.write_blob(partial, fetch_blob(client, manifest.config, MANIFEST_LIMIT))
        for layer in manifest.layers:
            path = ocilayout.blob_path(partial, layer.digest)
            if not path.exists():
                download_blob(client, layer, path)
        ocilayout.write_index(partial, oci.Descriptor(oci.MANIFEST, fetched.digest, len(fetched.data)))
        ocilayout.read_layout(partial)
        partial.rename(destination)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    return destination
