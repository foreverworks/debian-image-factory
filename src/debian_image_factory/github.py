"""The GitHub release edge: the REST API over urllib (DESIGN 7.4, 8.2, 9.1).

Nothing else in the package talks to GitHub. What this module guarantees to its callers:

- **Where it talks.** The API is `$GITHUB_API_URL` (GitHub Actions sets it; the default is
  `https://api.github.com`), https, or http for the machine itself. The token is `$GITHUB_TOKEN`, else
  `$GH_TOKEN`; without one every request is anonymous, which reads public repositories only, and the
  errors for a refused request say so.
- **The token goes to two hosts.** The API host, and the upload host the API itself returned in a
  release's `upload_url`. It is sent as an unredirected header, so a redirect (an asset download is
  answered with one to a storage host) never carries it, and it is never printed, logged or put in an
  error message.
- **Failures are OSErrors.** `GitHubError` is one, so a command reports it the way it reports an
  unreadable directory. A 5xx answer and a connection that fails are tried again after a short
  backoff, a few times; every request has a timeout; a 4xx answer is never retried.
- **A name is only given to a whole asset.** `store_asset` uploads under a temporary name, checks what
  arrived and renames it.
- **Everything read is checked.** A release and an asset are parsed from JSON field by field into
  typed dictionaries; an asset's bytes are counted against the size its listing states.

Pure functions (addresses, `Link` headers, name filtering, parsing) come first, the requests after.
"""

import hashlib
import http.client
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Final, TypedDict, TypeGuard

from . import registry
from .published import ReleaseTarget, partial_name, partial_of

DEFAULT_API: Final = "https://api.github.com"
API_VERSION: Final = "2022-11-28"
USER_AGENT: Final = "debian-image-factory"
TIMEOUT: Final = 60.0
"""Seconds a request may wait for its next byte, set on every one."""
ATTEMPTS: Final = 4
"""One try and three more for a 5xx answer or a connection that fails."""
BACKOFF: Final = 0.5
"""Seconds before the first retry; each later one waits twice as long."""
PER_PAGE: Final = 100
MAX_PAGES: Final = 100
JSON_LIMIT: Final = 4 * 1024 * 1024
"""The largest JSON answer read."""
RECORDS_LIMIT: Final = 64 * 1024 * 1024
"""The largest records asset read into memory."""
CHUNK: Final = 1024 * 1024

_NEXT: Final = re.compile(r'<([^>]*)>\s*;\s*rel="?next"?')
_DIGEST: Final = re.compile(r"sha256:([0-9a-f]{64})")
_TEMPLATE: Final = re.compile(r"\{[^}]*\}")


class GitHubError(OSError):
    """GitHub cannot be reached, or answered something this module cannot accept."""


class AlreadyExistsError(GitHubError):
    """An upload refused because the release already holds an asset of that name."""


class Release(TypedDict):
    """The parts of a release this module uses: its number and where its assets are uploaded."""

    id: int
    upload_url: str


class Asset(TypedDict):
    """A release asset: its number, name, size in bytes, and its sha256 in hex when GitHub states one
    (assets uploaded before mid 2025 have none)."""

    id: int
    name: str
    size: int
    digest: str | None


@dataclass(frozen=True, slots=True)
class Client:
    """One release of one repository and how to reach the API. No state beyond what the environment gave."""

    target: ReleaseTarget
    api: str
    token: str | None = field(repr=False)
    timeout: float

    @property
    def name(self) -> str:
        return f"github-release://{self.target.owner}/{self.target.repo}@{self.target.tag}"


# ---- pure: addresses and names ----------------------------------------------------------------


def api_base(environ: Mapping[str, str]) -> str:
    """The API's address without a trailing slash: `$GITHUB_API_URL` or GitHub's own. https only, except
    for the machine itself (a test, a local mirror); anything else would carry the token in the clear."""
    text = (environ.get("GITHUB_API_URL") or DEFAULT_API).rstrip("/")
    parts = urllib.parse.urlsplit(text)
    if not parts.netloc or parts.query or parts.fragment:
        raise GitHubError(f"GITHUB_API_URL is not an address: {text!r}")
    if parts.scheme != "https" and not (parts.scheme == "http" and registry.is_local(parts.netloc)):
        raise GitHubError("GITHUB_API_URL must be https (http is for the machine itself only)")
    return text


def token_from(environ: Mapping[str, str]) -> str | None:
    """`$GITHUB_TOKEN`, else `$GH_TOKEN`; None when neither holds a value."""
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = environ.get(name, "").strip()
        if value:
            return value
    return None


def repo_url(client: Client, tail: str) -> str:
    return f"{client.api}/repos/{client.target.owner}/{client.target.repo}/{tail}"


def upload_url_for(template: str, name: str) -> str:
    """Where to POST an asset called `name`: the release's `upload_url` without its `{?name,label}`
    template, then `?name=`."""
    base = _TEMPLATE.sub("", template)
    return f"{base}?{urllib.parse.urlencode({'name': name})}"


def next_link(header: str | None) -> str | None:
    """The address a `Link` header gives for `rel="next"`, or None on the last page."""
    found = _NEXT.search(header or "")
    return found[1] if found else None


def digest_hex(value: object) -> str | None:
    """The hex of an asset's `digest` field (`sha256:<64 hex>`); anything else, null included, is no digest."""
    if isinstance(value, str):
        found = _DIGEST.fullmatch(value)
        if found:
            return found[1]
    return None


def named_like(assets: Sequence[Asset], prefix: str) -> list[Asset]:
    """The assets whose name starts with `prefix`, by name."""
    return sorted((one for one in assets if one["name"].startswith(prefix)), key=lambda one: one["name"])


def parse_release(value: object) -> Release:
    body = _object(value, "a release")
    identifier, template = body.get("id"), body.get("upload_url")
    if not _is_int(identifier) or not isinstance(template, str) or not template:
        raise GitHubError("a release has no id or upload_url")
    return Release(id=identifier, upload_url=template)


def parse_asset(value: object) -> Asset:
    body = _object(value, "an asset")
    identifier, name, size = body.get("id"), body.get("name"), body.get("size")
    if not _is_int(identifier) or not isinstance(name, str) or not name or not _is_int(size) or size < 0:
        raise GitHubError("an asset has no id, name or size")
    return Asset(id=identifier, name=name, size=size, digest=digest_hex(body.get("digest")))


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _object(value: object, what: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise GitHubError(f"{what} is not an object")
    return {str(key): item for key, item in value.items()}


def parse_assets(value: object) -> list[Asset]:
    """The assets of one page of a listing. An asset still being uploaded (`state` other than
    `uploaded`) is not there yet and is left out, except an unfinished upload under a `.partial-` name,
    which `publish` deletes."""
    if not isinstance(value, list):
        raise GitHubError("a list of assets is not an array")
    found: list[Asset] = []
    for item in value:
        body = _object(item, "an asset")
        name = body.get("name")
        if body.get("state", "uploaded") == "uploaded" or (isinstance(name, str) and partial_of(name) is not None):
            found.append(parse_asset(item))
    return found


def error_text(body: bytes) -> tuple[str, bool]:
    """The `message` of an error answer, and whether one of its `errors` says `already_exists`."""
    try:
        answer: object = json.loads(body)
    except ValueError:
        return "", False
    if not isinstance(answer, dict):
        return "", False
    message = answer.get("message")
    errors = answer.get("errors")
    exists = isinstance(errors, list) and any(
        isinstance(one, dict) and one.get("code") == "already_exists" for one in errors
    )
    return (message if isinstance(message, str) else ""), exists


def connect(target: ReleaseTarget, environ: Mapping[str, str] | None = None, timeout: float = TIMEOUT) -> Client:
    """The client for a release, configured from the environment (`os.environ` unless one is given)."""
    given = os.environ if environ is None else environ
    return Client(target, api_base(given), token_from(given), timeout)


# ---- requests ---------------------------------------------------------------------------------

type Body = bytes | BinaryIO | None
type Answer = http.client.HTTPResponse | urllib.error.HTTPError


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    headers: Mapping[str, str]
    """Lower-case names."""
    body: bytes


def _opener(url: str) -> urllib.request.OpenerDirector:
    """The default opener (which honours the proxy variables), without a proxy for this machine."""
    if registry.is_local(urllib.parse.urlsplit(url).netloc):
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener()


def _trusted(client: Client, url: str, upload_host: str | None) -> bool:
    """Whether the token may go to `url`: the API host, or the upload host the API returned."""
    parts, api = urllib.parse.urlsplit(url), urllib.parse.urlsplit(client.api)
    return parts.scheme == api.scheme and parts.netloc in (api.netloc, upload_host)


def _open(
    client: Client, method: str, url: str, headers: Mapping[str, str], body: Body, upload_host: str | None = None
) -> Answer:
    """Send one request, again after a 5xx answer or a failed connection (the last answer is returned
    whatever its status; the last failure raises GitHubError)."""
    base = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        **headers,
    }
    for attempt in range(ATTEMPTS):
        last = attempt == ATTEMPTS - 1
        if body is not None and not isinstance(body, bytes):
            body.seek(0)
        request = urllib.request.Request(url, data=body, method=method, headers=base)
        if client.token is not None and _trusted(client, url, upload_host):
            request.add_unredirected_header("Authorization", f"Bearer {client.token}")
        try:
            response: Answer = _opener(url).open(request, timeout=client.timeout)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, http.client.HTTPException) as error:  # a refused connection, a timeout, a cut-off answer
            if last:
                reason = error.reason if isinstance(error, urllib.error.URLError) else error
                raise GitHubError(f"{client.name}: {method} {urllib.parse.urlsplit(url).netloc}: {reason}") from None
            time.sleep(BACKOFF * 2**attempt)
            continue
        if (response.status or 0) >= 500 and not last:
            response.close()
            time.sleep(BACKOFF * 2**attempt)
            continue
        return response
    raise AssertionError("unreachable")  # pragma: no cover


def _finish(client: Client, method: str, response: Answer, limit: int) -> Response:
    """The answer's body read in full, up to `limit` bytes."""
    with closing(response):
        try:
            data = response.read(limit + 1)
        except (OSError, http.client.HTTPException) as error:
            raise GitHubError(f"{client.name}: the answer to {method} broke off: {error!r}") from None
        if len(data) > limit:
            raise GitHubError(f"{client.name}: an answer to {method} was larger than {limit} bytes")
        status = response.status
        assert status is not None  # a response that came back has a status line
        return Response(status, {name.lower(): value for name, value in response.headers.items()}, data)


def _call(
    client: Client,
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: Body = None,
    upload_host: str | None = None,
    limit: int = JSON_LIMIT,
) -> Response:
    return _finish(client, method, _open(client, method, url, headers or {}, body, upload_host), limit)


def _refusal(client: Client, what: str, response: Response) -> GitHubError:
    """An error for an answer this module did not expect, with GitHub's message and, for the statuses
    that mean no access, what the token (or its absence) says about it."""
    message, _ = error_text(response.body)
    hint = ""
    if response.status in (401, 403, 404):
        if client.token is None:
            hint = (
                " (no GITHUB_TOKEN or GH_TOKEN is set: the request was anonymous, which sees public repositories only)"
            )
        else:
            hint = " (the token may be refused, lack access to this repository, or the repository may not exist)"
    return GitHubError(f"{client.name}: {what}: HTTP {response.status}{f' ({message})' if message else ''}{hint}")


def _json(client: Client, what: str, response: Response) -> object:
    try:
        answer: object = json.loads(response.body)
    except ValueError:
        raise GitHubError(f"{client.name}: {what}: the answer is not JSON") from None
    return answer


# ---- releases and assets ----------------------------------------------------------------------


def release_by_tag(client: Client) -> Release | None:
    """The release of the client's tag, or None when the repository has none. A repository that is
    private to an anonymous client answers 404 too, so None can also mean no access."""
    tag = urllib.parse.quote(client.target.tag, safe="")
    response = _call(client, "GET", repo_url(client, f"releases/tags/{tag}"))
    if response.status == 404:
        return None
    if response.status != 200:
        raise _refusal(client, "reading the release", response)
    try:
        return parse_release(_json(client, "reading the release", response))
    except GitHubError as error:
        raise GitHubError(f"{client.name}: reading the release: {error}") from None


def create_release(client: Client) -> Release:
    """Create the release of the client's tag (named like it, not a draft, not a prerelease). A tag the
    repository does not have yet is created by GitHub at the default branch's head."""
    tag = client.target.tag
    document = json.dumps({"tag_name": tag, "name": tag, "draft": False, "prerelease": False}).encode()
    response = _call(
        client, "POST", repo_url(client, "releases"), headers={"Content-Type": "application/json"}, body=document
    )
    if response.status != 201:
        raise _refusal(client, "creating the release", response)
    try:
        return parse_release(_json(client, "creating the release", response))
    except GitHubError as error:
        raise GitHubError(f"{client.name}: creating the release: {error}") from None


def list_assets(client: Client, release: Release) -> list[Asset]:
    """Every asset of the release, following the listing's pages (`Link: rel="next"`, which must stay on
    the API's host)."""
    url: str | None = repo_url(client, f"releases/{release['id']}/assets?per_page={PER_PAGE}")
    found: list[Asset] = []
    for _ in range(MAX_PAGES):
        if url is None:
            return found
        response = _call(client, "GET", url)
        if response.status != 200:
            raise _refusal(client, "listing the assets", response)
        try:
            page = parse_assets(_json(client, "listing the assets", response))
        except GitHubError as error:
            raise GitHubError(f"{client.name}: listing the assets: {error}") from None
        found.extend(page)
        following = next_link(response.headers.get("link"))
        url = None if following is None else urllib.parse.urljoin(url, following)
        api = urllib.parse.urlsplit(client.api)
        if url is not None and (urllib.parse.urlsplit(url).netloc, urllib.parse.urlsplit(url).scheme) != (
            api.netloc,
            api.scheme,
        ):
            raise GitHubError(f"{client.name}: its listing points to another host")
    raise GitHubError(f"{client.name}: the asset listing has more than {MAX_PAGES} pages")


def upload_asset(client: Client, release: Release, name: str, source: Path) -> Asset:
    """Upload the file `source` as the asset `name`, streamed from disk. The upload goes to the host
    the release's `upload_url` names (which must use the API's scheme), and the token with it. An asset
    of that name already there raises AlreadyExistsError: nothing is overwritten."""
    url = upload_url_for(release["upload_url"], name)
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != urllib.parse.urlsplit(client.api).scheme or not parts.netloc:
        raise GitHubError(f"{client.name}: its upload address does not use the API's scheme")
    headers = {"Content-Type": "application/octet-stream", "Content-Length": str(source.stat().st_size)}
    with source.open("rb") as handle:
        response = _call(client, "POST", url, headers=headers, body=handle, upload_host=parts.netloc)
    if response.status == 422 and error_text(response.body)[1]:
        raise AlreadyExistsError(
            f"{client.name}: the release already holds an asset called {name} "
            "(an earlier attempt may have stored it; publish again to compare)"
        )
    if response.status != 201:
        raise _refusal(client, f"uploading {name}", response)
    try:
        return parse_asset(_json(client, f"uploading {name}", response))
    except GitHubError as error:
        raise GitHubError(f"{client.name}: uploading {name}: {error}") from None


def rename_asset(client: Client, asset: Asset, name: str) -> Asset:
    """Give an uploaded asset another name (`PATCH /releases/assets/{id}`). An asset already called `name`
    raises AlreadyExistsError: nothing is overwritten."""
    document = json.dumps({"name": name}).encode()
    response = _call(
        client,
        "PATCH",
        repo_url(client, f"releases/assets/{asset['id']}"),
        headers={"Content-Type": "application/json"},
        body=document,
    )
    if response.status == 422 and error_text(response.body)[1]:
        raise AlreadyExistsError(f"{client.name}: the release already holds an asset called {name}")
    if response.status != 200:
        raise _refusal(client, f"renaming {asset['name']} to {name}", response)
    try:
        return parse_asset(_json(client, f"renaming {asset['name']}", response))
    except GitHubError as error:
        raise GitHubError(f"{client.name}: renaming {asset['name']}: {error}") from None


def store_asset(client: Client, release: Release, name: str, source: Path, token: str) -> Asset:
    """Put the file `source` on the release as `name` without a reader ever finding half of it there: it is
    uploaded as `partial_name(name, token)`, its size (and its sha256 when GitHub states one) checked against
    the file, and only then renamed. An interrupted upload leaves an asset no lookup reads and that
    `publish` removes the next time; one that arrived wrong is deleted here and raises GitHubError. An asset
    already called `name` raises AlreadyExistsError and nothing is left behind."""
    uploaded = upload_asset(client, release, partial_name(name, token), source)
    size = source.stat().st_size
    stated = uploaded["digest"]
    if uploaded["size"] != size or (stated is not None and stated != _sha256_of(source)):
        delete_asset(client, uploaded)
        raise GitHubError(
            f"{client.name}: {name} arrived as {uploaded['size']} bytes"
            f"{'' if stated is None else f' (sha256 {stated})'}, not the {size} bytes of {source}; it was removed"
        )
    try:
        return rename_asset(client, uploaded, name)
    except AlreadyExistsError:
        delete_asset(client, uploaded)
        raise


def _sha256_of(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def delete_asset(client: Client, asset: Asset) -> None:
    response = _call(client, "DELETE", repo_url(client, f"releases/assets/{asset['id']}"))
    if response.status != 204:
        raise _refusal(client, f"deleting {asset['name']}", response)


def asset_chunks(client: Client, asset: Asset) -> Iterator[bytes]:
    """An asset's bytes in chunks, through `GET /releases/assets/{id}` for `application/octet-stream`.
    GitHub answers with a redirect to a storage host; that request carries no token. The count is
    checked against the asset's size at the end."""
    url = repo_url(client, f"releases/assets/{asset['id']}")
    response = _open(client, "GET", url, {"Accept": "application/octet-stream"}, None)
    with closing(response):
        if response.status != 200:
            raise _refusal(client, f"reading {asset['name']}", _finish(client, "GET", response, JSON_LIMIT))
        seen = 0
        while True:
            try:
                chunk = response.read(CHUNK)
            except (OSError, http.client.HTTPException) as error:
                raise GitHubError(f"{client.name}: reading {asset['name']} broke off: {error!r}") from None
            if not chunk:
                break
            seen += len(chunk)
            yield chunk
    if seen != asset["size"]:
        raise GitHubError(f"{client.name}: {asset['name']} is {seen} bytes, not the {asset['size']} its listing states")


def download_asset(client: Client, asset: Asset, destination: Path) -> None:
    """Stream an asset to `destination` (a new file); nothing is left behind on a failure."""
    temporary = destination.with_name(destination.name + ".partial")
    try:
        with temporary.open("wb") as handle:
            for chunk in asset_chunks(client, asset):
                handle.write(chunk)
        temporary.replace(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def read_asset(client: Client, asset: Asset, limit: int = RECORDS_LIMIT) -> bytes:
    """A small asset in memory, at most `limit` bytes."""
    if asset["size"] > limit:
        raise GitHubError(f"{client.name}: {asset['name']} is {asset['size']} bytes, over {limit}")
    return b"".join(asset_chunks(client, asset))


def asset_sha256(client: Client, asset: Asset) -> str:
    """The sha256 of an asset in hex: the `digest` GitHub states for it when it states one, else the
    hash of its bytes, streamed from a download."""
    if asset["digest"] is not None:
        return asset["digest"]
    hasher = hashlib.sha256()
    for chunk in asset_chunks(client, asset):
        hasher.update(chunk)
    return hasher.hexdigest()
