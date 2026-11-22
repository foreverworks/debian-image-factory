"""GitHub's releases API in a thread, enough of it to test the client without a network: a release by
tag, release creation, paged asset listings (a small page size is switchable, so `Link` is exercised),
uploads on a separate path named by the release's `upload_url` (with its `{?name,label}` template),
renames (PATCH of an asset's name), deletes, and asset downloads answered with a redirect to another host name
on the same port, so a test can see that the token does not follow it. Assets carry a `digest` unless a test
hides it, a request can be made to fail with a 503 once, and a repository with a token set answers 404 to
anyone without it, as a private one does.

The state is a plain dataclass the test reads and changes while the server runs.
"""

import hashlib
import json
import os
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from debian_image_factory import github

TOKEN: Final = "gh-t0ken-s3cret"
OWNER: Final = "example"
REPO: Final = "images"
REDIRECT_HOST: Final = "localhost"
"""The other name of 127.0.0.1: a download redirects there, which is another host to a client."""

_API: Final = re.compile(
    rf"/repos/{OWNER}/{REPO}/releases(?:/tags/(?P<tag>[^/]+)|/(?P<release>[0-9]+)/assets|/assets/(?P<asset>[0-9]+))?"
)
_UPLOAD: Final = re.compile(rf"/upload/repos/{OWNER}/{REPO}/releases/(?P<release>[0-9]+)/assets")
_DOWNLOAD: Final = re.compile(r"/storage/(?P<asset>[0-9]+)")


@dataclass
class Stored:
    id: int
    name: str
    data: bytes


@dataclass
class Release:
    id: int
    tag: str
    assets: list[Stored] = field(default_factory=list[Stored])


@dataclass
class Fake:
    """Everything the server holds and how it behaves. `token` is required on every API and upload
    request (None: the repository is public)."""

    token: str | None = TOKEN
    releases: dict[str, Release] = field(default_factory=dict[str, Release])
    page_size: int | None = None
    hide_digest: set[str] = field(default_factory=set[str])
    truncate_uploads: set[str] = field(default_factory=set[str])
    """Names (a prefix of the uploaded name) whose stored bytes lose their last byte, as a broken upload would."""
    fail_once: list[str] = field(default_factory=list[str])
    """`<METHOD> <path prefix>` of requests that answer 503 the first time they are made."""
    log: list[str] = field(default_factory=list[str])
    authorization: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])
    """(Host header, Authorization header) of every request that carried one."""
    next_id: int = 1000
    port: int = 0

    def assets(self, tag: str) -> dict[str, bytes]:
        return {one.name: one.data for one in self.releases[tag].assets}


def new_id(fake: Fake) -> int:
    fake.next_id += 1
    return fake.next_id


def asset_json(fake: Fake, one: Stored) -> dict[str, object]:
    body: dict[str, object] = {"id": one.id, "name": one.name, "size": len(one.data), "state": "uploaded"}
    body["digest"] = None if one.name in fake.hide_digest else "sha256:" + hashlib.sha256(one.data).hexdigest()
    return body


def release_json(fake: Fake, release: Release) -> dict[str, object]:
    template = f"http://127.0.0.1:{fake.port}/upload/repos/{OWNER}/{REPO}/releases/{release.id}/assets{{?name,label}}"
    return {"id": release.id, "tag_name": release.tag, "name": release.tag, "upload_url": template, "draft": False}


def handler_for(fake: Fake) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # the base class's name
            pass

        def send(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def send_json(self, status: int, document: object, headers: dict[str, str] | None = None) -> None:
            self.send(status, json.dumps(document).encode(), {"Content-Type": "application/json", **(headers or {})})

        def body(self) -> bytes:
            return self.rfile.read(int(self.headers.get("Content-Length", "0")))

        def route(self) -> None:
            fake.log.append(f"{self.command} {self.path}")
            authorization = self.headers.get("Authorization")
            if authorization:
                fake.authorization.append((self.headers.get("Host", ""), authorization))
            data = self.body()  # always read, so a refused upload does not leave bytes on the socket
            parts = urlsplit(self.path)
            for pending in fake.fail_once:
                method, _, prefix = pending.partition(" ")
                if method == self.command and parts.path.startswith(prefix):
                    fake.fail_once.remove(pending)
                    self.send_json(503, {"message": "Service Unavailable"})
                    return
            storage = _DOWNLOAD.fullmatch(parts.path)
            if storage is not None:  # the storage host: no token is asked for, and none must arrive
                self.download(int(storage["asset"]))
                return
            if fake.token is not None and authorization != f"Bearer {fake.token}":
                self.send_json(404, {"message": "Not Found"})
                return
            upload = _UPLOAD.fullmatch(parts.path)
            if upload is not None and self.command == "POST":
                self.upload(int(upload["release"]), parse_qs(parts.query), data)
                return
            found = _API.fullmatch(parts.path)
            if found is None:
                self.send_json(404, {"message": "Not Found"})
            elif found["tag"] is not None:
                self.by_tag(found["tag"])
            elif found["release"] is not None:
                self.listing(int(found["release"]), parse_qs(parts.query))
            elif found["asset"] is not None:
                self.asset(int(found["asset"]), data)
            elif self.command == "POST":
                self.create(data)
            else:
                self.send_json(404, {"message": "Not Found"})

        do_GET = do_POST = do_DELETE = do_PATCH = route  # the base class's names

        def by_tag(self, tag: str) -> None:
            if tag not in fake.releases:
                self.send_json(404, {"message": "Not Found"})
                return
            self.send_json(200, release_json(fake, fake.releases[tag]))

        def create(self, data: bytes) -> None:
            document = json.loads(data)
            tag = document["tag_name"]
            if tag in fake.releases:
                error = {"resource": "Release", "code": "already_exists", "field": "tag_name"}
                self.send_json(422, {"message": "Validation Failed", "errors": [error]})
                return
            fake.releases[tag] = Release(new_id(fake), tag)
            self.send_json(201, release_json(fake, fake.releases[tag]))

        def listing(self, release_id: int, query: dict[str, list[str]]) -> None:
            release = next((one for one in fake.releases.values() if one.id == release_id), None)
            if release is None:
                self.send_json(404, {"message": "Not Found"})
                return
            size = fake.page_size or int(query.get("per_page", ["30"])[0])
            page = int(query.get("page", ["1"])[0])
            everything = sorted(release.assets, key=lambda one: one.name)
            headers: dict[str, str] = {}
            if page * size < len(everything):
                following = f"http://{self.headers.get('Host')}/repos/{OWNER}/{REPO}/releases/{release_id}/assets"
                headers["Link"] = f'<{following}?per_page={size}&page={page + 1}>; rel="next"'
            chosen = everything[(page - 1) * size : page * size]
            self.send_json(200, [asset_json(fake, one) for one in chosen], headers)

        def upload(self, release_id: int, query: dict[str, list[str]], data: bytes) -> None:
            release = next((one for one in fake.releases.values() if one.id == release_id), None)
            name = query.get("name", [""])[0]
            if release is None or not name:
                self.send_json(404, {"message": "Not Found"})
                return
            if self.headers.get("Content-Type") != "application/octet-stream":
                self.send_json(415, {"message": "Unsupported Media Type"})
                return
            if any(one.name == name for one in release.assets):
                error = {"resource": "ReleaseAsset", "code": "already_exists", "field": "name"}
                self.send_json(422, {"message": "Validation Failed", "errors": [error]})
                return
            if any(name.startswith(prefix) for prefix in fake.truncate_uploads):
                data = data[:-1]
            stored = Stored(new_id(fake), name, data)
            release.assets.append(stored)
            self.send_json(201, asset_json(fake, stored))

        def asset(self, asset_id: int, data: bytes) -> None:
            for release in fake.releases.values():
                for one in release.assets:
                    if one.id != asset_id:
                        continue
                    if self.command == "DELETE":
                        release.assets.remove(one)
                        self.send(204)
                    elif self.command == "PATCH":
                        name = json.loads(data).get("name", "")
                        if any(other.name == name for other in release.assets):
                            error = {"resource": "ReleaseAsset", "code": "already_exists", "field": "name"}
                            self.send_json(422, {"message": "Validation Failed", "errors": [error]})
                        else:
                            one.name = name
                            self.send_json(200, asset_json(fake, one))
                    elif "octet-stream" in self.headers.get("Accept", ""):
                        location = f"http://{REDIRECT_HOST}:{fake.port}/storage/{one.id}"
                        self.send(302, b"", {"Location": location})
                    else:
                        self.send_json(200, asset_json(fake, one))
                    return
            self.send_json(404, {"message": "Not Found"})

        def download(self, asset_id: int) -> None:
            for release in fake.releases.values():
                for one in release.assets:
                    if one.id == asset_id:
                        self.send(200, one.data, {"Content-Type": "application/octet-stream"})
                        return
            self.send(404, b"not found")

    return Handler


@contextmanager
def running(fake: Fake) -> Iterator[str]:
    """Serve `fake` on a free port of 127.0.0.1 and yield the API's address (`http://127.0.0.1:<port>`)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(fake))
    fake.port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{fake.port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


@contextmanager
def environment(api: str, token: str | None = TOKEN) -> Iterator[None]:
    """The environment a command runs in: the API at `api`, the token (none: anonymous), no waiting
    between retries, and the rest of the environment as it is."""
    env = {key: value for key, value in os.environ.items() if key not in ("GITHUB_API_URL", "GITHUB_TOKEN", "GH_TOKEN")}
    env["GITHUB_API_URL"] = api
    if token is not None:
        env["GITHUB_TOKEN"] = token
    with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(github, "BACKOFF", 0.0):
        yield
