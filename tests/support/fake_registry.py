"""A registry in a thread, speaking enough of the distribution spec (1.1) to test the client without a
network: blob uploads (monolithic, relative or absolute `Location`), manifests by tag and digest (a
manifest whose blobs are missing is refused, as a real registry does), deletes of a manifest (by digest,
which drops its tags too, or by tag; switchable off as a distribution registry has it by default), tag
listings with paging, the referrers API (switchable, with paging) and the `OCI-Subject` header, and three
kinds of authentication.

The state is a plain dataclass the test reads and changes while the server runs.
"""

import base64
import hashlib
import json
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final, Literal
from urllib.parse import parse_qs, urlsplit

TOKEN: Final = "t0ken-s3cret"
USER: Final = "robot"
PASSWORD: Final = "p4ssw0rd-s3cret"
UNAUTHORIZED: Final = b'{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}'

_ROUTE: Final = re.compile(
    r"/v2/(?P<name>.+?)/(?:blobs/uploads/(?P<upload>[^/]*)|blobs/(?P<blob>[^/]+)"
    r"|manifests/(?P<ref>[^/]+)|referrers/(?P<referrers>[^/]+)|tags/(?P<tags>list))"
)


@dataclass
class Fake:
    """Everything the registry holds and how it behaves. Keys of `blobs` and `manifests` are
    `sha256:<hex>`; `tags` maps a tag to a digest."""

    blobs: dict[str, bytes] = field(default_factory=dict[str, bytes])
    manifests: dict[str, bytes] = field(default_factory=dict[str, bytes])
    tags: dict[str, str] = field(default_factory=dict[str, str])
    uploads: dict[str, bytes] = field(default_factory=dict[str, bytes])
    log: list[str] = field(default_factory=list[str])
    referrers_api: bool = True
    delete_enabled: bool = True
    """False answers every DELETE with 405 UNSUPPORTED, as a distribution registry does by default."""
    tag_page_size: int | None = None
    subject_header: bool = True
    absolute_location: bool = False
    location_host: str | None = None
    page_size: int | None = None
    auth: Literal["none", "bearer", "bearer-login", "basic"] = "none"
    broken_blobs: set[str] = field(default_factory=set[str])
    port: int = 0
    seen_authorization: list[str] = field(default_factory=list[str])


def digest_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def referrers_of(fake: Fake, subject: str) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for digest, data in fake.manifests.items():
        manifest = json.loads(data)
        if (
            isinstance(manifest, dict)
            and isinstance(manifest.get("subject"), dict)
            and manifest["subject"].get("digest") == subject
        ):
            entry: dict[str, object] = {"mediaType": manifest.get("mediaType"), "digest": digest, "size": len(data)}
            if "artifactType" in manifest:
                entry["artifactType"] = manifest["artifactType"]
            found.append(entry)
    return sorted(found, key=lambda one: str(one["digest"]))


def handler_for(fake: Fake) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # the base class's name
            pass

        # ---- helpers
        def send(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def body(self) -> bytes:
            return self.rfile.read(int(self.headers.get("Content-Length", "0")))

        def authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            if header:
                fake.seen_authorization.append(header)
            if fake.auth == "none":
                return True
            if fake.auth == "basic":
                wanted = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
                if header == wanted:
                    return True
                self.send(401, UNAUTHORIZED, {"WWW-Authenticate": 'Basic realm="fake"'})
                return False
            if header == f"Bearer {TOKEN}":
                return True
            realm = f"http://127.0.0.1:{fake.port}/token"
            challenge = f'Bearer realm="{realm}",service="fake",scope="repository:x:pull,push"'
            self.send(401, UNAUTHORIZED, {"WWW-Authenticate": challenge})
            return False

        def route(self) -> None:
            fake.log.append(f"{self.command} {self.path}")
            parts = urlsplit(self.path)
            if parts.path == "/token":
                self.token(parse_qs(parts.query))
                return
            if not self.authorized():
                return
            found = _ROUTE.fullmatch(parts.path)
            if found is None:
                self.send(404, b"404 page not found")
                return
            name = found["name"]
            if found["upload"] is not None:
                self.upload(name, found["upload"], parse_qs(parts.query))
            elif found["blob"] is not None:
                self.blob(found["blob"])
            elif found["ref"] is not None:
                self.manifest(found["ref"])
            elif found["tags"] is not None:
                self.tag_list(parse_qs(parts.query))
            else:
                self.referrers(name, found["referrers"], parse_qs(parts.query))

        do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = route  # the base class's names

        # ---- endpoints
        def token(self, query: dict[str, list[str]]) -> None:
            if fake.auth == "bearer-login":
                wanted = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
                if self.headers.get("Authorization") != wanted:
                    self.send(401, b"{}")
                    return
            elif self.headers.get("Authorization"):
                fake.seen_authorization.append("anonymous token request carried credentials")
            self.send(200, json.dumps({"token": TOKEN}).encode())

        def upload(self, name: str, upload: str, query: dict[str, list[str]]) -> None:
            if self.command == "POST":
                self.body()
                path = f"/v2/{name}/blobs/uploads/session-{len(fake.uploads)}"
                fake.uploads[path] = b""
                location = path
                if fake.absolute_location or fake.location_host:
                    location = f"http://{fake.location_host or f'127.0.0.1:{fake.port}'}{path}"
                self.send(202, b"", {"Location": location})
                return
            data = self.body()
            digest = query.get("digest", [""])[0]
            if digest != digest_of(data):
                self.send(400, b'{"errors":[{"code":"DIGEST_INVALID","message":"digest does not match"}]}')
                return
            fake.blobs[digest] = data
            self.send(201, b"", {"Docker-Content-Digest": digest})

        def blob(self, digest: str) -> None:
            if digest not in fake.blobs:
                self.send(404, b'{"errors":[{"code":"BLOB_UNKNOWN","message":"unknown blob"}]}')
                return
            data = fake.blobs[digest]
            if digest in fake.broken_blobs:
                data = data[:-1] + bytes([data[-1] ^ 1])
            self.send(200, data, {"Docker-Content-Digest": digest, "Content-Type": "application/octet-stream"})

        def tag_list(self, query: dict[str, list[str]]) -> None:
            names = sorted(fake.tags)
            last = query.get("last", [""])[0]
            names = [one for one in names if one > last]
            headers: dict[str, str] = {}
            if fake.tag_page_size is not None and len(names) > fake.tag_page_size:
                names = names[: fake.tag_page_size]
                headers["Link"] = f'</v2/x/tags/list?last={names[-1]}>; rel="next"'
            self.send(200, json.dumps({"name": "x", "tags": names}).encode(), headers)

        def delete(self, reference: str) -> None:
            if not fake.delete_enabled:
                self.send(405, b'{"errors":[{"code":"UNSUPPORTED","message":"The operation is unsupported."}]}')
                return
            if reference.startswith("sha256:"):
                if reference not in fake.manifests:
                    self.send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN","message":"unknown manifest"}]}')
                    return
                del fake.manifests[reference]
                for tag in [name for name, digest in fake.tags.items() if digest == reference]:
                    del fake.tags[tag]
            elif reference in fake.tags:
                del fake.tags[reference]
            else:
                self.send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN","message":"unknown manifest"}]}')
                return
            self.send(202)

        def manifest(self, reference: str) -> None:
            if self.command == "DELETE":
                self.delete(reference)
                return
            if self.command == "PUT":
                data = self.body()
                digest = digest_of(data)
                if reference.startswith("sha256:") and reference != digest:
                    self.send(400, b'{"errors":[{"code":"DIGEST_INVALID","message":"digest mismatch"}]}')
                    return
                document = json.loads(data)
                needed = [document["config"]["digest"]] if "config" in document else []
                needed += [one["digest"] for one in document.get("layers", [])]
                needed += [one["digest"] for one in document.get("manifests", [])]
                missing = [one for one in needed if one not in fake.blobs and one not in fake.manifests]
                if missing:
                    self.send(404, b'{"errors":[{"code":"MANIFEST_BLOB_UNKNOWN","message":"blob unknown"}]}')
                    return
                fake.manifests[digest] = data
                if not reference.startswith("sha256:"):
                    fake.tags[reference] = digest
                headers = {"Docker-Content-Digest": digest}
                subject = document.get("subject")
                if fake.subject_header and isinstance(subject, dict):
                    headers["OCI-Subject"] = str(subject["digest"])
                self.send(201, b"", headers)
                return
            digest = reference if reference.startswith("sha256:") else fake.tags.get(reference, "")
            if digest not in fake.manifests:
                self.send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN","message":"unknown manifest"}]}')
                return
            data = fake.manifests[digest]
            try:
                media = json.loads(data).get("mediaType", "application/octet-stream")
            except ValueError:
                media = "application/octet-stream"
            self.send(200, data, {"Docker-Content-Digest": digest, "Content-Type": media})

        def referrers(self, name: str, digest: str, query: dict[str, list[str]]) -> None:
            if not fake.referrers_api:
                self.send(404, b"404 page not found")
                return
            everything = referrers_of(fake, digest)
            page = int(query.get("page", ["0"])[0])
            headers = {"Content-Type": "application/vnd.oci.image.index.v1+json"}
            if fake.page_size is not None:
                size = fake.page_size
                if (page + 1) * size < len(everything):
                    headers["Link"] = f'</v2/{name}/referrers/{digest}?page={page + 1}>; rel="next"'
                everything = everything[page * size : (page + 1) * size]
            body = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": everything}
            self.send(200, json.dumps(body).encode(), headers)

    return Handler


@contextmanager
def running(fake: Fake) -> Iterator[str]:
    """Serve `fake` on a free port of 127.0.0.1 and yield the registry's name (`127.0.0.1:<port>`)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(fake))
    fake.port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{fake.port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
