"""The registry edge against a registry in a thread (tests/support/fake_registry.py): references, http
for this machine only, the three kinds of authentication and how credentials are found, blob uploads
with relative and absolute locations, manifests, bounded and checked reads, the tag schema and the
referrers API, and pulling an image back."""

import base64
import json
import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Final

from input_lock.records import TestOutcome

from debian_image_factory import oci, ocilayout, publish, registry
from debian_image_factory.published import OciTarget
from tests.support import fake_registry
from tests.support.fake_registry import PASSWORD, TOKEN, USER, Fake
from tests.support.oci_fixtures import IDENTITY, make_image

LOGIN: Final = registry.Credentials(USER, PASSWORD)


def client_for(name: str, credentials: registry.Credentials | None = None, timeout: float = 10.0) -> registry.Client:
    return registry.connect(OciTarget(name, "team/app"), credentials=lambda _: credentials, timeout=timeout)


class ReferenceTest(unittest.TestCase):
    def test_a_reference_by_digest_or_by_tag(self) -> None:
        digest = "ab" * 32
        by_digest = registry.parse_reference(f"oci://ghcr.io/example/app@sha256:{digest}")
        assert by_digest is not None
        self.assertEqual(
            (by_digest.registry, by_digest.repository, by_digest.digest, by_digest.tag),
            ("ghcr.io", "example/app", digest, None),
        )
        self.assertEqual(by_digest.target, OciTarget("ghcr.io", "example/app"))
        by_tag = registry.parse_reference("oci://127.0.0.1:5000/app:v1.2")
        assert by_tag is not None
        self.assertEqual(
            (by_tag.registry, by_tag.repository, by_tag.digest, by_tag.tag), ("127.0.0.1:5000", "app", None, "v1.2")
        )
        ipv6 = registry.parse_reference("oci://[::1]:5000/app:latest")
        assert ipv6 is not None
        self.assertEqual(ipv6.registry, "[::1]:5000")

    def test_anything_else_is_not_a_reference(self) -> None:
        for text in (
            "oci://ghcr.io/example/app",
            "oci://ghcr.io/Example/app:v1",
            "oci://ghcr.io/app@sha256:abc",
            "ghcr.io/app:v1",
            "dir:///x",
            "oci://ghcr.io/app@sha512:" + "a" * 64,
        ):
            with self.subTest(text=text):
                self.assertIsNone(registry.parse_reference(text))


class SchemeTest(unittest.TestCase):
    def test_http_for_this_machine_and_https_for_the_rest(self) -> None:
        for name in ("localhost", "localhost:5000", "127.0.0.1", "127.0.0.1:5001", "[::1]", "[::1]:5000"):
            with self.subTest(name=name):
                self.assertTrue(registry.is_local(name))
                self.assertEqual(registry.base_url(name), f"http://{name}")
        for name in ("ghcr.io", "registry.example.com:5000", "127.0.0.1.example.com", "localhost.example.com"):
            with self.subTest(name=name):
                self.assertFalse(registry.is_local(name))
                self.assertEqual(registry.base_url(name), f"https://{name}")
        self.assertEqual(registry.base_url("docker.io"), "https://registry-1.docker.io")


class ChallengeTest(unittest.TestCase):
    def test_a_bearer_challenge_gives_its_realm_service_and_scope(self) -> None:
        found = registry.pick_challenge(
            ['Bearer realm="https://auth.example.com/token",service="registry",scope="repository:a/b:pull,push"']
        )
        assert found is not None
        self.assertEqual(found.scheme, "bearer")
        self.assertEqual(
            dict(found.params),
            {"realm": "https://auth.example.com/token", "service": "registry", "scope": "repository:a/b:pull,push"},
        )

    def test_bearer_is_preferred_and_the_scheme_is_case_insensitive(self) -> None:
        found = registry.pick_challenge(['Basic realm="x"', 'bearer realm="https://a/t"'])
        assert found is not None
        self.assertEqual(found.scheme, "bearer")
        basic = registry.pick_challenge(['BASIC realm="x"'])
        assert basic is not None
        self.assertEqual(basic.scheme, "basic")

    def test_other_schemes_and_nothing_are_not_challenges(self) -> None:
        self.assertIsNone(registry.pick_challenge([]))
        self.assertIsNone(registry.pick_challenge(["Negotiate abc"]))


class CredentialsTest(unittest.TestCase):
    def test_auths_with_an_auth_field_or_a_username_and_password(self) -> None:
        auth = base64.b64encode(b"alice:s3cret:with:colons").decode()
        config = {"auths": {"ghcr.io": {"auth": auth}, "https://quay.io": {"username": "bob", "password": "pw"}}}
        self.assertEqual(
            registry.credential_plan(config, "ghcr.io"), (registry.Credentials("alice", "s3cret:with:colons"), None)
        )
        self.assertEqual(registry.credential_plan(config, "quay.io"), (registry.Credentials("bob", "pw"), None))
        self.assertEqual(registry.credential_plan(config, "other.io"), (None, None))

    def test_a_helper_for_the_registry_beats_the_store(self) -> None:
        config = {"credHelpers": {"ghcr.io": "pass"}, "credsStore": "desktop", "auths": {"ghcr.io": {}}}
        self.assertEqual(registry.credential_plan(config, "ghcr.io"), (None, "pass"))
        self.assertEqual(registry.credential_plan(config, "quay.io"), (None, "desktop"))

    def test_docker_hub_is_found_under_its_old_name(self) -> None:
        config = {"auths": {"https://index.docker.io/v1/": {"username": "u", "password": "p"}}}
        self.assertEqual(registry.credential_plan(config, "docker.io"), (registry.Credentials("u", "p"), None))

    def test_nonsense_gives_nothing(self) -> None:
        nocolon = base64.b64encode(b"nocolon").decode()
        configs: list[object] = [
            None,
            [],
            {"auths": {"ghcr.io": {"auth": "!!!"}}},
            {"auths": {"ghcr.io": {"auth": nocolon}}},
            {"credsStore": "../evil"},
        ]
        for config in configs:
            with self.subTest(config=config):
                self.assertEqual(registry.credential_plan(config, "ghcr.io"), (None, None))

    def test_the_password_is_not_in_a_repr(self) -> None:
        self.assertNotIn("p4ss", repr(registry.Credentials("u", "p4ss")))

    def test_the_docker_config_and_a_credential_helper_are_read(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "bin").mkdir()
            helper = root / "bin" / "docker-credential-fake"
            reply = '{"ServerURL":"%s","Username":"helper-user","Secret":"helper-secret"}'
            helper.write_text(f"#!/bin/sh\nread server\nprintf '{reply}' \"$server\"\n")
            helper.chmod(helper.stat().st_mode | stat.S_IXUSR)
            (root / "docker").mkdir()
            (root / "docker" / "config.json").write_text(
                json.dumps(
                    {
                        "credHelpers": {"registry.example.com": "fake"},
                        "auths": {"direct.example.com": {"username": "d", "password": "w"}},
                    }
                )
            )
            env = {"DOCKER_CONFIG": str(root / "docker"), "PATH": f"{root / 'bin'}:/usr/bin:/bin", "HOME": str(root)}
            self.assertEqual(
                registry.docker_credentials("registry.example.com", env),
                registry.Credentials("helper-user", "helper-secret"),
            )
            self.assertEqual(registry.docker_credentials("direct.example.com", env), registry.Credentials("d", "w"))
            self.assertIsNone(registry.docker_credentials("unknown.example.com", env))
            self.assertIsNone(registry.docker_credentials("registry.example.com", {**env, "PATH": "/nonexistent"}))
            self.assertIsNone(registry.docker_credentials("x", {"HOME": str(root / "none")}))  # no config at all

    def test_the_default_config_is_under_home(self) -> None:
        self.assertEqual(registry.docker_config_path({"HOME": "/h"}), Path("/h/.docker/config.json"))
        self.assertEqual(registry.docker_config_path({"HOME": "/h", "DOCKER_CONFIG": "/d"}), Path("/d/config.json"))


class AuthenticationTest(unittest.TestCase):
    def blob(self, client: registry.Client) -> None:
        data = b"payload"
        digest = oci.sha256_hex(data)
        registry.put_blob(client, digest, len(data), data)
        self.assertTrue(registry.blob_exists(client, digest))
        found = registry.fetch_blob(client, oci.Descriptor(oci.LAYER_GZIP, digest, len(data)), 100)
        self.assertEqual(found, data)

    def test_anonymous_registries_need_no_credentials(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            self.blob(client_for(name))
        self.assertEqual(fake.seen_authorization, [])

    def test_a_bearer_registry_hands_an_anonymous_token_to_a_client_without_credentials(self) -> None:
        fake = Fake(auth="bearer")
        with fake_registry.running(fake) as name:
            client = client_for(name)
            self.blob(client)
        self.assertIn(f"Bearer {TOKEN}", fake.seen_authorization)
        self.assertNotIn("anonymous token request carried credentials", fake.seen_authorization)

    def test_a_bearer_registry_that_wants_a_login_gets_the_docker_config_credentials(self) -> None:
        fake = Fake(auth="bearer-login")
        with fake_registry.running(fake) as name:
            self.blob(client_for(name, LOGIN))
            with self.assertRaisesRegex(registry.RegistryError, "token service answered HTTP 401"):
                self.blob(client_for(name))

    def test_basic_registries_get_basic_credentials(self) -> None:
        fake = Fake(auth="basic")
        with fake_registry.running(fake) as name:
            self.blob(client_for(name, LOGIN))
            with self.assertRaisesRegex(registry.RegistryError, "HTTP 401"):
                registry.blob_exists(client_for(name), "ab" * 32)

    def test_credentials_are_looked_up_once_per_client(self) -> None:
        fake = Fake(auth="bearer-login")
        looked: list[str] = []

        def credentials(host: str) -> registry.Credentials:
            looked.append(host)
            return LOGIN

        with fake_registry.running(fake) as name:
            client = registry.connect(OciTarget(name, "team/app"), credentials=credentials)
            self.blob(client)
            registry.blob_exists(client, "ab" * 32)
        self.assertEqual(looked, [name])

    def test_no_secret_reaches_an_error_message(self) -> None:
        fake = Fake(auth="bearer-login")
        with fake_registry.running(fake) as name:
            client = client_for(name, LOGIN)
            with self.assertRaises(registry.RegistryError) as caught:
                registry.fetch_blob(client, oci.Descriptor(oci.LAYER_GZIP, "ab" * 32, 3), 100)
        text = f"{caught.exception} {client!r}"
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(PASSWORD, text)


class BlobTest(unittest.TestCase):
    def test_uploads_follow_a_relative_or_an_absolute_location(self) -> None:
        for absolute in (False, True):
            with self.subTest(absolute=absolute):
                fake = Fake(absolute_location=absolute)
                with fake_registry.running(fake) as name:
                    registry.put_blob(client_for(name), oci.sha256_hex(b"abc"), 3, b"abc")
                self.assertEqual(list(fake.blobs.values()), [b"abc"])

    def test_a_file_is_streamed_up(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "layer"
            path.write_bytes(os.urandom(300_000))
            fake = Fake()
            with fake_registry.running(fake) as name:
                registry.put_blob(client_for(name), ocilayout.file_sha256(path), 300_000, path)
            self.assertEqual(list(fake.blobs.values()), [path.read_bytes()])

    def test_an_upload_location_on_another_host_is_refused(self) -> None:
        fake = Fake(location_host="evil.example:9")
        with fake_registry.running(fake) as name, self.assertRaisesRegex(registry.RegistryError, "another host"):
            registry.put_blob(client_for(name), oci.sha256_hex(b"abc"), 3, b"abc")

    def test_a_blob_the_registry_corrupted_is_refused(self) -> None:
        data = b"x" * 100
        descriptor = oci.descriptor_of(oci.LAYER_GZIP, data)
        fake = Fake(blobs={f"sha256:{descriptor.digest}": data}, broken_blobs={f"sha256:{descriptor.digest}"})
        with fake_registry.running(fake) as name, tempfile.TemporaryDirectory() as scratch:
            client = client_for(name)
            with self.assertRaises(registry.DigestMismatchError):
                registry.fetch_blob(client, descriptor, 1000)
            target = Path(scratch) / "blob"
            with self.assertRaises(registry.DigestMismatchError):
                registry.download_blob(client, descriptor, target)
            self.assertEqual(os.listdir(scratch), [])  # neither the file nor its partial is left

    def test_a_blob_longer_than_its_descriptor_is_refused_not_buffered(self) -> None:
        data = b"x" * 100
        descriptor = oci.descriptor_of(oci.LAYER_GZIP, data)
        fake = Fake(blobs={f"sha256:{descriptor.digest}": data + b"y" * 5000})
        with fake_registry.running(fake) as name, tempfile.TemporaryDirectory() as scratch:
            with self.assertRaises(registry.RegistryError):
                registry.fetch_blob(client_for(name), descriptor, 1000)
            with self.assertRaisesRegex(registry.DigestMismatchError, "larger than its size"):
                registry.download_blob(client_for(name), descriptor, Path(scratch) / "blob")

    def test_a_descriptor_over_the_cap_is_not_asked_for(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name, self.assertRaisesRegex(registry.RegistryError, "over 10"):
            registry.fetch_blob(client_for(name), oci.Descriptor(oci.LAYER_GZIP, "ab" * 32, 11), 10)
        self.assertEqual(fake.log, [])

    def test_a_download_is_streamed_and_checked(self) -> None:
        data = os.urandom(3_000_000)
        descriptor = oci.descriptor_of(oci.LAYER_GZIP, data)
        fake = Fake(blobs={f"sha256:{descriptor.digest}": data})
        with fake_registry.running(fake) as name, tempfile.TemporaryDirectory() as scratch:
            registry.download_blob(client_for(name), descriptor, Path(scratch) / "blob")
            self.assertEqual((Path(scratch) / "blob").read_bytes(), data)


class ManifestTest(unittest.TestCase):
    def pushed(self, client: registry.Client) -> tuple[bytes, str]:
        config = oci.image_config(oci.OciConfig(), [], "amd64")
        registry.put_blob(client, oci.sha256_hex(config), len(config), config)
        manifest = oci.image_manifest(oci.descriptor_of(oci.CONFIG, config), [], {})
        sent = registry.put_manifest(client, "v1", manifest, oci.MANIFEST)
        self.assertEqual(sent, registry.Put(oci.sha256_hex(manifest), None))
        return manifest, oci.sha256_hex(manifest)

    def test_a_manifest_is_found_by_tag_and_by_digest(self) -> None:
        with fake_registry.running(Fake()) as name:
            client = client_for(name)
            manifest, digest = self.pushed(client)
            for reference in ("v1", f"sha256:{digest}"):
                found = registry.get_manifest(client, reference)
                self.assertEqual(found, registry.Fetched(digest, manifest, oci.MANIFEST))
                self.assertEqual(registry.manifest_digest(client, reference), digest)
            self.assertIsNone(registry.get_manifest(client, "v2"))
            self.assertIsNone(registry.manifest_digest(client, "v2"))
            self.assertIsNone(registry.get_manifest(client, f"sha256:{'cd' * 32}"))

    def test_a_manifest_with_a_blob_the_registry_lacks_is_refused_with_its_reason(self) -> None:
        manifest = oci.image_manifest(oci.descriptor_of(oci.CONFIG, b"never uploaded"), [], {})
        with (
            fake_registry.running(Fake()) as name,
            self.assertRaisesRegex(registry.RegistryError, "MANIFEST_BLOB_UNKNOWN"),
        ):
            registry.put_manifest(client_for(name), "v1", manifest, oci.MANIFEST)

    def test_a_manifest_whose_bytes_changed_is_refused(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            client = client_for(name)
            _, digest = self.pushed(client)
            fake.manifests[f"sha256:{digest}"] = b'{"schemaVersion":2,"changed":true}'
            with self.assertRaises(registry.DigestMismatchError):
                registry.get_manifest(client, f"sha256:{digest}")
            with self.assertRaises(registry.DigestMismatchError):
                registry.get_manifest(client, "v1")  # the registry claims the old digest for the new bytes

    def test_a_manifest_over_the_cap_is_refused(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name:
            client = client_for(name)
            _, digest = self.pushed(client)
            fake.manifests[f"sha256:{digest}"] = b"x" * (registry.MANIFEST_LIMIT + 1)
            fake.tags["big"] = f"sha256:{digest}"
            with self.assertRaisesRegex(registry.RegistryError, "larger than"):
                registry.get_manifest(client, "big")

    def test_a_malformed_digest_reference_is_not_sent(self) -> None:
        with self.assertRaises(oci.OciError):
            registry.get_manifest(client_for("127.0.0.1:9"), "sha256:abc")


class ReferrersTest(unittest.TestCase):
    """The two ways a registry lists referrers, read back through `referrers_of`."""

    def push(self, client: registry.Client, root: Path) -> str:
        built = make_image(root / "out", checks=())  # two records: provenance and SBOM
        layout = ocilayout.read_layout(built.layout)
        lines = [line for line in built.records.read_bytes().split(b"\n") if line]
        publish.push_layout(client, layout, [oci.identity_tag(IDENTITY)], lines)
        return built.digest

    def test_with_the_api_the_registry_lists_them(self) -> None:
        with fake_registry.running(Fake()) as name, tempfile.TemporaryDirectory() as scratch:
            client = client_for(name)
            digest = self.push(client, Path(scratch))
            found = registry.referrers_of(client, digest)
            self.assertEqual(found.via, "api")
            self.assertEqual(found.problems, ())
            self.assertEqual(len(found.attached), 2)
            self.assertIsNone(registry.tag_index(client, digest))  # the tag schema was not needed

    def test_records_read_back_in_attach_order_whatever_the_listing_order(self) -> None:
        # the fake lists referrers by digest, as a registry may; "the last result wins" needs attach order
        names = ("oci-run", "ancestry", "package-set", "two-clones", "sbom-complete", "no-machine-identity")
        checks: list[tuple[str, TestOutcome]] = [(name, "PASSED") for name in names]
        for fake in (Fake(), Fake(referrers_api=False, subject_header=False)):
            with fake_registry.running(fake) as name, tempfile.TemporaryDirectory() as scratch:
                client = client_for(name)
                built = make_image(Path(scratch) / "out", checks=checks)
                layout = ocilayout.read_layout(built.layout)
                lines = [line for line in built.records.read_bytes().split(b"\n") if line]
                publish.push_layout(client, layout, [], lines)
                found = registry.referrers_of(client, built.digest)
                envelopes, problems = registry.fetch_envelopes(client, found.attached)
                self.assertEqual(problems, ())
                self.assertEqual(list(envelopes), lines)
                created = [one.created for one in found.attached]
                self.assertEqual(created, sorted(created))
                self.assertEqual(len(set(created)), len(lines))

    def test_the_api_is_followed_across_pages(self) -> None:
        with fake_registry.running(Fake(page_size=1)) as name, tempfile.TemporaryDirectory() as scratch:
            client = client_for(name)
            digest = self.push(client, Path(scratch))
            found = registry.referrers_of(client, digest)
            self.assertEqual(len(found.attached), 2)

    def test_without_the_api_the_referrers_tag_is_read(self) -> None:
        fake = Fake(referrers_api=False, subject_header=False)
        with fake_registry.running(fake) as name, tempfile.TemporaryDirectory() as scratch:
            client = client_for(name)
            digest = self.push(client, Path(scratch))
            found = registry.referrers_of(client, digest)
            self.assertEqual(found.via, "tag")
            self.assertEqual(len(found.attached), 2)
            self.assertIn(oci.referrers_tag(digest), fake.tags)
            envelopes, unread = registry.fetch_envelopes(client, found.attached)
            self.assertEqual((len(envelopes), unread), (2, ()))

    def test_nothing_attached_is_an_empty_listing_either_way(self) -> None:
        for api in (True, False):
            with self.subTest(api=api), fake_registry.running(Fake(referrers_api=api)) as name:
                found = registry.referrers_of(client_for(name), "ab" * 32)
                self.assertEqual((found.attached, found.problems), ((), ()))
                self.assertEqual(found.via, "api" if api else "tag")

    def test_an_envelope_that_does_not_match_its_digest_is_reported_not_returned(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name, tempfile.TemporaryDirectory() as scratch:
            client = client_for(name)
            digest = self.push(client, Path(scratch))
            found = registry.referrers_of(client, digest)
            fake.broken_blobs.add(f"sha256:{found.attached[0].envelope.digest}")
            envelopes, unread = registry.fetch_envelopes(client, found.attached)
            self.assertEqual(len(envelopes), 1)
            self.assertEqual(len(unread), 1)
            self.assertIn("does not match its digest", unread[0])

    def test_a_referrer_that_is_not_a_single_envelope_is_reported(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name, tempfile.TemporaryDirectory() as scratch:
            client = client_for(name)
            digest = self.push(client, Path(scratch))
            empty = oci.Descriptor(oci.EMPTY, oci.EMPTY_DIGEST, 2)
            odd = oci.canonical(
                oci.manifest_json(
                    oci.Manifest(
                        empty, (), subject=oci.Descriptor(oci.MANIFEST, digest, 1), artifact_type=oci.IN_TOTO_ARTIFACT
                    )
                )
            )
            registry.put_blob(client, oci.EMPTY_DIGEST, 2, oci.EMPTY_BLOB)
            registry.put_manifest(client, f"sha256:{oci.sha256_hex(odd)}", odd, oci.MANIFEST)
            found = registry.referrers_of(client, digest)
            self.assertEqual(len(found.attached), 2)
            self.assertEqual(len(found.problems), 1)
            self.assertIn("exactly one DSSE envelope", found.problems[0])


class PullTest(unittest.TestCase):
    def test_an_image_is_pulled_back_byte_for_byte(self) -> None:
        with fake_registry.running(Fake()) as name, tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            built = make_image(root / "out")
            client = client_for(name)
            original = ocilayout.read_layout(built.layout)
            publish.push_layout(client, original, [], [])
            pulled = registry.pull_layout(client, built.digest, root / "pulled")
            again = ocilayout.read_layout(pulled)
            self.assertEqual(again.manifest_bytes, original.manifest_bytes)
            self.assertEqual(again.config_bytes, original.config_bytes)
            self.assertEqual([p.read_bytes() for p in again.layers], [p.read_bytes() for p in original.layers])
            self.assertEqual(sorted(p.name for p in pulled.iterdir()), ["blobs", "index.json", "oci-layout"])
            self.assertEqual(sorted(os.listdir(root)), ["out", "pulled"])

    def test_nothing_is_left_when_a_layer_is_corrupt_or_the_image_is_missing(self) -> None:
        fake = Fake()
        with fake_registry.running(fake) as name, tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            built = make_image(root / "out")
            client = client_for(name)
            original = ocilayout.read_layout(built.layout)
            publish.push_layout(client, original, [], [])
            fake.broken_blobs.add(f"sha256:{original.manifest.layers[0].digest}")
            with self.assertRaises(registry.DigestMismatchError):
                registry.pull_layout(client, built.digest, root / "pulled")
            with self.assertRaisesRegex(registry.RegistryError, "no manifest"):
                registry.pull_layout(client, "cd" * 32, root / "pulled")
            self.assertEqual(sorted(os.listdir(root)), ["out"])

    def test_an_existing_destination_is_not_touched(self) -> None:
        with tempfile.TemporaryDirectory() as scratch, self.assertRaises(FileExistsError):
            registry.pull_layout(client_for("127.0.0.1:9"), "ab" * 32, Path(scratch))


class TimeoutTest(unittest.TestCase):
    def test_a_registry_that_never_answers_is_given_up_on(self) -> None:
        with socket.socket() as silent:
            silent.bind(("127.0.0.1", 0))
            silent.listen(1)
            client = client_for(f"127.0.0.1:{silent.getsockname()[1]}", timeout=0.3)
            with self.assertRaises(OSError):
                registry.blob_exists(client, "ab" * 32)


class ProxyTest(unittest.TestCase):
    def test_this_machine_is_not_sent_through_a_proxy(self) -> None:
        saved = {key: os.environ.get(key) for key in ("http_proxy", "HTTP_PROXY")}
        os.environ["http_proxy"] = os.environ["HTTP_PROXY"] = "http://127.0.0.1:9"  # nothing listens there
        try:
            with fake_registry.running(Fake()) as name:
                self.assertFalse(registry.blob_exists(client_for(name), "ab" * 32))
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


if __name__ == "__main__":
    unittest.main()
