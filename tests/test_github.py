"""The GitHub edge: its pure parts, and the client against a fake API in a thread (tests/support/fake_github.py)."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from debian_image_factory import github
from debian_image_factory.published import ReleaseTarget
from tests.support import fake_github
from tests.support.fake_github import OWNER, REDIRECT_HOST, REPO, TOKEN, Fake

TARGET = ReleaseTarget(OWNER, REPO, "v1")


def asset(name: str, identifier: int = 1, size: int = 3, digest: str | None = None) -> github.Asset:
    return github.Asset(id=identifier, name=name, size=size, digest=digest)


class PureTest(unittest.TestCase):
    def test_the_api_defaults_to_github_and_is_https_unless_it_is_this_machine(self) -> None:
        self.assertEqual(github.api_base({}), "https://api.github.com")
        self.assertEqual(
            github.api_base({"GITHUB_API_URL": "https://ghe.example.com/api/v3/"}), "https://ghe.example.com/api/v3"
        )
        self.assertEqual(github.api_base({"GITHUB_API_URL": "http://127.0.0.1:8080"}), "http://127.0.0.1:8080")
        for bad in ("http://ghe.example.com", "ftp://127.0.0.1", "api.github.com", "https://x.example.com/?a=b"):
            with self.subTest(bad=bad), self.assertRaises(github.GitHubError):
                github.api_base({"GITHUB_API_URL": bad})

    def test_the_token_is_github_token_then_gh_token(self) -> None:
        self.assertIsNone(github.token_from({}))
        self.assertIsNone(github.token_from({"GITHUB_TOKEN": " ", "GH_TOKEN": ""}))
        self.assertEqual(github.token_from({"GH_TOKEN": "b"}), "b")
        self.assertEqual(github.token_from({"GITHUB_TOKEN": "a", "GH_TOKEN": "b"}), "a")

    def test_the_upload_address_loses_its_template(self) -> None:
        template = "https://uploads.example.com/repos/o/r/releases/7/assets{?name,label}"
        self.assertEqual(
            github.upload_url_for(template, "a b+c.tar.gz"),
            "https://uploads.example.com/repos/o/r/releases/7/assets?name=a+b%2Bc.tar.gz",
        )

    def test_link_headers(self) -> None:
        header = '<https://x.example.com/a?page=2>; rel="next", <https://x.example.com/a?page=9>; rel="last"'
        self.assertEqual(github.next_link(header), "https://x.example.com/a?page=2")
        self.assertIsNone(github.next_link('<https://x.example.com/a?page=1>; rel="prev"'))
        self.assertIsNone(github.next_link(None))

    def test_a_digest_is_sha256_in_lowercase_hex_or_nothing(self) -> None:
        self.assertEqual(github.digest_hex("sha256:" + "a" * 64), "a" * 64)
        for bad in (None, "", "sha1:" + "a" * 40, "sha256:" + "A" * 64, "sha256:abc", 5):
            self.assertIsNone(github.digest_hex(bad))

    def test_assets_are_filtered_by_name_prefix_in_name_order(self) -> None:
        assets = [asset("b-1"), asset("a-2"), asset("b-0"), asset("c")]
        self.assertEqual([one["name"] for one in github.named_like(assets, "b-")], ["b-0", "b-1"])

    def test_parsing_checks_every_field(self) -> None:
        self.assertEqual(github.parse_release({"id": 5, "upload_url": "u", "x": 1}), {"id": 5, "upload_url": "u"})
        bad_releases: list[object] = [
            {},
            {"id": "5", "upload_url": "u"},
            {"id": True, "upload_url": "u"},
            {"id": 5},
            [],
            3,
        ]
        for bad_release in bad_releases:
            with self.subTest(bad=bad_release), self.assertRaises(github.GitHubError):
                github.parse_release(bad_release)
        good = {"id": 1, "name": "n", "size": 4, "digest": "sha256:" + "b" * 64}
        self.assertEqual(github.parse_asset(good), {"id": 1, "name": "n", "size": 4, "digest": "b" * 64})
        self.assertIsNone(github.parse_asset({**good, "digest": None})["digest"])
        for key in ("id", "name", "size"):
            with self.subTest(missing=key), self.assertRaises(github.GitHubError):
                github.parse_asset({k: v for k, v in good.items() if k != key})
        with self.assertRaises(github.GitHubError):
            github.parse_asset({**good, "size": -1})

    def test_an_asset_still_uploading_is_not_listed(self) -> None:
        page = [
            {"id": 1, "name": "done", "size": 1, "state": "uploaded"},
            {"id": 2, "name": "half", "size": 0, "state": "starter"},
            {"id": 3, "name": "old", "size": 1},
        ]
        self.assertEqual([one["name"] for one in github.parse_assets(page)], ["done", "old"])
        with self.assertRaises(github.GitHubError):
            github.parse_assets({})

    def test_an_unfinished_upload_under_a_partial_name_is_listed_so_it_can_be_deleted(self) -> None:
        page = [
            {"id": 1, "name": "a.tar.gz.partial-0123456789abcdef", "size": 0, "state": "starter"},
            {"id": 2, "name": "b.tar.gz", "size": 0, "state": "starter"},
        ]
        self.assertEqual([one["name"] for one in github.parse_assets(page)], ["a.tar.gz.partial-0123456789abcdef"])

    def test_error_answers(self) -> None:
        body = b'{"message":"Validation Failed","errors":[{"code":"already_exists"}]}'
        self.assertEqual(github.error_text(body), ("Validation Failed", True))
        self.assertEqual(github.error_text(b'{"message":"Not Found"}'), ("Not Found", False))
        self.assertEqual(github.error_text(b"<html>"), ("", False))
        self.assertEqual(github.error_text(b"[]"), ("", False))


class ClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def file(self, name: str, content: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(content)
        return path

    def test_a_release_is_created_found_and_lists_what_was_uploaded(self) -> None:
        fake = Fake()
        with fake_github.running(fake) as api, fake_github.environment(api):
            client = github.connect(TARGET)
            self.assertIsNone(github.release_by_tag(client))
            created = github.create_release(client)
            self.assertEqual(github.release_by_tag(client), created)
            stored = github.upload_asset(client, created, "one.bin", self.file("src", b"hello"))
            self.assertEqual(stored["digest"], hashlib.sha256(b"hello").hexdigest())
            self.assertEqual(github.list_assets(client, created), [stored])
            self.assertEqual(github.read_asset(client, stored), b"hello")
            github.delete_asset(client, stored)
            self.assertEqual(github.list_assets(client, created), [])
        self.assertEqual(fake.releases["v1"].tag, "v1")

    def test_the_headers_and_the_listing_page_size(self) -> None:
        fake = Fake()
        with fake_github.running(fake) as api, fake_github.environment(api):
            client = github.connect(TARGET)
            github.list_assets(client, github.create_release(client))
        self.assertIn(f"GET /repos/{OWNER}/{REPO}/releases/{fake.releases['v1'].id}/assets?per_page=100", fake.log)

    def test_listings_follow_the_link_header(self) -> None:
        fake = Fake(page_size=2)
        with fake_github.running(fake) as api, fake_github.environment(api):
            client = github.connect(TARGET)
            release = github.create_release(client)
            for number in range(5):
                github.upload_asset(client, release, f"a{number}", self.file(f"s{number}", b"x"))
            self.assertEqual([one["name"] for one in github.list_assets(client, release)], [f"a{n}" for n in range(5)])
        pages = [line for line in fake.log if "/assets?per_page" in line and line.startswith("GET")]
        self.assertEqual(len(pages), 3)

    def test_the_token_goes_to_the_api_host_and_not_to_the_redirect_target(self) -> None:
        fake = Fake()
        with fake_github.running(fake) as api, fake_github.environment(api):
            client = github.connect(TARGET)
            release = github.create_release(client)
            stored = github.upload_asset(client, release, "one.bin", self.file("src", b"payload"))
            self.assertEqual(github.read_asset(client, stored), b"payload")
        self.assertTrue(any(line.startswith("GET /storage/") for line in fake.log), "the download was redirected")
        hosts = {host.split(":")[0] for host, _ in fake.authorization}
        self.assertEqual(hosts, {"127.0.0.1"})
        self.assertNotIn(REDIRECT_HOST, hosts)
        self.assertEqual({value for _, value in fake.authorization}, {f"Bearer {TOKEN}"})

    def test_an_asset_without_a_digest_is_hashed_from_its_download(self) -> None:
        fake = Fake(hide_digest={"one.bin"})
        with fake_github.running(fake) as api, fake_github.environment(api):
            client = github.connect(TARGET)
            release = github.create_release(client)
            stored = github.upload_asset(client, release, "one.bin", self.file("src", b"payload"))
            self.assertIsNone(stored["digest"])
            self.assertEqual(github.asset_sha256(client, stored), hashlib.sha256(b"payload").hexdigest())
            target = self.dir / "downloaded"
            github.download_asset(client, stored, target)
            self.assertEqual(target.read_bytes(), b"payload")
            self.assertEqual([p.name for p in self.dir.iterdir() if p.name.endswith(".partial")], [])

    def test_a_download_of_the_wrong_size_is_refused_and_leaves_nothing(self) -> None:
        fake = Fake()
        with fake_github.running(fake) as api, fake_github.environment(api):
            client = github.connect(TARGET)
            stored = github.upload_asset(client, github.create_release(client), "one.bin", self.file("src", b"payload"))
            lying = github.Asset(id=stored["id"], name=stored["name"], size=99, digest=None)
            target = self.dir / "downloaded"
            with self.assertRaisesRegex(github.GitHubError, "is 7 bytes, not the 99"):
                github.download_asset(client, lying, target)
            self.assertFalse(target.exists())
            self.assertEqual([p.name for p in self.dir.iterdir() if p.name.endswith(".partial")], [])

    def test_a_5xx_answer_is_tried_again(self) -> None:
        fake = Fake(fail_once=[f"GET /repos/{OWNER}/{REPO}/releases/tags"])
        with fake_github.running(fake) as api, fake_github.environment(api):
            client = github.connect(TARGET)
            self.assertIsNone(github.release_by_tag(client))
        self.assertEqual(len([line for line in fake.log if "/releases/tags/v1" in line]), 2)

    def test_an_upload_is_tried_again_after_a_5xx_too(self) -> None:
        fake = Fake(fail_once=["POST /upload"])
        with fake_github.running(fake) as api, fake_github.environment(api):
            client = github.connect(TARGET)
            release = github.create_release(client)
            github.upload_asset(client, release, "one.bin", self.file("src", b"payload"))
        self.assertEqual(fake.assets("v1"), {"one.bin": b"payload"})

    def test_a_5xx_that_does_not_stop_is_an_error_after_the_last_try(self) -> None:
        fake = Fake(fail_once=[f"GET /repos/{OWNER}/{REPO}/releases/tags"] * github.ATTEMPTS)
        with (
            fake_github.running(fake) as api,
            fake_github.environment(api),
            self.assertRaisesRegex(github.GitHubError, "reading the release: HTTP 503"),
        ):
            github.release_by_tag(github.connect(TARGET))
        self.assertEqual(len(fake.log), github.ATTEMPTS)

    def test_a_connection_that_fails_is_an_error_naming_the_target(self) -> None:
        with fake_github.environment("http://127.0.0.1:9"), self.assertRaises(github.GitHubError) as caught:
            github.release_by_tag(github.connect(TARGET))
        self.assertIn(f"github-release://{OWNER}/{REPO}@v1", str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_a_client_error_is_not_tried_again(self) -> None:
        fake = Fake()
        with fake_github.running(fake) as api, fake_github.environment(api):
            client = github.connect(TARGET)
            release = github.create_release(client)
            with self.assertRaisesRegex(github.GitHubError, "HTTP 404"):
                github.delete_asset(client, asset("none", 4242))
            self.assertEqual(release["id"], fake.releases["v1"].id)
        self.assertEqual(len([line for line in fake.log if line.startswith("DELETE")]), 1)

    def test_a_private_repository_answers_an_anonymous_client_with_the_reason(self) -> None:
        fake = Fake()
        with fake_github.running(fake) as api, fake_github.environment(api, token=None):
            client = github.connect(TARGET)
            self.assertIsNone(github.release_by_tag(client))  # a 404 reads as no release
            with self.assertRaises(github.GitHubError) as caught:
                github.create_release(client)
        self.assertIn("anonymous", str(caught.exception))
        self.assertIn("HTTP 404", str(caught.exception))
        self.assertEqual(fake.releases, {})

    def test_a_refused_token_is_reported_without_being_printed(self) -> None:
        fake = Fake()
        with (
            fake_github.running(fake) as api,
            fake_github.environment(api, token="wr0ng-t0ken"),
            self.assertRaises(github.GitHubError) as caught,
        ):
            github.create_release(github.connect(TARGET))
        self.assertIn("the token may be refused", str(caught.exception))
        self.assertNotIn("wr0ng-t0ken", str(caught.exception))

    def test_a_public_repository_reads_without_a_token(self) -> None:
        fake = Fake(token=None)
        with fake_github.running(fake) as api, fake_github.environment(api, token=None):
            client = github.connect(TARGET)
            self.assertIsNone(github.release_by_tag(client))
            github.create_release(client)
        self.assertEqual(fake.authorization, [])

    def test_a_second_upload_of_a_name_is_reported_and_overwrites_nothing(self) -> None:
        fake = Fake()
        with fake_github.running(fake) as api, fake_github.environment(api):
            client = github.connect(TARGET)
            release = github.create_release(client)
            github.upload_asset(client, release, "one.bin", self.file("src", b"first"))
            with self.assertRaisesRegex(github.AlreadyExistsError, "already holds an asset called one.bin"):
                github.upload_asset(client, release, "one.bin", self.file("src2", b"second"))
        self.assertEqual(fake.assets("v1"), {"one.bin": b"first"})

    def test_an_upload_address_that_does_not_use_the_apis_scheme_is_refused(self) -> None:
        fake = Fake()
        with fake_github.running(fake) as api, fake_github.environment(api):
            client = github.connect(TARGET)
            elsewhere = github.Release(id=1, upload_url="https://uploads.example.com/x/assets{?name,label}")
            with self.assertRaisesRegex(github.GitHubError, "scheme"):
                github.upload_asset(client, elsewhere, "one.bin", self.file("src", b"x"))
        self.assertEqual(fake.authorization, [])

    def test_a_large_records_asset_is_not_read_into_memory(self) -> None:
        with fake_github.running(Fake()) as api, fake_github.environment(api):
            client = github.connect(TARGET)
            with self.assertRaisesRegex(github.GitHubError, "over 10"):
                github.read_asset(client, asset("big", size=11), limit=10)


if __name__ == "__main__":
    unittest.main()
