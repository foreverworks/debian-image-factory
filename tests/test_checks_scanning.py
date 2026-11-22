"""Finding a snapshot ID and a private key in chunks, including across the boundary between two."""

import itertools
import unittest

from debian_image_factory.checks import scanning

NEEDLE = b"20261121T004329Z"
KEY = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n"
CHUNK = 64 * 1024


def split_at(data: bytes, *offsets: int) -> list[bytes]:
    cuts = [0, *offsets, len(data)]
    return [data[a:b] for a, b in itertools.pairwise(cuts)]


class NeedleTest(unittest.TestCase):
    def test_found_in_one_chunk_and_absent(self) -> None:
        self.assertTrue(scanning.scan([b"x " + NEEDLE + b" y"], NEEDLE, False).needle)
        self.assertFalse(scanning.scan([b"nothing here", b"or here"], NEEDLE, False).needle)

    def test_found_across_every_split_point(self) -> None:
        data = b"." * 20 + NEEDLE + b"." * 20
        for cut in range(21, 20 + len(NEEDLE) + 1):
            with self.subTest(cut=cut):
                self.assertTrue(scanning.scan(split_at(data, cut), NEEDLE, False).needle)

    def test_found_across_the_64_kib_boundary(self) -> None:
        data = b"a" * (CHUNK - 8) + NEEDLE + b"b" * 100
        chunks = split_at(data, CHUNK)
        self.assertEqual(len(chunks[0]), CHUNK)
        self.assertTrue(scanning.scan(chunks, NEEDLE, False).needle)

    def test_not_asked_for_is_not_reported(self) -> None:
        self.assertFalse(scanning.scan([NEEDLE + KEY], None, False).needle)
        self.assertFalse(scanning.scan([NEEDLE + KEY], None, False).key)


class KeyTest(unittest.TestCase):
    def found(self, *chunks: bytes) -> bool:
        return scanning.scan(chunks, None, True).key

    def test_the_kinds_of_key_file(self) -> None:
        body = b"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
        for label in (b"RSA ", b"EC ", b"DSA ", b"OPENSSH ", b"ENCRYPTED ", b""):
            with self.subTest(label=label):
                self.assertTrue(self.found(b"-----BEGIN " + label + b"PRIVATE KEY-----\n" + body))
        self.assertTrue(self.found(b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES\n"))
        self.assertTrue(self.found(b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQcYBF\n"))
        self.assertTrue(self.found(b"-----BEGIN PRIVATE KEY-----\r\nMIIEvQIBADANBgkqhkiG9w0BAQ"))

    def test_found_below_other_text_and_across_a_boundary(self) -> None:
        self.assertTrue(self.found(b"# a key\n\n" + KEY))
        data = b"line\n" * 10 + KEY
        for cut in range(40, len(data) - 5):
            with self.subTest(cut=cut):
                self.assertTrue(self.found(*split_at(data, cut)))
        padded = b"x\n" * (CHUNK // 2 - 20) + KEY
        self.assertTrue(self.found(*split_at(padded, CHUNK)))

    def test_text_about_keys_is_not_a_key(self) -> None:
        prose = b"Put the line -----BEGIN RSA PRIVATE KEY----- at the top.\n"
        self.assertFalse(self.found(prose))
        self.assertFalse(self.found(b"  -----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQ\n"))
        self.assertFalse(self.found(b"-----BEGIN RSA PRIVATE KEY-----\n...\n"))
        self.assertFalse(self.found(b"-----BEGIN CERTIFICATE-----\nMIIEvQIBADANBgkqhkiG9w0BAQ\n"))
        self.assertFalse(self.found(b"-----BEGIN PUBLIC KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQ\n"))

    def test_a_chunk_that_starts_mid_line_is_not_a_line_start(self) -> None:
        self.assertFalse(
            self.found(b"the header is -----BEGIN RSA", b" PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQ\n")
        )
        self.assertFalse(self.found(b"x" * 200 + b"-----BEGIN RSA PRIVATE KEY-----\n", b"MIIEvQIBADANBgkqhkiG9w0BAQ\n"))

    def test_the_overlap_covers_the_longest_match(self) -> None:
        longest = b"-----BEGIN " + b"A" * 16 + b" " + b"B" * 16 + b" " + b"C" * 16 + b" PRIVATE KEY BLOCK-----\r\n"
        self.assertLess(len(longest) + 16 + 1, scanning.OVERLAP)
        self.assertTrue(self.found(*split_at(b"\n" + longest + b"A" * 16, 60)))


def fake(prefix: str, body: str, length: int) -> bytes:
    """A made-up token of a real shape: no token-shaped string sits in this file, it is built here."""
    return (prefix + (body * length)[:length]).encode()


ALNUM = "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
DIGITS = "1234567890"

SHAPES: dict[str, bytes] = {
    "GitHub token": fake("gh" + "p_", ALNUM, 36),
    "GitHub fine-grained token": fake("github" + "_pat_", ALNUM + "_", 82),
    "AWS access key ID": fake("AK" + "IA", BASE32, 16),
    "Slack token": b"xo" + b"xb-" + DIGITS.encode() + b"-" + (DIGITS * 2).encode()[:13] + b"-" + fake("", ALNUM, 24),
    "Slack app-level token": b"xa"
    + b"pp-1-"
    + fake("A", ALNUM, 10)[:10]
    + b"-"
    + DIGITS.encode()
    + b"123-"
    + fake("", ALNUM, 64),
    "npm token": fake("npm" + "_", ALNUM, 36),
    "PyPI token": fake("pypi" + "-AgEIcHlwaS5vcmc", ALNUM + "-_", 70),
    "GitLab token": fake("glpa" + "t-", ALNUM + "-_", 20),
}


class TokenTest(unittest.TestCase):
    def kinds(self, *chunks: bytes) -> list[str]:
        return [hit.kind for hit in scanning.scan(chunks, None, True).tokens]

    def test_every_shape_is_found_alone_and_in_text(self) -> None:
        for kind, token in SHAPES.items():
            for text in (token, b"before " + token + b" after\n", b'KEY="' + token + b'"\n', b"x\n" + token):
                with self.subTest(kind=kind, text=text[:12]):
                    self.assertEqual(self.kinds(text), [kind])

    def test_the_github_prefixes(self) -> None:
        for letter in "pousr":
            with self.subTest(letter=letter):
                self.assertEqual(self.kinds(fake(f"gh{letter}_", ALNUM, 36)), ["GitHub token"])
        self.assertEqual(self.kinds(fake("ghx_", ALNUM, 36)), [])

    def test_aws_temporary_keys_and_the_documentation_example(self) -> None:
        self.assertEqual(self.kinds(fake("AS" + "IA", BASE32, 16)), ["AWS access key ID"])
        self.assertEqual(self.kinds(b"AKIA" + b"IOSFODNN7" + b"EXAMPLE"), [], "AWS's own sample")
        self.assertEqual(
            self.kinds(b"AKIA" + b"IOSFODNN7" + b"EXAMPLE\n" + SHAPES["AWS access key ID"]), ["AWS access key ID"]
        )

    def test_slack_prefixes(self) -> None:
        for letter in "abprs":
            token = b"xo" + f"x{letter}-".encode() + DIGITS.encode() + b"-" + fake("", ALNUM, 24)
            with self.subTest(letter=letter):
                self.assertEqual(self.kinds(token), ["Slack token"])
        legacy = b"xo" + b"xb-" + b"263594206564-" + fake("", ALNUM, 24)
        self.assertEqual(self.kinds(legacy), ["Slack token"])
        user = b"xo" + b"xp-" + b"-".join([b"41684372915", b"1320496754", b"45609968301"]) + b"-" + fake("", "ab12", 32)
        self.assertEqual(self.kinds(user), ["Slack token"])

    def test_too_short_or_wrong_shapes_are_not_tokens(self) -> None:
        short = {
            "gh" + "p_": 35, "github" + "_pat_": 81, "AK" + "IA": 15, "npm" + "_": 35, "glpa" + "t-": 19,
        }  # fmt: skip
        for prefix, length in short.items():
            with self.subTest(prefix=prefix):
                self.assertEqual(self.kinds(fake(prefix, BASE32, length)), [])
        self.assertEqual(self.kinds(fake("pypi" + "-AgEIcHlwaS5vcmc", ALNUM, 49)), [])
        self.assertEqual(self.kinds(b"xo" + b"xb-123-abc"), [])
        self.assertEqual(self.kinds(fake("npm" + "_", "a_", 40)), [], "underscores end the run of letters and digits")

    def test_a_longer_run_of_letters_before_the_prefix_is_not_a_token(self) -> None:
        for kind in ("GitHub token", "npm token", "GitLab token"):
            with self.subTest(kind=kind):
                self.assertEqual(self.kinds(b"abc" + SHAPES[kind]), [])
                self.assertEqual(self.kinds(b"-" + SHAPES[kind]), [kind])

    def test_aws_keys_must_end_where_the_run_of_capitals_ends(self) -> None:
        self.assertEqual(self.kinds(SHAPES["AWS access key ID"] + b"Z"), [])
        self.assertEqual(self.kinds(SHAPES["AWS access key ID"] + b"."), ["AWS access key ID"])

    def test_found_across_every_boundary_of_a_chunk(self) -> None:
        for kind, token in SHAPES.items():
            data = b"head\n" + token + b"\ntail\n"
            for cut in range(6, 5 + len(token)):
                with self.subTest(kind=kind, cut=cut):
                    self.assertEqual(self.kinds(*split_at(data, cut)), [kind])

    def test_found_across_the_64_kib_boundary(self) -> None:
        for kind, token in SHAPES.items():
            data = b"x\n" * ((CHUNK - len(token) // 2) // 2) + token + b"\n"
            with self.subTest(kind=kind):
                self.assertEqual(self.kinds(*split_at(data, CHUNK)), [kind])

    def test_a_chunk_that_starts_inside_a_longer_run_is_not_a_line_start(self) -> None:
        token = SHAPES["GitHub token"]
        self.assertEqual(self.kinds(b"z" * 40, token), [])

    def test_the_overlap_covers_the_longest_token(self) -> None:
        longest = len(b"pypi-AgEIcHlwaS5vcmc") + 1000
        self.assertGreater(scanning.OVERLAP, longest)
        self.assertEqual(
            self.kinds(*split_at(b"\n" + fake("pypi" + "-AgEIcHlwaS5vcmc", ALNUM, 1000), 700)), ["PyPI token"]
        )

    def test_the_report_never_holds_the_token(self) -> None:
        for kind, token in SHAPES.items():
            hits = scanning.scan([token], None, True).tokens
            with self.subTest(kind=kind):
                self.assertEqual(len(hits), 1)
                self.assertNotIn(token.decode()[8:], hits[0].redacted)
                self.assertIn(f"({len(token)} characters)", hits[0].redacted)

    def test_not_asked_for_is_not_reported(self) -> None:
        self.assertEqual(scanning.scan([SHAPES["npm token"]], None, False).tokens, ())

    def test_executables_are_not_searched_for_tokens_but_for_keys(self) -> None:
        program = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"strings\n"
        self.assertEqual(self.kinds(program + SHAPES["GitHub token"]), [])
        self.assertEqual(self.kinds(program, SHAPES["GitHub token"]), [])
        self.assertTrue(scanning.scan([program + b"\n" + KEY], None, True).key)
        self.assertEqual(self.kinds(b"#!/bin/sh\n" + SHAPES["GitHub token"]), ["GitHub token"], "a script is text")

    def test_one_hit_per_kind_in_a_known_order(self) -> None:
        both = SHAPES["npm token"] + b"\n" + SHAPES["GitHub token"] + b"\n" + SHAPES["GitHub token"]
        self.assertEqual(self.kinds(both), ["GitHub token", "npm token"])

    def test_a_key_and_a_token_are_both_reported_and_the_needle_still_found(self) -> None:
        found = scanning.scan([KEY + SHAPES["npm token"] + NEEDLE], NEEDLE, True)
        self.assertTrue(found.key and found.needle)
        self.assertEqual([hit.kind for hit in found.tokens], ["npm token"])

    def test_ordinary_text_is_clean(self) -> None:
        prose = (
            b"The GitHub token starts with ghp_ and the npm one with npm_; an AWS key starts with AKIA.\n"
            b"npm_config_prefix=/usr/local\nghs_ is a prefix, glpat- too, xoxb- also, pypi-AgEIcHlwaS5vcmc as well.\n"
            b"ASIAN_PACIFIC_REGION_CODE and AKIAMBIGUOUS are words.\n"
        )
        self.assertEqual(self.kinds(prose), [])
