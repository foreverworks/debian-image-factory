"""Finding a snapshot ID and a private key in chunks, including across the boundary between two."""

import unittest

from debian_image_factory.checks import scanning

NEEDLE = b"20261121T004329Z"
KEY = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n"
CHUNK = 64 * 1024


def split_at(data: bytes, *offsets: int) -> list[bytes]:
    cuts = [0, *offsets, len(data)]
    return [data[a:b] for a, b in zip(cuts, cuts[1:], strict=False)]


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
        self.assertFalse(self.found(b"the header is -----BEGIN RSA", b" PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQ\n"))
        self.assertFalse(self.found(b"x" * 200 + b"-----BEGIN RSA PRIVATE KEY-----\n", b"MIIEvQIBADANBgkqhkiG9w0BAQ\n"))

    def test_the_overlap_covers_the_longest_match(self) -> None:
        longest = b"-----BEGIN " + b"A" * 16 + b" " + b"B" * 16 + b" " + b"C" * 16 + b" PRIVATE KEY BLOCK-----\r\n"
        self.assertLess(len(longest) + 16 + 1, scanning.OVERLAP)
        self.assertTrue(self.found(*split_at(b"\n" + longest + b"A" * 16, 60)))
