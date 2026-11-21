import unittest

from debian_image_factory import debian

SHA_A = "a" * 64
SHA_B = "b" * 64

RELEASE = f"""Origin: Example
Suite: trixie
Acquire-By-Hash: yes
SHA256:
 {SHA_A}     1234 main/binary-amd64/Packages
 {SHA_B}      321 main/binary-amd64/Packages.xz
"""

PACKAGES = """Package: base-files
Version: 1.0
Architecture: amd64
Essential: yes
Description: first line
 continued line
 .
 last line

Package: fixture-essential
Version: 1.0
Architecture: all
Essential: yes

Package: other-arch
Version: 1.0
Architecture: arm64
Essential: yes

Package: not-essential
Version: 1.0
Architecture: amd64
"""


class ParseDeb822Test(unittest.TestCase):
    def test_paragraphs_and_continuations(self) -> None:
        stanzas = debian.parse_deb822(PACKAGES)
        self.assertEqual(len(stanzas), 4)
        self.assertEqual(stanzas[0]["Description"], "first line\n continued line\n .\n last line")
        self.assertEqual(stanzas[1]["Package"], "fixture-essential")

    def test_case_is_preserved_and_blank_runs_collapse(self) -> None:
        stanzas = debian.parse_deb822("\n\nMiXeD-case: v\n\n\n\nB: w\n\n")
        self.assertEqual(stanzas, [{"MiXeD-case": "v"}, {"B": "w"}])

    def test_empty_and_comments(self) -> None:
        self.assertEqual(debian.parse_deb822(""), [])
        self.assertEqual(debian.parse_deb822("# c\nA: 1\n# d\nB: 2\n"), [{"A": "1", "B": "2"}])

    def test_repeated_field_is_an_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "repeated"):
            debian.parse_deb822("A: 1\nB: 2\nA: 3\n")
        with self.assertRaisesRegex(ValueError, "repeated"):
            debian.parse_deb822("Package: x\npackage: y\n")

    def test_same_field_in_two_paragraphs_is_fine(self) -> None:
        self.assertEqual(len(debian.parse_deb822("A: 1\n\nA: 2\n")), 2)

    def test_malformed_lines(self) -> None:
        with self.assertRaises(ValueError):
            debian.parse_deb822(" continuation first\n")
        with self.assertRaises(ValueError):
            debian.parse_deb822("no colon here\n")
        with self.assertRaises(ValueError):
            debian.parse_deb822(": value\n")

    def test_field_lookup_ignores_case(self) -> None:
        self.assertEqual(debian.field({"Acquire-By-Hash": "yes"}, "acquire-by-hash"), "yes")
        self.assertIsNone(debian.field({"A": "1"}, "B"))


class ReleaseTest(unittest.TestCase):
    def test_release_files(self) -> None:
        self.assertEqual(
            debian.release_files(RELEASE),
            {"main/binary-amd64/Packages": (SHA_A, 1234), "main/binary-amd64/Packages.xz": (SHA_B, 321)},
        )

    def test_missing_sha256_field(self) -> None:
        with self.assertRaisesRegex(ValueError, "no SHA256"):
            debian.release_files("Suite: trixie\n")

    def test_bad_lines(self) -> None:
        for line in (f" {SHA_A} 12", " nothex 12 path", f" {SHA_A} twelve path", f" {SHA_A} 12 path extra"):
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, "bad SHA256"):
                debian.release_files(f"SHA256:\n{line}\n")

    def test_duplicate_path(self) -> None:
        with self.assertRaisesRegex(ValueError, "twice"):
            debian.release_files(f"SHA256:\n {SHA_A} 1 p\n {SHA_B} 2 p\n")

    def test_one_paragraph_only(self) -> None:
        with self.assertRaisesRegex(ValueError, "one paragraph"):
            debian.release_files(RELEASE + "\nSuite: other\n")

    def test_acquire_by_hash(self) -> None:
        self.assertTrue(debian.acquire_by_hash(RELEASE))
        self.assertFalse(debian.acquire_by_hash("Suite: x\n"))
        self.assertFalse(debian.acquire_by_hash("Acquire-By-Hash: no\n"))

    def test_by_hash_path(self) -> None:
        self.assertEqual(
            debian.by_hash_path("dists/trixie", "main/binary-amd64/Packages.xz", SHA_B),
            f"dists/trixie/main/binary-amd64/by-hash/SHA256/{SHA_B}",
        )
        self.assertEqual(
            debian.by_hash_path("dists/trixie/", "Contents-amd64.gz", SHA_A), f"dists/trixie/by-hash/SHA256/{SHA_A}"
        )
        with self.assertRaises(ValueError):
            debian.by_hash_path("dists/trixie", "main/x", "short")


class PackagesTest(unittest.TestCase):
    def test_essential_for_arch_or_all(self) -> None:
        stanzas = debian.packages_stanzas(PACKAGES)
        self.assertEqual(debian.essential(stanzas, "amd64"), ["base-files", "fixture-essential"])
        self.assertEqual(debian.essential(stanzas, "arm64"), ["fixture-essential", "other-arch"])
        self.assertEqual(debian.essential(stanzas, "riscv64"), ["fixture-essential"])

    def test_essential_needs_a_package_name(self) -> None:
        with self.assertRaises(ValueError):
            debian.essential([{"Essential": "yes", "Architecture": "all"}], "amd64")


if __name__ == "__main__":
    unittest.main()
