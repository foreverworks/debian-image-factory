"""`ancestry`: the parent's layers are the first layers, and the base digest annotation names the parent; for a
root filesystem, the parent's files are present but for those of packages the child removed."""

import unittest

from debian_image_factory import oci
from debian_image_factory.checks import ancestry
from debian_image_factory.checks.model import NotRun, Result
from debian_image_factory.checks.tarball import Member

A, B, C, D = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)


def annotations(base: str | None) -> dict[str, str]:
    return {} if base is None else {oci.BASE_DIGEST: f"sha256:{base}"}


def run(layers: list[str], base: str | None, parent: ancestry.Parent | str) -> Result:
    found = ancestry.ancestry(layers, annotations(base), parent)
    assert isinstance(found, Result)
    return found


class AncestryTest(unittest.TestCase):
    def test_a_core_parent_is_the_first_layer(self) -> None:
        found = run([A, B], A, ancestry.Parent(A, (A,)))
        self.assertEqual(found.outcome, "PASSED")
        self.assertEqual(found.passed, ("parent-layers-are-first", "base-digest-annotation"))

    def test_an_oci_parent_s_layers_are_a_prefix(self) -> None:
        self.assertEqual(run([A, B, C], D, ancestry.Parent(D, (A, B))).outcome, "PASSED")

    def test_a_child_that_adds_nothing_passes(self) -> None:
        self.assertEqual(run([A, B], D, ancestry.Parent(D, (A, B))).outcome, "PASSED")

    def test_layers_in_the_wrong_order_fail_naming_the_first_difference(self) -> None:
        found = run([B, A, C], D, ancestry.Parent(D, (A, B)))
        self.assertEqual(found.outcome, "FAILED")
        self.assertEqual(found.passed, ("base-digest-annotation",))
        self.assertEqual(found.failed, (f"parent-layers-are-first: layer 1 is sha256:{B}, the parent's is sha256:{A}",))

    def test_a_different_first_layer_fails(self) -> None:
        found = run([C], A, ancestry.Parent(A, (A,)))
        self.assertEqual(found.failed, (f"parent-layers-are-first: layer 1 is sha256:{C}, the parent's is sha256:{A}",))

    def test_fewer_layers_than_the_parent_fail(self) -> None:
        found = run([A], D, ancestry.Parent(D, (A, B)))
        self.assertEqual(found.failed, ("parent-layers-are-first: the image has 1 layers, the parent 2",))

    def test_a_wrong_base_digest_fails_only_that_test(self) -> None:
        found = run([A, B], C, ancestry.Parent(A, (A,)))
        self.assertEqual(found.passed, ("parent-layers-are-first",))
        self.assertEqual(
            found.failed,
            (f"base-digest-annotation: {oci.BASE_DIGEST} is sha256:{C}, the parent artifact is sha256:{A}",),
        )

    def test_a_missing_or_malformed_annotation_fails(self) -> None:
        missing = run([A], None, ancestry.Parent(A, (A,)))
        self.assertEqual(missing.failed, (f"base-digest-annotation: the manifest has no {oci.BASE_DIGEST} annotation",))
        bad = ancestry.ancestry([A], {oci.BASE_DIGEST: "md5:1"}, ancestry.Parent(A, (A,)))
        assert isinstance(bad, Result)
        self.assertEqual(bad.outcome, "FAILED")

    def test_a_parent_that_is_not_available_is_not_run_with_its_reason(self) -> None:
        found = ancestry.ancestry([A], annotations(A), "the parent oci-base is not in the output")
        self.assertEqual(found, NotRun("ancestry", "the parent oci-base is not in the output"))

    def test_a_parent_known_only_by_digest_is_not_run(self) -> None:
        found = ancestry.ancestry([A], annotations(D), ancestry.Parent(D, None))
        self.assertIsInstance(found, NotRun)


PARENT = tuple(
    Member(p.rstrip("/") or "/", "dir" if p.endswith("/") else "file")
    for p in ("/", "/usr/", "/usr/bin/", "/usr/bin/vim", "/usr/bin/sh", "/usr/share/doc/vim/copyright", "/dev/null")
)


class RootAncestryTest(unittest.TestCase):
    def check(self, child: list[Member], recorded: list[str] | str, named: str | None = A) -> Result:
        found = ancestry.root_ancestry(child, PARENT, A, named, recorded)
        assert isinstance(found, Result)
        return found

    def test_a_child_with_every_parent_file_passes(self) -> None:
        found = self.check([*PARENT, Member("/usr/bin/extra", "file")], [])
        self.assertEqual(found.outcome, "PASSED")
        self.assertEqual(found.passed, ("parent-files-present", "provenance-names-parent"))

    def test_what_the_build_recorded_as_removed_may_go(self) -> None:
        child = [m for m in PARENT if not m.path.startswith(("/usr/share", "/dev"))]
        removed = ancestry.removed_from_parent(child, PARENT)
        self.assertEqual(removed, ["/dev/null", "/usr/share/doc/vim/copyright"])
        self.assertEqual(self.check(child, removed).outcome, "PASSED")

    def test_a_file_gone_and_not_recorded_fails(self) -> None:
        child = [m for m in PARENT if m.path != "/usr/bin/sh"]
        self.assertEqual(
            self.check(child, []).failed,
            (
                f"parent-files-present: /usr/bin/sh is in the parent sha256:{A[:12]}, "
                "not here and not recorded as removed",
            ),
        )

    def test_the_root_directory_need_not_be_a_member(self) -> None:
        child = [m for m in PARENT if m.path != "/"]
        self.assertEqual(ancestry.removed_from_parent(child, PARENT), [])
        self.assertEqual(self.check(child, []).outcome, "PASSED")

    def test_a_provenance_naming_another_parent_fails(self) -> None:
        found = self.check(list(PARENT), [], named=B)
        self.assertEqual(found.failed, (f"provenance-names-parent: the provenance names {B}, the parent is {A}",))

    def test_an_absent_parent_is_not_run_and_unreadable_records_fail(self) -> None:
        self.assertIsInstance(ancestry.root_ancestry([], "the parent core is not here", "", None, []), NotRun)
        found = self.check([], "there is no records file for this artifact")
        self.assertEqual(found.failed, ("parent-files-present: there is no records file for this artifact",))


if __name__ == "__main__":
    unittest.main()
