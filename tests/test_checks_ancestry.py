"""`ancestry`: the parent's layers are the first layers, and the base digest annotation names the parent."""

import unittest

from debian_image_factory import oci
from debian_image_factory.checks import ancestry
from debian_image_factory.checks.model import NotRun, Result

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


if __name__ == "__main__":
    unittest.main()
