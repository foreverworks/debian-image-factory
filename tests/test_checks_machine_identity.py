"""`no-machine-identity`: every test, passing and failing."""

import unittest
from collections.abc import Mapping, Sequence

from debian_image_factory.checks import machine_identity
from debian_image_factory.checks.model import Result
from debian_image_factory.checks.tarball import Member

ALL_TESTS = (
    "machine-id-empty-or-uninitialized",
    "no-dbus-machine-id",
    "no-hostname",
    "no-resolver-config",
    "no-ssh-host-keys",
    "no-private-keys",
    "no-random-seed",
    "no-cloud-init-state",
)


def file(path: str) -> Member:
    return Member(path, "file")


def run(members: Sequence[Member], contents: Mapping[str, bytes] | None = None, keys: Sequence[str] = ()) -> Result:
    return machine_identity.no_machine_identity(members, contents or {}, keys)


class PassingTest(unittest.TestCase):
    def test_an_empty_tree_passes_every_test(self) -> None:
        found = run([])
        self.assertEqual(found.outcome, "PASSED")
        self.assertEqual(sorted(found.passed), sorted(ALL_TESTS))
        self.assertEqual(found.failed, ())
        self.assertEqual(found.check, "no-machine-identity")

    def test_what_is_allowed(self) -> None:
        members = [
            file("/etc/machine-id"),
            file("/etc/hostname"),
            Member("/etc/resolv.conf", "symlink", "../run/systemd/resolve/stub-resolv.conf"),
            Member("/var/lib/dbus/machine-id", "symlink", "/etc/machine-id"),
            Member("/var/lib/cloud", "dir"),
            Member("/var/lib/cloud/instances", "dir"),
            Member("/etc/ssh", "dir"),
            file("/etc/ssh/sshd_config"),
        ]
        for content in (b"", b"uninitialized\n"):
            with self.subTest(content=content):
                found = run(members, {"/etc/machine-id": content, "/etc/hostname": b""})
                self.assertEqual(found.outcome, "PASSED", found.failed)

    def test_a_relative_link_to_the_machine_id_is_allowed(self) -> None:
        link = Member("/var/lib/dbus/machine-id", "symlink", "../../../etc/machine-id")
        self.assertEqual(run([link]).outcome, "PASSED")

    def test_an_absent_machine_id_passes(self) -> None:
        self.assertIn("machine-id-empty-or-uninitialized", run([file("/etc/os-release")]).passed)


class FailingTest(unittest.TestCase):
    def failed(self, found: Result) -> list[str]:
        self.assertEqual(found.outcome, "FAILED")
        return [name.split(":")[0] for name in found.failed]

    def test_a_machine_id_with_an_identity(self) -> None:
        found = run([file("/etc/machine-id")], {"/etc/machine-id": b"0123456789abcdef0123456789abcdef\n"})
        self.assertEqual(self.failed(found), ["machine-id-empty-or-uninitialized"])
        self.assertNotIn("machine-id-empty-or-uninitialized", found.passed)
        self.assertIn("no-ssh-host-keys", found.passed)

    def test_a_machine_id_that_is_a_link(self) -> None:
        found = run([Member("/etc/machine-id", "symlink", "/run/machine-id")])
        self.assertEqual(self.failed(found), ["machine-id-empty-or-uninitialized"])

    def test_a_dbus_machine_id(self) -> None:
        for member in (file("/var/lib/dbus/machine-id"), Member("/var/lib/dbus/machine-id", "symlink", "/elsewhere")):
            with self.subTest(member=member):
                self.assertEqual(self.failed(run([member], {"/var/lib/dbus/machine-id": b""})), ["no-dbus-machine-id"])

    def test_a_hostname(self) -> None:
        self.assertEqual(self.failed(run([file("/etc/hostname")], {"/etc/hostname": b"build-host\n"})), ["no-hostname"])
        self.assertEqual(self.failed(run([Member("/etc/hostname", "symlink", "x")])), ["no-hostname"])

    def test_a_resolver_config_copied_from_the_build_host(self) -> None:
        found = run([file("/etc/resolv.conf")], {"/etc/resolv.conf": b"nameserver 192.0.2.1\n"})
        self.assertEqual(self.failed(found), ["no-resolver-config"])

    def test_ssh_host_keys_of_every_kind(self) -> None:
        members = [file("/etc/ssh/ssh_host_ed25519_key"), file("/etc/ssh/ssh_host_rsa_key.pub")]
        found = run(members)
        self.assertEqual(self.failed(found), ["no-ssh-host-keys", "no-ssh-host-keys"])
        self.assertIn("/etc/ssh/ssh_host_ed25519_key", found.failed[0])

    def test_private_keys_are_named(self) -> None:
        found = run([], keys=["/root/.ssh/id_rsa", "/srv/key.pem"])
        self.assertEqual(found.failed, ("no-private-keys: /root/.ssh/id_rsa", "no-private-keys: /srv/key.pem"))

    def test_tokens_are_named_as_the_scan_reports_them(self) -> None:
        found = run([], keys=["/root/.npmrc (npm token: npm_…(40 characters))"])
        self.assertEqual(found.failed, ("no-private-keys: /root/.npmrc (npm token: npm_…(40 characters))",))

    def test_random_seeds(self) -> None:
        found = run([file("/var/lib/systemd/random-seed"), file("/var/lib/urandom/random-seed")])
        self.assertEqual(self.failed(found), ["no-random-seed", "no-random-seed"])

    def test_cloud_init_state(self) -> None:
        for members in (
            [Member("/var/lib/cloud/instance", "symlink", "instances/i-1")],
            [Member("/var/lib/cloud/instance", "dir")],
            [Member("/var/lib/cloud/instances/i-1", "dir")],
            [file("/var/lib/cloud/instances/i-1/user-data.txt")],
        ):
            with self.subTest(members=members):
                self.assertEqual(self.failed(run(members)), ["no-cloud-init-state"])

    def test_several_failures_are_all_listed_and_the_rest_still_pass(self) -> None:
        found = run([file("/etc/ssh/ssh_host_rsa_key"), file("/var/lib/systemd/random-seed")], keys=["/k"])
        self.assertEqual(sorted(set(self.failed(found))), ["no-private-keys", "no-random-seed", "no-ssh-host-keys"])
        self.assertEqual(len(found.passed), len(ALL_TESTS) - 3)
