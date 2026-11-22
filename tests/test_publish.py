"""Publishing to a `dir://` target: artifacts copied once, records merged, nothing rewritten, and a
plan's lookup finds what was published."""

import hashlib
import io
import tempfile
import unittest
from pathlib import Path

from input_lock.records import envelope, jsonl, statement, subject

from debian_image_factory import cli, commands, publish, published, targets

IDENTITY = "1" * 64


def provenance_line(name: str, digest: str) -> str:
    predicate = {
        "buildDefinition": {
            "buildType": "https://example.com/build-type",
            "externalParameters": {"image": "core"},
            "internalParameters": {"identity": IDENTITY},
            "resolvedDependencies": [],
        },
        "runDetails": {"builder": {"id": "https://example.com/builder"}, "metadata": {}},
    }
    record = statement([subject(name, digest)], "https://slsa.dev/provenance/v1", predicate)  # type: ignore[arg-type]  # a hand-made predicate, shaped as the lookup reads it
    return jsonl([envelope(record)])


def make_out(out: Path, content: bytes = b"rootfs") -> tuple[str, str]:
    out.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(content).hexdigest()
    name = published.artifact_name("core", "trixie", "amd64", IDENTITY, digest, "tar.gz")
    (out / name).write_bytes(content)
    (out / published.records_name_for(digest)).write_text(provenance_line(name, digest))
    (out / "plan.json").write_text("{}")
    (out / "core.build.log").write_text("log")
    return name, digest


class MergeTest(unittest.TestCase):
    def test_merge_keeps_what_is_there_and_appends_only_new_lines(self) -> None:
        self.assertEqual(publish.merged_lines("a\nb\n", "b\nc\n\nc\n"), "a\nb\nc\n")
        self.assertEqual(publish.merged_lines("", "x\n"), "x\n")


class PublishDirTest(unittest.TestCase):
    def test_publish_copies_artifacts_and_records_only(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            out, target = Path(scratch) / "out", Path(scratch) / "target"
            name, digest = make_out(out)
            status = publish.publish_command(out, [f"dir://{target}"], "none", io.StringIO())
            self.assertEqual(status, 0)
            self.assertEqual(sorted(p.name for p in target.iterdir()), sorted([name, f"{digest}.intoto.jsonl"]))
            found = targets.lookup(published.DirTarget(str(target)), "core", "trixie", "amd64", IDENTITY)
            self.assertEqual([one.digest for one in found.artifacts], [digest])

    def test_publishing_again_adds_only_new_record_lines(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            out, target = Path(scratch) / "out", Path(scratch) / "target"
            _, digest = make_out(out)
            publish.publish_command(out, [f"dir://{target}"], "none", io.StringIO())
            records = target / f"{digest}.intoto.jsonl"
            records.write_text(records.read_text() + "someone else's line\n")
            (out / f"{digest}.intoto.jsonl").write_text(
                (out / f"{digest}.intoto.jsonl").read_text() + "a test result\n"
            )
            said = io.StringIO()
            publish.publish_command(out, [f"dir://{target}"], "none", said)
            self.assertIn("already there, 1 record lines added", said.getvalue())
            lines = records.read_text().splitlines()
            self.assertEqual(lines[1:], ["someone else's line", "a test result"])

    def test_an_artifact_whose_bytes_do_not_match_its_name_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            out = Path(scratch) / "out"
            name, _ = make_out(out)
            (out / name).write_bytes(b"tampered")
            with self.assertRaisesRegex(commands.Failed, "does not match the digest in its name"):
                publish.publish_command(out, [f"dir://{scratch}/t"], "none", io.StringIO())

    def test_usage_errors(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            out = Path(scratch) / "out"
            make_out(out)
            for targets_, sign in (
                ([], "none"),
                (["github-release://example/images@v1"], "none"),
                ([f"dir://{scratch}"], "keyless"),
            ):
                with self.subTest(targets=targets_, sign=sign), self.assertRaises(commands.Usage):
                    publish.publish_command(out, targets_, sign, io.StringIO())
            self.assertEqual(cli.main(["publish", str(out), "--to", "github-release://example/images@v1"]), 2)
            with self.assertRaisesRegex(commands.Failed, "no such directory"):
                publish.publish_command(Path(scratch) / "missing", [f"dir://{scratch}"], "none", io.StringIO())


if __name__ == "__main__":
    unittest.main()
