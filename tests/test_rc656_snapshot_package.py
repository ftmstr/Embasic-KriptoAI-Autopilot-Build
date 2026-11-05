"""Adversarial tests for offline, unsigned, synthetic snapshot manifest.

No real data, model metrics, remote requests, private checkout or orders.
"""
import hashlib
import json
import unittest
from pathlib import Path

from safe_public_ci.snapshot_package import (
    MAX_ENTRIES, MAX_MEMBER, SnapshotRejected, build_synthetic_snapshot,
    verify_synthetic_snapshot,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "3e8d9965049443caf7977bd547c449b67ad2a3c4"
ROLLBACK_COMMIT = "0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def toy():
    return {"safe_public_ci/fixture.py": b"TOY = True\n",
            "README.md": b"synthetic-only, no trading\n"}


def make():
    return build_synthetic_snapshot(toy(), source_commit=SOURCE_COMMIT,
                                    rollback_commit=ROLLBACK_COMMIT)


def verify(archive, manifest, *, receipt=None, source=SOURCE_COMMIT, rollback=ROLLBACK_COMMIT):
    return verify_synthetic_snapshot(
        archive, manifest, trusted_manifest_sha256=sha256(manifest) if receipt is None else receipt,
        trusted_source_commit=source, trusted_rollback_commit=rollback)


def changed_manifest(archive, manifest, key, value):
    obj = json.loads(manifest)
    obj[key] = value
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


class RC656SnapshotTests(unittest.TestCase):
    def test_toy_snapshot_verifies(self):
        self.assertTrue(verify(*make()))

    def test_snapshot_bytes_reproducible(self):
        self.assertEqual(make(), make())

    def test_manifest_records_rollback(self):
        self.assertEqual(json.loads(make()[1])["rollback_commit"], ROLLBACK_COMMIT)

    def test_manifest_marks_live_disabled(self):
        self.assertIs(json.loads(make()[1])["live_trading_allowed"], False)

    def test_manifest_marks_not_scientifically_validated(self):
        self.assertIs(json.loads(make()[1])["scientifically_validated"], False)

    def test_source_commit_pinned(self):
        self.assertEqual(json.loads(make()[1])["source_commit"], SOURCE_COMMIT)

    def test_reject_wrong_external_receipt(self):
        archive, manifest = make()
        with self.assertRaises(SnapshotRejected):
            verify(archive, manifest, receipt="0" * 64)

    def test_reject_noncanonical_external_receipt(self):
        archive, manifest = make()
        with self.assertRaises(SnapshotRejected):
            verify(archive, manifest, receipt=sha256(manifest).upper())

    def test_reject_wrong_trusted_rollback(self):
        archive, manifest = make()
        with self.assertRaises(SnapshotRejected):
            verify(archive, manifest, rollback="f" * 40)

    def test_reject_wrong_trusted_source(self):
        archive, manifest = make()
        with self.assertRaises(SnapshotRejected):
            verify(archive, manifest, source="a" * 40)

    def test_reject_modified_manifest_with_old_checksum(self):
        archive, manifest = make()
        altered = changed_manifest(archive, manifest, "rollback_commit", "f" * 40)
        with self.assertRaises(SnapshotRejected):
            verify(archive, altered, receipt=sha256(manifest))

    def test_reject_modified_manifest_with_new_checksum_and_wrong_rollback(self):
        archive, manifest = make()
        altered = changed_manifest(archive, manifest, "rollback_commit", "f" * 40)
        with self.assertRaises(SnapshotRejected):
            verify(archive, altered)

    def test_reject_falsified_live_permission(self):
        archive, manifest = make()
        altered = changed_manifest(archive, manifest, "live_trading_allowed", True)
        with self.assertRaises(SnapshotRejected):
            verify(archive, altered)

    def test_reject_falsified_scientific_claim(self):
        archive, manifest = make()
        altered = changed_manifest(archive, manifest, "scientifically_validated", True)
        with self.assertRaises(SnapshotRejected):
            verify(archive, altered)

    def test_reject_unknown_manifest_field(self):
        archive, manifest = make()
        altered = changed_manifest(archive, manifest, "secret_field", "false")
        with self.assertRaises(SnapshotRejected):
            verify(archive, altered)

    def test_reject_noncanonical_manifest_whitespace(self):
        archive, manifest = make()
        pretty = json.dumps(json.loads(manifest), indent=2).encode("ascii")
        with self.assertRaises(SnapshotRejected):
            verify(archive, pretty)

    def test_reject_missing_declared_entry(self):
        archive, manifest = make()
        obj = json.loads(manifest)
        altered = changed_manifest(archive, manifest, "entries", obj["entries"][:1])
        with self.assertRaises(SnapshotRejected):
            verify(archive, altered)

    def test_reject_falsified_entry_hash(self):
        archive, manifest = make()
        obj = json.loads(manifest)
        obj["entries"][0]["sha256"] = "0" * 64
        altered = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
        with self.assertRaises(SnapshotRejected):
            verify(archive, altered)

    def test_reject_modified_zip_archive(self):
        archive, manifest = make()
        tampered = archive[:19] + bytes([archive[19] ^ 1]) + archive[20:]
        with self.assertRaises(SnapshotRejected):
            verify(tampered, manifest)

    def test_reject_zip_comment_even_with_updated_checksum(self):
        archive, manifest = make()
        extra = b"not-allowed"
        modified = archive + extra
        altered = changed_manifest(modified, manifest, "archive_sha256", sha256(modified))
        with self.assertRaises(SnapshotRejected):
            verify(modified, altered)

    def test_reject_absolute_path_at_build(self):
        with self.assertRaises(SnapshotRejected):
            build_synthetic_snapshot({"/tmp/secret": b"toy"}, source_commit=SOURCE_COMMIT,
                                     rollback_commit=ROLLBACK_COMMIT)

    def test_reject_zip_traversal_at_build(self):
        with self.assertRaises(SnapshotRejected):
            build_synthetic_snapshot({"safe_public_ci/../foo.py": b"toy"},
                                     source_commit=SOURCE_COMMIT, rollback_commit=ROLLBACK_COMMIT)

    def test_reject_private_tree_path_at_build(self):
        with self.assertRaises(SnapshotRejected):
            build_synthetic_snapshot({"data/raw/private.json": b"toy"},
                                     source_commit=SOURCE_COMMIT, rollback_commit=ROLLBACK_COMMIT)

    def test_reject_secret_extension_at_build(self):
        with self.assertRaises(SnapshotRejected):
            build_synthetic_snapshot({"safe_public_ci/apikey.pem": b"toy"},
                                     source_commit=SOURCE_COMMIT, rollback_commit=ROLLBACK_COMMIT)

    def test_reject_non_ascii_path(self):
        with self.assertRaises(SnapshotRejected):
            build_synthetic_snapshot({"safe_public_ci/ş.py": b"toy"},
                                     source_commit=SOURCE_COMMIT, rollback_commit=ROLLBACK_COMMIT)

    def test_reject_empty_source_bytes(self):
        with self.assertRaises(SnapshotRejected):
            build_synthetic_snapshot({"safe_public_ci/a.py": b""},
                                     source_commit=SOURCE_COMMIT, rollback_commit=ROLLBACK_COMMIT)

    def test_reject_too_large_source_bytes(self):
        with self.assertRaises(SnapshotRejected):
            build_synthetic_snapshot({"safe_public_ci/a.py": b"a" * (MAX_MEMBER + 1)},
                                     source_commit=SOURCE_COMMIT, rollback_commit=ROLLBACK_COMMIT)

    def test_reject_too_many_sources(self):
        data = {f"safe_public_ci/a{i}.py": b"x" for i in range(MAX_ENTRIES + 1)}
        with self.assertRaises(SnapshotRejected):
            build_synthetic_snapshot(data, source_commit=SOURCE_COMMIT,
                                     rollback_commit=ROLLBACK_COMMIT)

    def test_reject_boolean_as_archive_input(self):
        _, manifest = make()
        with self.assertRaises(SnapshotRejected):
            verify(True, manifest)

    def test_reject_bad_source_commit_on_build(self):
        with self.assertRaises(SnapshotRejected):
            build_synthetic_snapshot(toy(), source_commit="unknown",
                                     rollback_commit=ROLLBACK_COMMIT)

    def test_integrity_actual_public_source_files_without_export(self):
        """Measure this checkout only; do not publish an artifact or include private code."""
        permitted = {p.relative_to(ROOT).as_posix(): p.read_bytes()
                     for p in sorted((ROOT / "safe_public_ci").glob("*.py"))}
        permitted["README.md"] = (ROOT / "README.md").read_bytes()
        permitted["PUBLICATION_GATE.md"] = (ROOT / "PUBLICATION_GATE.md").read_bytes()
        self.assertGreater(len(permitted), 4)
        archive, manifest = build_synthetic_snapshot(
            permitted, source_commit=SOURCE_COMMIT, rollback_commit=ROLLBACK_COMMIT)
        self.assertTrue(verify(archive, manifest))
        self.assertLess(len(archive), 524288)


if __name__ == "__main__":
    unittest.main()
