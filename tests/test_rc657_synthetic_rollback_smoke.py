"""RC657 synthetic rollback selection smoke tests (NO deployment or restore).

All bytes invented locally. A checksum and a hex Git identifier are NOT a
signature, trusted release authorization, or evidence of a real rollback.
"""
import hashlib
import json
import unittest

from safe_public_ci.snapshot_package import (
    SnapshotRejected, build_synthetic_snapshot, verify_synthetic_snapshot,
)

SOURCE_A = "a" * 40
SOURCE_B = "b" * 40
PREVIOUS = "0" * 40


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def fixture_a():
    return {
        "README.md": b"toy-A:no-live\n",
        "safe_public_ci/__init__.py": b"SAFE_TEST_ONLY = True\n",
    }


def fixture_b():
    return {
        "README.md": b"toy-B:no-live\n",
        "safe_public_ci/__init__.py": b"SAFE_TEST_ONLY = True\n",
        "safe_public_ci/toy.py": b"VERSION = 2\n",
    }


def build(files, source, rollback):
    return build_synthetic_snapshot(files, source_commit=source,
                                    rollback_commit=rollback)


def verify(archive, manifest, source, rollback, *, receipt=None):
    return verify_synthetic_snapshot(
        archive, manifest,
        trusted_manifest_sha256=sha256(manifest) if receipt is None else receipt,
        trusted_source_commit=source,
        trusted_rollback_commit=rollback)


class RC657OfflineRollbackSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = build(fixture_a(), SOURCE_A, PREVIOUS)
        cls.b = build(fixture_b(), SOURCE_B, SOURCE_A)

    def test_A_can_be_verified_independently(self):
        self.assertTrue(verify(*self.a, SOURCE_A, PREVIOUS))

    def test_B_can_be_verified_independently(self):
        self.assertTrue(verify(*self.b, SOURCE_B, SOURCE_A))

    def test_B_names_A_as_rollback_reference(self):
        self.assertEqual(json.loads(self.b[1])["rollback_commit"], SOURCE_A)

    def test_rollback_reference_is_not_a_restoration_action(self):
        self.assertEqual(json.loads(self.b[1])["rollback_commit"], SOURCE_A)
        self.assertEqual(json.loads(self.a[1])["source_commit"], SOURCE_A)
        self.assertNotEqual(self.a[0], self.b[0])

    def test_B_rejected_with_wrong_trusted_rollback(self):
        with self.assertRaises(SnapshotRejected):
            verify(*self.b, SOURCE_B, PREVIOUS)

    def test_A_rejected_with_wrong_trusted_rollback(self):
        with self.assertRaises(SnapshotRejected):
            verify(*self.a, SOURCE_A, SOURCE_B)

    def test_B_rejected_with_A_source_commit(self):
        with self.assertRaises(SnapshotRejected):
            verify(*self.b, SOURCE_A, SOURCE_A)

    def test_A_rejected_with_B_source_commit(self):
        with self.assertRaises(SnapshotRejected):
            verify(*self.a, SOURCE_B, PREVIOUS)

    def test_B_archive_cannot_use_A_manifest(self):
        with self.assertRaises(SnapshotRejected):
            verify(self.b[0], self.a[1], SOURCE_A, PREVIOUS)

    def test_A_archive_cannot_use_B_manifest(self):
        with self.assertRaises(SnapshotRejected):
            verify(self.a[0], self.b[1], SOURCE_B, SOURCE_A)

    def test_B_receipt_substituted_by_A_receipt_rejected(self):
        with self.assertRaises(SnapshotRejected):
            verify(*self.b, SOURCE_B, SOURCE_A, receipt=sha256(self.a[1]))

    def test_toy_snapshots_have_identical_repeated_bytes(self):
        self.assertEqual(self.a, build(fixture_a(), SOURCE_A, PREVIOUS))
        self.assertEqual(self.b, build(fixture_b(), SOURCE_B, SOURCE_A))

    def test_in_memory_inputs_not_mutated(self):
        before = fixture_b()
        original = dict(before)
        build(before, SOURCE_B, SOURCE_A)
        self.assertEqual(before, original)

    def test_B_entries_in_canonical_lexical_order(self):
        paths = [x["path"] for x in json.loads(self.b[1])["entries"]]
        self.assertEqual(paths, sorted(paths))

    def test_genesis_init_file_allowed_but_private_config_not(self):
        self.assertTrue(verify(*self.a, SOURCE_A, PREVIOUS))
        with self.assertRaises(SnapshotRejected):
            build({"private/settings.json": b"synthetic"},
                  SOURCE_B, SOURCE_A)

    def test_modified_B_archive_rejected_even_with_new_manifest_checksum(self):
        archive, manifest = self.b
        modified_archive = archive + b"trailing"
        altered = json.loads(manifest)
        altered["archive_sha256"] = sha256(modified_archive)
        changed_manifest = json.dumps(
            altered, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        with self.assertRaises(SnapshotRejected):
            verify(modified_archive, changed_manifest, SOURCE_B, SOURCE_A)

    def test_unsigned_manifest_cannot_assert_cryptographic_signature(self):
        archive, manifest = self.b
        altered = json.loads(manifest)
        altered["signed_release"] = True
        changed_manifest = json.dumps(
            altered, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        with self.assertRaises(SnapshotRejected):
            verify(archive, changed_manifest, SOURCE_B, SOURCE_A)

    def test_rollback_to_A_fails_on_untrusted_receipt(self):
        with self.assertRaises(SnapshotRejected):
            verify(*self.a, SOURCE_A, PREVIOUS, receipt="f" * 64)

    def test_historical_A_is_unchanged_after_B_verification(self):
        previous = sha256(self.a[0])
        verify(*self.b, SOURCE_B, SOURCE_A)
        self.assertEqual(sha256(self.a[0]), previous)
        self.assertTrue(verify(*self.a, SOURCE_A, PREVIOUS))


if __name__ == "__main__":
    unittest.main()
