"""RC658 synthetic-only cross-platform snapshot & Windows-hosted CI controls.

This suite never executes deployment, real rollback, real orders or a signing key.
GitHub-hosted Windows validation is a unit-test smoke, not an installer test.
"""
import hashlib
import io
import json
from pathlib import Path
import re
import unittest
import zipfile

from safe_public_ci.snapshot_package import (
    SnapshotRejected, build_synthetic_snapshot, verify_synthetic_snapshot,
    FIXED_DATE, FILE_ATTR,
)

ROOT = Path(__file__).resolve().parents[1]
WINDOWS_WORKFLOW = ROOT / ".github/workflows/rc658-windows-synthetic.yml"
SHA_CHECKOUT = "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
SHA_PYTHON = "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
SOURCE = "a" * 40
ROLLBACK = "b" * 40


def toy():
    return {
        "safe_public_ci/__init__.py": b"SAFE_TEST_ONLY = True\n",
        "README.md": b"only invented fixture data\n",
    }


def build(files=None):
    return build_synthetic_snapshot(
        toy() if files is None else files,
        source_commit=SOURCE, rollback_commit=ROLLBACK,
    )


def verify(archive, manifest):
    return verify_synthetic_snapshot(
        archive, manifest,
        trusted_manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        trusted_source_commit=SOURCE,
        trusted_rollback_commit=ROLLBACK,
    )


class RC658WindowsPortabilitySmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WINDOWS_WORKFLOW.read_text(encoding="utf-8")

    def test_windows_workflow_exists(self):
        self.assertTrue(WINDOWS_WORKFLOW.is_file())

    def test_windows_hosted_runner_only(self):
        self.assertEqual(self.workflow.count("runs-on: windows-latest"), 1)
        self.assertNotIn("self-hosted", self.workflow)

    def test_windows_branch_scoped_push(self):
        self.assertIn("      - validation/rc654-pr1-rc653-combined-ci", self.workflow)
        for untrusted in ("pull_request:", "pull_request_target:", "workflow_run:",
                          "workflow_dispatch:", "repository_dispatch:"):
            self.assertNotIn(untrusted, self.workflow)

    def test_windows_permissions_read_only(self):
        self.assertEqual(self.workflow.count("contents: read"), 2)
        self.assertNotIn("contents: write", self.workflow)

    def test_windows_two_exact_pinned_actions(self):
        actions = re.findall(r"(?m)^\s+uses:\s+([^\n]+)$", self.workflow)
        self.assertEqual(actions, [SHA_CHECKOUT, SHA_PYTHON])

    def test_windows_python_exact_pinned_version(self):
        self.assertIn("python-version: '3.13.5'", self.workflow)
        self.assertIn("architecture: x64", self.workflow)
        self.assertIn("sys.version_info[:3] == (3, 13, 5)", self.workflow)

    def test_windows_checkout_has_no_persisted_token(self):
        for setting in ("persist-credentials: false", "fetch-depth: 1",
                        "submodules: false", "lfs: false"):
            self.assertIn(setting, self.workflow)

    def test_windows_synthetic_only_and_bounded_runtime(self):
        self.assertIn("SAFE_TEST_ONLY: '1'", self.workflow)
        self.assertIn("timeout-minutes: 12", self.workflow)

    def test_windows_full_test_suite_is_required(self):
        self.assertIn("python -m compileall -q safe_public_ci tests", self.workflow)
        self.assertIn("python -m unittest discover -s tests -v", self.workflow)

    def test_windows_no_remote_download_or_deploy(self):
        for blocked in ("secrets.", "${{", "id-token:", "upload-artifact",
                        "curl ", "wget ", "pip install", "git clone ",
                        "docker ", "deploy", "release:"):
            self.assertNotIn(blocked, self.workflow)

    def test_windows_no_soft_fail(self):
        for blocked in ("continue-on-error:", "|| true", "exit 0",
                        "set +e", "always()"):
            self.assertNotIn(blocked, self.workflow)

    def test_fixture_build_is_deterministic(self):
        self.assertEqual(build(), build())

    def test_fixture_build_ignores_input_dict_order(self):
        forward = toy()
        reverse = dict(reversed(list(forward.items())))
        self.assertEqual(build(forward), build(reverse))

    def test_manifest_has_stable_sorted_encoding(self):
        archive, manifest = build()
        self.assertEqual(json.dumps(json.loads(manifest), sort_keys=True,
                                    separators=(",", ":"), ensure_ascii=True).encode(), manifest)
        self.assertTrue(verify(archive, manifest))

    def test_zip_has_fixed_time_and_unix_file_mode(self):
        archive, _ = build()
        with zipfile.ZipFile(io.BytesIO(archive), "r") as z:
            for member in z.infolist():
                self.assertEqual(member.date_time, FIXED_DATE)
                self.assertEqual(member.create_system, 3)
                self.assertEqual(member.external_attr, FILE_ATTR)
                self.assertEqual(member.compress_type, zipfile.ZIP_STORED)

    def test_windows_device_con_rejected(self):
        with self.assertRaises(SnapshotRejected):
            build({"safe_public_ci/con.py": b"toy"})

    def test_windows_device_prn_rejected(self):
        with self.assertRaises(SnapshotRejected):
            build({"safe_public_ci/prn.py": b"toy"})

    def test_windows_device_aux_rejected(self):
        with self.assertRaises(SnapshotRejected):
            build({"safe_public_ci/aux.py": b"toy"})

    def test_windows_device_nul_rejected(self):
        with self.assertRaises(SnapshotRejected):
            build({"safe_public_ci/nul.py": b"toy"})

    def test_windows_device_com1_rejected(self):
        with self.assertRaises(SnapshotRejected):
            build({"safe_public_ci/com1.py": b"toy"})

    def test_windows_device_lpt9_rejected(self):
        with self.assertRaises(SnapshotRejected):
            build({"safe_public_ci/lpt9.py": b"toy"})

    def test_windows_absolute_drive_path_rejected(self):
        with self.assertRaises(SnapshotRejected):
            build({"C:\\private\\settings.py": b"toy"})

    def test_windows_unc_path_rejected(self):
        with self.assertRaises(SnapshotRejected):
            build({"\\\\server\\share\\log.py": b"toy"})

    def test_windows_backslash_traversal_rejected(self):
        with self.assertRaises(SnapshotRejected):
            build({"safe_public_ci\\..\\hidden.py": b"toy"})

    def test_windows_alternate_data_stream_rejected(self):
        with self.assertRaises(SnapshotRejected):
            build({"safe_public_ci/a.py:private": b"toy"})

    def test_toy_rollback_commit_does_not_authorize_restore(self):
        archive, manifest = build()
        self.assertTrue(verify(archive, manifest))
        data = json.loads(manifest)
        self.assertEqual(data["rollback_commit"], ROLLBACK)
        self.assertNotIn("signature", data)
        self.assertIs(data["live_trading_allowed"], False)
        self.assertIs(data["scientifically_validated"], False)

    def test_modified_archive_fails_even_with_same_manifest(self):
        archive, manifest = build()
        with self.assertRaises(SnapshotRejected):
            verify(archive + b"unsafe", manifest)

    def test_license_decision_remains_outside_ci(self):
        policy = (ROOT / "PUBLICATION_GATE.md").read_text("utf-8")
        self.assertIn("No open source license is granted", policy)

    def test_windows_workflow_does_not_check_out_private_repo(self):
        self.assertNotIn("ftmstr/KriptoAI-Autopilot", self.workflow)
        self.assertNotIn("repository:", self.workflow)


class RC659DisposableToyRollback(unittest.TestCase):
    """Windows ephemeral on-disk toy fixture only; never an installed app restore."""

    OLD_SOURCE = "c" * 40
    NEW_SOURCE = "d" * 40
    GENESIS = "0" * 40
    FILENAME = "safe_public_ci/toy.py"

    def _package(self, payload, source, rollback):
        return build_synthetic_snapshot(
            {self.FILENAME: payload}, source_commit=source,
            rollback_commit=rollback)

    def _apply_verified(self, temp_root, archive, manifest,
                        *, manifest_digest, source, rollback):
        # Reject first; do not even create a destination on failed verification.
        verify_synthetic_snapshot(
            archive, manifest, trusted_manifest_sha256=manifest_digest,
            trusted_source_commit=source, trusted_rollback_commit=rollback)
        with zipfile.ZipFile(io.BytesIO(archive), "r") as package:
            self.assertEqual(package.namelist(), [self.FILENAME])
            payload = package.read(self.FILENAME)
        target = temp_root / "toy.py"
        target.write_bytes(payload)
        return target

    def _fixtures(self):
        old = self._package(b"TOY_VERSION = 'A'\\n",
                            self.OLD_SOURCE, self.GENESIS)
        new = self._package(b"TOY_VERSION = 'B'\\n",
                            self.NEW_SOURCE, self.OLD_SOURCE)
        return old, new

    def test_disposable_old_new_old_roundtrip(self):
        import tempfile
        old, new = self._fixtures()
        with tempfile.TemporaryDirectory(prefix="rc659_toy_") as d:
            root = Path(d)
            target = self._apply_verified(
                root, *old, manifest_digest=hashlib.sha256(old[1]).hexdigest(),
                source=self.OLD_SOURCE, rollback=self.GENESIS)
            self.assertEqual(target.read_bytes(), b"TOY_VERSION = 'A'\\n")
            self._apply_verified(
                root, *new, manifest_digest=hashlib.sha256(new[1]).hexdigest(),
                source=self.NEW_SOURCE, rollback=self.OLD_SOURCE)
            self.assertEqual(target.read_bytes(), b"TOY_VERSION = 'B'\\n")
            self._apply_verified(
                root, *old, manifest_digest=hashlib.sha256(old[1]).hexdigest(),
                source=self.OLD_SOURCE, rollback=self.GENESIS)
            self.assertEqual(target.read_bytes(), b"TOY_VERSION = 'A'\\n")

    def test_bad_new_archive_cannot_modify_disposable_old(self):
        import tempfile
        old, new = self._fixtures()
        with tempfile.TemporaryDirectory(prefix="rc659_toy_") as d:
            root = Path(d)
            target = self._apply_verified(
                root, *old, manifest_digest=hashlib.sha256(old[1]).hexdigest(),
                source=self.OLD_SOURCE, rollback=self.GENESIS)
            corrupt = new[0] + b"untrusted-trailer"
            with self.assertRaises(SnapshotRejected):
                self._apply_verified(
                    root, corrupt, new[1],
                    manifest_digest=hashlib.sha256(new[1]).hexdigest(),
                    source=self.NEW_SOURCE, rollback=self.OLD_SOURCE)
            self.assertEqual(target.read_bytes(), b"TOY_VERSION = 'A'\\n")

    def test_bad_new_manifest_receipt_cannot_modify_old(self):
        import tempfile
        old, new = self._fixtures()
        with tempfile.TemporaryDirectory(prefix="rc659_toy_") as d:
            root = Path(d)
            target = self._apply_verified(
                root, *old, manifest_digest=hashlib.sha256(old[1]).hexdigest(),
                source=self.OLD_SOURCE, rollback=self.GENESIS)
            with self.assertRaises(SnapshotRejected):
                self._apply_verified(
                    root, *new, manifest_digest="f" * 64,
                    source=self.NEW_SOURCE, rollback=self.OLD_SOURCE)
            self.assertEqual(target.read_bytes(), b"TOY_VERSION = 'A'\\n")

    def test_wrong_new_rollback_reference_cannot_modify_old(self):
        import tempfile
        old, new = self._fixtures()
        with tempfile.TemporaryDirectory(prefix="rc659_toy_") as d:
            root = Path(d)
            target = self._apply_verified(
                root, *old, manifest_digest=hashlib.sha256(old[1]).hexdigest(),
                source=self.OLD_SOURCE, rollback=self.GENESIS)
            with self.assertRaises(SnapshotRejected):
                self._apply_verified(
                    root, *new, manifest_digest=hashlib.sha256(new[1]).hexdigest(),
                    source=self.NEW_SOURCE, rollback=self.GENESIS)
            self.assertEqual(target.read_bytes(), b"TOY_VERSION = 'A'\\n")

    def test_wrong_new_source_reference_cannot_modify_old(self):
        import tempfile
        old, new = self._fixtures()
        with tempfile.TemporaryDirectory(prefix="rc659_toy_") as d:
            root = Path(d)
            target = self._apply_verified(
                root, *old, manifest_digest=hashlib.sha256(old[1]).hexdigest(),
                source=self.OLD_SOURCE, rollback=self.GENESIS)
            with self.assertRaises(SnapshotRejected):
                self._apply_verified(
                    root, *new, manifest_digest=hashlib.sha256(new[1]).hexdigest(),
                    source=self.OLD_SOURCE, rollback=self.OLD_SOURCE)
            self.assertEqual(target.read_bytes(), b"TOY_VERSION = 'A'\\n")

    def test_damaged_old_cannot_replace_good_new_on_rollback(self):
        import tempfile
        old, new = self._fixtures()
        with tempfile.TemporaryDirectory(prefix="rc659_toy_") as d:
            root = Path(d)
            target = self._apply_verified(
                root, *new, manifest_digest=hashlib.sha256(new[1]).hexdigest(),
                source=self.NEW_SOURCE, rollback=self.OLD_SOURCE)
            damaged = old[0][:-4]
            with self.assertRaises(SnapshotRejected):
                self._apply_verified(
                    root, damaged, old[1],
                    manifest_digest=hashlib.sha256(old[1]).hexdigest(),
                    source=self.OLD_SOURCE, rollback=self.GENESIS)
            self.assertEqual(target.read_bytes(), b"TOY_VERSION = 'B'\\n")

    def test_disposable_directory_is_removed_after_smoke(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix="rc659_toy_") as d:
            root = Path(d)
            old, _ = self._fixtures()
            self._apply_verified(
                root, *old, manifest_digest=hashlib.sha256(old[1]).hexdigest(),
                source=self.OLD_SOURCE, rollback=self.GENESIS)
            self.assertTrue((root / "toy.py").is_file())
        self.assertFalse(root.exists())

    def test_restore_smoke_has_no_signature_or_installer_claim(self):
        old, new = self._fixtures()
        for archive, manifest in (old, new):
            meta = json.loads(manifest)
            self.assertNotIn("signature", meta)
            self.assertNotIn("installer", meta)
            self.assertIs(meta["live_trading_allowed"], False)
            self.assertIs(meta["scientifically_validated"], False)
            self.assertTrue(verify(archive, manifest) if
                meta["source_commit"] == SOURCE and
                meta["rollback_commit"] == ROLLBACK else True)


if __name__ == "__main__":
    unittest.main()
