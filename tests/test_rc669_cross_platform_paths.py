"""Invented Windows-platform path attacks against Public source manifests."""
import hashlib
import unittest
from safe_public_ci.ci_source_byte_gate import (
    SourceByteRejected, git_blob_sha1, verify_public_source_byte_claims,
)

SHA = "a" * 40
RAW = b"# synthetic source only\n"


def verify_path(path):
    return verify_public_source_byte_claims(
        ((path, RAW),), expected_commit_sha=SHA,
        trusted_claims=((path, hashlib.sha256(RAW).hexdigest(), git_blob_sha1(RAW)),),
    )


class RC669WindowsSourcePathCases(unittest.TestCase):
    def bad(self, path):
        with self.assertRaises(SourceByteRejected):
            verify_path(path)

    def test_01_valid_test_module(self):
        self.assertEqual(verify_path("tests/test_rc669_safe.py")["verified_files"], 1)

    def test_02_valid_public_module(self):
        self.assertEqual(verify_path("safe_public_ci/checkpoint.py")["verified_files"], 1)

    def test_03_con_device(self):
        self.bad("tests/con.py")

    def test_04_prn_device(self):
        self.bad("safe_public_ci/prn.py")

    def test_05_aux_device(self):
        self.bad("tests/aux.py")

    def test_06_nul_device(self):
        self.bad("safe_public_ci/nul.py")

    def test_07_com1_device(self):
        self.bad("tests/com1.py")

    def test_08_com9_device(self):
        self.bad("safe_public_ci/com9.py")

    def test_09_lpt1_device(self):
        self.bad("tests/lpt1.py")

    def test_10_lpt9_device(self):
        self.bad("safe_public_ci/lpt9.py")

    def test_11_path_length_bound(self):
        self.bad("tests/" + "a" * 129 + ".py")

    def test_12_non_device_com0_is_allowed(self):
        self.assertEqual(verify_path("tests/com0.py")["verified_files"], 1)

    def test_13_mixed_case_filename_still_rejected(self):
        self.bad("tests/CON.py")

    def test_14_path_traversal_still_rejected(self):
        self.bad("tests/../con.py")


if __name__ == "__main__":
    unittest.main()
