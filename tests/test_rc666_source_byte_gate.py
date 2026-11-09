"""RC666 invented source bytes only; no local filesystem/GitHub reads."""
import hashlib
import unittest
from safe_public_ci.ci_source_byte_gate import (
    SourceByteRejected, git_blob_sha1, verify_public_source_byte_claims,
)

SHA = "a" * 40
A = "safe_public_ci/ci_hosted_unittest_log_gate.py"
B = "tests/test_rc665_hosted_unittest_log_gate.py"
X = b"month_days = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)\n"
Y = b"def test_ok():\n    assert True\n"


def claims(files):
    return tuple((path, hashlib.sha256(raw).hexdigest(), git_blob_sha1(raw))
                 for path, raw in files)


def verify(files=None, expected=None, commit=SHA):
    data = ((A, X), (B, Y)) if files is None else files
    return verify_public_source_byte_claims(
        data, expected_commit_sha=commit,
        trusted_claims=claims(data) if expected is None else expected,
    )


class RC666ByteGateTests(unittest.TestCase):
    def reject(self, data=None, expected=None, commit=SHA):
        with self.assertRaises(SourceByteRejected):
            verify(data, expected, commit)

    def test_01_valid_miniature_source_manifest(self):
        r = verify()
        self.assertEqual(r["status"], "SOURCE_BYTES_CONSISTENT_NOT_AUTHENTICATED")
        self.assertEqual(r["verified_files"], 2)
        self.assertFalse(r["release_ready"])
        self.assertFalse(r["live_trading_allowed"])

    def test_02_git_object_prefix_is_checked(self):
        self.assertEqual(git_blob_sha1(b"test\n"),
                         hashlib.sha1(b"blob 5\x00test\n").hexdigest())

    def test_03_sha256_of_modified_november_table_fails(self):
        original = claims(((A, X), (B, Y)))
        self.reject(((A, X.replace(b", 30, 31)\n", b")\n")), (B, Y)), original)

    def test_04_git_blob_mismatch_fails(self):
        old = claims(((A, X), (B, Y)))
        self.reject(expected=((A, old[0][1], "f" * 40), old[1]))

    def test_05_sha256_mismatch_fails(self):
        old = claims(((A, X), (B, Y)))
        self.reject(expected=((A, "f" * 64, old[0][2]), old[1]))

    def test_06_wrong_commit_format(self):
        self.reject(commit="main")

    def test_07_commit_uppercase(self):
        self.reject(commit="A" * 40)

    def test_08_blank_manifest(self):
        self.reject((), ())

    def test_09_list_rejected(self):
        self.reject([(A, X)], claims(((A, X),)))

    def test_10_duplicate_path(self):
        self.reject(((A, X), (A, X)))

    def test_11_reordered_source_paths(self):
        self.reject(((B, Y), (A, X)))

    def test_12_wrong_claim_path(self):
        c = list(claims(((A, X), (B, Y))))
        c[0] = (B, c[0][1], c[0][2])
        self.reject(expected=tuple(c))

    def test_13_missing_expected_record(self):
        self.reject(expected=claims(((A, X),)))

    def test_14_additional_unreviewed_source_fails(self):
        self.reject(((A, X), (B, Y), ("tests/extra.py", b"pass\n")),
                    claims(((A, X), (B, Y))))

    def test_15_absolute_path_rejected(self):
        self.reject((("/etc/passwd", X),), claims((("/etc/passwd", X),)))

    def test_16_traversal_rejected(self):
        self.reject((("tests/../private.py", X),),
                    claims((("tests/../private.py", X),)))

    def test_17_private_path_rejected(self):
        self.reject((("private/strategy.py", X),),
                    claims((("private/strategy.py", X),)))

    def test_18_credentials_path_rejected(self):
        self.reject(((".github/secrets.py", X),),
                    claims(((".github/secrets.py", X),)))

    def test_19_extension_rejected(self):
        self.reject((("tests/a.json", X),), claims((("tests/a.json", X),)))

    def test_20_empty_payload(self):
        self.reject(((A, b""),), ((A, "0" * 64, "0" * 40),))

    def test_21_string_payload(self):
        self.reject(((A, "fake"),), ((A, "0" * 64, "0" * 40),))

    def test_22_boolean_payload(self):
        self.reject(((A, True),), ((A, "0" * 64, "0" * 40),))

    def test_23_nul_byte(self):
        raw = b"pass\x00\n"
        self.reject(((A, raw),))

    def test_24_carriage_return(self):
        raw = b"pass\r\n"
        self.reject(((A, raw),))

    def test_25_utf8_bom(self):
        raw = b"\xef\xbb\xbfpass\n"
        self.reject(((A, raw),))

    def test_26_ansi_escape(self):
        raw = b"pass\x1b[32m\n"
        self.reject(((A, raw),))

    def test_27_invalid_utf8(self):
        raw = b"pass\xff\n"
        self.reject(((A, raw),))

    def test_28_missing_final_newline(self):
        raw = b"pass"
        self.reject(((A, raw),))

    def test_29_bool_expected_hash(self):
        c = claims(((A, X), (B, Y)))
        self.reject(expected=((A, True, c[0][2]), c[1]))

    def test_30_fake_git_sha_without_object_prefix(self):
        c = claims(((A, X), (B, Y)))
        raw_sha = hashlib.sha1(X).hexdigest()
        self.reject(expected=((A, c[0][1], raw_sha), c[1]))

    def test_31_oversized_file(self):
        raw = b"a" * 131073 + b"\n"
        self.reject(((A, raw),), ((A, "f" * 64, "f" * 40),))

    def test_32_missing_claim_shape(self):
        c = claims(((A, X), (B, Y)))
        self.reject(expected=((A, c[0][1]), c[1]))


if __name__ == "__main__":
    unittest.main()
