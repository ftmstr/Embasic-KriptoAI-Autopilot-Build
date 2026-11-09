"""RC667 invented-only hostile source bytes; never reads files or networks."""
import hashlib
import unittest

from safe_public_ci.ci_source_byte_gate import (
    SourceByteRejected,
    git_blob_sha1,
    verify_public_source_byte_claims,
)

PATH = "safe_public_ci/ci_source_byte_gate.py"
COMMIT = "a" * 40


def validate(source):
    digest = hashlib.sha256(source).hexdigest()
    blob = git_blob_sha1(source)
    return verify_public_source_byte_claims(
        ((PATH, source),), expected_commit_sha=COMMIT,
        trusted_claims=((PATH, digest, blob),),
    )


class RC667UnicodeAndASTTests(unittest.TestCase):
    def bad(self, source):
        with self.assertRaises(SourceByteRejected):
            validate(source)

    def test_01_regular_python(self):
        self.assertEqual(validate(b"x = 3\n")["verified_files"], 1)

    def test_02_tabs_are_valid_python(self):
        self.assertEqual(validate(b"if True:\n\tpass\n")["verified_files"], 1)

    def test_03_turkish_utf8_comment(self):
        self.assertEqual(validate("# Türkçe açıklama\n".encode())["verified_files"], 1)

    def test_04_unicode_identifier(self):
        self.assertEqual(validate("değer = 12\n".encode())["verified_files"], 1)

    def test_05_combining_accent_in_comment(self):
        self.assertEqual(validate("# cafe\u0301\n".encode())["verified_files"], 1)

    def test_06_emoji_in_comment(self):
        self.assertEqual(validate("# 🛡\n".encode())["verified_files"], 1)

    def test_07_all_twelve_months_fixture(self):
        raw = b"month_days = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)\n"
        self.assertEqual(validate(raw)["verified_files"], 1)

    def test_08_bidi_right_override_comment(self):
        self.bad("# a\u202eb\n".encode())

    def test_09_bidi_left_override_comment(self):
        self.bad("# a\u202db\n".encode())

    def test_10_bidi_left_embedding_comment(self):
        self.bad("# a\u202ab\n".encode())

    def test_11_bidi_right_embedding_comment(self):
        self.bad("# a\u202bb\n".encode())

    def test_12_bidi_pop_direction_comment(self):
        self.bad("# a\u202cb\n".encode())

    def test_13_bidi_ltr_isolate_comment(self):
        self.bad("# a\u2066b\n".encode())

    def test_14_bidi_rtl_isolate_comment(self):
        self.bad("# a\u2067b\n".encode())

    def test_15_bidi_pop_isolate_comment(self):
        self.bad("# a\u2069b\n".encode())

    def test_16_zero_width_space(self):
        self.bad("# a\u200bb\n".encode())

    def test_17_zero_width_joiner(self):
        self.bad("# a\u200db\n".encode())

    def test_18_unicode_word_joiner(self):
        self.bad("# a\u2060b\n".encode())

    def test_19_soft_hyphen(self):
        self.bad("# a\u00adb\n".encode())

    def test_20_c1_nel(self):
        self.bad("# a\u0085b\n".encode())

    def test_21_unicode_line_separator(self):
        self.bad("# a\u2028b\n".encode())

    def test_22_unicode_paragraph_separator(self):
        self.bad("# a\u2029b\n".encode())

    def test_23_tab_in_comment_allowed(self):
        self.assertEqual(validate(b"# hello\tworld\n")["verified_files"], 1)

    def test_24_incomplete_function_header(self):
        self.bad(b"def broken(:\n")

    def test_25_unclosed_parenthesis(self):
        self.bad(b"month_days = (31, 28\n")

    def test_26_bad_indentation(self):
        self.bad(b"def ok():\npass\n")

    def test_27_null_byte(self):
        self.bad(b"x = 1\x00\n")

    def test_28_crlf(self):
        self.bad(b"x = 1\r\n")

    def test_29_utf8_bom(self):
        self.bad(b"\xef\xbb\xbfx = 1\n")

    def test_30_missing_newline(self):
        self.bad(b"x = 1")

    def test_31_invalid_utf8(self):
        self.bad(b"# \xff\n")

    def test_32_control_escape_comment(self):
        self.bad(b"# \x1b[31m\n")

    def test_33_deeply_nested_expression(self):
        self.bad(b"a = " + b"(" * 600 + b"1" + b")" * 600 + b"\n")

    def test_34_pure_comment_is_valid_python(self):
        self.assertEqual(validate(b"# public-only notes\n")["verified_files"], 1)

    def test_35_annotated_return_without_body(self):
        self.bad(b"def f() -> int:\n")

    def test_36_source_module_cannot_execute_on_parse(self):
        # Never import or execute the source string; syntax-only check.
        raw = b"raise RuntimeError('would execute if run')\n"
        result = validate(raw)
        self.assertFalse(result["release_ready"])
        self.assertFalse(result["live_trading_allowed"])


if __name__ == "__main__":
    unittest.main()
