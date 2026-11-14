"""Invented log text only: no real GitHub logs, exchange or API access."""
import hashlib
import unittest

from safe_public_ci.ci_unittest_log_guard import (
    LogEvidenceRejected, check_synthetic_unittest_log,
)

P = "2026-11-09T00:00:00.1234567Z "


def sample(*, names=("test_alpha", "test_beta"), tail="Ran 2 tests in 0.123s\nOK", leading=""):
    return (leading + "".join(P + x + " (test_rc663.GuardTests." + x + ") ... ok\n" for x in names)
            + "".join(P + line + "\n" for line in tail.split("\n"))).encode("utf-8")


def check(data=None, *, count=2, digest=None):
    data = sample() if data is None else data
    return check_synthetic_unittest_log(data, expected_count=count,
        expected_sha256=hashlib.sha256(data).hexdigest() if digest is None else digest)


class RC663LogGuardTests(unittest.TestCase):
    def fail(self, payload, *, count=2, digest=None):
        with self.assertRaises(LogEvidenceRejected):
            check(payload, count=count, digest=digest)

    def test_01_valid_structural_log_not_authenticated(self):
        result = check()
        self.assertEqual(result["status"], "LOG_STRUCTURALLY_CONSISTENT_NOT_AUTHENTICATED")
        self.assertEqual(result["tests"], 2)
        self.assertFalse(result["release_ready"])
        self.assertFalse(result["live_trading_allowed"])

    def test_02_valid_surrounding_hosted_lines(self):
        d = (P + "Set up job\n").encode() + sample() + (P + "Cleaning up\n").encode()
        self.assertEqual(check(d)["tests"], 2)

    def test_03_missing_summary(self):
        self.fail(sample(tail=""))

    def test_04_missing_ok(self):
        self.fail(sample(tail="Ran 2 tests in 0.123s"))

    def test_05_bad_summary_count(self):
        self.fail(sample(tail="Ran 3 tests in 0.123s\nOK"))

    def test_06_duplicate_case(self):
        self.fail(sample(names=("test_alpha", "test_alpha")))

    def test_07_duplicate_summary(self):
        self.fail(sample(tail="Ran 2 tests in 0.123s\nRan 2 tests in 0.123s\nOK"))

    def test_08_double_ok(self):
        self.fail(sample(tail="Ran 2 tests in 0.123s\nOK\nOK"))

    def test_09_fail(self):
        self.fail(sample(tail="Ran 2 tests in 0.123s\nFAILED (failures=1)"))

    def test_10_error(self):
        self.fail(sample(tail="Ran 2 tests in 0.123s\nERROR: failure"))

    def test_11_skipped(self):
        self.fail(sample(tail="Ran 2 tests in 0.123s\nOK" ) + (P + "test_z (...) ... skipped\n").encode())

    def test_12_case_after_summary(self):
        self.fail(sample() + (P + "test_extra (test_rc663.GuardTests.test_extra) ... ok\n").encode())

    def test_13_summary_before_cases(self):
        self.fail((P + "Ran 2 tests in 0.123s\n").encode() + sample())

    def test_14_fake_truncated_log(self):
        self.fail(sample()[:-4])

    def test_15_mutated_digest(self):
        self.fail(sample(), digest="f" * 64)

    def test_16_invalid_digest_text(self):
        self.fail(sample(), digest="BAD")

    def test_17_boolean_count(self):
        self.fail(sample(), count=True)

    def test_18_zero_count(self):
        self.fail(sample(), count=0)

    def test_19_expected_count_mismatch(self):
        self.fail(sample(), count=3)

    def test_20_log_type_string(self):
        with self.assertRaises(LogEvidenceRejected):
            check_synthetic_unittest_log(sample().decode(), expected_count=2, expected_sha256="f" * 64)

    def test_21_invalid_utf8(self):
        self.fail(sample() + b"\xff")

    def test_22_null_control(self):
        self.fail(sample() + b"\x00")

    def test_23_ansi_escape(self):
        self.fail(sample() + b"\x1b[31m")

    def test_24_carriage_return(self):
        self.fail(sample() + b"\r")

    def test_25_bom(self):
        self.fail(sample() + b"\xef\xbb\xbf")

    def test_26_bad_timestamp_line(self):
        self.fail(b"INJECTED TEST PASSED\n" + sample())

    def test_27_summary_not_immediately_followed_by_ok(self):
        self.fail(sample(tail="Ran 2 tests in 0.123s\nwarning\nOK"))

    def test_28_test_case_not_regular_unittest_name(self):
        self.fail((P + "test_$bad (test_rc663.GuardTests.test_$bad) ... ok\n").encode() + sample())

    def test_29_too_large_log(self):
        self.fail(sample() + (P + "filler\n").encode() * 14000)

    def test_30_too_many_lines(self):
        self.fail(sample() + (P + "filler\n").encode() * 4001)

    def test_31_uppercase_OK_only_rejected(self):
        self.fail(sample(tail="Ran 2 tests in 0.123s\nOk"))

    def test_32_positive_one_test(self):
        d=sample(names=("test_alpha",),tail="Ran 1 tests in 0.001s\nOK")
        self.assertEqual(check(d,count=1)["tests"],1)


    def test_33_leading_hosted_bom_accepted(self):
        self.assertEqual(check(b"\xef\xbb\xbf" + sample())["tests"], 2)

    def test_34_split_test_print_line_accepted(self):
        d = ((P + "test_alpha (test_rc663.GuardTests.test_alpha)\n" +
              P + "Measure this checkout only; do not publish an artifact or include private code. ... ok\n" +
              P + "test_beta (test_rc663.GuardTests.test_beta) ... ok\n" +
              P + "Ran 2 tests in 0.1s\n" + P + "OK\n").encode())
        self.assertEqual(check(d)["tests"], 2)

    def test_35_split_without_continuation_rejected(self):
        self.fail((P + "test_alpha (test_rc663.GuardTests.test_alpha)\n").encode() + sample())

    def test_36_split_injection_wrong_continuation_rejected(self):
        d=((P + "test_alpha (test_rc663.GuardTests.test_alpha)\n" +
            P + "FAILED 1 ... ok\n").encode() + sample())
        self.fail(d)


if __name__ == "__main__":
    unittest.main()
