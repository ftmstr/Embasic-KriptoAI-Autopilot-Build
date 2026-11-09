"""RC664 adversarial synthetic-only roster evidence; no external services."""
import hashlib
import unittest
from safe_public_ci.ci_case_roster_guard import (
    RosterRejected, canonical_roster_sha256, verify_synthetic_unittest_roster,
)

P = "2026-11-09T01:01:01.1234567Z "
A = "test_toy.AlphaTests.test_alpha"
B = "test_toy.BetaTests.test_beta"
C = "test_toy.GammaTests.test_gamma"
S = "test_rc656_snapshot_package.RC656SnapshotTests.test_integrity_actual_public_source_files_without_export"
NOTE = "Measure this checkout only; do not publish an artifact or include private code. ... ok"
ROSTER = (A, B)


def output(ids=ROSTER, *, summary=None, middle="", leading="", trailing=""):
    lines = [leading] if leading else []
    for case in ids:
        method = case.rsplit(".", 1)[-1]
        lines.append(method + " (" + case + ") ... ok")
    if middle:
        lines.append(middle)
    n = len(ids)
    if summary is None:
        summary = "Ran %d %s in 0.123s\n\nOK" % (n, "test" if n == 1 else "tests")
    lines.extend(summary.split("\n"))
    if trailing:
        lines.append(trailing)
    return ("\n".join(P + line for line in lines) + "\n").encode("utf-8")


def verify(raw=None, roster=ROSTER, *, log_hash=None, roster_hash=None):
    raw = output() if raw is None else raw
    return verify_synthetic_unittest_roster(
        raw,
        trusted_log_sha256=hashlib.sha256(raw).hexdigest() if log_hash is None else log_hash,
        trusted_case_ids=roster,
        trusted_roster_sha256=canonical_roster_sha256(roster) if roster_hash is None else roster_hash,
    )


class RC664RosterGuardTests(unittest.TestCase):
    def bad(self, data, **kwargs):
        with self.assertRaises(RosterRejected):
            verify(data, **kwargs)

    def test_01_valid_two_test_fixture_is_not_authenticated(self):
        result = verify()
        self.assertEqual(result["tests"], 2)
        self.assertEqual(result["status"], "ROSTER_STRUCTURALLY_CONSISTENT_NOT_AUTHENTICATED")
        self.assertFalse(result["live_trading_allowed"])
        self.assertFalse(result["release_ready"])

    def test_02_case_order_can_change_but_set_cannot(self):
        self.assertEqual(verify(output((B, A)))["tests"], 2)

    def test_03_omitted_case_rejected_despite_matching_self_count(self):
        self.bad(output((A,)))

    def test_04_substituted_case_rejected(self):
        self.bad(output((A, C)))

    def test_05_duplicate_case_rejected(self):
        self.bad(output((A, A)))

    def test_06_method_and_qualified_identity_disagree(self):
        self.bad((P + "test_alpha (test_toy.AlphaTests.test_beta) ... ok\n").encode() + output((B,)))

    def test_07_bad_roster_digest_rejected(self):
        self.bad(output(), roster_hash="f" * 64)

    def test_08_bad_log_digest_rejected(self):
        self.bad(output(), log_hash="f" * 64)

    def test_09_uppercase_digest_rejected(self):
        self.bad(output(), log_hash="A" * 64)

    def test_10_roster_must_be_tuple(self):
        with self.assertRaises(RosterRejected):
            canonical_roster_sha256([A, B])

    def test_11_duplicate_expected_roster_rejected(self):
        with self.assertRaises(RosterRejected):
            canonical_roster_sha256((A, A))

    def test_12_out_of_order_roster_rejected(self):
        with self.assertRaises(RosterRejected):
            canonical_roster_sha256((B, A))

    def test_13_empty_roster_rejected(self):
        with self.assertRaises(RosterRejected):
            canonical_roster_sha256(())

    def test_14_synthetic_venue_in_roster_rejected(self):
        with self.assertRaises(RosterRejected):
            canonical_roster_sha256(("BTCUSDT",))

    def test_15_invalid_timestamp_month_rejected(self):
        self.bad(output().replace(b"2026-11-09", b"2026-99-09"))

    def test_16_invalid_timestamp_day_rejected(self):
        self.bad(output().replace(b"2026-11-09", b"2026-11-31"))

    def test_17_invalid_timestamp_hour_rejected(self):
        self.bad(output().replace(b"T01:01:01", b"T25:01:01"))

    def test_18_unicode_digit_in_prefix_rejected(self):
        self.bad(output().replace(b"2026", "２０２６".encode("utf-8")))

    def test_19_missing_unittest_ok_rejected(self):
        self.bad(output(summary="Ran 2 tests in 0.123s"))

    def test_20_two_ok_lines_rejected(self):
        self.bad(output(summary="Ran 2 tests in 0.123s\nOK\nOK"))

    def test_21_skipped_case_rejected(self):
        self.bad(output() + (P + "test_gamma (test_toy.GammaTests.test_gamma) ... skipped\n").encode())

    def test_22_gh_error_annotation_rejected(self):
        self.bad(output(trailing="##[error]synthetic failure"))

    def test_23_nonzero_exit_marker_rejected(self):
        self.bad(output(trailing="Error: Process completed with exit code 1."))

    def test_24_arbitrary_split_stdout_rejected(self):
        data = (P + "test_alpha (" + A + ")\n" + P + "FAKE PASS ... ok\n" +
                P + "test_beta (" + B + ") ... ok\n" + P + "Ran 2 tests in 0.123s\n" + P + "OK\n").encode()
        self.bad(data)

    def test_25_known_split_stdout_accepted_but_not_authenticated(self):
        ids = (S,)
        data = (P + "test_integrity_actual_public_source_files_without_export (" + S + ")\n" +
                P + NOTE + "\n" + P + "Ran 1 test in 0.123s\n" + P + "OK\n").encode()
        self.assertEqual(verify(data, ids)["tests"], 1)

    def test_26_known_message_cannot_close_other_case(self):
        data = (P + "test_alpha (" + A + ")\n" + P + NOTE + "\n" +
                P + "test_beta (" + B + ") ... ok\n" + P + "Ran 2 tests in 0.123s\n" + P + "OK\n").encode()
        self.bad(data)

    def test_27_control_character_rejected(self):
        self.bad(output() + b"\x1b[31m")

    def test_28_bom_only_at_start_is_permitted(self):
        self.assertEqual(verify(b"\xef\xbb\xbf" + output())["tests"], 2)

    def test_29_embedded_bom_rejected(self):
        self.bad(output() + b"\xef\xbb\xbf")

    def test_30_oversize_log_rejected(self):
        self.bad(output() + ((P + "irrelevant\n").encode() * 16000))

    def test_31_one_valid_test_grammar_accepted(self):
        self.assertEqual(verify(output((A,)), (A,))["tests"], 1)

    def test_32_wrong_singular_grammar_rejected(self):
        self.bad(output((A,), summary="Ran 1 tests in 0.123s\nOK"), roster=(A,))

    def test_33_no_actual_tests_rejected(self):
        self.bad((P + "Ran 2 tests in 0.123s\n" + P + "OK\n").encode())

    def test_34_successful_summary_but_unknown_case_rejected(self):
        self.bad(output((C, B)))

    def test_35_test_after_ok_rejected(self):
        self.bad(output(trailing="test_gamma (" + C + ") ... ok"))

    def test_36_boolean_as_log_rejected(self):
        with self.assertRaises(RosterRejected):
            verify_synthetic_unittest_roster(True, trusted_log_sha256="f"*64,
                                             trusted_case_ids=ROSTER,
                                             trusted_roster_sha256=canonical_roster_sha256(ROSTER))


if __name__ == "__main__":
    unittest.main()
