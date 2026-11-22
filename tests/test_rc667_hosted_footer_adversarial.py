"""RC667 synthetic hosted-job footer boundary adversaries; no real log content."""
import hashlib
import unittest

from safe_public_ci.ci_hosted_unittest_log_gate import (
    HostedLogRejected,
    verify_hosted_unittest_log,
)

STAMP = "2026-11-09T11:02:03.1234567Z "
CASE = "test_rc667.HostedFixtures.test_safe"
COMMAND = "python -m unittest discover -s tests -v"


def fabricated(*, pre=(), command=COMMAND, footer=(), end=True, cleanups=1):
    lines = [*pre, "##[group]Run " + COMMAND, command, "env:",
             "  SAFE_TEST_ONLY: 1", "##[endgroup]",
             "test_safe (" + CASE + ") ... ok", "Ran 1 test in 0.1s", "OK"]
    lines.extend(footer)
    lines.extend(["Post job cleanup."] * cleanups)
    if end:
        lines.append("Cleaning up orphan processes")
    return "".join(STAMP + x + "\n" for x in lines).encode("utf-8")


def check(data):
    return verify_hosted_unittest_log(
        data,
        trusted_log_sha256=hashlib.sha256(data).hexdigest(),
        trusted_case_ids=(CASE,),
        trusted_roster_sha256=hashlib.sha256(CASE.encode()).hexdigest(),
    )


class RC667HostedFooterTests(unittest.TestCase):
    def rejects(self, data):
        with self.assertRaises(HostedLogRejected):
            check(data)

    def test_01_minimal_valid_hosted_job(self):
        r = check(fabricated())
        self.assertEqual(r["tests"], 1)
        self.assertFalse(r["release_ready"])

    def test_02_two_realistic_cleanup_markers(self):
        self.assertEqual(check(fabricated(cleanups=2))["tests"], 1)

    def test_03_ansi_header_from_runner(self):
        header = "\x1b[36;1m" + COMMAND + "\x1b[0m"
        self.assertEqual(check(fabricated(command=header))["tests"], 1)

    def test_04_pretest_log_has_non_test_lines(self):
        self.assertEqual(check(fabricated(pre=("Set up job",)))["tests"], 1)

    def test_05_postlude_bare_run_marker_rejected(self):
        self.rejects(fabricated(footer=("##[group]Run",)))

    def test_06_postlude_tab_separated_run_rejected(self):
        self.rejects(fabricated(footer=("##[group]Run\tpwsh",)))

    def test_07_postlude_run_suffix_rejected(self):
        self.rejects(fabricated(footer=("##[group]RunEvil",)))

    def test_08_postlude_run_nonbreaking_space_rejected(self):
        self.rejects(fabricated(footer=("##[group]Run\u00a0command",)))

    def test_09_nonblank_after_final_cleanup_rejected(self):
        self.rejects(fabricated() + (STAMP + "success, trust me\n").encode())

    def test_10_empty_lines_after_final_cleanup_allowed(self):
        self.assertEqual(check(fabricated() + (STAMP + "\n").encode())["tests"], 1)

    def test_11_missing_final_cleanup_rejected(self):
        self.rejects(fabricated(end=False))

    def test_12_duplicate_orphan_cleanup_rejected(self):
        self.rejects(fabricated() + (STAMP + "Cleaning up orphan processes\n").encode())

    def test_13_reject_second_unittest_summary(self):
        self.rejects(fabricated(footer=("Ran 1 test in 0.1s",)))

    def test_14_reject_failure_in_postlude(self):
        self.rejects(fabricated(footer=("##[error]Process completed with exit code 1.",)))

    def test_15_reject_duplicate_test_after_ok(self):
        self.rejects(fabricated(footer=("test_safe (" + CASE + ") ... ok",)))

    def test_16_reject_malformed_post_job_time(self):
        self.rejects(fabricated().replace(b"2026-11-09", b"2026-13-09"))


if __name__ == "__main__":
    unittest.main()
