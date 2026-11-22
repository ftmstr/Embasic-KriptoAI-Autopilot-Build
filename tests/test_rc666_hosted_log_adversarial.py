"""Synthetic RC665 full-job-log adversaries, no GitHub or market data."""
import hashlib
import unittest
from safe_public_ci.ci_hosted_unittest_log_gate import (
    HostedLogRejected, verify_hosted_unittest_log,
)

PREFIX = "2026-11-09T01:00:00.1234567Z "
COMMAND = "python -m unittest discover -s tests -v"
CASE = "test_rc666.FixtureTests.test_one"


def fixture(*, command=COMMAND, env="  SAFE_TEST_ONLY: 1", cases=(CASE,),
            footer=("Post job cleanup.", "Cleaning up orphan processes")):
    parts = ["##[group]Run " + COMMAND, command, "env:", env, "##[endgroup]"]
    parts.extend(x.rsplit(".", 1)[-1] + " (" + x + ") ... ok" for x in cases)
    count = len(cases)
    parts += ["Ran %d %s in 0.1s" % (count, "test" if count == 1 else "tests"),
              "OK", *footer]
    return ("".join(PREFIX + item + "\n" for item in parts)).encode("utf-8")


def check(data, roster=(CASE,)):
    return verify_hosted_unittest_log(
        data, trusted_log_sha256=hashlib.sha256(data).hexdigest(),
        trusted_case_ids=roster,
        trusted_roster_sha256=hashlib.sha256("\n".join(roster).encode()).hexdigest(),
    )


class RC666HostedLogAdversaries(unittest.TestCase):
    def rejects(self, data, roster=(CASE,)):
        with self.assertRaises(HostedLogRejected):
            check(data, roster)

    def test_01_valid_fixture_is_not_authenticated(self):
        result = check(fixture())
        self.assertEqual(result["status"], "HOSTED_LOG_STRUCTURE_ONLY_NOT_AUTHENTICATED")
        self.assertFalse(result["release_ready"])
        self.assertFalse(result["live_trading_allowed"])

    def test_02_whitelisted_header_sgr(self):
        self.assertEqual(check(fixture(command="\x1b[36;1m" + COMMAND + "\x1b[0m"))["tests"], 1)

    def test_03_forged_second_run_step_with_suffix_rejected(self):
        self.rejects(fixture(footer=("Post job cleanup.",
                                     "##[group]Run python -m unittest discover -s tests -v --fake",
                                     "Cleaning up orphan processes")))

    def test_04_second_run_echo_rejected(self):
        self.rejects(fixture(footer=("Post job cleanup.",
                                     "##[group]Run echo unauthorized",
                                     "Cleaning up orphan processes")))

    def test_05_second_run_after_cleanup_rejected(self):
        self.rejects(fixture(footer=("Post job cleanup.",
                                     "Cleaning up orphan processes",
                                     "##[group]Run echo fake")))

    def test_06_late_forged_case_rejected(self):
        self.rejects(fixture(footer=("Post job cleanup.",
                                     "test_extra (test_rc666.FixtureTests.test_extra) ... ok",
                                     "Cleaning up orphan processes")))

    def test_07_github_error_footer_rejected(self):
        self.rejects(fixture(footer=("Post job cleanup.",
                                     "##[error]synthetic failure",
                                     "Cleaning up orphan processes")))

    def test_08_bad_header_command_rejected(self):
        self.rejects(fixture(command="python -m unittest discover -s wrong -v"))

    def test_09_duplicate_test_identity_rejected(self):
        self.rejects(fixture(cases=(CASE, CASE)), roster=(CASE,))

    def test_10_test_roster_mismatch_rejected(self):
        self.rejects(fixture(cases=("test_rc666.FixtureTests.test_two",)))

    def test_11_duplicate_unittest_ok_rejected(self):
        self.rejects(fixture(footer=("OK", "Post job cleanup.", "Cleaning up orphan processes")))

    def test_12_disabled_safe_only_flag_rejected(self):
        self.rejects(fixture(env="  SAFE_TEST_ONLY: 0"))


if __name__ == "__main__":
    unittest.main()
