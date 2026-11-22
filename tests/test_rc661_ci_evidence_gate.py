"""Invented dual-run metadata only; NOT authentic GitHub run evidence."""
import unittest

from safe_public_ci.ci_evidence_gate import (
    EvidenceRejected, verify_dual_platform_metadata,
)

SHA = "a" * 40


def records():
    return (
        dict(platform="ubuntu-24.04", sha=SHA, run_id=101, job_id=301,
             status="completed", conclusion="success", tests_run=345,
             tests_passed=345, failures=0, errors=0, skipped=0,
             steps_total=9, steps_passed=9),
        dict(platform="windows-latest", sha=SHA, run_id=102, job_id=302,
             status="completed", conclusion="success", tests_run=345,
             tests_passed=345, failures=0, errors=0, skipped=0,
             steps_total=9, steps_passed=9),
    )


def check(rows=None, sha=SHA, ids=None):
    return verify_dual_platform_metadata(
        records() if rows is None else rows, expected_sha=sha,
        trusted_run_ids={"ubuntu-24.04": 101, "windows-latest": 102}
        if ids is None else ids)


class EvidenceGateTests(unittest.TestCase):
    def test_consistent_toy_metadata_is_not_authenticated(self):
        result = check()
        self.assertEqual(result["status"], "METADATA_CONSISTENT_NOT_AUTHENTICATED")
        self.assertFalse(result["release_ready"])
        self.assertFalse(result["live_trading_allowed"])
        self.assertEqual(result["tests_per_platform"], 345)

    def test_rejects_different_commit(self):
        a, b = records()
        b["sha"] = "b" * 40
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_different_test_count(self):
        a, b = records()
        b["tests_run"] = b["tests_passed"] = 344
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_stale_run_id(self):
        a, b = records()
        b["run_id"] = 99
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_duplicate_job_id(self):
        a, b = records()
        b["job_id"] = a["job_id"]
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_duplicate_runner(self):
        a, b = records()
        b["platform"] = a["platform"]
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_unknown_runner(self):
        a, b = records()
        b["platform"] = "self-hosted"
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_failed_workflow(self):
        a, b = records()
        b["conclusion"] = "failure"
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_pending_workflow(self):
        a, b = records()
        b["status"] = "queued"
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_skipped_steps(self):
        a, b = records()
        b["steps_passed"] = 8
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_skipped_tests(self):
        a, b = records()
        b["skipped"] = 1
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_zero_tests(self):
        a, b = records()
        a["tests_run"] = a["tests_passed"] = 0
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_boolean_numeric_forgery(self):
        a, b = records()
        a["tests_passed"] = True
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_extra_claim(self):
        a, b = records()
        a["signed_release"] = True
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_missing_field(self):
        a, b = records()
        del a["run_id"]
        with self.assertRaises(EvidenceRejected): check((a, b))

    def test_rejects_invalid_expected_sha(self):
        with self.assertRaises(EvidenceRejected): check(sha="not-a-sha")

    def test_rejects_untrusted_mapping(self):
        with self.assertRaises(EvidenceRejected): check(ids={"ubuntu-24.04": 101})

    def test_rejects_untrusted_boolean_run_id(self):
        with self.assertRaises(EvidenceRejected): check(ids={"ubuntu-24.04": True,
                                                         "windows-latest": 102})

    def test_rejects_list_instead_of_fixed_records(self):
        with self.assertRaises(EvidenceRejected): check(list(records()))

    def test_rejects_only_one_platform(self):
        with self.assertRaises(EvidenceRejected): check(records()[:1])


if __name__ == "__main__":
    unittest.main()
