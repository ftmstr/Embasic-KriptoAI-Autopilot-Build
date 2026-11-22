"""Invented CI metadata only; no credentials, GitHub API, or live trading."""
import copy
import hashlib
import unittest

from safe_public_ci.ci_hosted_pair_identity_gate import (
    HostedPairRejected, verify_synthetic_hosted_pair, _STEPS,
)

SHA = "a" * 40
ROSTER = "b" * 64
LOGS = (b"invented ubuntu synthetic log", b"invented windows synthetic log")
RUNS = (11001, 11002)
JOBS = (12001, 12002)


def receipts():
    result = []
    for i, platform in enumerate(("ubuntu", "windows")):
        digest = hashlib.sha256(LOGS[i]).hexdigest()
        result.append({
            "platform": platform,
            "run": {"id": RUNS[i], "head_sha": SHA, "event": "push",
                    "run_attempt": 1, "status": "completed", "conclusion": "success"},
            "job": {"id": JOBS[i], "run_id": RUNS[i],
                    "status": "completed", "conclusion": "success"},
            "steps": tuple({"name": name, "status": "completed", "conclusion": "success"}
                           for name in _STEPS[platform]),
            "raw_log": LOGS[i],
            "log_check": {"status": "HOSTED_LOG_STRUCTURE_ONLY_NOT_AUTHENTICATED",
                          "tests": 607, "log_sha256": digest,
                          "roster_sha256": ROSTER, "release_ready": False,
                          "live_trading_allowed": False},
        })
    return tuple(result)


def verify(data=None, **overrides):
    args = {"expected_sha": SHA, "expected_run_ids": RUNS,
            "expected_job_ids": JOBS, "expected_log_sha256": tuple(
                hashlib.sha256(log).hexdigest() for log in LOGS),
            "expected_roster_sha256": ROSTER, "expected_tests": 607}
    args.update(overrides)
    return verify_synthetic_hosted_pair(receipts() if data is None else data, **args)


class RC668HostedPairTests(unittest.TestCase):
    def reject(self, mutate=None, **overrides):
        original = copy.deepcopy(receipts())
        if mutate is not None:
            mutate(original)
        with self.assertRaises(HostedPairRejected):
            verify(original, **overrides)

    def test_01_two_synthetic_host_receipts_consistent_not_authenticated(self):
        result = verify()
        self.assertEqual(result["status"], "HOSTED_PAIR_CONSISTENT_NOT_AUTHENTICATED")
        self.assertEqual(result["per_platform_tests"], 607)
        self.assertEqual(result["platforms"], 2)
        self.assertFalse(result["release_ready"])
        self.assertFalse(result["live_trading_allowed"])

    def test_02_exact_sha_guard(self):
        self.reject(lambda r: r[1]["run"].update(head_sha="c" * 40))

    def test_03_expected_sha_wrong_type(self):
        self.reject(expected_sha=True)

    def test_04_expected_sha_wrong_length(self):
        self.reject(expected_sha="f" * 39)

    def test_05_wrong_branch_event(self):
        self.reject(lambda r: r[0]["run"].update(event="workflow_dispatch"))

    def test_06_no_pull_request_fake_success(self):
        self.reject(lambda r: r[1]["run"].update(event="pull_request"))

    def test_07_queued_run_rejected(self):
        self.reject(lambda r: r[0]["run"].update(status="queued"))

    def test_08_failed_run_rejected(self):
        self.reject(lambda r: r[1]["run"].update(conclusion="failure"))

    def test_09_run_attempt_two_rejected(self):
        self.reject(lambda r: r[0]["run"].update(run_attempt=2))

    def test_10_bool_attempt_rejected(self):
        self.reject(lambda r: r[1]["run"].update(run_attempt=True))

    def test_11_swapped_platforms_rejected(self):
        self.reject(lambda r: r[0].update(platform="windows"))

    def test_12_only_one_platform_rejected(self):
        with self.assertRaises(HostedPairRejected):
            verify(receipts()[:1])

    def test_13_duplicate_run_ids_rejected(self):
        self.reject(expected_run_ids=(11001, 11001))

    def test_14_invalid_run_identifier_rejected(self):
        self.reject(lambda r: r[0]["run"].update(id=0))

    def test_15_run_identity_not_in_trusted_expectations_rejected(self):
        self.reject(lambda r: r[0]["run"].update(id=9999))

    def test_16_job_bound_to_wrong_run_rejected(self):
        self.reject(lambda r: r[1]["job"].update(run_id=11001))

    def test_17_expected_job_id_mismatch_rejected(self):
        self.reject(expected_job_ids=(12001, 12003))

    def test_18_job_failure_rejected(self):
        self.reject(lambda r: r[1]["job"].update(conclusion="failure"))

    def test_19_job_pending_rejected(self):
        self.reject(lambda r: r[0]["job"].update(status="in_progress"))

    def test_20_step_skipped_rejected(self):
        self.reject(lambda r: r[1]["steps"][5].update(conclusion="skipped"))

    def test_21_step_failure_rejected(self):
        self.reject(lambda r: r[0]["steps"][5].update(conclusion="failure"))

    def test_22_forged_publish_step_rejected(self):
        self.reject(lambda r: r[0]["steps"][5].update(name="Publish actual trader"))

    def test_23_missing_step_rejected(self):
        self.reject(lambda r: r[1].update(steps=r[1]["steps"][:-1]))

    def test_24_injected_step_rejected(self):
        self.reject(lambda r: r[0].update(steps=r[0]["steps"] + (r[0]["steps"][0],)))

    def test_25_wrong_os_step_order_rejected(self):
        def mutation(r):
            a = list(r[0]["steps"])
            a[4], a[5] = a[5], a[4]
            r[0]["steps"] = tuple(a)
        self.reject(mutation)

    def test_26_raw_log_byte_mutation_rejected(self):
        self.reject(lambda r: r[0].update(raw_log=b"changed synthetic log"))

    def test_27_raw_log_wrong_type_rejected(self):
        self.reject(lambda r: r[1].update(raw_log="invented log"))

    def test_28_log_guard_must_not_claim_authenticated(self):
        self.reject(lambda r: r[1]["log_check"].update(
            status="AUTHENTICATED_GITHUB_SUCCESS"))

    def test_29_log_guard_false_count_rejected(self):
        self.reject(lambda r: r[0]["log_check"].update(tests=606))

    def test_30_log_guard_boolean_count_rejected(self):
        self.reject(lambda r: r[0]["log_check"].update(tests=True))

    def test_31_roster_digest_mismatch_rejected(self):
        self.reject(lambda r: r[1]["log_check"].update(roster_sha256="e" * 64))

    def test_32_log_digest_mismatch_rejected(self):
        self.reject(lambda r: r[1]["log_check"].update(log_sha256="e" * 64))

    def test_33_external_log_digest_mismatch_rejected(self):
        self.reject(expected_log_sha256=("f" * 64, "f" * 64))

    def test_34_release_flag_truthy_rejected(self):
        self.reject(lambda r: r[1]["log_check"].update(release_ready=True))

    def test_35_live_flag_truthy_rejected(self):
        self.reject(lambda r: r[0]["log_check"].update(live_trading_allowed=True))

    def test_36_invented_overflow_log_rejected(self):
        self.reject(lambda r: r[0].update(raw_log=b"x" * 262145))

    def test_37_unexpected_metadata_key_rejected(self):
        self.reject(lambda r: r[1].update(token="private-key"))

    def test_38_wrong_step_type_rejected(self):
        self.reject(lambda r: r[1].update(steps=list(r[1]["steps"])))

    def test_39_untrusted_roster_checksum_rejected(self):
        self.reject(expected_roster_sha256="F" * 64)

    def test_40_zero_expected_count_rejected(self):
        self.reject(expected_tests=0)


if __name__ == "__main__":
    unittest.main()
