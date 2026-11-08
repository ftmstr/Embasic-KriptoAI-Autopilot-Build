"""RC662: 24 isolated, invented-metadata tests; no real GitHub attestation."""
import copy
import unittest
from safe_public_ci.ci_evidence_gate import (
    EvidenceRejected, verify_dual_platform_metadata,
)

SHA = "a" * 40
TRUSTED = {"ubuntu-24.04": 1101, "windows-latest": 1102}


def fixtures():
    return (
        dict(platform="ubuntu-24.04", sha=SHA, run_id=1101, job_id=2101,
             status="completed", conclusion="success", tests_run=365,
             tests_passed=365, failures=0, errors=0, skipped=0,
             steps_total=9, steps_passed=9),
        dict(platform="windows-latest", sha=SHA, run_id=1102, job_id=2102,
             status="completed", conclusion="success", tests_run=365,
             tests_passed=365, failures=0, errors=0, skipped=0,
             steps_total=9, steps_passed=9),
    )


def verify(records=None, trusted=None, expected=SHA):
    return verify_dual_platform_metadata(
        fixtures() if records is None else records,
        expected_sha=expected, trusted_run_ids=TRUSTED if trusted is None else trusted,
    )


class RC662IndependentSyntheticMetadataTests(unittest.TestCase):
    def reject(self, mutate):
        entries = list(copy.deepcopy(fixtures()))
        mutate(entries)
        with self.assertRaises(EvidenceRejected):
            verify(tuple(entries))

    def test_01_valid_reversed_order_is_not_authenticated(self):
        result = verify(tuple(reversed(fixtures())))
        self.assertEqual(result["status"], "METADATA_CONSISTENT_NOT_AUTHENTICATED")
        self.assertEqual(result["tests_per_platform"], 365)
        self.assertFalse(result["release_ready"])
        self.assertFalse(result["live_trading_allowed"])

    def test_02_same_run_id_in_trust_map_rejected(self):
        with self.assertRaises(EvidenceRejected):
            verify(trusted={"ubuntu-24.04": 1101, "windows-latest": 1101})

    def test_03_same_run_id_in_records_rejected(self):
        self.reject(lambda x: x[1].update(run_id=x[0]["run_id"]))

    def test_04_cross_platform_equal_run_ids_even_if_trusted_rejected(self):
        e = list(fixtures())
        e[1]["run_id"] = e[0]["run_id"]
        with self.assertRaises(EvidenceRejected):
            verify(tuple(e), trusted={"ubuntu-24.04": 1101, "windows-latest": 1101})

    def test_05_distinct_job_ids_required(self):
        self.reject(lambda x: x[1].update(job_id=x[0]["job_id"]))

    def test_06_bool_job_id_rejected(self):
        self.reject(lambda x: x[0].update(job_id=True))

    def test_07_bool_step_total_rejected(self):
        self.reject(lambda x: x[1].update(steps_total=True))

    def test_08_bool_failure_counter_rejected(self):
        self.reject(lambda x: x[1].update(failures=False))

    def test_09_float_success_count_rejected(self):
        self.reject(lambda x: x[0].update(tests_passed=365.0))

    def test_10_negative_skips_rejected(self):
        self.reject(lambda x: x[0].update(skipped=-1))

    def test_11_empty_steps_rejected(self):
        self.reject(lambda x: x[1].update(steps_total=0, steps_passed=0))

    def test_12_incomplete_steps_rejected(self):
        self.reject(lambda x: x[1].update(steps_total=9, steps_passed=8))

    def test_13_step_overclaim_rejected(self):
        self.reject(lambda x: x[1].update(steps_total=9, steps_passed=10))

    def test_14_error_without_test_failure_rejected(self):
        self.reject(lambda x: x[0].update(errors=1))

    def test_15_skipped_workflow_rejected(self):
        self.reject(lambda x: x[0].update(conclusion="skipped"))

    def test_16_cancelled_workflow_rejected(self):
        self.reject(lambda x: x[1].update(conclusion="cancelled"))

    def test_17_wrong_exact_sha_rejected(self):
        self.reject(lambda x: x[0].update(sha="b" * 40))

    def test_18_uppercase_sha_rejected(self):
        with self.assertRaises(EvidenceRejected):
            verify(expected=SHA.upper().replace("a", "A"))

    def test_19_whitespace_sha_rejected(self):
        with self.assertRaises(EvidenceRejected):
            verify(expected=SHA + " ")

    def test_20_unknown_metadata_claim_rejected(self):
        self.reject(lambda x: x[0].update(production_ready=True))

    def test_21_replayed_ubuntu_record_rejected(self):
        self.reject(lambda x: x.__setitem__(1, x[0].copy()))

    def test_22_untrusted_float_run_id_rejected(self):
        with self.assertRaises(EvidenceRejected):
            verify(trusted={"ubuntu-24.04": 1101.0, "windows-latest": 1102})

    def test_23_rejected_total_mismatch_even_both_pass(self):
        self.reject(lambda x: x[1].update(tests_run=364, tests_passed=364))

    def test_24_trusted_mapping_cannot_have_unknown_runner(self):
        with self.assertRaises(EvidenceRejected):
            verify(trusted={"ubuntu-24.04": 1101, "windows-latest": 1102, "other": 1103})


if __name__ == "__main__":
    unittest.main()
