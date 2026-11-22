"""Original all-invented RC669 replay and identity adversarial fixtures."""
import unittest
from safe_public_ci.ci_receipt_replay_fence import (
    ReplayFenceRejected, verify_synthetic_receipt_replay,
)

SHA = "a" * 40
UBUNTU_LOG = "1" * 64
WINDOWS_LOG = "2" * 64
ROSTER = "3" * 64
SOURCE = "4" * 64
RUNS = (1201, 1202)
JOBS = (1301, 1302)


def pair():
    return (("ubuntu", RUNS[0], JOBS[0], SHA, UBUNTU_LOG, ROSTER),
            ("windows", RUNS[1], JOBS[1], SHA, WINDOWS_LOG, ROSTER))


def verify(receipts=None, **kwargs):
    args = dict(expected_sha=SHA, expected_run_ids=RUNS,
                expected_job_ids=JOBS,
                expected_log_sha256=(UBUNTU_LOG, WINDOWS_LOG),
                expected_roster_sha256=ROSTER,
                expected_source_sha256=SOURCE,
                trusted_seen_pair_sha256=(), trusted_seen_log_sha256=())
    args.update(kwargs)
    return verify_synthetic_receipt_replay(pair() if receipts is None else receipts,
                                            **args)


class RC669ReplayAdversaries(unittest.TestCase):
    def rejected(self, receipts=None, **changes):
        with self.assertRaises(ReplayFenceRejected):
            verify(receipts, **changes)

    def test_01_new_candidate_is_not_authenticated(self):
        result = verify()
        self.assertEqual(result["platforms"], 2)
        self.assertTrue(result["status"].endswith("NOT_AUTHENTICATED"))
        self.assertFalse(result["release_ready"])
        self.assertFalse(result["live_trading_allowed"])

    def test_02_deterministic_receipt_fingerprint(self):
        self.assertEqual(verify()["fingerprint_sha256"], verify()["fingerprint_sha256"])

    def test_03_replayed_pair_rejected(self):
        old = verify()["fingerprint_sha256"]
        self.rejected(trusted_seen_pair_sha256=(old,))

    def test_04_seen_ubuntu_log_rejected(self):
        self.rejected(trusted_seen_log_sha256=(UBUNTU_LOG,))

    def test_05_seen_windows_log_rejected(self):
        self.rejected(trusted_seen_log_sha256=(WINDOWS_LOG,))

    def test_06_same_log_on_both_hosts_rejected_even_with_matching_expectations(self):
        modified = (pair()[0], ("windows", RUNS[1], JOBS[1], SHA, UBUNTU_LOG, ROSTER))
        self.rejected(modified, expected_log_sha256=(UBUNTU_LOG, UBUNTU_LOG))

    def test_07_cross_os_swap_rejected(self):
        self.rejected((pair()[1], pair()[0]))

    def test_08_same_run_id_rejected(self):
        self.rejected(expected_run_ids=(RUNS[0], RUNS[0]))

    def test_09_same_job_id_rejected(self):
        self.rejected(expected_job_ids=(JOBS[0], JOBS[0]))

    def test_10_other_sha_in_receipt_rejected(self):
        old = pair()
        self.rejected(((old[0][0], old[0][1], old[0][2], "b" * 40, *old[0][4:]), old[1]))

    def test_11_external_sha_wrong_rejected(self):
        self.rejected(expected_sha="z" * 40)

    def test_12_external_sha_wrong_type_rejected(self):
        self.rejected(expected_sha=True)

    def test_13_wrong_roster_rejected(self):
        old = pair()
        self.rejected((old[0], (*old[1][:5], "5" * 64)))

    def test_14_wrong_expected_roster_rejected(self):
        self.rejected(expected_roster_sha256="f" * 64)

    def test_15_malformed_source_digest_rejected(self):
        self.rejected(expected_source_sha256="bad")

    def test_16_lost_platform_rejected(self):
        self.rejected((pair()[0],))

    def test_17_extra_platform_rejected(self):
        self.rejected(pair() + (pair()[0],))

    def test_18_list_receipts_rejected(self):
        self.rejected(list(pair()))

    def test_19_boolean_run_identifier_rejected(self):
        old = pair()
        self.rejected(((old[0][0], True, *old[0][2:]), old[1]))

    def test_20_boolean_job_identifier_rejected(self):
        old = pair()
        self.rejected((old[0], (old[1][0], old[1][1], True, *old[1][3:])))

    def test_21_expected_run_id_boolean_rejected(self):
        self.rejected(expected_run_ids=(True, RUNS[1]))

    def test_22_expected_log_uppercase_rejected(self):
        self.rejected(expected_log_sha256=(UBUNTU_LOG.upper(), "F" * 64))

    def test_23_malformed_prior_history_rejected(self):
        self.rejected(trusted_seen_pair_sha256=("not-sha",))

    def test_24_duplicate_history_entry_rejected(self):
        self.rejected(trusted_seen_log_sha256=(UBUNTU_LOG, UBUNTU_LOG))

    def test_25_unsorted_prior_history_rejected(self):
        self.rejected(trusted_seen_log_sha256=(WINDOWS_LOG, UBUNTU_LOG))

    def test_26_prior_history_list_rejected(self):
        self.rejected(trusted_seen_pair_sha256=[])

    def test_27_history_size_limit_rejected(self):
        self.rejected(trusted_seen_log_sha256=("1" * 64,) * 1025)

    def test_28_wrong_expected_job_id_rejected(self):
        self.rejected(expected_job_ids=(9999, JOBS[1]))

    def test_29_log_digest_mutation_rejected(self):
        old = pair()
        self.rejected((old[0], (*old[1][:4], "5" * 64, old[1][5])))

    def test_30_same_source_digest_replay_still_detected_by_history(self):
        old = verify()["fingerprint_sha256"]
        self.rejected(trusted_seen_pair_sha256=(old,), expected_source_sha256=SOURCE)

    def test_31_different_source_digest_changes_candidate_identity(self):
        self.assertNotEqual(verify()["fingerprint_sha256"],
                            verify(expected_source_sha256="5" * 64)["fingerprint_sha256"])

    def test_32_provided_empty_histories_do_not_claim_provenance(self):
        verdict = verify()
        self.assertFalse(verdict["release_ready"])
        self.assertFalse(verdict["live_trading_allowed"])


if __name__ == "__main__":
    unittest.main()
