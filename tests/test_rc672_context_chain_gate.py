"""Fifty invented-data tests of pinned source/CI/CAS context transitions."""
import copy
import unittest

from safe_public_ci.ci_context_chain_gate import (
    ContextChainRejected, context_sha256, check_synthetic_context_transition,
)

P = "a" * 64
Q = "b" * 64
ROOT = "c" * 64
CAS0 = "d" * 64
CAS1 = "e" * 64
SHA0 = "1" * 40
SHA1 = "2" * 40
SRC0 = "1" * 64
SRC1 = "2" * 64
FLOW0 = "3" * 64
FLOW1 = "4" * 64
ROSTER0 = "5" * 64
ROSTER1 = "6" * 64
LOGS0 = ("7" * 64, "8" * 64)
LOGS1 = ("9" * 64, "a" * 64)


def old():
    return dict(
        repository="ftmstr/Embasic-KriptoAI-Autopilot-Build",
        branch="validation/rc654-pr1-rc653-combined-ci",
        git_sha=SHA0, source_sha256=SRC0, workflow_sha256=FLOW0,
        roster_sha256=ROSTER0, authority_id="github-public-owner",
        authority_epoch=3, authority_root_sha256=ROOT,
        previous_context_sha256=P,
        run_ids=(1100, 1200), job_ids=(2100, 2200), log_sha256=LOGS0,
        run_attempts=(1, 1), cas_generation=7, cas_root_sha256=CAS0,
        ack_state="ACK_APPLIED",
        trace_status="CLAIMED_LINEARIZATION_CONSISTENT_NOT_AUTHENTICATED",
        pair_status="HOSTED_PAIR_CONSISTENT_NOT_AUTHENTICATED",
        replay_status="NOT_REPLAYED_AGAINST_SUPPLIED_HISTORY_NOT_AUTHENTICATED",
        release_ready=False, live_trading_allowed=False,
    )


def current(previous=None):
    prev = old() if previous is None else previous
    c = copy.deepcopy(prev)
    c.update(git_sha=SHA1, source_sha256=SRC1,
             workflow_sha256=FLOW1, roster_sha256=ROSTER1,
             previous_context_sha256=context_sha256(prev),
             run_ids=(1101, 1201), job_ids=(2101, 2201),
             log_sha256=LOGS1, cas_generation=8, cas_root_sha256=CAS1)
    return c


def verify(previous=None, updated=None, **updates):
    prior = old() if previous is None else previous
    candidate = current(prior) if updated is None else updated
    pins = dict(
        trusted_previous_context_sha256=context_sha256(prior),
        trusted_authority_root_sha256=ROOT, trusted_authority_epoch=3,
        trusted_current_git_sha=SHA1, trusted_current_source_sha256=SRC1,
        trusted_current_workflow_sha256=FLOW1,
        trusted_current_roster_sha256=ROSTER1,
        trusted_current_run_ids=(1101, 1201),
        trusted_current_job_ids=(2101, 2201),
        trusted_current_log_sha256=LOGS1,
    )
    pins.update(updates)
    return check_synthetic_context_transition(prior, candidate, **pins)


class RC672ContextChainTests(unittest.TestCase):
    def bad(self, change=None, old_change=None, **pins):
        prev = old()
        if old_change:
            old_change(prev)
        nxt = current(prev)
        if change:
            change(nxt)
        with self.assertRaises(ContextChainRejected):
            verify(prev, nxt, **pins)

    def test_01_valid_chain_is_not_authenticated(self):
        result = verify()
        self.assertEqual(result["status"], "CONTEXT_CHAIN_CONSISTENT_NOT_AUTHENTICATED")
        self.assertFalse(result["release_ready"])
        self.assertFalse(result["live_trading_allowed"])

    def test_02_context_commitment_is_deterministic(self):
        self.assertEqual(context_sha256(old()), context_sha256(old()))

    def test_03_context_commitment_changes_with_source(self):
        p = current()
        other = copy.deepcopy(p)
        other["source_sha256"] = Q
        self.assertNotEqual(context_sha256(p), context_sha256(other))

    def test_04_context_commitment_changes_with_workflow(self):
        p = current()
        other = copy.deepcopy(p)
        other["workflow_sha256"] = Q
        self.assertNotEqual(context_sha256(p), context_sha256(other))

    def test_05_context_commitment_changes_with_roster(self):
        p = current()
        other = copy.deepcopy(p)
        other["roster_sha256"] = Q
        self.assertNotEqual(context_sha256(p), context_sha256(other))

    def test_06_context_commitment_changes_with_authority(self):
        p = current()
        other = copy.deepcopy(p)
        other["authority_root_sha256"] = Q
        self.assertNotEqual(context_sha256(p), context_sha256(other))

    def test_07_context_commitment_changes_with_run_id(self):
        p = current()
        other = copy.deepcopy(p)
        other["run_ids"] = (1101, 1250)
        self.assertNotEqual(context_sha256(p), context_sha256(other))

    def test_08_context_commitment_changes_with_log_order(self):
        p = current()
        other = copy.deepcopy(p)
        other["log_sha256"] = (LOGS1[1], LOGS1[0])
        self.assertNotEqual(context_sha256(p), context_sha256(other))

    def test_09_lost_ack_context_is_ambiguous(self):
        p = current()
        p["ack_state"] = "ACK_LOST_READBACK_ONLY"
        self.assertEqual(verify(updated=p)["status"],
                         "LOST_ACK_CONTEXT_CONSISTENT_NOT_AUTHENTICATED")

    def test_10_untrusted_prior_context_rejected(self):
        self.bad(trusted_previous_context_sha256=Q)

    def test_11_wrong_previous_context_link_rejected(self):
        self.bad(lambda c: c.update(previous_context_sha256=Q))

    def test_12_root_rotation_rejected(self):
        self.bad(lambda c: c.update(authority_root_sha256=Q))

    def test_13_epoch_rotation_rejected(self):
        self.bad(lambda c: c.update(authority_epoch=4))

    def test_14_authority_id_rotation_rejected(self):
        self.bad(lambda c: c.update(authority_id="new-key"))

    def test_15_pinned_authority_root_wrong_rejected(self):
        self.bad(trusted_authority_root_sha256=Q)

    def test_16_pinned_authority_epoch_wrong_rejected(self):
        self.bad(trusted_authority_epoch=4)

    def test_17_new_git_sha_wrong_rejected(self):
        self.bad(lambda c: c.update(git_sha="3" * 40))

    def test_18_new_git_pin_wrong_rejected(self):
        self.bad(trusted_current_git_sha="3" * 40)

    def test_19_new_source_sha_wrong_rejected(self):
        self.bad(lambda c: c.update(source_sha256=Q))

    def test_20_source_pin_wrong_rejected(self):
        self.bad(trusted_current_source_sha256=Q)

    def test_21_workflow_changed_without_pin_rejected(self):
        self.bad(lambda c: c.update(workflow_sha256=Q))

    def test_22_roster_changed_without_pin_rejected(self):
        self.bad(lambda c: c.update(roster_sha256=Q))

    def test_23_provider_run_id_rebinding_rejected(self):
        self.bad(lambda c: c.update(run_ids=(1111, 1201)))

    def test_24_provider_job_id_rebinding_rejected(self):
        self.bad(lambda c: c.update(job_ids=(2101, 2211)))

    def test_25_ubuntu_log_rebinding_rejected(self):
        self.bad(lambda c: c.update(log_sha256=(Q, LOGS1[1])))

    def test_26_windows_log_rebinding_rejected(self):
        self.bad(lambda c: c.update(log_sha256=(LOGS1[0], Q)))

    def test_27_cas_generation_same_rejected(self):
        self.bad(lambda c: c.update(cas_generation=7))

    def test_28_cas_generation_jump_rejected(self):
        self.bad(lambda c: c.update(cas_generation=9))

    def test_29_cas_root_aba_rejected(self):
        self.bad(lambda c: c.update(cas_root_sha256=CAS0))

    def test_30_same_git_sha_different_attestation_rejected(self):
        self.bad(lambda c: c.update(git_sha=SHA0),
                 trusted_current_git_sha=SHA0)

    def test_31_run_ids_must_advance_rejected(self):
        self.bad(lambda c: c.update(run_ids=(1100, 1201)),
                 trusted_current_run_ids=(1100, 1201))

    def test_32_job_ids_must_advance_rejected(self):
        self.bad(lambda c: c.update(job_ids=(2101, 2200)),
                 trusted_current_job_ids=(2101, 2200))

    def test_33_prior_ubuntu_log_reuse_rejected(self):
        self.bad(lambda c: c.update(log_sha256=(LOGS0[0], LOGS1[1])),
                 trusted_current_log_sha256=(LOGS0[0], LOGS1[1]))

    def test_34_cross_platform_prior_log_reuse_rejected(self):
        self.bad(lambda c: c.update(log_sha256=(LOGS0[1], LOGS1[1])),
                 trusted_current_log_sha256=(LOGS0[1], LOGS1[1]))

    def test_35_same_new_platform_log_rejected(self):
        self.bad(lambda c: c.update(log_sha256=(LOGS1[0], LOGS1[0])))

    def test_36_duplicate_new_run_ids_rejected(self):
        self.bad(lambda c: c.update(run_ids=(1101, 1101)))

    def test_37_duplicate_new_job_ids_rejected(self):
        self.bad(lambda c: c.update(job_ids=(2101, 2101)))

    def test_38_second_run_attempt_rejected(self):
        self.bad(lambda c: c.update(run_attempts=(2, 1)))

    def test_39_boolean_run_attempt_rejected(self):
        self.bad(lambda c: c.update(run_attempts=(True, 1)))

    def test_40_claimed_release_ready_rejected(self):
        self.bad(lambda c: c.update(release_ready=True))

    def test_41_claimed_live_trading_rejected(self):
        self.bad(lambda c: c.update(live_trading_allowed=True))

    def test_42_fake_signed_trace_status_rejected(self):
        self.bad(lambda c: c.update(trace_status="SIGNED_GITHUB_PASS"))

    def test_43_fake_authenticated_pair_status_rejected(self):
        self.bad(lambda c: c.update(pair_status="AUTHENTICATED"))

    def test_44_fake_replay_authority_status_rejected(self):
        self.bad(lambda c: c.update(replay_status="COMMITTED_ATOMICALLY"))

    def test_45_non_public_repository_rejected(self):
        self.bad(lambda c: c.update(repository="ftmstr/Private-Code"))

    def test_46_main_branch_rejected(self):
        self.bad(lambda c: c.update(branch="main"))

    def test_47_unknown_extra_metadata_rejected(self):
        self.bad(lambda c: c.update(production_api_key="invented"))

    def test_48_invalid_authority_key_id_rejected(self):
        self.bad(lambda c: c.update(authority_id="../owner"))

    def test_49_bool_generation_rejected(self):
        self.bad(lambda c: c.update(cas_generation=True))

    def test_50_attacker_controls_all_pins_not_authentication(self):
        p = current()
        # This remains only an internally consistent claimed context, even if
        # a malicious submitter supplies every pin and both invented logs.
        p["source_sha256"] = Q
        answer = verify(updated=p, trusted_current_source_sha256=Q)
        self.assertTrue(answer["status"].endswith("NOT_AUTHENTICATED"))
        self.assertFalse(answer["release_ready"])


if __name__ == "__main__":
    unittest.main()
