"""RC674 fully invented issuer, provider, replay and false-signature fixtures."""
import copy
import unittest
from safe_public_ci.ci_witness_equivocation_quarantine import (
    WitnessQuarantineRejected, claimed_witness_digest,
    quarantine_synthetic_witnesses,
)

S = lambda c: c * 64
OLD, NEW, CTX, SRC, FLOW, ROSTER, NONCE = map(S, "1234567")
LOGS = (S("8"), S("9"))
SHA = "a" * 40
ACTORS = ("owner_alice", "reviewer_bob", "custodian_carol")
KEYS = (S("a"), S("b"), S("c"))
ROLES = ("owner", "independent_reviewer", "incumbent_custodian")


def sample():
    e = dict(
        repository="ftmstr/Embasic-KriptoAI-Autopilot-Build",
        branch="validation/rc654-pr1-rc653-combined-ci",
        intent_sha256=S("d"), previous_context_sha256=CTX,
        old_root_sha256=OLD, new_root_sha256=NEW,
        git_sha=SHA, source_sha256=SRC, workflow_sha256=FLOW,
        roster_sha256=ROSTER, nonce_sha256=NONCE, cas_generation=12,
        ack_state="NOT_SUBMITTED", run_ids=(300, 400),
        job_ids=(500, 600), log_sha256=LOGS,
        approval_claims=(), provider_claims=(),
        release_ready=False, live_trading_allowed=False,
    )
    d = claimed_witness_digest(e)
    e["approval_claims"] = tuple((role, name, key, d, "NOT_VERIFIED")
                                 for role, name, key in zip(ROLES, ACTORS, KEYS))
    e["provider_claims"] = tuple(
        (name, run, job, SHA, log, d, "NOT_VERIFIED")
        for name, run, job, log in zip(("ubuntu", "windows"),
                                        e["run_ids"], e["job_ids"], LOGS)
    )
    pins = dict(
        intent_sha256=e["intent_sha256"], previous_context_sha256=CTX,
        old_root_sha256=OLD, git_sha=SHA, source_sha256=SRC,
        workflow_sha256=FLOW, roster_sha256=ROSTER,
        cas_generation=12, run_ids=(300, 400), job_ids=(500, 600),
        log_sha256=LOGS, spent_nonce_sha256=(), seen_log_sha256=(),
        old_root_history=(OLD,), approver_ids=ACTORS,
        approver_key_fingerprints=KEYS,
    )
    return e, pins


def _replace_approval(e, index, field, value):
    approvals = list(e["approval_claims"])
    item = list(approvals[index])
    item[field] = value
    approvals[index] = tuple(item)
    e["approval_claims"] = tuple(approvals)


def _replace_provider(e, index, field, value):
    reports = list(e["provider_claims"])
    item = list(reports[index])
    item[field] = value
    reports[index] = tuple(reports)


class RC674WitnessAdversarialTests(unittest.TestCase):
    def reject(self, edit):
        e, pinned = sample()
        edit(e, pinned)
        with self.assertRaises(WitnessQuarantineRejected):
            quarantine_synthetic_witnesses(e, pinned=pinned)

    def test_01_good_invented_case_is_still_quarantined(self):
        e, pinned = sample()
        r = quarantine_synthetic_witnesses(e, pinned=pinned)
        self.assertEqual(r["status"], "WITNESS_CLAIMS_QUARANTINED_NOT_AUTHENTICATED")
        self.assertFalse(r["independent_signatures_verified"])
        self.assertFalse(r["provider_origin_verified"])
        self.assertFalse(r["cas_atomicity_verified"])
        self.assertFalse(r["release_ready"])
        self.assertFalse(r["live_trading_allowed"])

    def test_02_digest_is_deterministic_but_not_signature(self):
        e, _ = sample()
        self.assertEqual(claimed_witness_digest(e), claimed_witness_digest(e))

    def test_03_source_sha_change_changes_statement(self):
        e, _ = sample()
        old = claimed_witness_digest(e)
        e["source_sha256"] = S("e")
        self.assertNotEqual(old, claimed_witness_digest(e))

    def test_04_os_order_changes_statement(self):
        e, _ = sample()
        old = claimed_witness_digest(e)
        e["log_sha256"] = tuple(reversed(LOGS))
        self.assertNotEqual(old, claimed_witness_digest(e))

    def test_05_nonce_changes_statement(self):
        e, _ = sample()
        old = claimed_witness_digest(e)
        e["nonce_sha256"] = S("f")
        self.assertNotEqual(old, claimed_witness_digest(e))

    def test_06_lost_ack_cannot_authenticate(self):
        e, pinned = sample()
        e["ack_state"] = "ACK_LOST_UNRESOLVED"
        d = claimed_witness_digest(e)
        e["approval_claims"] = tuple((role, actor, key, d, "NOT_VERIFIED")
                                     for role, actor, key in zip(ROLES, ACTORS, KEYS))
        e["provider_claims"] = tuple((os, run, job, SHA, log, d, "NOT_VERIFIED")
                                     for os, run, job, log in zip(("ubuntu", "windows"),
                                         e["run_ids"], e["job_ids"], LOGS))
        answer = quarantine_synthetic_witnesses(e, pinned=pinned)
        self.assertFalse(answer["independent_signatures_verified"])
        self.assertFalse(answer["release_ready"])

    def test_07_attacker_may_control_pins_but_cannot_enable(self):
        e, pins = sample()
        e["source_sha256"] = S("f")
        pins["source_sha256"] = S("f")
        d = claimed_witness_digest(e)
        e["approval_claims"] = tuple((role, name, key, d, "NOT_VERIFIED")
                                     for role, name, key in zip(ROLES, ACTORS, KEYS))
        e["provider_claims"] = tuple((name, run, job, SHA, log, d, "NOT_VERIFIED")
                                     for name, run, job, log in zip(("ubuntu", "windows"),
                                         e["run_ids"], e["job_ids"], LOGS))
        out = quarantine_synthetic_witnesses(e, pinned=pins)
        self.assertFalse(out["provider_origin_verified"])
        self.assertFalse(out["release_ready"])

    def test_08_foreign_repo(self):
        self.reject(lambda e, p: e.update(repository="ftmstr/Private-Code"))

    def test_09_main_branch(self):
        self.reject(lambda e, p: e.update(branch="main"))

    def test_10_invalid_git_sha(self):
        self.reject(lambda e, p: e.update(git_sha="z" * 40))

    def test_11_wrong_git_pin(self):
        self.reject(lambda e, p: p.update(git_sha="f" * 40))

    def test_12_wrong_source_pin(self):
        self.reject(lambda e, p: p.update(source_sha256=S("f")))

    def test_13_wrong_workflow_pin(self):
        self.reject(lambda e, p: p.update(workflow_sha256=S("f")))

    def test_14_wrong_roster_pin(self):
        self.reject(lambda e, p: p.update(roster_sha256=S("f")))

    def test_15_wrong_prior_context_pin(self):
        self.reject(lambda e, p: p.update(previous_context_sha256=S("f")))

    def test_16_wrong_old_root_pin(self):
        self.reject(lambda e, p: p.update(old_root_sha256=S("f")))

    def test_17_wrong_intent_pin(self):
        self.reject(lambda e, p: p.update(intent_sha256=S("f")))

    def test_18_same_old_new_root(self):
        self.reject(lambda e, p: e.update(new_root_sha256=OLD))

    def test_19_epoch_boolean(self):
        self.reject(lambda e, p: e.update(cas_generation=True))

    def test_20_wrong_generation_pin(self):
        self.reject(lambda e, p: p.update(cas_generation=13))

    def test_21_malformed_run_ids(self):
        self.reject(lambda e, p: e.update(run_ids=(True, 400)))

    def test_22_duplicate_run_ids(self):
        self.reject(lambda e, p: e.update(run_ids=(300, 300)))

    def test_23_duplicate_job_ids(self):
        self.reject(lambda e, p: e.update(job_ids=(500, 500)))

    def test_24_wrong_run_pin(self):
        self.reject(lambda e, p: p.update(run_ids=(301, 400)))

    def test_25_wrong_job_pin(self):
        self.reject(lambda e, p: p.update(job_ids=(501, 600)))

    def test_26_ubuntu_windows_same_log(self):
        self.reject(lambda e, p: e.update(log_sha256=(LOGS[0], LOGS[0])))

    def test_27_wrong_log_pin(self):
        self.reject(lambda e, p: p.update(log_sha256=(S("e"), LOGS[1])))

    def test_28_spent_nonce(self):
        self.reject(lambda e, p: p.update(spent_nonce_sha256=(NONCE,)))

    def test_29_reused_ubuntu_log(self):
        self.reject(lambda e, p: p.update(seen_log_sha256=(LOGS[0],)))

    def test_30_reused_windows_log(self):
        self.reject(lambda e, p: p.update(seen_log_sha256=(LOGS[1],)))

    def test_31_aba_new_root(self):
        self.reject(lambda e, p: p.update(old_root_history=(OLD, NEW)))

    def test_32_unsorted_root_history(self):
        self.reject(lambda e, p: p.update(old_root_history=(NEW, OLD)))

    def test_33_duplicate_nonce_history(self):
        self.reject(lambda e, p: p.update(spent_nonce_sha256=(NONCE, NONCE)))

    def test_34_invalid_history_list(self):
        self.reject(lambda e, p: p.update(seen_log_sha256=[LOGS[0]]))

    def test_35_fake_ack_applied(self):
        self.reject(lambda e, p: e.update(ack_state="ACK_APPLIED"))

    def test_36_live_flag(self):
        self.reject(lambda e, p: e.update(live_trading_allowed=True))

    def test_37_release_flag(self):
        self.reject(lambda e, p: e.update(release_ready=True))

    def test_38_extra_claim_key(self):
        self.reject(lambda e, p: e.update(signed=True))

    def test_39_missing_pin_key(self):
        self.reject(lambda e, p: p.pop("git_sha"))

    def test_40_approver_ids_cloned(self):
        self.reject(lambda e, p: p.update(approver_ids=(ACTORS[0], ACTORS[0], ACTORS[2])))

    def test_41_approver_keys_cloned(self):
        self.reject(lambda e, p: p.update(approver_key_fingerprints=(KEYS[0], KEYS[0], KEYS[2])))

    def test_42_approval_count_wrong(self):
        self.reject(lambda e, p: e.update(approval_claims=e["approval_claims"][:2]))

    def test_43_approval_list_wrong(self):
        self.reject(lambda e, p: e.update(approval_claims=list(e["approval_claims"])))

    def test_44_approval_role_conflict(self):
        self.reject(lambda e, p: _replace_approval(e, 1, 0, "owner"))

    def test_45_approval_actor_conflict(self):
        self.reject(lambda e, p: _replace_approval(e, 1, 1, ACTORS[0]))

    def test_46_approval_fingerprint_conflict(self):
        self.reject(lambda e, p: _replace_approval(e, 1, 2, KEYS[0]))

    def test_47_approval_statement_conflict(self):
        self.reject(lambda e, p: _replace_approval(e, 1, 3, S("f")))

    def test_48_fake_verified_approval(self):
        self.reject(lambda e, p: _replace_approval(e, 0, 4, "VERIFIED"))

    def test_49_missing_provider_claim(self):
        self.reject(lambda e, p: e.update(provider_claims=e["provider_claims"][:1]))

    def test_50_swapped_provider_os(self):
        self.reject(lambda e, p: _replace_provider(e, 0, 0, "windows"))

    def test_51_wrong_provider_run(self):
        self.reject(lambda e, p: _replace_provider(e, 0, 1, 301))

    def test_52_wrong_provider_job(self):
        self.reject(lambda e, p: _replace_provider(e, 1, 2, 601))

    def test_53_provider_foreign_commit(self):
        self.reject(lambda e, p: _replace_provider(e, 0, 3, "b" * 40))

    def test_54_provider_log_rebind(self):
        self.reject(lambda e, p: _replace_provider(e, 1, 4, LOGS[0]))

    def test_55_provider_statement_conflict(self):
        self.reject(lambda e, p: _replace_provider(e, 0, 5, S("f")))

    def test_56_provider_fake_signed_status(self):
        self.reject(lambda e, p: _replace_provider(e, 0, 6, "SIGNED"))

    def test_57_provider_wrong_type(self):
        self.reject(lambda e, p: e.update(provider_claims=list(e["provider_claims"])))

    def test_58_boolean_claimed_run(self):
        self.reject(lambda e, p: _replace_provider(e, 0, 1, True))

    def test_59_invalid_root_history(self):
        self.reject(lambda e, p: p.update(old_root_history=("nothex",)))

    def test_60_wrong_key_format(self):
        self.reject(lambda e, p: p.update(approver_key_fingerprints=(KEYS[0], "bad", KEYS[2])))


if __name__ == "__main__":
    unittest.main()
