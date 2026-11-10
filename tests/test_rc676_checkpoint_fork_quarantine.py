"""Original invented-data RC676 fork, revocation and lost-ACK adversaries."""
import copy
import unittest
from safe_public_ci.ci_claimed_checkpoint_fork_quarantine import (
    CheckpointForkRejected, claimed_checkpoint_sha256,
    quarantine_synthetic_checkpoint,
)


def d(ch):
    return ch * 64


WIDS = ("writer_alpha", "writer_beta")
OIDS = ("observer_north", "observer_south")
AIDS = ("owner_alice", "reviewer_bob", "custodian_carol")
KEYS = (d("a"), d("b"), d("c"))
LOGS = (d("7"), d("8"))
ROLES = ("owner", "independent_reviewer", "incumbent_custodian")


def fixture():
    c = {
        "repository": "ftmstr/Embasic-KriptoAI-Autopilot-Build",
        "branch": "validation/rc654-pr1-rc653-combined-ci",
        "git_sha": "a" * 40, "source_sha256": d("d"),
        "workflow_sha256": d("e"), "roster_sha256": d("9"),
        "authority_root_sha256": d("3"), "authority_epoch": 3,
        "before_generation": 5, "before_root_sha256": d("1"),
        "after_generation": 6, "after_root_sha256": d("2"),
        "nonce_sha256": d("4"), "pair_sha256": d("5"),
        "log_sha256": LOGS,
        "writer_claims": (
            (WIDS[0], 5, d("1"), "CLAIMED_WIN", d("4"), d("5")),
            (WIDS[1], 5, d("1"), "CLAIMED_CONFLICT", d("4"), d("5")),
        ),
        "observer_claims": (
            (OIDS[0], 6, d("2"), "NOT_VERIFIED"),
            (OIDS[1], 6, d("2"), "NOT_VERIFIED"),
        ),
        "approver_ids": AIDS,
        "approver_keys": KEYS,
        "approval_claims": tuple((role, a, key, "NOT_VERIFIED")
                                 for role, a, key in zip(ROLES, AIDS, KEYS)),
        "revoked_before": (d("0"),),
        "revoked_after": (d("0"), d("f")),
        "spent_before": (), "spent_after": (d("4"),),
        "logs_before": (), "logs_after": LOGS,
        "ack_state": "ACK_CLAIMED", "provider_status": "NOT_VERIFIED",
        "signature_status": "NOT_VERIFIED",
        "release_ready": False, "live_trading_allowed": False,
    }
    p = {
        "git_sha": c["git_sha"], "source_sha256": c["source_sha256"],
        "workflow_sha256": c["workflow_sha256"],
        "roster_sha256": c["roster_sha256"],
        "authority_root_sha256": c["authority_root_sha256"],
        "authority_epoch": 3, "before_generation": 5,
        "before_root_sha256": d("1"), "after_root_sha256": d("2"),
        "nonce_sha256": d("4"), "pair_sha256": d("5"),
        "log_sha256": LOGS, "writer_ids": WIDS,
        "observer_ids": OIDS, "approver_ids": AIDS,
        "approver_keys": KEYS,
        "expected_claim_sha256": claimed_checkpoint_sha256(c),
    }
    return c, p


def replace_writer(c, i, field, value):
    a = list(c["writer_claims"])
    b = list(a[i])
    b[field] = value
    a[i] = tuple(b)
    c["writer_claims"] = tuple(a)


def replace_observer(c, i, field, value):
    a = list(c["observer_claims"])
    b = list(a[i])
    b[field] = value
    a[i] = tuple(b)
    c["observer_claims"] = tuple(a)


def replace_approval(c, i, field, value):
    a = list(c["approval_claims"])
    b = list(a[i])
    b[field] = value
    a[i] = tuple(b)
    c["approval_claims"] = tuple(a)


class RC676CheckpointForkTests(unittest.TestCase):
    def reject(self, mutate):
        c, p = fixture()
        mutate(c, p)
        with self.assertRaises(CheckpointForkRejected):
            quarantine_synthetic_checkpoint(c, pinned=p)

    def test_01_consistent_claim_remains_quarantined(self):
        c, p = fixture()
        r = quarantine_synthetic_checkpoint(c, pinned=p)
        self.assertEqual(r["status"],
                         "CLAIMED_FORK_FREE_CHECKPOINT_QUARANTINED_NOT_AUTHENTICATED")
        for field in ("provider_origin_verified", "signatures_verified",
                      "cas_atomicity_verified", "ledger_write_performed",
                      "release_ready", "live_trading_allowed"):
            self.assertFalse(r[field])
        self.assertEqual((r["claimed_winners"], r["claimed_conflicts"]), (1, 1))

    def test_02_claim_hash_deterministic_not_signature(self):
        c, _ = fixture()
        self.assertEqual(claimed_checkpoint_sha256(c),
                         claimed_checkpoint_sha256(copy.deepcopy(c)))

    def test_03_source_mutation_changes_digest(self):
        c, _ = fixture()
        old = claimed_checkpoint_sha256(c)
        c["source_sha256"] = d("f")
        self.assertNotEqual(claimed_checkpoint_sha256(c), old)

    def test_04_workflow_mutation_changes_digest(self):
        c, _ = fixture()
        old = claimed_checkpoint_sha256(c)
        c["workflow_sha256"] = d("f")
        self.assertNotEqual(claimed_checkpoint_sha256(c), old)

    def test_05_claimed_ack_lost_remains_no_go(self):
        c, p = fixture()
        c["ack_state"] = "ACK_LOST_UNRESOLVED"
        p["expected_claim_sha256"] = claimed_checkpoint_sha256(c)
        r = quarantine_synthetic_checkpoint(c, pinned=p)
        self.assertTrue(r["lost_ack_unresolved"])
        self.assertFalse(r["ledger_write_performed"])

    def test_06_parallel_calls_do_not_atomically_consume(self):
        c, p = fixture()
        a = quarantine_synthetic_checkpoint(c, pinned=p)
        b = quarantine_synthetic_checkpoint(c, pinned=p)
        self.assertEqual(a, b)
        self.assertFalse(a["cas_atomicity_verified"])

    def test_07_forged_matching_pin_still_not_authenticated(self):
        c, p = fixture()
        c["source_sha256"] = d("f")
        p["source_sha256"] = d("f")
        p["expected_claim_sha256"] = claimed_checkpoint_sha256(c)
        result = quarantine_synthetic_checkpoint(c, pinned=p)
        self.assertFalse(result["provider_origin_verified"])

    def test_08_extra_unrelated_revocation_is_structurally_allowed(self):
        c, p = fixture()
        c["revoked_after"] = (d("0"), d("e"), d("f"))
        p["expected_claim_sha256"] = claimed_checkpoint_sha256(c)
        r = quarantine_synthetic_checkpoint(c, pinned=p)
        self.assertFalse(r["signatures_verified"])

    def test_09_claimed_winner_does_not_mean_committed(self):
        c, p = fixture()
        r = quarantine_synthetic_checkpoint(c, pinned=p)
        self.assertNotIn("COMMITTED", r["status"])
        self.assertFalse(r["ledger_write_performed"])

    def test_10_forged_observer_names_still_not_provider_verified(self):
        c, p = fixture()
        replace_observer(c, 0, 0, "observer_forged")
        p["observer_ids"] = ("observer_forged", OIDS[1])
        p["expected_claim_sha256"] = claimed_checkpoint_sha256(c)
        r = quarantine_synthetic_checkpoint(c, pinned=p)
        self.assertFalse(r["provider_origin_verified"])
    def test_11_foreign_repo(self):
        self.reject(lambda c, p: c.update(repository="ftmstr/Private"))

    def test_12_wrong_branch(self):
        self.reject(lambda c, p: c.update(branch="main"))

    def test_13_invalid_git_sha(self):
        self.reject(lambda c, p: c.update(git_sha="z" * 40))

    def test_14_bad_git_pin(self):
        self.reject(lambda c, p: p.update(git_sha="b" * 40))

    def test_15_source_pin_mismatch(self):
        self.reject(lambda c, p: p.update(source_sha256=d("f")))

    def test_16_workflow_pin_mismatch(self):
        self.reject(lambda c, p: p.update(workflow_sha256=d("f")))

    def test_17_roster_pin_mismatch(self):
        self.reject(lambda c, p: p.update(roster_sha256=d("f")))

    def test_18_authority_pin_mismatch(self):
        self.reject(lambda c, p: p.update(authority_root_sha256=d("f")))

    def test_19_authority_epoch_pin_mismatch(self):
        self.reject(lambda c, p: p.update(authority_epoch=4))

    def test_20_bool_authority_epoch(self):
        self.reject(lambda c, p: c.update(authority_epoch=True))

    def test_21_before_generation_pin_mismatch(self):
        self.reject(lambda c, p: p.update(before_generation=6))

    def test_22_bool_before_generation(self):
        self.reject(lambda c, p: c.update(before_generation=True))

    def test_23_generation_jump(self):
        self.reject(lambda c, p: c.update(after_generation=7))

    def test_24_generation_rollback(self):
        self.reject(lambda c, p: c.update(after_generation=4))

    def test_25_aba_same_root(self):
        self.reject(lambda c, p: c.update(after_root_sha256=d("1")))

    def test_26_wrong_before_root(self):
        self.reject(lambda c, p: p.update(before_root_sha256=d("f")))

    def test_27_wrong_after_root(self):
        self.reject(lambda c, p: p.update(after_root_sha256=d("f")))

    def test_28_wrong_nonce_pin(self):
        self.reject(lambda c, p: p.update(nonce_sha256=d("f")))

    def test_29_wrong_pair_pin(self):
        self.reject(lambda c, p: p.update(pair_sha256=d("f")))

    def test_30_swapped_logs(self):
        self.reject(lambda c, p: c.update(log_sha256=(LOGS[1], LOGS[0])))

    def test_31_duplicate_logs(self):
        self.reject(lambda c, p: c.update(log_sha256=(LOGS[0], LOGS[0])))

    def test_32_wrong_logs_pin(self):
        self.reject(lambda c, p: p.update(log_sha256=(d("f"), LOGS[1])))

    def test_33_wrong_writer_ids_pin(self):
        self.reject(lambda c, p: p.update(writer_ids=("writer_other", WIDS[1])))

    def test_34_wrong_observer_ids_pin(self):
        self.reject(lambda c, p: p.update(observer_ids=("observer_other", OIDS[1])))

    def test_35_writer_both_winners(self):
        self.reject(lambda c, p: replace_writer(c, 1, 3, "CLAIMED_WIN"))

    def test_36_writer_both_conflicts(self):
        self.reject(lambda c, p: replace_writer(c, 0, 3, "CLAIMED_CONFLICT"))

    def test_37_writer_stale_generation(self):
        self.reject(lambda c, p: replace_writer(c, 1, 1, 4))

    def test_38_writer_wrong_base_root(self):
        self.reject(lambda c, p: replace_writer(c, 0, 2, d("f")))

    def test_39_writer_changed_nonce(self):
        self.reject(lambda c, p: replace_writer(c, 1, 4, d("f")))

    def test_40_writer_changed_pair(self):
        self.reject(lambda c, p: replace_writer(c, 1, 5, d("f")))

    def test_41_writer_duplicate_name(self):
        self.reject(lambda c, p: replace_writer(c, 1, 0, WIDS[0]))

    def test_42_writer_bool_generation(self):
        self.reject(lambda c, p: replace_writer(c, 0, 1, True))

    def test_43_observer_forked_root(self):
        self.reject(lambda c, p: replace_observer(c, 1, 2, d("f")))

    def test_44_observer_stale_generation(self):
        self.reject(lambda c, p: replace_observer(c, 0, 1, 5))

    def test_45_observer_fake_signed(self):
        self.reject(lambda c, p: replace_observer(c, 1, 3, "VERIFIED"))

    def test_46_observer_duplicate_name(self):
        self.reject(lambda c, p: replace_observer(c, 1, 0, OIDS[0]))

    def test_47_observer_bool_generation(self):
        self.reject(lambda c, p: replace_observer(c, 0, 1, True))

    def test_48_approver_cloned_actor(self):
        self.reject(lambda c, p: c.update(approver_ids=(AIDS[0], AIDS[0], AIDS[2])))

    def test_49_approver_cloned_key(self):
        self.reject(lambda c, p: c.update(approver_keys=(KEYS[0], KEYS[0], KEYS[2])))

    def test_50_approver_false_signed(self):
        self.reject(lambda c, p: replace_approval(c, 1, 3, "SIGNED"))

    def test_51_approver_wrong_role(self):
        self.reject(lambda c, p: replace_approval(c, 1, 0, "owner"))

    def test_52_approver_actor_rebind(self):
        self.reject(lambda c, p: replace_approval(c, 1, 1, AIDS[0]))

    def test_53_approver_key_rebind(self):
        self.reject(lambda c, p: replace_approval(c, 1, 2, KEYS[0]))

    def test_54_approver_key_revoked(self):
        self.reject(lambda c, p: c.update(revoked_after=(d("0"), KEYS[0], d("f"))))

    def test_55_reviewer_key_revoked(self):
        self.reject(lambda c, p: c.update(revoked_after=(d("0"), KEYS[1], d("f"))))

    def test_56_custodian_key_revoked(self):
        self.reject(lambda c, p: c.update(revoked_after=(d("0"), KEYS[2], d("f"))))

    def test_57_revocation_rollback(self):
        self.reject(lambda c, p: c.update(revoked_after=(d("f"),)))

    def test_58_revocation_list_not_tuple(self):
        self.reject(lambda c, p: c.update(revoked_after=[d("0"), d("f")]))

    def test_59_spent_nonce_replay(self):
        self.reject(lambda c, p: c.update(spent_before=(d("4"),)))

    def test_60_missing_spent_write(self):
        self.reject(lambda c, p: c.update(spent_after=()))

    def test_61_duplicate_spent_write(self):
        self.reject(lambda c, p: c.update(spent_after=(d("4"), d("4"))))

    def test_62_old_log_reuse(self):
        self.reject(lambda c, p: c.update(logs_before=(LOGS[0],)))

    def test_63_missing_windows_log_consumption(self):
        self.reject(lambda c, p: c.update(logs_after=(LOGS[0],)))

    def test_64_duplicate_seen_log(self):
        self.reject(lambda c, p: c.update(logs_after=(LOGS[0], LOGS[0], LOGS[1])))

    def test_65_fake_ack_applied(self):
        self.reject(lambda c, p: c.update(ack_state="ACK_APPLIED"))

    def test_66_rollback_after_ambiguous_ack(self):
        self.reject(lambda c, p: c.update(ack_state="ROLLBACK_AFTER_ACK_LOST"))

    def test_67_fake_provider_verified(self):
        self.reject(lambda c, p: c.update(provider_status="VERIFIED"))

    def test_68_fake_signature_verified(self):
        self.reject(lambda c, p: c.update(signature_status="VERIFIED"))

    def test_69_release_ready_bypass(self):
        self.reject(lambda c, p: c.update(release_ready=True))

    def test_70_live_trading_bypass(self):
        self.reject(lambda c, p: c.update(live_trading_allowed=True))


if __name__ == "__main__":
    unittest.main()
