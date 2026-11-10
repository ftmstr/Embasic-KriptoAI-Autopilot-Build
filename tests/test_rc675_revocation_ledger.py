"""Original invented-data tests; never proof of genuine keys, CI or CAS."""
import copy
import unittest
from safe_public_ci.ci_revocation_ledger_quarantine import (
    LedgerQuarantineRejected, claim_sha256, quarantine_synthetic_ledger,
)


def d(c):
    return c * 64


ROLES = ("owner", "independent_reviewer", "incumbent_custodian")
ACTORS = ("owner_a", "reviewer_b", "custodian_c")
KEYS = (d("a"), d("b"), d("c"))
LOGS = (d("7"), d("8"))


def fixture():
    claim = {
        "repository": "ftmstr/Embasic-KriptoAI-Autopilot-Build",
        "branch": "validation/rc654-pr1-rc653-combined-ci",
        "git_sha": "a" * 40, "source_sha256": d("3"),
        "workflow_sha256": d("4"), "roster_sha256": d("5"),
        "authority_epoch": 3, "authority_root_sha256": d("1"),
        "ledger_generation": 9, "ledger_root_sha256": d("e"),
        "proposed_generation": 10, "proposed_root_sha256": d("2"),
        "nonce_sha256": d("6"), "log_sha256": LOGS,
        "run_ids": (1001, 1002), "job_ids": (2001, 2002),
        "issuer_ids": ACTORS, "key_fingerprints": KEYS,
        "approval_claims": (), "approval_state": "UNVERIFIED",
        "provider_state": "UNVERIFIED", "ack_state": "NOT_SENT",
        "release_ready": False, "live_trading_allowed": False,
    }
    digest = claim_sha256(claim)
    claim["approval_claims"] = tuple((role, name, key, digest, "NOT_VERIFIED")
                                      for role, name, key in zip(ROLES, ACTORS, KEYS))
    pins = {
        "git_sha": claim["git_sha"], "source_sha256": claim["source_sha256"],
        "workflow_sha256": claim["workflow_sha256"],
        "roster_sha256": claim["roster_sha256"],
        "authority_epoch": 3, "authority_root_sha256": d("1"),
        "ledger_generation": 9, "ledger_root_sha256": d("e"),
        "run_ids": claim["run_ids"], "job_ids": claim["job_ids"],
        "log_sha256": LOGS, "issuer_ids": ACTORS,
        "key_fingerprints": KEYS, "revoked_key_fingerprints": (),
        "retired_authority_roots": (), "consumed_nonce_sha256": (),
        "seen_log_sha256": (), "seen_proposal_sha256": (),
        "expected_claim_sha256": digest,
    }
    return claim, pins


def refresh(claim, pins):
    """Emulate attacker rewriting all matching hashes; never true auth."""
    digest = claim_sha256(claim)
    claim["approval_claims"] = tuple((role, actor, key, digest, "NOT_VERIFIED")
                                      for role, actor, key in zip(ROLES, claim["issuer_ids"],
                                                                  claim["key_fingerprints"]))
    pins["expected_claim_sha256"] = digest


class RC675TrustedLedgerClaimsTests(unittest.TestCase):
    def reject(self, mutate):
        claim, pins = fixture()
        mutate(claim, pins)
        with self.assertRaises(LedgerQuarantineRejected):
            quarantine_synthetic_ledger(claim, pinned=pins)

    def test_01_consistent_claim_still_quarantined(self):
        claim, pins = fixture()
        result = quarantine_synthetic_ledger(claim, pinned=pins)
        self.assertEqual(result["status"],
                         "REVOKED_LEDGER_CLAIMS_QUARANTINED_NOT_AUTHENTICATED")
        for field in ("external_root_authenticated", "signatures_verified",
                      "cas_atomicity_verified", "ledger_write_performed",
                      "release_ready", "live_trading_allowed"):
            self.assertIs(result[field], False)

    def test_02_deterministic_claim_hash_not_signature(self):
        claim, _ = fixture()
        self.assertEqual(claim_sha256(claim), claim_sha256(copy.deepcopy(claim)))

    def test_03_source_changes_commitment(self):
        claim, _ = fixture()
        old = claim_sha256(claim)
        claim["source_sha256"] = d("f")
        self.assertNotEqual(old, claim_sha256(claim))

    def test_04_log_order_changes_commitment(self):
        claim, _ = fixture()
        old = claim_sha256(claim)
        claim["log_sha256"] = tuple(reversed(LOGS))
        self.assertNotEqual(old, claim_sha256(claim))

    def test_05_nonce_changes_commitment(self):
        claim, _ = fixture()
        old = claim_sha256(claim)
        claim["nonce_sha256"] = d("f")
        self.assertNotEqual(old, claim_sha256(claim))

    def test_06_lost_ack_stays_quarantined(self):
        claim, pins = fixture()
        claim["ack_state"] = "ACK_LOST_UNRESOLVED"
        refresh(claim, pins)
        result = quarantine_synthetic_ledger(claim, pinned=pins)
        self.assertIs(result["ledger_write_performed"], False)
        self.assertIs(result["release_ready"], False)

    def test_07_attacker_controls_pins_no_authentication(self):
        claim, pins = fixture()
        claim["source_sha256"] = d("f")
        pins["source_sha256"] = d("f")
        refresh(claim, pins)
        answer = quarantine_synthetic_ledger(claim, pinned=pins)
        self.assertIs(answer["external_root_authenticated"], False)
        self.assertIs(answer["signatures_verified"], False)

    def test_08_parallel_same_proposal_not_atomic(self):
        claim, pins = fixture()
        one = quarantine_synthetic_ledger(claim, pinned=pins)
        two = quarantine_synthetic_ledger(claim, pinned=pins)
        self.assertEqual(one, two)
        self.assertFalse(one["cas_atomicity_verified"])

    def test_09_proposed_generation_changes_commitment(self):
        claim, _ = fixture()
        old = claim_sha256(claim)
        claim["ledger_generation"] = 10
        claim["proposed_generation"] = 11
        self.assertNotEqual(old, claim_sha256(claim))

    def test_10_consistent_root_and_issuer_hashes_are_unverified(self):
        claim, pins = fixture()
        result = quarantine_synthetic_ledger(claim, pinned=pins)
        self.assertNotIn("AUTHENTICATED", result["status"].replace("NOT_AUTHENTICATED", ""))

    def test_11_foreign_repository(self):
        self.reject(lambda c, p: c.update(repository="ftmstr/Private"))

    def test_12_main_branch(self):
        self.reject(lambda c, p: c.update(branch="main"))

    def test_13_malformed_git_sha(self):
        self.reject(lambda c, p: c.update(git_sha="z" * 40))

    def test_14_wrong_git_pin(self):
        self.reject(lambda c, p: p.update(git_sha="b" * 40))

    def test_15_wrong_source_pin(self):
        self.reject(lambda c, p: p.update(source_sha256=d("f")))

    def test_16_wrong_workflow_pin(self):
        self.reject(lambda c, p: p.update(workflow_sha256=d("f")))

    def test_17_wrong_roster_pin(self):
        self.reject(lambda c, p: p.update(roster_sha256=d("f")))

    def test_18_wrong_root_pin(self):
        self.reject(lambda c, p: p.update(authority_root_sha256=d("f")))

    def test_19_wrong_ledger_root_pin(self):
        self.reject(lambda c, p: p.update(ledger_root_sha256=d("f")))

    def test_20_wrong_epoch_pin(self):
        self.reject(lambda c, p: p.update(authority_epoch=4))

    def test_21_bool_epoch(self):
        self.reject(lambda c, p: c.update(authority_epoch=True))

    def test_22_bool_generation(self):
        self.reject(lambda c, p: c.update(ledger_generation=True))

    def test_23_generation_jump(self):
        self.reject(lambda c, p: c.update(proposed_generation=11))

    def test_24_generation_rollback(self):
        self.reject(lambda c, p: c.update(proposed_generation=8))

    def test_25_aba_same_root(self):
        self.reject(lambda c, p: c.update(proposed_root_sha256=d("e")))

    def test_26_bad_nonce(self):
        self.reject(lambda c, p: c.update(nonce_sha256="garbage"))

    def test_27_duplicate_runs(self):
        self.reject(lambda c, p: c.update(run_ids=(1001, 1001)))

    def test_28_duplicate_jobs(self):
        self.reject(lambda c, p: c.update(job_ids=(2001, 2001)))

    def test_29_boolean_run(self):
        self.reject(lambda c, p: c.update(run_ids=(True, 1002)))

    def test_30_wrong_runs_pin(self):
        self.reject(lambda c, p: p.update(run_ids=(1001, 1003)))

    def test_31_wrong_jobs_pin(self):
        self.reject(lambda c, p: p.update(job_ids=(2001, 2003)))

    def test_32_duplicate_os_log(self):
        self.reject(lambda c, p: c.update(log_sha256=(LOGS[0], LOGS[0])))

    def test_33_wrong_log_pin(self):
        self.reject(lambda c, p: p.update(log_sha256=(d("f"), LOGS[1])))

    def test_34_approval_fake_verified(self):
        self.reject(lambda c, p: c.update(approval_state="VERIFIED"))

    def test_35_provider_fake_verified(self):
        self.reject(lambda c, p: c.update(provider_state="GITHUB_SIGNED"))

    def test_36_ack_applied_claim(self):
        self.reject(lambda c, p: c.update(ack_state="ACK_APPLIED"))

    def test_37_live_true(self):
        self.reject(lambda c, p: c.update(live_trading_allowed=True))

    def test_38_release_true(self):
        self.reject(lambda c, p: c.update(release_ready=True))

    def test_39_extra_claim_field(self):
        self.reject(lambda c, p: c.update(private_token="invented"))

    def test_40_missing_claim_field(self):
        self.reject(lambda c, p: c.pop("source_sha256"))

    def test_41_missing_pin(self):
        self.reject(lambda c, p: p.pop("expected_claim_sha256"))

    def test_42_extra_pin(self):
        self.reject(lambda c, p: p.update(signature_approved=True))

    def test_43_fake_expected_digest(self):
        self.reject(lambda c, p: p.update(expected_claim_sha256=d("f")))

    def test_44_revoked_reviewer_key(self):
        self.reject(lambda c, p: p.update(revoked_key_fingerprints=(KEYS[1],)))

    def test_45_revoked_owner_key(self):
        self.reject(lambda c, p: p.update(revoked_key_fingerprints=(KEYS[0],)))

    def test_46_revoked_incumbent_key(self):
        self.reject(lambda c, p: p.update(revoked_key_fingerprints=(KEYS[2],)))

    def test_47_retired_current_root(self):
        self.reject(lambda c, p: p.update(retired_authority_roots=(d("1"),)))

    def test_48_retired_proposed_root(self):
        self.reject(lambda c, p: p.update(retired_authority_roots=(d("2"),)))

    def test_49_reused_nonce(self):
        self.reject(lambda c, p: p.update(consumed_nonce_sha256=(d("6"),)))

    def test_50_reused_ubuntu_log(self):
        self.reject(lambda c, p: p.update(seen_log_sha256=(LOGS[0],)))

    def test_51_reused_windows_log(self):
        self.reject(lambda c, p: p.update(seen_log_sha256=(LOGS[1],)))

    def test_52_reused_proposal_root(self):
        self.reject(lambda c, p: p.update(seen_proposal_sha256=(d("2"),)))

    def test_53_unsorted_key_history(self):
        self.reject(lambda c, p: p.update(revoked_key_fingerprints=(d("f"), d("a"))))

    def test_54_duplicate_nonce_history(self):
        self.reject(lambda c, p: p.update(consumed_nonce_sha256=(d("6"), d("6"))))

    def test_55_history_list_not_tuple(self):
        self.reject(lambda c, p: p.update(seen_log_sha256=[LOGS[0]]))

    def test_56_cloned_issuer(self):
        self.reject(lambda c, p: c.update(issuer_ids=(ACTORS[0], ACTORS[0], ACTORS[2])))

    def test_57_cloned_key(self):
        self.reject(lambda c, p: c.update(key_fingerprints=(KEYS[0], KEYS[0], KEYS[2])))

    def test_58_wrong_issuer_pin(self):
        self.reject(lambda c, p: p.update(issuer_ids=(ACTORS[0], "other", ACTORS[2])))

    def test_59_wrong_key_pin(self):
        self.reject(lambda c, p: p.update(key_fingerprints=(KEYS[0], d("f"), KEYS[2])))

    def test_60_missing_approval(self):
        self.reject(lambda c, p: c.update(approval_claims=c["approval_claims"][:2]))

    def test_61_list_approval(self):
        self.reject(lambda c, p: c.update(approval_claims=list(c["approval_claims"])))

    def test_62_wrong_approval_role(self):
        self.reject(lambda c, p: c.update(approval_claims=(("owner", *c["approval_claims"][0][1:]), ("owner", *c["approval_claims"][1][1:]), c["approval_claims"][2])))

    def test_63_wrong_signature_claim(self):
        self.reject(lambda c, p: c.update(approval_claims=(c["approval_claims"][0], ("independent_reviewer", ACTORS[1], KEYS[1], d("f"), "NOT_VERIFIED"), c["approval_claims"][2])))

    def test_64_false_signed_approval(self):
        self.reject(lambda c, p: c.update(approval_claims=(c["approval_claims"][0], ("independent_reviewer", ACTORS[1], KEYS[1], c["approval_claims"][1][3], "SIGNED"), c["approval_claims"][2])))

    def test_65_false_revocation_history_type(self):
        self.reject(lambda c, p: p.update(retired_authority_roots="fake"))


if __name__ == "__main__":
    unittest.main()
