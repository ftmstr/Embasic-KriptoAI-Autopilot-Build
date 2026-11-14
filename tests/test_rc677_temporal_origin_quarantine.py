"""RC677 invented chronology, issuer, clock and CAS adversarial regressions."""
import copy
import unittest
from safe_public_ci.ci_temporal_origin_quarantine import (
    TemporalOriginRejected, temporal_claim_sha256, quarantine_temporal_origin,
)


def h(ch):
    return ch * 64


IDS = ("owner_alice", "reviewer_bob", "custodian_cara")
KEYS = (h("a"), h("b"), h("c"))
LOGS = (h("7"), h("8"))
ROLES = ("owner", "independent_reviewer", "incumbent_custodian")


def fixture():
    c = {
        "repository": "ftmstr/Embasic-KriptoAI-Autopilot-Build",
        "branch": "validation/rc654-pr1-rc653-combined-ci",
        "git_sha": "a" * 40,
        "source_sha256": h("3"), "workflow_sha256": h("4"),
        "roster_sha256": h("5"), "authority_epoch": 3,
        "authority_root_sha256": h("6"), "before_generation": 9,
        "before_root_sha256": h("1"), "after_generation": 10,
        "after_root_sha256": h("2"), "issued_at": 100,
        "observed_at": 120, "nonce_sha256": h("9"),
        "log_sha256": LOGS,
        "writers": (("writer_alice", 9, h("1"), h("9"), "CLAIMED_WIN"),
                    ("writer_bob", 9, h("1"), h("9"), "CLAIMED_CONFLICT")),
        "witnesses": tuple((role, actor, key, 80, 160, 101 + i, "NOT_VERIFIED")
                           for i, (role, actor, key) in enumerate(zip(ROLES, IDS, KEYS))),
        "providers": (("ubuntu", 300, 400, "a" * 40, LOGS[0], 10, h("2"), 110, "NOT_VERIFIED"),
                      ("windows", 301, 401, "a" * 40, LOGS[1], 10, h("2"), 111, "NOT_VERIFIED")),
        "ack_state": "ACK_CLAIMED", "release_ready": False,
        "live_trading_allowed": False,
    }
    p = {k: c[k] for k in ("git_sha", "source_sha256", "workflow_sha256",
                             "roster_sha256", "authority_epoch", "authority_root_sha256",
                             "before_generation", "before_root_sha256",
                             "after_root_sha256", "nonce_sha256", "log_sha256")}
    p.update(witness_keys=KEYS, revocation_history=(), spent_nonces=(),
             seen_logs=(), seen_roots=(), expected_claim_sha256=temporal_claim_sha256(c))
    return c, p


def alter_row(c, name, i, field, value):
    seq = list(c[name])
    row = list(seq[i])
    row[field] = value
    seq[i] = tuple(row)
    c[name] = tuple(seq)


class RC677TemporalOriginAdversaries(unittest.TestCase):
    def reject(self, mutate):
        c, p = fixture()
        mutate(c, p)
        try:
            p["expected_claim_sha256"] = temporal_claim_sha256(c)
        except TemporalOriginRejected:
            pass
        with self.assertRaises(TemporalOriginRejected):
            quarantine_temporal_origin(c, pinned=p)

    def test_01_consistent_claim_remains_unverified(self):
        c, p = fixture()
        r = quarantine_temporal_origin(c, pinned=p)
        self.assertEqual(r["status"], "TEMPORAL_PROVIDER_CLAIMS_QUARANTINED_NOT_AUTHENTICATED")
        for field in ("authenticated_signatures", "authenticated_clock",
                      "provider_origin_verified", "atomic_cas_verified",
                      "durable_receipts_consumed", "release_ready", "live_trading_allowed"):
            self.assertIs(r[field], False)

    def test_02_claim_digest_deterministic(self):
        c, _ = fixture()
        self.assertEqual(temporal_claim_sha256(c), temporal_claim_sha256(copy.deepcopy(c)))

    def test_03_provider_order_changes_digest(self):
        c, _ = fixture()
        before = temporal_claim_sha256(c)
        c["providers"] = tuple(reversed(c["providers"]))
        with self.assertRaises(TemporalOriginRejected):
            temporal_claim_sha256(c)
        self.assertEqual(before, temporal_claim_sha256(fixture()[0]))

    def test_04_lost_ack_cannot_certify_cas(self):
        c, p = fixture()
        c["ack_state"] = "ACK_LOST_UNRESOLVED"
        p["expected_claim_sha256"] = temporal_claim_sha256(c)
        r = quarantine_temporal_origin(c, pinned=p)
        self.assertTrue(r["lost_ack_unresolved"])
        self.assertFalse(r["atomic_cas_verified"])

    def test_05_parallel_pure_calls_are_not_atomic(self):
        c, p = fixture()
        self.assertEqual(quarantine_temporal_origin(c, pinned=p),
                         quarantine_temporal_origin(c, pinned=p))
        self.assertFalse(quarantine_temporal_origin(c, pinned=p)["durable_receipts_consumed"])

    def test_06_attacker_matching_source_pin_not_authentic(self):
        c, p = fixture()
        c["source_sha256"] = h("e")
        p["source_sha256"] = h("e")
        p["expected_claim_sha256"] = temporal_claim_sha256(c)
        self.assertFalse(quarantine_temporal_origin(c, pinned=p)["provider_origin_verified"])

    def test_07_future_key_revocation_cannot_authenticate(self):
        c, p = fixture()
        p["revocation_history"] = ((KEYS[0], 121),)
        r = quarantine_temporal_origin(c, pinned=p)
        self.assertFalse(r["authenticated_signatures"])

    def test_08_expired_claim_cannot_be_signed_later(self):
        self.reject(lambda c, p: alter_row(c, "witnesses", 0, 5, 121))

    def test_09_claim_digest_binds_clock(self):
        c, _ = fixture()
        before = temporal_claim_sha256(c)
        c["observed_at"] = 121
        self.assertNotEqual(before, temporal_claim_sha256(c))

    def test_10_readback_digest_binds_run_id(self):
        c, _ = fixture()
        before = temporal_claim_sha256(c)
        alter_row(c, "providers", 0, 1, 305)
        self.assertNotEqual(before, temporal_claim_sha256(c))


CASES = (
    ("foreign_repo", lambda c, p: c.update(repository="ftmstr/Private")),
    ("main_branch", lambda c, p: c.update(branch="main")),
    ("bad_git_sha", lambda c, p: c.update(git_sha="z" * 40)),
    ("wrong_git_pin", lambda c, p: p.update(git_sha="b" * 40)),
    ("wrong_source_pin", lambda c, p: p.update(source_sha256=h("f"))),
    ("wrong_workflow_pin", lambda c, p: p.update(workflow_sha256=h("f"))),
    ("wrong_roster_pin", lambda c, p: p.update(roster_sha256=h("f"))),
    ("wrong_authority_root_pin", lambda c, p: p.update(authority_root_sha256=h("f"))),
    ("wrong_authority_epoch_pin", lambda c, p: p.update(authority_epoch=4)),
    ("boolean_authority_epoch", lambda c, p: c.update(authority_epoch=True)),
    ("wrong_generation_pin", lambda c, p: p.update(before_generation=10)),
    ("generation_jump", lambda c, p: c.update(after_generation=11)),
    ("generation_rollback", lambda c, p: c.update(after_generation=8)),
    ("aba_same_root", lambda c, p: c.update(after_root_sha256=h("1"))),
    ("wrong_old_root_pin", lambda c, p: p.update(before_root_sha256=h("f"))),
    ("wrong_new_root_pin", lambda c, p: p.update(after_root_sha256=h("f"))),
    ("issued_after_observed", lambda c, p: c.update(issued_at=121)),
    ("boolean_issued_time", lambda c, p: c.update(issued_at=True)),
    ("zero_observed_time", lambda c, p: c.update(observed_at=0)),
    ("expired_signer", lambda c, p: alter_row(c, "witnesses", 1, 4, 101)),
    ("signer_before_issue", lambda c, p: alter_row(c, "witnesses", 0, 5, 99)),
    ("signer_after_observation", lambda c, p: alter_row(c, "witnesses", 1, 5, 121)),
    ("signer_boolean_timestamp", lambda c, p: alter_row(c, "witnesses", 0, 5, True)),
    ("signer_future_valid_from", lambda c, p: alter_row(c, "witnesses", 2, 3, 110)),
    ("signer_malformed_key", lambda c, p: alter_row(c, "witnesses", 2, 2, "fake")),
    ("signer_duplicate_actor", lambda c, p: alter_row(c, "witnesses", 1, 1, IDS[0])),
    ("signer_duplicate_key", lambda c, p: alter_row(c, "witnesses", 1, 2, KEYS[0])),
    ("signer_wrong_role", lambda c, p: alter_row(c, "witnesses", 1, 0, "owner")),
    ("fake_signed_witness", lambda c, p: alter_row(c, "witnesses", 0, 6, "VERIFIED")),
    ("revoked_owner_at_observation", lambda c, p: p.update(revocation_history=((KEYS[0], 120),))),
    ("revoked_reviewer_prior", lambda c, p: p.update(revocation_history=((KEYS[1], 101),))),
    ("revoked_custodian_prior", lambda c, p: p.update(revocation_history=((KEYS[2], 100),))),
    ("duplicate_revocation_key", lambda c, p: p.update(revocation_history=((KEYS[0], 101), (KEYS[0], 102)))),
    ("revocation_unsorted", lambda c, p: p.update(revocation_history=((KEYS[1], 101), (KEYS[0], 102)))),
    ("revocation_bool_time", lambda c, p: p.update(revocation_history=((KEYS[0], True),))),
    ("revocation_history_list", lambda c, p: p.update(revocation_history=[(KEYS[0], 101)])),
    ("consumed_nonce", lambda c, p: p.update(spent_nonces=(c["nonce_sha256"],))),
    ("reused_ubuntu_log", lambda c, p: p.update(seen_logs=(LOGS[0],))),
    ("reused_windows_log", lambda c, p: p.update(seen_logs=(LOGS[1],))),
    ("reused_authority_root", lambda c, p: p.update(seen_roots=(c["authority_root_sha256"],))),
    ("reused_checkpoint_root", lambda c, p: p.update(seen_roots=(c["after_root_sha256"],))),
    ("history_duplicate", lambda c, p: p.update(spent_nonces=(h("9"), h("9")))),
    ("history_not_tuple", lambda c, p: p.update(seen_roots=[h("f")])),
    ("duplicate_platform_logs", lambda c, p: c.update(log_sha256=(LOGS[0], LOGS[0]))),
    ("swapped_platform_logs", lambda c, p: c.update(log_sha256=tuple(reversed(LOGS)))),
    ("two_writer_wins", lambda c, p: alter_row(c, "writers", 1, 4, "CLAIMED_WIN")),
    ("two_writer_conflicts", lambda c, p: alter_row(c, "writers", 0, 4, "CLAIMED_CONFLICT")),
    ("writer_stale_generation", lambda c, p: alter_row(c, "writers", 1, 1, 8)),
    ("writer_foreign_root", lambda c, p: alter_row(c, "writers", 0, 2, h("f"))),
    ("writer_foreign_nonce", lambda c, p: alter_row(c, "writers", 1, 3, h("f"))),
    ("duplicate_writer_name", lambda c, p: alter_row(c, "writers", 1, 0, "writer_alice")),
    ("provider_wrong_os", lambda c, p: alter_row(c, "providers", 1, 0, "ubuntu")),
    ("provider_wrong_git", lambda c, p: alter_row(c, "providers", 0, 3, "b" * 40)),
    ("provider_wrong_root", lambda c, p: alter_row(c, "providers", 1, 6, h("f"))),
    ("provider_stale_generation", lambda c, p: alter_row(c, "providers", 0, 5, 9)),
    ("provider_before_issue", lambda c, p: alter_row(c, "providers", 0, 7, 99)),
    ("provider_after_observation", lambda c, p: alter_row(c, "providers", 1, 7, 121)),
    ("provider_fake_signed", lambda c, p: alter_row(c, "providers", 1, 8, "GITHUB_SIGNED")),
    ("duplicate_provider_run", lambda c, p: alter_row(c, "providers", 1, 1, 300)),
    ("duplicate_provider_job", lambda c, p: alter_row(c, "providers", 1, 2, 400)),
    ("fake_ack_applied", lambda c, p: c.update(ack_state="ACK_APPLIED")),
    ("release_flag", lambda c, p: c.update(release_ready=True)),
    ("live_flag", lambda c, p: c.update(live_trading_allowed=True)),
    ("extra_metadata", lambda c, p: c.update(signed_by="invented")),
)


def _make_case(mutator):
    def _test(self):
        self.reject(mutator)
    return _test


for number, (name, change) in enumerate(CASES, 11):
    setattr(RC677TemporalOriginAdversaries,
            "test_%02d_%s" % (number, name), _make_case(change))

if __name__ == "__main__":
    unittest.main()
