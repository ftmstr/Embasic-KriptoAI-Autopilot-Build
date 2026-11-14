"""RC678 invented-only full-history, revocation and provider-fork regressions."""
import copy
import unittest

from safe_public_ci.ci_append_only_receipt_gate import (
    AppendOnlyClaimRejected, history_root_sha256,
    claim_leaf_sha256, quarantine_append_only_claim,
)


def d(char):
    return char * 64


KEYS = (d("b"), d("c"), d("d"))
ROLES = ("owner", "independent_reviewer", "incumbent_custodian")


def fixture():
    claim = {
        "repository": "ftmstr/Embasic-KriptoAI-Autopilot-Build",
        "branch": "validation/rc654-pr1-rc653-combined-ci",
        "git_sha": "a" * 40,
        "source_sha256": d("1"), "workflow_sha256": d("2"),
        "roster_sha256": d("3"), "authority_root_sha256": d("4"),
        "authority_epoch": 5, "nonce_sha256": d("5"),
        "issued_at": 100, "observed_at": 120,
        "prior_generation": 7, "next_generation": 8,
        "prior_history": (d("6"),), "next_history": (),
        "prior_root_sha256": "", "next_root_sha256": "",
        "writer_views": (), "provider_views": (), "reviewer_views": (),
        "revocations_before": ((d("a"), 90),),
        "revocations_after": ((d("a"), 90), (d("f"), 140)),
        "ack_state": "NOT_SENT", "release_ready": False,
        "live_trading_allowed": False,
    }
    leaf = claim_leaf_sha256(claim)
    claim["next_history"] = (*claim["prior_history"], leaf)
    claim["prior_root_sha256"] = history_root_sha256(claim["prior_history"])
    claim["next_root_sha256"] = history_root_sha256(claim["next_history"])
    claim["writer_views"] = (
        ("writer_a", 7, claim["prior_root_sha256"], "CLAIMED_WIN"),
        ("writer_b", 7, claim["prior_root_sha256"], "CLAIMED_CONFLICT"),
    )
    claim["provider_views"] = (
        ("ubuntu", 300, 400, "a" * 40, 8, claim["next_root_sha256"], 110, "NOT_VERIFIED"),
        ("windows", 301, 401, "a" * 40, 8, claim["next_root_sha256"], 112, "NOT_VERIFIED"),
    )
    claim["reviewer_views"] = tuple(
        (role, actor, key, 80, 160, 103 + i, "NOT_VERIFIED")
        for i, (role, actor, key) in enumerate(zip(
            ROLES, ("owner_a", "reviewer_b", "custodian_c"), KEYS))
    )
    pinned = {k: claim[k] for k in (
        "git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
        "authority_root_sha256", "authority_epoch", "prior_generation",
        "prior_root_sha256", "next_root_sha256",
    )}
    pinned.update(expected_leaf_sha256=leaf, reviewer_keys=KEYS,
                  seen_nonce_sha256=(), seen_history_roots=())
    return claim, pinned


def row_mutate(claim, field, i, index, value):
    items = list(claim[field])
    row = list(items[i])
    row[index] = value
    items[i] = tuple(row)
    claim[field] = tuple(items)


class RC678ClaimedHistoryTests(unittest.TestCase):
    def fails(self, mutate):
        c, p = fixture()
        mutate(c, p)
        with self.assertRaises(AppendOnlyClaimRejected):
            quarantine_append_only_claim(c, pinned=p)

    def test_01_normal_but_unverified(self):
        c, p = fixture()
        r = quarantine_append_only_claim(c, pinned=p)
        self.assertEqual(r["status"], "APPEND_ONLY_CLAIM_QUARANTINED_NOT_AUTHENTICATED")
        for k in ("trusted_anchor_verified", "signatures_verified",
                  "clock_verified", "provider_origin_verified",
                  "atomic_cas_verified", "durable_write_verified",
                  "release_ready", "live_trading_allowed"):
            self.assertIs(r[k], False)

    def test_02_full_history_root_deterministic(self):
        c, _ = fixture()
        self.assertEqual(history_root_sha256(c["prior_history"]), c["prior_root_sha256"])

    def test_03_append_changes_root(self):
        c, _ = fixture()
        self.assertNotEqual(c["prior_root_sha256"], c["next_root_sha256"])

    def test_04_reordering_history_changes_commitment(self):
        a = (d("1"), d("2"))
        self.assertNotEqual(history_root_sha256(a), history_root_sha256(tuple(reversed(a))))

    def test_05_leaf_changes_with_source(self):
        c, _ = fixture()
        leaf = claim_leaf_sha256(c)
        c["source_sha256"] = d("e")
        self.assertNotEqual(leaf, claim_leaf_sha256(c))

    def test_06_lost_ack_always_unresolved(self):
        c, p = fixture()
        c["ack_state"] = "ACK_LOST_UNRESOLVED"
        leaf = claim_leaf_sha256(c)
        c["next_history"] = (*c["prior_history"], leaf)
        c["next_root_sha256"] = history_root_sha256(c["next_history"])
        for i in range(2):
            row_mutate(c, "provider_views", i, 5, c["next_root_sha256"])
        p["expected_leaf_sha256"] = leaf
        p["next_root_sha256"] = c["next_root_sha256"]
        r = quarantine_append_only_claim(c, pinned=p)
        self.assertTrue(r["lost_ack_unresolved"])
        self.assertFalse(r["durable_write_verified"])

    def test_07_repeat_calls_do_not_consume_receipt(self):
        c, p = fixture()
        self.assertEqual(quarantine_append_only_claim(c, pinned=p),
                         quarantine_append_only_claim(c, pinned=p))

    def test_08_attacker_can_repin_forged_source_but_cannot_authorize(self):
        c, p = fixture()
        c["source_sha256"] = p["source_sha256"] = d("e")
        leaf = claim_leaf_sha256(c)
        c["next_history"] = (*c["prior_history"], leaf)
        c["next_root_sha256"] = history_root_sha256(c["next_history"])
        for i in range(2):
            row_mutate(c, "provider_views", i, 5, c["next_root_sha256"])
        p["expected_leaf_sha256"] = leaf
        p["next_root_sha256"] = c["next_root_sha256"]
        r = quarantine_append_only_claim(c, pinned=p)
        self.assertFalse(r["trusted_anchor_verified"])
        self.assertFalse(r["atomic_cas_verified"])

    def test_09_future_revocation_does_not_authorize(self):
        c, p = fixture()
        c["revocations_after"] = (*c["revocations_after"], (KEYS[0], 140))
        c["revocations_after"] = tuple(sorted(c["revocations_after"]))
        self.assertFalse(quarantine_append_only_claim(c, pinned=p)["signatures_verified"])

    def test_10_prior_revocation_monotonic(self):
        c, p = fixture()
        self.assertTrue(set(c["revocations_before"]).issubset(c["revocations_after"]))
        self.assertFalse(quarantine_append_only_claim(c, pinned=p)["clock_verified"])

    def test_11_missing_history_rejected(self):
        self.fails(lambda c, p: c.update(prior_history="not-a-history"))

    def test_12_duplicate_history_leaf_rejected(self):
        self.fails(lambda c, p: c.update(prior_history=(d("6"), d("6"))))


CASES = (
    ("foreign_repo", lambda c,p: c.update(repository="ftmstr/Private")),
    ("main_branch", lambda c,p: c.update(branch="main")),
    ("invalid_git", lambda c,p: c.update(git_sha="g" * 40)),
    ("wrong_git_pin", lambda c,p: p.update(git_sha="b" * 40)),
    ("wrong_source_pin", lambda c,p: p.update(source_sha256=d("f"))),
    ("wrong_workflow_pin", lambda c,p: p.update(workflow_sha256=d("f"))),
    ("wrong_roster_pin", lambda c,p: p.update(roster_sha256=d("f"))),
    ("wrong_authority_pin", lambda c,p: p.update(authority_root_sha256=d("f"))),
    ("wrong_epoch_pin", lambda c,p: p.update(authority_epoch=6)),
    ("boolean_epoch", lambda c,p: c.update(authority_epoch=True)),
    ("wrong_prior_generation_pin", lambda c,p: p.update(prior_generation=8)),
    ("generation_skipped", lambda c,p: c.update(next_generation=9)),
    ("generation_rollback", lambda c,p: c.update(next_generation=6)),
    ("boolean_generation", lambda c,p: c.update(prior_generation=True)),
    ("observed_before_issue", lambda c,p: c.update(observed_at=99)),
    ("boolean_issue_time", lambda c,p: c.update(issued_at=True)),
    ("fake_ack_applied", lambda c,p: c.update(ack_state="ACK_APPLIED")),
    ("live_flag", lambda c,p: c.update(live_trading_allowed=True)),
    ("release_flag", lambda c,p: c.update(release_ready=True)),
    ("extra_claim_metadata", lambda c,p: c.update(signed=True)),
    ("missing_pin", lambda c,p: p.pop("expected_leaf_sha256")),
    ("relabel_leaf_pin", lambda c,p: p.update(expected_leaf_sha256=d("f"))),
    ("stale_prior_root", lambda c,p: p.update(prior_root_sha256=d("f"))),
    ("forged_next_root", lambda c,p: p.update(next_root_sha256=d("f"))),
    ("empty_next_history", lambda c,p: c.update(next_history=())),
    ("next_history_wrong_predecessor", lambda c,p: c.update(next_history=(d("f"), c["next_history"][-1]))),
    ("next_history_wrong_leaf", lambda c,p: c.update(next_history=(d("6"), d("f")))),
    ("next_history_duplicate", lambda c,p: c.update(next_history=(d("6"), d("6")))),
    ("phantom_extra_append", lambda c,p: c.update(next_history=(*c["next_history"], d("f")))),
    ("replayed_nonce", lambda c,p: p.update(seen_nonce_sha256=(d("5"),))),
    ("replayed_root", lambda c,p: p.update(seen_history_roots=(c["next_root_sha256"],))),
    ("noncanonical_nonce_history", lambda c,p: p.update(seen_nonce_sha256=(d("f"), d("a")))),
    ("nonce_history_list", lambda c,p: p.update(seen_nonce_sha256=[d("f")])),
    ("double_claimed_winner", lambda c,p: row_mutate(c,"writer_views",1,3,"CLAIMED_WIN")),
    ("double_claimed_conflict", lambda c,p: row_mutate(c,"writer_views",0,3,"CLAIMED_CONFLICT")),
    ("writer_root_conflict", lambda c,p: row_mutate(c,"writer_views",1,2,d("f"))),
    ("writer_old_generation", lambda c,p: row_mutate(c,"writer_views",0,1,6)),
    ("writer_duplicate_actor", lambda c,p: row_mutate(c,"writer_views",1,0,"writer_a")),
    ("provider_root_fork", lambda c,p: row_mutate(c,"provider_views",1,5,d("f"))),
    ("provider_git_rebind", lambda c,p: row_mutate(c,"provider_views",0,3,"b" * 40)),
    ("provider_bad_generation", lambda c,p: row_mutate(c,"provider_views",0,4,7)),
    ("provider_wrong_os", lambda c,p: row_mutate(c,"provider_views",1,0,"ubuntu")),
    ("provider_duplicate_run", lambda c,p: row_mutate(c,"provider_views",1,1,300)),
    ("provider_duplicate_job", lambda c,p: row_mutate(c,"provider_views",1,2,400)),
    ("provider_too_early", lambda c,p: row_mutate(c,"provider_views",0,6,99)),
    ("provider_fake_verified", lambda c,p: row_mutate(c,"provider_views",1,7,"SIGNED")),
    ("reviewer_duplicate_actor", lambda c,p: row_mutate(c,"reviewer_views",1,1,"owner_a")),
    ("reviewer_duplicate_key", lambda c,p: row_mutate(c,"reviewer_views",1,2,KEYS[0])),
    ("reviewer_foreign_key", lambda c,p: p.update(reviewer_keys=(KEYS[0], d("f"), KEYS[2]))),
    ("reviewer_wrong_role", lambda c,p: row_mutate(c,"reviewer_views",1,0,"owner")),
    ("reviewer_expired", lambda c,p: row_mutate(c,"reviewer_views",0,4,100)),
    ("reviewer_not_yet_valid", lambda c,p: row_mutate(c,"reviewer_views",2,3,110)),
    ("reviewer_fake_signed", lambda c,p: row_mutate(c,"reviewer_views",0,6,"VERIFIED")),
    ("revocation_rollback", lambda c,p: c.update(revocations_after=())),
    ("revoked_owner", lambda c,p: c.update(revocations_after=tuple(sorted((*c["revocations_after"], (KEYS[0], 112)))))),
    ("revoked_reviewer", lambda c,p: c.update(revocations_after=tuple(sorted((*c["revocations_after"], (KEYS[1], 112)))))),
    ("revoked_custodian", lambda c,p: c.update(revocations_after=tuple(sorted((*c["revocations_after"], (KEYS[2], 112)))))),
    ("revocation_unsorted", lambda c,p: c.update(revocations_after=tuple(reversed(c["revocations_after"])))),
    ("revocation_history_list", lambda c,p: c.update(revocations_after=list(c["revocations_after"]))),
)


def _make_test(mutator):
    def check(self):
        self.fails(mutator)
    return check


for n, (name, mutator) in enumerate(CASES, start=13):
    setattr(RC678ClaimedHistoryTests, "test_%02d_%s" % (n, name), _make_test(mutator))


if __name__ == "__main__":
    unittest.main()
