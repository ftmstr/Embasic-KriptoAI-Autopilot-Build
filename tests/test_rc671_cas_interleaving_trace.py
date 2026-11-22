"""Original invented-only RC671 CAS interleaving/adversarial trace fixtures."""
import unittest
from safe_public_ci.ci_cas_interleaving_trace import (
    InterleavingRejected, _root, verify_synthetic_cas_trace,
)

COMMIT_SHA = "a" * 40
SOURCE_SHA = "b" * 64
P = "1" * 64
U = "2" * 64
W = "3" * 64
Q = "4" * 64
X = "5" * 64
Y = "6" * 64
ZERO = _root(0, (), ())
ONE = _root(1, (P,), (U, W))
TWO = _root(2, (P, Q), (U, W, X, Y))
INITIAL = (0, ZERO, (), ())


def ev(action, worker="alice", gen=0, root=ZERO, pair=P, ubuntu=U, windows=W):
    return (action, worker, gen, root, pair, ubuntu, windows)


def one_win():
    return (ev("PREPARE"), ev("COMMIT", gen=1, root=ONE))


def check(events=None, **overrides):
    args = dict(trusted_initial_digest=ZERO, expected_git_sha=COMMIT_SHA,
                expected_source_sha256=SOURCE_SHA,
                expected_final_generation=1, trusted_final_digest=ONE)
    args.update(overrides)
    return verify_synthetic_cas_trace(INITIAL,
                                      one_win() if events is None else events, **args)


class RC671CASInterleavingAdversaries(unittest.TestCase):
    def bad(self, events=None, **overrides):
        with self.assertRaises(InterleavingRejected):
            check(events, **overrides)

    def test_01_single_claimed_winner_not_authenticated(self):
        a = check()
        self.assertEqual(a["status"], "CLAIMED_LINEARIZATION_CONSISTENT_NOT_AUTHENTICATED")
        self.assertEqual(a["claimed_wins"], 1)
        self.assertFalse(a["release_ready"])
        self.assertFalse(a["live_trading_allowed"])

    def test_02_two_prepares_one_winner_one_conflict(self):
        events = (ev("PREPARE"), ev("PREPARE", "bob"),
                  ev("COMMIT", gen=1, root=ONE),
                  ev("CONFLICT", "bob", 1, ONE))
        self.assertEqual(check(events)["claimed_wins"], 1)

    def test_03_two_prepares_both_winners_rejected(self):
        events = (ev("PREPARE"), ev("PREPARE", "bob"),
                  ev("COMMIT", gen=1, root=ONE),
                  ev("COMMIT", "bob", 1, ONE))
        self.bad(events)

    def test_04_lost_ack_matching_readback_is_only_a_claim(self):
        events = (ev("PREPARE"), ev("ACK_LOST"), ev("READBACK", gen=1, root=ONE))
        result = check(events)
        self.assertEqual(result["lost_ack_readback_claims"], 1)
        self.assertFalse(result["release_ready"])

    def test_05_lost_ack_readback_stale_rejected(self):
        self.bad((ev("PREPARE"), ev("ACK_LOST"), ev("READBACK")))

    def test_06_lost_ack_commit_without_reconcile_rejected(self):
        self.bad((ev("PREPARE"), ev("ACK_LOST"), ev("COMMIT", gen=1, root=ONE)))

    def test_07_unresolved_lost_ack_rejected(self):
        self.bad((ev("PREPARE"), ev("ACK_LOST")))

    def test_08_lost_ack_cannot_roll_back_blindly(self):
        self.bad((ev("PREPARE"), ev("ACK_LOST"), ev("ROLLBACK")))

    def test_09_lost_ack_intervening_other_winner_reconcile_fails(self):
        events = (ev("PREPARE"), ev("PREPARE", "bob"), ev("ACK_LOST"),
                  ev("COMMIT", "bob", 1, ONE), ev("READBACK", gen=1, root=ONE))
        self.bad(events)

    def test_10_lost_ack_intervening_other_winner_conflict_ok(self):
        events = (ev("PREPARE"), ev("PREPARE", "bob"), ev("ACK_LOST"),
                  ev("COMMIT", "bob", 1, ONE), ev("CONFLICT", "alice", 1, ONE))
        self.assertEqual(check(events)["claimed_wins"], 1)

    def test_11_false_conflict_with_unchanged_root_rejected(self):
        self.bad((ev("PREPARE"), ev("CONFLICT")))

    def test_12_rollback_without_commit_cannot_pass_final(self):
        self.bad((ev("PREPARE"), ev("ROLLBACK")))

    def test_13_rollback_one_worker_then_other_commit(self):
        x = (ev("PREPARE"), ev("ROLLBACK"), ev("PREPARE", "bob"),
             ev("COMMIT", "bob", 1, ONE))
        self.assertEqual(check(x)["claimed_wins"], 1)

    def test_14_rollback_then_replayed_commit_rejected(self):
        self.bad((ev("PREPARE"), ev("ROLLBACK"), ev("COMMIT", gen=1, root=ONE)))

    def test_15_same_worker_prepare_twice_rejected(self):
        self.bad((ev("PREPARE"), ev("PREPARE"), ev("COMMIT", gen=1, root=ONE)))

    def test_16_same_worker_new_after_win_rejected(self):
        self.bad(one_win() + (ev("PREPARE", gen=1, root=ONE),))

    def test_17_two_sequential_distinct_commits(self):
        events = one_win() + (ev("PREPARE", "bob", 1, ONE, Q, X, Y),
                              ev("COMMIT", "bob", 2, TWO, Q, X, Y))
        result = check(events, expected_final_generation=2, trusted_final_digest=TWO)
        self.assertEqual(result["claimed_wins"], 2)

    def test_18_aba_old_root_with_new_generation_rejected(self):
        self.bad((ev("PREPARE"), ev("COMMIT", 1, ZERO)))

    def test_19_old_generation_with_new_root_rejected(self):
        self.bad((ev("PREPARE"), ev("COMMIT", 0, ONE)))

    def test_20_old_base_after_success_new_prepare_rejected(self):
        self.bad(one_win() + (ev("PREPARE", "bob", 0, ZERO, Q, X, Y),))

    def test_21_same_pair_in_second_generation_rejected(self):
        self.bad(one_win() + (ev("PREPARE", "bob", 1, ONE, P, X, Y),))

    def test_22_same_ubuntu_log_reused_rejected(self):
        self.bad(one_win() + (ev("PREPARE", "bob", 1, ONE, Q, U, Y),))

    def test_23_same_windows_log_reused_rejected(self):
        self.bad(one_win() + (ev("PREPARE", "bob", 1, ONE, Q, X, W),))

    def test_24_same_log_for_ubuntu_and_windows_rejected(self):
        self.bad((ev("PREPARE", ubuntu=U, windows=U),))

    def test_25_modified_pair_after_prepare_rejected(self):
        self.bad((ev("PREPARE"), ev("COMMIT", gen=1, root=ONE, pair=Q)))

    def test_26_modified_log_after_prepare_rejected(self):
        self.bad((ev("PREPARE"), ev("COMMIT", gen=1, root=ONE, windows=Y)))

    def test_27_extra_duplicate_commit_rejected(self):
        self.bad(one_win() + (ev("COMMIT", gen=1, root=ONE),))

    def test_28_commit_without_prepare_rejected(self):
        self.bad((ev("COMMIT", gen=1, root=ONE),))

    def test_29_wrong_pinned_initial_digest_rejected(self):
        self.bad(trusted_initial_digest="f" * 64)

    def test_30_wrong_pinned_final_digest_rejected(self):
        self.bad(trusted_final_digest="f" * 64)

    def test_31_wrong_expected_generation_rejected(self):
        self.bad(expected_final_generation=2)

    def test_32_boolean_expected_generation_rejected(self):
        self.bad(expected_final_generation=True)

    def test_33_foreign_git_sha_shape_rejected(self):
        self.bad(expected_git_sha="g" * 40)

    def test_34_false_source_hash_shape_rejected(self):
        self.bad(expected_source_sha256="UNVERIFIED")

    def test_35_non_tuple_trace_rejected(self):
        self.bad(list(one_win()))

    def test_36_bad_empty_trace_rejected(self):
        self.bad(())

    def test_37_oversized_trace_rejected(self):
        self.bad(one_win() * 49)

    def test_38_unknown_event_kind_rejected(self):
        self.bad((ev("PREPARE"), ev("LIVE_TRADE", 1, ONE)))

    def test_39_noncanonical_worker_rejected(self):
        self.bad((ev("PREPARE", "Alice"),))

    def test_40_duplicate_worker_rejected_even_after_rollback(self):
        self.bad((ev("PREPARE"), ev("ROLLBACK"), ev("PREPARE")))

    def test_41_terminal_pending_worker_rejected(self):
        self.bad(one_win() + (ev("PREPARE", "bob", 1, ONE, Q, X, Y),))

    def test_42_boolean_event_generation_rejected(self):
        self.bad((ev("PREPARE", gen=True),))

    def test_43_malformed_event_structure_rejected(self):
        self.bad((ev("PREPARE"), ("COMMIT", "alice")))

    def test_44_bad_source_root_in_snapshot_rejected(self):
        initial = (0, "f" * 64, (), ())
        with self.assertRaises(InterleavingRejected):
            verify_synthetic_cas_trace(initial, one_win(),
                                       trusted_initial_digest=ZERO,
                                       expected_git_sha=COMMIT_SHA,
                                       expected_source_sha256=SOURCE_SHA,
                                       expected_final_generation=1,
                                       trusted_final_digest=ONE)

    def test_45_canonical_root_reproduces_rc670_expected_hash(self):
        import hashlib
        expected = hashlib.sha256(("RC670-PUBLIC-SYNTHETIC-CAS-V1\n0\nPAIRS\n0\nLOGS\n0").encode()).hexdigest()
        self.assertEqual(ZERO, expected)

    def test_46_trace_checker_never_returns_authentication(self):
        result = check(one_win())
        self.assertIn("NOT_AUTHENTICATED", result["status"])
        self.assertNotIn("provider_signature", result)


if __name__ == "__main__":
    unittest.main()
