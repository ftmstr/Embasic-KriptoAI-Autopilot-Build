"""Original invented-only RC670 CAS readback and adverse interleaving cases."""
import copy
import unittest

from safe_public_ci.ci_cas_readback_guard import (
    CasEvidenceRejected, snapshot_digest, prepare_synthetic_cas,
    check_synthetic_cas_readback,
)

GIT = "a" * 40
SOURCE = "b" * 64
PAIR = "c" * 64
U = "d" * 64
W = "e" * 64
OTHER = "f" * 64


def snap(gen=0, pairs=(), logs=()):
    return (gen, snapshot_digest(gen, pairs, logs), pairs, logs)


def prepare(base=None, **kwargs):
    s = snap() if base is None else base
    args = dict(trusted_snapshot_digest=s[1], expected_generation=s[0],
                expected_git_sha=GIT, expected_source_sha256=SOURCE,
                pair_sha256=PAIR, log_sha256=(U, W))
    args.update(kwargs)
    return prepare_synthetic_cas(s, **args)


def observed(p):
    return (p['proposed_generation'], p['proposed_snapshot_sha256'],
            p['proposed_pair_history'], p['proposed_log_history'])


def check(p=None, *, ack='ACK_APPLIED', readback=None, trusted=None):
    proposal = prepare() if p is None else p
    actual = observed(proposal) if readback is None else readback
    trusted_digest = actual[1] if trusted is None else trusted
    return check_synthetic_cas_readback(proposal, provider_ack_state=ack,
                                         observed_snapshot=actual,
                                         trusted_observed_digest=trusted_digest)


class RC670CasAdversarialTests(unittest.TestCase):
    def bad_prepare(self, base=None, **kwargs):
        with self.assertRaises(CasEvidenceRejected):
            prepare(base, **kwargs)

    def bad_check(self, p=None, **kwargs):
        with self.assertRaises(CasEvidenceRejected):
            check(p, **kwargs)

    def test_01_valid_empty_snapshot_proposal_only(self):
        p = prepare()
        self.assertEqual(p['status'], 'PROPOSED_CAS_ONLY_NOT_AUTHENTICATED')
        self.assertEqual(p['expected_generation'], 0)
        self.assertEqual(p['proposed_generation'], 1)
        self.assertFalse(p['release_ready'])

    def test_02_matching_ack_requires_readback_but_not_authenticated(self):
        x = check()
        self.assertEqual(x['status'], 'ACK_READBACK_CONSISTENT_NOT_AUTHENTICATED')
        self.assertFalse(x['live_trading_allowed'])

    def test_03_lost_ack_matching_readback_is_not_certified(self):
        x = check(ack='ACK_LOST')
        self.assertEqual(x['status'], 'LOST_ACK_READBACK_CONSISTENT_NOT_AUTHENTICATED')
        self.assertFalse(x['release_ready'])

    def test_04_missing_ack_stale_readback_rejected(self):
        self.bad_check(ack='ACK_LOST', readback=snap())

    def test_05_ack_applied_stale_readback_rejected(self):
        self.bad_check(readback=snap())

    def test_06_ack_conflict_rejected_despite_matching_readback(self):
        self.bad_check(ack='CONFLICT')

    def test_07_not_sent_rejected_despite_matching_readback(self):
        self.bad_check(ack='NOT_SENT')

    def test_08_unknown_ack_rejected(self):
        self.bad_check(ack='ACK_TIMEOUT_IGNORED')

    def test_09_boolean_ack_rejected(self):
        self.bad_check(ack=True)

    def test_10_false_generation_rejected(self):
        self.bad_prepare((True, snap()[1], (), ()))

    def test_11_negative_generation_rejected(self):
        self.bad_prepare((-1, 'f'*64, (), ()))

    def test_12_external_anchor_mismatch_rejected(self):
        self.bad_prepare(trusted_snapshot_digest='f'*64)

    def test_13_external_expected_generation_mismatch(self):
        self.bad_prepare(expected_generation=3)

    def test_14_wrong_git_sha_rejected(self):
        self.bad_prepare(expected_git_sha='z'*40)

    def test_15_source_digest_bad_shape_rejected(self):
        self.bad_prepare(expected_source_sha256='BAD_SHA')

    def test_16_source_digest_changes_are_visible_in_proposal(self):
        self.assertNotEqual(prepare()['expected_source_sha256'],
                            prepare(expected_source_sha256=OTHER)['expected_source_sha256'])

    def test_17_reused_pair_is_rejected(self):
        self.bad_prepare(snap(1, (PAIR,), ()))

    def test_18_reused_ubuntu_log_is_rejected(self):
        self.bad_prepare(snap(1, (), (U,)))

    def test_19_reused_windows_log_is_rejected(self):
        self.bad_prepare(snap(1, (), (W,)))

    def test_20_identical_ubuntu_windows_log_rejected(self):
        self.bad_prepare(log_sha256=(U, U))

    def test_21_log_digest_invalid_rejected(self):
        self.bad_prepare(log_sha256=(U, 'z'*64))

    def test_22_swapped_log_tuple_changes_proposal_identity(self):
        a = prepare()
        b = prepare(log_sha256=(W, U))
        self.assertEqual(a['proposed_snapshot_sha256'], b['proposed_snapshot_sha256'])
        self.assertNotEqual(a['log_sha256'], b['log_sha256'])
        self.assertEqual(a['proposed_log_history'], b['proposed_log_history'])

    def test_23_parallel_workers_on_same_snapshot_not_mutating_snapshot(self):
        before = snap()
        a = prepare(before)
        b = prepare(before)
        self.assertEqual(a['proposed_snapshot_sha256'], b['proposed_snapshot_sha256'])
        self.assertEqual(before, snap())
        self.assertNotEqual(a['status'], 'COMMITTED')

    def test_24_second_prepare_after_external_consumption_rejected(self):
        p = prepare()
        self.bad_prepare(observed(p))

    def test_25_older_snapshot_can_reprepare_showing_external_cas_needed(self):
        old = snap()
        p = prepare(old)
        self.assertEqual(prepare(old)['proposed_snapshot_sha256'], p['proposed_snapshot_sha256'])
        self.assertFalse(p['release_ready'])

    def test_26_wrong_observed_generation_rejected(self):
        p = prepare()
        self.bad_check(p, readback=snap(3, (PAIR,), (U, W)))

    def test_27_untrusted_observed_root_rejected(self):
        self.bad_check(trusted=OTHER)

    def test_28_foreign_observed_log_history_rejected(self):
        p = prepare()
        r = snap(1, (PAIR,), (U, OTHER))
        self.bad_check(p, readback=r)

    def test_29_foreign_observed_pair_history_rejected(self):
        p = prepare()
        r = snap(1, (OTHER,), (U, W))
        self.bad_check(p, readback=r)

    def test_30_tampered_observed_digest_rejected(self):
        p = prepare()
        bad = (1, OTHER, (PAIR,), (U, W))
        self.bad_check(p, readback=bad)

    def test_31_unsorted_history_rejected(self):
        self.bad_prepare((1, OTHER, (), (W, U)))

    def test_32_duplicate_history_rejected(self):
        self.bad_prepare((1, OTHER, (PAIR, PAIR), ()))

    def test_33_wrong_proposal_status_rejected(self):
        p = prepare()
        p['status'] = 'SIGNED_GITHUB_RECEIPT'
        self.bad_check(p)

    def test_34_proposal_release_ready_true_rejected(self):
        p = prepare()
        p['release_ready'] = True
        self.bad_check(p)

    def test_35_proposal_live_trading_enabled_rejected(self):
        p = prepare()
        p['live_trading_allowed'] = True
        self.bad_check(p)

    def test_36_proposal_extra_metadata_rejected(self):
        p = prepare()
        p['secret_provider_key'] = 'synthetic'
        self.bad_check(p)

    def test_37_proposed_root_mutation_rejected(self):
        p = prepare()
        p['proposed_snapshot_sha256'] = OTHER
        self.bad_check(p)

    def test_38_wrong_pinned_git_sha_in_proposal_rejected(self):
        p = prepare()
        p['expected_git_sha'] = 'Z'*40
        self.bad_check(p)

    def test_39_wrong_pinned_source_digest_in_proposal_rejected(self):
        p = prepare()
        p['expected_source_sha256'] = 'BAD'
        self.bad_check(p)

    def test_40_altered_proposed_pair_history_rejected(self):
        p = prepare()
        p['proposed_pair_history'] = (OTHER,)
        self.bad_check(p)

    def test_41_altered_proposed_log_history_rejected(self):
        p = prepare()
        p['proposed_log_history'] = (OTHER,)
        self.bad_check(p)

    def test_42_wrong_proposal_generation_rejected(self):
        p = prepare()
        p['proposed_generation'] = 3
        self.bad_check(p)

    def test_43_proposal_is_new_object_each_call(self):
        x = prepare()
        y = prepare()
        self.assertIsNot(x, y)
        self.assertEqual(x, y)

    def test_44_ack_lost_without_authoritative_readback_is_no_go(self):
        self.bad_check(ack='ACK_LOST', readback=(0, snap()[1], (), ()))

    def test_45_oversized_pair_history_rejected(self):
        pairs = tuple(f'{i:064x}' for i in range(1024))
        with self.assertRaises(CasEvidenceRejected):
            snap(1, pairs, ())

    def test_46_oversized_log_history_rejected(self):
        logs = tuple(f'{i:064x}' for i in range(1023))
        with self.assertRaises(CasEvidenceRejected):
            snap(1, (), logs)

    def test_47_non_tuple_snapshot_rejected(self):
        self.bad_prepare(list(snap()))

    def test_48_non_tuple_history_rejected(self):
        self.bad_prepare((0, snap()[1], [], ()))

    def test_49_readback_does_not_claim_durable_or_authoritative(self):
        self.assertNotIn('COMMITTED', check(ack='ACK_LOST')['status'])

    def test_50_duplicate_ack_cannot_turn_proposal_into_release(self):
        p = prepare()
        a = check(p)
        b = check(p)
        self.assertEqual(a, b)
        self.assertFalse(b['release_ready'])


if __name__ == '__main__':
    unittest.main()
