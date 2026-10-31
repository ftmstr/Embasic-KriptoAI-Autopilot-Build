"""RC653: deterministic synthetic-only journal receipt boundary checks."""
from dataclasses import replace
import unittest

from safe_public_ci.offline_spot_ledger import (
    LedgerRejected, SyntheticLedgerPolicy, SyntheticSpotLedger,
)


class SyntheticReceiptBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.policy = SyntheticLedgerPolicy()
        self.ledger = SyntheticSpotLedger(self.policy)
        self.snapshot = self.ledger.balances()

    def replay(self, entries=None, expected_digest=None, expected_count=None, policy=None):
        if entries is None:
            entries = tuple(self.ledger.journal)
        if expected_digest is None:
            expected_digest = self.snapshot.journal_digest
        if expected_count is None:
            expected_count = self.snapshot.journal_count
        return SyntheticSpotLedger.replay(
            self.policy if policy is None else policy,
            entries, expected_digest=expected_digest,
            expected_count=expected_count,
        )

    def test_empty_journal_replays_deterministically(self):
        self.assertEqual(self.replay().balances(), self.snapshot)

    def test_empty_journal_has_zero_receipts(self):
        self.assertEqual(self.snapshot.journal_count, 0)

    def test_genesis_digest_has_64_hex_characters(self):
        self.assertEqual(len(self.snapshot.journal_digest), 64)

    def test_wrong_external_digest_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(expected_digest="0" * 64)

    def test_invalid_external_digest_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(expected_digest="invalid")

    def test_missing_expected_count_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(expected_count=1)

    def test_negative_expected_count_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(expected_count=-1)

    def test_boolean_expected_count_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(expected_count=True)

    def test_list_entries_not_accepted(self):
        with self.assertRaises(LedgerRejected):
            self.replay(entries=[])

    def test_wrong_genesis_policy_rejected(self):
        changed = replace(self.policy, fee_bps=self.policy.fee_bps + 1)
        with self.assertRaises(LedgerRejected):
            self.replay(policy=changed)

    def test_both_balances_are_synthetic(self):
        self.assertEqual(self.snapshot.quote_total, self.policy.quote_initial)
        self.assertEqual(self.snapshot.base_total, self.policy.base_initial)

    def test_no_live_permission(self):
        self.assertFalse(self.snapshot.live_trading_allowed)

    def test_not_a_production_ledger(self):
        self.assertFalse(self.snapshot.production_ledger)

    def test_no_financial_evaluation(self):
        self.assertFalse(self.snapshot.financial_performance_evaluated)


if __name__ == "__main__":
    unittest.main()
