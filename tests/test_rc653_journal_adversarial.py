"""Extra RC653 replay integrity tests on wholly invented, in-memory journals."""
from dataclasses import replace
import json
import unittest

from safe_public_ci.offline_order_fsm import (
    SyntheticOrderIntent, SyntheticOrderEvent, deterministic_client_id,
)
from safe_public_ci.offline_spot_ledger import (
    LedgerRejected, SyntheticExecution, SyntheticLedgerPolicy,
    SyntheticSpotIntent, SyntheticSpotLedger,
)


class SyntheticJournalAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.policy = SyntheticLedgerPolicy(
            quote_initial=10000, base_initial=10, fee_bps=100, max_notional=5000)
        self.ledger = SyntheticSpotLedger(self.policy)
        order = SyntheticOrderIntent(
            deterministic_client_id("SYN-SEED-RC653", 1), 4, 1000, 995)
        self.request = SyntheticSpotIntent(order, "BUY", 100)
        self.ledger.submit(self.request, as_of_ms=1000)
        ack = SyntheticOrderEvent("SIM-EVT-001", 1, "ACK", 1010, 1011)
        self.ledger.apply(SyntheticExecution(order.client_id, ack), as_of_ms=5000)
        fill = SyntheticOrderEvent("SIM-EVT-002", 2, "FILL", 1020, 1021,
                                   filled_increment=2)
        self.ledger.apply(SyntheticExecution(order.client_id, fill, 95), as_of_ms=5000)
        self.entries = tuple(self.ledger.journal)
        self.snapshot = self.ledger.balances()

    def replay(self, entries=None, *, expected_digest=None, expected_count=None,
               policy=None):
        return SyntheticSpotLedger.replay(
            self.policy if policy is None else policy,
            self.entries if entries is None else entries,
            expected_digest=self.snapshot.journal_digest if expected_digest is None
                else expected_digest,
            expected_count=len(self.entries) if expected_count is None
                else expected_count)

    def test_three_record_roundtrip(self):
        self.assertEqual(self.replay().balances(), self.snapshot)

    def test_determinism_across_two_replays(self):
        self.assertEqual(self.replay().balances(), self.replay().balances())

    def test_dropped_record_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(self.entries[:-1])

    def test_duplicated_record_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(self.entries + (self.entries[-1],))

    def test_swapped_record_order_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay((self.entries[1], self.entries[0], self.entries[2]))

    def test_first_record_predecessor_corruption_rejected(self):
        changed = replace(self.entries[0], previous_digest="0" * 64)
        with self.assertRaises(LedgerRejected):
            self.replay((changed,) + self.entries[1:])

    def test_last_record_predecessor_corruption_rejected(self):
        changed = replace(self.entries[-1], previous_digest="0" * 64)
        with self.assertRaises(LedgerRejected):
            self.replay(self.entries[:-1] + (changed,))

    def test_record_digest_corruption_rejected(self):
        changed = replace(self.entries[-1], digest="0" * 64)
        with self.assertRaises(LedgerRejected):
            self.replay(self.entries[:-1] + (changed,))

    def test_record_index_corruption_rejected(self):
        changed = replace(self.entries[1], index=10)
        with self.assertRaises(LedgerRejected):
            self.replay((self.entries[0], changed, self.entries[-1]))

    def test_record_payload_corruption_rejected(self):
        changed = replace(self.entries[1], payload_json='{}')
        with self.assertRaises(LedgerRejected):
            self.replay((self.entries[0], changed, self.entries[-1]))

    def test_noncanonical_payload_rejected(self):
        pretty = json.dumps(json.loads(self.entries[1].payload_json), indent=2)
        changed = replace(self.entries[1], payload_json=pretty)
        with self.assertRaises(LedgerRejected):
            self.replay((self.entries[0], changed, self.entries[-1]))

    def test_external_tip_tamper_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(expected_digest="0" * 64)

    def test_malformed_external_tip_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(expected_digest="NOT-A-HASH")

    def test_external_count_tamper_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(expected_count=2)

    def test_boolean_external_count_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(expected_count=True)

    def test_altered_fee_policy_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(policy=replace(self.policy, fee_bps=200))

    def test_altered_initial_balance_policy_rejected(self):
        with self.assertRaises(LedgerRejected):
            self.replay(policy=replace(self.policy, quote_initial=11000))

    def test_no_live_trading_permission_in_replay(self):
        self.assertFalse(self.replay().balances().live_trading_allowed)

    def test_no_financial_performance_attestation(self):
        self.assertFalse(self.replay().balances().financial_performance_evaluated)

    def test_no_production_ledger_attestation(self):
        self.assertFalse(self.replay().balances().production_ledger)


if __name__ == "__main__":
    unittest.main()
