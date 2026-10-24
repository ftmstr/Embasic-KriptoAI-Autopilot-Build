"""Adversarial tests of invented offline-only order-state transitions."""
from dataclasses import replace
import unittest

from safe_public_ci.offline_order_fsm import (
    LiveTradingDisabled, OfflineOrderSimulator, OfflineRefusal, OfflineRiskPolicy,
    SyntheticOrderEvent, SyntheticOrderIntent, deterministic_client_id,
)


def intent(nonce=1, units=6, created_ms=1000, market_ms=990):
    return SyntheticOrderIntent(deterministic_client_id("SYN-SEED-TRIAL", nonce),
                                units, created_ms, market_ms)


def event(seq, kind, *, filled=0, total=0, exchange_state="", time=None, recv=None):
    t = 1000 + seq * 10 if time is None else time
    return SyntheticOrderEvent(f"SIM-EVT-{seq:03d}", seq, kind, t,
                               t + 2 if recv is None else recv, filled, total, exchange_state)


class OfflineFSMTests(unittest.TestCase):
    def setUp(self):
        self.engine = OfflineOrderSimulator(OfflineRiskPolicy())
        self.order = intent()
        self.engine.submit(self.order, as_of_ms=1000)

    def feed(self, seq, kind, **kwargs):
        return self.engine.apply(self.order.client_id, event(seq, kind, **kwargs), as_of_ms=5000)

    def test_deterministic_client_id(self):
        self.assertEqual(deterministic_client_id("SYN-SEED-TRIAL", 4), deterministic_client_id("SYN-SEED-TRIAL", 4))
    def test_unique_nonce_ids(self):
        self.assertNotEqual(deterministic_client_id("SYN-SEED-TRIAL", 4), deterministic_client_id("SYN-SEED-TRIAL", 5))
    def test_btc_symbol_rejected(self):
        with self.assertRaises(OfflineRefusal): self.engine.submit(replace(intent(2),invented_pair="BTCUSDT"), as_of_ms=1000)
    def test_live_mode_rejected(self):
        with self.assertRaises(OfflineRefusal): self.engine.submit(replace(intent(2),mode="LIVE"),as_of_ms=1000)
    def test_invalid_seed_rejected(self):
        with self.assertRaises(OfflineRefusal):deterministic_client_id("BTCUSDT",2)
    def test_bool_nonce_rejected(self):
        with self.assertRaises(OfflineRefusal):deterministic_client_id("SYN-SEED-TRIAL",True)
    def test_submit_starts_pending_ack(self):self.assertEqual(self.engine.snapshot(self.order.client_id).state,"PENDING_ACK")
    def test_submit_idempotent(self):
        self.assertEqual(self.engine.submit(self.order,as_of_ms=1000), self.engine.snapshot(self.order.client_id))
    def test_conflicting_duplicate_client_id(self):
        with self.assertRaises(OfflineRefusal):self.engine.submit(replace(self.order,units=5),as_of_ms=1000)
    def test_no_actual_exchange_id(self):self.assertIsNone(self.engine.snapshot(self.order.client_id).actual_exchange_order_id)
    def test_no_scientific_performance(self):self.assertFalse(self.engine.snapshot(self.order.client_id).scientific_performance_evaluated)
    def test_live_place_hard_disabled(self):
        with self.assertRaises(LiveTradingDisabled):self.engine.place_real_order(symbol="BTCUSDT")
    def test_live_cancel_hard_disabled(self):
        with self.assertRaises(LiveTradingDisabled):self.engine.cancel_real_order(client_id="ABC")
    def test_ack_new_to_open(self):self.assertEqual(self.feed(1,"ACK").state,"OPEN")
    def test_partial_fill(self):
        self.feed(1,"ACK");x=self.feed(2,"FILL",filled=2)
        self.assertEqual((x.state,x.filled_units,x.remaining_units),("PARTIALLY_FILLED",2,4))
    def test_full_fill(self):
        self.feed(1,"ACK");self.feed(2,"FILL",filled=2);x=self.feed(3,"FILL",filled=4)
        self.assertEqual((x.state,x.remaining_units),("FILLED",0))
    def test_no_overfill(self):
        self.feed(1,"ACK")
        with self.assertRaises(OfflineRefusal):self.feed(2,"FILL",filled=7)
    def test_zero_increment_rejected(self):
        self.feed(1,"ACK")
        with self.assertRaises(OfflineRefusal):self.feed(2,"FILL")
    def test_cancel_after_open(self):
        self.feed(1,"ACK");self.assertEqual(self.feed(2,"CANCEL_REQUEST").state,"CANCEL_PENDING")
        self.assertEqual(self.feed(3,"CANCEL_ACK").state,"CANCELED")
    def test_partial_fill_while_cancel_pending(self):
        self.feed(1,"ACK");self.feed(2,"CANCEL_REQUEST");x=self.feed(3,"FILL",filled=2)
        self.assertEqual((x.state,x.filled_units),("CANCEL_PENDING",2))
        self.assertEqual(self.feed(4,"CANCEL_ACK").filled_units,2)
    def test_filled_while_cancel_pending(self):
        self.feed(1,"ACK");self.feed(2,"CANCEL_REQUEST")
        self.assertEqual(self.feed(3,"FILL",filled=6).state,"FILLED")
    def test_terminal_fill_rejected(self):
        self.feed(1,"ACK");self.feed(2,"FILL",filled=6)
        with self.assertRaises(OfflineRefusal):self.feed(3,"FILL",filled=1)
    def test_reject_initial_order(self):self.assertEqual(self.feed(1,"REJECT").state,"REJECTED")
    def test_reject_after_partial_fills_refused(self):
        self.feed(1,"ACK");self.feed(2,"FILL",filled=1)
        with self.assertRaises(OfflineRefusal):self.feed(3,"REJECT")
    def test_ambiguous_timeout_freezes(self):
        self.feed(1,"ACK");self.assertEqual(self.feed(2,"TIMEOUT").state,"UNKNOWN")
        with self.assertRaises(OfflineRefusal):self.feed(3,"FILL",filled=1)
    def test_reconcile_unknown_open(self):
        self.feed(1,"TIMEOUT");self.assertEqual(self.feed(2,"RECONCILE",total=0,exchange_state="OPEN").state,"OPEN")
    def test_reconcile_partial_snapshot(self):
        self.feed(1,"TIMEOUT");x=self.feed(2,"RECONCILE",total=3,exchange_state="OPEN")
        self.assertEqual((x.state,x.filled_units),("PARTIALLY_FILLED",3))
    def test_reconcile_filled_snapshot(self):
        self.feed(1,"TIMEOUT");self.assertEqual(self.feed(2,"RECONCILE",total=6,exchange_state="FILLED").state,"FILLED")
    def test_reconcile_canceled_snapshot(self):
        self.feed(1,"TIMEOUT");x=self.feed(2,"RECONCILE",total=2,exchange_state="CANCELED")
        self.assertEqual((x.state,x.filled_units),("CANCELED",2))
    def test_reconcile_reject_snapshot(self):
        self.feed(1,"TIMEOUT");self.assertEqual(self.feed(2,"RECONCILE",total=0,exchange_state="REJECTED").state,"REJECTED")
    def test_reconcile_full_without_fill_rejected(self):
        self.feed(1,"TIMEOUT")
        with self.assertRaises(OfflineRefusal):self.feed(2,"RECONCILE",total=5,exchange_state="FILLED")
    def test_reconcile_decreasing_quantity_rejected(self):
        self.feed(1,"ACK");self.feed(2,"FILL",filled=3);self.feed(3,"TIMEOUT")
        with self.assertRaises(OfflineRefusal):self.feed(4,"RECONCILE",total=2,exchange_state="OPEN")
    def test_reconcile_after_open_rejected(self):
        self.feed(1,"ACK")
        with self.assertRaises(OfflineRefusal):self.feed(2,"RECONCILE",total=0,exchange_state="OPEN")
    def test_duplicate_event_replay_idempotent(self):
        e=event(1,"ACK");a=self.engine.apply(self.order.client_id,e,as_of_ms=5000)
        self.assertEqual(self.engine.apply(self.order.client_id,e,as_of_ms=5000),a)
    def test_conflicting_duplicate_event_rejected(self):
        e=event(1,"ACK");self.engine.apply(self.order.client_id,e,as_of_ms=5000)
        with self.assertRaises(OfflineRefusal): self.engine.apply(self.order.client_id,replace(e,kind="REJECT"),as_of_ms=5000)
    def test_event_sequence_gap_rejected(self):
        with self.assertRaises(OfflineRefusal):self.feed(2,"ACK")
    def test_bad_receive_time_rejected(self):
        with self.assertRaises(OfflineRefusal):self.feed(1,"ACK",recv=900)
    def test_observation_in_future_rejected(self):
        with self.assertRaises(OfflineRefusal):self.engine.apply(self.order.client_id,event(1,"ACK"),as_of_ms=1000)
    def test_lag_rejected(self):
        with self.assertRaises(OfflineRefusal):self.engine.apply(self.order.client_id,event(1,"ACK",recv=1700),as_of_ms=5000)
    def test_no_fill_on_ack(self):
        with self.assertRaises(OfflineRefusal):self.feed(1,"ACK",filled=1)
    def test_unknown_event_rejected(self):
        with self.assertRaises(OfflineRefusal):self.feed(1,"PLACE_MARKET")
    def test_unknown_client_rejected(self):
        with self.assertRaises(OfflineRefusal):self.engine.snapshot("SIM-NA")
    def test_kill_switch_disables_new_orders(self):
        self.engine.kill_switch()
        with self.assertRaises(OfflineRefusal):self.engine.submit(intent(2),as_of_ms=1000)
    def test_kill_switch_does_not_hide_reconciliation(self):
        self.feed(1,"TIMEOUT");self.engine.kill_switch()
        self.assertEqual(self.feed(2,"RECONCILE",total=0,exchange_state="CANCELED").state,"CANCELED")
    def test_session_risk_limit(self):
        e=OfflineOrderSimulator(OfflineRiskPolicy(max_units_per_order=7,max_session_requested_units=7))
        e.submit(intent(1,units=7),as_of_ms=1000)
        with self.assertRaises(OfflineRefusal):e.submit(intent(2,units=1),as_of_ms=1000)
    def test_max_count_limit(self):
        e=OfflineOrderSimulator(OfflineRiskPolicy(max_units_per_order=10,max_session_requested_units=30,max_unique_orders=1))
        e.submit(intent(1),as_of_ms=1000)
        with self.assertRaises(OfflineRefusal):e.submit(intent(2),as_of_ms=1000)
    def test_stale_market_submission(self):
        with self.assertRaises(OfflineRefusal):self.engine.submit(intent(2,market_ms=300),as_of_ms=1000)
    def test_future_market_submission(self):
        with self.assertRaises(OfflineRefusal):self.engine.submit(intent(2,market_ms=1200),as_of_ms=1200)
    def test_invalid_bool_risk_limit(self):
        with self.assertRaises(OfflineRefusal):OfflineRiskPolicy(max_units_per_order=True)
    def test_mutation_rejected_leaves_state_unchanged(self):
        before=self.engine.snapshot(self.order.client_id)
        with self.assertRaises(OfflineRefusal):self.feed(1,"FILL",filled=6)
        self.assertEqual(self.engine.snapshot(self.order.client_id),before)
    def test_event_receipt_hash_deterministic(self):
        f=OfflineOrderSimulator(OfflineRiskPolicy()); f.submit(self.order,as_of_ms=1000)
        self.feed(1,"ACK");f.apply(self.order.client_id,event(1,"ACK"),as_of_ms=5000)
        self.assertEqual(self.engine.snapshot(self.order.client_id).audit_sha256,f.snapshot(self.order.client_id).audit_sha256)
    def test_receipt_hash_changes_after_event(self):
        before=self.engine.snapshot(self.order.client_id).audit_sha256
        self.feed(1,"ACK")
        self.assertNotEqual(before,self.engine.snapshot(self.order.client_id).audit_sha256)
    def test_fill_idempotent_no_double_count(self):
        self.feed(1,"ACK");e=event(2,"FILL",filled=2)
        self.engine.apply(self.order.client_id,e,as_of_ms=5000)
        self.engine.apply(self.order.client_id,e,as_of_ms=5000)
        self.assertEqual(self.engine.snapshot(self.order.client_id).filled_units,2)

if __name__=='__main__':unittest.main()
