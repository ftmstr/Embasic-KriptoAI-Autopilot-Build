"""Adversarial purely invented spot cash accounting and journal replay tests."""
from dataclasses import replace
import unittest

from safe_public_ci.offline_order_fsm import (
    OfflineRefusal, SyntheticOrderEvent, SyntheticOrderIntent, deterministic_client_id,
)
from safe_public_ci.offline_spot_ledger import (
    LedgerRejected, SyntheticExecution, SyntheticLedgerPolicy, SyntheticSpotIntent,
    SyntheticSpotLedger, fee_ceil,
)


def request(n=1, side="BUY", units=4, limit=100, created=1000, observed=995):
    order = SyntheticOrderIntent(deterministic_client_id("SYN-SEED-LEDGER", n),units,created,observed)
    return SyntheticSpotIntent(order,side,limit)


def ev(n,kind,*,filled=0,total=0,state="",price=0):
    return SyntheticOrderEvent(f"SIM-EVT-{n:03d}",n,kind,1000+10*n,1000+10*n+1,filled,total,state),price


class SpotLedgerTests(unittest.TestCase):
    def setUp(self):
        self.p = SyntheticLedgerPolicy(quote_initial=10000,base_initial=10,fee_bps=100,max_notional=5000)
        self.l = SyntheticSpotLedger(self.p)
        self.r = request()
        self.l.submit(self.r,as_of_ms=1000)

    def apply(self,n,kind,*,filled=0,total=0,state="",price=0):
        e,pr=ev(n,kind,filled=filled,total=total,state=state,price=price)
        return self.l.apply(SyntheticExecution(self.r.order.client_id,e,pr),as_of_ms=5000)

    def test_initial_balances(self):
        l=SyntheticSpotLedger(self.p)
        self.assertEqual((l.balances().quote_total,l.balances().base_total),(10000,10))
    def test_reservation_worst_case_fee(self):
        # 4 units * 100 price + 4 * ceil(100*1%) = 404
        self.assertEqual(self.l.balances().quote_reserved,404)
    def test_available_quote(self):
        self.assertEqual(self.l.balances().quote_available,9596)
    def test_idempotent_duplicate_submit(self):
        n=len(self.l.journal);b=self.l.balances()
        self.assertEqual(b,self.l.submit(self.r,as_of_ms=1000))
        self.assertEqual(len(self.l.journal),n)
    def test_conflicting_idempotency(self):
        with self.assertRaises(LedgerRejected):self.l.submit(replace(self.r,limit_price_ticks=99),as_of_ms=1000)
    def test_buyer_partial_fill(self):
        self.apply(1,"ACK")
        b=self.apply(2,"FILL",filled=2,price=95)
        self.assertEqual((b.quote_total,b.base_total,b.total_fee_quote),(9808,12,2))
        self.assertEqual((b.quote_reserved,b.quote_available),(212,9596))
    def test_buyer_full_fill_releases_price_improvement(self):
        self.apply(1,"ACK");self.apply(2,"FILL",filled=2,price=95)
        b=self.apply(3,"FILL",filled=2,price=90)
        self.assertEqual((b.quote_total,b.quote_reserved,b.base_total),(9626,0,14))
        self.assertEqual(b.total_fee_quote,4)
    def test_buyer_cancel_release(self):
        self.apply(1,"ACK");self.apply(2,"CANCEL_REQUEST")
        b=self.apply(3,"CANCEL_ACK")
        self.assertEqual((b.quote_total,b.quote_reserved),(10000,0))
    def test_reject_release(self):
        b=self.apply(1,"REJECT")
        self.assertEqual(b.quote_reserved,0)
    def test_buyer_partial_then_cancel(self):
        self.apply(1,"ACK");self.apply(2,"FILL",filled=1,price=100)
        self.apply(3,"CANCEL_REQUEST");b=self.apply(4,"CANCEL_ACK")
        self.assertEqual((b.quote_total,b.quote_reserved,b.base_total),(9899,0,11))
    def test_sell_reserves_base(self):
        l=SyntheticSpotLedger(self.p);l.submit(request(2,"SELL",5,100),as_of_ms=1000)
        self.assertEqual((l.balances().base_total,l.balances().base_reserved),(10,5))
    def test_sell_partial_and_cancel(self):
        l=SyntheticSpotLedger(self.p);r=request(2,"SELL",5,100)
        l.submit(r,as_of_ms=1000)
        for i,kind in [(1,"ACK"),(3,"CANCEL_REQUEST"),(4,"CANCEL_ACK")]:
            if i==3:
                e,pr=ev(2,"FILL",filled=2)
                l.apply(SyntheticExecution(r.order.client_id,e,120),as_of_ms=5000)
            e,pr=ev(i,kind)
            l.apply(SyntheticExecution(r.order.client_id,e),as_of_ms=5000)
        b=l.balances()
        self.assertEqual((b.base_total,b.base_reserved,b.quote_total,b.total_fee_quote),(8,0,10237,3))
    def test_sell_fee_ceil(self):self.assertEqual(fee_ceil(201,100),3)
    def test_buy_fill_over_limit_rejected(self):
        self.apply(1,"ACK")
        with self.assertRaises(LedgerRejected):self.apply(2,"FILL",filled=1,price=101)
    def test_sell_fill_under_limit_rejected(self):
        l=SyntheticSpotLedger(self.p);r=request(2,"SELL",1,100)
        l.submit(r,as_of_ms=1000);e,_=ev(1,"ACK")
        l.apply(SyntheticExecution(r.order.client_id,e),as_of_ms=5000)
        e,_=ev(2,"FILL",filled=1)
        with self.assertRaises(LedgerRejected):l.apply(SyntheticExecution(r.order.client_id,e,99),as_of_ms=5000)
    def test_duplicate_fill_no_double_debit(self):
        self.apply(1,"ACK");b=self.apply(2,"FILL",filled=2,price=100)
        self.assertEqual(self.apply(2,"FILL",filled=2,price=100),b)
    def test_conflicting_same_event_price(self):
        self.apply(1,"ACK");self.apply(2,"FILL",filled=2,price=100)
        with self.assertRaises(LedgerRejected):self.apply(2,"FILL",filled=2,price=99)
    def test_timeout_freezes_reserve(self):
        b=self.apply(1,"TIMEOUT")
        self.assertEqual(b.quote_reserved,404)
        with self.assertRaises(LedgerRejected):self.apply(2,"FILL",filled=1,price=100)
    def test_reconcile_without_new_fills(self):
        self.apply(1,"TIMEOUT");b=self.apply(2,"RECONCILE",total=0,state="CANCELED")
        self.assertEqual((b.quote_reserved,b.quote_total),(0,10000))
    def test_reconcile_new_unpriced_fill_denied(self):
        self.apply(1,"TIMEOUT")
        before=self.l.balances()
        with self.assertRaises(LedgerRejected):self.apply(2,"RECONCILE",total=2,state="OPEN")
        self.assertEqual(self.l.balances(),before)
    def test_fsm_overfill_fails_without_ledger_mutation(self):
        self.apply(1,"ACK")
        before=self.l.balances()
        with self.assertRaises(LedgerRejected):self.apply(2,"FILL",filled=5,price=100)
        self.assertEqual(self.l.balances(),before)
    def test_invalid_event_no_mutation(self):
        before=self.l.balances()
        with self.assertRaises(LedgerRejected):self.apply(1,"BAD")
        self.assertEqual(self.l.balances(),before)
    def test_invalid_bool_fee_policy(self):
        with self.assertRaises(LedgerRejected):SyntheticLedgerPolicy(fee_bps=True)
    def test_float_balances_denied(self):
        with self.assertRaises(LedgerRejected):SyntheticLedgerPolicy(quote_initial=1000.0)
    def test_negative_balances_denied(self):
        with self.assertRaises(LedgerRejected):SyntheticLedgerPolicy(base_initial=-1)
    def test_large_spend_denied(self):
        l=SyntheticSpotLedger(SyntheticLedgerPolicy(quote_initial=30,max_notional=5000))
        with self.assertRaises(LedgerRejected):l.submit(request(),as_of_ms=1000)
    def test_large_notional_denied(self):
        with self.assertRaises(LedgerRejected):self.l.submit(request(2,units=4,limit=1500),as_of_ms=1000)
    def test_sell_overinventory_denied(self):
        with self.assertRaises(LedgerRejected):self.l.submit(request(2,side="SELL",units=11),as_of_ms=1000)
    def test_buy_overbooked_balance_denied(self):
        l=SyntheticSpotLedger(SyntheticLedgerPolicy(quote_initial=450,max_notional=5000))
        l.submit(request(1),as_of_ms=1000)
        with self.assertRaises(LedgerRejected):l.submit(request(2),as_of_ms=1000)
    def test_kill_denies_new_orders(self):
        self.l.kill_switch()
        with self.assertRaises(LedgerRejected):self.l.submit(request(2),as_of_ms=1000)
    def test_kill_idempotency(self):
        b=self.l.kill_switch()
        self.assertEqual(self.l.kill_switch(),b)
    def test_kill_allows_reconcile(self):
        self.apply(1,"TIMEOUT");self.l.kill_switch()
        self.assertEqual(self.apply(2,"RECONCILE",state="CANCELED").quote_reserved,0)
    def test_live_symbol_denied(self):
        with self.assertRaises(LedgerRejected):self.l.submit(SyntheticSpotIntent(replace(request(2).order,invented_pair="BTCUSDT"),"BUY",100),as_of_ms=1000)
    def test_no_live_permission(self):
        self.assertFalse(self.l.balances().live_trading_allowed)
    def test_no_pnl_assertion(self):
        self.assertFalse(self.l.balances().financial_performance_evaluated)
    def test_no_production_ledger_assertion(self):
        self.assertFalse(self.l.balances().production_ledger)
    def test_journal_verified(self):self.assertTrue(self.l.verify_journal())
    def test_replay_single_submit(self):
        b=self.l.balances()
        self.assertEqual(SyntheticSpotLedger.replay(self.p,tuple(self.l.journal),expected_digest=b.journal_digest,expected_count=b.journal_count).balances(),b)
    def test_replay_fills_cancel(self):
        self.apply(1,"ACK");self.apply(2,"FILL",filled=2,price=96)
        self.apply(3,"CANCEL_REQUEST");self.apply(4,"CANCEL_ACK")
        b=self.l.balances()
        self.assertEqual(SyntheticSpotLedger.replay(self.p,tuple(self.l.journal),expected_digest=b.journal_digest,expected_count=b.journal_count).balances(),b)
    def test_replay_timeout_kill_reconcile(self):
        self.apply(1,"TIMEOUT");self.l.kill_switch();self.apply(2,"RECONCILE",state="CANCELED")
        b=self.l.balances()
        self.assertEqual(SyntheticSpotLedger.replay(self.p,tuple(self.l.journal),expected_digest=b.journal_digest,expected_count=b.journal_count).balances(),b)
    def test_detect_mutated_entry(self):
        entries=list(self.l.journal);entries[0]=replace(entries[0],payload_json='{}')
        b=self.l.balances()
        with self.assertRaises(LedgerRejected):SyntheticSpotLedger.replay(self.p,tuple(entries),expected_digest=b.journal_digest,expected_count=b.journal_count)
    def test_detect_missing_entry(self):
        b=self.l.balances()
        with self.assertRaises(LedgerRejected):SyntheticSpotLedger.replay(self.p,(),expected_digest=b.journal_digest,expected_count=b.journal_count)
    def test_detect_wrong_expected_tip(self):
        b=self.l.balances()
        with self.assertRaises(LedgerRejected):SyntheticSpotLedger.replay(self.p,tuple(self.l.journal),expected_digest='0'*64,expected_count=b.journal_count)
    def test_replay_with_altered_policy(self):
        b=self.l.balances()
        with self.assertRaises(LedgerRejected):SyntheticSpotLedger.replay(replace(self.p,fee_bps=200),tuple(self.l.journal),expected_digest=b.journal_digest,expected_count=b.journal_count)
    def test_replay_stable_digest(self):
        self.apply(1,"ACK");self.apply(2,"FILL",filled=1,price=98)
        b=self.l.balances()
        self.assertEqual(SyntheticSpotLedger.replay(self.p,tuple(self.l.journal),expected_digest=b.journal_digest,expected_count=b.journal_count).balances().journal_digest,b.journal_digest)

if __name__=='__main__':unittest.main()
