"""Synthetic-only deterministic, adversarial stream checks. No trading or market data."""
from dataclasses import replace
import unittest

from safe_public_ci.synthetic_stream_guard import (
    SyntheticObservation as O, SyntheticStreamRejected as Rejected,
    SyntheticStreamReceipt, validate_synthetic_stream,
)


def stream():
    return (O(0, 1_000, 1_005, 100, "SYN-001"),
            O(1, 1_100, 1_105, 101, "SYN-002"),
            O(2, 1_200, 1_205, 100, "SYN-003"))


def validate(rows=None, **kwargs):
    settings = dict(as_of_ms=1_210, max_transport_latency_ms=15, max_last_event_age_ms=20)
    settings.update(kwargs)
    return validate_synthetic_stream(stream() if rows is None else rows, **settings)


class SyntheticGuardTests(unittest.TestCase):
    def test_valid_invented_stream(self):
        self.assertEqual(validate().observations, 3)
    def test_deterministic_digest(self):
        self.assertEqual(validate().canonical_sha256, validate().canonical_sha256)
    def test_invented_data_only_label(self):
        self.assertEqual(validate().kind, "EMBASIC_PUBLIC_INVENTED_STREAM_ONLY")
    def test_no_market_attestation(self):
        self.assertFalse(validate().verified_market_data)
    def test_no_live_or_release(self):
        self.assertFalse(validate().trading_enabled or validate().production_ready)
    def test_no_scientific_performance(self):
        self.assertFalse(validate().scientific_validated)
    def test_gap(self):
        a=list(stream());a[1]=replace(a[1],sequence=4)
        with self.assertRaises(Rejected):validate(tuple(a))
    def test_duplicate_sequence(self):
        a=list(stream());a[1]=replace(a[1],sequence=0)
        with self.assertRaises(Rejected):validate(tuple(a))
    def test_future_exchange_time(self):
        a=list(stream());a[-1]=replace(a[-1], event_time_ms=1_220)
        with self.assertRaises(Rejected):validate(tuple(a))
    def test_future_reception(self):
        a=list(stream());a[-1]=replace(a[-1], observed_time_ms=1_220)
        with self.assertRaises(Rejected):validate(tuple(a))
    def test_non_monotone_event_time(self):
        a=list(stream());a[1]=replace(a[1], event_time_ms=1_000)
        with self.assertRaises(Rejected):validate(tuple(a))
    def test_non_monotone_reception_time(self):
        a=list(stream());a[1]=replace(a[1], observed_time_ms=1_005)
        with self.assertRaises(Rejected):validate(tuple(a))
    def test_duplicate_event_id(self):
        a=list(stream());a[2]=replace(a[2],synthetic_id="SYN-001")
        with self.assertRaises(Rejected):validate(tuple(a))
    def test_non_synthetic_id(self):
        a=list(stream());a[2]=replace(a[2],synthetic_id="BTCUSDT")
        with self.assertRaises(Rejected):validate(tuple(a))
    def test_stale_transport(self):
        with self.assertRaises(Rejected):validate(max_transport_latency_ms=4)
    def test_stale_final_event(self):
        with self.assertRaises(Rejected):validate(as_of_ms=1_230)
    def test_invalid_zero_price(self):
        a=list(stream());a[2]=replace(a[2],price_ticks=0)
        with self.assertRaises(Rejected):validate(tuple(a))
    def test_invalid_float_price(self):
        a=list(stream());a[2]=replace(a[2],price_ticks=100.0)
        with self.assertRaises(Rejected):validate(tuple(a))
    def test_bool_time_rejected(self):
        with self.assertRaises(Rejected):validate(as_of_ms=True)
    def test_negative_latency_budget_rejected(self):
        with self.assertRaises(Rejected):validate(max_transport_latency_ms=-1)
    def test_list_rejected(self):
        with self.assertRaises(Rejected):validate(list(stream()))
    def test_empty_rejected(self):
        with self.assertRaises(Rejected):validate(())
    def test_oversize_rejected(self):
        with self.assertRaises(Rejected):validate(stream()*22)
    def test_hash_changes_with_toy_input(self):
        a=list(stream());a[-1]=replace(a[-1],price_ticks=99)
        self.assertNotEqual(validate(tuple(a)).canonical_sha256,validate().canonical_sha256)
    def test_strict_class_rejected(self):
        with self.assertRaises(Rejected):validate((dict(sequence=0),))

if __name__ == "__main__": unittest.main()
