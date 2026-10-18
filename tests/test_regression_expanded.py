"""Expanded deterministic security regressions for the public synthetic-only harness.

All values below are invented; no network, credentials, models, or market data.
"""
import io
import json
import unittest
import warnings
import zipfile

from safe_public_ci.boundaries import (
    UnsafeInput,
    validate_parquet_envelope,
    validate_synthetic_json,
    validate_zip_envelope,
)
from safe_public_ci.checkpoint import checksum, require_integrity
from safe_public_ci.mock_exchange import (
    LiveTradingDisabled,
    OfflineExchange,
    ToyQuote,
)


def _json(rows, **extra):
    doc = {"kind": "synthetic-v1", "records": rows}
    doc.update(extra)
    return json.dumps(doc).encode("utf-8")


def _zip(members):
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, payload in members:
                zf.writestr(name, payload)
    return buffer.getvalue()


class ExpandedBoundaryTests(unittest.TestCase):
    def test_01_json_valid_maximum_rows(self):
        rows = [{"index": index, "value": float(index) / 10}
                for index in range(32)]
        self.assertEqual(len(validate_synthetic_json(_json(rows))), 32)

    def test_02_json_reject_boolean_index(self):
        with self.assertRaises(UnsafeInput):
            validate_synthetic_json(_json([{"index": True, "value": 1}]))

    def test_03_json_reject_boolean_value(self):
        with self.assertRaises(UnsafeInput):
            validate_synthetic_json(_json([{"index": 0, "value": False}]))

    def test_04_json_reject_overflow_to_infinity(self):
        data = b'{"kind":"synthetic-v1","records":[{"index":0,"value":1e999}]}'
        with self.assertRaises(UnsafeInput):
            validate_synthetic_json(data)

    def test_05_json_reject_unknown_schema_field(self):
        with self.assertRaises(UnsafeInput):
            validate_synthetic_json(_json([{"index": 0, "value": 1}], account="toy"))

    def test_06_json_reject_zero_rows(self):
        with self.assertRaises(UnsafeInput):
            validate_synthetic_json(_json([]))

    def test_07_json_reject_decreasing_index(self):
        with self.assertRaises(UnsafeInput):
            validate_synthetic_json(_json([
                {"index": 5, "value": 1},
                {"index": 4, "value": 2},
            ]))

    def test_08_zip_reject_duplicate_names(self):
        with self.assertRaises(UnsafeInput):
            validate_zip_envelope(_zip([("toy.txt", b"a"), ("toy.txt", b"b")]))

    def test_09_zip_reject_windows_traversal(self):
        with self.assertRaises(UnsafeInput):
            validate_zip_envelope(_zip([("folder\\..\\toy", b"x")]))

    def test_10_zip_reject_more_than_sixteen_members(self):
        with self.assertRaises(UnsafeInput):
            validate_zip_envelope(_zip([(f"{i}.txt", b"x") for i in range(17)]))

    def test_11_parquet_reject_out_of_range_footer(self):
        data = b"PAR1" + b"abcd" + (9000).to_bytes(4, "little") + b"PAR1"
        with self.assertRaises(UnsafeInput):
            validate_parquet_envelope(data)


class ExpandedGuardTests(unittest.TestCase):
    def test_12_quote_reject_boolean_slot(self):
        with self.assertRaises(ValueError):
            OfflineExchange((ToyQuote(True, 7),))

    def test_13_quote_reject_boolean_price(self):
        with self.assertRaises(ValueError):
            OfflineExchange((ToyQuote(0, True),))

    def test_14_quote_reject_excessive_price(self):
        with self.assertRaises(ValueError):
            OfflineExchange((ToyQuote(0, 1000001),))

    def test_15_quotes_require_tuple(self):
        with self.assertRaises(ValueError):
            OfflineExchange([ToyQuote(0, 3)])

    def test_16_order_kwargs_also_fail_closed(self):
        ex = OfflineExchange((ToyQuote(0, 3),))
        with self.assertRaises(LiveTradingDisabled):
            ex.place_order(side="BUY", qty=2)
        with self.assertRaises(LiveTradingDisabled):
            ex.cancel_order(order_id="toy")

    def test_17_checksum_rejects_oversized_data(self):
        with self.assertRaises(ValueError):
            checksum(b"q" * 65537)

    def test_18_integrity_requires_canonical_lowercase_digest(self):
        payload = b"synthetic-only"
        with self.assertRaises(ValueError):
            require_integrity(payload, checksum(payload).upper())


if __name__ == "__main__":
    unittest.main()
