"""Fail-closed trading and toy-data integrity checks."""
import ast
import unittest
from pathlib import Path
import safe_public_ci
from safe_public_ci.mock_exchange import OfflineExchange, ToyQuote, LiveTradingDisabled
from safe_public_ci.checkpoint import checksum, require_integrity

class GuardTests(unittest.TestCase):
    def mock(self):
        return OfflineExchange((ToyQuote(0,10),ToyQuote(1,12)))
    def test_safe_only(self):
        self.assertTrue(safe_public_ci.SAFE_TEST_ONLY)
    def test_mock_data(self):
        self.assertEqual(len(self.mock().read()),2)
    def test_no_orders(self):
        with self.assertRaises(LiveTradingDisabled): self.mock().place_order("BUY")
    def test_no_cancellations(self):
        with self.assertRaises(LiveTradingDisabled): self.mock().cancel_order(1)
    def test_bad_quote(self):
        with self.assertRaises(ValueError): OfflineExchange((ToyQuote(2,3),))
    def test_bad_empty(self):
        with self.assertRaises(ValueError): OfflineExchange(())
    def test_integrity_pass(self):
        data=b"toy-fixture"
        self.assertTrue(require_integrity(data,checksum(data)))
    def test_integrity_tamper(self):
        with self.assertRaises(ValueError): require_integrity(b"tamper",checksum(b"toy-fixture"))
    def test_empty_checksum(self):
        with self.assertRaises(ValueError): checksum(b"")
    def test_import_whitelist(self):
        root=Path(__file__).resolve().parents[1]
        allowed={"dataclasses","hashlib","hmac","io","json","math","stat","zipfile"}
        for f in (root/"safe_public_ci").glob("*.py"):
            for n in ast.walk(ast.parse(f.read_text())):
                if isinstance(n,ast.Import):
                    for alias in n.names: self.assertIn(alias.name.split(".")[0],allowed)
                elif isinstance(n,ast.ImportFrom):
                    self.assertIn((n.module or "").split(".")[0],allowed)
