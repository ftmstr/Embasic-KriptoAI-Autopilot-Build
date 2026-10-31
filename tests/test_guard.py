"""Fail-closed trading and toy-data integrity checks; explicitly stdlib-only."""
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
        allowed={"__future__","dataclasses","hashlib","hmac","io","json","math","re","stat","zipfile","safe_public_ci"}
        for f in (root/"safe_public_ci").glob("*.py"):
            for n in ast.walk(ast.parse(f.read_text())):
                if isinstance(n,ast.Import):
                    for alias in n.names:
                        self.assertIn(alias.name.split(".")[0],allowed)
                        if alias.name.startswith("safe_public_ci."):
                            self.assertEqual(alias.name,"safe_public_ci.offline_order_fsm")
                elif isinstance(n,ast.ImportFrom):
                    self.assertIn((n.module or "").split(".")[0],allowed)
                    if (n.module or "").startswith("safe_public_ci."):
                        self.assertEqual(n.module, "safe_public_ci.offline_order_fsm")
    def test_dynamic_import_execution_forbidden(self):
        root=Path(__file__).resolve().parents[1]
        banned={"eval","exec","__import__","open","compile"}
        for f in (root/"safe_public_ci").glob("*.py"):
            for node in ast.walk(ast.parse(f.read_text())):
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                    self.assertNotIn(node.func.id,banned, f.name)
    def test_public_no_runtime_trading_clients(self):
        from safe_public_ci.offline_order_fsm import OfflineOrderSimulator, OfflineRiskPolicy
        simulator=OfflineOrderSimulator(OfflineRiskPolicy())
        with self.assertRaises(RuntimeError): simulator.place_real_order()
        with self.assertRaises(RuntimeError): simulator.cancel_real_order()
