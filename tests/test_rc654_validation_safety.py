"""RC654 isolated validation-branch security contract, no real trading.

PR #1's 18-test module was not imported because the transfer was blocked.
This module tests only the safety of a new independent validation workflow.
"""
from pathlib import Path
import re
import unittest

from safe_public_ci.mock_exchange import OfflineExchange, ToyQuote, LiveTradingDisabled
from safe_public_ci import SAFE_TEST_ONLY

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/rc654-validation-synthetic.yml"
CHECKOUT = "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
PYTHON = "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"


class RC654IsolationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = WORKFLOW.read_text(encoding="utf-8")

    def test_validation_branch_is_the_only_trigger(self):
        self.assertIn("      - validation/rc654-pr1-rc653-combined-ci", self.src)
        for disallowed in ("pull_request:", "pull_request_target:", "workflow_dispatch:",
                           "workflow_run:", "schedule:", "repository_dispatch:"):
            self.assertNotIn(disallowed, self.src)

    def test_no_private_checkout_or_runner(self):
        self.assertIn("runs-on: ubuntu-24.04", self.src)
        self.assertNotIn("self-hosted", self.src)
        self.assertNotIn("repository:", self.src)

    def test_readonly_workflow_and_job_permissions(self):
        self.assertEqual(self.src.count("contents: read"), 2)
        self.assertNotIn("contents: write", self.src)
        self.assertNotIn("id-token: write", self.src)

    def test_exact_pinned_action_shas(self):
        self.assertIn(CHECKOUT, self.src)
        self.assertIn(PYTHON, self.src)
        uses = re.findall(r"(?m)^\s+uses:\s+([^\n]+)$", self.src)
        self.assertEqual(uses, [CHECKOUT, PYTHON])

    def test_python_version_exactly_pinned(self):
        self.assertIn("python-version: '3.13.5'", self.src)
        self.assertIn("sys.version_info[:3] == (3, 13, 5)", self.src)

    def test_synthetic_flag_enabled(self):
        self.assertIs(SAFE_TEST_ONLY, True)
        self.assertIn("SAFE_TEST_ONLY: '1'", self.src)

    def test_no_live_order(self):
        instance = OfflineExchange((ToyQuote(0, 10),))
        with self.assertRaises(LiveTradingDisabled):
            instance.place_order("BUY")

    def test_no_live_cancel(self):
        instance = OfflineExchange((ToyQuote(0, 10),))
        with self.assertRaises(LiveTradingDisabled):
            instance.cancel_order(1)

    def test_no_serializer_unapproved_artifact(self):
        self.assertFalse((ROOT / "safe_public_ci" / "synthetic_receipt.py").exists())

    def test_no_real_data_or_strategy_tree(self):
        for path in ("data", "models", "private", "strategies"):
            self.assertFalse((ROOT / path).exists(), path)

    def test_all_rc653_predecessor_tests_present(self):
        for name in ("test_rc653_receipt_boundary.py",
                     "test_rc653_journal_adversarial.py",
                     "test_rc653_ci_security.py"):
            self.assertTrue((ROOT / "tests" / name).is_file())

    def test_no_secret_reference_in_workflow(self):
        for forbidden in ("secrets.", "${{", "BINANCE", "MEXC",
                          "api_key", "private/", "pull_request_target:"):
            self.assertNotIn(forbidden, self.src)

    def test_no_remote_install_deployment_or_metrics(self):
        for forbidden in ("curl ", "wget ", "pip install", "git clone", "docker ",
                          "deploy", "upload-artifact", "trading_order",
                          "backtest", "pnl", "train_model"):
            self.assertNotIn(forbidden, self.src)

    def test_checkout_does_not_persist_credentials(self):
        for item in ("persist-credentials: false", "fetch-depth: 1",
                     "submodules: false", "lfs: false"):
            self.assertIn(item, self.src)

    def test_no_soft_fail(self):
        for forbidden in ("continue-on-error:", "|| true", "exit 0", "set +e"):
            self.assertNotIn(forbidden, self.src)

    def test_full_suite_runs_with_failure_propagation(self):
        self.assertIn("python -m unittest discover -s tests -v", self.src)
        self.assertIn("python -m compileall -q safe_public_ci tests", self.src)


if __name__ == "__main__":
    unittest.main()
