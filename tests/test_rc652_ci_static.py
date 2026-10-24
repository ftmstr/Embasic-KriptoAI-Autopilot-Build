"""Conservative textual checks on synthetic-only PR CI; not a hosted run."""
from pathlib import Path
import unittest


class PRWorkflowStaticTests(unittest.TestCase):
    def setUp(self):
        self.text = (Path(__file__).resolve().parents[1] / '.github/workflows/rc652-pr-synthetic-ci.yml').read_text()
    def test_no_pull_request_target_or_deployment(self):
        self.assertIn('  pull_request:\n', self.text)
        for bad in ('pull_request_target', 'workflow_run:', 'self-hosted', 'deploy', 'secrets.', 'id-token: write'):
            self.assertNotIn(bad, self.text)
    def test_no_write_permissions(self):
        self.assertEqual(self.text.count('contents: read'), 2)
        self.assertNotIn('contents: write', self.text)
        self.assertIn('persist-credentials: false', self.text)
    def test_sha_pinned_actions(self):
        self.assertIn('actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09', self.text)
        self.assertIn('actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1', self.text)
        self.assertIn("python-version: '3.13.5'", self.text)
    def test_local_suite_only(self):
        self.assertIn('runs-on: ubuntu-24.04', self.text)
        self.assertNotIn('runs-on: ubuntu-latest', self.text)
        self.assertIn('SAFE_TEST_ONLY:', self.text)
        self.assertIn('python -m unittest discover -s tests -v', self.text)


if __name__ == '__main__': unittest.main()
