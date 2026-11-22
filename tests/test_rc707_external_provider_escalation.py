"""RC707: narrowly test real provider ticket scope and fail-closed semantics."""
import ast
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_rc707_external_provider_escalation as m


class RealProviderEscalation(unittest.TestCase):
    def test_01_exact_ubuntu_provenance(self):
        p = m.escalation_packet('ubuntu')
        self.assertEqual((p['scope']['run_id'], p['scope']['job_id']),
                         (44575994515, 135743537628))
        self.assertEqual(p['scope']['head_sha'], m.SOURCE_SHA)
        self.assertEqual(p['scope']['unittest_cases'], 3205)
    def test_02_exact_windows_provenance(self):
        p = m.escalation_packet('windows')
        self.assertEqual((p['scope']['run_id'], p['scope']['job_id']),
                         (44575994468, 135743537077))
        self.assertEqual(p['scope']['run_attempt'], 1)
        self.assertNotEqual(p['scope']['workflow_git_blob_sha1'],
                            m.escalation_packet('ubuntu')['scope']['workflow_git_blob_sha1'])
    def test_03_no_plaintext_or_artifact_downgrade(self):
        for platform in ('ubuntu', 'windows'):
            p = m.escalation_packet(platform)
            self.assertIn('ORIGINAL RAW COMPLETE', p['request'])
            self.assertIn('not redirected readable plaintext', p['request'])
            self.assertFalse(p['signature_obtained'])
            self.assertFalse(p['original_raw_full_log_verified'])
            self.assertTrue(p['not_submitted'])
    def test_04_exact_eight_gates_remain_blocked(self):
        gates = m.remaining_gate_handoff()
        self.assertEqual(len(gates), 8)
        self.assertEqual(len({x['gate'] for x in gates}), 8)
        self.assertTrue(all(x['status'] == 'BLOCKED' and
                            not x['independently_verified'] for x in gates))
        self.assertEqual(m.safety_state()['external_verified'], 0)
    def test_05_reject_unrecognized_platform_or_false_subject(self):
        for candidate in ('linux', 'win32', None, True, 1, {}, ''):
            with self.assertRaisesRegex(ValueError, 'only_pinned_real_os_jobs'):
                m.escalation_packet(candidate)
    def test_06_deterministic_request_not_signed_evidence(self):
        for os in ('ubuntu', 'windows'):
            self.assertEqual(m.escalation_packet(os)['request_sha256'],
                             m.escalation_packet(os)['request_sha256'])
            self.assertEqual(len(m.escalation_packet(os)['request_sha256']), 64)
        self.assertNotEqual(m.escalation_packet('ubuntu')['request_sha256'],
                            m.escalation_packet('windows')['request_sha256'])
    def test_07_read_only_import_and_ast_guard(self):
        path = ROOT/'safe_public_ci'/'ci_rc707_external_provider_escalation.py'
        tree = ast.parse(path.read_text(encoding='utf-8'))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(item.name for item in node.names)
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ('open', 'exec', 'eval', 'compile', '__import__'))
        self.assertEqual(imported, {'hashlib', 'json'})


if __name__ == '__main__':
    unittest.main()
