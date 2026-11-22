"""RC708 targeted regression against actual TUR64 hosted run identities."""
import ast
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_rc708_support_channel_handoff as m


class OfficialChannelHandoff(unittest.TestCase):
    def test_01_exact_tur64_ubuntu_windows_real_runs(self):
        u = m.support_packet('ubuntu', 'paid_support')['subject']
        w = m.support_packet('windows', 'free_community')['subject']
        self.assertEqual((u['run_id'], u['job_id']), (44611783408, 135870006293))
        self.assertEqual((w['run_id'], w['job_id']), (44611783309, 135870006799))
        self.assertEqual(u['source_sha'], m.BASE_SHA)
        self.assertEqual(w['source_sha'], m.BASE_SHA)
        self.assertEqual((u['unittest_passes'], w['unittest_passes']), (3212, 3212))
    def test_02_support_eligibility_not_inferred(self):
        for channel in m.CHANNELS:
            p = m.support_packet('ubuntu', channel)
            self.assertTrue(p['eligibility_is_not_verified'])
            self.assertFalse(p['submitted'])
            self.assertIsNone(p['actual_support_case_id'])
            self.assertFalse(p['support_reply_received'])
        self.assertNotEqual(m.support_packet('ubuntu', 'paid_support')['request_digest_sha256'],
                            m.support_packet('ubuntu', 'free_community')['request_digest_sha256'])
    def test_03_explicit_original_raw_not_plaintext(self):
        for platform in m.PINNED:
            p = m.support_packet(platform, 'paid_support')
            self.assertIn('ORIGINAL RAW COMPLETE', p['request_text'])
            self.assertIn('artifact attestations', p['request_text'])
            self.assertIn('canonical byte preimage', p['request_text'])
            self.assertFalse(p['provider_raw_verified'])
    def test_04_untrusted_reply_even_unsupported_keeps_no_go(self):
        for klass in ('UNSUBMITTED','USER_REPORT_ONLY','UNAUTHENTICATED_REPLY',
                      'DOCUMENTED_UNSUPPORTED','POSSIBLE_ESCALATION'):
            v = m.classify_unverified_response('windows','free_community',klass)
            self.assertEqual(v['external_gates_verified'],0)
            self.assertEqual(v['external_total'],8)
            self.assertEqual(v['auth'],'NO-GO')
            self.assertFalse(v['provider_signature_verified'])
    def test_05_unknown_source_and_trust_claim_rejected(self):
        for candidate in (None, True, 3, 'macos', 'Ubuntu', ''):
            with self.assertRaisesRegex(ValueError, 'unknown_pinned_platform'):
                m.support_packet(candidate, 'paid_support')
        for candidate in (None, False, 2, 'github_support', 'community'):
            with self.assertRaisesRegex(ValueError, 'unknown_support_channel'):
                m.support_packet('ubuntu', candidate)
        for candidate in (True, False, 1, {}, 'PROVIDER_VERIFIED'):
            with self.assertRaisesRegex(ValueError, 'untrusted_reply_class'):
                m.classify_unverified_response('ubuntu','paid_support',candidate)
    def test_06_read_only_AST_whitelist_and_reproducible_hash(self):
        path = ROOT/'safe_public_ci'/'ci_rc708_support_channel_handoff.py'
        tree = ast.parse(path.read_text(encoding='utf-8'))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(x.name for x in node.names)
            if isinstance(node, ast.ImportFrom):
                imports.add(node.module)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ('eval','exec','open','compile','__import__'))
        self.assertEqual(imports, {'hashlib', 'json'})
        self.assertEqual(m.support_packet('ubuntu','paid_support')['request_digest_sha256'],
                         m.support_packet('ubuntu','paid_support')['request_digest_sha256'])


if __name__ == '__main__':
    unittest.main()
