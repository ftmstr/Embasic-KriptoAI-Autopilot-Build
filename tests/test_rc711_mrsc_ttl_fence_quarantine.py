"""RC711 targeted provider-specific TTL and expired-fence proof-type tests."""
import ast
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_rc711_mrsc_ttl_fence_quarantine as m


def candidate(kind='NONE'):
    return {'repository': m.REPO, 'branch': m.BRANCH, 'source_sha': m.BASE_SHA,
            'ubuntu_run': m.HOSTS['ubuntu'][0],
            'ubuntu_job': m.HOSTS['ubuntu'][1],
            'windows_run': m.HOSTS['windows'][0],
            'windows_job': m.HOSTS['windows'][1],
            'candidate_table_arn': 'arn:aws:dynamodb:us-east-1:123456789012:table/ClaimedFencing',
            'consistency': 'MRSC', 'ttl_configured': False,
            'ttl_support_claimed': False, 'ttl_expiry_releases_fence': False,
            'expired_item_deletion_observed': False,
            'expiry_candidate_kind': kind,
            'expiry_candidate_sha256': None if kind == 'NONE' else 'a'*64,
            'fence_epoch': 8, 'fence_generation': 13,
            'claim_time_authenticated': False, 'claim_cas_durable': False,
            'claim_admin_independent': False, 'claim_remote_ack_authenticated': False}


class MRSCTTLBoundary(unittest.TestCase):
    def test_01_actual_tur67_subjects_and_all_eight_stay_blocked(self):
        self.assertEqual(m.HOSTS['ubuntu'], (44709467778, 136197181580))
        self.assertEqual(m.HOSTS['windows'], (44709467752, 136197179925))
        q = m.quarantine_ttl_fence(candidate())
        self.assertEqual(q['external_gates_verified'], 0)
        self.assertEqual(q['external_required'], 8)
        self.assertEqual(q['auth'], 'NO-GO')
        self.assertFalse(q['ttl_configurable_for_mrsc'])

    def test_02_mrsc_ttl_expiration_cannot_release_a_fence(self):
        for field in ('ttl_configured', 'ttl_support_claimed',
                      'ttl_expiry_releases_fence', 'expired_item_deletion_observed'):
            c = candidate(); c[field] = True
            with self.assertRaisesRegex(m.TtlFenceBlocked,
                                        'mrsc_ttl_or_expiry_as_fencing_authority'):
                m.quarantine_ttl_fence(c)
        c = candidate(); c['consistency'] = 'MREC'
        with self.assertRaisesRegex(m.TtlFenceBlocked, 'only_mrsc_service_contract'):
            m.quarantine_ttl_fence(c)

    def test_03_candidate_timestamp_and_forged_trust_are_not_proof(self):
        for kind in m.EXPIRY_KINDS:
            q = m.quarantine_ttl_fence(candidate(kind))
            self.assertFalse(q['external_time_and_revocation_verified'])
            self.assertFalse(q['separate_admin_durable_cas_verified'])
        for field in ('claim_time_authenticated', 'claim_cas_durable',
                      'claim_admin_independent', 'claim_remote_ack_authenticated'):
            c = candidate(); c[field] = True
            with self.assertRaisesRegex(m.TtlFenceBlocked, 'self_asserted_external_authority'):
                m.quarantine_ttl_fence(c)
        c = candidate('RFC3161_CANDIDATE'); c['expiry_candidate_sha256'] = 'INVALID'
        with self.assertRaisesRegex(m.TtlFenceBlocked, 'expiry_candidate_digest'):
            m.quarantine_ttl_fence(c)

    def test_04_wrong_run_scope_extra_schema_ast_import_guard(self):
        c = candidate(); c['windows_job'] = c['ubuntu_job']
        with self.assertRaisesRegex(m.TtlFenceBlocked, 'actual_hosted_job_scope'):
            m.quarantine_ttl_fence(c)
        c = candidate(); c['extra_verified'] = True
        with self.assertRaisesRegex(m.TtlFenceBlocked, 'strict_schema'):
            m.quarantine_ttl_fence(c)
        path = ROOT/'safe_public_ci'/'ci_rc711_mrsc_ttl_fence_quarantine.py'
        tree = ast.parse(path.read_text(encoding='utf-8'))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(x.name for x in node.names)
            if isinstance(node, ast.ImportFrom):
                imports.add(node.module)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ('open','exec','eval','compile','__import__'))
        self.assertEqual(imports, {'hashlib', 'json', 're'})
        self.assertEqual(m.quarantine_ttl_fence(candidate())['candidate_digest_sha256'],
                         m.quarantine_ttl_fence(candidate())['candidate_digest_sha256'])


if __name__ == '__main__':
    unittest.main()
