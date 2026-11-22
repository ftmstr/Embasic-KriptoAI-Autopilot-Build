"""RC710 targeted AWS PITR/MRSC documentation-based no-trust regression."""
import ast
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_rc710_mrsc_pitr_restore_boundary as m


def candidate():
    return {
        'repository': m.REPO, 'branch': m.BRANCH, 'source_sha': m.BASE_SHA,
        'ubuntu_run': m.HOSTS['ubuntu'][0], 'ubuntu_job': m.HOSTS['ubuntu'][1],
        'windows_run': m.HOSTS['windows'][0], 'windows_job': m.HOSTS['windows'][1],
        'original_table_arn': 'arn:aws:dynamodb:us-east-1:123456789012:table/FenceOriginal',
        'pitr_restored_table_arn': 'arn:aws:dynamodb:us-east-1:123456789012:table/FenceRestored',
        'candidate_mrsc_table_arn': 'arn:aws:dynamodb:us-east-1:123456789012:table/FenceNewEmpty',
        'reported_restored_item_count': 16,
        'migration_method': 'NEW_EMPTY_MRSC_THEN_CONTROLLED_DATA_COPY',
        'prior_epoch': 7, 'prior_fence': 11, 'candidate_epoch': 8,
        'candidate_fence': 12,
        'provider_provisioning_authenticated': False,
        'separate_admin_reenrollment_authenticated': False,
        'two_host_cas_authenticated': False,
        'restored_data_copy_authenticated': False,
        'remote_recipient_ack_authenticated': False}


class RestoredMRSCGate(unittest.TestCase):
    def test_01_direct_populated_pitr_to_mrsc_always_rejected(self):
        a = candidate()
        a['migration_method'] = 'POPULATED_PITR_DIRECT_MRSC_CONVERSION'
        with self.assertRaisesRegex(m.RestoreBoundaryBlocked,
                                    'populated_pitr_cannot_convert_directly_to_mrsc'):
            m.classify_pitr_mrsc_recovery(a)

    def test_02_distinct_new_empty_mrsc_path_remains_blocked(self):
        r = m.classify_pitr_mrsc_recovery(candidate())
        self.assertEqual(r['independent_external_gates_verified'], 0)
        self.assertEqual(r['auth'], 'NO-GO')
        self.assertFalse(r['new_empty_mrsc_provisioned_and_verified'])
        self.assertFalse(r['remote_recipient_idempotent_ack_verified'])
        self.assertEqual(r['request_digest_sha256'],
                         m.classify_pitr_mrsc_recovery(candidate())['request_digest_sha256'])

    def test_03_cannot_reuse_table_or_fence_or_self_verify(self):
        for k in ('original_table_arn', 'pitr_restored_table_arn'):
            a = candidate(); a['candidate_mrsc_table_arn'] = a[k]
            with self.assertRaisesRegex(m.RestoreBoundaryBlocked,
                                        'new_empty_mrsc_target_identity_required'):
                m.classify_pitr_mrsc_recovery(a)
        for k, v in (('candidate_epoch', 7), ('candidate_fence', 11),
                     ('candidate_epoch', True)):
            a = candidate(); a[k] = v
            with self.assertRaises(m.RestoreBoundaryBlocked):
                m.classify_pitr_mrsc_recovery(a)
        for field in ('provider_provisioning_authenticated',
                      'separate_admin_reenrollment_authenticated',
                      'two_host_cas_authenticated',
                      'restored_data_copy_authenticated',
                      'remote_recipient_ack_authenticated'):
            a = candidate(); a[field] = True
            with self.assertRaisesRegex(m.RestoreBoundaryBlocked,
                                        'self_asserted_independent_service_proof'):
                m.classify_pitr_mrsc_recovery(a)

    def test_04_exact_tur66_jobs_and_read_only_ast(self):
        a = candidate(); a['windows_job'] = a['ubuntu_job']
        with self.assertRaisesRegex(m.RestoreBoundaryBlocked,
                                    'original_hosted_job_scope'):
            m.classify_pitr_mrsc_recovery(a)
        a = candidate(); a['extra_authorized'] = True
        with self.assertRaisesRegex(m.RestoreBoundaryBlocked, 'restore_schema'):
            m.classify_pitr_mrsc_recovery(a)
        tree = ast.parse((ROOT/'safe_public_ci'/'ci_rc710_mrsc_pitr_restore_boundary.py').read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(k.name for k in node.names)
            if isinstance(node, ast.ImportFrom):
                imports.add(node.module)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ('open', 'exec', 'eval', 'compile', '__import__'))
        self.assertEqual(imports, {'hashlib', 'json', 're'})


if __name__ == '__main__':
    unittest.main()
