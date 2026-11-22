"""RC713: AWS provider MRSC same-account vs cross-account MREC safety guard."""
import ast
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_rc713_mrsc_same_account_boundary as m


def candidate():
    return {
        'repository': m.REPOSITORY, 'branch': m.BRANCH, 'source_sha': m.SOURCE_SHA,
        'ubuntu_run': m.HOSTED['ubuntu'][0], 'ubuntu_job': m.HOSTED['ubuntu'][1],
        'windows_run': m.HOSTED['windows'][0], 'windows_job': m.HOSTED['windows'][1],
        'consistency_mode': 'MRSC', 'account_model': 'SAME_ACCOUNT',
        'replica_table_arns': [
            'arn:aws:dynamodb:us-east-1:123456789012:table/FencingTable',
            'arn:aws:dynamodb:us-east-2:123456789012:table/FencingTable'],
        'witness_region': 'us-west-2',
        'claimed_provider_response_sha256': 'a' * 64,
        'request_id_sha256': 'b' * 64,
        'claims_aws_describe_authenticated': False,
        'claims_distinct_admin_roles_verified': False,
        'claims_independent_oob_reviewer': False,
        'claims_two_host_durable_cas': False,
        'claims_restore_antireplay_verified': False,
        'claims_remote_recipient_ack_authenticated': False,
    }


class MRSCMultiAccountNoGo(unittest.TestCase):
    def test_01_actual_tur69_subject_and_same_account_still_zero_evidence(self):
        self.assertEqual(m.HOSTED['ubuntu'], (44840891682, 136648671157))
        self.assertEqual(m.HOSTED['windows'], (44840891793, 136648670967))
        x = m.quarantine_same_account_mrsc(candidate())
        self.assertEqual(x['external_gates_verified'], 0)
        self.assertEqual(x['auth'], 'NO-GO')
        self.assertFalse(x['aws_resource_or_admin_custody_verified'])
    def test_02_cross_account_mrec_downgrade_and_mode_claim_rejected(self):
        x = candidate()
        x['replica_table_arns'][1] = 'arn:aws:dynamodb:us-east-2:999999999999:table/FencingTable'
        with self.assertRaisesRegex(m.MRSCAccountBoundaryBlocked, 'mrsc_replica_aws_accounts_must_match'):
            m.quarantine_same_account_mrsc(x)
        x = candidate(); x['account_model'] = 'MULTI_ACCOUNT'
        with self.assertRaisesRegex(m.MRSCAccountBoundaryBlocked, 'mrsc_multi_account_not_supported'):
            m.quarantine_same_account_mrsc(x)
        x = candidate(); x['consistency_mode'] = 'MREC'
        with self.assertRaisesRegex(m.MRSCAccountBoundaryBlocked, 'mrec_cannot_supply_strong_cas'):
            m.quarantine_same_account_mrsc(x)
    def test_03_global_replicas_same_name_and_region_scope(self):
        x = candidate(); x['replica_table_arns'][1] = 'arn:aws:dynamodb:us-east-2:123456789012:table/WrongTable'
        with self.assertRaisesRegex(m.MRSCAccountBoundaryBlocked, 'global_replica_table_name_must_match'):
            m.quarantine_same_account_mrsc(x)
        x = candidate(); x['witness_region'] = 'us-west-1'
        with self.assertRaisesRegex(m.MRSCAccountBoundaryBlocked, 'mrsc_supported_region'):
            m.quarantine_same_account_mrsc(x)
        x = candidate()
        x['replica_table_arns'].append('arn:aws:dynamodb:us-west-2:123456789012:table/FencingTable')
        x['witness_region'] = None
        self.assertEqual(m.quarantine_same_account_mrsc(x)['external_gates_verified'], 0)
        self.assertEqual(len(m.SUPPORTED_MRSC_REGIONS), 15)
        x = candidate()
        x['replica_table_arns'] = [
            'arn:aws:dynamodb:ca-central-1:123456789012:table/FencingTable',
            'arn:aws:dynamodb:eu-north-1:123456789012:table/FencingTable']
        x['witness_region'] = 'ap-southeast-1'
        self.assertEqual(m.quarantine_same_account_mrsc(x)['external_gates_verified'], 0)
        x['replica_table_arns'][1] = 'arn:aws:dynamodb:eu-central-2:123456789012:table/FencingTable'
        with self.assertRaisesRegex(m.MRSCAccountBoundaryBlocked, 'mrsc_supported_region'):
            m.quarantine_same_account_mrsc(x)
    def test_04_untrusted_admin_claims_exact_scope_and_ast_import(self):
        for key in ('claims_aws_describe_authenticated', 'claims_distinct_admin_roles_verified',
                    'claims_independent_oob_reviewer', 'claims_two_host_durable_cas',
                    'claims_restore_antireplay_verified', 'claims_remote_recipient_ack_authenticated'):
            x = candidate(); x[key] = True
            with self.assertRaisesRegex(m.MRSCAccountBoundaryBlocked, 'self_asserted_provider_or_admin_proof'):
                m.quarantine_same_account_mrsc(x)
        x = candidate(); x['windows_job'] = x['ubuntu_job']
        with self.assertRaisesRegex(m.MRSCAccountBoundaryBlocked, 'exact_original_hosted_job'):
            m.quarantine_same_account_mrsc(x)
        x = candidate(); x['extra_authority'] = True
        with self.assertRaisesRegex(m.MRSCAccountBoundaryBlocked, 'strict_schema'):
            m.quarantine_same_account_mrsc(x)
        path = ROOT/'safe_public_ci'/'ci_rc713_mrsc_same_account_boundary.py'
        tree = ast.parse(path.read_text(encoding='utf-8'))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name for a in node.names)
            if isinstance(node, ast.ImportFrom):
                imports.add(node.module)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {'eval', 'exec', 'open', 'compile', '__import__'})
        self.assertEqual(imports, {'hashlib', 'json', 're'})
        self.assertEqual(m.quarantine_same_account_mrsc(candidate())['request_sha256_not_a_signature'],
                         m.quarantine_same_account_mrsc(candidate())['request_sha256_not_a_signature'])


if __name__ == '__main__':
    unittest.main()
