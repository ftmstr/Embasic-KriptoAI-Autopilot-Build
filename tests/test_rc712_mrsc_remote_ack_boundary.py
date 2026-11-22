"""RC712 focused provider-specific remote recipient proof downgrade checks."""
import ast
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_rc712_mrsc_remote_ack_boundary as m


def candidate(kind='MRSC_CONDITIONAL_WRITE_RESULT'):
    return {'repository': m.REPO, 'branch': m.BRANCH, 'head_sha': m.BASE_SHA,
            'ubuntu_run': m.HOSTS['ubuntu'][0], 'ubuntu_job': m.HOSTS['ubuntu'][1],
            'windows_run': m.HOSTS['windows'][0], 'windows_job': m.HOSTS['windows'][1],
            'replica_regions': ['us-east-1', 'us-east-2'],
            'witness_region': 'us-west-2', 'material_type': kind,
            'material_sha256': 'a'*64, 'request_id_sha256': 'b'*64,
            'claims_independent_recipient_auth': False,
            'claims_durable_cas': False, 'claims_external_time': False,
            'claims_provider_original_raw_log': False}


class RemoteRecipientNonEquivalence(unittest.TestCase):
    def test_01_actual_tur68_hosted_run_identity_and_no_external_promotion(self):
        self.assertEqual(m.HOSTS['ubuntu'], (44712263026, 136206625554))
        self.assertEqual(m.HOSTS['windows'], (44712262558, 136206624211))
        for kind in ('MRSC_CONDITIONAL_WRITE_RESULT', 'MRSC_STREAM_RECORD',
                     'RECIPIENT_SIGNED_ACK_CANDIDATE'):
            result = m.inspect_candidate(candidate(kind))
            self.assertEqual(result['external_gates_verified'], 0)
            self.assertEqual(result['auth'], 'NO-GO')
            self.assertFalse(result['remote_recipient_identity_and_signature_verified'])

    def test_02_mrsc_has_no_replication_latency_metric_or_readable_witness(self):
        for kind, error in (('CLOUDWATCH_REPLICATION_LATENCY',
                             'mrsc_does_not_publish_replication_latency'),
                            ('MRSC_WITNESS_READ_RESULT',
                             'mrsc_witness_cannot_be_read_or_written')):
            with self.assertRaisesRegex(m.RecipientAckBlocked, error):
                m.inspect_candidate(candidate(kind))

    def test_03_unsupported_region_and_self_attested_ack_rejected(self):
        for regions, witness in ((['us-east-1', 'eu-west-1'], 'af-south-1'),
                                 (['us-east-1', 'us-east-2'], 'us-west-1')):
            value = candidate(); value['replica_regions'] = regions
            value['witness_region'] = witness
            with self.assertRaisesRegex(m.RecipientAckBlocked,
                                        'unsupported_mrsc_region'):
                m.inspect_candidate(value)
        value = candidate(); value['replica_regions'] = ['eu-west-1', 'eu-west-2']
        value['witness_region'] = 'eu-central-1'
        self.assertEqual(m.inspect_candidate(value)['external_gates_verified'], 0)
        # AWS 2026-09-23: cross-continent topology is now supported.
        self.assertEqual(len(m.SUPPORTED_MRSC_REGIONS), 15)
        value = candidate(); value['replica_regions'] = ['us-east-1', 'eu-west-1']
        value['witness_region'] = 'ap-south-1'
        self.assertEqual(m.inspect_candidate(value)['external_gates_verified'], 0)
        value = candidate(); value['replica_regions'] = ['ca-central-1', 'eu-south-2']
        value['witness_region'] = 'ap-southeast-1'
        self.assertEqual(m.inspect_candidate(value)['external_gates_verified'], 0)
        for key in ('claims_independent_recipient_auth', 'claims_durable_cas',
                    'claims_external_time', 'claims_provider_original_raw_log'):
            value = candidate(); value[key] = True
            with self.assertRaisesRegex(m.RecipientAckBlocked,
                                        'self_asserted_third_party_authority'):
                m.inspect_candidate(value)

    def test_04_replay_scope_import_ast_and_deterministic_digest(self):
        for field in ('ubuntu_job', 'windows_run'):
            value = candidate(); value[field] = 1
            with self.assertRaisesRegex(m.RecipientAckBlocked, 'actual_hosted_jobs'):
                m.inspect_candidate(value)
        value = candidate(); value['extra_verified'] = True
        with self.assertRaisesRegex(m.RecipientAckBlocked, 'strict_schema'):
            m.inspect_candidate(value)
        tree = ast.parse((ROOT/'safe_public_ci'/'ci_rc712_mrsc_remote_ack_boundary.py').read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            if isinstance(node, ast.ImportFrom):
                imports.add(node.module)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ('eval','exec','open','compile','__import__'))
        self.assertEqual(imports, {'hashlib', 'json'})
        self.assertEqual(m.inspect_candidate(candidate())['untrusted_request_sha256'],
                         m.inspect_candidate(candidate())['untrusted_request_sha256'])


if __name__ == '__main__':
    unittest.main()
