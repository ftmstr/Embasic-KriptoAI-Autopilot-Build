"""RC709 focused checks: actual TUR65 run identities and real Rekor v2 time rule."""
import ast
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_rc709_rekor_v2_time_boundary as m


def case(platform='ubuntu', kind='NONE'):
    run, job = m.RUNS[platform]
    return {'repository': m.REPO, 'branch': m.BRANCH, 'head_sha': m.BASE_SHA,
            'platform': platform, 'run_id': run, 'job_id': job,
            'integrated_time': 0, 'kind': kind,
            'candidate_sha256': None if kind == 'NONE' else 'a'*64,
            'claim_time_authenticated': False,
            'claim_oob_witness_authenticated': False,
            'claim_provider_raw_authenticated': False}


class RekorV2TimeBoundary(unittest.TestCase):
    def test_01_both_actual_tur65_jobs_never_supply_trusted_time(self):
        for p, expected in [('ubuntu', (44626964180, 135923234434)),
                            ('windows', (44626964302, 135923235552))]:
            self.assertEqual(m.RUNS[p], expected)
            result = m.quarantine_rekor_time(case(p))
            self.assertEqual(result['external_verified'], 0)
            self.assertEqual(result['auth'], 'NO-GO')
    def test_02_integrated_time_nonzero_bool_and_wrong_source_rejected(self):
        for bad in (True, 1, -1, '0', None):
            c = case(); c['integrated_time'] = bad
            with self.assertRaisesRegex(m.TimestampBoundaryBlocked, 'rekor_v2_integrated_time_not_timestamp'):
                m.quarantine_rekor_time(c)
        for change in ({'head_sha': 'f'*40}, {'job_id': m.RUNS['windows'][1]},
                       {'run_id': 1}):
            c = case(); c.update(change)
            with self.assertRaisesRegex(m.TimestampBoundaryBlocked, 'source_run_job_scope'):
                m.quarantine_rekor_time(c)
    def test_03_rfc3161_and_c2sp_candidate_still_unverified(self):
        for kind in m.KINDS[1:]:
            p = m.quarantine_rekor_time(case('windows', kind))
            self.assertFalse(p['rfc3161_crypto_and_tsa_root_verified'])
            self.assertFalse(p['witness_crypto_and_independent_custody_verified'])
            self.assertEqual(p['live'], 'DISABLED')
        c = case(); c['candidate_sha256'] = 'f'*64
        with self.assertRaisesRegex(m.TimestampBoundaryBlocked, 'candidate_material_digest'):
            m.quarantine_rekor_time(c)
    def test_04_fake_trust_or_extra_authority_rejected_and_ast_safe(self):
        for key in ('claim_time_authenticated', 'claim_oob_witness_authenticated',
                    'claim_provider_raw_authenticated'):
            c = case(); c[key] = True
            with self.assertRaisesRegex(m.TimestampBoundaryBlocked, 'self_asserted_external_trust'):
                m.quarantine_rekor_time(c)
        c = case(); c['trusted'] = True
        with self.assertRaisesRegex(m.TimestampBoundaryBlocked, 'timestamp_schema'):
            m.quarantine_rekor_time(c)
        f = ROOT/'safe_public_ci'/'ci_rc709_rekor_v2_time_boundary.py'
        tree = ast.parse(f.read_text(encoding='utf-8'))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(x.name for x in node.names)
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {'open','exec','eval','compile','__import__'})
        self.assertEqual(imported, {'hashlib', 'json'})
        self.assertEqual(m.quarantine_rekor_time(case())['public_candidate_digest_sha256'],
                         m.quarantine_rekor_time(case())['public_candidate_digest_sha256'])


if __name__ == '__main__':
    unittest.main()
