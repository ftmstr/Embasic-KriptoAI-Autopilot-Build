"""RC705: capability evidence must not silently become authenticated proof."""
import ast
import hashlib
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_rc705_provider_proof_firewall as m

def d(x): return hashlib.sha256(x.encode('ascii')).hexdigest()
def claim(gate='provider_raw_ubuntu',material_type='GITHUB_JOB_LOG_PLAINTEXT'):
    islog=gate in m.RUN_JOBS
    r,j=m.RUN_JOBS[gate] if islog else (None,None)
    return {'repository':m.REPO,'branch':m.BRANCH,'source_sha':m.BASE_SHA,
            'gate':gate,'material_type':material_type,
            'material_sha256':d('candidate'), 'challenge_sha256':d('challenge'),
            'nonce_sha256':d('nonce'), 'subject_run':r, 'subject_job':j,
            'claim_authorized':False,'claim_provider_signed_raw_log':False,
            'claim_independent_custody':False,'claim_origin_verified':False}

def state():
    return {'source_sha':m.BASE_SHA,
            'table_arn':'arn:aws:dynamodb:us-east-1:123456789012:table/SyntheticFence',
            'epoch':5,'fence':12,'generation':6,
            'root_sha256':d('old root'),'request_id_sha256':d('original request')}

def observed(**updates):
    x=state();x.update({'provider_authenticated':False,'independent_restore_attested':False});x.update(updates)
    return x

class ProviderProofType(unittest.TestCase):
    def test_01_public_documentation_not_authority(self):
        p=m.procurement_matrix()
        self.assertEqual(len(p),8)
        self.assertTrue(all(x['status']=='BLOCKED' and not x['provider_observation_is_authority'] for x in p))
    def test_02_plaintext_job_log_cannot_be_provider_signature(self):
        x=m.classify_untrusted_candidate(claim())
        self.assertEqual(x['classification'],'READABLE_LOG_NOT_PROVIDER_SIGNED_RAW')
        self.assertEqual(x['external_gates_verified'],0)
    def test_03_artifact_attestation_does_not_sign_job_log(self):
        x=m.classify_untrusted_candidate(claim(material_type='GITHUB_ARTIFACT_SUBJECT_ATTESTATION'))
        self.assertEqual(x['classification'],'ARTIFACT_SUBJECT_NOT_PROVIDER_SIGNED_RAW_LOG')
        self.assertFalse(x['raw_log_provider_signature_verified'])
    def test_04_even_signature_candidate_lacks_independent_issuer(self):
        x=m.classify_untrusted_candidate(claim(material_type='PROVIDER_RAW_LOG_SIGNATURE_CANDIDATE'))
        self.assertEqual(x['classification'],'SIGNATURE_CANDIDATE_NO_INDEPENDENT_ISSUER_PIN')
        self.assertEqual(x['auth'],'NO-GO')
    def test_05_windows_run_and_job_exact_scope(self):
        c=claim('provider_raw_windows')
        self.assertEqual((c['subject_run'],c['subject_job']), (44384407494,135084924161))
        self.assertFalse(m.classify_untrusted_candidate(c)['raw_log_provider_signature_verified'])
        c['subject_job']=135084924784
        with self.assertRaisesRegex(m.ProofTypeBlocked,'wrong_provider_run_job_scope'):
            m.classify_untrusted_candidate(c)
    def test_06_cross_gate_splice_and_claimed_authority_rejected(self):
        c=claim();c['material_type']='REKOR_WITNESSED_CHECKPOINT_CANDIDATE'
        with self.assertRaisesRegex(m.ProofTypeBlocked,'evidence_type_downgrade_or_splice'):
            m.classify_untrusted_candidate(c)
        for flag in ('claim_authorized','claim_provider_signed_raw_log','claim_independent_custody','claim_origin_verified'):
            c=claim();c[flag]=True
            with self.assertRaisesRegex(m.ProofTypeBlocked,'self_asserted_external_authority'):
                m.classify_untrusted_candidate(c)
    def test_07_rekor_checkpoint_signature_does_not_supply_witness_history(self):
        for kind in m.PROOF_TYPES['witnessed_historical_merkle']:
            x=m.classify_untrusted_candidate(claim('witnessed_historical_merkle',kind))
            self.assertFalse(x['independent_witness_and_historical_root_verified'])
            self.assertEqual(x['external_gates_verified'],0)
    def test_08_mrsc_describe_table_and_cas_result_not_actual_restore_drill(self):
        for kind in m.PROOF_TYPES['separate_admin_durable_mrsc_cas']:
            x=m.classify_untrusted_candidate(claim('separate_admin_durable_mrsc_cas',kind))
            self.assertFalse(x['remote_mrsc_and_restore_fence_verified'])
    def test_09_nonce_replay_and_wrong_source(self):
        c=claim();c['nonce_sha256']=c['challenge_sha256']
        with self.assertRaisesRegex(m.ProofTypeBlocked,'nonce_reuse'):
            m.classify_untrusted_candidate(c)
        c=claim();c['source_sha']='a'*40
        with self.assertRaisesRegex(m.ProofTypeBlocked,'exact_repo_branch_source'):
            m.classify_untrusted_candidate(c)
    def test_10_matching_state_and_restore_table_reenrollment(self):
        same=m.classify_reported_restore(state(),observed())
        self.assertEqual(same['classification'],'MATCHING_CALLER_REPORTED_STATE_NOT_AWS_PROOF')
        self.assertEqual(same['external_gates_verified'],0)
        restored=m.classify_reported_restore(state(),observed(table_arn='arn:aws:dynamodb:us-east-1:123456789012:table/RestoredFence'))
        self.assertEqual(restored['classification'],'NEW_RESTORED_TABLE_REQUIRES_DIFFERENT_ADMIN_REENROLLMENT')
    def test_11_old_epoch_and_changed_fence_nonautomated(self):
        self.assertEqual(m.classify_reported_restore(state(),observed(fence=11))['classification'],'REPORTED_ROLLBACK_OR_OLD_SNAPSHOT_FENCE')
        x=m.classify_reported_restore(state(),observed(fence=13))
        self.assertEqual(x['classification'],'UNOBSERVED_INTERVENING_CHANGE_OR_REPLAY')
        self.assertFalse(x['multi_host_conditional_cas_observed'])
        with self.assertRaisesRegex(m.ProofTypeBlocked,'self_asserted_aws_provider_auth'):
            m.classify_reported_restore(state(),observed(provider_authenticated=True))
    def test_12_strict_import_guard_and_deterministic_proof_quarantine(self):
        source=(ROOT/'safe_public_ci'/'ci_rc705_provider_proof_firewall.py').read_text()
        node=ast.parse(source);imports=set()
        for n in ast.walk(node):
            if isinstance(n,ast.Import): imports.update(a.name for a in n.names)
            if isinstance(n,ast.ImportFrom):imports.add(n.module)
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name):
                self.assertNotIn(n.func.id,('open','eval','exec','compile','__import__'))
        self.assertEqual(imports,{'hashlib','hmac','json','re'})
        a=m.classify_untrusted_candidate(claim())['quarantine_sha256']
        b=m.classify_untrusted_candidate(claim())['quarantine_sha256']
        self.assertEqual(a,b)
        self.assertRegex(a,r'^[a-f0-9]{64}$')

if __name__=='__main__':unittest.main()
