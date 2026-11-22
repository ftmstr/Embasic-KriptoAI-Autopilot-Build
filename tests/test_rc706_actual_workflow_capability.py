"""RC706: exact *real* workflow file bytes and provider gap classification."""
import ast
import copy
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from safe_public_ci import ci_rc706_actual_workflow_capability as m


def snapshot():
    w={}
    for os,(path,sha) in m.WORKFLOWS.items():
        w[os]={'path':path,'git_blob_sha1':sha,
               'content':(ROOT/path).read_text(encoding='utf-8')}
    jobs={}
    for os,(run,job) in m.RUNS.items():
        jobs[os]={'run_id':run,'job_id':job,'head_sha':m.BASE_SHA,
                  'run_status':'completed','run_conclusion':'success',
                  'job_status':'completed','job_conclusion':'success',
                  'successful_steps':9,'total_steps':9,
                  'distinct_test_passes':3194,'rc705_test_passes':12,
                  'workflow_artifact_count':0}
    return {'repository':m.REPO,'branch':m.BRANCH,'source_sha':m.BASE_SHA,
            'workflows':w,'observed_jobs':jobs}

class RealWorkflowCapability(unittest.TestCase):
    def test_01_actual_workflow_bytes_are_both_pinned(self):
        q=snapshot();out=m.assess_hosted_capabilities(q)
        for os in ('ubuntu','windows'):
            self.assertEqual(m.git_blob_sha1(q['workflows'][os]['content'].encode()),m.WORKFLOWS[os][1])
            self.assertTrue(out['workflows'][os]['read_only_contents_permissions_observed'])
    def test_02_source_is_actual_prior_final_commit(self):
        out=m.assess_hosted_capabilities(snapshot())
        self.assertEqual(out['historical_jobs']['ubuntu']['job_id'],135726515869)
        self.assertEqual(out['historical_jobs']['windows']['job_id'],135726515350)
        self.assertEqual(out['external_gates_verified'],0)
    def test_03_plaintext_logs_do_not_mean_provider_signed_raw(self):
        out=m.assess_hosted_capabilities(snapshot())
        self.assertFalse(out['attested_artifact_is_original_raw_job_log'])
        self.assertTrue(all(not a['full_raw_log_provider_signature_present'] for a in out['historical_jobs'].values()))
        self.assertFalse(any(a['workflow_has_attestation_action'] for a in out['workflows'].values()))
    def test_04_exact_git_blob_tamper_detected(self):
        q=snapshot();q['workflows']['ubuntu']['content']+='\n'
        with self.assertRaisesRegex(m.CapabilityRejected,'protected_workflow_bytes_changed'):
            m.assess_hosted_capabilities(q)
    def test_05_wrong_git_blob_claim_detected(self):
        q=snapshot();q['workflows']['windows']['git_blob_sha1']='0'*40
        with self.assertRaisesRegex(m.CapabilityRejected,'protected_workflow_identity'):
            m.assess_hosted_capabilities(q)
    def test_06_wrong_os_run_job_or_sha_detected(self):
        for field,val in (('run_id',1),('job_id',1),('head_sha','a'*40)):
            q=snapshot();q['observed_jobs']['windows'][field]=val
            with self.assertRaisesRegex(m.CapabilityRejected,'run_job_exact_subject'):
                m.assess_hosted_capabilities(q)
    def test_07_inflated_ci_pass_count_not_accepted(self):
        q=snapshot();q['observed_jobs']['ubuntu']['distinct_test_passes']=3195
        with self.assertRaisesRegex(m.CapabilityRejected,'observed_job_scope'):
            m.assess_hosted_capabilities(q)
    def test_08_forged_false_success_rejected(self):
        q=snapshot();q['observed_jobs']['windows']['job_conclusion']='failure'
        with self.assertRaisesRegex(m.CapabilityRejected,'observed_ci_not_success'):
            m.assess_hosted_capabilities(q)
    def test_09_external_keys_and_admins_cannot_be_self_supplied(self):
        q=snapshot();q['owner_pin_verified']=True
        with self.assertRaisesRegex(m.CapabilityRejected,'snapshot_schema'):
            m.assess_hosted_capabilities(q)
        p=m.assess_hosted_capabilities(snapshot())
        self.assertFalse(p['oob_trust_roots_verified'])
        self.assertFalse(p['reliable_rekor_witness_verified'])
        self.assertFalse(p['mrsc_real_cas_verified'])
    def test_10_eight_actionable_gates_stay_blocked(self):
        p=m.assess_hosted_capabilities(snapshot())
        self.assertEqual(len(p['missing_independent_evidence']),8)
        self.assertTrue(all(x['status']=='BLOCKED' and x['next_external_action'] for x in p['missing_independent_evidence']))
        self.assertEqual(p['auth'],'NO-GO')
        self.assertEqual(p['net20'],'NOT_TESTED')
    def test_11_deterministic_digest_and_import_guard(self):
        a=m.assess_hosted_capabilities(snapshot());b=m.assess_hosted_capabilities(snapshot())
        self.assertEqual(a['acquisition_handoff_sha256'],b['acquisition_handoff_sha256'])
        tree=ast.parse((ROOT/'safe_public_ci'/'ci_rc706_actual_workflow_capability.py').read_text())
        imports=set()
        for n in ast.walk(tree):
            if isinstance(n,ast.Import):imports.update(z.name for z in n.names)
            if isinstance(n,ast.ImportFrom): imports.add(n.module)
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name):
                self.assertNotIn(n.func.id,('open','exec','eval','compile','__import__'))
        self.assertEqual(imports,{'hashlib','hmac','json','re'})

if __name__=='__main__':unittest.main()
