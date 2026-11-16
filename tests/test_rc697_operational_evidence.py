"""RC697/TUR54: real hosted observation pins and trust handoff fail-closed tests."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from safe_public_ci import ci_rc697_operational_evidence as gate

MANIFEST=json.loads((ROOT/'docs'/'RC697_TUR54_HOSTED_OPERATIONAL_OBSERVATIONS.json').read_text(encoding='utf-8'))
def H(x):return hashlib.sha256(str(x).encode('ascii')).hexdigest()
def mutate(fn):
    m=copy.deepcopy(MANIFEST)
    fn(m)
    return m

def req(platform='ubuntu',audience='OWNER',nonce='fresh'):
    return gate.make_handoff_request(MANIFEST,platform,H('independent challenge pending'),H(nonce),audience)

def claim(request=None):
    r=req() if request is None else request
    return {'gate':'owner_oob_key','request_sha256':gate.handoff_sha256(r),
            'controller':'operator_owner','domain':'claimed_owner_domain',
            'key_fingerprint_sha256':H('untrusted pk'),
            'claimed_signature_sha256':H('fake plausible signature'),
            'claimed_origin':'SELF_ASSERTED','verified':False,
            'trusted_time':False,'remote_cas':False,'remote_ack':False,
            'immutable_root':False}

class ActualObservationBoundaries(unittest.TestCase):
    def test_01_independently_observed_ubuntu_windows_snapshot(self):
        r=gate.inspect_snapshot(MANIFEST)
        self.assertEqual((r['hosted_observation_count'],r['verified_external_gates']),(2,0))
        self.assertFalse(r['authenticated'])
    def test_02_real_log_observation_sha256_values_in_scope(self):
        x=MANIFEST['observations']
        self.assertEqual(x[0]['decoded_log_utf8_sha256'],'4b5e6a8bfb8ba430709c53d4c473d8dbe99a33a62f7e95eff32b8e12bec4355a')
        self.assertEqual(x[1]['decoded_log_utf8_sha256'],'3955877ecedfb8f0deb4cb741cf263de9cfc154187e8b3abe7ad3e50f35ffed7')
    def test_03_eight_explicit_external_gates_blocked(self):
        self.assertEqual(len(gate.observation_plan()),8)
        self.assertTrue(all(x['status']=='BLOCKED' and not x['verified'] for x in gate.observation_plan()))
        self.assertTrue(all(x['required_external'] for x in gate.observation_plan()))
    def test_04_untrusted_synthetic_example_cannot_replay_real_log_digest(self):
        a='claimed raw log'; o=MANIFEST['observations'][0]
        self.assertNotEqual(hashlib.sha256(a.encode()).hexdigest(),o['decoded_log_utf8_sha256'])
    def test_05_manual_false_provider_signed_claim_rejected(self):
        m=mutate(lambda m:m['observations'][0].__setitem__('provider_signature_verified',True))
        with self.assertRaisesRegex(gate.EvidenceRejected,'provider_signature_not_available'):gate.inspect_snapshot(m)
    def test_06_wrong_provider_run_rejected(self):
        m=mutate(lambda m:m['observations'][0].__setitem__('run',1))
        with self.assertRaisesRegex(gate.EvidenceRejected,'historical_observation_pin'):gate.inspect_snapshot(m)
    def test_07_wrong_provider_job_rejected(self):
        m=mutate(lambda m:m['observations'][1].__setitem__('job',1))
        with self.assertRaisesRegex(gate.EvidenceRejected,'historical_observation_pin'):gate.inspect_snapshot(m)
    def test_08_wrong_workflow_blob_rejected(self):
        m=mutate(lambda m:m['observations'][1].__setitem__('workflow_blob_sha','a'*40))
        with self.assertRaisesRegex(gate.EvidenceRejected,'historical_observation_pin'):gate.inspect_snapshot(m)
    def test_09_fake_success_while_step_skipped_rejected(self):
        m=mutate(lambda m:m['observations'][0].__setitem__('step_success',8))
        with self.assertRaisesRegex(gate.EvidenceRejected,'hosted_ci_observation'):gate.inspect_snapshot(m)
    def test_10_false_three_thousand_tests_rejected(self):
        m=mutate(lambda m:m['observations'][0].__setitem__('test_pass',3003))
        with self.assertRaisesRegex(gate.EvidenceRejected,'hosted_ci_observation'):gate.inspect_snapshot(m)
    def test_11_no_artifact_is_not_provider_signature(self):
        self.assertEqual([x['artifact_count'] for x in MANIFEST['observations']],[0,0])
        self.assertFalse(gate.inspect_snapshot(MANIFEST)['original_raw_log_signature_verified'])
    def test_12_artifact_claim_changes_rejected(self):
        m=mutate(lambda m:m['observations'][1].__setitem__('artifact_count',1))
        with self.assertRaisesRegex(gate.EvidenceRejected,'provider_signature_not_available'):gate.inspect_snapshot(m)
    def test_13_same_run_job_cross_os_replay_rejected(self):
        m=mutate(lambda m:m['observations'][1].update({'run':m['observations'][0]['run'],'job':m['observations'][0]['job'],'attempt':1}))
        with self.assertRaisesRegex(gate.EvidenceRejected,'duplicate_job'):gate.inspect_snapshot(m)
    def test_14_replayed_digest_cross_os_rejected(self):
        m=mutate(lambda m:m['observations'][1].__setitem__('decoded_log_utf8_sha256',m['observations'][0]['decoded_log_utf8_sha256']))
        with self.assertRaisesRegex(gate.EvidenceRejected,'duplicate_log'):gate.inspect_snapshot(m)
    def test_15_privileged_rollback_to_old_sha_rejected(self):
        m=mutate(lambda m:m.__setitem__('source_sha','a'*40))
        with self.assertRaisesRegex(gate.EvidenceRejected,'source_scope'):gate.inspect_snapshot(m)
    def test_16_promoted_live_or_release_flag_rejected(self):
        for field in ('release_allowed','live_allowed'):
            m=mutate(lambda m:m.__setitem__(field,True))
            with self.assertRaisesRegex(gate.EvidenceRejected,'forged_trust_promotion'):gate.inspect_snapshot(m)
    def test_17_missing_authority_data_no_datetime_fallback(self):
        m=mutate(lambda m:m.__setitem__('trusted_at','2026-11-16T00:00Z'))
        with self.assertRaisesRegex(gate.EvidenceRejected,'forged_trust_promotion'):gate.inspect_snapshot(m)
    def test_18_ubuntu_and_windows_handoff_distinct(self):
        self.assertNotEqual(gate.handoff_sha256(req('ubuntu')),gate.handoff_sha256(req('windows')))
    def test_19_challenge_and_nonce_replay_change_scope(self):
        self.assertNotEqual(gate.handoff_sha256(req(nonce='one')),gate.handoff_sha256(req(nonce='two')))
    def test_20_audience_change_changes_scope(self):
        self.assertNotEqual(gate.handoff_sha256(req(audience='OWNER')),gate.handoff_sha256(req(audience='INDEPENDENT_REVIEWER')))
    def test_21_fake_manifest_field_rejected(self):
        m=mutate(lambda m:m.__setitem__('real_provider_signed',True))
        with self.assertRaisesRegex(gate.EvidenceRejected,'manifest_schema'):gate.inspect_snapshot(m)
    def test_22_handoff_source_branch_scope_immutable(self):
        r=req(); r['branch']='main'
        with self.assertRaisesRegex(gate.EvidenceRejected,'request_scope'):gate.handoff_sha256(r)
    def test_23_handoff_job_replay_rejected(self):
        r=req();r['job']+=1
        with self.assertRaisesRegex(gate.EvidenceRejected,'request_observation_pin'):gate.handoff_sha256(r)
    def test_24_synthetic_fake_quorum_never_authenticates(self):
        r=req(); result=gate.inspect_untrusted_candidate(claim(r),r)
        self.assertFalse(result['owner_reviewer_authorized'])
        self.assertEqual(result['external_verified'],0)
    def test_25_fake_remote_ack_or_cas_rejected(self):
        for field in ('remote_ack','remote_cas','immutable_root','trusted_time','verified'):
            r=req();c=claim(r);c[field]=True
            with self.assertRaisesRegex(gate.EvidenceRejected,'forged_external_authority'):
                gate.inspect_untrusted_candidate(c,r)
    def test_26_fake_provider_origin_rejected(self):
        r=req(); c=claim(r);c['claimed_origin']='GITHUB_SIGNED'
        with self.assertRaisesRegex(gate.EvidenceRejected,'forged_provider_origin'):
            gate.inspect_untrusted_candidate(c,r)
    def test_27_replayed_request_digest_rejected(self):
        r=req(); c=claim(r);c['request_sha256']=H('old request')
        with self.assertRaisesRegex(gate.EvidenceRejected,'request_replay'):
            gate.inspect_untrusted_candidate(c,r)
    def test_28_extra_candidate_authentication_field_rejected(self):
        r=req();c=claim(r);c['authenticated']=True
        with self.assertRaisesRegex(gate.EvidenceRejected,'candidate_schema'):
            gate.inspect_untrusted_candidate(c,r)
    def test_29_decoded_log_mismatch_byte_length_fails_closed(self):
        x=MANIFEST.copy()
        with self.assertRaisesRegex(gate.EvidenceRejected,'decoded_log_length'):
            gate.inspect_snapshot(x,{'ubuntu':'fake','windows':'fake'})
    def test_30_no_network_io_or_unauthorized_imports(self):
        path=ROOT/'safe_public_ci'/'ci_rc697_operational_evidence.py'
        tree=ast.parse(path.read_text(encoding='utf-8'))
        imports=set()
        for n in ast.walk(tree):
            if isinstance(n,ast.Import):imports.update(a.name for a in n.names)
            if isinstance(n,ast.ImportFrom):imports.add(n.module)
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name):
                self.assertNotIn(n.func.id,('open','eval','exec','compile','__import__'))
        self.assertEqual(imports,{'hashlib','hmac','json','re'})

if __name__=='__main__':unittest.main()
