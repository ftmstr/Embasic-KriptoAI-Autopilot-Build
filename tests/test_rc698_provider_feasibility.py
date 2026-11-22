"""RC698/TUR55 targeted independent-provider feasibility and fail-closed tests."""
import ast
import copy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from safe_public_ci import ci_rc698_provider_feasibility as f

def H(s):return hashlib.sha256(str(s).encode('ascii')).hexdigest()
def packet():
    q=f.make_challenge(H('untrusted challenge'),H('nonce separate'),'EXTERNAL_SECURITY_AUDITOR')
    d=f.challenge_digest(q)
    p=[{'gate':gate,'route':f.ACCEPTABLE_PILOT[gate],
        'controller':'controller_%02d'%i,'failure_domain':'domain_%02d'%i,
        'source_sha':f.BASE_SHA,'request_sha256':d,
        'claimed_verified':False,'origin':'SELF_ASSERTED',
        'external_proof_sha256':None} for i,gate in enumerate(f.GATES)]
    return q,p

class ExternalCapabilityCases(unittest.TestCase):
    def test_01_eight_external_gates_still_blocked(self):
        p=f.acquisition_matrix()
        self.assertEqual(len(p),8)
        self.assertTrue(all(r['status']=='BLOCKED' and not r['actual_external_verified'] for r in p))
    def test_02_exact_tur54_source_scope(self):
        self.assertEqual(f.BASE_SHA,'7939a9a81932a8307e9155edfa44cb772e1062a2')
        self.assertEqual(f.REPO,'ftmstr/Embasic-KriptoAI-Autopilot-Build')
    def test_03_valid_pilot_all_blocked(self):
        q,p=packet();out=f.evaluate_routes(q,p)
        self.assertEqual((out['real_external_gate_count'],out['candidate_count']),(0,8))
        self.assertFalse(out['raw_logs_provider_signed'])
        self.assertTrue(all(v['status']=='BLOCKED' for v in out['blocked_gates']))
    def test_04_github_job_download_is_not_signed_full_log(self):
        q,p=packet();p[2]['route']='GITHUB_JOB_LOG_DOWNLOAD'
        self.assertEqual(f.evaluate_routes(q,p)['blocked_gates'][2]['reason'],
                         'GITHUB_READABLE_LOG_NOT_SIGNED_PROVIDER_ATTESTATION')
    def test_05_artifact_attestation_is_not_raw_job_log(self):
        q,p=packet();p[3]['route']='GITHUB_ARTIFACT_ATTESTATION'
        self.assertEqual(f.evaluate_routes(q,p)['blocked_gates'][3]['reason'],
                         'ARTIFACT_SUBJECT_NOT_SIGNED_RAW_FULL_JOB_LOG')
    def test_06_rekor_entry_not_identity_authorization(self):
        q,p=packet();p[5]['route']='SIGSTORE_REKOR_ENTRY'
        self.assertEqual(f.evaluate_routes(q,p)['blocked_gates'][5]['reason'],
                         'TRANSPARENCY_ENTRY_NOT_SUBJECT_SIGNER_AUTHORITY')
    def test_07_rekor_set_promise_not_inclusion(self):
        q,p=packet();p[5]['route']='REKOR_SIGNED_ENTRY_TIMESTAMP'
        self.assertEqual(f.evaluate_routes(q,p)['blocked_gates'][5]['reason'],
                         'SET_PROMISE_NOT_INCLUSION_OR_GOSSIP_PROOF')
    def test_08_dynamodb_global_mrec_lww_not_cas(self):
        q,p=packet();p[6]['route']='DYNAMODB_MREC_GLOBAL_TABLES'
        self.assertEqual(f.evaluate_routes(q,p)['blocked_gates'][6]['reason'],
                         'MREC_LAST_WRITER_WINS_NOT_CROSS_REGION_LINEARIZABLE')
    def test_09_sqlite_restore_not_crosshost_cas(self):
        q,p=packet();p[6]['route']='LOCAL_SQLITE'
        self.assertEqual(f.evaluate_routes(q,p)['blocked_gates'][6]['reason'],
                         'LOCAL_SNAPSHOT_RESTORE_NOT_INDEPENDENT_CAS')
    def test_10_unpinned_timestamp_and_remote_ack_not_trust(self):
        q,p=packet();p[4]['route']='RFC3161_UNPINNED_TIME';p[7]['route']='FAKE_RECIPIENT_ACK'
        out=f.evaluate_routes(q,p)
        self.assertEqual(out['blocked_gates'][4]['reason'],'TIMESTAMP_SHAPE_NOT_TRUSTED_CLOCK')
        self.assertEqual(out['blocked_gates'][7]['reason'],'LOCAL_ACK_NOT_AUTHENTICATED_RECIPIENT')
    def test_11_claimed_key_roles_not_proven(self):
        q,p=packet();p[0]['route']='SELF_ASSERTED_SIGNER'
        self.assertEqual(f.evaluate_routes(q,p)['blocked_gates'][0]['reason'],
                         'LABEL_NOT_INDEPENDENT_ED25519_KEY_PROVENANCE')
    def test_12_fake_verification_flag_denied(self):
        q,p=packet();p[0]['claimed_verified']=True
        with self.assertRaisesRegex(f.CapabilityRejected,'untrusted_auth_promotion'):f.evaluate_routes(q,p)
    def test_13_forged_provider_origin_denied(self):
        q,p=packet();p[2]['origin']='GITHUB_SIGNED'
        with self.assertRaisesRegex(f.CapabilityRejected,'fake_origin'):f.evaluate_routes(q,p)
    def test_14_fake_quorum_same_domain_denied(self):
        q,p=packet();p[1]['failure_domain']=p[0]['failure_domain']
        with self.assertRaisesRegex(f.CapabilityRejected,'fake_quorum_domain'):f.evaluate_routes(q,p)
    def test_15_challenge_nonce_replay_denied(self):
        with self.assertRaisesRegex(f.CapabilityRejected,'challenge_nonce_replay'):
            f.make_challenge(H('same'),H('same'),'OWNER')
    def test_16_old_challenge_request_denied(self):
        q,p=packet();p[7]['request_sha256']=H('replayed old request')
        with self.assertRaisesRegex(f.CapabilityRejected,'challenge_replay'):f.evaluate_routes(q,p)
    def test_17_privileged_old_source_rollback_denied(self):
        q,p=packet();p[6]['source_sha']='a'*40
        with self.assertRaisesRegex(f.CapabilityRejected,'source_replay'):f.evaluate_routes(q,p)
    def test_18_external_fake_proof_hash_denied(self):
        q,p=packet();p[5]['external_proof_sha256']=H('claimed proof')
        with self.assertRaisesRegex(f.CapabilityRejected,'unverified_proof_injection'):f.evaluate_routes(q,p)
    def test_19_unknown_provider_route_denied(self):
        q,p=packet();p[5]['route']='MAGIC_SIGNER'
        with self.assertRaisesRegex(f.CapabilityRejected,'unknown_route'):f.evaluate_routes(q,p)
    def test_20_untrusted_nonce_audience_scope_bound(self):
        q,p=packet();d=f.challenge_digest(q)
        q['audience']='OWNER'
        self.assertNotEqual(d,f.challenge_digest(q))
    def test_21_one_missing_gate_denied(self):
        q,p=packet();p.pop()
        with self.assertRaisesRegex(f.CapabilityRejected,'proposal_cardinality'):f.evaluate_routes(q,p)
    def test_22_boolean_type_confusion_denied(self):
        q,p=packet();q['max_replies']=True
        with self.assertRaisesRegex(f.CapabilityRejected,'request_cardinality'):f.evaluate_routes(q,p)
    def test_23_schema_injection_denied(self):
        q,p=packet();p[2]['authenticated']=True
        with self.assertRaisesRegex(f.CapabilityRejected,'proposal_schema'):f.evaluate_routes(q,p)
    def test_24_stdlib_only_ast_no_io_and_no_trading(self):
        t=ast.parse((ROOT/'safe_public_ci'/'ci_rc698_provider_feasibility.py').read_text())
        imp=set()
        for n in ast.walk(t):
            if isinstance(n,ast.Import):imp.update(a.name for a in n.names)
            if isinstance(n,ast.ImportFrom):imp.add(n.module)
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name):
                self.assertNotIn(n.func.id,('open','eval','exec','compile','__import__'))
        self.assertEqual(imp,{'hashlib','hmac','json','re'})

if __name__=='__main__':unittest.main()
