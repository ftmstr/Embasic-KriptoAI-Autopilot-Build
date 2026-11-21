"""RC695/TUR52: new synthetic-only external evidence acquisition adversaries."""
import ast
import copy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from safe_public_ci import ci_rc695_external_acquisition_boundary as a

SHA='f3c377d71bc6d3e3fdad871aba070e2411576bef'

def H(s):return hashlib.sha256(str(s).encode('ascii')).hexdigest()

def fixture():
    req=a.acquisition_requests(SHA,H('independently-UNVERIFIED-challenge'),100,
                               (43637641205,132577872873,1),
                               (43637641171,132577872781,1))
    observations=[]
    for i,r in enumerate(req):
        observations.append({'gate':r['gate'],'proof_type':r['proof_type'],
           'controller':'operator_%02d'%i,'domain':'claimed_domain_%02d'%i,
           'source_sha':SHA,'challenge_sha':r['challenge_sha'],
           'payload_sha':H('whole-bytes-not-proven-%d'%i),
           'signature_sha':H('untrusted-signature-%d'%i),
           'run':r['run'],'job':r['job'],'attempt':r['attempt'],'epoch':100,
           'generation':15,'fence':25,'nonce_sha':H('nonce-%d'%i),
           'checkpoint_root':H('claimed-checkpoint'),
           'ack_id':'ack-remote-claimed' if i==7 else '',
           'claimed_origin':'SELF_ASSERTED','verified':False})
    return req,tuple(observations)

def mutated(observations,index,**changes):
    o=copy.deepcopy(observations);o[index].update(changes);return o

class AcquisitionContract(unittest.TestCase):
    def test_01_eight_real_external_evidence_requirements_remain_blocked(self):
        req,obs=fixture();self.assertEqual(len(req),8)
        self.assertEqual(tuple(x['gate'] for x in req),a.GATES)
        self.assertEqual(tuple(x['proof_type'] for x in req),a.PROOF_TYPES)
        self.assertTrue(all(x['status']=='BLOCKED' and not x['external_evidence_acquired'] for x in req))
        self.assertEqual(a.inspect_observations(req,obs)['external_verified'],0)
    def test_02_exact_real_hosted_identifiers_bound_as_unverified_claims(self):
        req,_=fixture()
        self.assertEqual((req[2]['run'],req[2]['job'],req[2]['attempt']),(43637641205,132577872873,1))
        self.assertEqual((req[3]['run'],req[3]['job'],req[3]['attempt']),(43637641171,132577872781,1))
        self.assertTrue(all(r['source_sha']==SHA for r in req))
    def test_03_fake_quorum_one_operator_repeated(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'fake_quorum_sybil',a.inspect_observations,q,mutated(o,1,controller=o[0]['controller']))
    def test_04_fake_quorum_one_domain_repeated(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'fake_quorum_sybil',a.inspect_observations,q,mutated(o,4,domain=o[1]['domain']))
    def test_05_claimed_distinct_domains_are_not_identity_proof(self):
        q,o=fixture();self.assertFalse(a.inspect_observations(q,o)['owner_reviewer_ed25519_authorized'])
    def test_06_ed25519_signature_shape_or_digest_not_authorization(self):
        q,o=fixture();self.assertFalse(a.inspect_observations(q,mutated(o,0,signature_sha=H('a valid-looking signature')))['owner_reviewer_ed25519_authorized'])
    def test_07_provider_signed_claim_cannot_be_promoted(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'fake_provider_origin',a.inspect_observations,q,mutated(o,2,claimed_origin='GITHUB_SIGNED'))
    def test_08_verification_claim_cannot_be_true(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'fake_authentication',a.inspect_observations,q,mutated(o,1,verified=True))
    def test_09_provider_job_substitution(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'provider_job_scope',a.inspect_observations,q,mutated(o,2,job=132577872781))
    def test_10_provider_platform_swap(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'provider_job_scope',a.inspect_observations,q,mutated(o,3,run=43637641205))
    def test_11_provider_attempt_replay(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'provider_job_scope',a.inspect_observations,q,mutated(o,2,attempt=2))
    def test_12_old_challenge_replay(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'challenge_replay',a.inspect_observations,q,mutated(o,7,challenge_sha=H('old-challenge')))
    def test_13_duplicate_nonce_within_quorum(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'nonce_replay',a.inspect_observations,q,mutated(o,7,nonce_sha=o[0]['nonce_sha']))
    def test_14_duplicate_payload_receipt(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'duplicate_payload',a.inspect_observations,q,mutated(o,7,payload_sha=o[0]['payload_sha']))
    def test_15_source_mismatch_rejected(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'source_mismatch',a.inspect_observations,q,mutated(o,5,source_sha='b'*40))
    def test_16_untrusted_epoch_drift(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'untrusted_time_claim',a.inspect_observations,q,mutated(o,4,epoch=101))
    def test_17_revocation_not_authenticated_by_time_claim(self):
        q,o=fixture();self.assertFalse(a.inspect_observations(q,o)['trusted_clock_revocation'])
    def test_18_gossip_merkle_split_view_classified_not_resolved(self):
        q,o=fixture();self.assertEqual(a.compare_fork_views(q,o,mutated(o,5,checkpoint_root=H('evil-root'))),'GOSSIP_SPLIT_VIEW_BLOCKED')
    def test_19_cross_host_different_cas_generation_forks(self):
        q,o=fixture();self.assertEqual(a.compare_fork_views(q,o,mutated(o,6,generation=16)),'MULTI_HOST_CAS_FORK_BLOCKED')
    def test_20_stale_fencing_token_fork(self):
        q,o=fixture();self.assertEqual(a.compare_fork_views(q,o,mutated(o,6,fence=24)),'MULTI_HOST_CAS_FORK_BLOCKED')
    def test_21_privileged_snapshot_restore_replays_old_generation(self):
        q,o=fixture();new=mutated(o,6,generation=16,fence=26)
        self.assertEqual(a.compare_fork_views(q,o,new),'MULTI_HOST_CAS_FORK_BLOCKED')
        self.assertEqual(a.compare_fork_views(q,new,o),'MULTI_HOST_CAS_FORK_BLOCKED')
    def test_22_aba_same_generation_new_payload(self):
        q,o=fixture();self.assertEqual(a.compare_fork_views(q,o,mutated(o,6,payload_sha=H('aba'))),'EQUIVOCATING_CLAIMS_BLOCKED')
    def test_23_same_nonce_claimed_replayed_signature(self):
        q,o=fixture();self.assertEqual(a.compare_fork_views(q,o,mutated(o,0,signature_sha=H('fake-changed'))),'EQUIVOCATING_CLAIMS_BLOCKED')
    def test_24_multi_host_isolated_identical_views_not_quorum(self):
        q,o=fixture();self.assertEqual(a.compare_fork_views(q,o,copy.deepcopy(o)),'EQUAL_CLAIMS_STILL_UNAUTHENTICATED')
    def test_25_lost_ack_changed_claim_remains_ambiguous(self):
        q,o=fixture();self.assertEqual(a.compare_fork_views(q,o,mutated(o,7,ack_id='ambiguous-ack')),'REPLAY_OR_LOST_ACK_AMBIGUOUS_BLOCKED')
    def test_26_lost_ack_missing_signed_result(self):
        p={'source_sha':SHA,'nonce_sha':H('sent'),'idempotency_sha':H('order-id'),'fence':50}
        b={**p,'signature_sha':H('caller supplied'),'claimed_origin':'SELF_ASSERTED'}
        self.assertIn('PENDING_',a.reconcile_remote_ack(p,b))
    def test_27_remote_ack_fence_replay_rejected(self):
        p={'source_sha':SHA,'nonce_sha':H('sent'),'idempotency_sha':H('order-id'),'fence':50}
        b={**p,'signature_sha':H('sig'),'claimed_origin':'SELF_ASSERTED','fence':49}
        self.assertRaisesRegex(a.EvidenceRejected,'ack_replay_or_fencing',a.reconcile_remote_ack,p,b)
    def test_28_remote_ack_false_authenticated_origin_rejected(self):
        p={'source_sha':SHA,'nonce_sha':H('sent'),'idempotency_sha':H('order-id'),'fence':50}
        b={**p,'signature_sha':H('sig'),'claimed_origin':'SIGNED_REMOTE'}
        self.assertRaisesRegex(a.EvidenceRejected,'ack_forged_origin',a.reconcile_remote_ack,p,b)
    def test_29_unexpected_ack_on_non_ack_gate(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'ack_scope',a.inspect_observations,q,mutated(o,0,ack_id='out-of-scope'))
    def test_30_proof_type_omission_or_remapping(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'proof_type',a.inspect_observations,q,mutated(o,3,proof_type=o[2]['proof_type']))
    def test_31_bool_counter_type_confusion(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'counter_type',a.inspect_observations,q,mutated(o,6,fence=True))
    def test_32_malformed_evidence_field_rejected(self):
        q,o=fixture();self.assertRaisesRegex(a.EvidenceRejected,'observation_schema',a.inspect_observations,q,mutated(o,1,bogus='true'))
    def test_33_same_source_different_nonce_observation_digest_differs(self):
        q,o=fixture();other=mutated(o,7,nonce_sha=H('changed'))
        self.assertNotEqual(a.inspect_observations(q,o)['digest'],a.inspect_observations(q,other)['digest'])
    def test_34_no_challenge_or_key_claim_redeems_live(self):
        q,o=fixture();r=a.inspect_observations(q,o)
        self.assertEqual((r['final'],r['live'],r['single_fit'],r['net20']),('SEALED','DISABLED','UNUSED','NOT_TESTED'))
    def test_35_no_unsafe_io_network_crypto_auth_in_code(self):
        tree=ast.parse((ROOT/'safe_public_ci'/'ci_rc695_external_acquisition_boundary.py').read_text(encoding='utf-8'))
        imports=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imports.update(v.name for v in node.names)
            if isinstance(node,ast.ImportFrom):imports.add(node.module)
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                self.assertNotIn(node.func.id,('open','eval','exec','compile','__import__'))
        self.assertEqual(imports,{'hashlib','hmac','re'})

if __name__=='__main__':unittest.main()
