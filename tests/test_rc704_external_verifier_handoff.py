"""RC704: real provider identity cannot come from the same untrusted request."""
import ast
import hashlib
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_rc704_external_verifier_handoff as m

def sha(data):
    return hashlib.sha256(data.encode('ascii')).hexdigest()

def request():
    return {'repository': m.REPO, 'branch': m.BRANCH, 'source_sha': m.BASE_SHA,
            'audience': 'INDEPENDENT_EXTERNAL_VERIFIER',
            'challenge_sha256': sha('challenge unique 704'),
            'nonce_sha256': sha('nonce unique 704'),
            'requested_gates': list(m.GATES),
            'ubuntu_run': 44382073029, 'ubuntu_job': 135076777223,
            'windows_run': 44382073065, 'windows_job': 135076777097,
            'operator_claims_verified': False,
            'provider_raw_job_logs_present': False,
            'mrsc_service_provisioned': False,
            'remote_ack_received': False}

def receipt(req=None):
    q = request() if req is None else req
    return {'request_digest_sha256': m.canonical_request(q),
            'role': m.GATES[0], 'subject_sha': m.BASE_SHA,
            'response_nonce_sha256': sha('response unique 704'),
            'issuer_name': 'caller-claimed-operator',
            'issuer_admin_fingerprint_sha256': sha('fake authority'),
            'receipt_sha256': sha('candidate digest'),
            'claimed_provider_verified': False,
            'claimed_role_authorized': False}

class Acquisition(unittest.TestCase):
    def test_01_eight_provider_steps_are_not_proofs(self):
        h=m.handoff(request())
        self.assertEqual(len(h['requested_evidence']), 8)
        self.assertEqual([z['gate'] for z in h['requested_evidence']],list(m.GATES))
        self.assertTrue(all(z['status']=='BLOCKED' and not z['independently_verified']
                            for z in h['requested_evidence']))
        self.assertEqual(h['external_verified_count'],0)
        self.assertEqual(h['auth'],'NO-GO')
    def test_02_raw_original_logs_subject_bound_to_github_jobs(self):
        h=m.handoff(request())
        self.assertIn('135076777223',h['requested_evidence'][2]['subject'])
        self.assertIn('135076777097',h['requested_evidence'][3]['subject'])
        self.assertIn(m.BASE_SHA,h['requested_evidence'][2]['subject'])
        self.assertFalse(h['github_artifact_attestation_is_full_raw_log_proof'])
    def test_03_reject_wrong_source_or_repository(self):
        for field,val in [('source_sha','a'*40),('repository','wrong/repo'),('branch','main')]:
            q=request();q[field]=val
            with self.assertRaisesRegex(m.ExternalProofBlocked,'exact_source_scope'):
                m.handoff(q)
    def test_04_reject_run_or_job_swaps(self):
        for key in ('ubuntu_run','ubuntu_job','windows_run','windows_job'):
            q=request();q[key]+=1
            with self.assertRaisesRegex(m.ExternalProofBlocked,'run_job_scope'):
                m.handoff(q)
    def test_05_challenge_and_nonce_bound(self):
        q=request();h=m.handoff(q)
        q['nonce_sha256']=sha('different nonce 704')
        self.assertNotEqual(m.handoff(q)['request_digest_sha256'],h['request_digest_sha256'])
        q['nonce_sha256']=q['challenge_sha256']
        with self.assertRaisesRegex(m.ExternalProofBlocked,'challenge_nonce_replay'):
            m.handoff(q)
    def test_06_reject_caller_asserted_provider_ownership(self):
        for flag in ('operator_claims_verified','provider_raw_job_logs_present',
                     'mrsc_service_provisioned','remote_ack_received'):
            q=request();q[flag]=True
            with self.assertRaisesRegex(m.ExternalProofBlocked,'untrusted_authority_promotion'):
                m.handoff(q)
    def test_07_reject_untrusted_extra_trust_root_field(self):
        q=request();q['oob_pinned_ed25519_key']='deadbeef'
        with self.assertRaisesRegex(m.ExternalProofBlocked,'request_schema'):
            m.handoff(q)
    def test_08_no_gate_reordering_or_omission(self):
        q=request();q['requested_gates']=list(reversed(m.GATES))
        with self.assertRaisesRegex(m.ExternalProofBlocked,'gate_order_or_scope'):
            m.handoff(q)
    def test_09_claim_quarantine_never_promotes_even_with_checksum_match(self):
        r=m.quarantine_claimed_receipt(request(),receipt())
        self.assertEqual(r['classification'],'UNTRUSTED_PROOF_CLAIM_QUARANTINED')
        self.assertFalse(r['independent_provider_signature_verified'])
        self.assertFalse(r['oob_authority_verified'])
        self.assertEqual(r['external_verified_count'],0)
    def test_10_cross_request_receipt_replay_denied(self):
        q=request();other=request();other['nonce_sha256']=sha('a different request')
        with self.assertRaisesRegex(m.ExternalProofBlocked,'cross_request_or_replay'):
            m.quarantine_claimed_receipt(other,receipt(q))
    def test_11_synthetic_issuer_cannot_claim_true_verification(self):
        for key in ('claimed_provider_verified','claimed_role_authorized'):
            r=receipt();r[key]=True
            with self.assertRaisesRegex(m.ExternalProofBlocked,'caller_asserted_trust_is_forbidden'):
                m.quarantine_claimed_receipt(request(),r)
    def test_12_subject_replay_and_role_injection_denied(self):
        r=receipt();r['subject_sha']='a'*40
        with self.assertRaisesRegex(m.ExternalProofBlocked,'receipt_subject_scope'):
            m.quarantine_claimed_receipt(request(),r)
        r=receipt();r['role']='random'
        with self.assertRaisesRegex(m.ExternalProofBlocked,'unrecognized_evidence_role'):
            m.quarantine_claimed_receipt(request(),r)
    def test_13_response_nonce_cannot_reuse_challenge_or_request_nonce(self):
        for nonce in (request()['nonce_sha256'],request()['challenge_sha256']):
            r=receipt();r['response_nonce_sha256']=nonce
            with self.assertRaisesRegex(m.ExternalProofBlocked,'response_nonce_replay'):
                m.quarantine_claimed_receipt(request(),r)
    def test_14_removing_receipt_field_or_adding_provider_verified_rejected(self):
        r=receipt();del r['issuer_name']
        with self.assertRaisesRegex(m.ExternalProofBlocked,'untrusted_receipt_schema'):
            m.quarantine_claimed_receipt(request(),r)
        r=receipt();r['cryptographic_ed25519_verified']=True
        with self.assertRaisesRegex(m.ExternalProofBlocked,'untrusted_receipt_schema'):
            m.quarantine_claimed_receipt(request(),r)
    def test_15_no_import_whitelist_change_network_or_exec(self):
        text=(ROOT/'safe_public_ci'/'ci_rc704_external_verifier_handoff.py').read_text()
        t=ast.parse(text); imports=set()
        for node in ast.walk(t):
            if isinstance(node,ast.Import):imports.update(a.name for a in node.names)
            if isinstance(node,ast.ImportFrom):imports.add(node.module)
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                self.assertNotIn(node.func.id,('open','exec','eval','compile','__import__'))
        self.assertEqual(imports,{'hashlib','hmac','json','re'})
    def test_16_exact_scoped_digest_is_deterministic(self):
        q=request();h=m.handoff(q)
        self.assertEqual(h['request_digest_sha256'],m.canonical_request(q))
        self.assertRegex(h['request_digest_sha256'],r'^[0-9a-f]{64}$')
        self.assertEqual(h['final'],'SEALED')
        self.assertEqual(h['net20'],'NOT_TESTED')

if __name__=='__main__':
    unittest.main()
