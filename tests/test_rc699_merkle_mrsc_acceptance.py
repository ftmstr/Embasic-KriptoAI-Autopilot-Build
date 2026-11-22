"""RC699: verify actual RFC6962 math, cross-region MRSC claims, and fail-closed contracts."""
import ast
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_rc699_merkle_mrsc_acceptance as g


def digest(x):
    return hashlib.sha256(x).digest()


def root(entries):
    if len(entries) == 1:
        return digest(b'\x00' + entries[0])
    k = 1 << ((len(entries)-1).bit_length()-1)
    return digest(b'\x01' + root(entries[:k]) + root(entries[k:]))


def path_for(entries, idx):
    if len(entries) == 1:
        return []
    k = 1 << ((len(entries)-1).bit_length()-1)
    if idx < k:
        return path_for(entries[:k], idx) + [root(entries[k:]).hex()]
    return path_for(entries[k:], idx-k) + [root(entries[:k]).hex()]


def proof(entries, idx):
    return dict(source_sha=g.BASE_SHA, log_origin='rekor.example.invalid',
                entry_sha256=digest(entries[idx]).hex(), leaf_index=idx,
                tree_size=len(entries), root_sha256=root(entries).hex(),
                audit_path=path_for(entries, idx),
                checkpoint_text_sha256=digest(b'untrusted checkpoint text').hex())


def cas(**kw):
    data=dict(backend='DYNAMODB', consistency_mode='MRSC', region_count=3,
              strong_read=True, conditional_write=True, transaction_api=False,
              restore_fence_tested=False, distinct_admin_verified=False)
    data.update(kw)
    return data


def handoff():
    return {'repository':g.REPO, 'branch':g.BRANCH, 'source_sha':g.BASE_SHA,
            'challenge_sha256':digest(b'independent challenge').hex(),
            'nonce_sha256':digest(b'unique nonce').hex(),
            'audience':'EXTERNAL_AUDITOR', 'gates':list(g.GATES),
            'purpose':'INDEPENDENT_PROOF_ACQUISITION_NO_AUTH'}


class Rfc6962MathCases(unittest.TestCase):
    def test_01_true_inclusion_all_indices_1_to_20_tree_sizes(self):
        for n in range(1,21):
            entries=[('record-%d'%i).encode() for i in range(n)]
            for idx in range(n):
                with self.subTest(n=n,idx=idx):
                    result=g.audit_inclusion(proof(entries,idx),entries[idx])
                    self.assertEqual(result['rfc6962_inclusion_math'],
                                     'VALID_UNTRUSTED_ROOT')
                    self.assertFalse(result['checkpoint_signature_verified'])
                    self.assertEqual(result['external_gates_verified'],0)
    def test_02_tampered_leaf_is_rejected(self):
        p=proof([b'a',b'b',b'c'],1)
        with self.assertRaisesRegex(g.ProofRejected,'raw_entry_digest'):
            g.audit_inclusion(p,b'wrong')
    def test_03_tampered_sibling_is_rejected(self):
        e=[b'a',b'b',b'c',b'd',b'e']; p=proof(e,2)
        p['audit_path'][0]=digest(b'fake branch').hex()
        with self.assertRaisesRegex(g.ProofRejected,'merkle_root_mismatch'):
            g.audit_inclusion(p,e[2])
    def test_04_truncated_inclusion_path_is_rejected(self):
        e=[b'a',b'b',b'c',b'd'];p=proof(e,0);p['audit_path'].pop()
        with self.assertRaisesRegex(g.ProofRejected,'short_audit_path'):
            g.audit_inclusion(p,e[0])
    def test_05_extra_audit_path_node_is_rejected(self):
        e=[b'a'];p=proof(e,0);p['audit_path'].append(digest(b'extra').hex())
        with self.assertRaisesRegex(g.ProofRejected,'extra_audit_nodes'):
            g.audit_inclusion(p,e[0])
    def test_06_old_source_sha_is_rejected(self):
        e=[b'a'];p=proof(e,0);p['source_sha']='a'*40
        with self.assertRaisesRegex(g.ProofRejected,'source_binding'):
            g.audit_inclusion(p,e[0])
    def test_07_leaf_index_outside_tree_is_rejected(self):
        e=[b'a'];p=proof(e,0);p['leaf_index']=1
        with self.assertRaisesRegex(g.ProofRejected,'tree_bounds'):
            g.audit_inclusion(p,e[0])
    def test_08_forged_signature_authentication_field_is_rejected(self):
        e=[b'a'];p=proof(e,0);p['trusted_witness']=True
        with self.assertRaisesRegex(g.ProofRejected,'proof_schema'):
            g.audit_inclusion(p,e[0])
    def test_09_wrong_root_rejected_even_with_correct_leaf(self):
        e=[b'a',b'b'];p=proof(e,0);p['root_sha256']=digest(b'wrong').hex()
        with self.assertRaisesRegex(g.ProofRejected,'merkle_root_mismatch'):
            g.audit_inclusion(p,e[0])
    def test_10_empty_and_oversize_entry_rejected(self):
        for data in (b'',b'x'*(g.MAX_ENTRY+1)):
            p=proof([b'a'],0)
            p['entry_sha256']=digest(data).hex()
            with self.assertRaisesRegex(g.ProofRejected,'entry_bytes'):
                g.audit_inclusion(p,data)
    def test_11_singleton_tree_requires_no_siblings(self):
        e=[b'only'];p=proof(e,0)
        self.assertEqual(p['audit_path'],[])
        self.assertFalse(g.audit_inclusion(p,e[0])['subject_signer_authorized'])
    def test_12_historical_consistency_never_assumed_from_inclusion(self):
        e=[b'a',b'b'];p=proof(e,1)
        result=g.audit_inclusion(p,e[1])
        self.assertFalse(result['history_consistency_verified'])
        self.assertFalse(result['independent_witness_verified'])

class RemoteCasAcceptCases(unittest.TestCase):
    def test_13_documented_mrsc_candidate_remains_blocked(self):
        x=g.assess_cas_provider(cas())
        self.assertTrue(x['documented_candidate'])
        self.assertEqual(x['status'],'BLOCKED')
        self.assertFalse(x['cross_host_linearizability_observed'])
    def test_14_mrec_multi_region_lww_rejected(self):
        x=g.assess_cas_provider(cas(consistency_mode='MREC'))
        self.assertEqual(x['candidate_reason'],'MREC_LWW_CROSS_REGION_NOT_LINEARIZABLE')
    def test_15_mrsc_not_three_regions_rejected(self):
        x=g.assess_cas_provider(cas(region_count=2))
        self.assertEqual(x['candidate_reason'],'MRSC_REQUIRES_THREE_REGION_CONFIGURATION')
    def test_16_mrsc_transaction_apis_not_supported(self):
        x=g.assess_cas_provider(cas(transaction_api=True))
        self.assertEqual(x['candidate_reason'],'MRSC_DOES_NOT_SUPPORT_TRANSACTION_APIS')
    def test_17_mrsc_strong_read_and_conditional_write_needed(self):
        for kw in ({'strong_read':False},{'conditional_write':False}):
            x=g.assess_cas_provider(cas(**kw))
            self.assertEqual(x['candidate_reason'],
                             'MRSC_STRONG_READ_AND_CONDITIONAL_WRITE_REQUIRED')
    def test_18_caller_assertion_of_real_external_proof_denied(self):
        for flag in ('restore_fence_tested','distinct_admin_verified'):
            with self.assertRaisesRegex(g.ProofRejected,'self_asserted_external_cas_proof'):
                g.assess_cas_provider(cas(**{flag:True}))
    def test_19_mrsc_backend_does_not_authenticate_8_gates(self):
        self.assertEqual(len(g.acquisition_contract()),8)
        self.assertTrue(all(t['status']=='BLOCKED' and not t['external_evidence_present']
                            for t in g.acquisition_contract()))
    def test_20_bad_cas_type_rejected(self):
        with self.assertRaisesRegex(g.ProofRejected,'cas_boolean_type'):
            g.assess_cas_provider(cas(strong_read=1))

class HandoffContractCases(unittest.TestCase):
    def test_21_independent_audience_bound(self):
        a=handoff();b=handoff();b['audience']='OOB_REVIEWER'
        self.assertNotEqual(g.handoff_digest(a),g.handoff_digest(b))
    def test_22_nonce_challenge_replay_rejected(self):
        a=handoff();a['nonce_sha256']=a['challenge_sha256']
        with self.assertRaisesRegex(g.ProofRejected,'challenge_nonce'):
            g.handoff_digest(a)
    def test_23_exact_eight_gates_no_unauthorized_source(self):
        a=handoff();a['gates'].pop()
        with self.assertRaisesRegex(g.ProofRejected,'request_gates'):
            g.handoff_digest(a)
    def test_24_stdlib_only_ast_and_forbidden_io(self):
        t=ast.parse((ROOT/'safe_public_ci'/'ci_rc699_merkle_mrsc_acceptance.py').read_text())
        imp=set()
        for n in ast.walk(t):
            if isinstance(n,ast.Import):imp.update(a.name for a in n.names)
            if isinstance(n,ast.ImportFrom):imp.add(n.module)
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name):
                self.assertNotIn(n.func.id,('open','eval','exec','compile','__import__'))
        self.assertEqual(imp,{'hashlib','hmac','json','re'})

if __name__=='__main__':unittest.main()
