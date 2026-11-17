"""RC700: independent RFC6962 SUBPROOF vectors and inert AWS MRSC CAS shape."""
import ast
import hashlib
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_rc700_consistency_fencing_boundary as g


def hash_tree(entries):
    if len(entries)==1: return hashlib.sha256(b'\x00'+entries[0]).digest()
    split=1<<((len(entries)-1).bit_length()-1)
    return hashlib.sha256(b'\x01'+hash_tree(entries[:split])+hash_tree(entries[split:])).digest()


def make_proof(entries, old_size):
    # Independently implement RFC 6962 SUBPROOF(m,D[n],b), not the verifier.
    def walk(items,m,complete):
        n=len(items)
        if m==n: return [] if complete else [hash_tree(items).hex()]
        k=1<<((n-1).bit_length()-1)
        if m<=k:
            return walk(items[:k],m,complete)+[hash_tree(items[k:]).hex()]
        return walk(items[k:],m-k,False)+[hash_tree(items[:k]).hex()]
    return walk(entries,old_size,True)


def evidence(entries,old_size):
    return {'repository':g.REPO,'branch':g.BRANCH,'source_sha':g.BASE_SHA,
            'old_size':old_size,'new_size':len(entries),
            'old_root_sha256':hash_tree(entries[:old_size]).hex(),
            'new_root_sha256':hash_tree(entries).hex(),
            'log_identity_sha256':hashlib.sha256(b'unpinned log id').hexdigest(),
            'witness_identity_sha256':hashlib.sha256(b'unpinned witness id').hexdigest(),
            'audit_path':make_proof(entries,old_size) if old_size<len(entries) else []}


def topology(**kw):
    t={'service':'DYNAMODB','consistency':'MRSC',
       'replicas':['us_east_1','us_west_2'],'witness_region':'eu_west_1',
       'transaction_api':False,'strong_reads':True,'conditional_writes':True,
       'restore_drill_verified':False,'independent_admin_verified':False}
    t.update(kw)
    return t


def request(**kw):
    p={'source_sha':g.BASE_SHA,'table':'SyntheticFence','key':'SyntheticAudit',
       'epoch':3,'generation':8,'fence':14,'next_generation':9,'next_fence':15,
       'expected_root_sha256':hashlib.sha256(b'old').hexdigest(),
       'new_root_sha256':hashlib.sha256(b'new').hexdigest(),
       'request_id_sha256':hashlib.sha256(b'challenge 57').hexdigest()}
    p.update(kw)
    return p


class TrueConsistencyMath(unittest.TestCase):
    def test_01_rfc6962_all_prefixes_for_sizes_1_through_48(self):
        cases=0
        for size in range(1,49):
            leaves=[('original-entry-%d'%i).encode() for i in range(size)]
            for m in range(1,size+1):
                with self.subTest(size=size,old=m):
                    out=g.verify_consistency(evidence(leaves,m))
                    self.assertTrue(out['math_valid'])
                    self.assertEqual(out['classification'],'CONSISTENT_UNTRUSTED_ROOTS')
                    self.assertEqual(out['external_gates_open'],0)
                    cases+=1
        self.assertEqual(cases,1176)
    def test_02_reference_rfc_example_3_to_7(self):
        e=[('d%d'%i).encode() for i in range(7)]
        self.assertEqual(len(make_proof(e,3)),4)
        self.assertTrue(g.verify_consistency(evidence(e,3))['math_valid'])
    def test_03_reference_rfc_example_4_to_7(self):
        e=[('d%d'%i).encode() for i in range(7)]
        self.assertEqual(len(make_proof(e,4)),1)
        self.assertTrue(g.verify_consistency(evidence(e,4))['math_valid'])
    def test_04_reference_rfc_example_6_to_7(self):
        e=[('d%d'%i).encode() for i in range(7)]
        self.assertEqual(len(make_proof(e,6)),3)
        self.assertTrue(g.verify_consistency(evidence(e,6))['math_valid'])
    def test_05_tampered_old_root_fails(self):
        c=evidence([b'a',b'b',b'c'],2)
        c['old_root_sha256']=hashlib.sha256(b'faked').hexdigest()
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'consistency_root_mismatch'):
            g.verify_consistency(c)
    def test_06_tampered_new_root_fails(self):
        c=evidence([b'a',b'b',b'c'],2)
        c['new_root_sha256']=hashlib.sha256(b'faked').hexdigest()
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'consistency_root_mismatch'):
            g.verify_consistency(c)
    def test_07_corrupted_node_fails(self):
        c=evidence([b'a',b'b',b'c',b'd',b'e'],3)
        c['audit_path'][0]=hashlib.sha256(b'faked').hexdigest()
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'consistency_root_mismatch'):
            g.verify_consistency(c)
    def test_08_missing_node_fails(self):
        c=evidence([b'a',b'b',b'c',b'd',b'e'],3)
        c['audit_path'].pop()
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'consistency_root_mismatch'):
            g.verify_consistency(c)
    def test_09_extra_node_fails(self):
        c=evidence([b'a',b'b',b'c',b'd'],2)
        c['audit_path'].append('e'*64)
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'excess_consistency_nodes'):
            g.verify_consistency(c)
    def test_10_same_size_fork_denied(self):
        c=evidence([b'a',b'b',b'c'],3)
        c['new_root_sha256']='a'*64
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'same_size_fork'):
            g.verify_consistency(c)
    def test_11_same_size_unnecessary_proof_denied(self):
        c=evidence([b'a',b'b',b'c'],3)
        c['audit_path']=['a'*64]
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'same_size_fork'):
            g.verify_consistency(c)
    def test_12_rollback_invalid_m_greater_than_n(self):
        c=evidence([b'a',b'b',b'c'],2)
        c['old_size']=4
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'rollback_or_invalid_size'):
            g.verify_consistency(c)
    def test_13_wrong_source_and_self_witness_denied(self):
        c=evidence([b'a',b'b',b'c'],2)
        c['source_sha']='a'*40
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'source_scope'):
            g.verify_consistency(c)
        c['source_sha']=g.BASE_SHA
        c['witness_identity_sha256']=c['log_identity_sha256']
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'witness_must_differ_from_log'):
            g.verify_consistency(c)
    def test_14_math_does_not_mark_auth_or_external_witness(self):
        c=evidence([b'a',b'b'],1)
        x=g.checkpoint_acceptance(c)
        self.assertEqual(x['status'],'BLOCKED_EXTERNAL_LOG_AND_WITNESS_NOT_PRESENT')
        self.assertFalse(x['math']['log_origin_signature_verified'])
        self.assertFalse(x['math']['witness_cosignature_verified'])
        self.assertFalse(x['math']['historical_checkpoint_authenticated'])
        self.assertEqual(x['external_gates_verified'],0)
    def test_15_caller_verified_field_rejected(self):
        c=evidence([b'a',b'b'],1);c['signed_checkpoint']=True
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'consistency_schema'):
            g.verify_consistency(c)


class AwsCasPreflight(unittest.TestCase):
    def test_16_good_mrsc_2_replicas_plus_witness_and_3_replicas(self):
        for t in (topology(),topology(replicas=['aa_1','bb_2','cc_3'],witness_region=None)):
            self.assertTrue(g.assess_mrsc_topology(t)['api_design_compatible'])
            self.assertFalse(g.assess_mrsc_topology(t)['remote_cas_verified'])
    def test_17_mrec_and_invalid_region_counts(self):
        self.assertEqual(g.assess_mrsc_topology(topology(consistency='MREC'))['reason'],
                         'MREC_LWW_IS_NOT_LINEARIZABLE_CAS')
        self.assertEqual(g.assess_mrsc_topology(topology(witness_region=None))['reason'],
                         'MRSC_REQUIRES_THREE_DISTINCT_REGIONS')
    def test_18_duplicate_witness_and_unsupported_transactions(self):
        self.assertEqual(g.assess_mrsc_topology(topology(witness_region='us_east_1'))['reason'],
                         'MRSC_REQUIRES_THREE_DISTINCT_REGIONS')
        self.assertEqual(g.assess_mrsc_topology(topology(transaction_api=True))['reason'],
                         'MRSC_TRANSACTION_API_NOT_SUPPORTED')
    def test_19_strong_read_and_conditional_write_required(self):
        for kw in ({'strong_reads':False},{'conditional_writes':False}):
            self.assertEqual(g.assess_mrsc_topology(topology(**kw))['reason'],
                             'MRSC_REQUIRES_STRONG_READ_AND_CONDITIONAL_WRITE')
    def test_20_inert_update_exact_old_state_generation_and_reconcile(self):
        out=g.build_inert_cas_request(topology(),request())
        self.assertEqual(out['status'],'UNEXECUTED_MRSC_REQUEST_NO_AUTH')
        u=out['update_item']
        self.assertIn('#root = :old_root',u['ConditionExpression'])
        self.assertIn('#fence = :fence',u['ConditionExpression'])
        self.assertEqual(u['ReturnValues'],'ALL_NEW')
        self.assertTrue(out['reconcile_get_item']['ConsistentRead'])
        self.assertFalse(out['remote_write_occurred'])
        self.assertFalse(out['remote_ack_authenticated'])
        self.assertEqual(out['external_gates_open'],0)
    def test_21_stale_fence_next_generation_rejected(self):
        for changes in ({'next_fence':14},{'next_generation':11},{'next_generation':8}):
            with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'monotone_fence_expected'):
                g.build_inert_cas_request(topology(),request(**changes))
    def test_22_no_signer_or_remote_success_booleans_accepted(self):
        t=topology(restore_drill_verified=True)
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'caller_proof_cannot_authorize'):
            g.build_inert_cas_request(t,request())
        t=topology(independent_admin_verified=True)
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'caller_proof_cannot_authorize'):
            g.build_inert_cas_request(t,request())
    def test_23_source_scope_and_schema_injection_denied(self):
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'cas_source_scope'):
            g.build_inert_cas_request(topology(),request(source_sha='a'*40))
        q=request();q['signed_by_owner']=True
        with self.assertRaisesRegex(g.ExternalEvidenceBlocked,'cas_request_schema'):
            g.build_inert_cas_request(topology(),q)
    def test_24_no_network_io_or_external_auth_promotions(self):
        t=ast.parse((ROOT/'safe_public_ci'/'ci_rc700_consistency_fencing_boundary.py').read_text())
        imports=set()
        for n in ast.walk(t):
            if isinstance(n,ast.Import): imports.update(a.name for a in n.names)
            if isinstance(n,ast.ImportFrom):imports.add(n.module)
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name):
                self.assertNotIn(n.func.id,('open','eval','exec','compile','__import__'))
        self.assertEqual(imports,{'hashlib','hmac','json','re'})
        self.assertEqual(g.acquire_external_proof_status()['external_verified'],0)

if __name__=='__main__':unittest.main()
