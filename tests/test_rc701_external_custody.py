"""RC701: C2SP checkpoint binding and AWS lost-response readback, NO TRUST."""
import ast
import base64
import copy
import hashlib
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from safe_public_ci import ci_rc701_external_custody as m

def H(x): return hashlib.sha256(str(x).encode('ascii')).hexdigest()
def b64(x): return base64.b64encode(x).decode('ascii')
def cp(size, root, origin='rekor-test.example/log/v1', *, logkey=None, witness=None):
    signature = b64(bytes([17])*68)
    body = (origin+'\n'+str(size)+'\n'+b64(bytes.fromhex(root))+'\n\n')
    note = (body+'— rekor.test '+signature+'\n').encode()
    return {'tree_size':size,'root_sha256':root,'log_origin':origin,
            'note_b64':b64(note), 'log_key_fingerprint_sha256':logkey or H('log-pubkey'),
            'witness_key_fingerprint_sha256':witness or H('other-admin-witness'),
            'witness_cosignature_b64':b64(b'cosignature candidate not verified')}

def intake():
    return {'repository':m.REPO,'branch':m.BRANCH,'source_sha':m.BASE_SHA,
            'challenge_sha256':H('challenge'), 'nonce_sha256':H('nonce'),
            'audience':'INDEPENDENT_LOG_AUDITOR',
            'historical':cp(7,H('old-root')), 'current':cp(11,H('new-root')),
            'consistency_nodes_sha256':H('RFC6962 nodes, not verified here'),
            'operator_separation_claim':False,'verified':False}

def expected():
    return {'source_sha':m.BASE_SHA,'table':'SyntheticAudit','item_key':'AuditRoot',
            'epoch':5,'generation':16,'fence':21,'next_generation':17,'next_fence':22,
            'old_root_sha256':H('old'), 'new_root_sha256':H('new'),
            'request_id_sha256':H('request')}

def receipt(state='applied'):
    e=expected()
    r={'source_sha':m.BASE_SHA,'table':e['table'],'item_key':e['item_key'],
       'epoch':e['epoch'], 'consistently_read':True,
       'origin':'CALLER_REPORTED_AWS_JSON', 'provider_signature_verified':False}
    if state=='applied': r.update(generation=e['next_generation'],fence=e['next_fence'],root_sha256=e['new_root_sha256'],request_id_sha256=e['request_id_sha256'])
    if state=='old': r.update(generation=e['generation'],fence=e['fence'],root_sha256=e['old_root_sha256'],request_id_sha256=H('prior'))
    if state=='conflict': r.update(generation=e['next_generation']+2,fence=e['next_fence']+2,root_sha256=H('unknown'),request_id_sha256=H('other'))
    return r

class CheckpointCustody(unittest.TestCase):
    def test_01_valid_c2sp_note_structure_not_authentic(self):
        x=m.prepare_custody_intake(intake())
        self.assertEqual(x['classification'],'DETACHED_UNTRUSTED_EVIDENCE_CUSTODY_ONLY')
        self.assertFalse(x['historical']['log_root_pin_independent'])
        self.assertEqual(x['external_gates_verified'],0)
    def test_02_source_scope_rejected(self):
        x=intake();x['source_sha']='a'*40
        with self.assertRaisesRegex(m.CustodyRejected,'source_scope'):m.prepare_custody_intake(x)
    def test_03_genuine_note_root_binding_rejects_splice(self):
        x=intake();x['current']['root_sha256']=H('substituted')
        with self.assertRaisesRegex(m.CustodyRejected,'checkpoint_body_not_bound_to_tree'):m.prepare_custody_intake(x)
    def test_04_note_size_binding_rejects_splice(self):
        x=intake();x['historical']['tree_size']=9
        with self.assertRaisesRegex(m.CustodyRejected,'checkpoint_body_not_bound_to_tree'):m.prepare_custody_intake(x)
    def test_05_note_origin_binding_rejects_splice(self):
        x=intake();x['current']['log_origin']='another-origin'
        with self.assertRaisesRegex(m.CustodyRejected,'checkpoint_body_not_bound_to_tree'):m.prepare_custody_intake(x)
    def test_06_different_log_origins_rejected(self):
        x=intake();x['current']=cp(11,H('new-root'),origin='evil.example/log')
        with self.assertRaisesRegex(m.CustodyRejected,'log_origin_splice'):m.prepare_custody_intake(x)
    def test_07_owner_root_key_rotation_untrusted(self):
        x=intake();x['current']=cp(11,H('new-root'),logkey=H('rotated'))
        with self.assertRaisesRegex(m.CustodyRejected,'log_key_rotation_untrusted'):m.prepare_custody_intake(x)
    def test_08_witness_rotation_untrusted(self):
        x=intake();x['current']=cp(11,H('new-root'),witness=H('rotated witness'))
        with self.assertRaisesRegex(m.CustodyRejected,'witness_key_rotation_untrusted'):m.prepare_custody_intake(x)
    def test_09_log_witness_same_key_rejected(self):
        x=intake();x['historical']['witness_key_fingerprint_sha256']=x['historical']['log_key_fingerprint_sha256']
        with self.assertRaisesRegex(m.CustodyRejected,'independent_witness_key_required'):m.prepare_custody_intake(x)
    def test_10_tree_size_rollback_rejected(self):
        x=intake();x['historical']=cp(19,H('old-root'))
        with self.assertRaisesRegex(m.CustodyRejected,'checkpoint_rollback'):m.prepare_custody_intake(x)
    def test_11_same_size_fork_rejected(self):
        x=intake();x['current']=cp(7,H('new-root'))
        with self.assertRaisesRegex(m.CustodyRejected,'checkpoint_split_view'):m.prepare_custody_intake(x)
    def test_12_same_size_consistent_root_allowed_but_untrusted(self):
        x=intake();x['current']=copy.deepcopy(x['historical'])
        self.assertEqual(m.prepare_custody_intake(x)['external_gates_verified'],0)
    def test_13_unsigned_note_rejected(self):
        x=intake();p=x['current'];p['note_b64']=b64((p['log_origin']+'\n11\n'+b64(bytes.fromhex(p['root_sha256']))+'\n\n').encode())
        with self.assertRaisesRegex(m.CustodyRejected,'malformed_note_signatures'):m.prepare_custody_intake(x)
    def test_14_noncanonical_b64_rejected(self):
        x=intake();x['current']['note_b64']+='\n'
        with self.assertRaisesRegex(m.CustodyRejected,'invalid_base64_material'):m.prepare_custody_intake(x)
    def test_15_fake_verified_and_independent_role_denied(self):
        for flag in ('verified','operator_separation_claim'):
            x=intake();x[flag]=True
            with self.assertRaisesRegex(m.CustodyRejected,'caller_authority_promotion'):m.prepare_custody_intake(x)
    def test_16_nonce_replay_and_audience_bound(self):
        x=intake();a=m.prepare_custody_intake(x)['handoff_sha256'];x['audience']='INDEPENDENT_REVIEWER'
        self.assertNotEqual(m.prepare_custody_intake(x)['handoff_sha256'],a)
        x=intake();x['nonce_sha256']=x['challenge_sha256']
        with self.assertRaisesRegex(m.CustodyRejected,'nonce_challenge'):m.prepare_custody_intake(x)
    def test_17_injected_authority_key_rejected(self):
        x=intake();x['trusted_root']=True
        with self.assertRaisesRegex(m.CustodyRejected,'bundle_schema'):m.prepare_custody_intake(x)
    def test_18_checkpoint_material_is_digest_only_no_false_signer(self):
        x=m.checkpoint_material(cp(1,H('root')))
        self.assertEqual(x['tree_size'],1)
        self.assertFalse(x['witness_root_pin_independent'])

class AwsLostReply(unittest.TestCase):
    def test_19_applied_read_is_only_untrusted_claim(self):
        x=m.reconcile_untrusted_mrsc_read(expected(),receipt())
        self.assertEqual(x['classification'],'CLAIMED_APPLIED_BUT_UNAUTHENTICATED')
        self.assertFalse(x['remote_ack_authenticated'])
    def test_20_old_read_does_not_auto_retry(self):
        x=m.reconcile_untrusted_mrsc_read(expected(),receipt('old'))
        self.assertEqual(x['classification'],'CLAIMED_OLD_STATE_RETRY_NOT_AUTHORIZED')
        self.assertFalse(x['automated_retry_authorized'])
    def test_21_conflict_read_blocks_actions(self):
        x=m.reconcile_untrusted_mrsc_read(expected(),receipt('conflict'))
        self.assertEqual(x['classification'],'CONFLICT_OR_ROLLBACK_NO_AUTOMATED_ACTION')
        self.assertEqual(x['external_gates_verified'],0)
    def test_22_forged_remote_provenance_rejected(self):
        for field,value in [('origin','AWS_SIGNED'),('provider_signature_verified',True),('consistently_read',False)]:
            x=receipt();x[field]=value
            with self.assertRaisesRegex(m.CustodyRejected,'fake_remote_attestation'):m.reconcile_untrusted_mrsc_read(expected(),x)
    def test_23_old_epoch_and_aba_fail(self):
        x=receipt();x['epoch']=4
        with self.assertRaisesRegex(m.CustodyRejected,'remote_epoch_mismatch'):m.reconcile_untrusted_mrsc_read(expected(),x)
        x=receipt();x['fence']=21
        self.assertEqual(m.reconcile_untrusted_mrsc_read(expected(),x)['classification'],'CONFLICT_OR_ROLLBACK_NO_AUTOMATED_ACTION')
    def test_24_no_external_io_and_no_trade(self):
        tree=ast.parse((ROOT/'safe_public_ci'/'ci_rc701_external_custody.py').read_text())
        imports=set()
        for n in ast.walk(tree):
            if isinstance(n,ast.Import):imports.update(a.name for a in n.names)
            if isinstance(n,ast.ImportFrom):imports.add(n.module)
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name):
                self.assertNotIn(n.func.id,('open','eval','exec','compile','__import__'))
        self.assertEqual(imports,{'base64','hashlib','hmac','json','re'})
        self.assertEqual(len(m.external_gate_matrix()),8)
        self.assertTrue(all(x['status']=='BLOCKED' for x in m.external_gate_matrix()))

if __name__=='__main__':unittest.main()
