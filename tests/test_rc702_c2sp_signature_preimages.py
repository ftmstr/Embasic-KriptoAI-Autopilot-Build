"""RC702: C2SP signed-note and witness *preimages*, NO authority promotion."""
import ast
import base64
import hashlib
import pathlib
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from safe_public_ci import ci_rc702_c2sp_signature_preimages as m


def digest(x): return hashlib.sha256(x).hexdigest()
def encoding(x):return base64.b64encode(x).decode('ascii')

def example(timestamp=1700000000,old_size=3,new_size=5):
    log_name='rekor.example/log';witness_name='independent.example/witness'
    log_key=bytes(range(32));wit_key=bytes(range(1,33))
    old_root=digest(b'old checkpoint');new_root=digest(b'new checkpoint')
    body=f'{log_name}\n{new_size}\n{encoding(bytes.fromhex(new_root))}\n'.encode()
    log_signature=m.key_identifier(log_name,log_key,1)+b'\x11'*64
    witness_signature=m.key_identifier(witness_name,wit_key,4)+timestamp.to_bytes(8,'big')+b'\x22'*64
    note=body+b'\n'+f'— {log_name} {encoding(log_signature)}\n'.encode()+f'— {witness_name} {encoding(witness_signature)}\n'.encode()
    return {'repository':m.REPO,'branch':m.BRANCH,'source_sha':m.BASE_SHA,
            'challenge_sha256':digest(b'challenge'),'nonce_sha256':digest(b'nonce'),
            'audience':'INDEPENDENT_EXTERNAL_VERIFIER','note_b64':encoding(note),
            'log_name':log_name,'log_public_key_hex':log_key.hex(),
            'witness_name':witness_name,'witness_public_key_hex':wit_key.hex(),
            'old_size':old_size,'old_root_sha256':old_root,
            'consistency_proof_sha256':digest(b'untrusted consistency proof')}

def changed_note(req,modify):
    b=base64.b64decode(req['note_b64']);req['note_b64']=encoding(modify(b))

class C2SPPreimageTests(unittest.TestCase):
    def test_01_exact_two_domain_separated_messages(self):
        a=example();x=m.prepare_signature_handoff(a)
        root=digest(b'new checkpoint');body=f'rekor.example/log\n5\n{encoding(bytes.fromhex(root))}\n'.encode()
        witness_msg=b'cosignature/v1\ntime 1700000000\n'+body
        self.assertEqual(x['log_preimage_sha256'],digest(body))
        self.assertEqual(x['witness_preimage_sha256'],digest(witness_msg))
        self.assertNotEqual(x['log_preimage_sha256'],x['witness_preimage_sha256'])
        self.assertEqual(x['status'],'SIGNATURE_PREIMAGES_ONLY_NO_VERIFICATION')
        self.assertEqual(x['external_proofs_verified'],0)
    def test_02_key_id_formula_ed25519_log_and_witness(self):
        name='signer.example/foo';key=b'x'*32
        for t in (1,4):
            self.assertEqual(m.key_identifier(name,key,t),
                hashlib.sha256(name.encode()+b'\n'+bytes([t])+key).digest()[:4])
        self.assertNotEqual(m.key_identifier(name,key,1),m.key_identifier(name,key,4))
    def test_03_candidate_key_does_not_establish_custody(self):
        x=m.prepare_signature_handoff(example())
        self.assertFalse(x['log_signature_verified'])
        self.assertFalse(x['witness_signature_verified'])
        self.assertFalse(x['key_ownership_verified'])
        self.assertEqual(x['auth'],'NO-GO')
    def test_04_tampered_root_fails_claimed_historical_boundary(self):
        r=example(old_size=5,new_size=5)
        with self.assertRaisesRegex(m.EvidenceRejected,'same_size_split_view'):
            m.prepare_signature_handoff(r)
    def test_05_timestamp_binding_changes_message(self):
        a=m.prepare_signature_handoff(example(1700000000))
        b=m.prepare_signature_handoff(example(1700000001))
        self.assertNotEqual(a['witness_preimage_sha256'],b['witness_preimage_sha256'])
        self.assertEqual(a['log_preimage_sha256'],b['log_preimage_sha256'])
    def test_06_wrong_log_key_rejected(self):
        r=example();r['log_public_key_hex']=(b'Z'*32).hex()
        with self.assertRaisesRegex(m.EvidenceRejected,'expected_candidate_signatures_missing'):
            m.prepare_signature_handoff(r)
    def test_07_wrong_witness_key_rejected(self):
        r=example();r['witness_public_key_hex']=(b'Y'*32).hex()
        with self.assertRaisesRegex(m.EvidenceRejected,'expected_candidate_signatures_missing'):
            m.prepare_signature_handoff(r)
    def test_08_same_log_witness_key_rejected(self):
        r=example();r['witness_public_key_hex']=r['log_public_key_hex']
        with self.assertRaisesRegex(m.EvidenceRejected,'same_candidate_key'):
            m.prepare_signature_handoff(r)
    def test_09_malformed_log_signature_length(self):
        r=example();changed_note(r,lambda b:b.replace('— rekor.example/log '.encode()+encoding(m.key_identifier('rekor.example/log',bytes(range(32)),1)+b'\x11'*64).encode(),'— rekor.example/log '.encode()+encoding(m.key_identifier('rekor.example/log',bytes(range(32)),1)+b'\x11'*63).encode()))
        with self.assertRaisesRegex(m.EvidenceRejected,'log_signature_length'):
            m.prepare_signature_handoff(r)
    def test_10_malformed_witness_timestamp_highbit(self):
        r=example(timestamp=2**63)
        with self.assertRaisesRegex(m.EvidenceRejected,'untrusted_witness_timestamp_range'):
            m.prepare_signature_handoff(r)
    def test_11_note_control_character_rejected(self):
        r=example();changed_note(r,lambda b:b.replace(b'rekor.example/log\n',b'rekor.example/log\r\n',1))
        with self.assertRaisesRegex(m.EvidenceRejected,'note_controls'):
            m.prepare_signature_handoff(r)
    def test_12_checkpoint_extension_rejected_without_review(self):
        r=example();changed_note(r,lambda b:b.replace('\n\n— rekor.example/log'.encode(),'\nadditional-extension\n\n— rekor.example/log'.encode(),1))
        with self.assertRaisesRegex(m.EvidenceRejected,'checkpoint_extensions_unreviewed'):
            m.prepare_signature_handoff(r)
    def test_13_wrong_source_rejected(self):
        r=example();r['source_sha']='a'*40
        with self.assertRaisesRegex(m.EvidenceRejected,'handoff_scope'):
            m.prepare_signature_handoff(r)
    def test_14_nonce_replay_rejected(self):
        r=example();r['nonce_sha256']=r['challenge_sha256']
        with self.assertRaisesRegex(m.EvidenceRejected,'replay_nonce'):
            m.prepare_signature_handoff(r)
    def test_15_faked_verified_field_rejected(self):
        r=example();r['signature_valid']=True
        with self.assertRaisesRegex(m.EvidenceRejected,'handoff_schema'):
            m.prepare_signature_handoff(r)
    def test_16_caller_origin_not_rekor_identity(self):
        r=example();r['log_name']='attacker.example/log'
        with self.assertRaisesRegex(m.EvidenceRejected,'checkpoint_log_name'):
            m.prepare_signature_handoff(r)
    def test_17_rollback_size_rejected(self):
        r=example(old_size=6,new_size=5)
        with self.assertRaisesRegex(m.EvidenceRejected,'old_root_rollback'):
            m.prepare_signature_handoff(r)
    def test_18_import_guard_no_io_no_live(self):
        source=(ROOT/'safe_public_ci'/'ci_rc702_c2sp_signature_preimages.py').read_text()
        tree=ast.parse(source);imports=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imports.update(a.name for a in node.names)
            if isinstance(node,ast.ImportFrom):imports.add(node.module)
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                self.assertNotIn(node.func.id,('open','eval','exec','compile','__import__'))
        self.assertEqual(imports,{'hashlib','hmac','json','re','safe_public_ci'})
        self.assertNotIn('subprocess',source)
        self.assertNotIn('LIVE=ENABLED',source)

if __name__=='__main__':unittest.main()
