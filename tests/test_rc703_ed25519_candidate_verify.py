"""RC703: true Ed25519 equations on candidate keys; OOB identity ALWAYS blocked."""
import ast
import base64
import hashlib
import pathlib
import sys
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from safe_public_ci import ci_rc703_ed25519_candidate_verify as m
from safe_public_ci import ci_rc702_c2sp_signature_preimages as c2sp

LOG='rekor.example/log'
WIT='witness.example/w1'
LP='79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664'
WP='e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0'
LS='18a10adb4e0fafade45dd1c176eef747225d3e956e5629efbfc982ef613c7060f5098d99eac92c75fd21cb61e65cc6110188dfd6666e4f96d371b9e2d9f0e007'
WS='8e66ec978b35967c636cb5fa662bc7135af61913cd6d5f5587a4b81172f4533cd6b179c6b2f38a55f048b5f347c77fc7d97e1b4ba56fcb0de9f484fd82874001'
TS=1700000000
ROOT_HEX=hashlib.sha256(b'new-root').hexdigest()

def sha(b):return hashlib.sha256(b).hexdigest()
def b64(b):return base64.b64encode(b).decode()
BODY=f'{LOG}\n5\n{b64(bytes.fromhex(ROOT_HEX))}\n'.encode()
WMSG=b'cosignature/v1\ntime 1700000000\n'+BODY

def make(**kwargs):
    log_sig=c2sp.key_identifier(LOG,bytes.fromhex(LP),1)+bytes.fromhex(LS)
    wit_sig=c2sp.key_identifier(WIT,bytes.fromhex(WP),4)+TS.to_bytes(8,'big')+bytes.fromhex(WS)
    note=BODY+b'\n'+f'— {LOG} {b64(log_sig)}\n'.encode()+f'— {WIT} {b64(wit_sig)}\n'.encode()
    obj={'repository':c2sp.REPO,'branch':c2sp.BRANCH,'source_sha':c2sp.BASE_SHA,
         'challenge_sha256':sha(b'challenge 703'),'nonce_sha256':sha(b'nonce 703'),
         'audience':'INDEPENDENT_EXTERNAL_VERIFIER','note_b64':b64(note),
         'log_name':LOG,'log_public_key_hex':LP,'witness_name':WIT,
         'witness_public_key_hex':WP,'old_size':3,
         'old_root_sha256':sha(b'old-root'),'consistency_proof_sha256':sha(b'untrusted')}
    obj.update(kwargs)
    return obj

def replace_signature(r, marker, new_sig):
    note=base64.b64decode(r['note_b64'])
    lines=note.splitlines(keepends=True)
    for i,line in enumerate(lines):
        if line.startswith(('— '+marker+' ').encode()):
            old=base64.b64decode(line.decode().split(' ')[2])
            new=old[:-64]+new_sig
            lines[i]=('— '+marker+' '+b64(new)+'\n').encode()
    r['note_b64']=b64(b''.join(lines))

class RealCandidateSignatureMath(unittest.TestCase):
    def test_01_rfc8032_vector_1_valid(self):
        k=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        s=bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        self.assertTrue(m.verify_candidate_ed25519(k,s,b''))
    def test_02_rfc8032_vector_2_valid(self):
        k=bytes.fromhex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
        s=bytes.fromhex('92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00')
        self.assertTrue(m.verify_candidate_ed25519(k,s,b'\x72'))
    def test_03_real_log_signature_math_valid(self):
        self.assertTrue(m.verify_candidate_ed25519(bytes.fromhex(LP),bytes.fromhex(LS),BODY))
    def test_04_real_witness_cosignature_math_valid(self):
        self.assertTrue(m.verify_candidate_ed25519(bytes.fromhex(WP),bytes.fromhex(WS),WMSG))
    def test_05_canonical_verified_pair_but_no_authority(self):
        result=m.examine_untrusted_c2sp_pair(make(),verifier_source_sha=m.SOURCE_SHA)
        self.assertTrue(result['log_math_valid'])
        self.assertTrue(result['witness_math_valid'])
        self.assertEqual(result['external_gates_verified'],0)
        self.assertFalse(result['oob_witness_root_independently_pinned'])
        self.assertEqual(result['auth'],'NO-GO')
    def test_06_wrong_log_signature_rejected(self):
        a=make();replace_signature(a,LOG,bytes([0])*64)
        with self.assertRaisesRegex(m.InvalidCandidate,'bad_candidate_ed25519_equation'):
            m.examine_untrusted_c2sp_pair(a,verifier_source_sha=m.SOURCE_SHA)
    def test_07_wrong_witness_signature_rejected(self):
        a=make();replace_signature(a,WIT,bytes([0])*64)
        with self.assertRaisesRegex(m.InvalidCandidate,'bad_candidate_ed25519_equation'):
            m.examine_untrusted_c2sp_pair(a,verifier_source_sha=m.SOURCE_SHA)
    def test_08_wrong_timing_message_rejected(self):
        self.assertFalse(m.verify_candidate_ed25519(bytes.fromhex(WP),bytes.fromhex(WS),b'cosignature/v1\ntime 1700000001\n'+BODY))
    def test_09_bad_message_and_key_rejected(self):
        self.assertFalse(m.verify_candidate_ed25519(bytes.fromhex(LP),bytes.fromhex(LS),BODY+b'\n'))
        self.assertFalse(m.verify_candidate_ed25519(bytes.fromhex(WP),bytes.fromhex(LS),BODY))
    def test_10_high_s_signature_rejected(self):
        sig=bytes.fromhex(LS)
        self.assertFalse(m.verify_candidate_ed25519(bytes.fromhex(LP),sig[:32]+m.L.to_bytes(32,'little'),BODY))
    def test_11_noncanonical_public_y_rejected(self):
        self.assertFalse(m.verify_candidate_ed25519(b'\xff'*32,bytes.fromhex(LS),BODY))
    def test_12_identity_and_small_order_rejected(self):
        self.assertFalse(m.verify_candidate_ed25519(b'\x01'+b'\0'*31,bytes.fromhex(LS),BODY))
        self.assertFalse(m.verify_candidate_ed25519(b'\0'*32,bytes.fromhex(LS),BODY))
    def test_13_invalid_signature_r_point_rejected(self):
        s=b'\xff'*32+bytes.fromhex(LS)[32:]
        self.assertFalse(m.verify_candidate_ed25519(bytes.fromhex(LP),s,BODY))
    def test_14_wrong_types_and_lengths_rejected(self):
        for key,sig,msg in ((LP,bytes.fromhex(LS),BODY),(bytes.fromhex(LP),LS,BODY),(bytes.fromhex(LP),bytes.fromhex(LS),'text'),(bytes.fromhex(LP),bytes.fromhex(LS)[:63],BODY),(bytes.fromhex(LP),bytes.fromhex(LS),b'a'*65537)):
            self.assertFalse(m.verify_candidate_ed25519(key,sig,msg))
    def test_15_untrusted_provenance_sha_rejected(self):
        with self.assertRaisesRegex(m.InvalidCandidate,'rc703_exact_source_scope'):
            m.examine_untrusted_c2sp_pair(make(),verifier_source_sha='a'*40)
    def test_16_injected_verified_claim_rejected(self):
        a=make(verified=True)
        with self.assertRaisesRegex(m.InvalidCandidate,'rc702_preflight_failed'):
            m.examine_untrusted_c2sp_pair(a,verifier_source_sha=m.SOURCE_SHA)
    def test_17_noncandidate_fake_root_pin_not_accepted(self):
        r=m.examine_untrusted_c2sp_pair(make(),verifier_source_sha=m.SOURCE_SHA)
        self.assertEqual(r['final'],'SEALED')
        self.assertFalse(r['oob_log_root_independently_pinned'])
        self.assertFalse(r['provider_original_full_logs_authenticated'])
        self.assertFalse(r['mrsc_multi_host_fence_test_observed'])
        self.assertFalse(r['recipient_idempotent_ack_authenticated'])
    def test_18_no_unapproved_runtime_import_or_io(self):
        source=(ROOT/'safe_public_ci'/'ci_rc703_ed25519_candidate_verify.py').read_text()
        t=ast.parse(source);imports=set()
        for n in ast.walk(t):
            if isinstance(n,ast.Import):imports.update(a.name for a in n.names)
            if isinstance(n,ast.ImportFrom):imports.add(n.module)
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name):
                self.assertNotIn(n.func.id,('open','eval','exec','compile','__import__'))
        self.assertEqual(imports,{'hashlib','hmac','safe_public_ci'})
        self.assertNotIn('subprocess',source)

if __name__=='__main__':unittest.main()
