"""RC696/TUR53 adversarial offline crypto, time, Merkle and CAS intake tests."""
import ast
import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from safe_public_ci import ci_rc696_detached_evidence_boundary as gate

SHA='a5536e053e8b1c5cac8e02ffca1b7023884c5f7f'
def H(v):return hashlib.sha256(str(v).encode('ascii')).hexdigest()
def envelope(platform='ubuntu',body=b'original full hosted job log, byte for byte\n'):
    return {'repository':gate.REPO,'branch':gate.BRANCH,'source_sha':SHA,
      'platform':platform,'workflow_blob_sha':'a'*40 if platform=='ubuntu' else 'b'*40,
      'run':43651207798 if platform=='ubuntu' else 43651207796,
      'job':132619853365 if platform=='ubuntu' else 132619853563,
      'attempt':1,'log_sha256':hashlib.sha256(body).hexdigest(),'log_length':len(body),
      'challenge_sha256':H('external challenge unverified'),
      'nonce_sha256':H('unique '+platform),'epoch':200,'fence':300}
def cas():
    old={'generation':12,'fence':31,'idempotency_sha256':H('old'), 'state_sha256':H('state1')}
    new={'generation':13,'fence':32,'idempotency_sha256':H('new'), 'state_sha256':H('state2')}
    ack={'idempotency_sha256':H('new'),'fence':32,'origin':'UNTRUSTED_CLAIM',
         'signature_sha256':H('self claim')}
    return old,new,ack

class ProofBoundaryCases(unittest.TestCase):
    def test_01_all_eight_external_gates_remain_blocked(self):
        x=gate.pending_gates();self.assertEqual(len(x),8)
        self.assertEqual(len({z['gate'] for z in x}),8)
        self.assertTrue(all(not z['verified'] and z['status']=='BLOCKED' for z in x))
    def test_02_full_original_log_byte_digest_verified_as_data_only(self):
        b=b'synthetic exact bytes\r\n';e=envelope(body=b)
        self.assertTrue(gate.validate_envelope(e,b))
    def test_03_appended_newline_invalidates_full_log(self):
        b=b'a\r\n';e=envelope(body=b)
        with self.assertRaisesRegex(gate.EvidenceRejected,'log_length_mismatch'):
            gate.canonical_signed_scope(e,b+b'\n')
    def test_04_single_byte_modified_same_length_rejected(self):
        b=b'abcdef';e=envelope(body=b)
        with self.assertRaisesRegex(gate.EvidenceRejected,'full_log_bytes_mismatch'):
            gate.validate_envelope(e,b'abcdeg')
    def test_05_explicit_bad_log_length_rejected(self):
        b=b'abc';e=envelope(body=b);e['log_length']=4
        with self.assertRaisesRegex(gate.EvidenceRejected,'log_length_mismatch'):gate.validate_envelope(e,b)
    def test_06_not_a_provider_platform_rejected(self):
        b=b'abc';e=envelope(body=b);e['platform']='self-hosted'
        with self.assertRaisesRegex(gate.EvidenceRejected,'platform'):gate.validate_envelope(e,b)
    def test_07_unknown_field_rejected(self):
        b=b'abc';e=envelope(body=b);e['authenticated']=True
        with self.assertRaisesRegex(gate.EvidenceRejected,'envelope_schema'):gate.validate_envelope(e,b)
    def test_08_source_short_sha_rejected(self):
        b=b'abc';e=envelope(body=b);e['source_sha']='deadbeef'
        with self.assertRaisesRegex(gate.EvidenceRejected,'git_sha'):gate.validate_envelope(e,b)
    def test_09_workflow_blob_changes_signed_transcript(self):
        b=b'abc';e=envelope(body=b);f=copy.deepcopy(e);f['workflow_blob_sha']='c'*40
        self.assertNotEqual(gate.canonical_signed_scope(e,b),gate.canonical_signed_scope(f,b))
    def test_10_job_substitution_changes_signed_transcript(self):
        b=b'abc';e=envelope(body=b);f=copy.deepcopy(e);f['job']+=1
        self.assertNotEqual(gate.canonical_signed_scope(e,b),gate.canonical_signed_scope(f,b))
    def test_11_attempt_replay_changes_signed_transcript(self):
        b=b'abc';e=envelope(body=b);f=copy.deepcopy(e);f['attempt']+=1
        self.assertNotEqual(gate.canonical_signed_scope(e,b),gate.canonical_signed_scope(f,b))
    def test_12_nonce_replay_changes_signed_transcript(self):
        b=b'abc';e=envelope(body=b);f=copy.deepcopy(e);f['nonce_sha256']=H('reused')
        self.assertNotEqual(gate.canonical_signed_scope(e,b),gate.canonical_signed_scope(f,b))
    def test_13_challenge_replay_changes_signed_transcript(self):
        b=b'abc';e=envelope(body=b);f=copy.deepcopy(e);f['challenge_sha256']=H('old challenge')
        self.assertNotEqual(gate.canonical_signed_scope(e,b),gate.canonical_signed_scope(f,b))
    def test_14_bool_run_id_not_accepted(self):
        b=b'a';e=envelope(body=b);e['run']=True
        with self.assertRaisesRegex(gate.EvidenceRejected,'positive_counter_run'):gate.validate_envelope(e,b)
    def test_15_empty_full_log_rejected(self):
        b=b'';e=envelope(body=b);e['log_length']=1
        with self.assertRaises(gate.EvidenceRejected):gate.validate_envelope(e,b)
    def test_16_max_log_size_enforced(self):
        b=b'x'*(gate.MAX_LOG_BYTES+1);e=envelope(body=b)
        with self.assertRaisesRegex(gate.EvidenceRejected,'log_bytes_limit'):gate.validate_envelope(e,b)
    def test_17_detached_ed25519_known_rfc8032_vector(self):
        # RFC 8032 vector #1: test harness may use independent crypto backend.
        pk='d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
        sig=('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
             '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            def delegate(payload,key,signature):
                Ed25519PublicKey.from_public_bytes(key).verify(signature,payload)
                return True
        except ImportError:
            delegate=None
        r=gate.verify_detached_ed25519(b'',pk,sig,delegate)
        expected='UNTRUSTED_ED25519_EQUATION_CLAIM' if delegate else 'CRYPTO_BACKEND_UNAVAILABLE'
        self.assertEqual(r['status'],expected)
        self.assertFalse(r['signature_math_valid']);self.assertFalse(r['authorized'])
        self.assertFalse(r['external_gate_open'])
    def test_18_detached_ed25519_wrong_data_fails_or_backend_blocked(self):
        pk='d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
        sig=('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
             '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        def delegate(payload,key,signature):
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                Ed25519PublicKey.from_public_bytes(key).verify(signature,payload)
                return True
            except ImportError:
                return False
            except Exception:
                return False
        r=gate.verify_detached_ed25519(b'forged',pk,sig,delegate)
        self.assertEqual(r['status'],'INVALID_SIGNATURE')
        self.assertFalse(r['signature_math_valid']);self.assertFalse(r['authorized'])
    def test_19_malformed_ed25519_key_fails_closed(self):
        with self.assertRaisesRegex(gate.EvidenceRejected,'public_key_format'):
            gate.verify_detached_ed25519(b'hello','0'*63,'0'*128)
    def test_20_malformed_ed25519_signature_fails_closed(self):
        with self.assertRaisesRegex(gate.EvidenceRejected,'signature_format'):
            gate.verify_detached_ed25519(b'hello','0'*64,'0'*127)
    def test_21_provider_claimed_signature_never_issues_authority(self):
        b=b'fake full log';e=envelope(body=b)
        r=gate.inspect_provider_candidate(e,b,'0'*64,'0'*128)
        self.assertFalse(r['authenticated']);self.assertFalse(r['verified_provider_origin']);self.assertFalse(r['live'])
    def test_22_pair_distinct_real_hosted_identifiers_but_untrusted(self):
        a=b'ubuntu content';b=b'windows content'
        r=gate.compare_ubuntu_windows(envelope(body=a),a,envelope('windows',b),b)
        self.assertEqual(r['external_verified'],0);self.assertFalse(r['authenticated'])
    def test_23_cross_platform_job_replay_detected(self):
        a=b'ubuntu content';b=b'windows content';u=envelope(body=a);w=envelope('windows',b)
        w['job']=u['job'];w['run']=u['run']
        with self.assertRaisesRegex(gate.EvidenceRejected,'provider_job_replay'):
            gate.compare_ubuntu_windows(u,a,w,b)
    def test_24_cross_platform_challenge_split_view_detected(self):
        a=b'ubuntu content';b=b'windows content';w=envelope('windows',b)
        w['challenge_sha256']=H('split view')
        with self.assertRaisesRegex(gate.EvidenceRejected,'pair_source_challenge_fork'):
            gate.compare_ubuntu_windows(envelope(body=a),a,w,b)
    def test_25_cross_platform_nonce_replay_detected(self):
        a=b'ubuntu content';b=b'windows content';u=envelope(body=a);w=envelope('windows',b)
        w['nonce_sha256']=u['nonce_sha256']
        with self.assertRaisesRegex(gate.EvidenceRejected,'cross_platform_nonce_replay'):
            gate.compare_ubuntu_windows(u,a,w,b)
    def test_26_cross_platform_same_full_log_replay_detected(self):
        a=b'same log';u=envelope(body=a);w=envelope('windows',a)
        with self.assertRaisesRegex(gate.EvidenceRejected,'cross_platform_log_duplicate'):
            gate.compare_ubuntu_windows(u,a,w,a)
    def test_27_claimed_revocation_unchallenged_time_is_not_trusted(self):
        ev=({'key_sha256':H('old'),'counter':11,'event':'REVOKE','event_sha256':H('evt1')},)
        r=gate.inspect_external_sequence(ev)
        self.assertFalse(r['trusted_time']);self.assertFalse(r['revocation_authenticated'])
    def test_28_revocation_counter_rollback_rejected(self):
        x=({'key_sha256':H('a'),'counter':4,'event':'ISSUE','event_sha256':H('e1')},
           {'key_sha256':H('b'),'counter':3,'event':'REVOKE','event_sha256':H('e2')})
        with self.assertRaisesRegex(gate.EvidenceRejected,'timeline_rollback'):
            gate.inspect_external_sequence(x)
    def test_29_revocation_event_replay_rejected(self):
        x=({'key_sha256':H('a'),'counter':1,'event':'ISSUE','event_sha256':H('e1')},
           {'key_sha256':H('b'),'counter':2,'event':'REVOKE','event_sha256':H('e1')})
        with self.assertRaisesRegex(gate.EvidenceRejected,'timeline_replay'):
            gate.inspect_external_sequence(x)
    def test_30_revoked_key_reissue_without_authority_denied(self):
        x=({'key_sha256':H('a'),'counter':1,'event':'REVOKE','event_sha256':H('e1')},
           {'key_sha256':H('a'),'counter':2,'event':'ISSUE','event_sha256':H('e2')})
        with self.assertRaisesRegex(gate.EvidenceRejected,'revoked_key_reintroduced'):
            gate.inspect_external_sequence(x)
    def test_31_merkle_same_size_split_view_detected(self):
        a={'size':7,'root_sha256':H('root1'),'witness_sha256':H('claim')}
        b={**a,'root_sha256':H('root2')}
        self.assertEqual(gate.inspect_checkpoint_pair(a,b),'SPLIT_VIEW_BLOCKED')
    def test_32_merkle_snapshot_size_rollback_detected(self):
        a={'size':7,'root_sha256':H('root1'),'witness_sha256':H('claim')}
        self.assertEqual(gate.inspect_checkpoint_pair(a,{**a,'size':6}),
                         'ROLLBACK_REQUIRES_EXTERNAL_ANCHOR')
    def test_33_merkle_equal_claims_still_need_external_consistency(self):
        a={'size':7,'root_sha256':H('root1'),'witness_sha256':H('claim')}
        self.assertEqual(gate.inspect_checkpoint_pair(a,a),'EXTERNAL_SIGNED_CONSISTENCY_PROOF_REQUIRED')
    def test_34_remote_cas_healthy_local_claim_still_no_go(self):
        r=gate.inspect_remote_cas_ack(*cas())
        self.assertFalse(r['durable_external_cas_verified']);self.assertFalse(r['remote_ack_verified'])
    def test_35_remote_cas_multi_host_fence_replay_rejected(self):
        old,new,ack=cas();new['fence']=old['fence']
        with self.assertRaisesRegex(gate.EvidenceRejected,'cas_stale_or_rollback'):
            gate.inspect_remote_cas_ack(old,new,ack)
    def test_36_remote_cas_privileged_snapshot_restore_rejected(self):
        old,new,ack=cas();new['generation']=11
        with self.assertRaisesRegex(gate.EvidenceRejected,'cas_stale_or_rollback'):
            gate.inspect_remote_cas_ack(old,new,ack)
    def test_37_remote_cas_aba_idempotency_rejected(self):
        old,new,ack=cas();new['idempotency_sha256']=old['idempotency_sha256']
        with self.assertRaisesRegex(gate.EvidenceRejected,'cas_aba_replayed_idempotency'):
            gate.inspect_remote_cas_ack(old,new,ack)
    def test_38_remote_ack_wrong_fence_rejected(self):
        old,new,ack=cas();ack['fence']=31
        with self.assertRaisesRegex(gate.EvidenceRejected,'ack_stale_or_lost'):
            gate.inspect_remote_cas_ack(old,new,ack)
    def test_39_remote_ack_lost_wrong_idempotency_rejected(self):
        old,new,ack=cas();ack['idempotency_sha256']=H('ambiguous')
        with self.assertRaisesRegex(gate.EvidenceRejected,'ack_stale_or_lost'):
            gate.inspect_remote_cas_ack(old,new,ack)
    def test_40_fake_authenticated_remote_ack_denied(self):
        old,new,ack=cas();ack['origin']='SIGNED_REMOTE'
        with self.assertRaisesRegex(gate.EvidenceRejected,'ack_forged_auth'):
            gate.inspect_remote_cas_ack(old,new,ack)
    def test_41_source_ast_no_direct_io_or_network_import(self):
        f=ROOT/'safe_public_ci'/'ci_rc696_detached_evidence_boundary.py'
        t=ast.parse(f.read_text(encoding='utf-8'))
        imports=set()
        for x in ast.walk(t):
            if isinstance(x,ast.Import):imports.update(y.name for y in x.names)
            if isinstance(x,ast.ImportFrom):imports.add(x.module)
            if isinstance(x,ast.Call) and isinstance(x.func,ast.Name):
                self.assertNotIn(x.func.id,('open','exec','eval','compile','__import__'))
        self.assertEqual(imports,{'hashlib','hmac','json','re'})

if __name__=='__main__':unittest.main()
