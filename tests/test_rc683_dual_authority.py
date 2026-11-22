"""RC683: original, invented two-party witness and restart adversaries only."""
import copy
import hashlib
import unittest

from safe_public_ci.ci_dual_authority_quarantine import (
    DualAuthorityRejected, audit_dual_authority, checkpoint_bytes,
    ed25519_equation, _BASE, _L, _mul, _encode, _root, _proof,
)

SEEDS = (
    bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
    bytes.fromhex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'),
)
KEYS = (
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
)
LEAVES = tuple(hashlib.sha256(('rc683-fabricated-leaf-%03d' % i).encode()).hexdigest()
               for i in range(128))


def sign(i, msg):
    """TEST-ONLY deterministic RFC8032 fixture; never in safe_public_ci."""
    h = hashlib.sha512(SEEDS[i]).digest()
    a = (int.from_bytes(h[:32], 'little') & ((1 << 254) - 8)) | (1 << 254)
    assert _encode(_mul(_BASE, a)).hex() == KEYS[i]
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), 'little') % _L
    R = _encode(_mul(_BASE, r))
    k = int.from_bytes(hashlib.sha512(R + bytes.fromhex(KEYS[i]) + msg).digest(), 'little') % _L
    return (R + ((r+k*a) % _L).to_bytes(32, 'little')).hex()


def fixture(old=3, new=7):
    history = LEAVES[:new]
    root0 = _root(history[:old]).hex()
    root1 = _root(history).hex()
    c = dict(repository='ftmstr/Embasic-KriptoAI-Autopilot-Build',
             branch='validation/rc654-pr1-rc653-combined-ci',
             git_sha='a'*40, source_sha256='1'*64,
             workflow_sha256='2'*64, roster_sha256='3'*64,
             transcript_sha256='4'*64, old_size=old, new_size=new,
             old_root_sha256=root0, new_root_sha256=root1,
             full_history=history, consistency_proof=_proof(history, old),
             nonce_sha256='5'*64, issued_at=100, observed_at=120,
             authorities=(('owner','owner_one',KEYS[0],90,150,105),
                          ('independent_reviewer','reviewer_two',KEYS[1],90,150,106)),
             providers=(('ubuntu', 9100, 9200, 'a'*40, '1'*64, '6'*64, 'NOT_VERIFIED'),
                        ('windows',9101, 9201, 'a'*40, '1'*64, '7'*64, 'NOT_VERIFIED')),
             writers=(('writer_a',1,old,root0,root1,'CLAIMED_WIN'),
                      ('writer_b',2,old,root0,root1,'CLAIMED_CONFLICT')),
             revocations=(),spent_nonces=(),seen_roots=(),
             ack_state='ACK_LOST_UNRESOLVED',release_ready=False,
             live_trading_allowed=False)
    p = {key:c[key] for key in (
        'git_sha','source_sha256','workflow_sha256','roster_sha256',
        'transcript_sha256','old_root_sha256','new_root_sha256','nonce_sha256')}
    p.update(authority_fingerprints=tuple(hashlib.sha256(bytes.fromhex(k)).hexdigest()
                                          for k in KEYS),
             checkpoint_sha256=hashlib.sha256(checkpoint_bytes(c)).hexdigest(),
             out_of_band_trust_verified=False,
             provider_attestation_verified=False,
             durable_cas_verified=False)
    return c,p


def mutate_row(c,key,i,j,value):
    values = [list(row) for row in c[key]]
    values[i][j] = value
    c[key] = tuple(tuple(row) for row in values)


class RC683QuarantineTests(unittest.TestCase):
    def check(self,c,p,sigs=None):
        signed = sigs or (sign(0,checkpoint_bytes(c)),sign(1,checkpoint_bytes(c)))
        return audit_dual_authority(c,signed,p)

    def reject(self,fn,*,stale=False):
        c,p=fixture()
        sigs = (sign(0,checkpoint_bytes(c)),sign(1,checkpoint_bytes(c))) if stale else None
        fn(c,p)
        with self.assertRaises(DualAuthorityRejected):
            self.check(c,p,sigs=sigs)

    def test_01_valid_both_math_no_identity_authentication(self):
        c,p=fixture()
        out=self.check(c,p)
        self.assertEqual(out['status'],'DUAL_ED25519_EQUATIONS_VALID_ORIGIN_UNAUTHENTICATED')
        self.assertTrue(out['signature_equations_valid'])
        self.assertTrue(out['lost_ack_unresolved'])
        self.assertTrue(all(v is False for k,v in out.items() if k.endswith('authenticated') or
                            k in ('durable_cas_verified','restart_recovery_verified',
                                  'release_ready','live_trading_allowed')))

    def test_02_two_independent_key_signatures(self):
        c,_=fixture()
        msg=checkpoint_bytes(c)
        sig1,sig2=sign(0,msg),sign(1,msg)
        self.assertNotEqual(sig1,sig2)
        self.assertTrue(ed25519_equation(KEYS[0],msg,sig1))
        self.assertTrue(ed25519_equation(KEYS[1],msg,sig2))
        self.assertFalse(ed25519_equation(KEYS[1],msg,sig1))
        self.assertFalse(ed25519_equation(KEYS[0],msg,sig2))

    def test_03_rfc8032_known_vector(self):
        self.assertTrue(ed25519_equation(KEYS[0],b'',
            'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
            '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'))

    def test_04_independent_copies_are_deterministic(self):
        c,p=fixture()
        self.assertEqual(self.check(c,p),self.check(copy.deepcopy(c),copy.deepcopy(p)))

    def test_05_repeated_stateless_success_is_not_persistent_cas(self):
        c,p=fixture()
        self.assertFalse(self.check(c,p)['durable_cas_verified'])
        self.assertFalse(self.check(c,p)['restart_recovery_verified'])

    def test_06_owner_and_reviewer_can_both_re_sign_fabricated_history(self):
        c,p=fixture()
        c['nonce_sha256']='f'*64
        p['nonce_sha256']='f'*64
        p['checkpoint_sha256']=hashlib.sha256(checkpoint_bytes(c)).hexdigest()
        out=self.check(c,p)
        self.assertFalse(out['trust_anchor_distribution_authenticated'])
        self.assertFalse(out['merkle_history_authenticated'])

    def test_07_valid_future_revocation_changes_signed_message(self):
        c,p=fixture()
        old=checkpoint_bytes(c)
        c['revocations']=((p['authority_fingerprints'][0],121),)
        self.assertNotEqual(old,checkpoint_bytes(c))
        p['checkpoint_sha256']=hashlib.sha256(checkpoint_bytes(c)).hexdigest()
        self.assertFalse(self.check(c,p)['revocation_origin_authenticated'])

    def test_08_3_to_7_proof_cannot_claim_3_to_8(self):
        self.reject(lambda c,p:c.update(new_size=8))

    def test_09_reboot_claimed_win_is_not_durable(self):
        c,p=fixture()
        self.assertEqual(c['writers'][1][1],2)
        self.assertFalse(self.check(c,p)['restart_recovery_verified'])

    def test_10_lost_ack_never_mutates_to_committed(self):
        c,p=fixture()
        self.assertTrue(self.check(c,p)['lost_ack_unresolved'])
        self.assertFalse(self.check(c,p)['durable_cas_verified'])

    def test_11_all_merkle_sizes_and_inclusion_prefixes(self):
        for new in range(2,129):
            for old in set((1,new//2,new-1)):
                c,p=fixture(old,new)
                self.assertTrue(checkpoint_bytes(c).startswith(b'RC683-'))

    def test_12_ed25519_noncanonical_scalar(self):
        c,_=fixture()
        msg=checkpoint_bytes(c)
        sig=sign(0,msg)
        self.assertFalse(ed25519_equation(KEYS[0],msg,sig[:64]+_L.to_bytes(32,'little').hex()))

    def test_13_small_order_point_key(self):
        c,_=fixture()
        self.assertFalse(ed25519_equation('01'+'00'*31,checkpoint_bytes(c),sign(0,checkpoint_bytes(c))))

    def test_14_false_signer_anchor_is_a_new_unauthenticated_actor(self):
        c,p=fixture()
        self.assertFalse(self.check(c,p)['authority_origin_authenticated'])
        self.assertFalse(self.check(c,p)['provider_origin_authenticated'])

    def test_15_signatures_are_not_message_fields(self):
        c,p=fixture()
        self.assertEqual(hashlib.sha256(checkpoint_bytes(c)).hexdigest(),p['checkpoint_sha256'])
        self.assertNotIn('signatures',c)

    def test_16_altered_proof_even_with_re_signed_message_rejected(self):
        self.reject(lambda c,p:c.update(consistency_proof=c['consistency_proof'][:-1]))


MUTATIONS = (
    ('missing_field',lambda c,p:c.pop('roster_sha256'),False),
    ('foreign_field',lambda c,p:c.update(authenticated=True),False),
    ('wrong_repository',lambda c,p:c.update(repository='ftmstr/private'),False),
    ('main_branch',lambda c,p:c.update(branch='main'),False),
    ('wrong_git_sha',lambda c,p:c.update(git_sha='z'*40),False),
    ('git_source_rebind',lambda c,p:c.update(source_sha256='d'*64),True),
    ('workflow_rebind',lambda c,p:c.update(workflow_sha256='e'*64),True),
    ('roster_rebind',lambda c,p:c.update(roster_sha256='e'*64),True),
    ('transcript_rebind',lambda c,p:c.update(transcript_sha256='e'*64),True),
    ('old_root_false',lambda c,p:c.update(old_root_sha256='f'*64),False),
    ('new_root_false',lambda c,p:c.update(new_root_sha256='e'*64),False),
    ('nonce_rebind',lambda c,p:c.update(nonce_sha256='e'*64),True),
    ('old_zero',lambda c,p:c.update(old_size=0),False),
    ('new_129',lambda c,p:c.update(new_size=129),False),
    ('bool_size',lambda c,p:c.update(new_size=True),False),
    ('rollback_size',lambda c,p:c.update(new_size=2),False),
    ('time_backwards',lambda c,p:c.update(issued_at=121),False),
    ('invalid_history',lambda c,p:c.update(full_history=['0'*64]),False),
    ('truncated_history',lambda c,p:c.update(full_history=c['full_history'][:-1]),False),
    ('full_history_mutated',lambda c,p:c.update(full_history=('f'*64,*c['full_history'][1:])),False),
    ('duplicate_leaf',lambda c,p:c.update(full_history=(c['full_history'][0],*c['full_history'][1:-1],c['full_history'][0])),False),
    ('reorder_history',lambda c,p:c.update(full_history=tuple(reversed(c['full_history']))),False),
    ('proof_extra',lambda c,p:c.update(consistency_proof=(*c['consistency_proof'],'a'*64)),False),
    ('proof_wrong',lambda c,p:c.update(consistency_proof=('a'*64,*c['consistency_proof'][1:])),False),
    ('proof_list',lambda c,p:c.update(consistency_proof=list(c['consistency_proof'])),False),
    ('issuer_duplicate_actor',lambda c,p:mutate_row(c,'authorities',1,1,'owner_one'),False),
    ('issuer_duplicate_key',lambda c,p:mutate_row(c,'authorities',1,2,KEYS[0]),False),
    ('wrong_issuer_role',lambda c,p:mutate_row(c,'authorities',1,0,'owner'),False),
    ('issuer_time_expired',lambda c,p:mutate_row(c,'authorities',1,4,101),False),
    ('issuer_time_future',lambda c,p:mutate_row(c,'authorities',0,5,121),False),
    ('issuer_identity_rebind',lambda c,p:mutate_row(c,'authorities',0,1,'new_owner'),True),
    ('revoked_owner',lambda c,p:c.update(revocations=((p['authority_fingerprints'][0],100),)),False),
    ('revoked_reviewer',lambda c,p:c.update(revocations=((p['authority_fingerprints'][1],119),)),False),
    ('duplicate_revocation',lambda c,p:c.update(revocations=((p['authority_fingerprints'][0],90),(p['authority_fingerprints'][0],95))),False),
    ('invalid_revocation_type',lambda c,p:c.update(revocations=[('a'*64,90)]),False),
    ('noncanonical_revocation_order',lambda c,p:c.update(revocations=(('f'*64,90),('e'*64,90))),False),
    ('provider_wrong_os',lambda c,p:mutate_row(c,'providers',1,0,'ubuntu'),False),
    ('provider_duplicate_run',lambda c,p:mutate_row(c,'providers',1,1,9100),False),
    ('provider_duplicate_job',lambda c,p:mutate_row(c,'providers',1,2,9200),False),
    ('provider_wrong_git',lambda c,p:mutate_row(c,'providers',0,3,'b'*40),False),
    ('provider_wrong_source',lambda c,p:mutate_row(c,'providers',1,4,'d'*64),False),
    ('provider_false_auth',lambda c,p:mutate_row(c,'providers',0,6,'VERIFIED'),False),
    ('provider_run_rebind',lambda c,p:mutate_row(c,'providers',1,1,9109),True),
    ('provider_job_rebind',lambda c,p:mutate_row(c,'providers',0,2,9299),True),
    ('provider_log_rebind',lambda c,p:mutate_row(c,'providers',0,5,'f'*64),True),
    ('writer_double_win',lambda c,p:mutate_row(c,'writers',1,5,'CLAIMED_WIN'),False),
    ('writer_rollback',lambda c,p:mutate_row(c,'writers',1,2,2),False),
    ('writer_wrong_root',lambda c,p:mutate_row(c,'writers',0,3,'f'*64),False),
    ('writer_wrong_new_root',lambda c,p:mutate_row(c,'writers',1,4,'e'*64),False),
    ('writer_epoch_aba',lambda c,p:mutate_row(c,'writers',1,1,1),False),
    ('writer_epoch_jump',lambda c,p:mutate_row(c,'writers',1,1,3),False),
    ('writer_duplicate_actor',lambda c,p:mutate_row(c,'writers',1,0,'writer_a'),False),
    ('writer_actor_rebind',lambda c,p:mutate_row(c,'writers',0,0,'writer_new'),True),
    ('nonce_replay',lambda c,p:c.update(spent_nonces=('5'*64,)),False),
    ('root_replay',lambda c,p:c.update(seen_roots=(c['new_root_sha256'],)),False),
    ('noncanonical_seen',lambda c,p:c.update(seen_roots=['d'*64]),False),
    ('duplicate_spent',lambda c,p:c.update(spent_nonces=('d'*64,'d'*64)),False),
    ('ack_forgery',lambda c,p:c.update(ack_state='ACK_COMMITTED'),False),
    ('live_flag',lambda c,p:c.update(live_trading_allowed=True),False),
    ('release_flag',lambda c,p:c.update(release_ready=True),False),
    ('pin_digest_fake',lambda c,p:p.update(checkpoint_sha256='f'*64),False),
    ('pin_keys_fake',lambda c,p:p.update(authority_fingerprints=('f'*64,p['authority_fingerprints'][1])),False),
    ('pin_self_attested_root',lambda c,p:p.update(out_of_band_trust_verified=True),False),
    ('pin_fake_provider_auth',lambda c,p:p.update(provider_attestation_verified=True),False),
    ('pin_fake_durable_cas',lambda c,p:p.update(durable_cas_verified=True),False),
    ('pin_extra',lambda c,p:p.update(live=True),False),
    ('pin_missing',lambda c,p:p.pop('authority_fingerprints'),False),
)


def make_test(mutation,stale):
    def test(self):
        self.reject(mutation,stale=stale)
    return test


for n,(label,mutation,stale) in enumerate(MUTATIONS,17):
    setattr(RC683QuarantineTests,'test_%02d_%s' %(n,label),make_test(mutation,stale))


if __name__=='__main__':
    unittest.main()
