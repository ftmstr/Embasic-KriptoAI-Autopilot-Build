"""RC682 synthetic adversaries; no runtime keys, exchange, network or persistence."""
import copy
import hashlib
import unittest

from safe_public_ci.ci_signed_checkpoint_quarantine import (
    CheckpointRejected, checkpoint_message, quarantine_signed_checkpoint,
    verify_ed25519, _BASE, _L, _scalar, _encode_point,
)

SEED = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
PUBLIC = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
RFC_SIG = ('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
           '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')


def sign(message):
    """Deterministic test-only private key, NEVER used by safe_public_ci."""
    h = hashlib.sha512(SEED).digest()
    a = (int.from_bytes(h[:32], 'little') & ((1 << 254) - 8)) | (1 << 254)
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), 'little') % _L
    R = _encode_point(_scalar(_BASE, r))
    k = int.from_bytes(hashlib.sha512(R + bytes.fromhex(PUBLIC) + message).digest(), 'little') % _L
    return (R + ((r + k*a) % _L).to_bytes(32, 'little')).hex()


def fixture():
    source = '1'*64
    c = dict(git_sha='a'*40, source_sha256=source,
             workflow_sha256='2'*64, roster_sha256='3'*64,
             transcript_sha256='4'*64, old_size=3, new_size=7,
             old_root_sha256='5'*64, new_root_sha256='6'*64,
             nonce_sha256='7'*64, issued_at=100, observed_at=120,
             provider_claims=(
                 ('ubuntu', 1001, 2001, 'a'*40, source, '8'*64, 'NOT_VERIFIED'),
                 ('windows', 1002, 2002, 'a'*40, source, '9'*64, 'NOT_VERIFIED')),
             writer_claims=(
                 ('writer_a', 3, '5'*64, 'CLAIMED_WIN'),
                 ('writer_b', 3, '5'*64, 'CLAIMED_CONFLICT')),
             ack_state='ACK_LOST_UNRESOLVED', release_ready=False,
             live_trading_allowed=False)
    fingerprint = hashlib.sha256(bytes.fromhex(PUBLIC)).hexdigest()
    trust = dict(public_key_hex=PUBLIC, fingerprint_sha256=fingerprint,
                 not_before=90, not_after=130, revocations=(),
                 spent_nonces=(), seen_roots=())
    return c, trust


def row(c, key, index, cell, value):
    rows = [list(x) for x in c[key]]
    rows[index][cell] = value
    c[key] = tuple(tuple(x) for x in rows)


class RC682SignatureAndQuarantine(unittest.TestCase):
    def verify(self, c, t, sig=None, digest=None, anchor=None):
        return quarantine_signed_checkpoint(
            c, t, sign(checkpoint_message(c)) if sig is None else sig,
            expected_transcript_sha256=digest if digest is not None else '4'*64,
            expected_anchor_sha256=anchor if anchor is not None else t['fingerprint_sha256'])

    def reject(self, mutate, *, stale_signature=False):
        c, t = fixture()
        original = sign(checkpoint_message(c)) if stale_signature else None
        mutate(c, t)
        with self.assertRaises(CheckpointRejected):
            self.verify(c, t, sig=original)

    def test_01_rfc8032_test_vector_1(self):
        self.assertTrue(verify_ed25519(PUBLIC, b'', RFC_SIG))
        self.assertEqual(sign(b''), RFC_SIG)

    def test_02_rfc8032_test_vector_2(self):
        key = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'
        sig = ('92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da'
               '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00')
        self.assertTrue(verify_ed25519(key, b'\x72', sig))

    def test_03_valid_math_without_authenticated_provenance(self):
        c, t = fixture()
        r = self.verify(c, t)
        self.assertTrue(r['signature_equation_valid'])
        self.assertTrue(r['lost_ack_unresolved'])
        for k, v in r.items():
            if k.endswith('authenticated') or k in ('durable_cas_verified', 'clock_verified',
                                                    'release_ready', 'live_trading_allowed'):
                self.assertIs(v, False)

    def test_04_repeated_stateless_verification_does_not_make_cas(self):
        c, t = fixture()
        self.assertEqual(self.verify(c, t), self.verify(copy.deepcopy(c), copy.deepcopy(t)))
        self.assertFalse(self.verify(c, t)['durable_cas_verified'])

    def test_05_wrong_signed_size_3_to_8(self):
        self.reject(lambda c,t: c.update(new_size=8), stale_signature=True)

    def test_06_stale_full_transcript_digest_after_bound_update(self):
        self.reject(lambda c,t: c.update(transcript_sha256='f'*64), stale_signature=True)

    def test_07_legitimate_revocation_not_authenticated(self):
        c, t = fixture()
        t['revocations'] = ((t['fingerprint_sha256'], 121),)
        self.assertFalse(self.verify(c, t)['revocation_origin_authenticated'])

    def test_08_rfc_signature_tamper(self):
        altered = ('0' if RFC_SIG[0] != '0' else '1') + RFC_SIG[1:]
        self.assertFalse(verify_ed25519(PUBLIC, b'', altered))

    def test_09_noncanonical_S(self):
        self.assertFalse(verify_ed25519(PUBLIC, b'', RFC_SIG[:64] + _L.to_bytes(32,'little').hex()))

    def test_10_small_order_public_key(self):
        self.assertFalse(verify_ed25519('01' + '00'*31, b'', RFC_SIG))

    def test_11_noncanonical_public_y(self):
        self.assertFalse(verify_ed25519(((2**255-19).to_bytes(32,'little')).hex(), b'', RFC_SIG))

    def test_12_noncanonical_R(self):
        self.assertFalse(verify_ed25519(PUBLIC, b'', ((2**255-19).to_bytes(32,'little')).hex()+RFC_SIG[64:]))

    def test_13_type_strict_signature(self):
        self.assertFalse(verify_ed25519(PUBLIC, b'', ['0'*128]))
        self.assertFalse(verify_ed25519(PUBLIC, 'not bytes', RFC_SIG))


MUTATIONS = (
    ('unknown_field', lambda c,t: c.update(extra=True), False),
    ('drop_field', lambda c,t: c.pop('git_sha'), False),
    ('bool_size', lambda c,t: c.update(new_size=True), False),
    ('rollback_size', lambda c,t: c.update(new_size=2), False),
    ('oversize_tree', lambda c,t: c.update(new_size=129), False),
    ('old_root_equal_new', lambda c,t: c.update(new_root_sha256=c['old_root_sha256']), False),
    ('old_root_swap', lambda c,t: c.update(old_root_sha256='f'*64), True),
    ('new_root_swap', lambda c,t: c.update(new_root_sha256='f'*64), True),
    ('nonce_swap', lambda c,t: c.update(nonce_sha256='f'*64), True),
    ('different_git', lambda c,t: c.update(git_sha='b'*40), True),
    ('different_source', lambda c,t: c.update(source_sha256='f'*64), False),
    ('different_roster', lambda c,t: c.update(roster_sha256='f'*64), True),
    ('different_workflow', lambda c,t: c.update(workflow_sha256='f'*64), True),
    ('wrong_provider_os', lambda c,t: row(c,'provider_claims',1,0,'ubuntu'), False),
    ('duplicate_provider_run', lambda c,t: row(c,'provider_claims',1,1,1001), False),
    ('duplicate_provider_job', lambda c,t: row(c,'provider_claims',1,2,2001), False),
    ('changed_run', lambda c,t: row(c,'provider_claims',1,1,1003), True),
    ('changed_job', lambda c,t: row(c,'provider_claims',0,2,2003), True),
    ('changed_log', lambda c,t: row(c,'provider_claims',0,5,'f'*64), True),
    ('provider_source_mismatch', lambda c,t: row(c,'provider_claims',0,4,'f'*64), False),
    ('provider_signed_claim', lambda c,t: row(c,'provider_claims',0,6,'VERIFIED'), False),
    ('double_cas_winners', lambda c,t: row(c,'writer_claims',1,3,'CLAIMED_WIN'), False),
    ('cas_false_ack', lambda c,t: c.update(ack_state='ACK_COMMITTED'), False),
    ('different_cas_actor', lambda c,t: row(c,'writer_claims',0,0,'writer_c'), True),
    ('cas_aba_base', lambda c,t: row(c,'writer_claims',1,2,'f'*64), False),
    ('cas_old_generation', lambda c,t: row(c,'writer_claims',1,1,2), False),
    ('duplicate_actor', lambda c,t: row(c,'writer_claims',1,0,'writer_a'), False),
    ('live_enabled', lambda c,t: c.update(live_trading_allowed=True), False),
    ('release_enabled', lambda c,t: c.update(release_ready=True), False),
    ('lost_ack_asserted_applied', lambda c,t: c.update(ack_state='ACK_APPLIED'), False),
    ('future_issue_time', lambda c,t: c.update(issued_at=121), False),
    ('anchor_fingerprint_swap', lambda c,t: t.update(fingerprint_sha256='f'*64), False),
    ('different_public_key', lambda c,t: t.update(public_key_hex='a'*64), False),
    ('expired_anchor', lambda c,t: t.update(not_after=99), False),
    ('not_yet_valid_anchor', lambda c,t: t.update(not_before=101), False),
    ('revoked_key', lambda c,t: t.update(revocations=((t['fingerprint_sha256'],120),)), False),
    ('repeated_revocation', lambda c,t: t.update(revocations=((t['fingerprint_sha256'],90),(t['fingerprint_sha256'],110))), False),
    ('noncanonical_revocation', lambda c,t: t.update(revocations=[(t['fingerprint_sha256'],100)]), False),
    ('spent_nonce_replay', lambda c,t: t.update(spent_nonces=('7'*64,)), False),
    ('seen_root_replay', lambda c,t: t.update(seen_roots=('6'*64,)), False),
    ('noncanonical_spent', lambda c,t: t.update(spent_nonces=['7'*64]), False),
    ('duplicate_seen_root', lambda c,t: t.update(seen_roots=('e'*64,'e'*64)), False),
    ('trust_extra_field', lambda c,t: t.update(fake_approved=True), False),
    ('unbound_claimed_transcript', lambda c,t: c.update(transcript_sha256='f'*64), False),
)


def make_case(fn, stale):
    def test(self):
        self.reject(fn, stale_signature=stale)
    return test


for i, (name, mutate, stale) in enumerate(MUTATIONS, 14):
    setattr(RC682SignatureAndQuarantine, 'test_%02d_%s' % (i, name), make_case(mutate, stale))


if __name__ == '__main__':
    unittest.main()
