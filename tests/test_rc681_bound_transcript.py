"""Original all-invented transcript-binding, issuer, Merkle and CAS adversaries."""
import copy
import hashlib
import unittest

from safe_public_ci.ci_bound_transcript_quarantine import (
    TranscriptRejected, transcript_sha256, quarantine_bound_transcript,
    _tree, _consistency,
)


def h(ch):
    return ch * 64


KEYS = (h('a'), h('b'), h('c'))
ROLES = ('owner', 'independent_reviewer', 'incumbent_custodian')
LEAVES = tuple(hashlib.sha256(('RC681-invented-leaf-' + str(i)).encode()).hexdigest()
               for i in range(128))


def fixture(old_size=3, new_size=9):
    full = LEAVES[:new_size]
    old_root = _tree(full[:old_size]).hex()
    new_root = _tree(full).hex()
    c = dict(
        repository='ftmstr/Embasic-KriptoAI-Autopilot-Build',
        branch='validation/rc654-pr1-rc653-combined-ci',
        git_sha='a' * 40, source_sha256=h('1'), workflow_sha256=h('2'),
        roster_sha256=h('3'), old_size=old_size, new_size=new_size,
        old_root_sha256=old_root, new_root_sha256=new_root,
        nonce_sha256=h('4'), issued_at=100, observed_at=120,
        full_history=full, consistency_proof=_consistency(full, old_size),
        issuer_claims=tuple(
            (role, who, key, 80, 160, 105 + i, 'NOT_VERIFIED')
            for i, (role, who, key) in enumerate(zip(
                ROLES, ('owner_a', 'reviewer_b', 'custodian_c'), KEYS))),
        provider_claims=(
            ('ubuntu', 300, 400, 'a' * 40, h('1'), old_root, new_root, 110, 'NOT_VERIFIED'),
            ('windows', 301, 401, 'a' * 40, h('1'), old_root, new_root, 111, 'NOT_VERIFIED'),
        ),
        writer_claims=(
            ('writer_a', old_size, old_root, new_root, 'CLAIMED_WIN'),
            ('writer_b', old_size, old_root, new_root, 'CLAIMED_CONFLICT'),
        ),
        revocation_events=((h('9'), 90),), spent_nonces=(), seen_roots=(),
        ack_state='NOT_SENT', release_ready=False, live_trading_allowed=False,
    )
    p = {key: c[key] for key in (
        'git_sha', 'source_sha256', 'workflow_sha256', 'roster_sha256',
        'old_root_sha256', 'new_root_sha256', 'nonce_sha256',
    )}
    p['issuer_key_fingerprints'] = KEYS
    p['expected_transcript_sha256'] = transcript_sha256(c)
    return c, p


def set_row(c, group, i, field, value):
    arr = list(c[group])
    row = list(arr[i])
    row[field] = value
    arr[i] = tuple(row)
    c[group] = tuple(arr)


class RC681BoundTranscriptTests(unittest.TestCase):
    def reject(self, fn):
        c, p = fixture()
        fn(c, p)
        with self.assertRaises(TranscriptRejected):
            quarantine_bound_transcript(c, pinned=p)

    def test_01_matching_transcript_always_not_authenticated(self):
        c, p = fixture()
        r = quarantine_bound_transcript(c, pinned=p)
        self.assertEqual(r['status'], 'FULL_TRANSCRIPT_BOUND_QUARANTINED_NOT_AUTHENTICATED')
        for flag in ('provider_origin_authenticated', 'signatures_verified',
                     'clock_verified', 'merkle_anchor_authenticated',
                     'cas_atomicity_verified', 'durable_write_verified',
                     'release_ready', 'live_trading_allowed'):
            self.assertIs(r[flag], False)

    def test_02_deterministic_across_independent_copies(self):
        c, p = fixture()
        self.assertEqual(transcript_sha256(c), transcript_sha256(copy.deepcopy(c)))

    def test_03_valid_provider_id_change_is_cryptographically_bound(self):
        c, _ = fixture()
        original = transcript_sha256(c)
        set_row(c, 'provider_claims', 1, 1, 302)
        self.assertNotEqual(original, transcript_sha256(c))

    def test_04_valid_issuer_identity_change_is_bound(self):
        c, _ = fixture()
        original = transcript_sha256(c)
        set_row(c, 'issuer_claims', 0, 1, 'owner_new')
        self.assertNotEqual(original, transcript_sha256(c))

    def test_05_valid_signed_at_claim_change_is_bound(self):
        c, _ = fixture()
        original = transcript_sha256(c)
        set_row(c, 'issuer_claims', 2, 5, 114)
        self.assertNotEqual(original, transcript_sha256(c))

    def test_06_valid_writer_identity_change_is_bound(self):
        c, _ = fixture()
        original = transcript_sha256(c)
        set_row(c, 'writer_claims', 0, 0, 'writer_new')
        self.assertNotEqual(original, transcript_sha256(c))

    def test_07_valid_future_revocation_is_bound(self):
        c, _ = fixture()
        original = transcript_sha256(c)
        c['revocation_events'] = tuple(sorted((*c['revocation_events'], (KEYS[0], 121))))
        self.assertNotEqual(original, transcript_sha256(c))

    def test_08_altered_full_history_rejected_even_with_same_size(self):
        self.reject(lambda c, p: c.update(full_history=(h('f'), *c['full_history'][1:])))

    def test_09_missing_old_prefix_sibling_rejected(self):
        self.reject(lambda c, p: c.update(consistency_proof=c['consistency_proof'][:-1]))

    def test_10_lost_ack_always_unresolved(self):
        c, p = fixture()
        c['ack_state'] = 'ACK_LOST_UNRESOLVED'
        p['expected_transcript_sha256'] = transcript_sha256(c)
        answer = quarantine_bound_transcript(c, pinned=p)
        self.assertTrue(answer['lost_ack_unresolved'])
        self.assertFalse(answer['durable_write_verified'])

    def test_11_parallel_pure_calls_cannot_grant_single_winner(self):
        c, p = fixture()
        one = quarantine_bound_transcript(c, pinned=p)
        two = quarantine_bound_transcript(c, pinned=p)
        self.assertEqual(one, two)
        self.assertFalse(one['cas_atomicity_verified'])

    def test_12_attacker_controls_claim_and_pins_cannot_authenticate(self):
        c, p = fixture()
        c['source_sha256'] = p['source_sha256'] = h('e')
        for i in (0, 1):
            set_row(c, 'provider_claims', i, 4, h('e'))
        p['expected_transcript_sha256'] = transcript_sha256(c)
        result = quarantine_bound_transcript(c, pinned=p)
        self.assertFalse(result['provider_origin_authenticated'])
        self.assertFalse(result['signatures_verified'])

    def test_13_full_history_size_proof_all_128_boundaries(self):
        for n in range(2, 129):
            for m in (1, n // 2, n - 1):
                c, p = fixture(m, n)
                self.assertEqual(transcript_sha256(c), p['expected_transcript_sha256'])

    def test_14_original_3_to_7_proof_must_reject_claimed_3_to_8(self):
        c, p = fixture(3, 7)
        c['new_size'] = 8
        with self.assertRaises(TranscriptRejected):
            quarantine_bound_transcript(c, pinned=p)

    def test_15_before_after_merkle_roots_distinct(self):
        c, _ = fixture()
        self.assertNotEqual(c['old_root_sha256'], c['new_root_sha256'])

    def test_16_sha_domain_separated_from_ordinary_concatenation(self):
        c, _ = fixture()
        self.assertNotEqual(transcript_sha256(c), hashlib.sha256(
            (c['git_sha'] + c['source_sha256']).encode()).hexdigest())


CASES = (
    ('foreign_repository', lambda c,p: c.update(repository='ftmstr/Private')),
    ('main_branch', lambda c,p: c.update(branch='main')),
    ('git_invalid_hex', lambda c,p: c.update(git_sha='g'*40)),
    ('git_pin_mismatch', lambda c,p: p.update(git_sha='b'*40)),
    ('source_pin_mismatch', lambda c,p: p.update(source_sha256=h('e'))),
    ('workflow_pin_mismatch', lambda c,p: p.update(workflow_sha256=h('e'))),
    ('roster_pin_mismatch', lambda c,p: p.update(roster_sha256=h('e'))),
    ('old_root_pin_mismatch', lambda c,p: p.update(old_root_sha256=h('e'))),
    ('new_root_pin_mismatch', lambda c,p: p.update(new_root_sha256=h('e'))),
    ('nonce_pin_mismatch', lambda c,p: p.update(nonce_sha256=h('e'))),
    ('transcript_pin_mismatch', lambda c,p: p.update(expected_transcript_sha256=h('e'))),
    ('missing_expected_pin', lambda c,p: p.pop('expected_transcript_sha256')),
    ('unexpected_pin', lambda c,p: p.update(approve=True)),
    ('missing_source_field', lambda c,p: c.pop('source_sha256')),
    ('extra_claim_field', lambda c,p: c.update(authenticated=True)),
    ('bool_old_size', lambda c,p: c.update(old_size=True)),
    ('bool_new_size', lambda c,p: c.update(new_size=True)),
    ('old_size_zero', lambda c,p: c.update(old_size=0)),
    ('new_size_too_large', lambda c,p: c.update(new_size=129)),
    ('old_ge_new_size', lambda c,p: c.update(old_size=9)),
    ('new_size_nonint', lambda c,p: c.update(new_size='9')),
    ('issued_after_observed', lambda c,p: c.update(issued_at=121)),
    ('issued_bool', lambda c,p: c.update(issued_at=True)),
    ('observed_zero', lambda c,p: c.update(observed_at=0)),
    ('nonce_invalid', lambda c,p: c.update(nonce_sha256='untrusted')),
    ('released_flag', lambda c,p: c.update(release_ready=True)),
    ('live_flag', lambda c,p: c.update(live_trading_allowed=True)),
    ('claimed_applied_ack', lambda c,p: c.update(ack_state='ACK_APPLIED')),
    ('ack_nonstring', lambda c,p: c.update(ack_state=1)),
    ('history_as_list', lambda c,p: c.update(full_history=list(c['full_history']))),
    ('history_shrunk', lambda c,p: c.update(full_history=c['full_history'][:-1])),
    ('history_duplicate_leaf', lambda c,p: c.update(full_history=(*c['full_history'][:-1],c['full_history'][0]))),
    ('history_bad_leaf_hex', lambda c,p: c.update(full_history=(h('z'),*c['full_history'][1:]))),
    ('history_reordered', lambda c,p: c.update(full_history=tuple(reversed(c['full_history'])))),
    ('history_prepend', lambda c,p: c.update(full_history=(h('f'),*c['full_history'][:-1])),
    ('consistency_as_list', lambda c,p: c.update(consistency_proof=list(c['consistency_proof']))),
    ('consistency_extra_node', lambda c,p: c.update(consistency_proof=(*c['consistency_proof'],h('f')))),
    ('consistency_corrupt_node', lambda c,p: c.update(consistency_proof=(h('f'),*c['consistency_proof'][1:]))),
    ('consistency_missing_node', lambda c,p: c.update(consistency_proof=c['consistency_proof'][1:])),
    ('old_root_substitution', lambda c,p: c.update(old_root_sha256=h('e'))),
    ('new_root_substitution', lambda c,p: c.update(new_root_sha256=h('e'))),
    ('size_aba_same_root', lambda c,p: c.update(new_root_sha256=c['old_root_sha256'])),
    ('issuer_wrong_role', lambda c,p: set_row(c,'issuer_claims',1,0,'owner')),
    ('issuer_duplicate_person', lambda c,p: set_row(c,'issuer_claims',1,1,'owner_a')),
    ('issuer_duplicate_key', lambda c,p: set_row(c,'issuer_claims',1,2,KEYS[0])),
    ('issuer_foreign_fingerprint', lambda c,p: p.update(issuer_key_fingerprints=(KEYS[0],h('f'),KEYS[2]))),
    ('issuer_bad_key', lambda c,p: set_row(c,'issuer_claims',0,2,'bad')),
    ('issuer_not_yet_valid', lambda c,p: set_row(c,'issuer_claims',0,3,111)),
    ('issuer_expired', lambda c,p: set_row(c,'issuer_claims',1,4,102)),
    ('issuer_signed_future', lambda c,p: set_row(c,'issuer_claims',1,5,121)),
    ('issuer_signed_before_issued', lambda c,p: set_row(c,'issuer_claims',1,5,99)),
    ('issuer_fake_verified', lambda c,p: set_row(c,'issuer_claims',1,6,'VERIFIED')),
    ('issuer_signed_claim', lambda c,p: set_row(c,'issuer_claims',2,6,'SIGNED')),
    ('issuer_invalid_id', lambda c,p: set_row(c,'issuer_claims',0,1,'owner-a')),
    ('issuer_missing', lambda c,p: c.update(issuer_claims=c['issuer_claims'][:2])),
    ('provider_wrong_os', lambda c,p: set_row(c,'provider_claims',1,0,'ubuntu')),
    ('provider_duplicate_run', lambda c,p: set_row(c,'provider_claims',1,1,300)),
    ('provider_duplicate_job', lambda c,p: set_row(c,'provider_claims',1,2,400)),
    ('provider_wrong_git', lambda c,p: set_row(c,'provider_claims',0,3,'b'*40)),
    ('provider_source_rebind', lambda c,p: set_row(c,'provider_claims',0,4,h('f'))),
    ('provider_old_root_fork', lambda c,p: set_row(c,'provider_claims',0,5,h('f'))),
    ('provider_new_root_fork', lambda c,p: set_row(c,'provider_claims',1,6,h('f'))),
    ('provider_stale_time', lambda c,p: set_row(c,'provider_claims',0,7,99)),
    ('provider_future_time', lambda c,p: set_row(c,'provider_claims',1,7,121)),
    ('provider_claims_signed', lambda c,p: set_row(c,'provider_claims',0,8,'GITHUB_SIGNED')),
    ('provider_run_bool', lambda c,p: set_row(c,'provider_claims',0,1,True)),
    ('provider_missing', lambda c,p: c.update(provider_claims=c['provider_claims'][:1])),
    ('writer_both_win', lambda c,p: set_row(c,'writer_claims',1,4,'CLAIMED_WIN')),
    ('writer_both_conflict', lambda c,p: set_row(c,'writer_claims',0,4,'CLAIMED_CONFLICT')),
    ('writer_duplicate_actor', lambda c,p: set_row(c,'writer_claims',1,0,'writer_a')),
    ('writer_wrong_base_size', lambda c,p: set_row(c,'writer_claims',0,1,2)),
    ('writer_wrong_old_root', lambda c,p: set_row(c,'writer_claims',0,2,h('f'))),
    ('writer_wrong_proposed_root', lambda c,p: set_row(c,'writer_claims',1,3,h('f'))),
    ('writer_false_committed', lambda c,p: set_row(c,'writer_claims',0,4,'COMMITTED')),
    ('revocation_reviewer_expired', lambda c,p: c.update(revocation_events=tuple(sorted((*c['revocation_events'],(KEYS[1],119)))))),
    ('revocation_owner_expired', lambda c,p: c.update(revocation_events=tuple(sorted((*c['revocation_events'],(KEYS[0],100)))))),
    ('revocation_custodian_expired', lambda c,p: c.update(revocation_events=tuple(sorted((*c['revocation_events'],(KEYS[2],120)))))),
    ('revocation_duplicate_key', lambda c,p: c.update(revocation_events=((h('9'),90),(h('9'),95)))),
    ('revocation_unsorted', lambda c,p: c.update(revocation_events=((KEYS[1],121),(h('9'),90)))),
    ('revocation_list', lambda c,p: c.update(revocation_events=[(h('9'),90)])),
    ('revocation_bool_timestamp', lambda c,p: c.update(revocation_events=((h('9'),True),))),
    ('spent_nonce_replay', lambda c,p: c.update(spent_nonces=(h('4'),))),
    ('spent_nonce_as_list', lambda c,p: c.update(spent_nonces=[h('4')])),
    ('seen_new_merkle_root', lambda c,p: c.update(seen_roots=(c['new_root_sha256'],))),
    ('seen_root_duplicate', lambda c,p: c.update(seen_roots=(h('e'),h('e')))),
    ('seen_roots_unsorted', lambda c,p: c.update(seen_roots=(h('f'),h('d')))),
)


def _make_case(mutation):
    def check(self):
        self.reject(mutation)
    return check


for idx, (name, fn) in enumerate(CASES, 17):
    setattr(RC681BoundTranscriptTests, 'test_%02d_%s' % (idx,name), _make_case(fn))


if __name__ == '__main__':
    unittest.main()
