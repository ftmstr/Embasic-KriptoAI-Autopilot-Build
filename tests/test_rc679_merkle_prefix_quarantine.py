"""Original invented-only Merkle proof, root and authority spoof regressions."""
import copy
import hashlib
import unittest

from safe_public_ci.ci_merkle_prefix_quarantine import (
    MerkleClaimRejected, receipt_leaf_sha256, merkle_root_sha256,
    inclusion_path_sha256, inclusion_root_sha256, quarantine_merkle_prefix,
)


def H(ch):
    return ch * 64


KEYS = (H('b'), H('c'), H('d'))
ROLES = ('owner', 'independent_reviewer', 'incumbent_custodian')


def fixture(size=3):
    meta = {
        'repository': 'ftmstr/Embasic-KriptoAI-Autopilot-Build',
        'branch': 'validation/rc654-pr1-rc653-combined-ci',
        'git_sha': 'a' * 40, 'source_sha256': H('1'),
        'workflow_sha256': H('2'), 'roster_sha256': H('3'),
        'authority_root_sha256': H('4'), 'nonce_sha256': H('5'),
        'generation': 5, 'issued_at': 100,
        'release_ready': False, 'live_trading_allowed': False,
    }
    prior = tuple(hashlib.sha256(('synthetic-prior-%d' % i).encode()).hexdigest()
                  for i in range(size))
    leaf = receipt_leaf_sha256(meta)
    updated = (*prior, leaf)
    old_root = merkle_root_sha256(prior)
    new_root = merkle_root_sha256(updated)
    path = inclusion_path_sha256(updated, len(prior))
    claims = {
        'old_generation': 4, 'new_generation': 5,
        'old_root_sha256': old_root, 'new_root_sha256': new_root,
        'observed_at': 120,
        'writer_views': (
            ('writer_a', 4, old_root, 'CLAIMED_WIN'),
            ('writer_b', 4, old_root, 'CLAIMED_CONFLICT'),
        ),
        'provider_views': (
            ('ubuntu', 300, 400, meta['git_sha'], new_root, 110, 'NOT_VERIFIED', meta['source_sha256']),
            ('windows', 301, 401, meta['git_sha'], new_root, 112, 'NOT_VERIFIED', meta['source_sha256']),
        ),
        'reviewer_views': tuple(
            (role, actor, key, 80, 160, 105 + i, 'NOT_VERIFIED')
            for i, (role, actor, key) in enumerate(zip(
                ROLES, ('owner_a', 'reviewer_b', 'custodian_c'), KEYS))
        ),
        'ack_state': 'NOT_SENT', 'release_ready': False,
        'live_trading_allowed': False,
    }
    pins = {
        'expected_git_sha': meta['git_sha'],
        'expected_source_sha256': meta['source_sha256'],
        'expected_workflow_sha256': meta['workflow_sha256'],
        'expected_roster_sha256': meta['roster_sha256'],
        'expected_authority_root_sha256': meta['authority_root_sha256'],
        'expected_nonce_sha256': meta['nonce_sha256'],
        'expected_old_root_sha256': old_root,
        'expected_new_root_sha256': new_root,
        'expected_receipt_sha256': leaf,
        'reviewer_keys': KEYS, 'revocation_events': (),
        'spent_nonce_sha256': (), 'seen_root_sha256': (),
    }
    return meta, prior, updated, path, claims, pins


def edit_row(c, name, i, key, value):
    data = list(c[name]); row = list(data[i]); row[key] = value
    data[i] = tuple(row); c[name] = tuple(data)


class RC679MerklePrefixTests(unittest.TestCase):
    def rejected(self, mut):
        meta, old, new, proof, claims, pins = fixture()
        obj = dict(meta=meta, old=old, new=new, proof=proof,
                   claims=claims, pins=pins)
        mut(obj)
        with self.assertRaises(MerkleClaimRejected):
            quarantine_merkle_prefix(obj['meta'], obj['old'], obj['new'],
                                     obj['proof'], obj['claims'], pinned=obj['pins'])

    def test_01_claim_consistent_but_not_authenticated(self):
        meta, old, new, path, claims, pins = fixture()
        r = quarantine_merkle_prefix(meta, old, new, path, claims, pinned=pins)
        self.assertEqual(r['status'], 'MERKLE_PREFIX_CLAIM_QUARANTINED_NOT_AUTHENTICATED')
        for name in ('trust_anchor_authenticated', 'signatures_verified',
                     'clock_verified', 'provider_origin_verified',
                     'atomic_cas_verified', 'durable_write_verified',
                     'release_ready', 'live_trading_allowed'):
            self.assertIs(r[name], False)

    def test_02_known_empty_tree_root(self):
        self.assertEqual(merkle_root_sha256(()), hashlib.sha256(b'').hexdigest())

    def test_03_known_single_leaf_prefix(self):
        leaf = H('a')
        self.assertEqual(merkle_root_sha256((leaf,)),
                         hashlib.sha256(b'\x00' + bytes.fromhex(leaf)).hexdigest())

    def test_04_domains_are_different(self):
        a = H('f'); b = H('e')
        raw = hashlib.sha256(bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()
        self.assertNotEqual(raw, merkle_root_sha256((a, b)))

    def test_05_all_merkle_shapes_up_to_128(self):
        for n in range(1, 129):
            seq = tuple(hashlib.sha256(('leaf-%d' % i).encode()).hexdigest()
                        for i in range(n))
            for i in (0, n // 2, n - 1):
                path = inclusion_path_sha256(seq, i)
                self.assertEqual(inclusion_root_sha256(seq[i], i, n, path),
                                 merkle_root_sha256(seq))

    def test_06_proof_is_independent_of_copied_history(self):
        meta, old, new, proof, claims, pins = fixture(7)
        self.assertEqual(inclusion_root_sha256(new[-1], len(old), len(new), proof),
                         merkle_root_sha256(new))

    def test_07_lost_ack_never_confirms_write(self):
        meta, old, new, proof, claims, pins = fixture()
        claims['ack_state'] = 'ACK_LOST_UNRESOLVED'
        r = quarantine_merkle_prefix(meta, old, new, proof, claims, pinned=pins)
        self.assertTrue(r['lost_ack_unresolved'])
        self.assertFalse(r['durable_write_verified'])

    def test_08_repeat_call_does_not_consume(self):
        args = fixture()
        r = quarantine_merkle_prefix(*args[:4], args[4], pinned=args[5])
        self.assertEqual(r, quarantine_merkle_prefix(*args[:4], args[4], pinned=args[5]))

    def test_09_both_evidence_and_pins_forged_still_unauthenticated(self):
        meta, old, new, proof, claims, pins = fixture()
        meta['source_sha256'] = H('e')
        pins['expected_source_sha256'] = H('e')
        leaf = receipt_leaf_sha256(meta)
        new = (*old, leaf)
        proof = inclusion_path_sha256(new, len(old))
        new_root = merkle_root_sha256(new)
        claims['new_root_sha256'] = pins['expected_new_root_sha256'] = new_root
        pins['expected_receipt_sha256'] = leaf
        for index in (0, 1):
            edit_row(claims, 'provider_views', index, 4, new_root)
            edit_row(claims, 'provider_views', index, 7, H('e'))
        r = quarantine_merkle_prefix(meta, old, new, proof, claims, pinned=pins)
        self.assertFalse(r['trust_anchor_authenticated'])
        self.assertFalse(r['provider_origin_verified'])

    def test_10_future_revocation_is_still_not_auth(self):
        meta, old, new, proof, claims, pins = fixture()
        pins['revocation_events'] = ((KEYS[0], 121),)
        r = quarantine_merkle_prefix(meta, old, new, proof, claims, pinned=pins)
        self.assertFalse(r['signatures_verified'])

    def test_11_inclusion_truncated(self):
        seq = (H('1'), H('2'), H('3'))
        path = inclusion_path_sha256(seq, 2)
        with self.assertRaises(MerkleClaimRejected):
            inclusion_root_sha256(seq[2], 2, 3, path[:-1])

    def test_12_inclusion_extra_node(self):
        seq = (H('1'), H('2'), H('3'))
        path = inclusion_path_sha256(seq, 2)
        with self.assertRaises(MerkleClaimRejected):
            inclusion_root_sha256(seq[2], 2, 3, (*path, H('4')))

    def test_13_inclusion_wrong_size(self):
        seq = (H('1'), H('2'), H('3'))
        path = inclusion_path_sha256(seq, 2)
        with self.assertRaises(MerkleClaimRejected):
            inclusion_root_sha256(seq[2], 2, 4, path)

    def test_14_inclusion_wrong_sibling(self):
        seq = (H('1'), H('2'), H('3'))
        path = inclusion_path_sha256(seq, 2)
        changed = (H('f'), *path[1:])
        self.assertNotEqual(inclusion_root_sha256(seq[2], 2, 3, changed),
                            merkle_root_sha256(seq))

    def test_15_noninteger_negative_or_bool_index(self):
        seq = (H('1'),)
        for index in (True, -1, 1.0, '0'):
            with self.assertRaises(MerkleClaimRejected):
                inclusion_path_sha256(seq, index)


CASES = (
    ('private_repo', lambda x: x['meta'].update(repository='ftmstr/Private')),
    ('main_branch', lambda x: x['meta'].update(branch='main')),
    ('git_bad_hex', lambda x: x['meta'].update(git_sha='g' * 40)),
    ('git_pin_rebind', lambda x: x['pins'].update(expected_git_sha='b' * 40)),
    ('source_pin_rebind', lambda x: x['pins'].update(expected_source_sha256=H('e'))),
    ('workflow_pin_rebind', lambda x: x['pins'].update(expected_workflow_sha256=H('e'))),
    ('roster_pin_rebind', lambda x: x['pins'].update(expected_roster_sha256=H('e'))),
    ('authority_pin_rebind', lambda x: x['pins'].update(expected_authority_root_sha256=H('e'))),
    ('nonce_pin_rebind', lambda x: x['pins'].update(expected_nonce_sha256=H('e'))),
    ('old_root_pin_rebind', lambda x: x['pins'].update(expected_old_root_sha256=H('e'))),
    ('new_root_pin_rebind', lambda x: x['pins'].update(expected_new_root_sha256=H('e'))),
    ('receipt_pin_rebind', lambda x: x['pins'].update(expected_receipt_sha256=H('e'))),
    ('old_root_claim_rebind', lambda x: x['claims'].update(old_root_sha256=H('e'))),
    ('new_root_claim_rebind', lambda x: x['claims'].update(new_root_sha256=H('e'))),
    ('source_mutate', lambda x: x['meta'].update(source_sha256=H('e'))),
    ('workflow_mutate', lambda x: x['meta'].update(workflow_sha256=H('e'))),
    ('roster_mutate', lambda x: x['meta'].update(roster_sha256=H('e'))),
    ('nonce_mutate', lambda x: x['meta'].update(nonce_sha256=H('e'))),
    ('old_prefix_mutate', lambda x: x.update(old=(H('e'), *x['old'][1:]))),
    ('new_prefix_mutate', lambda x: x.update(new=(H('e'), *x['new'][1:]))),
    ('new_leaf_mutate', lambda x: x.update(new=(*x['new'][:-1], H('e')))),
    ('new_history_duplicate', lambda x: x.update(new=(*x['new'][:-1], x['new'][0]))),
    ('new_history_short', lambda x: x.update(new=x['old'])),
    ('new_history_extra', lambda x: x.update(new=(*x['new'], H('e')))),
    ('history_not_tuple', lambda x: x.update(old=list(x['old']))),
    ('proof_not_tuple', lambda x: x.update(proof=list(x['proof']))),
    ('proof_missing', lambda x: x.update(proof=x['proof'][:-1])),
    ('proof_extra', lambda x: x.update(proof=(*x['proof'], H('e')))),
    ('proof_corrupted', lambda x: x.update(proof=(H('e'), *x['proof'][1:]))),
    ('generation_skip', lambda x: x['claims'].update(new_generation=7)),
    ('generation_rollback', lambda x: x['claims'].update(old_generation=3)),
    ('boolean_generation', lambda x: x['meta'].update(generation=True)),
    ('issued_at_boolean', lambda x: x['meta'].update(issued_at=True)),
    ('observer_before_issue', lambda x: x['claims'].update(observed_at=99)),
    ('ack_applied_forgery', lambda x: x['claims'].update(ack_state='ACK_APPLIED')),
    ('live_true_meta', lambda x: x['meta'].update(live_trading_allowed=True)),
    ('release_true_claim', lambda x: x['claims'].update(release_ready=True)),
    ('unexpected_meta', lambda x: x['meta'].update(signed=True)),
    ('unexpected_pin', lambda x: x['pins'].update(authenticated=True)),
    ('spent_nonce', lambda x: x['pins'].update(spent_nonce_sha256=(H('5'),))),
    ('used_checkpoint_root', lambda x: x['pins'].update(seen_root_sha256=(x['claims']['new_root_sha256'],))),
    ('seen_nonce_not_tuple', lambda x: x['pins'].update(spent_nonce_sha256=[H('5')])),
    ('revoked_owner_key', lambda x: x['pins'].update(revocation_events=((KEYS[0], 120),))),
    ('revoked_reviewer_key', lambda x: x['pins'].update(revocation_events=((KEYS[1], 110),))),
    ('revoked_custodian_key', lambda x: x['pins'].update(revocation_events=((KEYS[2], 111),))),
    ('fake_verified_reviewer', lambda x: edit_row(x['claims'],'reviewer_views',1,6,'SIGNED')),
    ('expired_reviewer', lambda x: edit_row(x['claims'],'reviewer_views',0,4,100)),
    ('duplicate_reviewer', lambda x: edit_row(x['claims'],'reviewer_views',1,1,'owner_a')),
    ('duplicate_reviewer_key', lambda x: edit_row(x['claims'],'reviewer_views',1,2,KEYS[0])),
    ('foreign_reviewer_pin', lambda x: x['pins'].update(reviewer_keys=(KEYS[0],H('e'),KEYS[2]))),
    ('double_cas_winner', lambda x: edit_row(x['claims'],'writer_views',1,3,'CLAIMED_WIN')),
    ('double_cas_conflict', lambda x: edit_row(x['claims'],'writer_views',0,3,'CLAIMED_CONFLICT')),
    ('writer_stale_old_root', lambda x: edit_row(x['claims'],'writer_views',1,2,H('e'))),
    ('provider_fork_root', lambda x: edit_row(x['claims'],'provider_views',1,4,H('e'))),
    ('provider_relabel_sha', lambda x: edit_row(x['claims'],'provider_views',0,3,'b'*40)),
    ('provider_fake_signed', lambda x: edit_row(x['claims'],'provider_views',0,6,'GITHUB_SIGNED')),
    ('provider_relabel_source', lambda x: edit_row(x['claims'],'provider_views',1,7,H('e'))),
    ('provider_duplicate_job', lambda x: edit_row(x['claims'],'provider_views',1,2,400)),
    ('provider_stale_time', lambda x: edit_row(x['claims'],'provider_views',0,5,99)),
    ('provider_wrong_os', lambda x: edit_row(x['claims'],'provider_views',1,0,'ubuntu')),
)


def _make_test(change):
    def run(self):
        self.rejected(change)
    return run


for idx, (name, mutate) in enumerate(CASES, 16):
    setattr(RC679MerklePrefixTests, 'test_%02d_%s' % (idx, name), _make_test(mutate))


if __name__ == '__main__':
    unittest.main()
