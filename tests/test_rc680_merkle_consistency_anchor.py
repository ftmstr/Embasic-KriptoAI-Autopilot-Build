"""RC680 original and invented-only Merkle consistency, provenance and CAS tests."""
import copy
import hashlib
import unittest

from safe_public_ci.ci_merkle_consistency_anchor_quarantine import (
    AnchorClaimRejected, merkle_root, consistency_path,
    verify_consistency, statement_sha256, quarantine_anchor_consistency,
)


def D(v):
    return v * 64


KEYS = (D('a'), D('b'), D('c'))
ROLES = ('owner', 'independent_reviewer', 'incumbent_custodian')
LEAVES = tuple(hashlib.sha256(('invented-%02d' % i).encode()).hexdigest()
               for i in range(12))


def fixture(m=3, n=7):
    old = merkle_root(LEAVES[:m])
    new = merkle_root(LEAVES[:n])
    c = dict(repository='ftmstr/Embasic-KriptoAI-Autopilot-Build',
             branch='validation/rc654-pr1-rc653-combined-ci',
             git_sha='a' * 40, source_sha256=D('1'), workflow_sha256=D('2'),
             roster_sha256=D('3'), old_root_sha256=old,
             new_root_sha256=new, old_size=m, new_size=n,
             nonce_sha256=D('4'), issued_at=100, observed_at=120,
             issuer_claims=tuple((role, actor, key, 105+i, 'NOT_VERIFIED')
                                 for i, (role, actor, key) in enumerate(zip(
                                     ROLES, ('owner_a', 'reviewer_b', 'custodian_c'), KEYS))),
             provider_claims=(('ubuntu', 300, 400, 'a'*40, new, 110, 'NOT_VERIFIED'),
                              ('windows', 301, 401, 'a'*40, new, 111, 'NOT_VERIFIED')),
             writer_claims=(('worker_a', m, old, 'CLAIMED_WIN'),
                            ('worker_b', m, old, 'CLAIMED_CONFLICT')),
             ack_state='NOT_SENT', release_ready=False, live_trading_allowed=False)
    p = {k: c[k] for k in ('git_sha', 'source_sha256', 'workflow_sha256',
                           'roster_sha256', 'old_root_sha256',
                           'new_root_sha256', 'nonce_sha256')}
    p.update(issuer_key_fingerprints=KEYS, revocation_events=(),
             spent_nonces=(), seen_roots=(),
             expected_statement_sha256=statement_sha256(c))
    return c, consistency_path(LEAVES[:n], m), p, LEAVES[:n]


def edit_row(claim, key, i, field, val):
    data = list(claim[key]); row = list(data[i]); row[field] = val
    data[i] = tuple(row); claim[key] = tuple(data)


class RC680MerkleConsistencyAdversarialTests(unittest.TestCase):
    def reject(self, change):
        claim, path, pins, history = fixture()
        v = {'c': claim, 'path': path, 'p': pins, 'history': history}
        change(v)
        with self.assertRaises(AnchorClaimRejected):
            quarantine_anchor_consistency(v['c'], v['path'], pinned=v['p'], full_history=v['history'])

    def test_01_untrusted_matching_case_only_quarantined(self):
        c, path, pins, history = fixture()
        result = quarantine_anchor_consistency(c, path, pinned=pins, full_history=history)
        self.assertEqual(result['status'],
                         'MERKLE_CONSISTENCY_CLAIM_QUARANTINED_NOT_AUTHENTICATED')
        for k in ('authenticated_signatures', 'authenticated_anchor',
                  'authenticated_clock', 'authenticated_provider_origin',
                  'cas_atomicity_verified', 'durable_write_verified',
                  'release_ready', 'live_trading_allowed'):
            self.assertIs(result[k], False)

    def test_02_compact_proofs_all_bounded_sizes(self):
        leaves = tuple(hashlib.sha256(str(i).encode()).hexdigest() for i in range(128))
        for n in range(2, 129):
            for m in range(1, n):
                proof = consistency_path(leaves[:n], m)
                self.assertTrue(verify_consistency(
                    m, n, merkle_root(leaves[:m]), merkle_root(leaves[:n]), proof, full_history=leaves[:n]))

    def test_03_equal_size_requires_identical_root_and_empty_proof(self):
        root = merkle_root(LEAVES[:4])
        self.assertTrue(verify_consistency(4, 4, root, root, (), full_history=LEAVES[:4]))
        with self.assertRaises(AnchorClaimRejected):
            verify_consistency(4, 4, root, root, (D('f'),), full_history=LEAVES[:4])

    def test_04_truncated_consistency_proof(self):
        c, path, p, history = fixture()
        with self.assertRaises(AnchorClaimRejected):
            verify_consistency(c['old_size'], c['new_size'],
                               c['old_root_sha256'], c['new_root_sha256'], path[:-1], full_history=history)

    def test_05_forged_consistency_sibling(self):
        c, path, p, history = fixture()
        with self.assertRaises(AnchorClaimRejected):
            verify_consistency(c['old_size'], c['new_size'],
                               c['old_root_sha256'], c['new_root_sha256'], (D('f'), *path[1:]), full_history=history)

    def test_06_wrong_tree_size(self):
        c, path, p, history = fixture()
        with self.assertRaises(AnchorClaimRejected):
            verify_consistency(c['old_size'], c['new_size']+1,
                               c['old_root_sha256'], c['new_root_sha256'], path, full_history=history)

    def test_07_repeated_stateless_evaluation_no_cas(self):
        c, path, p, history = fixture()
        self.assertEqual(quarantine_anchor_consistency(c, path, pinned=p, full_history=history),
                         quarantine_anchor_consistency(c, path, pinned=p, full_history=history))

    def test_08_lost_ack_unresolved(self):
        c, path, p, history = fixture()
        c['ack_state'] = 'ACK_LOST_UNRESOLVED'
        p['expected_statement_sha256'] = statement_sha256(c)
        result = quarantine_anchor_consistency(c, path, pinned=p, full_history=history)
        self.assertTrue(result['lost_ack_unresolved'])
        self.assertFalse(result['durable_write_verified'])

    def test_09_attacker_controls_both_source_and_pins(self):
        c, path, p, history = fixture()
        c['source_sha256'] = p['source_sha256'] = D('e')
        p['expected_statement_sha256'] = statement_sha256(c)
        self.assertFalse(quarantine_anchor_consistency(c, path, pinned=p, full_history=history)[
            'authenticated_anchor'])

    def test_10_future_revocation_is_not_authority(self):
        c, path, p, history = fixture()
        p['revocation_events'] = ((KEYS[0], 130),)
        result = quarantine_anchor_consistency(c, path, pinned=p, full_history=history)
        self.assertFalse(result['authenticated_signatures'])

    def test_11_statement_domain_separated_and_deterministic(self):
        c, path, p, history = fixture()
        self.assertEqual(statement_sha256(c), statement_sha256(copy.deepcopy(c)))
        original = statement_sha256(c)
        c['issued_at'] = 101
        self.assertNotEqual(original, statement_sha256(c))

    def test_12_first_to_large_tree_is_not_signature(self):
        c, path, p, history = fixture(1, 12)
        self.assertFalse(quarantine_anchor_consistency(c, path, pinned=p, full_history=history)[
            'authenticated_provider_origin'])


CASES = (
    ('foreign_repo', lambda x: x['c'].update(repository='ftmstr/Private')),
    ('main_branch', lambda x: x['c'].update(branch='main')),
    ('malformed_git_sha', lambda x: x['c'].update(git_sha='z'*40)),
    ('foreign_git_pin', lambda x: x['p'].update(git_sha='b'*40)),
    ('foreign_source_pin', lambda x: x['p'].update(source_sha256=D('f'))),
    ('foreign_workflow_pin', lambda x: x['p'].update(workflow_sha256=D('f'))),
    ('foreign_roster_pin', lambda x: x['p'].update(roster_sha256=D('f'))),
    ('foreign_old_root_pin', lambda x: x['p'].update(old_root_sha256=D('f'))),
    ('foreign_new_root_pin', lambda x: x['p'].update(new_root_sha256=D('f'))),
    ('foreign_nonce_pin', lambda x: x['p'].update(nonce_sha256=D('f'))),
    ('wrong_statement_pin', lambda x: x['p'].update(expected_statement_sha256=D('f'))),
    ('negative_old_size', lambda x: x['c'].update(old_size=-1)),
    ('bool_old_size', lambda x: x['c'].update(old_size=True)),
    ('bool_new_size', lambda x: x['c'].update(new_size=True)),
    ('old_size_larger_than_new', lambda x: x['c'].update(old_size=9)),
    ('equal_sizes_not_transition', lambda x: x['c'].update(new_size=3)),
    ('future_time', lambda x: x['c'].update(issued_at=130)),
    ('bool_issue_time', lambda x: x['c'].update(issued_at=True)),
    ('negative_observed_time', lambda x: x['c'].update(observed_at=-1)),
    ('nonce_corrupt', lambda x: x['c'].update(nonce_sha256='bad')),
    ('false_ack_applied', lambda x: x['c'].update(ack_state='ACK_APPLIED')),
    ('wrong_ack_status_type', lambda x: x['c'].update(ack_state=1)),
    ('live_flag_claim', lambda x: x['c'].update(live_trading_allowed=True)),
    ('release_flag_claim', lambda x: x['c'].update(release_ready=True)),
    ('unexpected_claim', lambda x: x['c'].update(signed=True)),
    ('missing_claim', lambda x: x['c'].pop('source_sha256')),
    ('unexpected_pin', lambda x: x['p'].update(approved=True)),
    ('missing_pin', lambda x: x['p'].pop('expected_statement_sha256')),
    ('proof_corrupt_first', lambda x: x.update(path=(D('f'), *x['path'][1:]))),
    ('proof_extra_node', lambda x: x.update(path=(*x['path'], D('f')))),
    ('proof_truncated', lambda x: x.update(path=x['path'][:-1])),
    ('proof_list_instead_of_tuple', lambda x: x.update(path=list(x['path']))),
    ('old_merkle_root_aba', lambda x: x['c'].update(new_root_sha256=x['c']['old_root_sha256'])),
    ('wrong_new_merkle_root', lambda x: x['c'].update(new_root_sha256=D('f'))),
    ('wrong_old_merkle_root', lambda x: x['c'].update(old_root_sha256=D('f'))),
    ('spent_nonce', lambda x: x['p'].update(spent_nonces=(D('4'),))),
    ('used_new_root', lambda x: x['p'].update(seen_roots=(x['c']['new_root_sha256'],))),
    ('duplicate_nonce_history', lambda x: x['p'].update(spent_nonces=(D('4'), D('4')))),
    ('unordered_nonce_history', lambda x: x['p'].update(spent_nonces=(D('f'), D('a')))),
    ('history_list_type', lambda x: x['p'].update(seen_roots=[D('f')])),
    ('revoked_owner', lambda x: x['p'].update(revocation_events=((KEYS[0], 120),))),
    ('revoked_reviewer', lambda x: x['p'].update(revocation_events=((KEYS[1], 101),))),
    ('revoked_custodian', lambda x: x['p'].update(revocation_events=((KEYS[2], 102),))),
    ('revocation_duplicates', lambda x: x['p'].update(revocation_events=((KEYS[0], 105),(KEYS[0], 111)))),
    ('revocation_wrong_type', lambda x: x['p'].update(revocation_events=[(KEYS[0], 105)])),
    ('revocation_boolean_time', lambda x: x['p'].update(revocation_events=((KEYS[0], True),))),
    ('wrong_issuer_role', lambda x: edit_row(x['c'], 'issuer_claims', 1, 0, 'owner')),
    ('issuer_cloned_actor', lambda x: edit_row(x['c'], 'issuer_claims', 1, 1, 'owner_a')),
    ('issuer_cloned_key', lambda x: edit_row(x['c'], 'issuer_claims', 1, 2, KEYS[0])),
    ('issuer_wrong_fingerprint_pin', lambda x: x['p'].update(issuer_key_fingerprints=(KEYS[0], D('f'), KEYS[2]))),
    ('issuer_signed_outside_window', lambda x: edit_row(x['c'], 'issuer_claims', 1, 3, 121)),
    ('issuer_false_verification', lambda x: edit_row(x['c'], 'issuer_claims', 0, 4, 'SIGNED')),
    ('issuer_key_bad_hex', lambda x: edit_row(x['c'], 'issuer_claims', 2, 2, 'bad')),
    ('issuer_wrong_actor_type', lambda x: edit_row(x['c'], 'issuer_claims', 0, 1, 22)),
    ('missing_issuer', lambda x: x['c'].update(issuer_claims=x['c']['issuer_claims'][:2])),
    ('provider_wrong_os', lambda x: edit_row(x['c'], 'provider_claims', 1, 0, 'ubuntu')),
    ('provider_duplicate_run', lambda x: edit_row(x['c'], 'provider_claims', 1, 1, 300)),
    ('provider_duplicate_job', lambda x: edit_row(x['c'], 'provider_claims', 1, 2, 400)),
    ('provider_foreign_git', lambda x: edit_row(x['c'], 'provider_claims', 0, 3, 'b'*40)),
    ('provider_forked_root', lambda x: edit_row(x['c'], 'provider_claims', 1, 4, D('f'))),
    ('provider_future_timestamp', lambda x: edit_row(x['c'], 'provider_claims', 0, 5, 121)),
    ('provider_bogus_signed', lambda x: edit_row(x['c'], 'provider_claims', 1, 6, 'GITHUB_SIGNED')),
    ('provider_boolean_run', lambda x: edit_row(x['c'], 'provider_claims', 0, 1, True)),
    ('both_writers_win', lambda x: edit_row(x['c'], 'writer_claims', 1, 3, 'CLAIMED_WIN')),
    ('both_writers_conflict', lambda x: edit_row(x['c'], 'writer_claims', 0, 3, 'CLAIMED_CONFLICT')),
    ('writer_stale_generation', lambda x: edit_row(x['c'], 'writer_claims', 0, 1, 2)),
    ('writer_rebased_old_root', lambda x: edit_row(x['c'], 'writer_claims', 1, 2, D('f'))),
    ('writer_duplicate_actor', lambda x: edit_row(x['c'], 'writer_claims', 1, 0, 'worker_a')),
    ('writer_false_commit_ack', lambda x: edit_row(x['c'], 'writer_claims', 0, 3, 'ACK_APPLIED')),
)


def _test_case(mutate):
    def run(self):
        self.reject(mutate)
    return run


for i, (name, mutate) in enumerate(CASES, 13):
    setattr(RC680MerkleConsistencyAdversarialTests,
            'test_%02d_%s' % (i, name), _test_case(mutate))


if __name__ == '__main__':
    unittest.main()
