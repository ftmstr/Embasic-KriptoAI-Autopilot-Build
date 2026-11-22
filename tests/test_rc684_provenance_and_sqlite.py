"""RC684: invented provenance attacks and real disposable SQLite CAS crash tests.

SQLite tests validate only the behavior of this isolated test harness; they are
not proof that KriptoAI's shipping application has a durable CAS subsystem.
"""
import copy
import hashlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from safe_public_ci.ci_external_provenance_quarantine import (
    ProvenanceRejected, evidence_digest, quarantine_provenance,
)


def h(x):
    return x * 64


def witness():
    c = dict(
        repository='ftmstr/Embasic-KriptoAI-Autopilot-Build',
        branch='validation/rc654-pr1-rc653-combined-ci',
        git_sha='a'*40, source_sha256=h('1'), workflow_sha256=h('2'),
        roster_sha256=h('3'), checkpoint_sha256=h('4'), nonce_sha256=h('5'),
        issued_at=100, observed_at=120,
        owners=(('owner', 'owner_a', h('a'), 90, 150),
                ('independent_reviewer', 'reviewer_b', h('b'), 90, 150)),
        revocations=((h('c'), 100),),
        providers=(('ubuntu', 4300, 5300, 'a'*40, h('d'), False),
                   ('windows', 4301, 5301, 'a'*40, h('e'), False)),
        cas_trace=(('writer_a', 1, 3, h('f'), 'CLAIMED_WIN'),
                   ('writer_b', 2, 3, h('f'), 'CLAIMED_CONFLICT')),
        spent_nonces=(), seen_roots=(), ack_state='ACK_LOST_UNRESOLVED',
        release_ready=False, live_trading_allowed=False,
    )
    p = {k: c[k] for k in ('git_sha', 'source_sha256', 'workflow_sha256',
                          'roster_sha256', 'checkpoint_sha256', 'nonce_sha256')}
    p.update(issuer_fingerprints=(h('a'), h('b')),
             expected_digest_sha256=evidence_digest(c),
             verified_oob_issuers=False,
             verified_provider_origin=False,
             verified_revocation_origin=False,
             verified_transactional_cas=False)
    return c, p


def mutate_row(c, key, i, j, value):
    rows = [list(row) for row in c[key]]
    rows[i][j] = value
    c[key] = tuple(tuple(row) for row in rows)


class RC684Provenance(unittest.TestCase):
    def reject(self, fn):
        c, p = witness()
        fn(c, p)
        with self.assertRaises(ProvenanceRejected):
            quarantine_provenance(c, p)

    def test_01_valid_claims_remain_unauthenticated(self):
        c, p = witness()
        r = quarantine_provenance(c, p)
        self.assertEqual(r['status'], 'EXTERNAL_PROVENANCE_CLAIMS_QUARANTINED_NOT_AUTHENTICATED')
        self.assertTrue(r['lost_ack_unresolved'])
        for name in ('out_of_band_issuer_authenticated', 'provider_origin_authenticated',
                     'revocation_origin_authenticated', 'clock_authenticated',
                     'merkle_anchor_authenticated', 'durable_cas_verified',
                     'restart_recovery_verified', 'release_ready', 'live_trading_allowed'):
            self.assertIs(r[name], False)

    def test_02_canonical_is_deterministic(self):
        c, _ = witness()
        self.assertEqual(evidence_digest(c), evidence_digest(copy.deepcopy(c)))

    def test_03_valid_provider_id_change_changes_digest(self):
        c, _ = witness()
        before = evidence_digest(c)
        mutate_row(c, 'providers', 1, 1, 4400)
        self.assertNotEqual(before, evidence_digest(c))

    def test_04_owner_identity_change_changes_digest(self):
        c, _ = witness()
        before = evidence_digest(c)
        mutate_row(c, 'owners', 0, 1, 'owner_new')
        self.assertNotEqual(before, evidence_digest(c))

    def test_05_future_revocation_changes_digest(self):
        c, _ = witness()
        before = evidence_digest(c)
        c['revocations'] = tuple(sorted((*c['revocations'], (h('a'), 121))))
        self.assertNotEqual(before, evidence_digest(c))

    def test_06_even_jointly_rewritten_pins_do_not_authenticate(self):
        c, p = witness()
        c['source_sha256'] = h('f')
        p['source_sha256'] = h('f')
        p['expected_digest_sha256'] = evidence_digest(c)
        self.assertFalse(quarantine_provenance(c, p)['provider_origin_authenticated'])
        self.assertFalse(quarantine_provenance(c, p)['out_of_band_issuer_authenticated'])

    def test_07_lost_ack_does_not_become_applied(self):
        c, p = witness()
        self.assertTrue(quarantine_provenance(c, p)['lost_ack_unresolved'])
        self.assertFalse(quarantine_provenance(c, p)['durable_cas_verified'])

    def test_08_untrusted_anchor_validity_does_not_prove_independence(self):
        c, p = witness()
        self.assertNotEqual(c['owners'][0][2], c['owners'][1][2])
        self.assertFalse(quarantine_provenance(c, p)['out_of_band_issuer_authenticated'])

    def test_09_provider_log_hash_is_only_claim(self):
        c, p = witness()
        self.assertTrue(len(c['providers'][0][4]) == 64)
        self.assertFalse(quarantine_provenance(c, p)['provider_origin_authenticated'])

    def test_10_no_mutation_on_repeated_stateless_calls(self):
        c, p = witness()
        first = quarantine_provenance(c, p)
        second = quarantine_provenance(c, p)
        self.assertEqual(first, second)
        self.assertFalse(second['restart_recovery_verified'])


MUTATIONS = (
    ('missing_field', lambda c,p: c.pop('nonce_sha256')),
    ('extra_field', lambda c,p: c.update(authorised=True)),
    ('wrong_repo', lambda c,p: c.update(repository='ftmstr/private')),
    ('main', lambda c,p: c.update(branch='main')),
    ('bad_git', lambda c,p: c.update(git_sha='g'*40)),
    ('wrong_git_pin', lambda c,p: p.update(git_sha='b'*40)),
    ('source_mismatch', lambda c,p: p.update(source_sha256=h('8'))),
    ('workflow_mismatch', lambda c,p: p.update(workflow_sha256=h('8'))),
    ('roster_mismatch', lambda c,p: p.update(roster_sha256=h('8'))),
    ('checkpoint_mismatch', lambda c,p: p.update(checkpoint_sha256=h('8'))),
    ('nonce_mismatch', lambda c,p: p.update(nonce_sha256=h('8'))),
    ('digest_mismatch', lambda c,p: p.update(expected_digest_sha256=h('8'))),
    ('bool_timestamp', lambda c,p: c.update(issued_at=True)),
    ('negative_timestamp', lambda c,p: c.update(issued_at=-1)),
    ('time_reversed', lambda c,p: c.update(issued_at=130)),
    ('false_ack_committed', lambda c,p: c.update(ack_state='ACK_COMMITTED')),
    ('false_ack_applied', lambda c,p: c.update(ack_state='ACK_APPLIED')),
    ('bool_ack', lambda c,p: c.update(ack_state=False)),
    ('live_flag', lambda c,p: c.update(live_trading_allowed=True)),
    ('release_flag', lambda c,p: c.update(release_ready=True)),
    ('missing_owner', lambda c,p: c.update(owners=c['owners'][:1])),
    ('double_owner_key', lambda c,p: mutate_row(c,'owners',1,2,h('a'))),
    ('double_owner_actor', lambda c,p: mutate_row(c,'owners',1,1,'owner_a')),
    ('wrong_owner_role', lambda c,p: mutate_row(c,'owners',1,0,'owner')),
    ('invalid_owner_name', lambda c,p: mutate_row(c,'owners',0,1,'Owner-A')),
    ('expired_owner', lambda c,p: mutate_row(c,'owners',0,4,99)),
    ('owner_not_yet_valid', lambda c,p: mutate_row(c,'owners',0,3,110)),
    ('bad_fingerprint', lambda c,p: mutate_row(c,'owners',0,2,'not-hex')),
    ('revoked_owner', lambda c,p: c.update(revocations=tuple(sorted((*c['revocations'],(h('a'),119)))))),
    ('revoked_reviewer', lambda c,p: c.update(revocations=tuple(sorted((*c['revocations'],(h('b'),118)))))),
    ('duplicate_revocation', lambda c,p: c.update(revocations=((h('c'),100),(h('c'),110)))),
    ('revocation_as_list', lambda c,p: c.update(revocations=[(h('c'),100)])),
    ('revocation_bad_timestamp', lambda c,p: c.update(revocations=((h('c'),True),))),
    ('revocation_unsorted', lambda c,p: c.update(revocations=((h('c'),100),(h('a'),121)))),
    ('providers_missing', lambda c,p: c.update(providers=c['providers'][:1])),
    ('duplicate_provider_run', lambda c,p: mutate_row(c,'providers',1,1,4300)),
    ('duplicate_provider_job', lambda c,p: mutate_row(c,'providers',1,2,5300)),
    ('provider_wrong_os', lambda c,p: mutate_row(c,'providers',1,0,'ubuntu')),
    ('provider_wrong_git', lambda c,p: mutate_row(c,'providers',0,3,'b'*40)),
    ('provider_bad_log_sha', lambda c,p: mutate_row(c,'providers',0,4,'bad')),
    ('provider_asserts_verified', lambda c,p: mutate_row(c,'providers',0,5,True)),
    ('provider_run_boolean', lambda c,p: mutate_row(c,'providers',1,1,True)),
    ('provider_job_zero', lambda c,p: mutate_row(c,'providers',1,2,0)),
    ('cas_missing', lambda c,p: c.update(cas_trace=c['cas_trace'][:1])),
    ('double_winner', lambda c,p: mutate_row(c,'cas_trace',1,4,'CLAIMED_WIN')),
    ('cas_first_conflict', lambda c,p: mutate_row(c,'cas_trace',0,4,'CLAIMED_CONFLICT')),
    ('cas_repeated_actor', lambda c,p: mutate_row(c,'cas_trace',1,0,'writer_a')),
    ('cas_epoch_aba', lambda c,p: mutate_row(c,'cas_trace',1,1,1)),
    ('cas_epoch_skip', lambda c,p: mutate_row(c,'cas_trace',1,1,3)),
    ('cas_old_generation', lambda c,p: mutate_row(c,'cas_trace',1,2,2)),
    ('cas_wrong_root', lambda c,p: mutate_row(c,'cas_trace',1,3,h('9'))),
    ('cas_bad_actor', lambda c,p: mutate_row(c,'cas_trace',1,0,'WriterX')),
    ('nonce_replay', lambda c,p: c.update(spent_nonces=(h('5'),))),
    ('nonce_duplicate', lambda c,p: c.update(spent_nonces=(h('8'),h('8')))),
    ('nonce_unsorted', lambda c,p: c.update(spent_nonces=(h('f'),h('8')))),
    ('nonce_non_tuple', lambda c,p: c.update(spent_nonces=[h('8')])),
    ('root_replay', lambda c,p: c.update(seen_roots=(h('f'),))),
    ('root_not_hex', lambda c,p: c.update(seen_roots=('z'*64,))),
    ('key_pin_mismatch', lambda c,p: p.update(issuer_fingerprints=(h('f'),h('b')))),
    ('key_pin_list', lambda c,p: p.update(issuer_fingerprints=[h('a'),h('b')])),
    ('extra_pin', lambda c,p: p.update(override=True)),
    ('remove_pin', lambda c,p: p.pop('expected_digest_sha256')),
    ('oob_self_claim', lambda c,p: p.update(verified_oob_issuers=True)),
    ('provider_self_claim', lambda c,p: p.update(verified_provider_origin=True)),
    ('revocation_self_claim', lambda c,p: p.update(verified_revocation_origin=True)),
    ('cas_self_claim', lambda c,p: p.update(verified_transactional_cas=True)),
)


def case(fn):
    def test(self):
        self.reject(fn)
    return test


for number, (name, change) in enumerate(MUTATIONS, 11):
    setattr(RC684Provenance, 'test_%02d_%s' % (number, name), case(change))


# Actual SQLite transactions operate ONLY on temporary synthetic test data.
SCHEMA = (
    'CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), '
    'generation INTEGER NOT NULL, root TEXT NOT NULL);'
    'CREATE TABLE IF NOT EXISTS used (nonce TEXT PRIMARY KEY);'
)
OLD_ROOT = '1' * 64
NEW_ROOT = '2' * 64


def connect(path):
    db = sqlite3.connect(str(path), timeout=8, isolation_level=None)
    db.execute('PRAGMA busy_timeout=8000')
    db.execute('PRAGMA synchronous=FULL')
    return db


def setup(path):
    db = connect(path)
    try:
        db.executescript(SCHEMA)
        db.execute('INSERT INTO state(id,generation,root) VALUES(1,3,?)', (OLD_ROOT,))
    finally:
        db.close()


def cas(path, expected_gen, expected_root, desired_root, nonce, lost_ack=False, rollback=False):
    db = connect(path)
    try:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT 1 FROM used WHERE nonce=?',(nonce,)).fetchone():
            db.execute('ROLLBACK')
            return 'REPLAY'
        gen,root = db.execute('SELECT generation,root FROM state WHERE id=1').fetchone()
        if gen != expected_gen or root != expected_root:
            db.execute('ROLLBACK')
            return 'STALE'
        n = db.execute('UPDATE state SET generation=?,root=? '
                       'WHERE id=1 AND generation=? AND root=?',
                       (gen+1,desired_root,gen,root)).rowcount
        if n != 1:
            db.execute('ROLLBACK')
            return 'CONFLICT'
        db.execute('INSERT INTO used(nonce) VALUES(?)',(nonce,))
        if rollback:
            db.execute('ROLLBACK')
            return 'ROLLED_BACK'
        db.execute('COMMIT')
        return 'ACK_LOST' if lost_ack else 'COMMITTED'
    finally:
        db.close()


def current(path):
    db = connect(path)
    try:
        return db.execute('SELECT generation,root FROM state WHERE id=1').fetchone()
    finally:
        db.close()


class RC684DisposableSQLite(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='rc684_')
        self.path = Path(self.temporary.name) / 'synthetic.sqlite3'
        setup(self.path)

    def tearDown(self):
        self.temporary.cleanup()

    def test_01_initial_durable_state(self):
        self.assertEqual(current(self.path),(3, OLD_ROOT))

    def test_02_transaction_commit_survives_reconnect(self):
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-a'),'COMMITTED')
        self.assertEqual(current(self.path),(4,NEW_ROOT))

    def test_03_lost_ack_does_not_reissue_nonce(self):
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-b',lost_ack=True),'ACK_LOST')
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-b'),'REPLAY')
        self.assertEqual(current(self.path),(4,NEW_ROOT))

    def test_04_rollback_never_consumes_nonce(self):
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-c',rollback=True),'ROLLED_BACK')
        self.assertEqual(current(self.path),(3,OLD_ROOT))
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-c'),'COMMITTED')

    def test_05_stale_generation_rejected(self):
        self.assertEqual(cas(self.path,2,OLD_ROOT,NEW_ROOT,'nonce-d'),'STALE')

    def test_06_stale_root_rejected(self):
        self.assertEqual(cas(self.path,3,'f'*64,NEW_ROOT,'nonce-e'),'STALE')

    def test_07_distinct_nonces_same_old_version_one_winner(self):
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-f'),'COMMITTED')
        self.assertEqual(cas(self.path,3,OLD_ROOT,'3'*64,'nonce-g'),'STALE')

    def test_08_reused_nonce_across_generations_rejected(self):
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-h'),'COMMITTED')
        self.assertEqual(cas(self.path,4,NEW_ROOT,'3'*64,'nonce-h'),'REPLAY')

    def test_09_two_thread_contenders_only_one_commit(self):
        barrier = threading.Barrier(2)
        def runner(nonce, root):
            barrier.wait(timeout=6)
            return cas(self.path,3,OLD_ROOT,root,nonce)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(runner,'nonce-i','3'*64),pool.submit(runner,'nonce-j','4'*64)]
            results = sorted(f.result(timeout=15) for f in futures)
        self.assertEqual(results,['COMMITTED','STALE'])
        self.assertEqual(current(self.path)[0],4)

    def test_10_crash_before_commit_rolls_back(self):
        self._crash('before')
        self.assertEqual(current(self.path),(3,OLD_ROOT))
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-crash'),'COMMITTED')

    def test_11_crash_after_commit_lost_ack_is_persisted(self):
        self._crash('after')
        self.assertEqual(current(self.path),(4,NEW_ROOT))
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-crash'),'REPLAY')

    def test_12_stale_replay_after_process_restart(self):
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-k'),'COMMITTED')
        self.assertEqual(current(self.path),(4,NEW_ROOT))
        self.assertEqual(cas(self.path,3,OLD_ROOT,'f'*64,'nonce-l'),'STALE')

    def test_13_aba_cannot_reuse_generation_and_stale_root(self):
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-m'),'COMMITTED')
        self.assertEqual(cas(self.path,3,OLD_ROOT,OLD_ROOT,'nonce-n'),'STALE')
        self.assertEqual(current(self.path),(4,NEW_ROOT))

    def test_14_external_db_admin_rollback_still_unprotected(self):
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-o'),'COMMITTED')
        db = connect(self.path)
        try:
            db.execute('DELETE FROM used')
            db.execute('UPDATE state SET generation=3,root=? WHERE id=1',(OLD_ROOT,))
        finally:
            db.close()
        # Correctly exposes the missing independent monotonic trust root.
        self.assertEqual(cas(self.path,3,OLD_ROOT,'f'*64,'nonce-o'),'COMMITTED')

    def test_15_lost_ack_requires_reconciliation_not_second_commit(self):
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-p',lost_ack=True),'ACK_LOST')
        self.assertEqual(current(self.path),(4,NEW_ROOT))
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-p'),'REPLAY')

    def test_16_committed_epoch_monotonically_advances_normally(self):
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-q'),'COMMITTED')
        self.assertEqual(cas(self.path,4,NEW_ROOT,'3'*64,'nonce-r'),'COMMITTED')
        self.assertEqual(current(self.path),(5,'3'*64))

    def test_17_same_nonce_cross_process_precommit_recovery(self):
        self._crash('before')
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-crash'),'COMMITTED')
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-crash'),'REPLAY')

    def test_18_same_nonce_cross_process_postcommit_recovery(self):
        self._crash('after')
        self.assertEqual(cas(self.path,3,OLD_ROOT,NEW_ROOT,'nonce-crash'),'REPLAY')
        self.assertEqual(current(self.path),(4,NEW_ROOT))

    def _crash(self, stage):
        # Child process is forcibly exited before or after COMMIT; test DB only.
        program = (
            'import sqlite3,os,sys\n'
            'db=sqlite3.connect(sys.argv[1],timeout=8,isolation_level=None)\n'
            'db.execute("BEGIN IMMEDIATE")\n'
            'db.execute("UPDATE state SET generation=4,root=? WHERE id=1",("2"*64,))\n'
            'db.execute("INSERT INTO used(nonce) VALUES(?)",("nonce-crash",))\n'
            'if sys.argv[2]=="before": os._exit(61)\n'
            'db.execute("COMMIT")\n'
            'os._exit(62)\n'
        )
        result = subprocess.run([sys.executable,'-c',program,str(self.path),stage],
                                check=False,timeout=12,capture_output=True)
        self.assertEqual(result.returncode,61 if stage=='before' else 62,
                         result.stderr.decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
