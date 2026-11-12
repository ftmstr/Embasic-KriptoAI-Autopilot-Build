"""RC685 original fabricated witness audits and disposable multi-process SQLite.

All signing/provenance is caller asserted. Real SQLite tests run ONLY in temporary
local test files and cannot prove production multi-tenant CAS or anti-rollback.
"""
import copy
import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from safe_public_ci.ci_independent_origin_quarantine import (
    OriginRejected, _root, _consistency, claim_sha256, quarantine_witness_origin,
)


def h(s):
    return s * 64


LEAVES = tuple(hashlib.sha256(('rc685-invented-leaf-%03d' % i).encode()).hexdigest()
               for i in range(128))


def fixture(old_size=3, new_size=7):
    full = LEAVES[:new_size]
    old = _root(full[:old_size]).hex()
    new = _root(full).hex()
    c = dict(
        repository='ftmstr/Embasic-KriptoAI-Autopilot-Build',
        branch='validation/rc654-pr1-rc653-combined-ci',
        git_sha='a'*40, source_sha256=h('1'), workflow_sha256=h('2'),
        roster_sha256=h('3'), rc683_checkpoint_sha256=h('4'),
        old_size=old_size, new_size=new_size,
        old_root_sha256=old, new_root_sha256=new,
        full_history=full, consistency_proof=_consistency(full, old_size),
        nonce_sha256=h('5'), issued_at=100, observed_at=120,
        authority_claims=(
            ('owner','owner_one',h('a'),90,150,105),
            ('independent_reviewer','reviewer_two',h('b'),90,150,106),
        ),
        provider_claims=(
            ('ubuntu',9101,9201,'a'*40,h('1'),h('6'),1,'NOT_VERIFIED'),
            ('windows',9102,9202,'a'*40,h('1'),h('7'),1,'NOT_VERIFIED'),
        ),
        witness_claims=(
            ('domain_a',h('c'),1,new,h('6'),110,'NOT_VERIFIED'),
            ('domain_b',h('d'),2,new,h('7'),111,'NOT_VERIFIED'),
        ),
        revocations=((h('e'),95,1),),
        cas_attempts=(
            ('writer_one',1,old_size,old,new,'CLAIMED_WIN'),
            ('writer_two',2,old_size,old,new,'CLAIMED_CONFLICT'),
            ('writer_three',3,old_size,old,new,'CLAIMED_CONFLICT'),
        ),
        spent_nonces=(),seen_roots=(),ack_state='ACK_LOST_UNRESOLVED',
        release_ready=False,live_trading_allowed=False,
    )
    pins = {k:c[k] for k in ('git_sha','source_sha256','workflow_sha256',
                             'roster_sha256','rc683_checkpoint_sha256',
                             'old_root_sha256','new_root_sha256','nonce_sha256')}
    pins['authority_fingerprints'] = (h('a'),h('b'))
    pins['witness_fingerprints'] = (h('c'),h('d'))
    pins['expected_claim_sha256'] = claim_sha256(c)
    pins['independent_root_authenticated'] = False
    pins['provider_origin_authenticated'] = False
    pins['durable_cas_authenticated'] = False
    return c, pins


def replace_row(c, field, row, position, value):
    records = [list(x) for x in c[field]]
    records[row][position] = value
    c[field] = tuple(tuple(x) for x in records)


class RC685OriginQuarantine(unittest.TestCase):
    def reject(self, action):
        c,p=fixture()
        action(c,p)
        with self.assertRaises(OriginRejected):
            quarantine_witness_origin(c,p)

    def test_01_valid_structural_claim_never_authenticates(self):
        c,p=fixture()
        answer=quarantine_witness_origin(c,p)
        self.assertEqual(answer['status'], 'CLAIMED_CROSS_WITNESS_HISTORY_QUARANTINED_NOT_AUTHENTICATED')
        for k,v in answer.items():
            if k.endswith('authenticated') or k in ('durable_cas_verified',
                'restart_recovery_verified','release_ready','live_trading_allowed'):
                self.assertIs(v,False)
        self.assertTrue(answer['lost_ack_unresolved'])

    def test_02_complete_transcript_digest_deterministic(self):
        c,p=fixture()
        self.assertEqual(claim_sha256(c),claim_sha256(copy.deepcopy(c)))
        self.assertEqual(claim_sha256(c),p['expected_claim_sha256'])

    def test_03_valid_new_provider_run_changes_digest(self):
        c,_=fixture()
        before=claim_sha256(c)
        replace_row(c,'provider_claims',1,1,9121)
        self.assertNotEqual(before,claim_sha256(c))

    def test_04_valid_reviewer_key_change_changes_digest(self):
        c,_=fixture()
        old=claim_sha256(c)
        replace_row(c,'authority_claims',1,2,h('f'))
        self.assertNotEqual(old,claim_sha256(c))

    def test_05_witness_domain_change_changes_digest(self):
        c,_=fixture()
        before=claim_sha256(c)
        replace_row(c,'witness_claims',1,0,'domain_new')
        self.assertNotEqual(before,claim_sha256(c))

    def test_06_valid_provider_log_replacement_binds_both(self):
        c,_=fixture()
        before=claim_sha256(c)
        replace_row(c,'provider_claims',0,5,h('9'))
        replace_row(c,'witness_claims',0,4,h('9'))
        self.assertNotEqual(before,claim_sha256(c))

    def test_07_history_anchor_aided_by_second_witness_still_false(self):
        c,p=fixture()
        self.assertFalse(quarantine_witness_origin(c,p)['independent_trust_root_authenticated'])
        self.assertFalse(quarantine_witness_origin(c,p)['full_history_authenticated'])

    def test_08_provider_signatures_not_present_no_fake_authenticated(self):
        c,p=fixture()
        self.assertEqual(c['provider_claims'][0][-1],'NOT_VERIFIED')
        self.assertFalse(quarantine_witness_origin(c,p)['provider_origin_authenticated'])

    def test_09_all_128_history_boundaries(self):
        for new in range(2,129):
            for old in set((1,new//2,new-1)):
                c,p=fixture(old,new)
                self.assertEqual(claim_sha256(c),p['expected_claim_sha256'])

    def test_10_three_to_seven_not_three_to_eight(self):
        self.reject(lambda c,p:c.update(new_size=8))

    def test_11_proof_size_without_complete_history_is_insufficient(self):
        c,p=fixture()
        c['full_history']=c['full_history'][:-1]
        with self.assertRaises(OriginRejected): claim_sha256(c)

    def test_12_double_fabricated_signers_cannot_grant_origin(self):
        c,p=fixture()
        self.assertFalse(quarantine_witness_origin(c,p)['signature_authority_authenticated'])

    def test_13_valid_future_revocation_record_is_bound(self):
        c,_=fixture()
        before=claim_sha256(c)
        c['revocations']=(*c['revocations'],(h('a'),121,2))
        self.assertNotEqual(before,claim_sha256(c))

    def test_14_lost_ack_unresolved_after_repeated_stateless_calls(self):
        c,p=fixture()
        a=quarantine_witness_origin(c,p)
        b=quarantine_witness_origin(c,p)
        self.assertEqual(a,b)
        self.assertTrue(a['lost_ack_unresolved'])
        self.assertFalse(a['durable_cas_verified'])

    def test_15_two_witness_claims_are_not_two_admin_domains(self):
        c,p=fixture()
        self.assertEqual(len(c['witness_claims']),2)
        self.assertFalse(quarantine_witness_origin(c,p)['independent_trust_root_authenticated'])

    def test_16_full_history_root_changes_after_valid_extension(self):
        first,_=fixture(3,7)
        second,_=fixture(3,8)
        self.assertNotEqual(first['new_root_sha256'],second['new_root_sha256'])

    def test_17_a_changed_ack_state_is_cryptographically_bound(self):
        c,_=fixture()
        before=claim_sha256(c)
        c['ack_state']='NOT_SENT'
        self.assertNotEqual(before,claim_sha256(c))

    def test_18_revocation_does_not_externally_authenticate_itself(self):
        c,p=fixture()
        self.assertFalse(quarantine_witness_origin(c,p)['revocation_origin_authenticated'])

    def test_19_receipt_sequence_no_real_monotonic_anchor(self):
        c,p=fixture()
        self.assertEqual(tuple(row[1] for row in c['cas_attempts']),(1,2,3))
        self.assertFalse(quarantine_witness_origin(c,p)['restart_recovery_verified'])

    def test_20_collision_resistant_digest_is_not_signer_identity(self):
        c,p=fixture()
        self.assertEqual(len(claim_sha256(c)),64)
        self.assertFalse(quarantine_witness_origin(c,p)['signature_authority_authenticated'])


MUTATIONS=(
    ('bad_repo', lambda c,p:c.update(repository='ftmstr/private')),
    ('main_branch', lambda c,p:c.update(branch='main')),
    ('foreign_git',lambda c,p:c.update(git_sha='b'*40)),
    ('bad_git_hex',lambda c,p:c.update(git_sha='z'*40)),
    ('unexpected_field',lambda c,p:c.update(signed=True)),
    ('missing_field',lambda c,p:c.pop('workflow_sha256')),
    ('source_pin_wrong',lambda c,p:p.update(source_sha256=h('f'))),
    ('workflow_pin_wrong',lambda c,p:p.update(workflow_sha256=h('f'))),
    ('roster_pin_wrong',lambda c,p:p.update(roster_sha256=h('f'))),
    ('checkpoint_pin_wrong',lambda c,p:p.update(rc683_checkpoint_sha256=h('f'))),
    ('expected_digest_wrong',lambda c,p:p.update(expected_claim_sha256=h('f'))),
    ('missing_pin',lambda c,p:p.pop('nonce_sha256')),
    ('extra_pin',lambda c,p:p.update(reviewed=True)),
    ('empty_claim',lambda c,p:c.clear()),
    ('source_wrong_type',lambda c,p:c.update(source_sha256=bytes.fromhex(h('1')))),
    ('bool_old_size',lambda c,p:c.update(old_size=True)),
    ('bool_new_size',lambda c,p:c.update(new_size=False)),
    ('old_zero',lambda c,p:c.update(old_size=0)),
    ('new_129',lambda c,p:c.update(new_size=129)),
    ('old_equals_new',lambda c,p:c.update(new_size=3)),
    ('issued_after_observed',lambda c,p:c.update(issued_at=121)),
    ('negative_observation',lambda c,p:c.update(observed_at=-1)),
    ('history_list',lambda c,p:c.update(full_history=list(c['full_history']))),
    ('history_duplicate',lambda c,p:c.update(full_history=(c['full_history'][0],*c['full_history'][1:-1],c['full_history'][0]))),
    ('history_reorder',lambda c,p:c.update(full_history=tuple(reversed(c['full_history'])))),
    ('history_missing',lambda c,p:c.update(full_history=c['full_history'][:-1])),
    ('history_prepend',lambda c,p:c.update(full_history=(h('f'),*c['full_history'][:-1]))),
    ('proof_list',lambda c,p:c.update(consistency_proof=list(c['consistency_proof']))),
    ('proof_extra',lambda c,p:c.update(consistency_proof=(*c['consistency_proof'],h('f')))),
    ('proof_corrupt',lambda c,p:c.update(consistency_proof=(h('f'),*c['consistency_proof'][1:]))),
    ('proof_missing',lambda c,p:c.update(consistency_proof=c['consistency_proof'][:-1])),
    ('old_root_sub',lambda c,p:c.update(old_root_sha256=h('f'))),
    ('new_root_sub',lambda c,p:c.update(new_root_sha256=h('f'))),
    ('old_root_as_new',lambda c,p:c.update(new_root_sha256=c['old_root_sha256'])),
    ('revocation_list',lambda c,p:c.update(revocations=[(h('a'),120,1)])),
    ('revocation_dup_key',lambda c,p:c.update(revocations=((h('e'),95,1),(h('e'),100,2)))),
    ('revocation_dup_seq',lambda c,p:c.update(revocations=((h('e'),95,1),(h('f'),100,1)))),
    ('revocation_wrong_order',lambda c,p:c.update(revocations=((h('e'),95,2),(h('f'),100,1)))),
    ('revocation_owner',lambda c,p:c.update(revocations=((h('e'),95,1),(h('a'),120,2)))),
    ('revocation_reviewer',lambda c,p:c.update(revocations=((h('e'),95,1),(h('b'),119,2)))),
    ('revocation_bool_when',lambda c,p:c.update(revocations=((h('e'),True,1),))),
    ('authority_missing',lambda c,p:c.update(authority_claims=c['authority_claims'][:1])),
    ('authority_wrong_role',lambda c,p:replace_row(c,'authority_claims',1,0,'owner')),
    ('authority_duplicate_actor',lambda c,p:replace_row(c,'authority_claims',1,1,'owner_one')),
    ('authority_duplicate_key',lambda c,p:replace_row(c,'authority_claims',1,2,h('a'))),
    ('authority_expired',lambda c,p:replace_row(c,'authority_claims',0,4,101)),
    ('authority_future',lambda c,p:replace_row(c,'authority_claims',0,5,121)),
    ('authority_key_pin_change',lambda c,p:p.update(authority_fingerprints=(h('a'),h('f')))),
    ('authority_name_invalid',lambda c,p:replace_row(c,'authority_claims',0,1,'owner-name')),
    ('provider_missing',lambda c,p:c.update(provider_claims=c['provider_claims'][:1])),
    ('provider_wrong_os',lambda c,p:replace_row(c,'provider_claims',1,0,'ubuntu')),
    ('provider_duplicate_run',lambda c,p:replace_row(c,'provider_claims',1,1,9101)),
    ('provider_duplicate_job',lambda c,p:replace_row(c,'provider_claims',1,2,9201)),
    ('provider_wrong_git',lambda c,p:replace_row(c,'provider_claims',0,3,'b'*40)),
    ('provider_wrong_source',lambda c,p:replace_row(c,'provider_claims',0,4,h('f'))),
    ('provider_log_bad',lambda c,p:replace_row(c,'provider_claims',0,5,'ff')),
    ('provider_attempt_two',lambda c,p:replace_row(c,'provider_claims',0,6,2)),
    ('provider_attempt_bool',lambda c,p:replace_row(c,'provider_claims',0,6,True)),
    ('provider_forge_verified',lambda c,p:replace_row(c,'provider_claims',0,7,'SIGNED')),
    ('witness_missing',lambda c,p:c.update(witness_claims=c['witness_claims'][:1])),
    ('witness_duplicate_name',lambda c,p:replace_row(c,'witness_claims',1,0,'domain_a')),
    ('witness_duplicate_fp',lambda c,p:replace_row(c,'witness_claims',1,1,h('c'))),
    ('witness_bad_epoch',lambda c,p:replace_row(c,'witness_claims',1,2,1)),
    ('witness_wrong_root',lambda c,p:replace_row(c,'witness_claims',1,3,h('f'))),
    ('witness_wrong_log',lambda c,p:replace_row(c,'witness_claims',0,4,h('f'))),
    ('witness_future_stamp',lambda c,p:replace_row(c,'witness_claims',0,5,121)),
    ('witness_claim_authenticated',lambda c,p:replace_row(c,'witness_claims',1,6,'AUTHENTICATED')),
    ('witness_wrong_pin',lambda c,p:p.update(witness_fingerprints=(h('c'),h('f')))),
    ('cas_missing',lambda c,p:c.update(cas_attempts=c['cas_attempts'][:2])),
    ('cas_double_winner',lambda c,p:replace_row(c,'cas_attempts',1,5,'CLAIMED_WIN')),
    ('cas_no_winner',lambda c,p:replace_row(c,'cas_attempts',0,5,'CLAIMED_CONFLICT')),
    ('cas_duplicate_actor',lambda c,p:replace_row(c,'cas_attempts',1,0,'writer_one')),
    ('cas_epoch_aba',lambda c,p:replace_row(c,'cas_attempts',2,1,1)),
    ('cas_epoch_skip',lambda c,p:replace_row(c,'cas_attempts',1,1,4)),
    ('cas_gen_stale',lambda c,p:replace_row(c,'cas_attempts',1,2,2)),
    ('cas_wrong_old_root',lambda c,p:replace_row(c,'cas_attempts',0,3,h('f'))),
    ('cas_wrong_proposed',lambda c,p:replace_row(c,'cas_attempts',2,4,h('f'))),
    ('replay_nonce',lambda c,p:c.update(spent_nonces=(h('5'),))),
    ('replay_root',lambda c,p:c.update(seen_roots=(c['new_root_sha256'],))),
    ('replay_duplicate',lambda c,p:c.update(spent_nonces=(h('f'),h('f')))),
    ('replay_unsorted',lambda c,p:c.update(spent_nonces=(h('f'),h('d')))),
    ('seen_roots_list',lambda c,p:c.update(seen_roots=[h('a')])),
    ('false_ack_applied',lambda c,p:c.update(ack_state='ACK_APPLIED')),
    ('unknown_ack',lambda c,p:c.update(ack_state=7)),
    ('release_flag',lambda c,p:c.update(release_ready=True)),
    ('live_flag',lambda c,p:c.update(live_trading_allowed=True)),
    ('self_auth_root',lambda c,p:p.update(independent_root_authenticated=True)),
    ('self_auth_provider',lambda c,p:p.update(provider_origin_authenticated=True)),
    ('self_auth_cas',lambda c,p:p.update(durable_cas_authenticated=True)),
)


def _case(action):
    def run(self):
        self.reject(action)
    return run


for idx,(name,action) in enumerate(MUTATIONS,21):
    setattr(RC685OriginQuarantine,'test_%03d_%s' % (idx,name),_case(action))


# SQLite experiments must not be mistaken for live CAS, privileged IAM, or
# immutable independently distributed proofs.  They are disposable fixtures.
SCHEMA = '''
CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), gen INTEGER NOT NULL,
    root TEXT NOT NULL, epoch INTEGER NOT NULL);
INSERT INTO state VALUES (1,1,'R0',1);
CREATE TABLE nonces (nonce TEXT PRIMARY KEY, generation INTEGER NOT NULL);
'''


def initialize(path, *, journal='DELETE'):
    db=sqlite3.connect(path,timeout=10)
    try:
        db.execute('PRAGMA journal_mode='+journal)
        db.execute('PRAGMA synchronous=FULL')
        db.executescript(SCHEMA)
        db.commit()
    finally:
        db.close()


def cas(path,base_gen,base_root,new_root,nonce,*,abort=None):
    db=sqlite3.connect(path,timeout=10,isolation_level=None)
    try:
        db.execute('PRAGMA busy_timeout=10000')
        db.execute('BEGIN IMMEDIATE')
        cur=db.execute('SELECT gen,root FROM state WHERE id=1').fetchone()
        if cur != (base_gen,base_root):
            db.rollback()
            return 'STALE'
        if db.execute('SELECT 1 FROM nonces WHERE nonce=?',(nonce,)).fetchone():
            db.rollback()
            return 'REPLAY'
        row=db.execute('UPDATE state SET gen=?,root=?,epoch=epoch+1 WHERE id=1 AND gen=? AND root=?',
                       (base_gen+1,new_root,base_gen,base_root))
        assert row.rowcount==1
        db.execute('INSERT INTO nonces(nonce,generation) VALUES (?,?)',(nonce,base_gen+1))
        if abort=='before':
            os._exit(61)
        db.commit()
        if abort=='after':
            os._exit(62)
        return 'COMMITTED'
    finally:
        db.close()


def state(path):
    db=sqlite3.connect(path,timeout=10)
    try:
        return db.execute('SELECT gen,root,epoch FROM state WHERE id=1').fetchone(),\
               db.execute('SELECT nonce FROM nonces ORDER BY nonce').fetchall()
    finally:
        db.close()


class RC685RealSQLiteAdversaries(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='rc685_local_cas_')
        self.addCleanup(self.tmp.cleanup)
        self.path=str(Path(self.tmp.name)/'cas.db')
        initialize(self.path)

    def test_01_real_begin_immediate_conditional_commit(self):
        self.assertEqual(cas(self.path,1,'R0','R1','n01'),'COMMITTED')
        self.assertEqual(state(self.path),((2,'R1',2),[('n01',)]))

    def test_02_stale_reader_cannot_double_commit(self):
        self.assertEqual(cas(self.path,1,'R0','R1','n02'),'COMMITTED')
        self.assertEqual(cas(self.path,1,'R0','R2','n03'),'STALE')
        self.assertEqual(state(self.path)[0],(2,'R1',2))

    def test_03_same_nonce_across_new_generation_rejected(self):
        self.assertEqual(cas(self.path,1,'R0','R1','n04'),'COMMITTED')
        self.assertEqual(cas(self.path,2,'R1','R2','n04'),'REPLAY')

    def test_04_sequential_fresh_nonce_can_commit(self):
        self.assertEqual(cas(self.path,1,'R0','R1','n05'),'COMMITTED')
        self.assertEqual(cas(self.path,2,'R1','R2','n06'),'COMMITTED')
        self.assertEqual(state(self.path)[0],(3,'R2',3))

    def test_05_three_thread_race_is_single_winner(self):
        barrier=threading.Barrier(3)
        result=[]
        lock=threading.Lock()
        def contender(i):
            barrier.wait(timeout=10)
            output=cas(self.path,1,'R0','R'+str(i),'thread'+str(i))
            with lock: result.append(output)
        threads=[threading.Thread(target=contender,args=(i,)) for i in (1,2,3)]
        for t in threads:t.start()
        for t in threads:t.join(timeout=15)
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertEqual(result.count('COMMITTED'),1)
        self.assertEqual(result.count('STALE'),2)

    def test_06_process_contenders_have_one_winner(self):
        script='''import sys\nfrom tests.test_rc685_witness_and_sqlite import cas\nprint(cas(sys.argv[1],1,'R0',sys.argv[2],sys.argv[3]),flush=True)'''
        ps=[]
        for i in range(3):
            ps.append(subprocess.Popen([sys.executable,'-c',script,self.path,'P'+str(i),'p'+str(i)],
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE))
        results=[]
        for p in ps:
            out,err=p.communicate(timeout=25)
            self.assertEqual(p.returncode,0,err.decode(errors='replace'))
            results.append(out.decode().strip())
        self.assertEqual(sorted(results),['COMMITTED','STALE','STALE'])

    def test_07_before_commit_process_exit_rolls_back(self):
        self._crash('before',61)
        self.assertEqual(state(self.path),((1,'R0',1),[]))

    def test_08_after_commit_process_exit_lost_ack_persists(self):
        self._crash('after',62)
        self.assertEqual(state(self.path),((2,'R1',2),[('crash',)]))

    def test_09_replay_after_lost_ack_fails_closed(self):
        self._crash('after',62)
        self.assertEqual(cas(self.path,1,'R0','R1','crash'),'STALE')
        self.assertEqual(state(self.path)[0],(2,'R1',2))

    def test_10_unique_nonce_is_not_independent_root_provenance(self):
        self.assertEqual(cas(self.path,1,'R0','R1','u10'),'COMMITTED')
        self.assertEqual(state(self.path)[0][0],2)
        # DB owner can still reset both state and nonce history.
        db=sqlite3.connect(self.path)
        try:
            db.execute("UPDATE state SET gen=1,root='R0',epoch=1 WHERE id=1")
            db.execute("DELETE FROM nonces")
            db.commit()
        finally:
            db.close()
        self.assertEqual(cas(self.path,1,'R0','R2','u10'),'COMMITTED')

    def test_11_snapshot_restore_defeats_local_monotonicity(self):
        snapshot=str(Path(self.tmp.name)/'old.db')
        shutil.copy2(self.path,snapshot)
        self.assertEqual(cas(self.path,1,'R0','R1','restored'),'COMMITTED')
        self.assertEqual(state(self.path)[0][0],2)
        shutil.copy2(snapshot,self.path)
        self.assertEqual(state(self.path)[0][0],1)
        self.assertEqual(cas(self.path,1,'R0','R2','restored'),'COMMITTED')

    def test_12_separate_untrusted_anchor_file_detects_rollback_if_retained(self):
        anchor=Path(self.tmp.name)/'external_anchor.txt'
        self.assertEqual(cas(self.path,1,'R0','R1','anchored'),'COMMITTED')
        anchor.write_text('2:R1',encoding='ascii')
        db=sqlite3.connect(self.path)
        try:
            db.execute("UPDATE state SET gen=1,root='R0',epoch=1 WHERE id=1")
            db.commit()
        finally:
            db.close()
        self.assertNotEqual(anchor.read_text(encoding='ascii'),
                            '%d:%s' % state(self.path)[0][:2])
        # This anchor is a local file, NOT independently authenticated.

    def test_13_same_administrator_can_roll_back_both_anchor_and_db(self):
        anchor=Path(self.tmp.name)/'external_anchor.txt'
        anchor.write_text('1:R0',encoding='ascii')
        self.assertEqual(cas(self.path,1,'R0','R1','n13'),'COMMITTED')
        anchor.write_text('2:R1',encoding='ascii')
        db=sqlite3.connect(self.path)
        try:
            db.execute("UPDATE state SET gen=1,root='R0',epoch=1 WHERE id=1")
            db.execute('DELETE FROM nonces')
            db.commit()
        finally:
            db.close()
        anchor.write_text('1:R0',encoding='ascii')
        self.assertEqual(anchor.read_text(encoding='ascii'),
                         '%d:%s' % state(self.path)[0][:2])
        self.assertEqual(cas(self.path,1,'R0','R2','n13'),'COMMITTED')

    def test_14_delete_journal_mode_restart_still_persists_committed(self):
        self.assertEqual(cas(self.path,1,'R0','R1','n14'),'COMMITTED')
        self.assertEqual(state(self.path)[0],(2,'R1',2))
        self.assertEqual(state(self.path)[0],(2,'R1',2))

    def test_15_begin_immediate_rollback_does_not_consume_nonce(self):
        self._crash('before',61)
        self.assertEqual(cas(self.path,1,'R0','R2','crash'),'COMMITTED')

    def test_16_read_only_connection_cannot_mutate_state(self):
        db=sqlite3.connect('file:'+self.path+'?mode=ro',uri=True)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("UPDATE state SET root='EVIL' WHERE id=1")
        finally:
            db.close()

    def test_17_double_winner_if_two_disconnected_db_copies(self):
        copydb=str(Path(self.tmp.name)/'other.db')
        shutil.copy2(self.path,copydb)
        self.assertEqual(cas(self.path,1,'R0','R1','same'),'COMMITTED')
        self.assertEqual(cas(copydb,1,'R0','R2','same'),'COMMITTED')
        self.assertNotEqual(state(self.path),state(copydb))

    def test_18_same_actor_restart_is_not_distinct_signer(self):
        self.assertEqual(cas(self.path,1,'R0','R1','restart'),'COMMITTED')
        self.assertEqual(cas(self.path,1,'R0','R1','restart'),'STALE')

    def _crash(self,stage,code):
        script='''import sys\nfrom tests.test_rc685_witness_and_sqlite import cas\ncas(sys.argv[1],1,'R0','R1','crash',abort=sys.argv[2])'''
        result=subprocess.run([sys.executable,'-c',script,self.path,stage],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25)
        self.assertEqual(result.returncode,code,result.stderr.decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
