"""RC688 invented gossip evidence and disposable *actual* SQLite fault model.

A passing test is NOT a signature, provider attestation, external anchor,
application integration, durable multi-host CAS, or market validation.
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

from safe_public_ci.ci_gossip_receipt_fence import GossipRejected, audit_claimed_gossip


def h(value):
    return hashlib.sha256(value.encode('ascii')).hexdigest()


def sample():
    head = 'a' * 40
    pins = {
        'head_sha': head, 'source_sha256': h('source'),
        'ubuntu_log_sha256': h('ubuntu full real log claimed'),
        'windows_log_sha256': h('windows full real log claimed'),
        'owner_fingerprint': h('owner claim'), 'reviewer_fingerprint': h('reviewer claim'),
        'ack_root_sha256': h('ack root'), 'externally_authenticated': False,
        'provider_origin_authenticated': False, 'independent_monotonic_anchor': False,
        'durable_cas_authenticated': False,
    }
    def view(actor, epoch, osname):
        return dict(client=actor, domain={'alice': 'left', 'bob': 'right'}[actor],
                    fingerprint=h(actor), epoch=epoch, tree_size=epoch+2,
                    root_sha256=h('root'+str(epoch)), provider_os=osname,
                    provider_log_sha256=pins[osname+'_log_sha256'],
                    provider_receipt_sha256=h('receipt'+osname),
                    nonce_sha256=h('nonce'+actor+str(epoch)),
                    ack_ref_sha256=pins['ack_root_sha256'])
    bundle = {
        'repo': 'ftmstr/Embasic-KriptoAI-Autopilot-Build',
        'branch': 'validation/rc654-pr1-rc653-combined-ci',
        'head_sha': head, 'source_sha256': pins['source_sha256'],
        'epoch_min': 1, 'epoch_max': 2,
        'owner_reviewer': [
            dict(role='owner', actor='source_owner',fingerprint=pins['owner_fingerprint'],claimed_key_origin='external_unverified'),
            dict(role='reviewer',actor='source_reviewer',fingerprint=pins['reviewer_fingerprint'],claimed_key_origin='external_unverified'),
        ],
        'providers': [
            dict(os='ubuntu',run_id=43287206673,job_id=131423650392,
                 log_sha256=pins['ubuntu_log_sha256'],head_sha=head,attempt=1),
            dict(os='windows',run_id=43287206675,job_id=131423661944,
                 log_sha256=pins['windows_log_sha256'],head_sha=head,attempt=1),
        ],
        'observations': [view('alice',1,'ubuntu'),view('bob',1,'ubuntu'),
                         view('alice',2,'windows'),view('bob',2,'windows')],
        'revocations': [dict(fingerprint=h('old retired external candidate'),epoch=1,reason_sha256=h('reason'))],
        'outbox': dict(transaction_sha256=h('transaction'),generation=3,
                       nonce_sha256=h('outbox nonce'),pending_digest_sha256=h('pending'),
                       ack_state='ACK_LOST_UNRESOLVED',ack_digest_sha256=h('untrusted ack'),
                       claim_cas_winner_count=1),
        'prior_checkpoints': [h('older 1'), h('older 2')],
        'safety_flags': dict(final_unsealed=False,live_enabled=False,
                             single_fit_used=False,profit_verified=False),
    }
    return bundle,pins


class RC688GossipDirect(unittest.TestCase):
    def test_01_good_claim_still_untrusted(self):
        bundle,pins=sample()
        result=audit_claimed_gossip(bundle,pins)
        self.assertEqual(result['status'],'CLAIMED_GOSSIP_CONSISTENT_ORIGIN_UNAUTHENTICATED')
        self.assertFalse(result['live_trading_allowed'])
    def test_02_every_auth_flag_remains_false(self):
        b,p=sample();x=audit_claimed_gossip(b,p)
        for k,v in x.items():
            if k.endswith(('authenticated','verified','allowed','ready')):
                self.assertIs(v,False,k)
    def test_03_fork_same_epoch_same_size(self):
        b,p=sample();b['observations'][1]['root_sha256']=h('fork')
        x=audit_claimed_gossip(b,p)
        self.assertEqual(x['status'],'CLAIMED_SPLIT_VIEW_DETECTED_ORIGIN_UNAUTHENTICATED')
        self.assertTrue(x['claimed_split_view'])
    def test_04_claimed_provider_receipt_fork_without_merkle_fork(self):
        b,p=sample();b['observations'][1]['provider_receipt_sha256']=h('same log fake receipt differs')
        x=audit_claimed_gossip(b,p)
        self.assertEqual(x['status'],'CLAIMED_LOG_FORK_DETECTED_ORIGIN_UNAUTHENTICATED')
        self.assertTrue(x['claimed_provider_log_fork'])
    def test_05_cross_domain_fake_majority_does_not_authenticate(self):
        b,p=sample();x=audit_claimed_gossip(b,p)
        self.assertEqual(x['claimed_distinct_domain_count'],2)
        self.assertIs(x['ed25519_owner_reviewer_origin_authenticated'],False)
    def test_06_source_root_binding_changes_digest(self):
        b,p=sample();a=audit_claimed_gossip(b,p)['claim_transcript_sha256']
        b['prior_checkpoints'][0]=h('updated old checkpoint')
        self.assertNotEqual(a,audit_claimed_gossip(b,p)['claim_transcript_sha256'])
    def test_07_order_of_observations_changes_digest(self):
        b,p=sample();a=audit_claimed_gossip(b,p)['claim_transcript_sha256']
        b['observations'].reverse()
        self.assertNotEqual(a,audit_claimed_gossip(b,p)['claim_transcript_sha256'])
    def test_08_can_detect_multi_epoch_fork(self):
        b,p=sample();b['observations'][3]['root_sha256']=h('epoch2 fork')
        self.assertTrue(audit_claimed_gossip(b,p)['claimed_split_view'])
    def test_09_every_valid_claim_remains_no_real_ack(self):
        b,p=sample();self.assertIs(audit_claimed_gossip(b,p)['outbox_ack_from_external_provider_verified'],False)
    def test_10_no_merkle_immutable_anchor_proven(self):
        b,p=sample();self.assertIs(audit_claimed_gossip(b,p)['merkle_external_immutable_anchor_authenticated'],False)
    def test_11_no_durable_multihost_cas(self):
        b,p=sample();self.assertIs(audit_claimed_gossip(b,p)['durable_multihost_cas_verified'],False)
    def test_12_no_signed_revocation_clock(self):
        b,p=sample();self.assertIs(audit_claimed_gossip(b,p)['real_signed_revocation_and_clock_authenticated'],False)
    def test_13_wrong_claimed_git_head_rejected(self):
        b,p=sample();b['head_sha']='b'*40
        with self.assertRaises(GossipRejected): audit_claimed_gossip(b,p)
    def test_14_duplicate_actor_domain_sybils_rejected(self):
        b,p=sample();b['observations'][1]['fingerprint']=h('alice')
        with self.assertRaises(GossipRejected): audit_claimed_gossip(b,p)
    def test_15_witness_cannot_claim_multiple_domains(self):
        b,p=sample();b['observations'][2]['domain']='other'
        with self.assertRaises(GossipRejected): audit_claimed_gossip(b,p)
    def test_16_old_client_history_regression(self):
        b,p=sample();b['observations'][2]['tree_size']=1
        with self.assertRaises(GossipRejected): audit_claimed_gossip(b,p)
    def test_17_untrusted_provider_only_hash(self):
        b,p=sample();x=audit_claimed_gossip(b,p)
        self.assertIs(x['provider_run_job_full_log_authenticated'],False)
    def test_18_no_owned_real_key_proof(self):
        b,p=sample();self.assertIs(audit_claimed_gossip(b,p)['ed25519_owner_reviewer_origin_authenticated'],False)
    def test_19_provider_pins_untrusted_by_design(self):
        b,p=sample();p['ubuntu_log_sha256']=h('independently untrusted new pin')
        with self.assertRaises(GossipRejected): audit_claimed_gossip(b,p)
    def test_20_claimed_multiple_checkpoints_cannot_enable_final(self):
        b,p=sample();b['prior_checkpoints']=[h('a'),h('b'),h('c')]
        self.assertIs(audit_claimed_gossip(b,p)['release_ready'],False)
    def test_21_transcript_hash_is_deterministic(self):
        b,p=sample();self.assertEqual(audit_claimed_gossip(b,p)['claim_transcript_sha256'],
                                     audit_claimed_gossip(copy.deepcopy(b),copy.deepcopy(p))['claim_transcript_sha256'])
    def test_22_typed_bool_vs_integer(self):
        b,p=sample();b['outbox']['generation']=True
        with self.assertRaises(GossipRejected): audit_claimed_gossip(b,p)
    def test_23_typed_list_vs_tuple(self):
        b,p=sample();b['providers']=tuple(b['providers'])
        with self.assertRaises(GossipRejected): audit_claimed_gossip(b,p)
    def test_24_missing_key_fails_closed(self):
        b,p=sample();del b['safety_flags']
        with self.assertRaises(GossipRejected): audit_claimed_gossip(b,p)
    def test_25_nonce_replay_cross_os(self):
        b,p=sample();b['observations'][3]['nonce_sha256']=b['observations'][0]['nonce_sha256']
        with self.assertRaises(GossipRejected): audit_claimed_gossip(b,p)
    def test_26_provider_receipt_fork_does_not_grant_auth(self):
        b,p=sample();b['observations'][1]['provider_receipt_sha256']=h('other')
        x=audit_claimed_gossip(b,p)
        self.assertIs(x['provider_run_job_full_log_authenticated'],False)
    def test_27_fork_without_trusted_merkle_anchor_remains_fork_claim(self):
        b,p=sample();b['observations'][1]['root_sha256']=h('fork')
        x=audit_claimed_gossip(b,p)
        self.assertTrue(x['claimed_split_view'])
        self.assertIs(x['merkle_external_immutable_anchor_authenticated'],False)
    def test_28_signed_provider_claim_without_origin_is_not_authenticated(self):
        b,p=sample();self.assertFalse(audit_claimed_gossip(b,p)['provider_run_job_full_log_authenticated'])


def mutated(name, change, pins=False):
    def case(self):
        b,p=sample()
        change(p if pins else b)
        with self.assertRaises(GossipRejected, msg=name):
            audit_claimed_gossip(b,p)
    case.__name__='test_mutation_'+name
    setattr(RC688GossipDirect,case.__name__,case)


_MUTATIONS=[
    ('wrong_repo',lambda x:x.update(repo='foreign/private')),
    ('wrong_branch',lambda x:x.update(branch='main')),
    ('missing_repo',lambda x:x.pop('repo')),
    ('extra_bundle_key',lambda x:x.update(extra_claim=1)),
    ('repo_list',lambda x:x.update(repo=[])),
    ('head_uppercase',lambda x:x.update(head_sha='A'*40)),
    ('head_short',lambda x:x.update(head_sha='a'*39)),
    ('source_short',lambda x:x.update(source_sha256='1'*63)),
    ('source_bad_type',lambda x:x.update(source_sha256=True)),
    ('epoch_bool',lambda x:x.update(epoch_min=True)),
    ('epoch_zero',lambda x:x.update(epoch_min=0)),
    ('epoch_inverted',lambda x:x.update(epoch_min=3)),
    ('epoch_unbounded',lambda x:x.update(epoch_max=200)),
    ('missing_signer',lambda x:x['owner_reviewer'].pop()),
    ('duplicate_signer',lambda x:x['owner_reviewer'][1].update(role='owner')),
    ('signer_actor_bad',lambda x:x['owner_reviewer'][0].update(actor='Admin-User')),
    ('signer_actor_same',lambda x:x['owner_reviewer'][1].update(actor=x['owner_reviewer'][0]['actor'])),
    ('signer_fingerprint_equal',lambda x:x['owner_reviewer'][1].update(fingerprint=x['owner_reviewer'][0]['fingerprint'])),
    ('signer_fingerprint_malformed',lambda x:x['owner_reviewer'][0].update(fingerprint='!')),
    ('signer_origin_self_attest',lambda x:x['owner_reviewer'][0].update(claimed_key_origin='trusted')),
    ('signer_unknown_role',lambda x:x['owner_reviewer'][0].update(role='admin')),
    ('signer_extra',lambda x:x['owner_reviewer'][0].update(other='signed')),
    ('providers_missing',lambda x:x['providers'].pop()),
    ('providers_duplicate_os',lambda x:x['providers'][1].update(os='ubuntu')),
    ('provider_unknown_os',lambda x:x['providers'][1].update(os='darwin')),
    ('provider_run_bool',lambda x:x['providers'][0].update(run_id=True)),
    ('provider_run_zero',lambda x:x['providers'][0].update(run_id=0)),
    ('provider_job_zero',lambda x:x['providers'][0].update(job_id=0)),
    ('provider_head_mismatch',lambda x:x['providers'][1].update(head_sha='b'*40)),
    ('provider_invalid_log',lambda x:x['providers'][0].update(log_sha256='z'*64)),
    ('provider_attempt_two',lambda x:x['providers'][0].update(attempt=2)),
    ('provider_attempt_bool',lambda x:x['providers'][0].update(attempt=True)),
    ('provider_duplicate_run_job',lambda x:x['providers'][1].update(run_id=x['providers'][0]['run_id'],job_id=x['providers'][0]['job_id'])),
    ('too_few_observations',lambda x:x['observations'].__setitem__(slice(2,None),[])),
    ('obs_missing_field',lambda x:x['observations'][0].pop('nonce_sha256')),
    ('obs_unknown_field',lambda x:x['observations'][0].update(signed=True)),
    ('obs_actor_bad',lambda x:x['observations'][0].update(client='Bad-ID')),
    ('obs_domain_bad',lambda x:x['observations'][0].update(domain='bad domain')),
    ('obs_fingerprint_bad',lambda x:x['observations'][0].update(fingerprint='0')),
    ('obs_epoch_future',lambda x:x['observations'][0].update(epoch=99)),
    ('obs_tree_size_zero',lambda x:x['observations'][0].update(tree_size=0)),
    ('obs_tree_size_big',lambda x:x['observations'][0].update(tree_size=129)),
    ('obs_root_invalid',lambda x:x['observations'][0].update(root_sha256='f'*63)),
    ('obs_provider_mismatch',lambda x:x['observations'][0].update(provider_log_sha256=h('different log'))),
    ('obs_provider_unknown',lambda x:x['observations'][0].update(provider_os='spot')),
    ('obs_receipt_invalid',lambda x:x['observations'][0].update(provider_receipt_sha256='!')),
    ('obs_ack_wrong',lambda x:x['observations'][0].update(ack_ref_sha256=h('another'))),
    ('obs_duplicate_identity',lambda x:x['observations'].append(copy.deepcopy(x['observations'][0]))),
    ('obs_all_same_domain',lambda x:[v.update(domain='single') for v in x['observations']]),
    ('obs_revoked_key',lambda x:x['observations'][0].update(fingerprint=h('old retired external candidate'))),
    ('revoke_duplicate',lambda x:x['revocations'].append(copy.deepcopy(x['revocations'][0]))),
    ('revoke_reason_invalid',lambda x:x['revocations'][0].update(reason_sha256='bad')),
    ('revoke_epoch_zero',lambda x:x['revocations'][0].update(epoch=0)),
    ('revoke_owner_now',lambda x:x['revocations'].append(dict(fingerprint=x['owner_reviewer'][0]['fingerprint'],epoch=2,reason_sha256=h('reason')))),
    ('checkpoints_duplicate',lambda x:x['prior_checkpoints'].append(x['prior_checkpoints'][0])),
    ('checkpoints_empty',lambda x:x.update(prior_checkpoints=[])),
    ('checkpoints_invalid',lambda x:x['prior_checkpoints'].__setitem__(0,'!')),
    ('outbox_gen_zero',lambda x:x['outbox'].update(generation=0)),
    ('outbox_winner_two',lambda x:x['outbox'].update(claim_cas_winner_count=2)),
    ('outbox_ack_forged',lambda x:x['outbox'].update(ack_state='ACKED')),
    ('outbox_nonce_invalid',lambda x:x['outbox'].update(nonce_sha256='a'*65)),
    ('outbox_pending_invalid',lambda x:x['outbox'].update(pending_digest_sha256=10)),
    ('safety_enable_live',lambda x:x['safety_flags'].update(live_enabled=True)),
    ('safety_enable_final',lambda x:x['safety_flags'].update(final_unsealed=True)),
    ('safety_enable_fit',lambda x:x['safety_flags'].update(single_fit_used=True)),
    ('safety_enable_profit',lambda x:x['safety_flags'].update(profit_verified=True)),
    ('safety_false_int',lambda x:x['safety_flags'].update(live_enabled=0)),
]
for name,fn in _MUTATIONS:
    mutated(name,fn)
for field in ('externally_authenticated','provider_origin_authenticated','independent_monotonic_anchor','durable_cas_authenticated'):
    mutated('self_promotion_'+field,lambda x,f=field:x.update({f:True}),True)


# The disposable SQL store stays strictly under tests/. It is NOT production CAS.
def init_db(path):
    db=sqlite3.connect(path,timeout=15)
    try:
        db.execute('PRAGMA journal_mode=DELETE')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE control(generation INTEGER NOT NULL, root TEXT NOT NULL)')
        db.execute('INSERT INTO control VALUES(1,?)',(h('r1'),))
        db.execute('CREATE TABLE spent(nonce TEXT PRIMARY KEY)')
        db.execute('CREATE TABLE outbox(nonce TEXT PRIMARY KEY,payload TEXT NOT NULL,ack TEXT NOT NULL)')
        db.commit()
    finally:
        db.close()


def transact(path, expected, root, nonce, payload='payload'):
    db=sqlite3.connect(path,timeout=15,isolation_level=None)
    try:
        db.execute('PRAGMA synchronous=FULL')
        db.execute('BEGIN IMMEDIATE')
        got=db.execute('SELECT generation, root FROM control').fetchone()
        if got!=(expected,root):
            db.rollback()
            return 'STALE'
        db.execute('UPDATE control SET generation=?,root=?',(expected+1,h('new'+nonce)))
        db.execute('INSERT INTO spent VALUES(?)',(nonce,))
        db.execute('INSERT INTO outbox VALUES(?,?,?)',(nonce,payload,'PENDING'))
        db.commit()
        return 'COMMITTED'
    except sqlite3.IntegrityError:
        db.rollback()
        return 'DUPLICATE_NONCE'
    finally:
        db.close()


def inspect(path):
    db=sqlite3.connect(path,timeout=15)
    try:
        return (db.execute('SELECT generation,root FROM control').fetchone(),
                db.execute('SELECT nonce FROM spent ORDER BY nonce').fetchall(),
                db.execute('SELECT nonce,payload,ack FROM outbox ORDER BY nonce').fetchall())
    finally:
        db.close()


class RC688SQLiteTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db=str(Path(self.tmp.name)/'claims.db')
        init_db(self.db)
    def stage(self,nonce='a'):
        return transact(self.db,1,h('r1'),nonce)
    def test_01_single_cas_and_atomic_outbox(self):
        self.assertEqual(self.stage(),'COMMITTED')
        state,spent,outbox=inspect(self.db)
        self.assertEqual((state[0],len(spent),len(outbox)),(2,1,1))
        self.assertEqual(outbox[0][-1],'PENDING')
    def test_02_stale_root_rejected(self):
        self.assertEqual(transact(self.db,1,h('wrong'),'a'),'STALE')
        self.assertEqual(len(inspect(self.db)[1]),0)
    def test_03_stale_generation_rejected(self):
        self.stage()
        self.assertEqual(self.stage('b'),'STALE')
        self.assertEqual(len(inspect(self.db)[2]),1)
    def test_04_competing_threads_one_winner(self):
        results=[];barrier=threading.Barrier(3);lock=threading.Lock()
        def worker(i):
            barrier.wait()
            got=self.stage('race'+str(i))
            with lock:results.append(got)
        threads=[threading.Thread(target=worker,args=(i,)) for i in range(3)]
        for t in threads:t.start()
        for t in threads:t.join(timeout=15)
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertEqual(sorted(results),['COMMITTED','STALE','STALE'])
    def test_05_two_disconnected_copies_accept_double_winner(self):
        second=str(Path(self.tmp.name)/'clone.db')
        shutil.copyfile(self.db,second)
        self.assertEqual(self.stage('same'),'COMMITTED')
        self.assertEqual(transact(second,1,h('r1'),'different'),'COMMITTED')
        self.assertNotEqual(inspect(self.db)[0][1],inspect(second)[0][1])
    def test_06_clone_same_nonce_can_win_twice(self):
        second=str(Path(self.tmp.name)/'clone.db')
        shutil.copyfile(self.db,second)
        self.assertEqual(self.stage('same'),'COMMITTED')
        self.assertEqual(transact(second,1,h('r1'),'same'),'COMMITTED')
    def test_07_snapshot_restore_defeats_old_nonce(self):
        snap=str(Path(self.tmp.name)/'old.db');shutil.copyfile(self.db,snap)
        self.stage('reuse');shutil.copyfile(snap,self.db)
        self.assertEqual(self.stage('reuse'),'COMMITTED')
    def test_08_privileged_admin_changes_state_and_nonces(self):
        self.stage('reuse')
        db=sqlite3.connect(self.db)
        try:
            db.execute('UPDATE control SET generation=1,root=?',(h('r1'),))
            db.execute('DELETE FROM spent')
            db.execute('DELETE FROM outbox')
            db.commit()
        finally:db.close()
        self.assertEqual(self.stage('reuse'),'COMMITTED')
    def test_09_pending_ack_not_provider_ack(self):
        self.stage('a')
        self.assertEqual(inspect(self.db)[2][0][-1],'PENDING')
    def test_10_local_admin_can_forge_ack(self):
        self.stage('a')
        db=sqlite3.connect(self.db)
        try:
            db.execute("UPDATE outbox SET ack='ACKED' WHERE nonce='a'");db.commit()
        finally:db.close()
        self.assertEqual(inspect(self.db)[2][0][-1],'ACKED')
    def test_11_same_db_nonce_replay_blocked_after_new_generation(self):
        self.stage('a')
        root=inspect(self.db)[0][1]
        self.assertEqual(transact(self.db,2,root,'a'),'DUPLICATE_NONCE')
        self.assertEqual(inspect(self.db)[0][0],2)
    def test_12_nonce_reuse_after_rollback_not_committed(self):
        db=sqlite3.connect(self.db,isolation_level=None)
        try:
            db.execute('BEGIN IMMEDIATE');db.execute('INSERT INTO spent VALUES(?)',('a',));db.rollback()
        finally:db.close()
        self.assertEqual(self.stage('a'),'COMMITTED')
    def test_13_outbox_table_cannot_evidence_delivery(self):
        self.stage('a');self.assertEqual(len(inspect(self.db)[2]),1)
        self.assertNotEqual(inspect(self.db)[2][0][2],'PROVIDER_SIGNED_ACK')
    def test_14_connection_reopen_readback(self):
        self.stage('a');self.assertEqual(inspect(self.db),inspect(self.db))
    def test_15_commit_failure_then_no_orphaned_outbox(self):
        self.stage('a');root=inspect(self.db)[0][1]
        self.assertEqual(transact(self.db,2,root,'a'),'DUPLICATE_NONCE')
        self.assertEqual(len(inspect(self.db)[2]),1)
    def test_16_admin_root_and_local_anchor_can_both_be_rewritten(self):
        anchor=Path(self.tmp.name)/'anchor.txt'
        anchor.write_text(h('r1'),encoding='ascii')
        self.stage('a');anchor.write_text(inspect(self.db)[0][1],encoding='ascii')
        db=sqlite3.connect(self.db)
        try:
            db.execute('UPDATE control SET generation=1,root=?',(h('r1'),));db.commit()
        finally:db.close()
        anchor.write_text(h('r1'),encoding='ascii')
        self.assertEqual(anchor.read_text(encoding='ascii'),inspect(self.db)[0][1])
    def test_17_two_db_instances_no_external_linearization(self):
        a=str(Path(self.tmp.name)/'db2.db');shutil.copyfile(self.db,a)
        self.stage('a');transact(a,1,h('r1'),'b')
        self.assertEqual(inspect(self.db)[0][0],inspect(a)[0][0])
        self.assertNotEqual(inspect(self.db)[0][1],inspect(a)[0][1])
    def test_18_crash_before_commit_rolls_back(self):
        script="import os,sqlite3,sys;d=sqlite3.connect(sys.argv[1]);d.execute('BEGIN IMMEDIATE');d.execute(\"INSERT INTO spent VALUES('x')\");os._exit(71)"
        p=subprocess.run([sys.executable,'-c',script,self.db],capture_output=True,timeout=15)
        self.assertEqual(p.returncode,71,p.stderr.decode(errors='replace'))
        self.assertEqual(len(inspect(self.db)[1]),0)
    def test_19_crash_after_commit_before_ack_persists(self):
        script="import os,sqlite3,sys;d=sqlite3.connect(sys.argv[1]);d.execute('BEGIN IMMEDIATE');d.execute(\"INSERT INTO spent VALUES('x')\");d.execute(\"INSERT INTO outbox VALUES('x','payload','PENDING')\");d.commit();os._exit(72)"
        p=subprocess.run([sys.executable,'-c',script,self.db],capture_output=True,timeout=15)
        self.assertEqual(p.returncode,72,p.stderr.decode(errors='replace'))
        self.assertEqual(len(inspect(self.db)[1]),1)
        self.assertEqual(inspect(self.db)[2][0][-1],'PENDING')
    def test_20_separate_processes_on_clones_cannot_prevent_fork(self):
        other=str(Path(self.tmp.name)/'other.db');shutil.copyfile(self.db,other)
        script="import sqlite3,sys;d=sqlite3.connect(sys.argv[1]);d.execute('BEGIN IMMEDIATE');d.execute(\"UPDATE control SET generation=2,root='other'\");d.commit();d.close()"
        procs=[subprocess.run([sys.executable,'-c',script,name],capture_output=True,timeout=15) for name in (self.db,other)]
        self.assertEqual([p.returncode for p in procs],[0,0])
        self.assertEqual(inspect(self.db)[0][0],inspect(other)[0][0])
    def test_21_readonly_connection_cannot_write(self):
        db=sqlite3.connect(Path(self.db).as_uri()+'?mode=ro',uri=True)
        try:
            with self.assertRaises(sqlite3.OperationalError):db.execute('UPDATE control SET generation=7')
        finally:db.close()
    def test_23_actual_two_process_single_store_cas_one_winner(self):
        script = ("import sqlite3,sys;d=sqlite3.connect(sys.argv[1],timeout=15,isolation_level=None);"
                  "d.execute('BEGIN IMMEDIATE');"
                  "old=d.execute('SELECT generation,root FROM control').fetchone();"
                  "win=old==(1,sys.argv[2]);"
                  "d.execute('UPDATE control SET generation=2,root=\"process_winner\"') if win else None;"
                  "d.execute(\"INSERT INTO spent VALUES('claim_nonce')\") if win else None;"
                  "d.execute(\"INSERT INTO outbox VALUES('claim_nonce','claim','PENDING')\") if win else None;"
                  "d.commit() if win else d.rollback();"
                  "print('WIN' if win else 'STALE');d.close()")
        procs=[subprocess.Popen([sys.executable,'-c',script,self.db,h('r1')],
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
        out=[p.communicate(timeout=15) for p in procs]
        for p,(_,err) in zip(procs,out):
            self.assertEqual(p.returncode,0,err.decode(errors='replace'))
        self.assertEqual(sorted(x[0].decode().strip() for x in out),['STALE','WIN'])
        self.assertEqual((len(inspect(self.db)[1]),len(inspect(self.db)[2])),(1,1))
    def test_24_restart_after_lost_ack_is_still_pending(self):
        script=("import sqlite3,sys;d=sqlite3.connect(sys.argv[1]);"
                "r=d.execute('SELECT ack FROM outbox WHERE nonce=?',('a',)).fetchone();"
                "print(r[0] if r else 'MISSING');d.close()")
        self.assertEqual(self.stage('a'),'COMMITTED')
        p=subprocess.run([sys.executable,'-c',script,self.db],capture_output=True,timeout=15)
        self.assertEqual(p.returncode,0,p.stderr.decode(errors='replace'))
        self.assertEqual(p.stdout.decode().strip(),'PENDING')
    def test_22_test_model_is_not_runtime_dependency(self):
        import safe_public_ci.ci_gossip_receipt_fence as mod
        self.assertNotIn('sqlite3',mod.__dict__)
        self.assertFalse(audit_claimed_gossip(*sample())['durable_multihost_cas_verified'])


if __name__=='__main__':
    unittest.main()
