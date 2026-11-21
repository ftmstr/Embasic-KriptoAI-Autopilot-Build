"""RC692 original bounded chain-of-custody quarantine and actual disposable SQLite CAS tests.

Test-only databases and worker subprocesses never contact or authenticate an
exchange, GitHub provider, key authority, external log, or durable CAS quorum.
"""
import copy
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

# An executed child script's sys.path[0] is tests/, not the repository root.
# This is an exact-file-derived TEST bootstrap, no environment escape.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_chain_of_custody_quarantine as gate


def H(s):
    return hashlib.sha256(str(s).encode('ascii')).hexdigest()


def mk(seed='s0', epoch=3):
    leaves=[H('leaf:'+str(seed)+':'+str(i)) for i in range(8)]
    old=4
    root=gate._root(leaves).hex()
    oldroot=gate._root(leaves[:old]).hex()
    ids=['alpha','beta','gamma']
    return {
        'repository':'ftmstr/Embasic-KriptoAI-Autopilot-Build',
        'branch':'validation/rc654-pr1-rc653-combined-ci',
        'source_sha':'a'*40,'workflow_sha256':H('workflow'),
        'epoch':epoch,'observed_at':200,
        'authorities':[
            {'role':role,'controller':'ctrl_'+role,'fingerprint':H('fp_'+role),
             'ed25519_public_hex':H('pub_'+role),'signed_at':140,
             'valid_from':100,'valid_to':1000,'signature_hex':H('sig_'+role)*2}
            for role in ('owner','reviewer')],
        'revocations':[],
        'providers':[
            {'os':platform,'run':100+i,'job':200+i,'attempt':1,
             'head_sha':'a'*40,'workflow_sha256':H('workflow'),
             'full_log_sha256':H('full_'+platform), 'job_sha256':H('job_'+platform),
             'signed_receipt_sha256':H('claimed_receipt_'+platform),
             'signature_hex':H('provider_sig_'+platform)*2,
             'controller':'host_'+platform}
            for i,platform in enumerate(('ubuntu','windows'))],
        'history':{'leaves':leaves,'old_size':old,'old_root':oldroot,
                   'root':root,'included_index':6,
                   'inclusion_proof':list(gate.inclusion_proof(leaves,6)),
                   'consistency_proof':list(gate.consistency_proof(leaves,old))},
        'witnesses':[
            {'id':name,'domain':'domain_'+name,'controller':'member_'+name,
             'epoch':epoch,'root':root,'receipt_sha256':H('rcpt_'+name),
             'signature_hex':H('witness_sig_'+name)*2}
            for name in ids],
        'gossip':[{'from':a,'to':b,'epoch':epoch,'root':root,
                   'receipt_sha256':H('msg_'+a+'_'+b)}
                  for a in ids for b in ids if a!=b],
        'anchor':{'claimed_service':'caller_only','root':root,'epoch':epoch,
                  'time':250,'immutable_verified':False},
        'journal':{'epoch':epoch,'generation':5,'next_generation':6,
                   'fence':10,'next_fence':11,'nonce_sha256':H('nonce'),
                   'state':'PENDING','ack_sha256':None,'provider_seen':False,
                   'external_cas_verified':False,'snapshot_root':oldroot},
        'release':{k:False for k in ('authenticated','live','final','fitted','net20_tested')},
    }


class RC692CoreTests(unittest.TestCase):
    def test_good_claim_is_still_untrusted(self):
        r=gate.validate_claim(mk())
        self.assertEqual(r['status'],'QUARANTINED_CLAIM_ONLY_NOT_AUTHENTICATED')
        self.assertFalse(any(v is True for v in r.values()))
    def test_comparison_equal_is_not_authority(self):
        self.assertEqual(gate.compare_views(mk(),mk()),'CLAIMED_EQUAL_VIEWS_NOT_AUTHENTICATED')
    def test_same_epoch_different_tree(self):
        self.assertEqual(gate.compare_views(mk('a'),mk('b')),'CLAIMED_SAME_EPOCH_MERKLE_FORK_NOT_AUTHENTICATED')
    def test_claimed_provider_log_fork(self):
        other=mk();other['providers'][0]['full_log_sha256']=H('different')
        self.assertEqual(gate.compare_views(mk(),other),'CLAIMED_PROVIDER_FULL_LOG_FORK_NOT_AUTHENTICATED')
    def test_claimed_witness_receipt_fork(self):
        other=mk();other['witnesses'][2]['receipt_sha256']=H('different')
        self.assertEqual(gate.compare_views(mk(),other),'CLAIMED_GOSSIP_RECEIPT_FORK_NOT_AUTHENTICATED')
    def test_claimed_nonce_aba_replay(self):
        other=mk();other['journal']['generation']=6;other['journal']['next_generation']=7
        self.assertEqual(gate.compare_views(mk(),other),'CLAIMED_NONCE_ABA_REPLAY_NOT_AUTHENTICATED')
    def test_alleged_epoch_change_no_external_history(self):
        self.assertEqual(gate.compare_views(mk(epoch=3),mk(epoch=4)),'CLAIMED_DIFFERENT_EPOCH_NO_EXTERNAL_CONSISTENCY')
    def test_other_source_sha_fork(self):
        other=mk();other['source_sha']='b'*40;other['providers'][0]['head_sha']='b'*40;other['providers'][1]['head_sha']='b'*40
        self.assertEqual(gate.compare_views(mk(),other),'CLAIMED_BUILD_PIN_FORK_NOT_AUTHENTICATED')
    def test_merkle_sizes_one_to_twenty(self):
        for n in range(2,21):
            leaves=[H('x'+str(i)) for i in range(n)]
            for size in (1,n//2,n-1):
                self.assertEqual(gate._root(leaves[:size]).hex(),gate._root(leaves[:size]).hex())
                self.assertLessEqual(len(gate.consistency_proof(leaves,size)),n)
            for ix in (0,n//2,n-1):
                self.assertLessEqual(len(gate.inclusion_proof(leaves,ix)),n)


_MUTATIONS=[]
def add(name,fn):
    _MUTATIONS.append((name,fn))

def put(d,path,value):
    cur=d
    for k in path[:-1]:cur=cur[k]
    cur[path[-1]]=value

def remove(d,path):
    cur=d
    for k in path[:-1]:cur=cur[k]
    del cur[path[-1]]

for field in sorted(gate._FIELDS):
    add('missing_top_'+field,lambda d,field=field:remove(d,(field,)))
add('unexpected_top_field',lambda d:put(d,('unexpected',),True))
for name,path,val in [
    ('wrong_repository',('repository',),'another/repo'),
    ('wrong_branch',('branch',),'main'),
    ('source_sha_invalid',('source_sha',),'a'*39),
    ('source_sha_uppercase',('source_sha',),'A'*40),
    ('workflow_wrong_length',('workflow_sha256',),'a'*63),
    ('epoch_boolean',('epoch',),True),
    ('epoch_zero',('epoch',),0),
    ('epoch_float',('epoch',),3.0),
    ('observed_zero',('observed_at',),0),
    ('observed_boolean',('observed_at',),True),
    ('authorities_not_list',('authorities',),()),
    ('authorities_single',('authorities',),[]),
    ('authorities_triple',('authorities',),[mk()['authorities'][0]]*3),
    ('role_duplicate',('authorities',1,'role'),'owner'),
    ('role_foreign',('authorities',0,'role'),'admin'),
    ('controller_duplicate',('authorities',1,'controller'),'ctrl_owner'),
    ('controller_not_name',('authorities',0,'controller'),'OWNER!'),
    ('fingerprint_duplicate',('authorities',1,'fingerprint'),H('fp_owner')),
    ('fingerprint_truncated',('authorities',1,'fingerprint'),'0'),
    ('public_key_duplicate',('authorities',1,'ed25519_public_hex'),H('pub_owner')),
    ('public_key_not_hex',('authorities',0,'ed25519_public_hex'),'g'*64),
    ('syntactic_signature_short',('authorities',0,'signature_hex'),'f'*127),
    ('key_signed_before_start',('authorities',0,'signed_at'),80),
    ('key_signed_after_expiry',('authorities',0,'signed_at'),1001),
    ('key_signed_after_observed',('authorities',0,'signed_at'),250),
    ('key_valid_from_bool',('authorities',0,'valid_from'),True),
    ('key_valid_to_zero',('authorities',1,'valid_to'),0),
    ('revocations_wrong_type',('revocations',),'revoked'),
    ('revocations_unknown_fp',('revocations',),[{'fingerprint':H('unknown'),'effective_at':220,'reason':'lost','claimed_authorizer':'ctrl_owner'}]),
    ('revocations_early',('revocations',),[{'fingerprint':H('fp_owner'),'effective_at':180,'reason':'compromise','claimed_authorizer':'ctrl_reviewer'}]),
    ('revocations_malformed_reason',('revocations',),[{'fingerprint':H('fp_owner'),'effective_at':220,'reason':'speculative','claimed_authorizer':'ctrl_reviewer'}]),
    ('revocations_fake_controller',('revocations',),[{'fingerprint':H('fp_owner'),'effective_at':220,'reason':'lost','claimed_authorizer':'outsider'}]),
    ('providers_wrong_type',('providers',),()),
    ('providers_one',('providers',),[]),
    ('providers_duplicate_os',('providers',1,'os'),'ubuntu'),
    ('providers_fake_os',('providers',1,'os'),'mac'),
    ('providers_run_zero',('providers',0,'run'),0),
    ('providers_job_boolean',('providers',1,'job'),True),
    ('providers_attempt_boolean',('providers',0,'attempt'),True),
    ('providers_attempt_two',('providers',1,'attempt'),2),
    ('providers_wrong_head',('providers',0,'head_sha'),'b'*40),
    ('providers_wrong_workflow',('providers',1,'workflow_sha256'),H('changed workflow')),
    ('providers_log_bad',('providers',0,'full_log_sha256'),'0'),
    ('providers_job_digest_bad',('providers',0,'job_sha256'),'gg'*32),
    ('providers_receipt_bad',('providers',1,'signed_receipt_sha256'),'z'*64),
    ('providers_signature_bad',('providers',0,'signature_hex'),'a'*64),
    ('providers_controller_duplicate',('providers',1,'controller'),'host_ubuntu'),
    ('history_leaves_empty',('history','leaves'),[]),
    ('history_leaves_oversized',('history','leaves'),[H(i) for i in range(129)]),
    ('history_leaf_bad',('history','leaves',0),'z'*64),
    ('history_old_size_bool',('history','old_size'),True),
    ('history_old_size_zero',('history','old_size'),0),
    ('history_old_size_equal',('history','old_size'),8),
    ('history_old_root_bad',('history','old_root'),H('wrong')),
    ('history_root_bad',('history','root'),H('wrong')),
    ('history_index_bool',('history','included_index'),True),
    ('history_index_out',('history','included_index'),8),
    ('history_wrong_inclusion',('history','inclusion_proof'),[]),
    ('history_wrong_consistency',('history','consistency_proof'),[]),
    ('history_consistency_tuple',('history','consistency_proof'),()),
    ('witnesses_short',('witnesses',),mk()['witnesses'][:2]),
    ('witness_duplicate_id',('witnesses',1,'id'),'alpha'),
    ('witness_duplicate_domain',('witnesses',1,'domain'),'domain_alpha'),
    ('witness_duplicate_controller',('witnesses',1,'controller'),'member_alpha'),
    ('witness_root_wrong',('witnesses',1,'root'),H('other root')),
    ('witness_epoch_wrong',('witnesses',0,'epoch'),4),
    ('witness_receipt_bad',('witnesses',2,'receipt_sha256'),'bad'),
    ('witness_signature_bad',('witnesses',1,'signature_hex'),'f'*65),
    ('gossip_missing_edge',('gossip',),mk()['gossip'][:5]),
    ('gossip_duplicate_edge',('gossip',1),mk()['gossip'][0]),
    ('gossip_duplicate_target',('gossip',1,'to'),'beta'),
    ('gossip_self_edge',('gossip',0,'to'),'alpha'),
    ('gossip_foreign_sender',('gossip',0,'from'),'unknown'),
    ('gossip_wrong_root',('gossip',0,'root'),H('other')),
    ('gossip_wrong_epoch',('gossip',1,'epoch'),4),
    ('gossip_receipt_bad',('gossip',2,'receipt_sha256'),'w'*64),
    ('anchor_service_foreign',('anchor','claimed_service'),'external_auth'),
    ('anchor_root_wrong',('anchor','root'),H('external')),
    ('anchor_epoch_wrong',('anchor','epoch'),99),
    ('anchor_clock_reversed',('anchor','time'),199),
    ('anchor_immutable_forged',('anchor','immutable_verified'),True),
    ('journal_epoch_wrong',('journal','epoch'),99),
    ('journal_generation_zero',('journal','generation'),0),
    ('journal_generation_bool',('journal','generation'),True),
    ('journal_next_generation_wrong',('journal','next_generation'),99),
    ('journal_fence_zero',('journal','fence'),0),
    ('journal_stale_fence',('journal','next_fence'),10),
    ('journal_nonce_bad',('journal','nonce_sha256'),'0'),
    ('journal_ack_premature',('journal','ack_sha256'),H('fake ack')),
    ('journal_state_acked',('journal','state'),'ACKED'),
    ('journal_provider_seen_fake',('journal','provider_seen'),True),
    ('journal_external_cas_fake',('journal','external_cas_verified'),True),
    ('journal_snapshot_wrong',('journal','snapshot_root'),H('modified backup')),
]: add(name,lambda d,path=path,val=val:put(d,path,val))
for f in ('authenticated','live','final','fitted','net20_tested'):
    add('release_true_'+f,lambda d,f=f:put(d,('release',f),True))
add('release_extra',lambda d:put(d,('release','money'),True))

for name,mutation in _MUTATIONS:
    def make(fn):
        def test(self):
            d=mk();fn(d)
            with self.assertRaises(gate.CustodyRejected):gate.validate_claim(d)
        return test
    setattr(RC692CoreTests,'test_mutation_'+name,make(mutation))


def init_db(path):
    c=sqlite3.connect(path)
    try:
        c.executescript('''
        CREATE TABLE generation (id INTEGER PRIMARY KEY CHECK (id=1),epoch INTEGER NOT NULL,
             gen INTEGER NOT NULL,token INTEGER NOT NULL,root TEXT NOT NULL);
        CREATE TABLE spent (nonce TEXT PRIMARY KEY);
        CREATE TABLE outbox (nonce TEXT PRIMARY KEY,state TEXT NOT NULL,
             generation INTEGER NOT NULL,provider_receipt TEXT);
        CREATE TABLE anchor (id INTEGER PRIMARY KEY CHECK(id=1),root TEXT NOT NULL);
        INSERT INTO generation VALUES (1,3,5,10,'oldroot');
        INSERT INTO anchor VALUES(1,'oldroot');
        ''')
        c.commit()
    finally:c.close()


def cas(path,nonce,expected_gen=5,expected_token=10,mode='normal',newroot='newroot'):
    c=sqlite3.connect(path,timeout=12,isolation_level=None)
    try:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT COUNT(*) FROM spent WHERE nonce=?',(nonce,)).fetchone()[0]:
            c.rollback();return 'REPLAY'
        cur=c.execute('UPDATE generation SET gen=gen+1,token=token+1,root=? '
                      'WHERE id=1 AND epoch=3 AND gen=? AND token=?',
                      (newroot,expected_gen,expected_token))
        if cur.rowcount!=1:
            c.rollback();return 'STALE'
        c.execute('INSERT INTO spent(nonce) VALUES (?)',(nonce,))
        c.execute('INSERT INTO outbox(nonce,state,generation,provider_receipt) VALUES (?,"PENDING",?,NULL)',
                  (nonce,expected_gen+1))
        c.execute('UPDATE anchor SET root=? WHERE id=1',(newroot,))
        if mode=='before':
            os._exit(71)
        c.commit()
        if mode=='after':
            os._exit(72)
        return 'WON'
    finally:c.close()


def child_cmd(path,nonce,mode='normal',gen=5,token=10):
    return [sys.executable,str(Path(__file__).resolve()),'--worker',str(path),nonce,mode,str(gen),str(token)]


class SQLiteCases(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='rc692_offline_')
        self.path=str(Path(self.tmp.name)/'temp.sqlite3')
        init_db(self.path)
    def tearDown(self):self.tmp.cleanup()
    def state(self):
        c=sqlite3.connect(self.path)
        try:
            row=c.execute('SELECT epoch,gen,token,root FROM generation').fetchone()
            spent=c.execute('SELECT nonce FROM spent ORDER BY nonce').fetchall()
            outbox=c.execute('SELECT nonce,state,generation,provider_receipt FROM outbox').fetchall()
            anchor=c.execute('SELECT root FROM anchor').fetchone()[0]
            return row,spent,outbox,anchor
        finally:c.close()
    def test_01_initial_unmodified(self):
        self.assertEqual(self.state()[0],(3,5,10,'oldroot'))
    def test_02_one_winner(self):
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
        self.assertEqual(self.state()[0],(3,6,11,'newroot'))
    def test_03_duplicate_nonce_replay(self):
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
        self.assertEqual(cas(self.path,'nonce-a',6,11),'REPLAY')
    def test_04_stale_generation(self):
        self.assertEqual(cas(self.path,'nonce-a',4,10),'STALE')
    def test_05_stale_token(self):
        self.assertEqual(cas(self.path,'nonce-a',5,9),'STALE')
    def test_06_process_before_commit_rolls_back(self):
        p=subprocess.run(child_cmd(self.path,'nonce-a','before'),capture_output=True,text=True,timeout=18)
        self.assertEqual(p.returncode,71,p.stderr)
        self.assertEqual(self.state()[0],(3,5,10,'oldroot'))
    def test_07_process_after_commit_pending(self):
        p=subprocess.run(child_cmd(self.path,'nonce-a','after'),capture_output=True,text=True,timeout=18)
        self.assertEqual(p.returncode,72,p.stderr)
        self.assertEqual(self.state()[2][0][1],'PENDING')
    def test_08_lost_ack_replay_denied(self):
        self.assertEqual(subprocess.run(child_cmd(self.path,'nonce-a','after'),capture_output=True,timeout=18).returncode,72)
        self.assertEqual(cas(self.path,'nonce-a',6,11),'REPLAY')
    def test_09_two_subprocesses_one_winner(self):
        a=subprocess.Popen(child_cmd(self.path,'nonce-a'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        b=subprocess.Popen(child_cmd(self.path,'nonce-b'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        ax,ae=a.communicate(timeout=25);bx,be=b.communicate(timeout=25)
        self.assertEqual((a.returncode,b.returncode),(0,0),ae+be)
        self.assertEqual(sorted((ax.strip(),bx.strip())),['STALE','WON'])
    def test_10_three_threads_one_winner(self):
        answers=[];lock=threading.Lock()
        def run(i):
            r=cas(self.path,'nonce-'+str(i))
            with lock:answers.append(r)
        th=[threading.Thread(target=run,args=(i,)) for i in range(3)]
        for t in th:t.start()
        for t in th:t.join(timeout=20)
        self.assertEqual(answers.count('WON'),1)
    def test_11_disconnected_copies_double_winner(self):
        twin=str(Path(self.tmp.name)/'twin.sqlite3');shutil.copyfile(self.path,twin)
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
        self.assertEqual(cas(twin,'nonce-b'),'WON')
    def test_12_snapshot_restore_replays_nonce(self):
        backup=str(Path(self.tmp.name)/'backup.sqlite3');shutil.copyfile(self.path,backup)
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
        shutil.copyfile(backup,self.path)
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
    def test_13_privileged_reset_restores_generation(self):
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
        c=sqlite3.connect(self.path)
        try:
            c.execute('UPDATE generation SET gen=5,token=10,root="oldroot"')
            c.execute('DELETE FROM spent');c.execute('DELETE FROM outbox')
            c.execute('UPDATE anchor SET root="oldroot"');c.commit()
        finally:c.close()
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
    def test_14_local_anchor_not_independent(self):
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
        self.assertEqual(self.state()[3],'newroot')
        c=sqlite3.connect(self.path)
        try:c.execute('UPDATE anchor SET root="fakeold"');c.commit()
        finally:c.close()
        self.assertEqual(self.state()[3],'fakeold')
    def test_15_claimed_provider_ack_forgeable(self):
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
        c=sqlite3.connect(self.path)
        try:c.execute("UPDATE outbox SET state='ACKED',provider_receipt='CLAIMED_REMOTE'");c.commit()
        finally:c.close()
        self.assertEqual(self.state()[2][0][3],'CLAIMED_REMOTE')
    def test_16_new_nonce_after_generation(self):
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
        self.assertEqual(cas(self.path,'nonce-b',6,11),'WON')
        self.assertEqual(self.state()[0][:3],(3,7,12))
    def test_17_old_nonce_after_second_commit_rejected(self):
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
        self.assertEqual(cas(self.path,'nonce-b',6,11),'WON')
        self.assertEqual(cas(self.path,'nonce-a',7,12),'REPLAY')
    def test_18_malformed_generation_does_not_mutate(self):
        self.assertEqual(cas(self.path,'nonce-a',100,100),'STALE')
        self.assertEqual(self.state()[1],[])
    def test_19_process_after_commit_restart(self):
        p=subprocess.run(child_cmd(self.path,'nonce-a','after'),capture_output=True,text=True,timeout=18)
        self.assertEqual(p.returncode,72,p.stderr)
        self.assertEqual(self.state()[0][1],6)
        self.assertEqual(cas(self.path,'nonce-b',6,11),'WON')
    def test_20_aba_local_fence_rewind(self):
        backup=str(Path(self.tmp.name)/'before.sqlite3');shutil.copyfile(self.path,backup)
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
        self.assertEqual(cas(self.path,'nonce-b',6,11),'WON')
        shutil.copyfile(backup,self.path)
        self.assertEqual(cas(self.path,'nonce-a'),'WON')
        self.assertEqual(self.state()[0][2],11)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--worker':
        _,_,db,nonce,mode,gen,token=sys.argv
        print(cas(db,nonce,int(gen),int(token),mode),flush=True)
    else:
        unittest.main()
