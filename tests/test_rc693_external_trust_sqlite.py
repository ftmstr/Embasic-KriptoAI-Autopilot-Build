"""RC693: 8 external-evidence contracts, claimed Merkle/gossip and real local SQLite.

No real Ed25519 authority, provider-issued signature, outside storage, remote
CAS quorum, exchange order or remote ACK. All SQL is a disposable TEST fixture.
"""
import ast
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

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))
from safe_public_ci import ci_external_trust_contract as gate


def H(text):
    return hashlib.sha256(str(text).encode('ascii')).hexdigest()


def claim(epoch=7,seed='base'):
    sha='a'*40
    leaves=[H('%s-leaf-%d'%(seed,i)) for i in range(9)]
    gates=[r['kind'] for r in gate.contract_matrix()]
    cs=[]
    for i,k in enumerate(gates):
        cs.append({'kind':k,'controller':'operator_%d'%i,'control_domain':'domain_%d'%i,
            'source_sha':sha,'full_log_digest':H('log-%s-%s'%(k,seed)),
            'receipt_sha':H('receipt-%s-%s'%(k,seed)),
            'signature_hex':H('sig-%s'%k)*2,'issued_at':100,'expires_at':900,
            'run_id':100+i,'job_id':200+i,'attempt':1,'revoked_at':None,'claimed_external':False})
    dirs=[c['control_domain'] for c in cs[:3]]
    root=gate._merkle(leaves).hex()
    gossip=[{'from_domain':a,'to_domain':b,'epoch':epoch,'root':root,
             'receipt_sha':H('gossip-%s-%s-%s'%(seed,a,b))}
            for a in dirs for b in dirs if a!=b]
    return {'repository':'ftmstr/Embasic-KriptoAI-Autopilot-Build',
            'branch':'validation/rc654-pr1-rc653-combined-ci',
            'source_sha':sha,'epoch':epoch,
            'history':{'leaves':leaves,'previous_size':4,'previous_root':gate._merkle(leaves[:4]).hex(),
                       'current_root':root,'included_index':6,'inclusion_path':gate.inclusion_path(leaves,6)},
            'claims':cs,'gossip':gossip,
            'journal':{'old_generation':2,'new_generation':3,'old_fence':9,'new_fence':10,
                       'nonce_sha':H('nonce'),'pending_outbox_sha':H('outbox'),
                       'claimed_ack':None,'remote_ack_verified':False,'external_cas_verified':False,
                       'immutable_checkpoint_verified':False},
            'release':{k:False for k in ('authenticated','live','final','fitted','net20_tested')}}


class ExternalContractTests(unittest.TestCase):
    def test_required_eight_gates_exist_and_are_blocked(self):
        m=gate.contract_matrix()
        self.assertEqual(len(m),8)
        self.assertEqual(len({x['kind'] for x in m}),8)
        self.assertTrue(all(x['gate']=='BLOCKED' and x['source']=='NOT_ACQUIRED' and not x['externally_verified'] for x in m))
    def test_clear_unobtained_trust_boundaries(self):
        text=' '.join(x['required_external_evidence'] for x in gate.contract_matrix()).lower()
        for value in ('ed25519','reviewer','full log','revocation','checkpoint','rollback','ack','clock'):
            self.assertIn(value,text)
    def test_claim_is_not_authenticated_even_if_structurally_consistent(self):
        r=gate.audit(claim())
        self.assertEqual(r['status'],'CLAIM_ONLY_QUARANTINED')
        self.assertEqual((r['required_external_gates'],r['independently_verified_gates']),(8,0))
        self.assertFalse(any(v is True for v in r.values()))
    def test_caller_generated_signature_bytes_do_not_authenticate(self):
        p=claim();p['claims'][0]['signature_hex']='f'*128
        self.assertFalse(gate.audit(p)['ed25519_origin_verified'])
    def test_caller_generated_all_distinct_domains_do_not_authenticate(self):
        self.assertFalse(gate.audit(claim())['authenticated'])
    def test_same_view_is_not_external_proof(self):
        self.assertEqual(gate.compare_claims(claim(),claim()),'CLAIMED_VIEWS_EQUAL_BUT_UNAUTHENTICATED')
    def test_claim_source_fork(self):
        other=claim();other['source_sha']='b'*40
        for c in other['claims']:c['source_sha']='b'*40
        self.assertEqual(gate.compare_claims(claim(),other),'CLAIMED_SOURCE_FORK_NO_AUTH')
    def test_epoch_without_independent_clock(self):
        other=claim(epoch=8)
        self.assertEqual(gate.compare_claims(claim(),other),'CLAIMED_EPOCH_GAP_NO_EXTERNAL_CLOCK')
    def test_same_epoch_different_valid_merkle_roots(self):
        self.assertEqual(gate.compare_claims(claim(),claim(seed='other')),'CLAIMED_MERKLE_SPLIT_VIEW_NO_AUTH')
    def test_provider_log_fork_not_provider_signature(self):
        other=claim();other['claims'][3]['full_log_digest']=H('another-log')
        self.assertEqual(gate.compare_claims(claim(),other),'CLAIMED_PROVIDER_OR_KEY_RECEIPT_FORK_NO_AUTH')
    def test_gossip_equivocation_without_independent_witnesses(self):
        other=claim();other['gossip'][0]['receipt_sha']=H('changed-message')
        self.assertEqual(gate.compare_claims(claim(),other),'CLAIMED_GOSSIP_EQUIVOCATION_NO_AUTH')
    def test_nonce_reuse_with_different_local_generation(self):
        other=claim();other['journal']['old_generation']=3;other['journal']['new_generation']=4
        self.assertEqual(gate.compare_claims(claim(),other),'CLAIMED_NONCE_ABA_NO_EXTERNAL_FENCE')
    def test_generation_gap_with_distinct_nonce(self):
        other=claim();other['journal']['old_generation']=3;other['journal']['new_generation']=4;other['journal']['nonce_sha']=H('new-nonce')
        self.assertEqual(gate.compare_claims(claim(),other),'CLAIMED_GENERATION_GAP_NO_EXTERNAL_FENCE')
    def test_digest_changes_with_claim_receipt(self):
        a=gate.audit(claim())['claimed_digest'];other=claim();other['claims'][0]['receipt_sha']=H('different')
        self.assertNotEqual(a,gate.audit(other)['claimed_digest'])
    def test_digest_is_stable_for_identical_claims(self):
        self.assertEqual(gate.audit(claim())['claimed_digest'],gate.audit(copy.deepcopy(claim()))['claimed_digest'])
    def test_bounded_merkle_math_is_not_append_only_publication(self):
        for n in (2,3,7,8,9,15,16,31,32,63,64,127,128):
            leaves=[H('m%d_%d'%(n,i)) for i in range(n)]
            for ix in (0,n//2,n-1):
                path=gate.inclusion_path(leaves,ix)
                self.assertLessEqual(len(path),8)
                self.assertTrue(all(len(z)==64 for z in path))
        self.assertFalse(gate.audit(claim())['merkle_authority_verified'])
    def test_source_imports_and_dynamic_gate(self):
        src=(ROOT/'safe_public_ci'/'ci_external_trust_contract.py').read_text(encoding='utf-8')
        tree=ast.parse(src)
        imports=[alias.name for n in ast.walk(tree) if isinstance(n,ast.Import) for alias in n.names]
        self.assertEqual(sorted(imports),['hashlib','hmac','re'])
        self.assertFalse(any(isinstance(n,ast.ImportFrom) for n in ast.walk(tree)))
        self.assertFalse([n.func.id for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in ('open','eval','exec','compile','__import__')])


def put(path,value):
    def change(d):
        cur=d
        for part in path[:-1]:cur=cur[part]
        cur[path[-1]]=value
    return change


_MUTATIONS=[
 ('source_bad_sha',put(('source_sha',),'x'*40)),
 ('branch_change',put(('branch',),'main')),
 ('repo_change',put(('repository',),'random/private')),
 ('true_epoch_bool',put(('epoch',),True)),
 ('zero_epoch',put(('epoch',),0)),
 ('invalid_history_field',put(('history','extra'),1)),
 ('false_old_root',put(('history','previous_root'),H('fabricated'))),
 ('false_new_root',put(('history','current_root'),H('fabricated'))),
 ('invalid_inclusion_proof',put(('history','inclusion_path'),[H('fake')])),
 ('old_size_equal_new',put(('history','previous_size'),9)),
 ('old_size_zero',put(('history','previous_size'),0)),
 ('included_index_bool',put(('history','included_index'),True)),
 ('included_index_outside',put(('history','included_index'),9)),
 ('claims_extra',put(('claims',0,'extra'),1)),
 ('claims_missing',lambda d:d['claims'].pop()),
 ('duplicate_kind',put(('claims',1,'kind'),'owner_oob_key')),
 ('fake_kind',put(('claims',1,'kind'),'not-a-gate')),
 ('self_review_operator',put(('claims',1,'controller'),'operator_0')),
 ('shared_operator_domain',put(('claims',1,'control_domain'),'domain_0')),
 ('domain_same_actor',put(('claims',2,'control_domain'),'operator_0')),
 ('controller_invalid_name',put(('claims',2,'controller'),'Not An Operator')),
 ('provider_sha_mismatch',put(('claims',3,'source_sha'),'b'*40)),
 ('provider_log_short',put(('claims',3,'full_log_digest'),'abc')),
 ('fake_signed_signature',put(('claims',0,'signature_hex'),H('short'))),
 ('self_promoted_origin',put(('claims',0,'claimed_external'),True)),
 ('claim_external_bool_as_integer',put(('claims',0,'claimed_external'),1)),
 ('replayed_receipt',put(('claims',2,'receipt_sha'),H('receipt-owner_oob_key-base'))),
 ('exp_before_issue',put(('claims',2,'expires_at'),99)),
 ('issue_bool',put(('claims',2,'issued_at'),True)),
 ('issue_zero',put(('claims',2,'issued_at'),0)),
 ('revocation_before_issue',put(('claims',2,'revoked_at'),99)),
 ('run_zero',put(('claims',2,'run_id'),0)),
 ('job_as_bool',put(('claims',2,'job_id'),True)),
 ('attempt_as_bool',put(('claims',2,'attempt'),True)),
 ('gossip_missing',lambda d:d['gossip'].pop()),
 ('gossip_duplicate',lambda d:d['gossip'].__setitem__(1,copy.deepcopy(d['gossip'][0]))),
 ('gossip_wrong_root',put(('gossip',0,'root'),H('alien'))),
 ('gossip_epoch_bool',put(('gossip',0,'epoch'),True)),
 ('gossip_wrong_epoch',put(('gossip',0,'epoch'),9)),
 ('gossip_bad_receipt',put(('gossip',0,'receipt_sha'),'a')),
 ('gossip_loop',put(('gossip',0,'to_domain'),'domain_0')),
 ('gossip_wrong_to',put(('gossip',0,'to_domain'),'domain_7')),
 ('gossip_unexpected_key',put(('gossip',0,'verified'),True)),
 ('generation_bool',put(('journal','old_generation'),True)),
 ('generation_aba',put(('journal','new_generation'),2)),
 ('fence_stale',put(('journal','new_fence'),9)),
 ('fence_bool',put(('journal','old_fence'),True)),
 ('nonce_bad',put(('journal','nonce_sha'),'f')),
 ('outbox_bad',put(('journal','pending_outbox_sha'),'1')),
 ('forged_ack',put(('journal','claimed_ack'),H('ack'))),
 ('fake_remote_ack',put(('journal','remote_ack_verified'),True)),
 ('fake_durable_cas',put(('journal','external_cas_verified'),True)),
 ('fake_immutable_root',put(('journal','immutable_checkpoint_verified'),True)),
 ('release_auth',put(('release','authenticated'),True)),
 ('release_live',put(('release','live'),True)),
 ('release_final',put(('release','final'),True)),
 ('release_fit',put(('release','fitted'),True)),
 ('release_profit',put(('release','net20_tested'),True)),
 ('release_additional',put(('release','go'),True)),
]
for _name,_fn in _MUTATIONS:
    def _test(self,fn=_fn):
        d=claim();fn(d)
        with self.assertRaises(gate.ContractRejected):gate.audit(d)
    setattr(ExternalContractTests,'test_reject_'+_name,_test)


# The following SQL is an actual disposable SQLite fixture, not imported by
# the production/source gate or connected to any trading application.
_SCHEMA='''
PRAGMA journal_mode=DELETE;
PRAGMA synchronous=FULL;
CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1),generation INTEGER NOT NULL, fence INTEGER NOT NULL, root TEXT NOT NULL);
CREATE TABLE nonce (value TEXT PRIMARY KEY);
CREATE TABLE outbox (nonce TEXT PRIMARY KEY, status TEXT NOT NULL, receipt TEXT);
INSERT INTO state VALUES(1,0,0,'genesis');
'''


def _perform(path,expect_gen,expect_fence,nonce,newroot,mode='normal'):
    db=sqlite3.connect(str(path),timeout=8.0,isolation_level=None)
    try:
        db.execute('PRAGMA busy_timeout=8000')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT generation,fence FROM state WHERE id=1').fetchone()
        if row!=(expect_gen,expect_fence):db.execute('ROLLBACK');return 'STALE'
        if db.execute('SELECT 1 FROM nonce WHERE value=?',(nonce,)).fetchone():db.execute('ROLLBACK');return 'REPLAY'
        db.execute('INSERT INTO nonce VALUES(?)',(nonce,))
        db.execute('UPDATE state SET generation=?,fence=?,root=? WHERE id=1',
                   (expect_gen+1,expect_fence+1,newroot))
        db.execute("INSERT INTO outbox VALUES(?, 'PENDING', NULL)",(nonce,))
        if mode=='before':os._exit(71)
        db.execute('COMMIT')
        if mode=='after':os._exit(72)
        return 'COMMITTED'
    finally:db.close()


_CHILD='''import os,sqlite3,sys
p,eg,ef,nonce,root,mode=sys.argv[1:]
db=sqlite3.connect(p,timeout=8.0,isolation_level=None)
db.execute('PRAGMA busy_timeout=8000');db.execute('PRAGMA synchronous=FULL');db.execute('BEGIN IMMEDIATE')
row=db.execute('SELECT generation,fence FROM state WHERE id=1').fetchone()
if row!=(int(eg),int(ef)):db.execute('ROLLBACK');print('STALE',flush=True);sys.exit(0)
if db.execute('SELECT 1 FROM nonce WHERE value=?',(nonce,)).fetchone():db.execute('ROLLBACK');print('REPLAY',flush=True);sys.exit(0)
db.execute('INSERT INTO nonce VALUES(?)',(nonce,))
db.execute('UPDATE state SET generation=?,fence=?,root=? WHERE id=1',(int(eg)+1,int(ef)+1,root))
db.execute("INSERT INTO outbox VALUES(?, 'PENDING', NULL)",(nonce,))
if mode=='before':os._exit(71)
db.execute('COMMIT')
if mode=='after':os._exit(72)
print('COMMITTED',flush=True)
'''


class SQLiteGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='rc693_')
        self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'local.db'
        c=sqlite3.connect(self.db)
        c.executescript(_SCHEMA);c.close()
    def state(self,path=None):
        c=sqlite3.connect(path or self.db)
        try:return (c.execute('SELECT generation,fence,root FROM state').fetchone(),
                    c.execute('SELECT value FROM nonce ORDER BY value').fetchall(),
                    c.execute('SELECT nonce,status,receipt FROM outbox ORDER BY nonce').fetchall())
        finally:c.close()
    def child(self,path=None,gen=0,fence=0,nonce='nonce_a',root='root_a',mode='normal'):
        return subprocess.run([sys.executable,'-c',_CHILD,str(path or self.db),str(gen),str(fence),nonce,root,mode],capture_output=True,text=True,timeout=18)
    def test_01_starts_with_empty_outbox(self):
        self.assertEqual(self.state(),((0,0,'genesis'),[],[]))
    def test_02_single_local_commit_is_atomic(self):
        self.assertEqual(_perform(self.db,0,0,'a','root_1'),'COMMITTED')
        self.assertEqual(self.state(),((1,1,'root_1'),[('a',)],[('a','PENDING',None)]))
    def test_03_replayed_nonce_is_rejected(self):
        self.assertEqual(_perform(self.db,0,0,'a','root_1'),'COMMITTED')
        self.assertEqual(_perform(self.db,1,1,'a','root_2'),'REPLAY')
    def test_04_stale_generation_rejected(self):
        self.assertEqual(_perform(self.db,0,0,'a','root_1'),'COMMITTED')
        self.assertEqual(_perform(self.db,0,1,'b','root_2'),'STALE')
    def test_05_stale_fence_rejected(self):
        self.assertEqual(_perform(self.db,0,0,'a','root_1'),'COMMITTED')
        self.assertEqual(_perform(self.db,1,0,'b','root_2'),'STALE')
    def test_06_before_commit_hard_crash_rolls_back(self):
        r=self.child(mode='before');self.assertEqual(r.returncode,71,r.stderr)
        self.assertEqual(self.state(),((0,0,'genesis'),[],[]))
    def test_07_after_commit_hard_crash_preserves_pending(self):
        r=self.child(mode='after');self.assertEqual(r.returncode,72,r.stderr)
        self.assertEqual(self.state()[0],(1,1,'root_a'))
        self.assertEqual(self.state()[2],[('nonce_a','PENDING',None)])
    def test_08_after_commit_lost_ack_no_replay(self):
        self.assertEqual(self.child(mode='after').returncode,72)
        self.assertEqual(self.child(gen=1,fence=1).stdout.strip(),'REPLAY')
    def test_09_two_real_processes_one_local_winner(self):
        args=[sys.executable,'-c',_CHILD,str(self.db),'0','0','a','root_a','normal']
        x=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        y=subprocess.Popen(args[:-3]+['b','root_b','normal'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        out1,err1=x.communicate(timeout=18);out2,err2=y.communicate(timeout=18)
        self.assertEqual((x.returncode,y.returncode),(0,0),err1+err2)
        self.assertEqual(sorted((out1.strip(),out2.strip())),['COMMITTED','STALE'])
        self.assertEqual(len(self.state()[1]),1)
    def test_10_three_real_threads_one_local_winner(self):
        out=[]
        def work(i):out.append(_perform(self.db,0,0,'thread_'+str(i),'root_'+str(i)))
        th=[threading.Thread(target=work,args=(i,)) for i in range(3)]
        for t in th:t.start()
        for t in th:t.join(timeout=10);self.assertFalse(t.is_alive())
        self.assertEqual(out.count('COMMITTED'),1);self.assertEqual(out.count('STALE'),2)
    def test_11_two_disconnected_hosts_both_win(self):
        other=Path(self.tmp.name)/'clone.db';shutil.copyfile(self.db,other)
        self.assertEqual(_perform(self.db,0,0,'a','root_a'),'COMMITTED')
        self.assertEqual(_perform(other,0,0,'b','root_b'),'COMMITTED')
        self.assertNotEqual(self.state()[0][2],self.state(other)[0][2])
    def test_12_snapshot_restore_reuses_spent_nonce(self):
        backup=Path(self.tmp.name)/'backup.db';shutil.copyfile(self.db,backup)
        self.assertEqual(_perform(self.db,0,0,'a','root_a'),'COMMITTED')
        shutil.copyfile(backup,self.db)
        self.assertEqual(_perform(self.db,0,0,'a','root_b'),'COMMITTED')
    def test_13_privileged_rollback_defeats_local_anchor(self):
        _perform(self.db,0,0,'a','root_a')
        c=sqlite3.connect(self.db)
        c.execute("UPDATE state SET generation=0,fence=0,root='genesis'")
        c.execute('DELETE FROM nonce');c.execute('DELETE FROM outbox');c.commit();c.close()
        self.assertEqual(_perform(self.db,0,0,'a','root_b'),'COMMITTED')
    def test_14_local_ack_without_provider_receipt_is_forgeable(self):
        _perform(self.db,0,0,'a','root_a')
        c=sqlite3.connect(self.db);c.execute("UPDATE outbox SET status='ACKED',receipt='CLAIMED_REMOTE' WHERE nonce='a'");c.commit();c.close()
        self.assertEqual(self.state()[2],[('a','ACKED','CLAIMED_REMOTE')])
        self.assertFalse(gate.audit(claim())['provider_ack_verified'])
    def test_15_two_monotone_local_transactions_not_external_cas(self):
        self.assertEqual(_perform(self.db,0,0,'a','root_a'),'COMMITTED')
        self.assertEqual(_perform(self.db,1,1,'b','root_b'),'COMMITTED')
        self.assertEqual(self.state()[0],(2,2,'root_b'))
        self.assertFalse(gate.audit(claim())['durable_multihost_cas_verified'])
    def test_16_second_commit_restore_aba(self):
        backup=Path(self.tmp.name)/'backup.db';shutil.copyfile(self.db,backup)
        _perform(self.db,0,0,'a','root_a');_perform(self.db,1,1,'b','root_b')
        shutil.copyfile(backup,self.db)
        self.assertEqual(_perform(self.db,0,0,'a','root_replay'),'COMMITTED')
    def test_17_crash_after_commit_restart_detects_pending(self):
        self.assertEqual(self.child(mode='after').returncode,72)
        self.assertEqual(self.child(gen=1,fence=1,nonce='next',root='root_b').stdout.strip(),'COMMITTED')
        self.assertEqual(len(self.state()[2]),2)
    def test_18_invalid_expectation_no_write(self):
        self.assertEqual(_perform(self.db,-1,-1,'a','root_a'),'STALE')
        self.assertEqual(self.state(),((0,0,'genesis'),[],[]))
    def test_19_different_nonce_after_stale_does_not_register(self):
        self.assertEqual(_perform(self.db,9,9,'unused','root_a'),'STALE')
        self.assertNotIn(('unused',),self.state()[1])
    def test_20_pending_is_not_signed_remote_seen(self):
        self.assertEqual(self.child(mode='after').returncode,72)
        self.assertEqual(self.state()[2][0][1],'PENDING')
        for item in gate.contract_matrix():self.assertFalse(item['externally_verified'])


if __name__=='__main__':
    unittest.main()
