"""RC694: externally UNVERIFIED evidence-intake challenge and test-only SQLite.

No private keys, real signatures/provider logs, trades or production CAS used.
The local challenge store can be rolled back and is not multi-host durable.
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
    sys.path.insert(0, str(ROOT))
from safe_public_ci import ci_provenance_challenge_quarantine as gate


def H(value):
    return hashlib.sha256(str(value).encode('ascii')).hexdigest()


def packet(seed='valid', epoch=150):
    sha='a'*40
    challenge=H('fresh-but-caller-supplied-'+seed)
    receipts=[]
    for i, item in enumerate(gate.admission_dependencies()):
        kind=item['gate']
        provider=kind.startswith('provider_')
        receipt={
            'gate':kind,'controller':'operator_%d'%i,'domain':'domain_%d'%i,
            'source_sha':sha,'artifact_sha':H('artifact-%s-%d'%(seed,i)),
            'log_sha':H('full-log-%s-%d'%(seed,i)),
            'workflow_sha':H('workflow-%s-%d'%(seed,i)),
            'challenge_sha':challenge,'signature_hex':H('untrusted-sig-%d'%i)*2,
            'signed_transcript_sha':'0'*64,
            'run':(436180001+i) if provider else 0,
            'job':(132510001+i) if provider else 0,
            'attempt':1,'issued_at':100,'expires_at':300,'revoked_at':None,
            'claimed_verified':False,'origin':'SELF_ASSERTED',
        }
        receipt['signed_transcript_sha']=gate.receipt_transcript(gate.REPOSITORY,gate.BRANCH,epoch,receipt)
        receipts.append(receipt)
    return {'repository':gate.REPOSITORY,'branch':gate.BRANCH,'source_sha':sha,
            'epoch':epoch,'challenge_sha':challenge,'phase':'COLLECT_ONLY',
            'receipts':receipts,
            'checkpoint':{'previous_root':H('old-root-'+seed),
                          'current_root':H('new-root-'+seed),
                          'consistency_path':[H('proof-0'),H('proof-1')],
                          'independently_anchored':False},
            'journal':{'generation':3,'next_generation':4,'fence':5,
                       'next_fence':6,'nonce_sha':H('nonce-'+seed),
                       'pending_outbox_sha':H('outbox-'+seed),
                       'ack_sha':None,'external_cas_verified':False,
                       'remote_ack_verified':False},
            'release':{'authenticated':False,'live':False,'final':False,
                       'single_fit_used':False,'net20_tested':False}}


def rebind(p):
    for r in p['receipts']:
        r['signed_transcript_sha']=gate.receipt_transcript(p['repository'],p['branch'],p['epoch'],r)
    return p


class ContractCases(unittest.TestCase):
    def test_8_evidence_acquisition_gates_still_blocked(self):
        plan=gate.admission_dependencies()
        self.assertEqual(len(plan),8)
        self.assertEqual(len({x['gate'] for x in plan}),8)
        self.assertTrue(all(x['status']=='BLOCKED' and not x['verified'] and x['claim_only'] for x in plan))
        self.assertTrue(all(x['needs_real_external'] for x in plan))
    def test_acyclic_explicit_dependency_plan(self):
        seen=set()
        for row in gate.admission_dependencies():
            self.assertTrue(set(row['prerequisites'])<=seen)
            seen.add(row['gate'])
    def test_external_proof_requirements_not_claimed_implemented(self):
        req=' '.join(x['needs_real_external'] for x in gate.admission_dependencies()).lower()
        for word in ('ed25519','owner','reviewer','ubuntu','windows','log','revocation',
                     'timestamp','merkle','cas','rollback','ack'):
            self.assertIn(word,req)
    def test_valid_synthetic_transcript_never_authenticates(self):
        out=gate.inspect(packet())
        self.assertEqual(out['status'],'CLAIMED_INTAKE_ONLY_NOT_AUTHENTICATED')
        self.assertEqual(len(out['blocked_external_gates']),8)
        self.assertEqual(out['verified_external_gates'],0)
        self.assertFalse(any(v is True for v in out.values()))
    def test_same_data_same_claim_digest(self):
        self.assertEqual(gate.inspect(packet())['claim_digest'],gate.inspect(copy.deepcopy(packet()))['claim_digest'])
    def test_challenge_change_changes_digest(self):
        a=packet();b=packet(seed='different')
        self.assertNotEqual(gate.inspect(a)['claim_digest'],gate.inspect(b)['claim_digest'])
    def test_claimed_signature_hex_is_not_verification(self):
        p=packet();p['receipts'][0]['signature_hex']='f'*128
        self.assertFalse(gate.inspect(p)['independent_owner_reviewer_verified'])
    def test_claimed_external_key_rejection(self):
        p=packet();p['receipts'][0]['claimed_verified']=True
        with self.assertRaisesRegex(gate.IntakeRejected,'no_external_verification'):
            gate.inspect(p)
    def test_fake_provider_signed_label_rejection(self):
        p=packet();p['receipts'][3]['origin']='GITHUB_SIGNED'
        with self.assertRaisesRegex(gate.IntakeRejected,'no_forged_origin'):
            gate.inspect(p)
    def test_expired_claimed_clock_not_trusted(self):
        p=packet();p['epoch']=301
        with self.assertRaises(gate.IntakeRejected):gate.inspect(p)
    def test_revocation_is_a_claim_not_trusted_rejection(self):
        p=packet();p['receipts'][1]['revoked_at']=120
        rebind(p)
        out=gate.inspect(p)
        self.assertEqual(out['claimed_revocations'],('reviewer_oob_key',))
        self.assertFalse(out['trusted_clock_and_revocation_verified'])
    def test_missing_signed_provider_history_rejects_full_log_suggestion(self):
        p=packet();p['receipts'][2]['run']=0
        with self.assertRaisesRegex(gate.IntakeRejected,'provider_binding'):
            gate.inspect(p)
    def test_source_fork_no_authentication(self):
        p=packet();q=copy.deepcopy(p);q['source_sha']='b'*40
        for r in q['receipts']:r['source_sha']='b'*40
        rebind(q)
        self.assertEqual(gate.compare_intakes(p,q),'CLAIMED_SOURCE_FORK_NO_EXTERNAL_AUTH')
    def test_challenge_fork_no_independent_issuer(self):
        p=packet();q=copy.deepcopy(p);q['challenge_sha']=H('another-challenge')
        for r in q['receipts']:r['challenge_sha']=q['challenge_sha']
        rebind(q)
        self.assertEqual(gate.compare_intakes(p,q),'CLAIMED_CHALLENGE_FORK_NO_EXTERNAL_AUTH')
    def test_epoch_fork_no_trusted_time(self):
        p=packet();q=copy.deepcopy(p);q['epoch']=151;rebind(q)
        self.assertEqual(gate.compare_intakes(p,q),'CLAIMED_EPOCH_FORK_NO_EXTERNAL_AUTH')
    def test_checkpoint_split_view_no_independent_anchor(self):
        p=packet();q=copy.deepcopy(p);q['checkpoint']['current_root']=H('other-root')
        self.assertEqual(gate.compare_intakes(p,q),'CLAIMED_CHECKPOINT_FORK_NO_EXTERNAL_ANCHOR')
    def test_receipt_split_view_no_signed_provider_evidence(self):
        p=packet();q=copy.deepcopy(p);q['receipts'][3]['artifact_sha']=H('other-artifact');rebind(q)
        self.assertEqual(gate.compare_intakes(p,q),'CLAIMED_RECEIPT_FORK_NO_PROVIDER_SIGNED_PROOF')
    def test_same_nonce_aba_fork_no_external_cas(self):
        p=packet();q=copy.deepcopy(p);q['journal']['generation']=4;q['journal']['next_generation']=5
        self.assertEqual(gate.compare_intakes(p,q),'CLAIMED_NONCE_ABA_FORK_NO_DURABLE_CAS')
    def test_different_nonce_fork_not_durable_cas(self):
        p=packet();q=copy.deepcopy(p);q['journal']['nonce_sha']=H('another')
        self.assertEqual(gate.compare_intakes(p,q),'CLAIMED_LOCAL_CAS_FORK_NO_EXTERNAL_FENCE')
    def test_equal_views_remain_unverified(self):
        self.assertEqual(gate.compare_intakes(packet(),packet()),'CLAIMED_EQUAL_UNAUTHENTICATED')
    def test_bound_transcript_ambiguous_concat_not_equal(self):
        self.assertNotEqual(gate._transcript(('ab','c')),gate._transcript(('a','bc')))
    def test_type_confusion_not_equal(self):
        self.assertNotEqual(gate._transcript((123,)),gate._transcript(('123',)))
    def test_none_distinct_from_text_none(self):
        self.assertNotEqual(gate._transcript((None,)),gate._transcript(('None',)))
    def test_raw_proof_path_length_rejection(self):
        p=packet();p['checkpoint']['consistency_path']=[H(x) for x in range(17)]
        with self.assertRaisesRegex(gate.IntakeRejected,'checkpoint_path'):gate.inspect(p)
    def test_weak_malformed_signature_reject(self):
        p=packet();p['receipts'][0]['signature_hex']='0'*64
        with self.assertRaisesRegex(gate.IntakeRejected,'claimed_signature_format'):gate.inspect(p)
    def test_true_is_not_integer_epoch(self):
        p=packet();p['epoch']=True
        with self.assertRaisesRegex(gate.IntakeRejected,'epoch'):gate.inspect(p)
    def test_root_and_release_bools_fail_closed(self):
        for key in ('authenticated','live','final','single_fit_used','net20_tested'):
            p=packet();p['release'][key]=True
            with self.assertRaisesRegex(gate.IntakeRejected,'release_locked'):gate.inspect(p)
    def test_no_network_or_io_imports_in_module(self):
        tree=ast.parse((ROOT/'safe_public_ci'/'ci_provenance_challenge_quarantine.py').read_text(encoding='utf-8'))
        imported=set()
        for x in ast.walk(tree):
            if isinstance(x,ast.Import):imported.update(a.name for a in x.names)
            if isinstance(x,ast.ImportFrom):imported.add(x.module)
            if isinstance(x,ast.Call) and isinstance(x.func,ast.Name):
                self.assertNotIn(x.func.id,('open','eval','exec','compile','__import__'))
        self.assertEqual(imported,{'hashlib','hmac','re'})


# For each of EIGHT gates, mutate TEN independent surfaces and assert a
# fail-closed rejection category. These are distinct per-gate bindings.
def mutate_source(p,i):p['receipts'][i]['source_sha']='b'*40
def mutate_challenge(p,i):p['receipts'][i]['challenge_sha']=H('old-replayed-challenge')
def mutate_artifact(p,i):p['receipts'][i]['artifact_sha']=p['receipts'][(i+1)%8]['artifact_sha']
def mutate_controller(p,i):p['receipts'][i]['controller']=p['receipts'][(i+1)%8]['controller']
def mutate_domain(p,i):p['receipts'][i]['domain']=p['receipts'][(i+1)%8]['domain']
def mutate_signature(p,i):p['receipts'][i]['signature_hex']='not-a-signature'
def mutate_verified(p,i):p['receipts'][i]['claimed_verified']=True
def mutate_origin(p,i):p['receipts'][i]['origin']='SIGNED_PROVIDER'
def mutate_provider(p,i):
    provider=p['receipts'][i]['gate'].startswith('provider_')
    p['receipts'][i]['run']=0 if provider else 21
    p['receipts'][i]['job']=0 if provider else 42
def mutate_clock(p,i):p['receipts'][i]['expires_at']=99

_MUTATIONS=(('wrong_source',mutate_source,'source_binding'),
            ('replayed_challenge',mutate_challenge,'challenge_binding'),
            ('duplicate_artifact',mutate_artifact,'artifact_duplicate'),
            ('duplicate_controller',mutate_controller,'controller_duplicate'),
            ('sybil_domain',mutate_domain,'domain_duplicate'),
            ('invalid_signature',mutate_signature,'claimed_signature_format'),
            ('self_verified',mutate_verified,'no_external_verification'),
            ('forged_origin',mutate_origin,'no_forged_origin'),
            ('cross_provider_binding',mutate_provider,'provider_binding'),
            ('expired_clock',mutate_clock,'untrusted_claim_clock'))

class AllEightGateMutations(unittest.TestCase):pass

for _i in range(8):
    for _tag,_mutation,_expected in _MUTATIONS:
        def _test(self, i=_i,mut=_mutation,reason=_expected):
            p=packet();mut(p,i)
            # Keep the digest equation valid so the named failure is actually
            # exercised instead of being masked by an unrelated hash mismatch.
            rebind(p)
            with self.assertRaisesRegex(gate.IntakeRejected,reason):gate.inspect(p)
        _test.__name__='test_gate_%02d_%s'%(_i,_tag)
        setattr(AllEightGateMutations,_test.__name__,_test)


# Test-only local SQL is an illustration of an insufficient trust domain.
# It is intentionally NEVER imported by the safe_public_ci source module.
DDL = '''CREATE TABLE challenge (id TEXT PRIMARY KEY, state TEXT NOT NULL,
          generation INTEGER NOT NULL, fence INTEGER NOT NULL);
         CREATE TABLE pending (id TEXT PRIMARY KEY, receipt TEXT UNIQUE NOT NULL,
          status TEXT NOT NULL);'''

def setup_db(path, cid='challenge-1'):
    con = sqlite3.connect(path)
    try:
        con.execute('PRAGMA journal_mode=DELETE')
        con.execute('PRAGMA synchronous=FULL')
        con.executescript(DDL)
        con.execute('INSERT INTO challenge VALUES(?,?,?,?)',(cid,'UNUSED',1,5))
        con.commit()
    finally:
        con.close()

def consume(db,cid,gen,fence,receipt,mode='normal'):
    con=sqlite3.connect(db,timeout=30,isolation_level=None)
    try:
        con.execute('PRAGMA busy_timeout=30000')
        con.execute('PRAGMA synchronous=FULL')
        con.execute('BEGIN IMMEDIATE')
        row=con.execute('SELECT state,generation,fence FROM challenge WHERE id=?',(cid,)).fetchone()
        if row != ('UNUSED',gen,fence):
            con.execute('ROLLBACK')
            return 'STALE'
        updated=con.execute('UPDATE challenge SET state=?,generation=?,fence=? WHERE id=? AND state=? AND generation=? AND fence=?',
                            ('COMMITTED',gen+1,fence+1,cid,'UNUSED',gen,fence)).rowcount
        if updated != 1:
            con.execute('ROLLBACK');return 'STALE'
        con.execute('INSERT INTO pending VALUES(?,?,?)',(cid,receipt,'PENDING'))
        if mode=='before':os._exit(71)
        con.execute('COMMIT')
        if mode=='after':os._exit(72)
        return 'COMMITTED'
    finally:con.close()

class DisposableChallengeSqlite(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='rc694_challenge_')
        self.addCleanup(self.tmp.cleanup)
        self.db=os.path.join(self.tmp.name,'challenge.sqlite')
        setup_db(self.db)
    def run_child(self,mode='normal',receipt='outbox-1',db=None,env=None):
        e=os.environ.copy();e.pop('PYTHONPATH',None)
        if env is not None:e.update(env)
        return subprocess.run([sys.executable,str(Path(__file__).resolve()),'--rc694-child',
                               db or self.db,'challenge-1','1','5',receipt,mode],
                              cwd=self.tmp.name,env=e,capture_output=True,text=True,timeout=30)
    def rows(self,db=None):
        c = sqlite3.connect(db or self.db)
        try:
            return (c.execute('SELECT state,generation,fence FROM challenge').fetchone(),
                    c.execute('SELECT id,receipt,status FROM pending').fetchall())
        finally:
            c.close()
    def test_01_one_local_single_winner(self):
        self.assertEqual(consume(self.db,'challenge-1',1,5,'receipt-1'),'COMMITTED')
        self.assertEqual(self.rows()[0],('COMMITTED',2,6))
    def test_02_same_local_challenge_replay_rejected(self):
        self.assertEqual(consume(self.db,'challenge-1',1,5,'receipt-1'),'COMMITTED')
        self.assertEqual(consume(self.db,'challenge-1',1,5,'receipt-2'),'STALE')
    def test_03_stale_generation_denied(self):
        self.assertEqual(consume(self.db,'challenge-1',0,5,'receipt-1'),'STALE')
        self.assertEqual(self.rows()[1],[])
    def test_04_stale_fence_denied(self):
        self.assertEqual(consume(self.db,'challenge-1',1,4,'receipt-1'),'STALE')
    def test_05_mismatched_receipt_not_written(self):
        self.assertEqual(consume(self.db,'wrong',1,5,'receipt-1'),'STALE')
        self.assertEqual(self.rows()[1],[])
    def test_06_crash_before_commit_recovers_unspent(self):
        result=self.run_child('before')
        self.assertEqual((result.returncode,result.stdout),(71,''),result.stderr)
        self.assertEqual(self.rows(),(('UNUSED',1,5),[]))
    def test_07_crash_after_commit_persists_pending(self):
        result=self.run_child('after')
        self.assertEqual(result.returncode,72,result.stderr)
        self.assertEqual(self.rows(),(('COMMITTED',2,6),[('challenge-1','outbox-1','PENDING')]))
    def test_08_lost_ack_does_not_reuse_challenge(self):
        self.assertEqual(self.run_child('after').returncode,72)
        self.assertEqual(self.run_child('normal','second-try').stdout.strip(),'STALE')
        self.assertEqual(self.rows()[1][0][2],'PENDING')
    def test_09_subprocess_import_without_pythonpath(self):
        result=self.run_child()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'COMMITTED')
    def test_10_two_real_subprocesses_one_winner(self):
        e=os.environ.copy();e.pop('PYTHONPATH',None)
        base=[sys.executable,str(Path(__file__).resolve()),'--rc694-child',self.db,'challenge-1','1','5']
        a=subprocess.Popen(base+['a','normal'],cwd=self.tmp.name,env=e,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        b=subprocess.Popen(base+['b','normal'],cwd=self.tmp.name,env=e,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        ao,ae=a.communicate(timeout=30);bo,be=b.communicate(timeout=30)
        self.assertEqual((a.returncode,b.returncode),(0,0),ae+be)
        self.assertEqual(sorted((ao.strip(),bo.strip())),['COMMITTED','STALE'])
        self.assertEqual(len(self.rows()[1]),1)
    def test_11_three_threads_one_winner(self):
        out=[]
        def worker(i):out.append(consume(self.db,'challenge-1',1,5,'thread-'+str(i)))
        th=[threading.Thread(target=worker,args=(i,)) for i in range(3)]
        for t in th:t.start()
        for t in th:t.join(timeout=20)
        self.assertEqual(sorted(out),['COMMITTED','STALE','STALE'])
    def test_12_two_disconnected_clones_double_winner(self):
        second=os.path.join(self.tmp.name,'clone.sqlite');shutil.copyfile(self.db,second)
        self.assertEqual(self.run_child('normal','winner-a').stdout.strip(),'COMMITTED')
        self.assertEqual(self.run_child('normal','winner-b',db=second).stdout.strip(),'COMMITTED')
        self.assertNotEqual(self.rows()[1],self.rows(second)[1])
    def test_13_privileged_snapshot_restore_replays_challenge(self):
        snapshot=os.path.join(self.tmp.name,'earlier.sqlite');shutil.copyfile(self.db,snapshot)
        self.assertEqual(consume(self.db,'challenge-1',1,5,'once'),'COMMITTED')
        shutil.copyfile(snapshot,self.db)
        self.assertEqual(consume(self.db,'challenge-1',1,5,'replay'),'COMMITTED')
    def test_14_privileged_local_fake_ack_is_not_remote(self):
        consume(self.db,'challenge-1',1,5,'once')
        c=sqlite3.connect(self.db)
        try:
            c.execute('UPDATE pending SET status=?',('ACKED',))
            c.commit()
        finally:
            c.close()
        self.assertEqual(self.rows()[1][0][2],'ACKED')
        self.assertFalse(gate.inspect(packet())['remote_ack_authenticated'])
    def test_15_backed_up_pending_after_process_restart(self):
        self.assertEqual(self.run_child('after').returncode,72)
        self.assertEqual(self.run_child('normal','retry').stdout.strip(),'STALE')
        self.assertEqual(self.rows()[1][0][2],'PENDING')
    def test_16_challenge_db_reset_no_external_antirollback(self):
        consume(self.db,'challenge-1',1,5,'once')
        c=sqlite3.connect(self.db)
        try:
            c.execute('DELETE FROM pending')
            c.execute('UPDATE challenge SET state=?,generation=?,fence=?',('UNUSED',1,5))
            c.commit()
        finally:
            c.close()
        self.assertEqual(consume(self.db,'challenge-1',1,5,'privileged-replay'),'COMMITTED')

if __name__=='__main__':
    if len(sys.argv)==8 and sys.argv[1]=='--rc694-child':
        _,_,db,cid,gen,fence,receipt,mode=sys.argv
        print(consume(db,cid,int(gen),int(fence),receipt,mode),flush=True)
    else:
        unittest.main()
