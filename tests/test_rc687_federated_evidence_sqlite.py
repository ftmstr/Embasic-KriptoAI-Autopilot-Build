"""RC687 fabricated quorum split-view and test-only real SQLite atomic-outbox faults.

All records are invented. A caller-selected public key/domain is NOT an
independently certified Ed25519 authority. No provider-signed logs used.
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

from safe_public_ci.ci_federated_evidence_quarantine import (
    FederatedEvidenceRejected, _consistency, _digest, _inclusion, _root,
    compare_quarantined_claims, evidence_bytes, quarantine_cross_domain,
)

LEAVES = tuple(hashlib.sha256(("synthetic-rc687-%03d" % i).encode()).hexdigest()
               for i in range(128))
KEYS = ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")


def fixture(old=3, new=7, epoch=3):
    history = LEAVES[:new]
    old_root, new_root = _root(history[:old]).hex(), _root(history).hex()
    c = dict(
        repository="ftmstr/Embasic-KriptoAI-Autopilot-Build",
        branch="validation/rc654-pr1-rc653-combined-ci",
        git_sha="a"*40, workflow_sha256="1"*64,
        source_sha256="2"*64, roster_sha256="3"*64,
        previous_checkpoint_sha256="4"*64, history=history,
        old_size=old, new_size=new, old_root_sha256=old_root,
        new_root_sha256=new_root, inclusion_index=new-1,
        inclusion_path=_inclusion(history, new-1),
        consistency_path=_consistency(history, old),
        epoch=epoch, nonce_sha256="5"*64, issued_at=100, observed_at=120,
        principals=(("owner", "owner_one", KEYS[0], "admin_one", 90, 160, 106),
                    ("independent_reviewer", "reviewer_two", KEYS[1], "admin_two", 90, 160, 107)),
        revocations=(),
        providers=(("ubuntu",9101,9201,"a"*40,"2"*64,"1"*64,"6"*64,"UNVERIFIED"),
                   ("windows",9102,9202,"a"*40,"2"*64,"1"*64,"7"*64,"UNVERIFIED")),
        witnesses=(), cas_trace=(), used_nonces=(), prior_roots=(),
        ack_state="ACK_LOST_UNRESOLVED", release_ready=False,
        live_trading_allowed=False,
    )
    logs = _digest(tuple(row[6] for row in c["providers"]))
    c["witnesses"] = (("witness_a","network_one",epoch,new_root,logs,"UNVERIFIED"),
                      ("witness_b","network_two",epoch,new_root,logs,"UNVERIFIED"))
    c["cas_trace"] = tuple(("writer_" + s, epoch+i, old, old_root, new_root,
                            c["nonce_sha256"], "CLAIMED_WIN" if i==0 else "CLAIMED_CONFLICT")
                           for i,s in enumerate(("a","b","c")))
    return c, pins(c)


def pins(c):
    p = {key:c[key] for key in (
        "git_sha","workflow_sha256","source_sha256","roster_sha256",
        "previous_checkpoint_sha256","old_root_sha256","new_root_sha256","nonce_sha256")}
    fingerprints = tuple(hashlib.sha256(bytes.fromhex(x[2])).hexdigest()
                         for x in c["principals"])
    p.update(principals_sha256=_digest(fingerprints),
             witnesses_sha256=_digest(c["witnesses"]),
             claim_sha256=hashlib.sha256(evidence_bytes(c)).hexdigest(),
             out_of_band_keys_authenticated=False,
             provider_signature_authenticated=False,
             revocation_origin_authenticated=False,
             external_checkpoint_authenticated=False,
             durable_cas_authenticated=False)
    return p


def mutate(c,field,idx,part,value):
    rows = [list(row) for row in c[field]]
    rows[idx][part] = value
    c[field] = tuple(tuple(x) for x in rows)


def reconstruct(c,old=None,new=None,offset=0):
    if old is None: old = c["old_size"]
    if new is None: new = c["new_size"]
    history = LEAVES[:new] if offset==0 else (*LEAVES[:old],*LEAVES[64+offset:64+offset+new-old])
    c["old_size"], c["new_size"], c["history"] = old,new,tuple(history)
    c["old_root_sha256"],c["new_root_sha256"] = _root(history[:old]).hex(), _root(history).hex()
    c["inclusion_index"] = new-1
    c["inclusion_path"] = _inclusion(history,new-1)
    c["consistency_path"] = _consistency(history,old)
    log = _digest(tuple(r[6] for r in c["providers"]))
    c["witnesses"] = tuple((r[0],r[1],c["epoch"],c["new_root_sha256"],log,r[5]) for r in c["witnesses"])
    c["cas_trace"] = tuple((r[0],c["epoch"]+i,old,c["old_root_sha256"],
                            c["new_root_sha256"],c["nonce_sha256"],r[6])
                           for i,r in enumerate(c["cas_trace"]))


class RC687StructuralTests(unittest.TestCase):
    def run_audit(self,c,p=None):
        return quarantine_cross_domain(c, pins(c) if p is None else p)

    def reject(self,fn, stale=False):
        c,p=fixture()
        fn(c,p)
        with self.assertRaises(FederatedEvidenceRejected):
            self.run_audit(c,p)

    def test_01_valid_synthetic_claim_cannot_authenticate(self):
        c,p=fixture()
        out=self.run_audit(c,p)
        self.assertEqual(out["status"],"COHERENT_CROSS_DOMAIN_CLAIMS_ORIGIN_UNAUTHENTICATED")
        self.assertTrue(out["lost_ack_unresolved"])
        self.assertTrue(all(value is False for key,value in out.items()
                            if key.endswith("authenticated") or key.endswith("verified") or
                            key in ("release_ready","live_trading_allowed")))

    def test_02_same_caller_controls_all_distinct_admin_domains(self):
        c,p=fixture()
        self.assertNotEqual(c["principals"][0][3],c["principals"][1][3])
        self.assertNotEqual(c["witnesses"][0][1],c["witnesses"][1][1])
        self.assertFalse(self.run_audit(c,p)["witness_administrative_independence_authenticated"])

    def test_03_rekey_with_full_caller_repin_is_still_unauthenticated(self):
        c,_=fixture()
        mutate(c,"principals",0,2,"a"*64)
        result=self.run_audit(c)
        self.assertFalse(result["independent_key_distribution_authenticated"])

    def test_04_caller_can_replace_both_claimed_domain_names(self):
        c,_=fixture()
        mutate(c,"principals",0,3,"network_three")
        mutate(c,"principals",1,3,"network_four")
        self.assertFalse(self.run_audit(c)["owner_reviewer_authority_authenticated"])

    def test_05_revocation_later_than_claimed_observation_is_not_trusted_clock(self):
        c,_=fixture()
        fpr=hashlib.sha256(bytes.fromhex(KEYS[0])).hexdigest()
        c["revocations"] = ((fpr,1,121),)
        self.assertFalse(self.run_audit(c)["revocation_and_trusted_time_authenticated"])

    def test_06_consistency_3_to_7_not_3_to_8(self):
        self.reject(lambda c,p:c.update(new_size=8))

    def test_07_inclusion_0_1_and_all_boundaries(self):
        for size in (2,3,4,7,8,16,17,31,32,64,65,127,128):
            for old in set((1, size//2,size-1)):
                c,p=fixture(old,size)
                for i in (0,size//2,size-1):
                    c["inclusion_index"]=i
                    c["inclusion_path"]=_inclusion(c["history"],i)
                    self.assertTrue(evidence_bytes(c).startswith(b"RC687"))

    def test_08_equal_records_are_still_not_authentication(self):
        c,_=fixture()
        self.assertEqual(compare_quarantined_claims(c,copy.deepcopy(c)),
                         "EQUAL_CALLER_SUPPLIED_CLAIMS_ORIGIN_UNAUTHENTICATED")

    def test_09_detect_same_epoch_different_fork_root(self):
        c,_=fixture()
        fork=copy.deepcopy(c)
        reconstruct(fork,offset=1)
        self.assertEqual(compare_quarantined_claims(c,fork),
                         "CLAIMED_MERKLE_SPLIT_VIEW_ORIGIN_UNAUTHENTICATED")

    def test_10_identical_root_different_provider_log(self):
        c,_=fixture()
        fork=copy.deepcopy(c)
        mutate(fork,"providers",0,6,"e"*64)
        logs=_digest(tuple(p[6] for p in fork["providers"]))
        for i in (0,1): mutate(fork,"witnesses",i,4,logs)
        self.assertEqual(compare_quarantined_claims(c,fork),
                         "CLAIMED_PROVIDER_RECEIPT_SPLIT_VIEW_ORIGIN_UNAUTHENTICATED")

    def test_11_same_roots_different_nonce_still_transcript_fork(self):
        c,_=fixture(); fork=copy.deepcopy(c)
        fork["nonce_sha256"]="c"*64
        for i in (0,1,2): mutate(fork,"cas_trace",i,5,fork["nonce_sha256"])
        self.assertEqual(compare_quarantined_claims(c,fork),
                         "CLAIMED_TRANSCRIPT_FORK_ORIGIN_UNAUTHENTICATED")

    def test_12_epoch_gap_is_incomparable_not_authenticated(self):
        c,_=fixture(); fork=copy.deepcopy(c)
        fork["epoch"]+=1
        for i in (0,1): mutate(fork,"witnesses",i,2,fork["epoch"])
        for i in (0,1,2): mutate(fork,"cas_trace",i,1,fork["epoch"]+i)
        self.assertEqual(compare_quarantined_claims(c,fork),
                         "INCOMPARABLE_UNAUTHENTICATED_EPOCHS")

    def test_13_self_provided_log_hash_is_not_provider_signature(self):
        c,_=fixture()
        mutate(c,"providers",1,6,"f"*64)
        log=_digest(tuple(p[6] for p in c["providers"]))
        for i in (0,1): mutate(c,"witnesses",i,4,log)
        self.assertFalse(self.run_audit(c)["provider_signed_log_authenticated"])

    def test_14_multi_witness_repeat_never_persists_state(self):
        c,_=fixture()
        first=self.run_audit(c)
        second=self.run_audit(c)
        self.assertEqual(first,second)
        self.assertFalse(second["persistent_atomic_cas_verified"])

    def test_15_valid_claim_is_not_a_sig_verification(self):
        c,_=fixture()
        self.assertTrue(evidence_bytes(c))
        self.assertFalse(self.run_audit(c)["owner_reviewer_authority_authenticated"])

    def test_16_zero_evidence_flags_even_if_ack_not_sent(self):
        c,_=fixture();c["ack_state"]="NOT_SENT"
        d=self.run_audit(c)
        self.assertFalse(d["lost_ack_unresolved"])
        self.assertFalse(d["persistent_atomic_cas_verified"])

    def test_17_caller_provided_full_history_does_not_mean_external_history(self):
        c,_=fixture();self.assertEqual(len(c["history"]),c["new_size"])
        self.assertFalse(self.run_audit(c)["external_merkle_checkpoint_authenticated"])

    def test_18_independent_domain_labels_not_actual_independence(self):
        c,_=fixture();self.assertEqual(len(set(x[1] for x in c["witnesses"])),2)
        self.assertFalse(self.run_audit(c)["witness_administrative_independence_authenticated"])


MUTATIONS = (
    ("missing_schema",lambda c,p:c.pop("roster_sha256"),False),
    ("extra_schema",lambda c,p:c.update(authenticated=True),False),
    ("wrong_repo",lambda c,p:c.update(repository="ftmstr/private"),False),
    ("main_branch",lambda c,p:c.update(branch="main"),False),
    ("invalid_git",lambda c,p:c.update(git_sha="z"*40),False),
    ("source_repin_stale",lambda c,p:c.update(source_sha256="d"*64),True),
    ("workflow_repin_stale",lambda c,p:c.update(workflow_sha256="d"*64),True),
    ("roster_repin_stale",lambda c,p:c.update(roster_sha256="d"*64),True),
    ("previous_checkpoint_stale",lambda c,p:c.update(previous_checkpoint_sha256="d"*64),True),
    ("epoch_zero",lambda c,p:c.update(epoch=0),False),
    ("bool_epoch",lambda c,p:c.update(epoch=True),False),
    ("old_zero",lambda c,p:c.update(old_size=0),False),
    ("new_129",lambda c,p:c.update(new_size=129),False),
    ("reversed_time",lambda c,p:c.update(issued_at=121),False),
    ("live_on",lambda c,p:c.update(live_trading_allowed=True),False),
    ("release_on",lambda c,p:c.update(release_ready=True),False),
    ("ack_falsely_committed",lambda c,p:c.update(ack_state="ACK_COMMITTED"),False),
    ("history_list",lambda c,p:c.update(history=list(c["history"])),False),
    ("history_short",lambda c,p:c.update(history=c["history"][:-1]),False),
    ("history_duplicate",lambda c,p:c.update(history=(*c["history"][:-1],c["history"][0])),False),
    ("history_reversed",lambda c,p:c.update(history=tuple(reversed(c["history"]))),False),
    ("inclusion_wrong_index",lambda c,p:c.update(inclusion_index=c["new_size"]),False),
    ("inclusion_bool",lambda c,p:c.update(inclusion_index=True),False),
    ("inclusion_truncated",lambda c,p:c.update(inclusion_path=c["inclusion_path"][:-1]),False),
    ("inclusion_wrong",lambda c,p:c.update(inclusion_path=("a"*64,*c["inclusion_path"][1:])),False),
    ("inclusion_extra",lambda c,p:c.update(inclusion_path=(*c["inclusion_path"],"a"*64)),False),
    ("consistency_extra",lambda c,p:c.update(consistency_path=(*c["consistency_path"],"a"*64)),False),
    ("consistency_reversed",lambda c,p:c.update(consistency_path=tuple(reversed(c["consistency_path"]))),False),
    ("old_root_wrong",lambda c,p:c.update(old_root_sha256="f"*64),False),
    ("new_root_wrong",lambda c,p:c.update(new_root_sha256="f"*64),False),
    ("wrong_owner_role",lambda c,p:mutate(c,"principals",0,0,"viewer"),False),
    ("wrong_reviewer_role",lambda c,p:mutate(c,"principals",1,0,"owner"),False),
    ("duplicate_principal_id",lambda c,p:mutate(c,"principals",1,1,"owner_one"),False),
    ("duplicate_principal_key",lambda c,p:mutate(c,"principals",1,2,KEYS[0]),False),
    ("duplicate_admin",lambda c,p:mutate(c,"principals",1,3,"admin_one"),False),
    ("sign_before_validity",lambda c,p:mutate(c,"principals",0,6,89),False),
    ("sign_after_validity",lambda c,p:mutate(c,"principals",0,6,161),False),
    ("sign_future_observed",lambda c,p:mutate(c,"principals",0,6,121),False),
    ("principal_rebind_stale",lambda c,p:mutate(c,"principals",0,1,"other_owner"),True),
    ("revoked_owner",lambda c,p:c.update(revocations=((hashlib.sha256(bytes.fromhex(KEYS[0])).hexdigest(),1,120),)),False),
    ("revoked_reviewer",lambda c,p:c.update(revocations=((hashlib.sha256(bytes.fromhex(KEYS[1])).hexdigest(),1,120),)),False),
    ("revocations_wrong_type",lambda c,p:c.update(revocations=[("a"*64,1,100)]),False),
    ("revocations_reordered",lambda c,p:c.update(revocations=(("f"*64,1,100),("e"*64,1,100))),False),
    ("revocations_duplicate",lambda c,p:c.update(revocations=(("a"*64,1,100),("a"*64,2,110))),False),
    ("wrong_provider_os",lambda c,p:mutate(c,"providers",1,0,"ubuntu"),False),
    ("duplicate_run",lambda c,p:mutate(c,"providers",1,1,9101),False),
    ("duplicate_job",lambda c,p:mutate(c,"providers",1,2,9201),False),
    ("foreign_commit",lambda c,p:mutate(c,"providers",0,3,"b"*40),False),
    ("foreign_source",lambda c,p:mutate(c,"providers",0,4,"b"*64),False),
    ("foreign_workflow",lambda c,p:mutate(c,"providers",0,5,"b"*64),False),
    ("provider_claim_verified",lambda c,p:mutate(c,"providers",0,7,"VERIFIED"),False),
    ("provider_log_unbound",lambda c,p:mutate(c,"providers",0,6,"b"*64),False),
    ("provider_stale_job",lambda c,p:mutate(c,"providers",0,2,9301),True),
    ("witness_duplicate_id",lambda c,p:mutate(c,"witnesses",1,0,"witness_a"),False),
    ("witness_duplicate_admin",lambda c,p:mutate(c,"witnesses",1,1,"network_one"),False),
    ("witness_wrong_epoch",lambda c,p:mutate(c,"witnesses",1,2,999),False),
    ("witness_wrong_root",lambda c,p:mutate(c,"witnesses",0,3,"c"*64),False),
    ("witness_wrong_logs",lambda c,p:mutate(c,"witnesses",0,4,"c"*64),False),
    ("witness_fake_verified",lambda c,p:mutate(c,"witnesses",0,5,"SIGNED"),False),
    ("witness_stale_rebind",lambda c,p:mutate(c,"witnesses",0,1,"network_three"),True),
    ("wrong_cas_epoch",lambda c,p:mutate(c,"cas_trace",2,1,3),False),
    ("wrong_cas_gen",lambda c,p:mutate(c,"cas_trace",1,2,4),False),
    ("wrong_cas_old",lambda c,p:mutate(c,"cas_trace",0,3,"f"*64),False),
    ("wrong_cas_new",lambda c,p:mutate(c,"cas_trace",0,4,"f"*64),False),
    ("wrong_cas_nonce",lambda c,p:mutate(c,"cas_trace",0,5,"f"*64),False),
    ("double_cas_winner",lambda c,p:mutate(c,"cas_trace",1,6,"CLAIMED_WIN"),False),
    ("cas_duplicate_actor",lambda c,p:mutate(c,"cas_trace",2,0,"writer_a"),False),
    ("cas_stale_actor_rebind",lambda c,p:mutate(c,"cas_trace",2,0,"writer_x"),True),
    ("nonce_replay",lambda c,p:c.update(used_nonces=("5"*64,)),False),
    ("new_root_replay",lambda c,p:c.update(prior_roots=(c["new_root_sha256"],)),False),
    ("replay_list",lambda c,p:c.update(used_nonces=["a"*64]),False),
    ("replay_duplicate",lambda c,p:c.update(used_nonces=("a"*64,"a"*64)),False),
    ("fake_pin_authority",lambda c,p:p.update(out_of_band_keys_authenticated=True),True),
    ("fake_pin_provider",lambda c,p:p.update(provider_signature_authenticated=True),True),
    ("fake_pin_revocation",lambda c,p:p.update(revocation_origin_authenticated=True),True),
    ("fake_pin_checkpoint",lambda c,p:p.update(external_checkpoint_authenticated=True),True),
    ("fake_pin_cas",lambda c,p:p.update(durable_cas_authenticated=True),True),
    ("fake_pin_witness_hash",lambda c,p:p.update(witnesses_sha256="a"*64),True),
    ("fake_pin_signers_hash",lambda c,p:p.update(principals_sha256="a"*64),True),
    ("fake_pin_digest",lambda c,p:p.update(claim_sha256="a"*64),True),
    ("fake_pin_extra",lambda c,p:p.update(AUTHENTICATED=True),True),
)


def make_case(mutation,stale):
    def test(self):
        self.reject(mutation,stale=stale)
    return test


for n,(name,action,stale) in enumerate(MUTATIONS,19):
    setattr(RC687StructuralTests,"test_%03d_%s"%(n,name),make_case(action,stale))


SCHEMA = (
    "CREATE TABLE IF NOT EXISTS state(g INTEGER NOT NULL, root TEXT NOT NULL, epoch INTEGER NOT NULL);"
    "CREATE TABLE IF NOT EXISTS spent(nonce TEXT PRIMARY KEY, generation INTEGER NOT NULL);"
    "CREATE TABLE IF NOT EXISTS outbox(generation INTEGER PRIMARY KEY, nonce TEXT UNIQUE NOT NULL,"
    "  root TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('PENDING','ACKED')));"
)


def connect(dbpath):
    return sqlite3.connect(str(dbpath),timeout=3,isolation_level=None)


def initialize(dbpath, mode="delete"):
    db=connect(dbpath)
    try:
        db.execute("PRAGMA journal_mode="+mode)
        db.execute("PRAGMA synchronous=FULL")
        db.executescript(SCHEMA)
        if db.execute("SELECT COUNT(*) FROM state").fetchone()[0]==0:
            db.execute("INSERT INTO state VALUES(3,?,3)",( "a"*64,))
    finally:
        db.close()


def cas(dbpath, nonce="synthetic1", expect=3, root="a"*64, newroot="b"*64, crash=None):
    db=connect(dbpath)
    try:
        db.execute("BEGIN IMMEDIATE")
        g,old,ep=db.execute("SELECT g,root,epoch FROM state").fetchone()
        if (g,old)!=(expect,root):
            db.rollback()
            return "STALE"
        db.execute("INSERT INTO spent VALUES(?,?)",(nonce,expect+1))
        if crash=="after_nonce":os._exit(65)
        updated=db.execute("UPDATE state SET g=?,root=?,epoch=? WHERE g=? AND root=?",
                           (expect+1,newroot,ep+1,expect,root)).rowcount
        if updated!=1:
            db.rollback()
            return "STALE"
        db.execute("INSERT INTO outbox VALUES(?,?,?,'PENDING')",(expect+1,nonce,newroot))
        if crash=="before_commit":os._exit(66)
        db.commit()
        if crash=="after_commit":os._exit(67)
        return "COMMITTED"
    except sqlite3.IntegrityError:
        db.rollback()
        return "NONCE_REPLAY"
    finally:
        db.close()


def state(dbpath):
    db=connect(dbpath)
    try:
        return (db.execute("SELECT g,root,epoch FROM state").fetchone(),
                db.execute("SELECT nonce,generation FROM spent ORDER BY nonce").fetchall(),
                db.execute("SELECT generation,nonce,root,status FROM outbox ORDER BY generation").fetchall())
    finally:
        db.close()


CHILD = '''import os,sys,sqlite3
path,stage,nonce=sys.argv[1:]
db=sqlite3.connect(path,isolation_level=None,timeout=3)
try:
 db.execute('BEGIN IMMEDIATE')
 g,root,epoch=db.execute('SELECT g,root,epoch FROM state').fetchone()
 if g!=3 or root!='a'*64: sys.exit(73)
 db.execute('INSERT INTO spent VALUES(?,?)',(nonce,4))
 if stage=='after_nonce': os._exit(65)
 db.execute('UPDATE state SET g=?,root=?,epoch=? WHERE g=? AND root=?',(4,'b'*64,4,3,'a'*64))
 db.execute("INSERT INTO outbox VALUES(?,?,?,'PENDING')",(4,nonce,'b'*64))
 if stage=='before_commit': os._exit(66)
 db.commit()
 if stage=='after_commit': os._exit(67)
finally: db.close()
'''


class RC687SqliteOutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="rc687-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.dbpath=Path(self.temp.name)/"state.sqlite"
        initialize(self.dbpath)

    def child(self,stage,nonce="synthetic1"):
        return subprocess.run([sys.executable,"-c",CHILD,str(self.dbpath),stage,nonce],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)

    def test_01_receipt_and_state_atomic_at_commit(self):
        self.assertEqual(cas(self.dbpath),"COMMITTED")
        clock,nonces,outbox=state(self.dbpath)
        self.assertEqual(clock,(4,"b"*64,4))
        self.assertEqual(nonces,[("synthetic1",4)])
        self.assertEqual(outbox,[(4,"synthetic1","b"*64,"PENDING")])

    def test_02_stale_precondition_does_not_consume_nonce(self):
        self.assertEqual(cas(self.dbpath,expect=4),"STALE")
        self.assertEqual(state(self.dbpath)[1],[])

    def test_03_bad_root_does_not_publish_outbox(self):
        self.assertEqual(cas(self.dbpath,root="z"*64),"STALE")
        self.assertEqual(state(self.dbpath)[2],[])

    def test_04_replay_original_nonce_after_advancing_generation(self):
        cas(self.dbpath)
        self.assertEqual(cas(self.dbpath,expect=4,root="b"*64,nonce="synthetic1",newroot="c"*64),
                         "NONCE_REPLAY")
        self.assertEqual(state(self.dbpath)[0][0],4)

    def test_05_fresh_nonce_next_generation(self):
        cas(self.dbpath)
        self.assertEqual(cas(self.dbpath,expect=4,root="b"*64,nonce="synthetic2",newroot="c"*64),
                         "COMMITTED")
        self.assertEqual(len(state(self.dbpath)[2]),2)

    def test_06_two_distinct_nonces_race_single_winner(self):
        barrier=threading.Barrier(2)
        values=[]
        def task(n):
            barrier.wait(5)
            values.append(cas(self.dbpath,nonce=n))
        a=threading.Thread(target=task,args=("n1",));b=threading.Thread(target=task,args=("n2",))
        a.start();b.start();a.join(8);b.join(8)
        self.assertFalse(a.is_alive() or b.is_alive())
        self.assertCountEqual(values,["COMMITTED","STALE"])
        self.assertEqual(len(state(self.dbpath)[1]),1)

    def test_07_four_distinct_nonces_race_single_winner(self):
        barrier=threading.Barrier(4)
        values=[]
        def task(n):
            barrier.wait(5)
            values.append(cas(self.dbpath,nonce="race"+str(n)))
        threads=[threading.Thread(target=task,args=(i,)) for i in range(4)]
        for t in threads:t.start()
        for t in threads:t.join(8)
        self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertEqual(values.count("COMMITTED"),1)
        self.assertEqual(values.count("STALE"),3)

    def test_08_child_terminates_after_nonce_rollback(self):
        p=self.child("after_nonce")
        self.assertEqual(p.returncode,65,p.stderr.decode(errors="replace"))
        self.assertEqual(state(self.dbpath)[0][0],3)
        self.assertEqual(state(self.dbpath)[1],[])
        self.assertEqual(state(self.dbpath)[2],[])

    def test_09_child_terminates_after_state_before_commit_rollback(self):
        p=self.child("before_commit")
        self.assertEqual(p.returncode,66,p.stderr.decode(errors="replace"))
        self.assertEqual(state(self.dbpath)[0][0],3)
        self.assertEqual(state(self.dbpath)[1],[])

    def test_10_child_terminates_after_commit_lost_ack(self):
        p=self.child("after_commit")
        self.assertEqual(p.returncode,67,p.stderr.decode(errors="replace"))
        self.assertEqual(state(self.dbpath)[0][0],4)
        self.assertEqual(state(self.dbpath)[2][0][-1],"PENDING")

    def test_11_after_lost_ack_retry_same_nonce_is_not_second_winner(self):
        self.child("after_commit")
        self.assertEqual(cas(self.dbpath,nonce="synthetic1"),"STALE")
        self.assertEqual(len(state(self.dbpath)[2]),1)

    def test_12_ack_status_only_local_claim_not_actual_delivery(self):
        cas(self.dbpath)
        db=connect(self.dbpath)
        try:
            db.execute("UPDATE outbox SET status='ACKED' WHERE generation=4")
        finally:db.close()
        self.assertEqual(state(self.dbpath)[2][0][-1],"ACKED")
        self.assertEqual(state(self.dbpath)[0][0],4)
        # An attacker-controlled local value cannot prove an external receiver ACK.

    def test_13_rollback_does_not_consume_a_nonce(self):
        db=connect(self.dbpath)
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO spent VALUES('synthetic1',4)")
            db.rollback()
        finally:db.close()
        self.assertEqual(cas(self.dbpath),"COMMITTED")

    def test_14_savepoint_rollback_cannot_publish_phantom_nonce(self):
        db=connect(self.dbpath)
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("SAVEPOINT toy")
            db.execute("INSERT INTO spent VALUES('synthetic1',4)")
            db.execute("ROLLBACK TO toy")
            db.execute("RELEASE toy")
            db.commit()
        finally:db.close()
        self.assertEqual(state(self.dbpath)[1],[])

    def test_15_cloned_databases_each_claim_single_winner(self):
        clone=Path(self.temp.name)/"clone.sqlite"
        shutil.copy2(self.dbpath,clone)
        self.assertEqual(cas(self.dbpath),"COMMITTED")
        self.assertEqual(cas(clone),"COMMITTED")
        self.assertEqual(state(self.dbpath)[0],state(clone)[0])
        # No distributed single-winner guarantee despite matching local states.

    def test_16_disconnected_fork_with_distinct_root_and_same_nonce(self):
        clone=Path(self.temp.name)/"clone.sqlite"
        shutil.copy2(self.dbpath,clone)
        self.assertEqual(cas(self.dbpath,newroot="b"*64),"COMMITTED")
        self.assertEqual(cas(clone,newroot="c"*64),"COMMITTED")
        self.assertNotEqual(state(self.dbpath)[0],state(clone)[0])

    def test_17_trusted_admin_can_rollback_state_ledger_outbox(self):
        cas(self.dbpath)
        db=connect(self.dbpath)
        try:
            db.execute("DELETE FROM spent")
            db.execute("DELETE FROM outbox")
            db.execute("UPDATE state SET g=3, root=?, epoch=3",("a"*64,))
        finally:db.close()
        self.assertEqual(cas(self.dbpath),"COMMITTED")
        # Real privileged local admin defeats the rollback guard.

    def test_18_snapshot_restore_reuses_old_nonce(self):
        snap=Path(self.temp.name)/"old.sqlite"
        shutil.copy2(self.dbpath,snap)
        cas(self.dbpath)
        # DELETE journal mode; all writers closed before replacement.
        shutil.copy2(snap,self.dbpath)
        self.assertEqual(cas(self.dbpath),"COMMITTED")

    def test_19_text_anchor_detects_only_one_sided_rewind(self):
        anchor=Path(self.temp.name)/"local_untrusted_anchor.txt"
        anchor.write_text("3|"+"a"*64,encoding="ascii")
        cas(self.dbpath)
        anchor.write_text("4|"+"b"*64,encoding="ascii")
        db=connect(self.dbpath)
        try:db.execute("UPDATE state SET g=3,root=?,epoch=3",("a"*64,))
        finally:db.close()
        self.assertNotEqual(anchor.read_text(),str(state(self.dbpath)[0][0])+"|"+state(self.dbpath)[0][1])

    def test_20_same_admin_can_rewind_local_anchor_as_well(self):
        anchor=Path(self.temp.name)/"local_untrusted_anchor.txt"
        cas(self.dbpath)
        anchor.write_text("4|"+"b"*64,encoding="ascii")
        db=connect(self.dbpath)
        try:db.execute("UPDATE state SET g=3,root=?,epoch=3",("a"*64,))
        finally:db.close()
        anchor.write_text("3|"+"a"*64,encoding="ascii")
        self.assertEqual(anchor.read_text(),str(state(self.dbpath)[0][0])+"|"+state(self.dbpath)[0][1])
        # Consistent again, but still untrusted.

    def test_21_wal_mode_local_atomic_cas_not_external_attestation(self):
        db=connect(self.dbpath)
        try:db.execute("PRAGMA journal_mode=WAL")
        finally:db.close()
        self.assertEqual(cas(self.dbpath),"COMMITTED")
        self.assertEqual(state(self.dbpath)[0][0],4)

    def test_22_delete_mode_local_atomic_cas_not_external_attestation(self):
        db=connect(self.dbpath)
        try:db.execute("PRAGMA journal_mode=DELETE")
        finally:db.close()
        self.assertEqual(cas(self.dbpath),"COMMITTED")
        self.assertEqual(state(self.dbpath)[0][0],4)

    def test_23_falsified_ack_mark_fails_to_prove_external_receiver(self):
        cas(self.dbpath)
        db=connect(self.dbpath)
        try:db.execute("UPDATE outbox SET status='ACKED'")
        finally:db.close()
        self.assertEqual(state(self.dbpath)[2][0][-1],"ACKED")
        db=connect(self.dbpath)
        try:
            columns={row[1] for row in db.execute("PRAGMA table_info(outbox)")}
        finally:db.close()
        self.assertNotIn("receiver_signed_attestation",columns)
        # The local ACK field cannot establish external receiver delivery.

    def test_24_invalid_nonce_replay_does_not_publish_second_outbox(self):
        cas(self.dbpath)
        self.assertEqual(cas(self.dbpath,expect=4,root="b"*64,nonce="synthetic1"),"NONCE_REPLAY")
        self.assertEqual(len(state(self.dbpath)[2]),1)

    def test_25_caller_reconciles_pending_after_restart_without_receipt_proof(self):
        cas(self.dbpath)
        pending=state(self.dbpath)[2]
        self.assertEqual(pending[0][-1],"PENDING")
        self.assertEqual(pending[0][1],"synthetic1")
        # A local outbox row does not prove a remote exchange observed an order.


if __name__ == "__main__":
    unittest.main()
