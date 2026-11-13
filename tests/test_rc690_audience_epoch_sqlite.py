"""RC690 original fabricated cross-audience threat tests + local disposable SQLite.

All signing, provider and witness records are synthetic. No exchange/network.
SQLite is in TESTS only; its behavior is not proof of durable production CAS.
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

from safe_public_ci import ci_audience_epoch_quarantine as gate

ROOT = Path(__file__).resolve().parents[1]
SNAP_ROOT = hashlib.sha256(b"RC690-source").hexdigest()


def H(value):
    return hashlib.sha256(str(value).encode("ascii")).hexdigest()


def make_claim(n=5, previous=3):
    leaves = [H("leaf-" + str(i)) for i in range(n)]
    root = gate._root(leaves).hex()
    oldroot = gate._root(leaves[:previous]).hex()
    source = "363c739b23616b4cf0a5282edb0ba0b0019c5846"
    rosters = [
        {"role": r, "subject": name, "pubkey": H("pub-" + r),
         "fingerprint": gate._sha(bytes.fromhex(H("pub-" + r))),
         "since": 10, "until": 100}
        for r, name in (("owner", "alice"), ("reviewer", "bob"))]
    witnesses = [{"id": name, "domain": domain, "epoch": 9, "size": n,
                  "root": root, "time": 23, "receipt_digest": H("witness-" + name)}
                 for name, domain in (("alpha", "domaina"),
                                       ("beta", "domainb"),
                                       ("gamma", "domainc"))]
    gossip = [{"from": sender["id"], "to": recipient["id"], "epoch": 9,
               "root": root, "receipt_digest": sender["receipt_digest"]}
              for sender in witnesses for recipient in witnesses if sender != recipient]
    content = {
        "repository": "ftmstr/Embasic-KriptoAI-Autopilot-Build",
        "branch": "validation/rc654-pr1-rc653-combined-ci",
        "source_sha": source, "source_digest": H("sourceblob"),
        "roster_digest": H("roster"), "workflow_digest": H("workflow"),
        "previous": {"size": previous, "root": oldroot, "epoch": 8},
        "current": {"size": n, "root": root, "epoch": 9},
        "leaves": leaves, "included_index": n-1,
        "inclusion_path": list(gate._inclusion(leaves, n-1)),
        "prefix_proof": list(gate._consistency(leaves, previous)),
        "authorities": rosters, "revocations": [],
        "providers": [{"os": os_name, "run": run, "job": job, "attempt": 1,
                       "log_sha256": H("provider-" + os_name),
                       "source_sha": source, "workflow_digest": H("workflow"),
                       "signed_claim": False}
                      for os_name, run, job in (("ubuntu", 43493426392, 132120212859),
                                                ("windows", 43493425934, 132120212398))],
        "witnesses": witnesses, "gossip": gossip,
        "anchor": {"locator": "externalanchor", "epoch": 9,
                   "root": root, "root_sha256": gate._sha(bytes.fromhex(root)),
                   "independent_auth": False},
        "fence": {"old_generation": 4, "generation": 5, "token": 11,
                  "nonce": H("nonce"), "lease_start": 12,
                  "lease_end": 90, "observed_at": 23,
                  "outbox": "PENDING", "ack": "LOST_UNRESOLVED"},
        "release": False,
    }
    return content


def make_pins(p):
    return {"source_sha": p["source_sha"], "source_digest": p["source_digest"],
            "roster_digest": p["roster_digest"], "workflow_digest": p["workflow_digest"],
            "previous_root": p["previous"]["root"],
            "current_root": p["current"]["root"],
            "commit_digest": gate.claimed_digest(p)}


def verify(c):
    return gate.validate_claim(c, expected=make_pins(c))


class StructuralTests(unittest.TestCase):
    def test_coherent_transcript_still_not_authenticated(self):
        result = verify(make_claim())
        self.assertTrue(result["inclusion_math_consistent"])
        self.assertTrue(result["prefix_math_consistent"])
        self.assertTrue(result["claimed_gossip_mesh_complete"])
        self.assertIn("QUARANTINED", result["status"])
        for flag in ("independent_owner_reviewer_authenticated", "real_ed25519_signer_authority",
                     "external_provider_run_log_authenticated", "revocation_and_trusted_time_authenticated",
                     "immutable_checkpoint_authenticated", "durable_multihost_cas_verified",
                     "external_ack_verified", "release_ready", "live_trading_allowed"):
            self.assertIs(result[flag], False, flag)

    def test_domain_separated_digest_changes(self):
        a = make_claim()
        b = copy.deepcopy(a); b["fence"]["nonce"] = H("anothernonce")
        self.assertNotEqual(gate.claimed_digest(a), gate.claimed_digest(b))

    def test_zero_length_history_is_rejected(self):
        a = make_claim(); a["leaves"] = []
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_forked_external_pin_is_rejected(self):
        a = make_claim(); pins=make_pins(a); pins["current_root"] = H("externally-pinned-different")
        with self.assertRaises(gate.AudienceRejected): gate.validate_claim(a, expected=pins)

    def test_malformed_reference_pin_rejected(self):
        a = make_claim(); pins=make_pins(a); pins["commit_digest"] = "0"*63
        with self.assertRaises(gate.AudienceRejected): gate.validate_claim(a, expected=pins)

    def test_caller_supplied_roster_is_not_actual_owner_authority(self):
        result = verify(make_claim())
        self.assertFalse(result["real_ed25519_signer_authority"])

    def test_caller_supplied_anchor_is_not_immutable(self):
        result = verify(make_claim())
        self.assertFalse(result["immutable_checkpoint_authenticated"])

    def test_unknown_type_cannot_be_encoded(self):
        with self.assertRaises(gate.AudienceRejected): gate.claimed_digest({"unknown": object()})

    def test_bytes_are_not_accepted_as_signature_claim(self):
        with self.assertRaises(gate.AudienceRejected): gate.claimed_digest({"bytes": b"not-key"})

    def test_recursive_claim_rejected(self):
        value=[]; value.append(value)
        with self.assertRaises(gate.AudienceRejected): gate.claimed_digest(value)

    def test_case_sensitive_digest(self):
        self.assertNotEqual(gate.claimed_digest({"A": 1}), gate.claimed_digest({"a": 1}))

    def test_bool_is_not_int_in_canonical_digest(self):
        self.assertNotEqual(gate.claimed_digest({"a": True}), gate.claimed_digest({"a": 1}))

    def test_maximum_full_tree_finite(self):
        a=make_claim(n=128,previous=127)
        self.assertTrue(verify(a)["prefix_math_consistent"])

    def test_129_leaves_rejected(self):
        a=make_claim(n=129,previous=127)
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_distinct_valid_trees(self):
        for n,old in ((2,1),(3,1),(3,2),(4,3),(7,4),(16,8),(31,30),(64,31)):
            with self.subTest(n=n,old=old):
                self.assertTrue(verify(make_claim(n,old))["inclusion_math_consistent"])


# Each mutation is a separately named unittest case; recompute caller's claimed
# digest so tests exercise REAL structural checks, not just the digest gate.
def mutate(path, value, index=None):
    def act(c):
        node=c
        for k in path[:-1]: node=node[k]
        node[path[-1]]=value
    return act


_MUTATIONS = [
    ("repo_spoof", ("repository",), "ftmstr/Private"),
    ("branch_spoof", ("branch",), "main"),
    ("source_upper", ("source_sha",), "A"*40),
    ("source_short", ("source_sha",), "0"*39),
    ("wrong_old_size", ("previous","size"), 6),
    ("old_size_bool", ("previous","size"), True),
    ("new_size_bool", ("current","size"), True),
    ("new_size_zero", ("current","size"), 0),
    ("old_epoch_zero", ("previous","epoch"), 0),
    ("new_epoch_reused", ("current","epoch"), 8),
    ("new_epoch_bool", ("current","epoch"), True),
    ("old_root_wrong", ("previous","root"), H("fakeold")),
    ("new_root_wrong", ("current","root"), H("fakenew")),
    ("incl_negative", ("included_index",), -1),
    ("incl_bool", ("included_index",), True),
    ("incl_outside", ("included_index",), 5),
    ("incl_path_empty", ("inclusion_path",), []),
    ("incl_path_bogus", ("inclusion_path",), [H("x")]),
    ("incl_path_type", ("inclusion_path",), ()),
    ("prefix_path_empty", ("prefix_proof",), []),
    ("prefix_path_bogus", ("prefix_proof",), [H("bad")]),
    ("prefix_path_type", ("prefix_proof",), ()),
    ("owner_role_change", ("authorities",0,"role"), "reviewer"),
    ("reviewer_role_change", ("authorities",1,"role"), "owner"),
    ("owner_subject_invalid", ("authorities",0,"subject"), "Alice"),
    ("reviewer_subject_invalid", ("authorities",1,"subject"), "ro bert"),
    ("owner_pubkey_invalid", ("authorities",0,"pubkey"), "0"*63),
    ("owner_fingerprint_wrong", ("authorities",0,"fingerprint"), H("misbinding")),
    ("reviewer_fingerprint_wrong", ("authorities",1,"fingerprint"), H("misbinding")),
    ("owner_since_bool", ("authorities",0,"since"), True),
    ("owner_since_negative", ("authorities",0,"since"), -1),
    ("owner_until_before_since", ("authorities",0,"until"), 9),
    ("reviewer_until_bool", ("authorities",1,"until"), True),
    ("reviewer_until_zero", ("authorities",1,"until"), 0),
    ("provider_ubuntu_wrong_os", ("providers",0,"os"), "linux"),
    ("provider_windows_wrong_os", ("providers",1,"os"), "macos"),
    ("provider_run_bool", ("providers",0,"run"), True),
    ("provider_job_zero", ("providers",1,"job"), 0),
    ("provider_attempt_zero", ("providers",0,"attempt"), 0),
    ("provider_attempt_bool", ("providers",1,"attempt"), True),
    ("provider_attempt_two", ("providers",0,"attempt"), 2),
    ("provider_log_short", ("providers",0,"log_sha256"), "0"*63),
    ("provider_source_spoof", ("providers",1,"source_sha"), "0"*40),
    ("provider_workflow_spoof", ("providers",0,"workflow_digest"), H("fakeflow")),
    ("provider_fake_signed", ("providers",0,"signed_claim"), True),
    ("provider_fake_signed_one", ("providers",1,"signed_claim"), 1),
    ("witness_alpha_bad_name", ("witnesses",0,"id"), "Alpha"),
    ("witness_beta_bad_domain", ("witnesses",1,"domain"), "provider.com"),
    ("witness_gamma_bad_domain", ("witnesses",2,"domain"), ""),
    ("witness_epoch_stale", ("witnesses",0,"epoch"), 8),
    ("witness_epoch_bool", ("witnesses",1,"epoch"), True),
    ("witness_size_short", ("witnesses",2,"size"), 4),
    ("witness_root_split", ("witnesses",0,"root"), H("otherroot")),
    ("witness_time_zero", ("witnesses",1,"time"), 0),
    ("witness_time_bool", ("witnesses",2,"time"), True),
    ("witness_bad_receipt", ("witnesses",0,"receipt_digest"), "a"*63),
    ("gossip_bad_sender", ("gossip",0,"from"), "other"),
    ("gossip_self_loop", ("gossip",1,"to"), "alpha"),
    ("gossip_old_epoch", ("gossip",0,"epoch"), 8),
    ("gossip_split_root", ("gossip",0,"root"), H("forked")),
    ("gossip_unknown_receipt", ("gossip",0,"receipt_digest"), H("unknown")),
    ("anchor_bad_locator", ("anchor","locator"), "https://fake"),
    ("anchor_mismatch_epoch", ("anchor","epoch"), 8),
    ("anchor_fake_immutability", ("anchor","independent_auth"), True),
    ("anchor_bad_digest", ("anchor","root_sha256"), H("bad")),
    ("fence_old_gen_bool", ("fence","old_generation"), True),
    ("fence_gen_bool", ("fence","generation"), True),
    ("fence_aba", ("fence","generation"), 4),
    ("fence_token_old", ("fence","token"), 4),
    ("fence_token_bool", ("fence","token"), True),
    ("fence_nonce_invalid", ("fence","nonce"), "0"*63),
    ("fence_lease_start_bool", ("fence","lease_start"), True),
    ("fence_expired", ("fence","lease_end"), 22),
    ("fence_future", ("fence","lease_start"), 24),
    ("fence_time_bool", ("fence","observed_at"), True),
    ("outbox_fake_acked", ("fence","outbox"), "ACKED"),
    ("ack_fake_success", ("fence","ack"), "PROVIDER_SIGNED"),
    ("release_claim", ("release",), True),
    ("release_integer", ("release",), 0),
]


def _create_mutation_test(name, path, value):
    def test(self):
        case=make_claim()
        node=case
        for key in path[:-1]: node=node[key]
        node[path[-1]]=value
        with self.assertRaises(gate.AudienceRejected):
            gate.validate_claim(case, expected=make_pins(case))
    test.__name__="test_rc690_reject_"+name
    return test


for _n, _p, _v in _MUTATIONS:
    setattr(StructuralTests, "test_rc690_reject_"+_n, _create_mutation_test(_n,_p,_v))


class ListAndViewTests(unittest.TestCase):
    def test_duplicate_witness_domains(self):
        a=make_claim(); a["witnesses"][1]["domain"]="domaina"
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_duplicate_witness_id(self):
        a=make_claim(); a["witnesses"][1]["id"]="alpha"
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_missing_gossip_edge(self):
        a=make_claim(); a["gossip"].pop()
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_duplicate_gossip_edge(self):
        a=make_claim(); a["gossip"][1]=copy.deepcopy(a["gossip"][0])
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_revocation_blocks_active_fingerprint(self):
        a=make_claim(); a["revocations"]=[{"fingerprint":a["authorities"][0]["fingerprint"],"at":20,"issuer":"alice"}]
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_duplicate_revocation_fingerprint(self):
        a=make_claim(); r={"fingerprint":H("ghost"),"at":21,"issuer":"alice"};a["revocations"]=[r,dict(r)]
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_same_actor_two_roles(self):
        a=make_claim();a["authorities"][1]["subject"]="alice"
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_same_fingerprint_two_signers(self):
        a=make_claim();a["authorities"][1]["pubkey"]=a["authorities"][0]["pubkey"]
        a["authorities"][1]["fingerprint"]=a["authorities"][0]["fingerprint"]
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_duplicate_provider_os(self):
        a=make_claim();a["providers"][1]["os"]="ubuntu"
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_overlong_gossip(self):
        a=make_claim();a["gossip"].append(dict(a["gossip"][0]))
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_nonascii_identifier_fails_closed(self):
        a=make_claim();a["witnesses"][0]["id"]="çalışan"
        with self.assertRaises(gate.AudienceRejected): verify(a)

    def test_source_module_ast_import_and_call_gate(self):
        tree=ast.parse((ROOT/"safe_public_ci"/"ci_audience_epoch_quarantine.py").read_text())
        imports=set();forbidden={"open","eval","exec","compile","__import__"}
        for item in ast.walk(tree):
            if isinstance(item,ast.Import):
                for alias in item.names: imports.add(alias.name)
            if isinstance(item,ast.ImportFrom): imports.add(item.module)
            if isinstance(item,ast.Call) and isinstance(item.func,ast.Name):
                self.assertNotIn(item.func.id,forbidden)
        self.assertEqual(imports,{"hashlib","hmac","re"})


def view():
    return {"repository":"ftmstr/Embasic-KriptoAI-Autopilot-Build",
            "source_sha":"363c739b23616b4cf0a5282edb0ba0b0019c5846",
            "epoch":7,"size":9,"root":H("root"),"provider_digest":H("provider"),
            "witness_digest":H("witness"),"nonce":H("nonce"),"ack":"PENDING"}


class ViewClassifications(unittest.TestCase):
    def assert_case(self,field,value,expected):
        a=view();b=view();b[field]=value
        self.assertEqual(gate.classify_views(a,b),expected)
        self.assertTrue(expected.endswith(("UNAUTHENTICATED", "NOT_AUTHENTICATED")))

    def test_equal_views_not_authenticated(self):
        self.assertEqual(gate.classify_views(view(),view()),"CLAIMED_EQUAL_VIEWS_NOT_AUTHENTICATED")
    def test_source_fork(self):
        self.assert_case("source_sha","0"*40,"CLAIMED_SOURCE_FORK_UNAUTHENTICATED")
    def test_same_epoch_merkle_fork(self):
        self.assert_case("root",H("other"),"CLAIMED_SAME_EPOCH_MERKLE_FORK_UNAUTHENTICATED")
    def test_provider_receipt_fork(self):
        self.assert_case("provider_digest",H("other"),"CLAIMED_PROVIDER_LOG_SPLIT_UNAUTHENTICATED")
    def test_witness_receipt_fork(self):
        self.assert_case("witness_digest",H("other"),"CLAIMED_WITNESS_RECEIPT_SPLIT_UNAUTHENTICATED")
    def test_nonce_reused_after_epoch(self):
        self.assert_case("epoch",8,"CLAIMED_NONCE_REPLAY_FORK_UNAUTHENTICATED")
    def test_incomparable_ack_state(self):
        self.assert_case("ack","LOST_UNRESOLVED","CLAIMED_INCOMPARABLE_VIEWS_NOT_AUTHENTICATED")
    def test_incomparable_size(self):
        self.assert_case("size",10,"CLAIMED_INCOMPARABLE_VIEWS_NOT_AUTHENTICATED")
    def test_new_nonce(self):
        self.assert_case("nonce",H("new"),"CLAIMED_INCOMPARABLE_VIEWS_NOT_AUTHENTICATED")
    def test_bool_epoch_invalid(self):
        a=view();a["epoch"]=True
        with self.assertRaises(gate.AudienceRejected): gate.classify_views(a,view())
    def test_peer_release_not_part_of_view_schema(self):
        a=view();a["release"]=True
        with self.assertRaises(gate.AudienceRejected): gate.classify_views(a,view())


# Real, disposable SQLite transaction fixtures (no runtime production import).
DB_SCHEMA = """CREATE TABLE state(k INTEGER PRIMARY KEY CHECK(k=1),generation INTEGER NOT NULL,token INTEGER NOT NULL,root TEXT NOT NULL,ack TEXT NOT NULL);
CREATE TABLE nonce(n TEXT PRIMARY KEY);
CREATE TABLE outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,generation INTEGER NOT NULL,nonce TEXT UNIQUE NOT NULL,status TEXT NOT NULL);
INSERT INTO state VALUES(1,1,1,'0000000000000000000000000000000000000000000000000000000000000000','PENDING');"""


def init_db(path):
    db=sqlite3.connect(path,timeout=3)
    try:
        db.executescript(DB_SCHEMA);db.commit()
    finally:db.close()


def snapshot(path):
    db=sqlite3.connect(path)
    try:
        state=db.execute("SELECT generation,token,root,ack FROM state").fetchone()
        rows=db.execute("SELECT generation,nonce,status FROM outbox ORDER BY id").fetchall()
        count=db.execute("SELECT count(*) FROM nonce").fetchone()[0]
        return state,rows,count
    finally:db.close()


def advance(path,old_generation,token,nonce,newroot,fault="normal",delay=0):
    db=sqlite3.connect(path,timeout=3,isolation_level=None)
    try:
        db.execute("PRAGMA busy_timeout=3000")
        db.execute("BEGIN IMMEDIATE")
        state=db.execute("SELECT generation,token FROM state WHERE k=1").fetchone()
        if state[0]!=old_generation or token<=state[1]:
            db.execute("ROLLBACK");return "STALE"
        if delay:
            import time
            time.sleep(delay)
        try:
            db.execute("INSERT INTO nonce VALUES(?)",(nonce,))
        except sqlite3.IntegrityError:
            db.execute("ROLLBACK");return "REPLAY"
        cursor=db.execute("UPDATE state SET generation=?,token=?,root=?,ack='PENDING' WHERE k=1 AND generation=? AND token<?",
                          (old_generation+1,token,newroot,old_generation,token))
        if cursor.rowcount!=1:
            db.execute("ROLLBACK");return "STALE"
        db.execute("INSERT INTO outbox(generation,nonce,status) VALUES(?,?,'PENDING')",(old_generation+1,nonce))
        if fault=="before":
            os._exit(71)
        db.execute("COMMIT")
        if fault=="after":
            os._exit(72)
        return "COMMITTED_ACK_UNKNOWN"
    finally:db.close()


class SQLiteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="rc690_disposable_")
        self.addCleanup(self.tmp.cleanup)
        self.path=os.path.join(self.tmp.name,"one.sqlite")
        init_db(self.path)

    def child(self,path,old,token,nonce,root,fault="normal"):
        cmd=[sys.executable,__file__,"--rc690-child",path,str(old),str(token),nonce,root,fault]
        return subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=18,text=True)

    def test_01_one_atomic_commit(self):
        self.assertEqual(advance(self.path,1,2,H("n"),H("r")),"COMMITTED_ACK_UNKNOWN")
        state,rows,spent=snapshot(self.path)
        self.assertEqual((state[0],state[1],state[2]),(2,2,H("r")))
        self.assertEqual((len(rows),spent), (1,1))

    def test_02_nonce_replay_prevented_on_same_database(self):
        self.assertIn("COMMITTED",advance(self.path,1,2,H("n"),H("r")))
        self.assertEqual(advance(self.path,2,3,H("n"),H("r2")),"REPLAY")
        self.assertEqual(snapshot(self.path)[0][0],2)

    def test_03_stale_epoch_denied(self):
        self.assertIn("COMMITTED",advance(self.path,1,2,H("n"),H("r")))
        self.assertEqual(advance(self.path,1,4,H("n2"),H("r2")),"STALE")

    def test_04_old_fence_denied(self):
        self.assertEqual(advance(self.path,1,1,H("n"),H("r")),"STALE")

    def test_05_fence_cannot_go_backward(self):
        self.assertIn("COMMITTED",advance(self.path,1,9,H("n"),H("r")))
        self.assertEqual(advance(self.path,2,8,H("n2"),H("r2")),"STALE")

    def test_06_crash_before_commit_rolls_back(self):
        r=self.child(self.path,1,3,H("before"),H("r"),"before")
        self.assertEqual(r.returncode,71)
        self.assertEqual(snapshot(self.path),( (1,1,"0"*64,"PENDING"),[],0))

    def test_07_crash_after_commit_pending_ack(self):
        r=self.child(self.path,1,3,H("after"),H("r"),"after")
        self.assertEqual(r.returncode,72)
        self.assertEqual(snapshot(self.path)[0][0],2)
        self.assertEqual(snapshot(self.path)[1][0][2],"PENDING")

    def test_08_after_commit_lost_ack_replay_rejected(self):
        self.assertEqual(self.child(self.path,1,3,H("after"),H("r"),"after").returncode,72)
        self.assertEqual(advance(self.path,2,4,H("after"),H("again")),"REPLAY")

    def test_09_two_separate_process_contenders_one_winner(self):
        cmd=lambda root,nonce:[sys.executable,__file__,"--rc690-child",self.path,"1","2",nonce,root,"normal"]
        a=subprocess.Popen(cmd(H("aroot"),H("anonce")),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        b=subprocess.Popen(cmd(H("broot"),H("bnonce")),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        x,xe=a.communicate(timeout=18);y,ye=b.communicate(timeout=18)
        self.assertEqual((a.returncode,b.returncode),(0,0),xe+ye)
        self.assertEqual(sorted((x.strip(),y.strip())),["COMMITTED_ACK_UNKNOWN","STALE"])
        self.assertEqual(snapshot(self.path)[2],1)

    def test_10_three_real_threads_one_winner(self):
        barrier=threading.Barrier(3);results=[];lock=threading.Lock()
        def task(i):
            barrier.wait()
            r=advance(self.path,1,2,H("nonce"+str(i)),H("root"+str(i)))
            with lock:results.append(r)
        ts=[threading.Thread(target=task,args=(i,)) for i in range(3)]
        for t in ts:t.start()
        for t in ts:t.join(8);self.assertFalse(t.is_alive())
        self.assertEqual(results.count("COMMITTED_ACK_UNKNOWN"),1)
        self.assertEqual(results.count("STALE"),2)

    def test_11_two_disconnected_clones_both_win(self):
        second=os.path.join(self.tmp.name,"two.sqlite")
        shutil.copyfile(self.path,second)
        self.assertIn("COMMITTED",advance(self.path,1,3,H("n1"),H("r1")))
        self.assertIn("COMMITTED",advance(second,1,3,H("n2"),H("r2")))
        self.assertNotEqual(snapshot(self.path)[0][2],snapshot(second)[0][2])

    def test_12_privileged_rollback_reenables_same_nonce(self):
        backup=os.path.join(self.tmp.name,"old.sqlite")
        shutil.copyfile(self.path,backup)
        self.assertIn("COMMITTED",advance(self.path,1,2,H("reuse"),H("r")))
        shutil.copyfile(backup,self.path)
        self.assertIn("COMMITTED",advance(self.path,1,2,H("reuse"),H("r2")))

    def test_13_entire_database_and_local_anchor_can_be_rolled_back(self):
        external=os.path.join(self.tmp.name,"local-claimed-anchor.txt")
        Path(external).write_text("generation=1")
        db_backup=os.path.join(self.tmp.name,"backup.sqlite")
        shutil.copyfile(self.path,db_backup)
        self.assertIn("COMMITTED",advance(self.path,1,2,H("n"),H("r")))
        Path(external).write_text("generation=2")
        shutil.copyfile(db_backup,self.path)
        Path(external).write_text("generation=1")
        self.assertEqual(snapshot(self.path)[0][0],1)
        self.assertEqual(Path(external).read_text(),"generation=1")

    def test_14_local_outbox_status_can_be_forged_without_provider_signature(self):
        self.assertIn("COMMITTED",advance(self.path,1,2,H("n"),H("r")))
        db=sqlite3.connect(self.path)
        try:
            db.execute("UPDATE outbox SET status='CLAIMED_SIGNED_ACK'");db.commit()
        finally:db.close()
        self.assertEqual(snapshot(self.path)[1][0][2],"CLAIMED_SIGNED_ACK")
        self.assertFalse(verify(make_claim())["external_ack_verified"])

    def test_15_snapshot_generation_fence_blocks_aba_until_privileged_reset(self):
        self.assertIn("COMMITTED",advance(self.path,1,2,H("n1"),H("r1")))
        self.assertIn("COMMITTED",advance(self.path,2,3,H("n2"),"0"*64))
        self.assertEqual(advance(self.path,1,4,H("n3"),H("r3")),"STALE")
        self.assertEqual(snapshot(self.path)[0][0],3)

    def test_16_ack_lost_does_not_prove_remote_order_seen(self):
        self.assertEqual(self.child(self.path,1,2,H("n"),H("r"),"after").returncode,72)
        self.assertEqual(snapshot(self.path)[1][0][2],"PENDING")
        self.assertFalse(verify(make_claim())["live_trading_allowed"])


if __name__=="__main__":
    if len(sys.argv)>1 and sys.argv[1]=="--rc690-child":
        result=advance(sys.argv[2],int(sys.argv[3]),int(sys.argv[4]),sys.argv[5],sys.argv[6],sys.argv[7])
        print(result,flush=True)
    else:
        unittest.main()
