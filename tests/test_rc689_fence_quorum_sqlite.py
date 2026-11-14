"""RC689: fabricated multi-witness authority claims and disposable real SQLite CAS.

Real SQLite subprocess tests establish local behavior only.  No user orders,
exchange connectivity, external trust, production durability or real signer keys.
"""
import ast
import copy
import hashlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from safe_public_ci import ci_fenced_quorum_quarantine as q


def h(n):
    return hashlib.sha256(str(n).encode("ascii")).hexdigest()


def fixture():
    history = [h(100+i) for i in range(4)]
    root = q._root(history)
    witnesses = [
        {"id": "witness_%d" % i, "fingerprint": h(i+1), "seq": 1,
         "epoch": 1, "root": root, "prev_receipt": h(50+i),
         "signer_role": ("owner", "reviewer", "observer")[i],
         "signature": format(i+1, "x")*128, "reported_at": 100}
        for i in range(3)]
    providers = [
        {"platform": platform, "run": 500+i, "job": 700+i,
         "attempt": 1, "log_sha256": h(60+i),
         "signed_receipt": format(i+4,"x")*128,
         "provider_key_fingerprint": h(80+i)}
        for i, platform in enumerate(("ubuntu", "windows"))]
    return {
        "repo": "ftmstr/Embasic-KriptoAI-Autopilot-Build",
        "branch": "validation/rc654-pr1-rc653-combined-ci",
        "head": "a"*40, "issued": 100,
        "witnesses": witnesses, "providers": providers,
        "rotation": [h(91),h(92)], "revocations": [],
        "checkpoints": {"size":4, "root":root, "old_size":2,
                        "old_root":q._root(history[:2]), "history":history,
                        "inclusion_index":2,"inclusion_leaf":history[2],
                        "inclusion_proof":q._inclusion(history,2),
                        "external_anchor":root},
        "fence": {"generation":1,"token":h(30),"lease_epoch":1,
                  "previous_token":h(29),"nonce":h(32),
                  "outbox_sequence":1,"writer_id":"writer1","ack_state":"lost_ack"},
        "ack": {"provider":"ubuntu","nonce":h(32),"outbox_sequence":1,
                "claimed_ack_sha256":h(33),"ack_authorized":False},
        "claims_authenticated": False,"allow_live":False}


def pins(b):
    return {"repo":b["repo"], "branch":b["branch"],"head":b["head"],
            "expected_sha256":q.claimed_digest(b),
            "trust_root_authenticated":False,
            "provider_signature_authenticated":False,
            "immutable_anchor_authenticated":False,
            "durable_cas_authenticated":False}


class RC689SyntacticQuarantine(unittest.TestCase):
    def test_valid_claim_never_authenticates(self):
        b=fixture()
        result=q.evaluate_untrusted_bundle(b,pins(b))
        self.assertEqual(result["status"],"CONSISTENT_CALLER_CLAIMS_QUARANTINED_NOT_AUTHENTICATED")
        self.assertTrue(all(v is False for k,v in result.items() if k not in ("status","claim_sha256")))
        self.assertEqual(result["claim_sha256"],pins(b)["expected_sha256"])

    def test_valid_claim_is_deterministic(self):
        b=fixture()
        self.assertEqual(q.claimed_digest(b),q.claimed_digest(copy.deepcopy(b)))

    def test_mutations_bound_to_digest(self):
        b=fixture(); p=pins(b)
        b["fence"]["nonce"]=h(99)
        with self.assertRaises(q.QuarantineRejected):
            q.evaluate_untrusted_bundle(b,p)

    def test_mocked_nonexistent_authority_self_claims_rejected(self):
        for key in ("trust_root_authenticated","provider_signature_authenticated",
                    "immutable_anchor_authenticated","durable_cas_authenticated"):
            b=fixture(); p=pins(b); p[key]=True
            with self.subTest(key=key),self.assertRaises(q.QuarantineRejected):
                q.evaluate_untrusted_bundle(b,p)

    def test_inclusion_cryptographic_structure_math_not_authority(self):
        b=fixture(); cp=b["checkpoints"]
        self.assertEqual(q._root(cp["history"]),cp["root"])
        self.assertEqual(q._inclusion(cp["history"],cp["inclusion_index"]),cp["inclusion_proof"])
        self.assertIs(q.evaluate_untrusted_bundle(b,pins(b))["external_merkle_anchor_authenticated"],False)

    def test_source_import_and_dynamic_call_gate(self):
        src=Path(__file__).resolve().parents[1]/"safe_public_ci"/"ci_fenced_quorum_quarantine.py"
        tree=ast.parse(src.read_text(encoding="utf8"))
        imports=[]; forbidden=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                imports.extend(a.name for a in node.names)
            if isinstance(node,ast.ImportFrom):
                imports.append(node.module)
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in (
                    "eval","exec","open","compile","__import__"):
                forbidden.append(node.func.id)
        self.assertEqual(imports,["hashlib","hmac","re"])
        self.assertEqual(forbidden,[])

    def test_unbounded_declaration_rejected(self):
        b=fixture(); b["checkpoints"]["history"]=[h(x) for x in range(33)]
        with self.assertRaises(q.QuarantineRejected):
            q.evaluate_untrusted_bundle(b,pins(b))


# Each named input is a separate original regression, not merely a subtest.
MUTATIONS = [
    ("missing_top_key",lambda x:x.pop("issued")),
    ("unexpected_top_key",lambda x:x.update({"secret":"fake"})),
    ("wrong_public_repo",lambda x:x.update(repo="user/private")),
    ("wrong_validation_branch",lambda x:x.update(branch="main")),
    ("non_hex_head",lambda x:x.update(head="Z"*40)),
    ("head_wrong_length",lambda x:x.update(head="a"*39)),
    ("bool_issued",lambda x:x.update(issued=True)),
    ("zero_issued",lambda x:x.update(issued=0)),
    ("fake_authenticated_claim",lambda x:x.update(claims_authenticated=True)),
    ("fake_live_claim",lambda x:x.update(allow_live=True)),
    ("duplicate_witness_id",lambda x:x["witnesses"][1].update(id=x["witnesses"][0]["id"])),
    ("duplicate_signer_key",lambda x:x["witnesses"][1].update(fingerprint=x["witnesses"][0]["fingerprint"])),
    ("duplicate_claim_signature",lambda x:x["witnesses"][1].update(signature=x["witnesses"][0]["signature"])),
    ("one_witness_only",lambda x:x["witnesses"].pop()),
    ("missing_witness_role",lambda x:x["witnesses"][0].update(signer_role="observer")),
    ("invalid_witness_role",lambda x:x["witnesses"][0].update(signer_role="root")),
    ("witness_non_hex_key",lambda x:x["witnesses"][0].update(fingerprint="g"*64)),
    ("witness_non_hex_signature",lambda x:x["witnesses"][0].update(signature="x"*128)),
    ("witness_too_short_signature",lambda x:x["witnesses"][0].update(signature="1"*64)),
    ("witness_negative_sequence",lambda x:x["witnesses"][0].update(seq=-1)),
    ("witness_bool_epoch",lambda x:x["witnesses"][0].update(epoch=True)),
    ("witness_wrong_merkle_root",lambda x:x["witnesses"][0].update(root=h(999))),
    ("witness_unreported_clock",lambda x:x["witnesses"][0].update(reported_at=0)),
    ("witness_unexpected_field",lambda x:x["witnesses"][0].update(authenticated=True)),
    ("provider_wrong_platform",lambda x:x["providers"][0].update(platform="real")),
    ("provider_duplicate_platform",lambda x:x["providers"][1].update(platform="ubuntu")),
    ("provider_duplicate_key",lambda x:x["providers"][1].update(provider_key_fingerprint=x["providers"][0]["provider_key_fingerprint"])),
    ("provider_duplicate_receipt",lambda x:x["providers"][1].update(signed_receipt=x["providers"][0]["signed_receipt"])),
    ("provider_bad_log_digest",lambda x:x["providers"][0].update(log_sha256="x"*64)),
    ("provider_missing_run",lambda x:x["providers"][0].update(run=0)),
    ("provider_bool_job",lambda x:x["providers"][0].update(job=True)),
    ("provider_bad_attempt",lambda x:x["providers"][0].update(attempt=2)),
    ("provider_bool_attempt",lambda x:x["providers"][0].update(attempt=True)),
    ("provider_short_receipt",lambda x:x["providers"][0].update(signed_receipt="1"*127)),
    ("provider_key_same_as_owner",lambda x:x["providers"][0].update(provider_key_fingerprint=x["witnesses"][0]["fingerprint"])),
    ("rotation_duplicate_key",lambda x:x.update(rotation=[h(91),h(91)])),
    ("rotation_bad_count",lambda x:x.update(rotation=[h(91)])),
    ("rotation_invalid_hex",lambda x:x.update(rotation=[h(91),"G"*64])),
    ("revocation_duplicate",lambda x:x.update(revocations=[{"fingerprint":h(3),"revoked_at":101}]*2)),
    ("revocation_non_hex_key",lambda x:x.update(revocations=[{"fingerprint":"x"*64,"revoked_at":101}])),
    ("revocation_bool_time",lambda x:x.update(revocations=[{"fingerprint":h(3),"revoked_at":True}])),
    ("revoked_before_witness_claim",lambda x:x.update(revocations=[{"fingerprint":h(1),"revoked_at":99}])),
    ("checkpoint_history_changed",lambda x:x["checkpoints"]["history"].__setitem__(1,h(300))),
    ("checkpoint_wrong_old_size",lambda x:x["checkpoints"].update(old_size=4)),
    ("checkpoint_old_root_wrong",lambda x:x["checkpoints"].update(old_root=h(300))),
    ("checkpoint_missing_leaf",lambda x:x["checkpoints"].update(inclusion_leaf=h(444))),
    ("checkpoint_bad_inclusion_index",lambda x:x["checkpoints"].update(inclusion_index=4)),
    ("checkpoint_proof_mutated",lambda x:x["checkpoints"]["inclusion_proof"].__setitem__(0,h(500))),
    ("checkpoint_fake_external_anchor",lambda x:x["checkpoints"].update(external_anchor=h(550))),
    ("checkpoint_extra_proof_segment",lambda x:x["checkpoints"]["inclusion_proof"].append(h(600))),
    ("checkpoint_wrong_total_size",lambda x:x["checkpoints"].update(size=3)),
    ("fence_aba_same_previous_token",lambda x:x["fence"].update(previous_token=x["fence"]["token"])),
    ("fence_repeated_generation_zero",lambda x:x["fence"].update(generation=0)),
    ("fence_bool_lease_epoch",lambda x:x["fence"].update(lease_epoch=True)),
    ("fence_bad_nonce",lambda x:x["fence"].update(nonce="A"*64)),
    ("fence_wrong_ack_state",lambda x:x["fence"].update(ack_state="provider_verified")),
    ("fence_outbox_negative",lambda x:x["fence"].update(outbox_sequence=-1)),
    ("fence_invalid_writer",lambda x:x["fence"].update(writer_id="/admin")),
    ("ack_wrong_nonce",lambda x:x["ack"].update(nonce=h(900))),
    ("ack_wrong_sequence",lambda x:x["ack"].update(outbox_sequence=2)),
    ("ack_true_self_verified",lambda x:x["ack"].update(ack_authorized=True)),
    ("ack_unknown_provider",lambda x:x["ack"].update(provider="private")),
    ("ack_non_hex_digest",lambda x:x["ack"].update(claimed_ack_sha256="invalid")),
]


def make_mutation_case(transform):
    def test(self):
        b=fixture()
        transform(b)
        with self.assertRaises(q.QuarantineRejected):
            q.evaluate_untrusted_bundle(b,pins(b))
    return test

for name, mutate in MUTATIONS:
    setattr(RC689SyntacticQuarantine, "test_mutation_"+name,make_mutation_case(mutate))


class RC689ClaimedFork(unittest.TestCase):
    def view(self):
        return {"witness":"witness_0","fingerprint":h(1),"seq":1,"epoch":1,
                "root":h(11),"provider_log":h(12),"nonce":h(13),"token":h(14)}

    def case(self,key,val,expected):
        a=self.view(); b=copy.deepcopy(a);b[key]=val
        out=q.detect_claimed_fork(a,b)
        self.assertEqual(out["category"],expected)
        self.assertIs(out["witness_authority_authenticated"],False)
        self.assertIs(out["immutable_checkpoint_authenticated"],False)
        self.assertIs(out["live_trading_allowed"],False)

    def test_same_view_unauthenticated(self):
        self.case("seq",1,"SAME_UNTRUSTED_VIEW")
    def test_merkle_root_fork(self):
        self.case("root",h(20),"CLAIMED_MERKLE_EQUIVOCATION")
    def test_provider_log_fork(self):
        self.case("provider_log",h(20),"CLAIMED_PROVIDER_LOG_EQUIVOCATION")
    def test_fence_token_fork(self):
        self.case("token",h(20),"CLAIMED_FENCE_TOKEN_EQUIVOCATION")
    def test_nonce_fork(self):
        self.case("nonce",h(20),"CLAIMED_NONCE_REPLAY_FORK")
    def test_epoch_transition_not_authenticated(self):
        self.case("epoch",2,"UNAUTHENTICATED_EPOCH_TRANSITION")
    def test_seq_transition_not_authenticated(self):
        self.case("seq",2,"UNAUTHENTICATED_SEQUENCE_TRANSITION")
    def test_disjoint_id_cannot_be_assumed_equivocation(self):
        a=self.view(); b=self.view();b["witness"]="another_0"
        with self.assertRaises(q.QuarantineRejected):q.detect_claimed_fork(a,b)
    def test_same_id_different_key_cannot_be_assumed_identity(self):
        a=self.view(); b=self.view();b["fingerprint"]=h(21)
        with self.assertRaises(q.QuarantineRejected):q.detect_claimed_fork(a,b)
    def test_bad_schema_cannot_authenticate(self):
        a=self.view();b=self.view();b["real_signed"]=True
        with self.assertRaises(q.QuarantineRejected):q.detect_claimed_fork(a,b)


SCHEMA="""
CREATE TABLE cas (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL,
 token TEXT NOT NULL, lease_epoch INTEGER NOT NULL, root TEXT NOT NULL);
INSERT INTO cas VALUES (1,1,'t1',1,'r1');
CREATE TABLE nonces (nonce TEXT PRIMARY KEY);
CREATE TABLE outbox (nonce TEXT PRIMARY KEY, generation INTEGER NOT NULL,
 root TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('PENDING','CLAIMED_ACK')));
"""

# Test-only stand-alone subprocess; never in safe_public_ci or production app.
WORKER="""
import os,sys,sqlite3
path,mode,nonce,expected_gen,expected_token,lease=sys.argv[1:]
c=sqlite3.connect(path,timeout=10,isolation_level=None)
try:
    c.execute('BEGIN IMMEDIATE')
    row=c.execute('SELECT generation,token,lease_epoch FROM cas WHERE id=1').fetchone()
    if row!=(int(expected_gen),expected_token,int(lease)):
        c.execute('ROLLBACK'); print('STALE'); sys.exit(0)
    if c.execute('SELECT nonce FROM nonces WHERE nonce=?',(nonce,)).fetchone():
        c.execute('ROLLBACK'); print('REPLAY'); sys.exit(0)
    c.execute('INSERT INTO nonces(nonce) VALUES (?)',(nonce,))
    c.execute('UPDATE cas SET generation=generation+1,token=?,lease_epoch=lease_epoch+1,root=? WHERE id=1',('t'+str(row[0]+1),'r'+str(row[0]+1)))
    c.execute('INSERT INTO outbox VALUES (?,?,?,?)',(nonce,row[0]+1,'r'+str(row[0]+1),'PENDING'))
    if mode=='CRASH_BEFORE':os._exit(61)
    c.execute('COMMIT')
    if mode=='CRASH_AFTER':os._exit(62)
    print('COMMIT')
finally:c.close()
"""


class RC689RealDisposableSQLite(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="rc689_")
        self.path=str(Path(self.tmp.name)/"cas.db")
        c=sqlite3.connect(self.path)
        try:c.executescript(SCHEMA);c.commit()
        finally:c.close()

    def tearDown(self):
        self.tmp.cleanup()

    def connect(self,path=None):
        return sqlite3.connect(path or self.path,timeout=10)

    def state(self,path=None):
        c=self.connect(path)
        try:return (c.execute("SELECT generation,token,lease_epoch,root FROM cas").fetchone(),
                    c.execute("SELECT nonce FROM nonces ORDER BY nonce").fetchall(),
                    c.execute("SELECT nonce,generation,root,status FROM outbox ORDER BY nonce").fetchall())
        finally:c.close()

    def run_worker(self,mode="COMMIT",nonce="nonce1",gen=1,token="t1",lease=1,path=None):
        return subprocess.run([sys.executable,"-c",WORKER,path or self.path,mode,nonce,
                               str(gen),token,str(lease)],capture_output=True,text=True,timeout=20)

    def test_commit_atomically_updates_state_nonce_outbox(self):
        p=self.run_worker(); self.assertEqual((p.returncode,p.stdout.strip()),(0,"COMMIT"),p.stderr)
        state,nonces,outbox=self.state()
        self.assertEqual(state,(2,"t2",2,"r2"))
        self.assertEqual(nonces,[("nonce1",)])
        self.assertEqual(outbox,[("nonce1",2,"r2","PENDING")])

    def test_crash_before_commit_rolls_back_all(self):
        p=self.run_worker("CRASH_BEFORE");self.assertEqual(p.returncode,61,p.stderr)
        self.assertEqual(self.state(),((1,"t1",1,"r1"),[],[]))

    def test_crash_after_commit_durable_reopen_but_ack_lost(self):
        p=self.run_worker("CRASH_AFTER");self.assertEqual(p.returncode,62,p.stderr)
        self.assertEqual(self.state()[0][0],2)
        self.assertEqual(self.state()[2][0][3],"PENDING")

    def test_same_nonce_replay_after_restart_is_stale(self):
        self.assertEqual(self.run_worker().stdout.strip(),"COMMIT")
        self.assertEqual(self.run_worker().stdout.strip(),"STALE")
        self.assertEqual(len(self.state()[1]),1)

    def test_stale_fencing_token_fails_closed(self):
        p=self.run_worker(token="t0");self.assertEqual(p.stdout.strip(),"STALE")
        self.assertEqual(self.state()[0][0],1)

    def test_stale_lease_epoch_fails_closed(self):
        p=self.run_worker(lease=0);self.assertEqual(p.stdout.strip(),"STALE")

    def test_second_generation_new_nonce_can_commit(self):
        self.assertEqual(self.run_worker().stdout.strip(),"COMMIT")
        self.assertEqual(self.run_worker(nonce="nonce2",gen=2,token="t2",lease=2).stdout.strip(),"COMMIT")
        self.assertEqual(self.state()[0][0],3)
        self.assertEqual(len(self.state()[2]),2)

    def test_duplicate_nonce_cannot_commit_in_new_generation(self):
        self.run_worker();p=self.run_worker(nonce="nonce1",gen=2,token="t2",lease=2)
        self.assertEqual(p.stdout.strip(),"REPLAY")
        self.assertEqual(self.state()[0][0],2)

    def test_two_true_process_contenders_single_winner(self):
        results=[]
        def launch(n):results.append(self.run_worker(nonce=f"nonce{n}"))
        a=threading.Thread(target=launch,args=(1,));b=threading.Thread(target=launch,args=(2,))
        a.start();b.start();a.join();b.join()
        self.assertEqual(sorted(x.stdout.strip() for x in results),["COMMIT","STALE"])
        self.assertEqual(len(self.state()[2]),1)

    def test_three_true_process_contenders_single_winner(self):
        results=[]
        def launch(n):results.append(self.run_worker(nonce=f"nonce{n}"))
        ts=[threading.Thread(target=launch,args=(i,)) for i in (1,2,3)]
        for t in ts:t.start()
        for t in ts:t.join()
        self.assertEqual(sorted(x.stdout.strip() for x in results),["COMMIT","STALE","STALE"])

    def test_disconnected_full_db_copy_allows_double_winner(self):
        other=str(Path(self.tmp.name)/"fork.db")
        Path(other).write_bytes(Path(self.path).read_bytes())
        a=self.run_worker(nonce="nonce1");b=self.run_worker(nonce="nonce2",path=other)
        self.assertEqual((a.stdout.strip(),b.stdout.strip()),("COMMIT","COMMIT"))
        self.assertEqual(self.state()[0][0],2)
        self.assertEqual(self.state(other)[0][0],2)
        self.assertNotEqual(self.state()[1],self.state(other)[1])

    def test_privileged_db_rollback_reenables_old_nonce_and_gen(self):
        self.assertEqual(self.run_worker().stdout.strip(),"COMMIT")
        c=self.connect()
        try:
            c.executescript("UPDATE cas SET generation=1,token='t1',lease_epoch=1,root='r1';"
                            "DELETE FROM nonces; DELETE FROM outbox;")
            c.commit()
        finally:c.close()
        self.assertEqual(self.run_worker().stdout.strip(),"COMMIT")
        # A privileged rollback defeats local replay/monotonicity despite local CAS.
        self.assertEqual(self.state()[0][0],2)

    def test_old_snapshot_restore_defeats_local_fence(self):
        pristine=Path(self.path).read_bytes()
        self.assertEqual(self.run_worker().stdout.strip(),"COMMIT")
        Path(self.path).write_bytes(pristine)
        self.assertEqual(self.run_worker().stdout.strip(),"COMMIT")

    def test_claimed_ack_is_not_authenticated_remote_provider(self):
        self.run_worker()
        c=self.connect()
        try:
            c.execute("UPDATE outbox SET status='CLAIMED_ACK' WHERE nonce='nonce1'")
            c.commit()
        finally:c.close()
        self.assertEqual(self.state()[2][0][3],"CLAIMED_ACK")
        # No remote provider was contacted; this is a local self-claim only.
        self.assertNotIn("EXTERNAL_AUTHENTICATION",repr(self.state()))

    def test_pending_outbox_survives_local_process_restart(self):
        self.run_worker();self.assertEqual(self.state()[2][0][3],"PENDING")
        again=self.connect()
        try:self.assertEqual(again.execute("SELECT status FROM outbox").fetchone()[0],"PENDING")
        finally:again.close()

    def test_same_actor_restoring_db_and_text_anchor_undetectable_locally(self):
        anchor=Path(self.tmp.name)/"anchor.txt"
        anchor.write_text("r1",encoding="ascii")
        backup=Path(self.path).read_bytes()
        self.run_worker();anchor.write_text("r2",encoding="ascii")
        Path(self.path).write_bytes(backup);anchor.write_text("r1",encoding="ascii")
        self.assertEqual(self.state()[0][3],anchor.read_text(encoding="ascii"))
        # Matching *local* anchor never proves an immutable independent witness.


if __name__ == "__main__":
    unittest.main()
