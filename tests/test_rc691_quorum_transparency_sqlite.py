"""RC691 original hostile claimed quorum/gossip and disposable SQLite audit.

Production authority, immutable anchoring, signed ACK and durable multi-host
CAS are deliberately ABSENT. This fixture never touches credentials/exchanges.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import closing

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))
from safe_public_ci import ci_quorum_transparency_quarantine as gate


def h(s):
    return hashlib.sha256(str(s).encode("ascii")).hexdigest()


def good(n=7,old=3):
    leaves=[h("RC691-leaf-"+str(i)) for i in range(n)]
    root=gate.merkle_root(leaves)
    prev=gate.merkle_root(leaves[:old])
    wg=[{"id":name,"admin_group":group,"key_fingerprint":h("wg-"+name),
         "epoch":17,"size":n,"root":root,"receipt_digest":h("receipt-"+name)}
        for name,group in (("alpha","groupa"),("beta","groupb"),("gamma","groupc"))]
    return {
        "repo":"ftmstr/Embasic-KriptoAI-Autopilot-Build",
        "branch":"validation/rc654-pr1-rc653-combined-ci",
        "base":"6f15a509864b20214442838d76087c1dccbfb74d",
        "source_digest":h("code"),"workflow_digest":h("workflow"),
        "leaves":leaves,"old_size":old,"old_root":prev,"new_root":root,
        "authorities":[{"role":role,"subject":who,"admin_group":domain,
                        "public_fingerprint":h("pub-"+role),
                        "claimed_ed25519_signature":h("fake-sig-"+role),
                        "valid_from":3,"valid_until":100,"revoked_at":None}
                       for role,who,domain in (("owner","alice","owneradmin"),("reviewer","bob","reviewadmin"))],
        "providers":[{"os":osname,"run":run,"job":job,"attempt":1,
                      "log_sha256":h("provider-"+osname),"workflow_digest":h("workflow"),
                      "claimed_signature":h("provider-fake-sig-"+osname)}
                     for osname,run,job in (("ubuntu",43496729228,132131650101),
                                            ("windows",43496729268,132131650175))],
        "witnesses":wg,
        "gossip":[{"sender":s["id"],"recipient":r["id"],"epoch":17,"size":n,
                   "root":root,"receipt_digest":s["receipt_digest"]}
                  for s in wg for r in wg if s is not r],
        "anchor":{"witness":"untrustedanchor","root":root,"epoch":17,
                  "claimed_immutable":True,"claimed_signed":True},
        "fence":{"generation_before":12,"generation_after":13,
                 "token_before":21,"token_after":22,
                 "lease_start":9,"lease_end":90,"observed_at":17,"nonce":h("nonce")},
        "outbox":{"state":"PENDING","remote_ack":False,"ack_digest":h("ACK"),"receipt_claim":"CLAIMED_ACK"},
        "release":False,
        "trusted":{name:False for name in gate._TRUST},
    }


def pins(d):
    return {"base":d["base"],"source_digest":d["source_digest"],
            "workflow_digest":d["workflow_digest"],"old_root":d["old_root"],
            "new_root":d["new_root"],"transcript":gate.snapshot_digest(d)}


def validate(d):
    return gate.audit(d,pins(d))


class QuorumTests(unittest.TestCase):
    def test_baseline_quarantined_not_authenticated(self):
        result=validate(good())
        self.assertTrue(result["claimed_full_mesh_consistent"])
        self.assertTrue(result["claimed_merkle_prefix_consistent"])
        self.assertTrue(result["mathematical_inclusion_only"])
        self.assertIn("QUARANTINED_NOT_AUTHENTICATED",result["status"])
        for k,v in result.items():
            if k.endswith("authenticated") or k.endswith("verified") or k.endswith("allowed") or k.endswith("ready"):
                self.assertIs(v,False,k)

    def test_positive_claimed_immutability_does_not_authenticate(self):
        self.assertFalse(validate(good())["immutable_external_checkpoint_authenticated"])

    def test_positive_claimed_ed25519_fingerprint_does_not_authenticate(self):
        self.assertFalse(validate(good())["ed25519_owner_authority_authenticated"])

    def test_signature_shape_is_not_crypto_verification(self):
        d=good()
        d["authorities"][0]["claimed_ed25519_signature"]=h("totally forged")
        self.assertFalse(validate(d)["ed25519_owner_authority_authenticated"])

    def test_even_matching_provider_digest_not_authenticated(self):
        self.assertFalse(validate(good())["provider_signed_logs_authenticated"])

    def test_external_provider_ack_unresolved(self):
        self.assertFalse(validate(good())["remote_ack_verified"])

    def test_immutable_external_checkpoint_unresolved(self):
        self.assertFalse(validate(good())["immutable_external_checkpoint_authenticated"])

    def test_prod_cas_unresolved(self):
        self.assertFalse(validate(good())["production_durable_cas_verified"])

    def test_changing_nonce_changes_domain_digest(self):
        a=good();b=copy.deepcopy(a)
        b["fence"]["nonce"]=h("another")
        self.assertNotEqual(gate.snapshot_digest(a),gate.snapshot_digest(b))

    def test_wrong_caller_pinned_transcript_fails(self):
        a=good();p=pins(a);p["transcript"]=h("not same")
        with self.assertRaises(gate.EvidenceRejected):gate.audit(a,p)

    def test_wrong_caller_pinned_old_root_fails(self):
        a=good();p=pins(a);p["old_root"]=h("missing external source")
        with self.assertRaises(gate.EvidenceRejected):gate.audit(a,p)

    def test_unhashable_data_type_rejected(self):
        a=good();a["anchor"]["witness"]=object()
        with self.assertRaises(gate.EvidenceRejected):gate.snapshot_digest(a)

    def test_canonical_ascii_disallows_unicode(self):
        a=good();a["anchor"]["witness"]="özel"
        with self.assertRaises(gate.EvidenceRejected):gate.snapshot_digest(a)

    def test_merkle_inclusion_non_power_two(self):
        for n in range(2,32):
            leaves=good(n=n,old=1)["leaves"]
            root=gate.merkle_root(leaves)
            for i in range(n):
                proof=gate.inclusion_proof(leaves,i)
                self.assertTrue(gate.inclusion_matches(leaves[i],i,n,proof,root),(n,i))

    def test_merkle_rejects_changed_leaf(self):
        a=good()
        proof=gate.inclusion_proof(a["leaves"],6)
        self.assertFalse(gate.inclusion_matches(h("fake"),6,7,proof,a["new_root"]))

    def test_merkle_rejects_changed_sibling(self):
        a=good();proof=gate.inclusion_proof(a["leaves"],3)
        proof[0]=h("fake")
        self.assertFalse(gate.inclusion_matches(a["leaves"][3],3,7,proof,a["new_root"]))

    def test_merkle_rejects_claimed_root_change(self):
        a=good();proof=gate.inclusion_proof(a["leaves"],4)
        self.assertFalse(gate.inclusion_matches(a["leaves"][4],4,7,proof,h("different")))

    def test_nonempty_history_is_not_immutable(self):
        a=good();a["anchor"]["claimed_immutable"]=False
        self.assertFalse(validate(a)["immutable_external_checkpoint_authenticated"])

    def test_revocation_claim_does_not_prove_chronology(self):
        a=good();a["authorities"][0]["revoked_at"]=23
        self.assertFalse(validate(a)["revocation_and_clock_authenticated"])

    def test_transcript_pin_does_not_prove_witness_rights(self):
        a=good();self.assertEqual(pins(a)["transcript"],gate.snapshot_digest(a))
        self.assertFalse(validate(a)["ed25519_owner_authority_authenticated"])

    def test_unauthorized_claimed_signed_anchor_does_not_authenticate(self):
        a=good();a["anchor"]["claimed_signed"]=True
        self.assertFalse(validate(a)["immutable_external_checkpoint_authenticated"])

    def test_malformed_inclusion_path_rejected(self):
        a=good();p=gate.inclusion_proof(a["leaves"],3)
        with self.assertRaises(gate.EvidenceRejected):
            gate.inclusion_matches(a["leaves"][3],3,7,p+["z"],a["new_root"])

    def test_old_size_positive_prefix(self):
        for n in [3,5,9,15,31,64]:
            for old in [1,2,n-1]:
                a=good(n,old)
                self.assertEqual(gate.merkle_root(a["leaves"][:old]),a["old_root"])
                validate(a)

    def test_bools_are_not_valid_ints(self):
        for key in ("generation_after","token_after","lease_end"):
            a=good();a["fence"][key]=True
            with self.assertRaises(gate.EvidenceRejected):validate(a)

    def test_classified_cross_audience_variations_never_authenticated(self):
        d={"audience":"clienta","epoch":17,"size":7,"root":h("r"),"provider_digest":h("p"),
           "receipt_digest":h("w"),"source_digest":h("s")}
        changes=[("root",h("other"),"MERKLE_FORK"),("provider_digest",h("other"),"PROVIDER_LOG_FORK"),
                 ("receipt_digest",h("other"),"RECEIPT_FORK"),("source_digest",h("other"),"SOURCE_FORK"),
                 ("size",9,"INCOMPARABLE"),("epoch",18,"INCOMPARABLE")]
        for key,value,expect in changes:
            newer=dict(d);newer[key]=value
            self.assertIn(expect,gate.compare_views(d,newer))
            self.assertIn("NOT_AUTHENTICATED",gate.compare_views(d,newer))

    def test_equal_claims_are_still_not_verified(self):
        d={"audience":"clienta","epoch":17,"size":7,"root":h("r"),"provider_digest":h("p"),
           "receipt_digest":h("w"),"source_digest":h("s")}
        self.assertEqual(gate.compare_views(d,dict(d)),"CLAIMED_EQUAL_VIEWS_NOT_AUTHENTICATED")

    def test_client_audience_alias_does_not_grant_independence(self):
        d={"audience":"clienta","epoch":17,"size":7,"root":h("r"),"provider_digest":h("p"),
           "receipt_digest":h("w"),"source_digest":h("s")}
        e=dict(d);e["audience"]="clientb"
        self.assertEqual(gate.compare_views(d,e),"CLAIMED_EQUAL_VIEWS_NOT_AUTHENTICATED")

    def test_ast_import_allowlist_and_forbidden_dynamic_calls(self):
        source=(ROOT/"safe_public_ci"/"ci_quorum_transparency_quarantine.py").read_text(encoding="utf-8")
        tree=ast.parse(source)
        imp=[]; calls=[]
        for n in ast.walk(tree):
            if isinstance(n,ast.Import): imp.extend(x.name for x in n.names)
            if isinstance(n,ast.ImportFrom): imp.append("FROM:"+str(n.module))
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in ("open","eval","exec","compile","__import__"):
                calls.append(n.func.id)
        self.assertEqual(imp,["hashlib","hmac","re"])
        self.assertEqual(calls,[])

    def test_public_scope_constants(self):
        a=good()
        self.assertEqual((a["repo"],a["branch"],a["base"]),(gate._REPO,gate._BRANCH,gate._BASE))


# Each mutation is an independent named unittest exercising a distinct hostile shape.
MUTATIONS = [
    ("repository_public_scope",lambda x:x.__setitem__("repo","ftmstr/other")),
    ("branch_public_scope",lambda x:x.__setitem__("branch","main")),
    ("base_sha",lambda x:x.__setitem__("base","0"*40)),
    ("source_digest_invalid",lambda x:x.__setitem__("source_digest","f"*63)),
    ("workflow_digest_invalid",lambda x:x.__setitem__("workflow_digest","G"*64)),
    ("leaves_empty",lambda x:x.__setitem__("leaves",[])),
    ("leaves_too_many",lambda x:x.__setitem__("leaves",[h(str(i)) for i in range(65)])),
    ("leaf_invalid_hex",lambda x:x["leaves"].__setitem__(0,"0"*63)),
    ("leaf_uppercase",lambda x:x["leaves"].__setitem__(0,"A"*64)),
    ("old_size_zero",lambda x:x.__setitem__("old_size",0)),
    ("old_size_equal",lambda x:x.__setitem__("old_size",7)),
    ("old_size_bool",lambda x:x.__setitem__("old_size",True)),
    ("old_root_forged",lambda x:x.__setitem__("old_root",h("old"))),
    ("new_root_forged",lambda x:x.__setitem__("new_root",h("new"))),
    ("authority_count_missing",lambda x:x.__setitem__("authorities",x["authorities"][:1])),
    ("authority_count_extra",lambda x:x["authorities"].append(dict(x["authorities"][0]))),
    ("owner_role_swapped",lambda x:x["authorities"][0].__setitem__("role","reviewer")),
    ("reviewer_role_swapped",lambda x:x["authorities"][1].__setitem__("role","owner")),
    ("owner_subject_alias",lambda x:x["authorities"][0].__setitem__("subject","bob")),
    ("authority_admin_alias",lambda x:x["authorities"][1].__setitem__("admin_group","owneradmin")),
    ("authority_key_alias",lambda x:x["authorities"][1].__setitem__("public_fingerprint",x["authorities"][0]["public_fingerprint"])),
    ("owner_pub_fingerprint_short",lambda x:x["authorities"][0].__setitem__("public_fingerprint","1")),
    ("reviewer_signature_nonhex",lambda x:x["authorities"][1].__setitem__("claimed_ed25519_signature","invalid")),
    ("owner_signature_integer",lambda x:x["authorities"][0].__setitem__("claimed_ed25519_signature",1)),
    ("owner_valid_from_bool",lambda x:x["authorities"][0].__setitem__("valid_from",True)),
    ("owner_invalid_range",lambda x:x["authorities"][0].__setitem__("valid_until",3)),
    ("reviewer_revoked_too_early",lambda x:x["authorities"][1].__setitem__("revoked_at",1)),
    ("reviewer_revoked_too_late",lambda x:x["authorities"][1].__setitem__("revoked_at",101)),
    ("providers_count_one",lambda x:x.__setitem__("providers",x["providers"][:1])),
    ("providers_os_swapped",lambda x:x["providers"][0].__setitem__("os","windows")),
    ("provider_run_zero",lambda x:x["providers"][0].__setitem__("run",0)),
    ("provider_job_bool",lambda x:x["providers"][1].__setitem__("job",True)),
    ("provider_attempt_bool",lambda x:x["providers"][0].__setitem__("attempt",True)),
    ("provider_attempt_two",lambda x:x["providers"][0].__setitem__("attempt",2)),
    ("provider_duplicate_run",lambda x:x["providers"][1].__setitem__("run",x["providers"][0]["run"])),
    ("provider_duplicate_job",lambda x:x["providers"][1].__setitem__("job",x["providers"][0]["job"])),
    ("provider_log_nonhex",lambda x:x["providers"][0].__setitem__("log_sha256","4"*65)),
    ("provider_signature_short",lambda x:x["providers"][0].__setitem__("claimed_signature","0"*32)),
    ("provider_workflow_fork",lambda x:x["providers"][1].__setitem__("workflow_digest",h("fork"))),
    ("witness_count_one",lambda x:x.__setitem__("witnesses",x["witnesses"][:1])),
    ("witness_id_duplicate",lambda x:x["witnesses"][1].__setitem__("id","alpha")),
    ("witness_admin_alias",lambda x:x["witnesses"][1].__setitem__("admin_group","groupa")),
    ("witness_key_alias",lambda x:x["witnesses"][1].__setitem__("key_fingerprint",x["witnesses"][0]["key_fingerprint"])),
    ("witness_size_fork",lambda x:x["witnesses"][0].__setitem__("size",8)),
    ("witness_epoch_fork",lambda x:x["witnesses"][2].__setitem__("epoch",18)),
    ("witness_root_fork",lambda x:x["witnesses"][1].__setitem__("root",h("fork"))),
    ("witness_receipt_short",lambda x:x["witnesses"][1].__setitem__("receipt_digest","aaa")),
    ("gossip_missing_edge",lambda x:x["gossip"].pop()),
    ("gossip_double_edge",lambda x:x["gossip"].__setitem__(1,dict(x["gossip"][0]))),
    ("gossip_self_edge",lambda x:x["gossip"][0].__setitem__("recipient",x["gossip"][0]["sender"])),
    ("gossip_rogue_sender",lambda x:x["gossip"][0].__setitem__("sender","outsider")),
    ("gossip_rogue_recipient",lambda x:x["gossip"][0].__setitem__("recipient","outsider")),
    ("gossip_epoch_fork",lambda x:x["gossip"][0].__setitem__("epoch",18)),
    ("gossip_size_fork",lambda x:x["gossip"][0].__setitem__("size",6)),
    ("gossip_root_fork",lambda x:x["gossip"][2].__setitem__("root",h("fork"))),
    ("gossip_receipt_replay",lambda x:x["gossip"][0].__setitem__("receipt_digest",h("other"))),
    ("anchor_missing_root",lambda x:x["anchor"].__setitem__("root",h("fork"))),
    ("anchor_future_epoch",lambda x:x["anchor"].__setitem__("epoch",18)),
    ("anchor_claimed_immutable_int",lambda x:x["anchor"].__setitem__("claimed_immutable",1)),
    ("anchor_claimed_signed_string",lambda x:x["anchor"].__setitem__("claimed_signed","true")),
    ("fence_generation_same",lambda x:x["fence"].__setitem__("generation_after",12)),
    ("fence_generation_jump",lambda x:x["fence"].__setitem__("generation_after",14)),
    ("fence_generation_bool",lambda x:x["fence"].__setitem__("generation_before",False)),
    ("fence_token_equal",lambda x:x["fence"].__setitem__("token_after",21)),
    ("fence_token_rollback",lambda x:x["fence"].__setitem__("token_after",20)),
    ("fence_token_bool",lambda x:x["fence"].__setitem__("token_before",True)),
    ("fence_expired_lease",lambda x:x["fence"].__setitem__("observed_at",90)),
    ("fence_before_lease",lambda x:x["fence"].__setitem__("observed_at",8)),
    ("fence_invalid_end",lambda x:x["fence"].__setitem__("lease_end",True)),
    ("fence_nonce_short",lambda x:x["fence"].__setitem__("nonce","abcd")),
    ("outbox_acked_state",lambda x:x["outbox"].__setitem__("state","ACKED")),
    ("outbox_remote_ack_true",lambda x:x["outbox"].__setitem__("remote_ack",True)),
    ("outbox_ack_digest_invalid",lambda x:x["outbox"].__setitem__("ack_digest","nothex")),
    ("outbox_wrong_claim",lambda x:x["outbox"].__setitem__("receipt_claim","VERIFIED")),
    ("release_promotion",lambda x:x.__setitem__("release",True)),
    ("trusted_owner_promotion",lambda x:x["trusted"].__setitem__("externally_authenticated_owner",True)),
    ("trusted_reviewer_promotion",lambda x:x["trusted"].__setitem__("externally_authenticated_reviewer",True)),
    ("trusted_provider_promotion",lambda x:x["trusted"].__setitem__("externally_verified_provider",True)),
    ("trusted_anchor_promotion",lambda x:x["trusted"].__setitem__("independent_checkpoint",True)),
    ("trusted_cas_promotion",lambda x:x["trusted"].__setitem__("production_cas_verified",True)),
    ("trusted_live_promotion",lambda x:x["trusted"].__setitem__("live_approval",True)),
    ("unexpected_nested_schema",lambda x:x["fence"].__setitem__("secret_extra",h("x"))),
    ("unexpected_top_level",lambda x:x.__setitem__("live_flag",True)),
]

for _name,_change in MUTATIONS:
    def build(fn):
        def test(self):
            d=good()
            fn(d)
            with self.assertRaises(gate.EvidenceRejected):validate(d)
        return test
    setattr(QuorumTests,"test_mutation_"+_name,build(_change))


CHILD = r'''
import sqlite3,sys,os
p,gen,tok,nonce,root,mode=sys.argv[1:]
gen=int(gen);tok=int(tok)
c=sqlite3.connect(p, timeout=15.0, isolation_level=None)
try:
    c.execute("PRAGMA busy_timeout=15000")
    c.execute("BEGIN IMMEDIATE")
    current=c.execute("SELECT generation,token FROM state WHERE id=1").fetchone()
    if current != (gen,tok):
        c.execute("ROLLBACK")
        print("STALE",flush=True)
        sys.exit(0)
    if c.execute("SELECT 1 FROM spent WHERE nonce=?",(nonce,)).fetchone():
        c.execute("ROLLBACK")
        print("REPLAY",flush=True)
        sys.exit(0)
    c.execute("INSERT INTO spent(nonce) VALUES(?)",(nonce,))
    c.execute("UPDATE state SET generation=?,token=?,root=? WHERE id=1 AND generation=? AND token=?",(gen+1,tok+1,root,gen,tok))
    if c.execute("SELECT changes()").fetchone()[0] != 1:
        c.execute("ROLLBACK")
        print("CAS_LOST",flush=True)
        sys.exit(0)
    c.execute("INSERT INTO pending(nonce,root,ack) VALUES(?,?,?)",(nonce,root,'PENDING'))
    if mode == 'before':os._exit(71)
    c.execute("COMMIT")
    if mode == 'after':os._exit(72)
    print("COMMITTED",flush=True)
finally:
    c.close()
'''


class SQLiteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="rc691-sql-")
        self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/"test.sqlite"
        with closing(sqlite3.connect(self.db)) as c:
            c.execute("CREATE TABLE state (id INTEGER PRIMARY KEY,generation INTEGER NOT NULL,token INTEGER NOT NULL,root TEXT NOT NULL)")
            c.execute("INSERT INTO state VALUES(1,0,0,?)",(h("root0"),))
            c.execute("CREATE TABLE spent (nonce TEXT PRIMARY KEY)")
            c.execute("CREATE TABLE pending(nonce TEXT PRIMARY KEY,root TEXT NOT NULL,ack TEXT NOT NULL)")
            c.commit()

    def child(self,path=None,g=0,t=0,nonce=None,root=None,mode="normal"):
        args=[sys.executable,"-c",CHILD,str(path or self.db),str(g),str(t),nonce or h("nonce1"),root or h("root1"),mode]
        return subprocess.run(args,capture_output=True,text=True,timeout=30,check=False)

    def state(self,path=None):
        with closing(sqlite3.connect(path or self.db)) as c:
            return c.execute("SELECT generation,token,root FROM state").fetchone()

    def pending(self,path=None):
        with closing(sqlite3.connect(path or self.db)) as c:
            return c.execute("SELECT nonce,root,ack FROM pending ORDER BY nonce").fetchall()

    def test_01_one_local_commit(self):
        p=self.child()
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn("COMMITTED",p.stdout)
        self.assertEqual(self.state()[:2],(1,1))

    def test_02_stale_generation_rejected(self):
        self.assertEqual(self.child().returncode,0)
        self.assertIn("STALE",self.child(g=0,t=0,nonce=h("fresh")).stdout)
        self.assertEqual(len(self.pending()),1)

    def test_03_stale_token_rejected(self):
        self.child()
        self.assertIn("STALE",self.child(g=1,t=0,nonce=h("fresh")).stdout)

    def test_04_nonce_replay_rejected(self):
        self.child()
        self.assertIn("REPLAY",self.child(g=1,t=1).stdout)

    def test_05_pre_commit_process_exit_rolls_back(self):
        self.assertEqual(self.child(mode="before").returncode,71)
        self.assertEqual(self.state()[:2],(0,0))
        self.assertEqual(self.pending(),[])

    def test_06_post_commit_process_exit_persists_pending(self):
        self.assertEqual(self.child(mode="after").returncode,72)
        self.assertEqual(self.state()[:2],(1,1))
        self.assertEqual(len(self.pending()),1)
        self.assertEqual(self.pending()[0][2],"PENDING")

    def test_07_lost_ack_is_unresolved(self):
        self.assertEqual(self.child(mode="after").returncode,72)
        self.assertIn("REPLAY",self.child(g=1,t=1).stdout)
        self.assertEqual(self.pending()[0][2],"PENDING")

    def test_08_two_processes_compete_single_db(self):
        cmd=[sys.executable,"-c",CHILD,str(self.db),"0","0",h("race"),h("root"),"normal"]
        a=subprocess.Popen(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        b=subprocess.Popen(cmd[:-3]+[h("other"),h("root"),"normal"],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out1,err1=a.communicate(timeout=30);out2,err2=b.communicate(timeout=30)
        self.assertEqual((a.returncode,b.returncode),(0,0),err1+err2)
        self.assertEqual(sorted([out1.strip(),out2.strip()]),["COMMITTED","STALE"])
        self.assertEqual(len(self.pending()),1)

    def test_09_three_independent_processes_one_winner(self):
        cmds=[[sys.executable,"-c",CHILD,str(self.db),"0","0",h("n"+str(i)),h("r"+str(i)),"normal"] for i in range(3)]
        pp=[subprocess.Popen(c,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for c in cmds]
        outs=[p.communicate(timeout=30) for p in pp]
        self.assertTrue(all(p.returncode==0 for p in pp),outs)
        self.assertEqual(sum("COMMITTED" in o for o,_ in outs),1)
        self.assertEqual(len(self.pending()),1)

    def test_10_offline_db_copies_both_can_win(self):
        alt=Path(self.tmp.name)/"copy.sqlite"
        shutil.copy2(self.db,alt)
        self.assertIn("COMMITTED",self.child(nonce=h("left")).stdout)
        self.assertIn("COMMITTED",self.child(path=alt,nonce=h("right"),root=h("other")).stdout)
        self.assertNotEqual(self.state()[2],self.state(alt)[2])

    def test_11_privileged_state_reset_reuses_generation(self):
        self.child()
        with closing(sqlite3.connect(self.db)) as c:
            c.execute("DELETE FROM spent")
            c.execute("DELETE FROM pending")
            c.execute("UPDATE state SET generation=0,token=0,root=? WHERE id=1",(h("root0"),))
            c.commit()
        self.assertIn("COMMITTED",self.child(nonce=h("nonce1"),root=h("rewritten")).stdout)
        self.assertEqual(self.state()[2],h("rewritten"))

    def test_12_whole_snapshot_restore_rewinds_nonce(self):
        snapshot=Path(self.tmp.name)/"old.sqlite"
        shutil.copy2(self.db,snapshot)
        self.child()
        shutil.copy2(snapshot,self.db)
        self.assertIn("COMMITTED",self.child(nonce=h("nonce1"),root=h("after-restore")).stdout)

    def test_13_local_anchor_only_detects_while_unchanged(self):
        anchor=Path(self.tmp.name)/"anchor.txt"
        anchor.write_text(h("root0"),encoding="ascii")
        self.child()
        self.assertNotEqual(self.state()[2],anchor.read_text(encoding="ascii"))
        anchor.write_text(self.state()[2],encoding="ascii")
        self.assertEqual(self.state()[2],anchor.read_text(encoding="ascii"))

    def test_14_local_claimed_ack_not_signed_provider_ack(self):
        self.child()
        with closing(sqlite3.connect(self.db)) as c:
            c.execute("UPDATE pending SET ack='CLAIMED_SIGNED_ACK'")
            c.commit()
        self.assertEqual(self.pending()[0][2],"CLAIMED_SIGNED_ACK")
        self.assertFalse(gate.audit(good(),pins(good()))["remote_ack_verified"])

    def test_15_aba_reset_not_prevented_by_local_token(self):
        self.child()
        with closing(sqlite3.connect(self.db)) as c:
            c.execute("DELETE FROM spent")
            c.execute("DELETE FROM pending")
            c.execute("UPDATE state SET generation=0,token=0,root=?",(h("root0"),))
            c.commit()
        self.assertEqual(self.child(nonce=h("nonce1")).returncode,0)

    def test_16_local_wal_not_external_checkpoint(self):
        with closing(sqlite3.connect(self.db)) as c:
            c.execute("PRAGMA journal_mode=WAL")
        self.assertEqual(self.child().returncode,0)
        self.assertFalse(gate.audit(good(),pins(good()))["immutable_external_checkpoint_authenticated"])

    def test_17_concurrent_threads_serialized_local_only(self):
        barrier=threading.Barrier(3)
        results=[];lock=threading.Lock()
        def run(i):
            barrier.wait(timeout=10)
            res=self.child(nonce=h("thread"+str(i)),root=h("root"+str(i)))
            with lock: results.append((res.returncode,res.stdout,res.stderr))
        pp=[threading.Thread(target=run,args=(i,)) for i in range(3)]
        for p in pp:p.start()
        for p in pp:p.join(timeout=30)
        self.assertEqual(len(results),3)
        self.assertTrue(all(r[0]==0 for r in results),results)
        self.assertEqual(sum("COMMITTED" in r[1] for r in results),1)

    def test_18_second_commit_new_token_only(self):
        self.child()
        self.assertIn("COMMITTED",self.child(g=1,t=1,nonce=h("second"),root=h("second-root")).stdout)
        self.assertEqual(self.state()[:2],(2,2))
        self.assertEqual(len(self.pending()),2)

    def test_19_outbox_fails_closed_to_remote_ack_uncertainty(self):
        self.assertEqual(self.child(mode="after").returncode,72)
        with closing(sqlite3.connect(self.db)) as c:
            row=c.execute("SELECT ack FROM pending").fetchone()[0]
        self.assertEqual(row,"PENDING")
        self.assertFalse(gate.audit(good(),pins(good()))["production_durable_cas_verified"])

    def test_20_two_db_copies_same_claimed_nonce_not_global_unique(self):
        alt=Path(self.tmp.name)/"clone.sqlite"
        shutil.copy2(self.db,alt)
        a=self.child(nonce=h("same"));b=self.child(path=alt,nonce=h("same"))
        self.assertEqual((a.returncode,b.returncode),(0,0),a.stderr+b.stderr)
        self.assertEqual(len(self.pending()),len(self.pending(alt)))


if __name__ == "__main__":
    unittest.main()
