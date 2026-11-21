"""RC686: invented origin proofs and disposable, test-only SQLite crash/fork lab.

These tests DO NOT integrate an application trading CAS or authenticate signers.
The privileged adversary can rewrite every locally held reference/receipt.
"""
import copy
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from safe_public_ci.ci_origin_checkpoint_inclusion_quarantine import (
    OriginCheckpointRejected, canonical_claim, inclusion_root,
    quarantine_inclusion,
)


def digest(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


LEAVES = tuple(digest("RC686 fabricated leaf %03d" % i) for i in range(128))


def node(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def merkle(leaves):
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + bytes.fromhex(leaves[0])).digest()
    s = 1 << ((len(leaves) - 1).bit_length() - 1)
    return node(merkle(leaves[:s]), merkle(leaves[s:]))


def inclusion(leaves, index):
    if len(leaves) == 1:
        return ()
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < split:
        return (*inclusion(leaves[:split], index), merkle(leaves[split:]).hex())
    return (*inclusion(leaves[split:], index - split), merkle(leaves[:split]).hex())


def example(size=9, index=6, old=3):
    leaves = LEAVES[:size]
    prev = merkle(leaves[:old]).hex()
    current = merkle(leaves).hex()
    claim = {
        "repository": "ftmstr/Embasic-KriptoAI-Autopilot-Build",
        "branch": "validation/rc654-pr1-rc653-combined-ci",
        "git_sha": "1" * 40,
        "source_sha256": "2" * 64,
        "workflow_sha256": "3" * 64,
        "checkpoint_sha256": "4" * 64,
        "previous_size": old,
        "tree_size": size,
        "previous_root": prev,
        "tree_root": current,
        "leaf_sha256": leaves[index],
        "leaf_index": index,
        "inclusion_path": inclusion(leaves, index),
        "owner": ("owner", "alice_owner", "a" * 64, 10, 200, 101),
        "reviewer": ("reviewer", "bob_reviewer", "b" * 64, 10, 200, 102),
        "provider": ("github_actions", 4326, 13135, "1" * 40, "2" * 64,
                     "9" * 64, "UNVERIFIED"),
        "witnesses": (("owner_domain", "owner_witness", "c" * 64, size, current,
                       "9" * 64),
                      ("reviewer_domain", "review_witness", "d" * 64, size,
                       current, "9" * 64)),
        "revocations": (),
        "issued_at": 100,
        "observed_at": 110,
        "epoch": 4,
        "nonce_sha256": "5" * 64,
        "spent_nonces": (),
        "last_seen": (3, old, prev),
        "ack_state": "ACK_LOST_UNRESOLVED",
        "release_ready": False,
        "live_trading_allowed": False,
    }
    return claim


def pins(claim):
    result = {k: claim[k] for k in (
        "git_sha", "source_sha256", "workflow_sha256", "checkpoint_sha256",
        "previous_root", "tree_root", "leaf_sha256", "nonce_sha256")}
    result.update(owner_fingerprint=claim["owner"][2],
                  reviewer_fingerprint=claim["reviewer"][2],
                  claim_sha256=hashlib.sha256(canonical_claim(claim)).hexdigest(),
                  trusted_owner_origin=False,
                  trusted_reviewer_origin=False,
                  trusted_provider_origin=False,
                  trusted_revocations=False,
                  trusted_append_only_anchor=False,
                  trusted_durable_cas=False)
    return result


def change_record(claim, name, row, index, value):
    if name == "witnesses":
        records = [list(item) for item in claim[name]]
        records[row][index] = value
        claim[name] = tuple(tuple(x) for x in records)
    else:
        record = list(claim[name])
        record[index] = value
        claim[name] = tuple(record)


class RC686LogInclusionTests(unittest.TestCase):
    def rejected(self, mutation, *, stale=False):
        claim = example()
        old_pins = pins(claim) if stale else None
        mutation(claim)
        with self.assertRaises(OriginCheckpointRejected):
            quarantine_inclusion(claim, old_pins if stale else pins(claim))

    def test_01_canonical_validity_is_not_authentication(self):
        claim = example()
        result = quarantine_inclusion(claim, pins(claim))
        self.assertEqual(result["status"],
                         "MERKLE_INCLUSION_EQUATION_VALID_ORIGIN_UNAUTHENTICATED")
        self.assertTrue(result["inclusion_equation_valid"])
        self.assertTrue(result["claimed_ack_lost"])
        self.assertTrue(all(v is False for k, v in result.items()
                            if k.endswith("authenticated") or
                            k.endswith("verified") or k in (
                                "release_ready", "live_trading_allowed")))

    def test_02_inclusion_all_sizes_and_positions(self):
        count = 0
        for size in range(1, 129):
            leaves = LEAVES[:size]
            for index in sorted({0, size // 4, size // 2, size - 1}):
                self.assertEqual(inclusion_root(leaves[index], index, size,
                                 inclusion(leaves, index)), merkle(leaves).hex())
                count += 1
        self.assertGreater(count, 400)

    def test_03_alternate_leaf_must_not_verify_same_root(self):
        c = example()
        fake = LEAVES[10]
        self.assertNotEqual(inclusion_root(fake, c["leaf_index"], c["tree_size"],
                         c["inclusion_path"]), c["tree_root"])

    def test_04_odd_merkle_width_root_binding(self):
        for size in (3, 5, 7, 9, 17, 31, 33, 63, 65, 127):
            c = example(size, size - 1)
            self.assertTrue(quarantine_inclusion(c, pins(c))["inclusion_equation_valid"])

    def test_05_malformed_indexes_are_rejected(self):
        for index in (-1, 9, 900, True, 2.0, "0"):
            with self.assertRaises(OriginCheckpointRejected):
                inclusion_root(LEAVES[1], index, 9, ())

    def test_06_bogus_audit_path_lengths_are_rejected(self):
        c = example()
        for audit in ((), ("0" * 64,) * 9, ("bad",), ["a" * 64], ("a" * 64,)):
            with self.assertRaises(OriginCheckpointRejected):
                inclusion_root(c["leaf_sha256"], c["leaf_index"], c["tree_size"], audit)

    def test_07_stateless_replay_is_not_durable_replay_protection(self):
        c = example()
        self.assertEqual(quarantine_inclusion(c, pins(c)),
                         quarantine_inclusion(copy.deepcopy(c), pins(copy.deepcopy(c))))
        self.assertFalse(quarantine_inclusion(c, pins(c))["durable_cas_verified"])

    def test_08_fabricated_second_witness_not_independent(self):
        c = example()
        change_record(c, "witnesses", 1, 1, "second_fabricated")
        self.assertFalse(quarantine_inclusion(c, pins(c))[
            "external_immutable_anchor_authenticated"])

    def test_09_alternate_untrusted_provider_claim_not_signed_provenance(self):
        c = example()
        change_record(c, "provider", None, 1, 999900)
        self.assertFalse(quarantine_inclusion(c, pins(c))["provider_signature_authenticated"])

    def test_10_revocation_future_claim_not_authority(self):
        c = example()
        c["revocations"] = (("a" * 64, 111),)
        self.assertFalse(quarantine_inclusion(c, pins(c))["revocation_origin_authenticated"])

    def test_11_no_external_monotonic_root(self):
        c = example()
        self.assertEqual(c["last_seen"][0], 3)
        self.assertFalse(quarantine_inclusion(c, pins(c))["restart_recovery_verified"])

    def test_12_all_fields_covered_in_canonical_digest(self):
        c = example()
        before = hashlib.sha256(canonical_claim(c)).hexdigest()
        change_record(c, "provider", None, 2, 100500)
        self.assertNotEqual(before, hashlib.sha256(canonical_claim(c)).hexdigest())

    def test_13_singleton_merkle_width(self):
        c = example(1, 0, 1)
        self.assertEqual(c["inclusion_path"], ())
        self.assertTrue(quarantine_inclusion(c, pins(c))["inclusion_equation_valid"])

    def test_14_self_signed_owner_reviewer_not_root_provenance(self):
        c = example()
        self.assertFalse(quarantine_inclusion(c, pins(c))["owner_authority_authenticated"])
        self.assertFalse(quarantine_inclusion(c, pins(c))["reviewer_authority_authenticated"])

    def test_15_valid_ack_not_silently_applied(self):
        c = example()
        self.assertTrue(quarantine_inclusion(c, pins(c))["claimed_ack_lost"])
        self.assertFalse(quarantine_inclusion(c, pins(c))["durable_cas_verified"])

    def test_16_canonical_copy(self):
        c = example()
        self.assertEqual(canonical_claim(c), canonical_claim(copy.deepcopy(c)))


MUTATIONS = (
    ("field_missing", lambda c: c.pop("branch"), False),
    ("field_injected", lambda c: c.update(authenticated=True), False),
    ("wrong_repo", lambda c: c.update(repository="ftmstr/PRIVATE"), False),
    ("main_branch", lambda c: c.update(branch="main"), False),
    ("nonhex_git", lambda c: c.update(git_sha="Z" * 40), False),
    ("git_changed", lambda c: c.update(git_sha="f" * 40), True),
    ("source_replaced", lambda c: c.update(source_sha256="f" * 64), True),
    ("workflow_replaced", lambda c: c.update(workflow_sha256="f" * 64), True),
    ("checkpoint_replaced", lambda c: c.update(checkpoint_sha256="f" * 64), True),
    ("wrong_tree_root", lambda c: c.update(tree_root="e" * 64), False),
    ("wrong_previous_root", lambda c: c.update(previous_root="f" * 64), True),
    ("wrong_leaf", lambda c: c.update(leaf_sha256="e" * 64), False),
    ("negative_leaf_index", lambda c: c.update(leaf_index=-1), False),
    ("index_bool", lambda c: c.update(leaf_index=True), False),
    ("width_greater_128", lambda c: c.update(tree_size=129), False),
    ("old_size_greater", lambda c: c.update(previous_size=10), False),
    ("old_size_zero", lambda c: c.update(previous_size=0), False),
    ("size_bool", lambda c: c.update(tree_size=True), False),
    ("epoch_bool", lambda c: c.update(epoch=True), False),
    ("epoch_rollback", lambda c: c.update(epoch=3), False),
    ("epoch_aba", lambda c: c.update(last_seen=(4, 3, c["previous_root"])), False),
    ("old_root_different", lambda c: c.update(last_seen=(3, 3, "0" * 64)), False),
    ("old_size_different", lambda c: c.update(last_seen=(3, 2, c["previous_root"])), False),
    ("ack_committed", lambda c: c.update(ack_state="ACK_COMMITTED"), False),
    ("live_true", lambda c: c.update(live_trading_allowed=True), False),
    ("release_true", lambda c: c.update(release_ready=True), False),
    ("nonce_spent", lambda c: c.update(spent_nonces=("5" * 64,)), False),
    ("nonce_hist_repeated", lambda c: c.update(spent_nonces=("8" * 64,) * 2), False),
    ("nonce_hist_unsorted", lambda c: c.update(spent_nonces=("f" * 64, "e" * 64)), False),
    ("nonce_hist_list", lambda c: c.update(spent_nonces=["f" * 64]), False),
    ("nonce_replaced", lambda c: c.update(nonce_sha256="e" * 64), True),
    ("clock_rollback", lambda c: c.update(observed_at=99), False),
    ("clock_bool", lambda c: c.update(issued_at=True), False),
    ("revoked_owner", lambda c: c.update(revocations=(("a" * 64, 109),)), False),
    ("revoked_reviewer", lambda c: c.update(revocations=(("b" * 64, 101),)), False),
    ("revocation_duplicate", lambda c: c.update(revocations=(("e" * 64, 10), ("e" * 64, 11))), False),
    ("revocation_unsorted", lambda c: c.update(revocations=(("f" * 64, 100), ("e" * 64, 110))), False),
    ("revocation_list", lambda c: c.update(revocations=[("a" * 64, 111)]), False),
    ("owner_key_equal_reviewer", lambda c: change_record(c, "owner", None, 2, "b" * 64), False),
    ("owner_actor_equal_reviewer", lambda c: change_record(c, "owner", None, 1, "bob_reviewer"), False),
    ("owner_bad_time", lambda c: change_record(c, "owner", None, 5, 201), False),
    ("reviewer_bad_role", lambda c: change_record(c, "reviewer", None, 0, "owner"), False),
    ("reviewer_key_changed", lambda c: change_record(c, "reviewer", None, 2, "f" * 64), True),
    ("provider_name_forged", lambda c: change_record(c, "provider", None, 0, "my_fake"), False),
    ("provider_run_zero", lambda c: change_record(c, "provider", None, 1, 0), False),
    ("provider_job_bool", lambda c: change_record(c, "provider", None, 2, True), False),
    ("provider_sha_changed", lambda c: change_record(c, "provider", None, 3, "f" * 40), False),
    ("provider_source_changed", lambda c: change_record(c, "provider", None, 4, "f" * 64), False),
    ("provider_log_forged", lambda c: change_record(c, "provider", None, 5, "f" * 64), False),
    ("provider_self_claim_verified", lambda c: change_record(c, "provider", None, 6, "VERIFIED"), False),
    ("witness_first_wrong_domain", lambda c: change_record(c, "witnesses", 0, 0, "reviewer_domain"), False),
    ("witness_duplicate_actor", lambda c: change_record(c, "witnesses", 1, 1, "owner_witness"), False),
    ("witness_duplicate_key", lambda c: change_record(c, "witnesses", 1, 2, "c" * 64), False),
    ("witness_owner_key_reuse", lambda c: change_record(c, "witnesses", 0, 2, "a" * 64), False),
    ("witness_signer_key_reuse", lambda c: change_record(c, "witnesses", 1, 2, "b" * 64), False),
    ("witness_wrong_log", lambda c: change_record(c, "witnesses", 1, 5, "f" * 64), False),
    ("witness_wrong_size", lambda c: change_record(c, "witnesses", 0, 3, 5), False),
    ("witness_wrong_root", lambda c: change_record(c, "witnesses", 1, 4, "e" * 64), False),
    ("witness_unsupported_extra", lambda c: c.update(witnesses=(*c["witnesses"], c["witnesses"][0])), False),
    ("inclusion_proof_truncated", lambda c: c.update(inclusion_path=c["inclusion_path"][:-1]), False),
    ("inclusion_proof_reordered", lambda c: c.update(inclusion_path=tuple(reversed(c["inclusion_path"]))), False),
    ("inclusion_proof_extra", lambda c: c.update(inclusion_path=(*c["inclusion_path"], "e" * 64)), False),
    ("inclusion_proof_list", lambda c: c.update(inclusion_path=list(c["inclusion_path"])), False),
    ("provider_log_rebind", lambda c: change_record(c, "provider", None, 1, 9999), True),
)


def create_mutation(fn, stale):
    def test(self):
        self.rejected(fn, stale=stale)
    return test


for n, (label, fn, stale) in enumerate(MUTATIONS, 17):
    setattr(RC686LogInclusionTests, "test_%02d_%s" % (n, label),
            create_mutation(fn, stale))


# This database adapter is test-only: it does NOT run inside a trading app.
def init_database(path):
    db = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
    try:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("CREATE TABLE state (id INTEGER PRIMARY KEY, epoch INTEGER NOT NULL, "
                   "generation INTEGER NOT NULL, root TEXT NOT NULL)")
        db.execute("CREATE TABLE receipt (nonce TEXT PRIMARY KEY, nextroot TEXT NOT NULL)")
        db.execute("INSERT INTO state VALUES (1, 1, 1, ?)", ("a" * 64,))
    finally:
        db.close()


def read_state(path):
    db = sqlite3.connect(str(path), timeout=5.0)
    try:
        return db.execute("SELECT epoch,generation,root FROM state WHERE id=1").fetchone()
    finally:
        db.close()


def receipt_count(path):
    db = sqlite3.connect(str(path), timeout=5.0)
    try:
        return db.execute("SELECT count(*) FROM receipt").fetchone()[0]
    finally:
        db.close()


def compare_and_swap(path, epoch, generation, old_root, new_root, nonce):
    db = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
    try:
        db.execute("PRAGMA busy_timeout=4000")
        db.execute("BEGIN IMMEDIATE")
        actual = db.execute("SELECT epoch,generation,root FROM state WHERE id=1").fetchone()
        if actual != (epoch, generation, old_root):
            db.rollback()
            return "STALE"
        try:
            db.execute("INSERT INTO receipt(nonce,nextroot) VALUES (?,?)", (nonce, new_root))
        except sqlite3.IntegrityError:
            db.rollback()
            return "REPLAY"
        cur = db.execute("UPDATE state SET epoch=?,generation=?,root=? "
                         "WHERE id=1 AND epoch=? AND generation=? AND root=?",
                         (epoch + 1, generation + 1, new_root,
                          epoch, generation, old_root))
        if cur.rowcount != 1:
            db.rollback()
            return "STALE"
        db.commit()
        return "COMMITTED"
    finally:
        db.close()


_SUBPROCESS = '''import sqlite3,sys,time
p,mode,new,nonce=sys.argv[1:]
db=sqlite3.connect(p,timeout=5,isolation_level=None)
try:
 db.execute("PRAGMA busy_timeout=4000")
 db.execute("BEGIN IMMEDIATE")
 a=db.execute("SELECT epoch,generation,root FROM state WHERE id=1").fetchone()
 if a != (1,1,"a"*64):
  db.rollback(); sys.exit(20)
 db.execute("INSERT INTO receipt VALUES (?,?)",(nonce,new))
 db.execute("UPDATE state SET epoch=2,generation=2,root=? WHERE id=1",(new,))
 if mode == "before": os_exit=61
 elif mode == "after": db.commit(); os_exit=62
 elif mode == "race": db.commit(); os_exit=0
 else: os_exit=63
finally:
 db.close() if mode == "race" else None
import os;os._exit(os_exit)
'''


class RC686SQLiteCrashAndForkTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="rc686_")
        self.addCleanup(self._temp.cleanup)
        self.path = Path(self._temp.name) / "synthetic.db"
        init_database(self.path)

    def run_child(self, mode, nonce, path=None):
        return subprocess.run([sys.executable, "-c", _SUBPROCESS,
                               str(path or self.path), mode, "b" * 64, nonce],
                              capture_output=True, text=True, timeout=12)

    def test_01_first_cas_commits_once(self):
        self.assertEqual(compare_and_swap(self.path, 1, 1, "a"*64, "b"*64, "n1"), "COMMITTED")
        self.assertEqual(read_state(self.path), (2, 2, "b"*64))

    def test_02_stale_generation_rejected(self):
        compare_and_swap(self.path, 1, 1, "a"*64, "b"*64, "n1")
        self.assertEqual(compare_and_swap(self.path, 1, 1, "a"*64, "c"*64, "n2"), "STALE")

    def test_03_stale_root_rejected(self):
        self.assertEqual(compare_and_swap(self.path, 1, 1, "c"*64, "b"*64, "n1"), "STALE")

    def test_04_replay_nonce_after_second_generation_rejected(self):
        compare_and_swap(self.path, 1, 1, "a"*64, "b"*64, "n1")
        self.assertEqual(compare_and_swap(self.path, 2, 2, "b"*64, "c"*64, "n1"), "REPLAY")

    def test_05_fresh_nonce_allows_second_generation(self):
        compare_and_swap(self.path, 1, 1, "a"*64, "b"*64, "n1")
        self.assertEqual(compare_and_swap(self.path, 2, 2, "b"*64, "c"*64, "n2"), "COMMITTED")

    def test_06_aborted_cas_does_not_consume_nonce(self):
        self.assertEqual(compare_and_swap(self.path, 9, 9, "a"*64, "b"*64, "n1"), "STALE")
        self.assertEqual(receipt_count(self.path), 0)

    def test_07_aba_epoch_rejected_after_restart(self):
        compare_and_swap(self.path, 1, 1, "a"*64, "b"*64, "n1")
        self.assertEqual(compare_and_swap(self.path, 1, 1, "a"*64, "c"*64, "n2"), "STALE")

    def test_08_three_threads_one_winner(self):
        gate = threading.Barrier(3)
        results = []
        lock = threading.Lock()
        def worker(i):
            gate.wait(timeout=5)
            value = compare_and_swap(self.path, 1, 1, "a"*64,
                                     ("b" if i == 0 else "c" if i == 1 else "d")*64,
                                     "nonce_%d" % i)
            with lock:
                results.append(value)
        threads = [threading.Thread(target=worker,args=(i,)) for i in range(3)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=8)
        self.assertEqual(sorted(results), ["COMMITTED", "STALE", "STALE"])

    def test_09_three_processes_one_winner(self):
        children = [subprocess.Popen([sys.executable, "-c", _SUBPROCESS,
                     str(self.path), "race", "b"*64, "n%d" % i],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    for i in range(3)]
        status = []
        for child in children:
            out, err = child.communicate(timeout=12)
            self.assertFalse(err, err.decode(errors="replace"))
            status.append(child.returncode)
        self.assertEqual(sorted(status), [0, 20, 20])

    def test_10_before_commit_process_exit_rolls_back(self):
        child = self.run_child("before", "n1")
        self.assertEqual(child.returncode, 61, child.stderr)
        self.assertEqual(read_state(self.path), (1, 1, "a"*64))
        self.assertEqual(receipt_count(self.path), 0)

    def test_11_after_commit_exit_retains_state_but_loses_ack(self):
        child = self.run_child("after", "n1")
        self.assertEqual(child.returncode, 62, child.stderr)
        self.assertEqual(read_state(self.path), (2, 2, "b"*64))
        self.assertEqual(receipt_count(self.path), 1)

    def test_12_replay_after_lost_ack_does_not_commit_again(self):
        self.run_child("after", "n1")
        self.assertEqual(compare_and_swap(self.path, 1, 1, "a"*64, "b"*64, "n1"), "STALE")

    def test_13_db_copy_fork_proves_missing_external_arbiter(self):
        from shutil import copyfile
        clone = Path(self._temp.name) / "clone.db"
        copyfile(self.path, clone)
        self.assertEqual(compare_and_swap(self.path, 1, 1, "a"*64, "b"*64, "n1"), "COMMITTED")
        self.assertEqual(compare_and_swap(clone, 1, 1, "a"*64, "c"*64, "n2"), "COMMITTED")
        self.assertNotEqual(read_state(self.path)[2], read_state(clone)[2])

    def test_14_admin_restores_old_backup(self):
        from shutil import copyfile
        backup = Path(self._temp.name) / "backup.db"
        copyfile(self.path, backup)
        compare_and_swap(self.path, 1, 1, "a"*64, "b"*64, "n1")
        copyfile(backup, self.path)
        self.assertEqual(read_state(self.path), (1, 1, "a"*64))
        self.assertEqual(compare_and_swap(self.path, 1, 1, "a"*64, "c"*64, "n1"), "COMMITTED")

    def test_15_local_anchor_detects_restoration_only_if_retained(self):
        anchor = Path(self._temp.name) / "anchor.txt"
        anchor.write_text("a"*64)
        compare_and_swap(self.path, 1, 1, "a"*64, "b"*64, "n1")
        anchor.write_text("b"*64)
        from shutil import copyfile
        clone = Path(self._temp.name) / "initial.db"
        # Resetting DB to an old state while keeping anchor reveals mismatch.
        db = sqlite3.connect(str(self.path))
        try:
            db.execute("UPDATE state SET epoch=1,generation=1,root=?", ("a"*64,))
            db.commit()
        finally:
            db.close()
        self.assertNotEqual(read_state(self.path)[2], anchor.read_text())

    def test_16_admin_can_rewrite_db_and_same_domain_anchor(self):
        anchor = Path(self._temp.name) / "anchor.txt"
        compare_and_swap(self.path, 1, 1, "a"*64, "b"*64, "n1")
        anchor.write_text("b"*64)
        db = sqlite3.connect(str(self.path))
        try:
            db.execute("UPDATE state SET epoch=1,generation=1,root=?", ("a"*64,))
            db.execute("DELETE FROM receipt")
            db.commit()
        finally:
            db.close()
        anchor.write_text("a"*64)
        self.assertEqual(read_state(self.path)[2], anchor.read_text())
        self.assertEqual(compare_and_swap(self.path, 1, 1, "a"*64, "c"*64, "n1"), "COMMITTED")

    def test_17_read_only_connection_disallows_writes(self):
        ro = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                ro.execute("UPDATE state SET generation=99")
        finally:
            ro.close()

    def test_18_synchronous_full_does_not_certify_powerloss_or_trustroot(self):
        self.assertEqual(read_state(self.path), (1, 1, "a"*64))
        claim = example()
        self.assertFalse(quarantine_inclusion(claim, pins(claim))[
            "external_immutable_anchor_authenticated"])


if __name__ == "__main__":
    unittest.main()
