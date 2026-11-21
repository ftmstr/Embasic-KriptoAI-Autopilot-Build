"""RC691: bounded transparency gossip and lease-fence transcript quarantine.

This is a PURE structural checker of caller-fabricated claims, not a signature
verifier, real provider attestation, independent log, trusted clock or database.
It has no filesystem, network, exchange or live release access.
"""
import hashlib
import hmac
import re


class EvidenceRejected(ValueError):
    """An untrusted fabricated transcript violates a local consistency gate."""


_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_BASE = "6f15a509864b20214442838d76087c1dccbfb74d"
_H40 = re.compile(r"[0-9a-f]{40}\Z")
_H64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_FIELDS = frozenset(("repo", "branch", "base", "source_digest", "workflow_digest",
                     "leaves", "old_size", "old_root", "new_root", "authorities",
                     "providers", "witnesses", "gossip", "anchor", "fence", "outbox",
                     "release", "trusted"))
_AUTH = frozenset(("role", "subject", "admin_group", "public_fingerprint",
                   "claimed_ed25519_signature", "valid_from", "valid_until", "revoked_at"))
_PROVIDER = frozenset(("os", "run", "job", "attempt", "log_sha256", "workflow_digest", "claimed_signature"))
_WITNESS = frozenset(("id", "admin_group", "key_fingerprint", "epoch", "size", "root", "receipt_digest"))
_GOSSIP = frozenset(("sender", "recipient", "epoch", "size", "root", "receipt_digest"))
_ANCHOR = frozenset(("witness", "root", "epoch", "claimed_immutable", "claimed_signed"))
_FENCE = frozenset(("generation_before", "generation_after", "token_before",
                    "token_after", "lease_start", "lease_end", "observed_at", "nonce"))
_OUTBOX = frozenset(("state", "remote_ack", "ack_digest", "receipt_claim"))
_TRUST = frozenset(("externally_authenticated_owner", "externally_authenticated_reviewer",
                   "externally_verified_provider", "independent_checkpoint",
                   "production_cas_verified", "live_approval"))
_MAX = (1 << 63) - 1


def _require(test, reason):
    if not test:
        raise EvidenceRejected(reason)


def _hex(s, size=64):
    return type(s) is str and ( _H64 if size == 64 else _H40).fullmatch(s) is not None


def _id(s):
    return type(s) is str and _ID.fullmatch(s) is not None


def _int(x, zero=False):
    return type(x) is int and (0 if zero else 1) <= x <= _MAX


def _keys(v, s):
    return type(v) is dict and v.keys() == s


def _digest(payload):
    return hashlib.sha256(payload).hexdigest()


def _node(leaves):
    _require(type(leaves) is list and 0 < len(leaves) <= 64, "bounded leaves")
    _require(all(_hex(v) for v in leaves), "hex leaves")
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + bytes.fromhex(leaves[0])).digest()
    half = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + _node(leaves[:half]) + _node(leaves[half:])).digest()


def merkle_root(leaves):
    """RFC6962-style mathematical root of CLAIMED bounded leaf commitments."""
    return _node(leaves).hex()


def inclusion_proof(leaves, index):
    _require(type(index) is int and 0 <= index < len(leaves), "index")
    _node(leaves)
    if len(leaves) == 1:
        return []
    half = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < half:
        return inclusion_proof(leaves[:half], index) + [_node(leaves[half:]).hex()]
    return inclusion_proof(leaves[half:], index-half) + [_node(leaves[:half]).hex()]


def inclusion_matches(leaf, index, total, proof, root):
    """Verify an inclusion equation against a claimed root (NOT an origin)."""
    _require(_hex(leaf) and _hex(root), "commitment")
    _require(_int(index, zero=True) and _int(total) and index < total and total <= 64, "bounds")
    _require(type(proof) is list and len(proof) <= 7 and all(_hex(x) for x in proof), "path")
    fn, sn = index, total - 1
    h = hashlib.sha256(b"\x00" + bytes.fromhex(leaf)).digest()
    for item in proof:
        sibling = bytes.fromhex(item)
        if fn & 1 or fn == sn:
            h = hashlib.sha256(b"\x01" + sibling + h).digest()
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            h = hashlib.sha256(b"\x01" + h + sibling).digest()
        fn >>= 1
        sn >>= 1
    return sn == 0 and hmac.compare_digest(h.hex(), root)


def snapshot_digest(doc):
    """Digest strictly typed caller-owned evidence; no trusted signer attached."""
    _require(type(doc) is dict and _keys(doc, _FIELDS), "unknown schema")
    def enc(v):
        if v is None:
            return b"N"
        if type(v) is bool:
            return b"B1" if v else b"B0"
        if type(v) is int:
            _require(0 <= v <= _MAX, "int range")
            return b"I" + str(v).encode("ascii") + b";"
        if type(v) is str:
            _require(len(v) <= 4096 and v.isascii(), "canonical ascii")
            b = v.encode("ascii")
            return b"S" + str(len(b)).encode("ascii") + b":" + b
        if type(v) is list:
            _require(len(v) <= 128, "bounded array")
            return b"L" + str(len(v)).encode("ascii") + b":" + b"".join(enc(x) for x in v)
        if type(v) is dict:
            _require(len(v) <= 32 and all(type(k) is str for k in v), "typed dict")
            return b"D" + str(len(v)).encode("ascii") + b":" + b"".join(enc(k)+enc(v[k]) for k in sorted(v))
        raise EvidenceRejected("unsupported canonical type")
    return _digest(b"RC691-UNTRUSTED-QUORUM-TRANSCRIPT-V1\x00" + enc(doc))


def audit(doc, pins):
    """Reject contradictions, quarantine all coherent caller-defined authority."""
    _require(type(doc) is dict and _keys(doc, _FIELDS), "schema")
    _require(type(pins) is dict and pins.keys() == frozenset(("base", "source_digest", "workflow_digest", "old_root", "new_root", "transcript")), "pins")
    _require(doc["repo"] == _REPO and doc["branch"] == _BRANCH and doc["base"] == _BASE, "public scope")
    for name in ("source_digest", "workflow_digest"):
        _require(_hex(doc[name]) and pins[name] == doc[name], name)
    _require(pins["base"] == doc["base"], "baseline")
    ls = doc["leaves"]
    root = merkle_root(ls)
    old = doc["old_size"]
    _require(_int(old) and old < len(ls), "old prefix")
    previous = merkle_root(ls[:old])
    _require(doc["old_root"] == previous and doc["new_root"] == root, "merkle consistency")
    _require(pins["old_root"] == previous and pins["new_root"] == root, "pinned roots")
    _require(_hex(pins["transcript"]) and hmac.compare_digest(snapshot_digest(doc), pins["transcript"]), "transcript fingerprint")
    a = doc["authorities"]
    _require(type(a) is list and len(a) == 2, "claimed authorities")
    groups, fingerprints = set(), set()
    for x,role in zip(a, ("owner", "reviewer")):
        _require(_keys(x, _AUTH) and x["role"] == role and _id(x["subject"]) and _id(x["admin_group"]), "authority fields")
        _require(_hex(x["public_fingerprint"]) and _hex(x["claimed_ed25519_signature"]), "unverified key/signature")
        _require(_int(x["valid_from"]) and _int(x["valid_until"]) and x["valid_from"] < x["valid_until"], "claimed chronology")
        _require(x["revoked_at"] is None or (_int(x["revoked_at"]) and x["valid_from"] <= x["revoked_at"] <= x["valid_until"]), "claimed revocation")
        groups.add(x["admin_group"]);fingerprints.add(x["public_fingerprint"])
    _require(len(groups) == 2 and len(fingerprints) == 2 and a[0]["subject"] != a[1]["subject"], "duplicate claimed authority")
    providers = doc["providers"]
    _require(type(providers) is list and len(providers) == 2, "provider count")
    for item,os in zip(providers,("ubuntu", "windows")):
        _require(_keys(item,_PROVIDER) and item["os"] == os, "provider schema")
        _require(_int(item["run"]) and _int(item["job"]) and type(item["attempt"]) is int and item["attempt"] == 1, "provider run")
        _require(item["workflow_digest"] == doc["workflow_digest"] and _hex(item["log_sha256"]) and _hex(item["claimed_signature"]), "provider digest")
    _require(providers[0]["run"] != providers[1]["run"] and providers[0]["job"] != providers[1]["job"], "reused run/job")
    witnesses = doc["witnesses"]
    _require(type(witnesses) is list and len(witnesses) == 3, "witness count")
    ids, wg, keys = set(), set(), set()
    epoch = None
    for w in witnesses:
        _require(_keys(w,_WITNESS) and _id(w["id"]) and _id(w["admin_group"]) and _hex(w["key_fingerprint"]) and _hex(w["receipt_digest"]), "witness fields")
        _require(_int(w["epoch"]) and w["size"] == len(ls) and w["root"] == root, "witness view")
        if epoch is None: epoch = w["epoch"]
        _require(w["epoch"] == epoch, "witness epoch")
        ids.add(w["id"]);wg.add(w["admin_group"]);keys.add(w["key_fingerprint"])
    _require(len(ids) == len(wg) == len(keys) == 3, "claimed domain alias")
    gossip=doc["gossip"]
    _require(type(gossip) is list and len(gossip) == 6, "gossip coverage")
    seen=set()
    directory={w["id"]:w for w in witnesses}
    for receipt in gossip:
        _require(_keys(receipt,_GOSSIP), "gossip schema")
        sender,recipient=receipt["sender"],receipt["recipient"]
        _require(sender in ids and recipient in ids and sender != recipient, "gossip endpoints")
        _require((sender,recipient) not in seen, "gossip replay")
        seen.add((sender,recipient))
        _require(receipt["epoch"] == epoch and receipt["size"] == len(ls) and receipt["root"] == root and receipt["receipt_digest"] == directory[sender]["receipt_digest"], "split-view gossip")
    _require(len(seen)==6,"gossip matrix")
    anchor=doc["anchor"]
    _require(_keys(anchor,_ANCHOR) and _id(anchor["witness"]), "anchor")
    _require(anchor["root"] == root and anchor["epoch"] == epoch and type(anchor["claimed_immutable"]) is bool and type(anchor["claimed_signed"]) is bool, "untrusted anchor")
    fence=doc["fence"]
    _require(_keys(fence,_FENCE), "fence")
    _require(_int(fence["generation_before"],zero=True) and _int(fence["generation_after"]) and fence["generation_after"] == fence["generation_before"] + 1, "ABA generation")
    _require(_int(fence["token_before"],zero=True) and _int(fence["token_after"]) and fence["token_after"] > fence["token_before"], "stale lease token")
    _require(_int(fence["lease_start"]) and _int(fence["lease_end"]) and _int(fence["observed_at"]) and fence["lease_start"] <= fence["observed_at"] < fence["lease_end"], "untrusted lease chronology")
    _require(_hex(fence["nonce"]), "nonce")
    out=doc["outbox"]
    _require(_keys(out,_OUTBOX) and out["state"] in ("PENDING", "UNRESOLVED") and out["remote_ack"] is False and out["receipt_claim"] in ("NONE", "CLAIMED_ACK"), "provider ACK promotion")
    _require(_hex(out["ack_digest"]), "ACK digest")
    _require(doc["release"] is False and _keys(doc["trusted"],_TRUST) and all(v is False for v in doc["trusted"].values()), "unauthorized AUTH/LIVE promotion")
    return {"status":"CLAIMED_QUORUM_GOSSIP_QUARANTINED_NOT_AUTHENTICATED", "claimed_merkle_prefix_consistent":True,
            "claimed_full_mesh_consistent":True, "mathematical_inclusion_only":inclusion_matches(ls[-1],len(ls)-1,len(ls),inclusion_proof(ls,len(ls)-1),root),
            "ed25519_owner_authority_authenticated":False,"provider_signed_logs_authenticated":False,
            "revocation_and_clock_authenticated":False,"immutable_external_checkpoint_authenticated":False,
            "production_durable_cas_verified":False,"remote_ack_verified":False,"release_ready":False,"live_trading_allowed":False}


def compare_views(left, right):
    """Classify caller-supplied contradictions; classification is NOT authentication."""
    for d in (left,right):
        _require(type(d) is dict and d.keys() == frozenset(("audience","epoch","size","root","provider_digest","receipt_digest","source_digest")),"view schema")
        _require(_id(d["audience"]) and _int(d["epoch"]) and _int(d["size"]),"view bounds")
        _require(all(_hex(d[k]) for k in ("root","provider_digest","receipt_digest","source_digest")),"view digest")
    if left["source_digest"] != right["source_digest"]:return "CLAIMED_SOURCE_FORK_NOT_AUTHENTICATED"
    if left["epoch"] != right["epoch"] or left["size"] != right["size"]:return "CLAIMED_INCOMPARABLE_EPOCHS_NOT_AUTHENTICATED"
    if left["root"] != right["root"]:return "CLAIMED_SAME_EPOCH_MERKLE_FORK_NOT_AUTHENTICATED"
    if left["provider_digest"] != right["provider_digest"]:return "CLAIMED_PROVIDER_LOG_FORK_NOT_AUTHENTICATED"
    if left["receipt_digest"] != right["receipt_digest"]:return "CLAIMED_WITNESS_RECEIPT_FORK_NOT_AUTHENTICATED"
    return "CLAIMED_EQUAL_VIEWS_NOT_AUTHENTICATED"
