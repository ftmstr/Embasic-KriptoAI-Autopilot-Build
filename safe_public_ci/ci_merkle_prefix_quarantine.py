"""RC679 offline Merkle prefix/inclusion proof checker, strictly NO AUTH.

SHA-256 authenticates no issuer, clock, GitHub runner, immutable source, or CAS.
All claims, leaves and expected roots are caller supplied; no IO or mutation.
"""
import hashlib
import hmac
import re


class MerkleClaimRejected(ValueError):
    """A synthetic Merkle prefix or claimed provider witness is inconsistent."""


_H40 = re.compile(r"[0-9a-f]{40}\Z")
_H64 = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_ROLES = ("owner", "independent_reviewer", "incumbent_custodian")
_PLATFORMS = ("ubuntu", "windows")
_META = ("repository", "branch", "git_sha", "source_sha256", "workflow_sha256",
         "roster_sha256", "authority_root_sha256", "nonce_sha256", "generation",
         "issued_at", "release_ready", "live_trading_allowed")
_CLAIMS = ("old_generation", "new_generation", "old_root_sha256",
           "new_root_sha256", "observed_at", "writer_views", "provider_views",
           "reviewer_views", "ack_state", "release_ready", "live_trading_allowed")
_PINS = ("expected_git_sha", "expected_source_sha256", "expected_workflow_sha256",
         "expected_roster_sha256", "expected_authority_root_sha256",
         "expected_nonce_sha256", "expected_old_root_sha256",
         "expected_new_root_sha256", "expected_receipt_sha256",
         "reviewer_keys", "revocation_events", "spent_nonce_sha256",
         "seen_root_sha256")


def _sha(s, digits=64):
    return type(s) is str and (_H40 if digits == 40 else _H64).fullmatch(s) is not None


def _int(x):
    return type(x) is int and 1 <= x <= (1 << 63) - 2


def _name(s):
    return type(s) is str and _NAME.fullmatch(s) is not None


def _leaves(leaves):
    return (type(leaves) is tuple and len(leaves) <= 128 and
            all(_sha(x) for x in leaves) and len(set(leaves)) == len(leaves))


def _history(values):
    return (type(values) is tuple and len(values) <= 128 and
            all(_sha(x) for x in values) and values == tuple(sorted(set(values))))


def _events(events):
    return (type(events) is tuple and len(events) <= 128 and
            all(type(e) is tuple and len(e) == 2 and _sha(e[0]) and _int(e[1])
                for e in events) and events == tuple(sorted(events)) and
            len(set(e[0] for e in events)) == len(events))


def receipt_leaf_sha256(meta):
    """Synthetic receipt commitment; it is NOT signed or externally sourced."""
    if type(meta) is not dict or set(meta) != set(_META):
        raise MerkleClaimRejected("unexpected receipt metadata")
    if (meta["repository"] != _REPO or meta["branch"] != _BRANCH or
            not _sha(meta["git_sha"], 40) or
            any(not _sha(meta[k]) for k in (
                "source_sha256", "workflow_sha256", "roster_sha256",
                "authority_root_sha256", "nonce_sha256")) or
            not _int(meta["generation"]) or not _int(meta["issued_at"]) or
            meta["release_ready"] is not False or
            meta["live_trading_allowed"] is not False):
        raise MerkleClaimRejected("malformed or unsafe receipt metadata")
    fields = ("RC679-UNSIGNED-RECEIPT-V1", meta["repository"], meta["branch"],
              meta["git_sha"], meta["source_sha256"], meta["workflow_sha256"],
              meta["roster_sha256"], meta["authority_root_sha256"],
              meta["nonce_sha256"], str(meta["generation"]),
              str(meta["issued_at"]), "release_ready=False", "live_trading_allowed=False")
    return hashlib.sha256("\n".join(fields).encode("ascii")).hexdigest()


def _subtree(leaves):
    if len(leaves) == 0:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + bytes.fromhex(leaves[0])).digest()
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + _subtree(leaves[:k]) + _subtree(leaves[k:])).digest()


def merkle_root_sha256(leaves):
    """RFC6962-style domain-separated binary Merkle root, never a trust anchor."""
    if not _leaves(leaves):
        raise MerkleClaimRejected("noncanonical full history")
    return _subtree(leaves).hex()


def inclusion_path_sha256(leaves, index):
    """Generate an independent-checkable audit path from invented full history."""
    if not _leaves(leaves) or type(index) is not int or index < 0:
        raise MerkleClaimRejected("noncanonical inclusion request")
    if index >= len(leaves):
        raise MerkleClaimRejected("inclusion index out of range")

    def walk(items, at):
        if len(items) == 1:
            return ()
        k = 1 << ((len(items) - 1).bit_length() - 1)
        if at < k:
            return (*walk(items[:k], at), _subtree(items[k:]).hex())
        return (*walk(items[k:], at - k), _subtree(items[:k]).hex())
    return walk(leaves, index)


def inclusion_root_sha256(leaf_sha256, index, size, proof):
    """Rebuild claimed root strictly from one leaf and its path, no trust claim."""
    if not _sha(leaf_sha256) or type(index) is not int or index < 0:
        raise MerkleClaimRejected("invalid audit index or leaf")
    if (not _int(size) or size > 128 or index >= size or
            type(proof) is not tuple or len(proof) > 8 or
            any(not _sha(h) for h in proof)):
        raise MerkleClaimRejected("invalid audit path or tree size")
    location = [0]

    def verify(n, at):
        if n == 1:
            return hashlib.sha256(b"\x00" + bytes.fromhex(leaf_sha256)).digest()
        k = 1 << ((n - 1).bit_length() - 1)
        if at < k:
            left = verify(k, at)
            if location[0] == len(proof):
                raise MerkleClaimRejected("truncated Merkle inclusion")
            right = bytes.fromhex(proof[location[0]])
        else:
            right = verify(n - k, at - k)
            if location[0] == len(proof):
                raise MerkleClaimRejected("truncated Merkle inclusion")
            left = bytes.fromhex(proof[location[0]])
        location[0] += 1
        return hashlib.sha256(b"\x01" + left + right).digest()
    root = verify(size, index)
    if location[0] != len(proof):
        raise MerkleClaimRejected("extraneous Merkle path nodes")
    return root.hex()


def quarantine_merkle_prefix(meta, before, after, proof, claims, *, pinned):
    """Validate claimed append and witnesses only; NEVER prove an actual write.

    A caller controlling inputs and pins can fabricate matching digests.
    Two concurrent invocations can both pass, so atomicity is NOT verified.
    """
    leaf = receipt_leaf_sha256(meta)
    if (not _leaves(before) or not _leaves(after) or
            len(after) != len(before) + 1 or after != (*before, leaf)):
        raise MerkleClaimRejected("not a unique one-leaf prefix extension")
    old_root, new_root = merkle_root_sha256(before), merkle_root_sha256(after)
    audit_root = inclusion_root_sha256(leaf, len(before), len(after), proof)
    if not hmac.compare_digest(audit_root, new_root):
        raise MerkleClaimRejected("invalid independent inclusion audit")
    if type(claims) is not dict or set(claims) != set(_CLAIMS):
        raise MerkleClaimRejected("unexpected claimed provider schema")
    if (not _int(claims["old_generation"]) or
            claims["old_generation"] != meta["generation"] - 1 or
            claims["new_generation"] != meta["generation"] or
            not _sha(claims["old_root_sha256"]) or
            not hmac.compare_digest(claims["old_root_sha256"], old_root) or
            not _sha(claims["new_root_sha256"]) or
            not hmac.compare_digest(claims["new_root_sha256"], new_root) or
            not _int(claims["observed_at"]) or
            claims["observed_at"] < meta["issued_at"] or
            type(claims["ack_state"]) is not str or
            claims["ack_state"] not in ("NOT_SENT", "ACK_LOST_UNRESOLVED") or
            claims["release_ready"] is not False or
            claims["live_trading_allowed"] is not False):
        raise MerkleClaimRejected("fork, rollback, invalid ACK or release claim")
    if type(pinned) is not dict or set(pinned) != set(_PINS):
        raise MerkleClaimRejected("missing or foreign expected pin")
    for k, field in (("expected_source_sha256", "source_sha256"),
                     ("expected_workflow_sha256", "workflow_sha256"),
                     ("expected_roster_sha256", "roster_sha256"),
                     ("expected_authority_root_sha256", "authority_root_sha256"),
                     ("expected_nonce_sha256", "nonce_sha256")):
        if not _sha(pinned[k]) or not hmac.compare_digest(pinned[k], meta[field]):
            raise MerkleClaimRejected("foreign source or authority pin")
    if (not _sha(pinned["expected_git_sha"], 40) or
            not hmac.compare_digest(pinned["expected_git_sha"], meta["git_sha"]) or
            any(not _sha(pinned[k]) for k in (
                "expected_old_root_sha256", "expected_new_root_sha256",
                "expected_receipt_sha256")) or
            not hmac.compare_digest(pinned["expected_old_root_sha256"], old_root) or
            not hmac.compare_digest(pinned["expected_new_root_sha256"], new_root) or
            not hmac.compare_digest(pinned["expected_receipt_sha256"], leaf) or
            not _history(pinned["spent_nonce_sha256"]) or
            not _history(pinned["seen_root_sha256"]) or
            not _events(pinned["revocation_events"]) or
            type(pinned["reviewer_keys"]) is not tuple or
            len(pinned["reviewer_keys"]) != 3 or
            any(not _sha(k) for k in pinned["reviewer_keys"]) or
            len(set(pinned["reviewer_keys"])) != 3):
        raise MerkleClaimRejected("invalid or unpinned source/history")
    if (meta["nonce_sha256"] in pinned["spent_nonce_sha256"] or
            new_root in pinned["seen_root_sha256"]):
        raise MerkleClaimRejected("replayed nonce or checkpoint root")
    writers = claims["writer_views"]
    if (type(writers) is not tuple or len(writers) != 2 or
            any(type(x) is not tuple or len(x) != 4 for x in writers) or
            not all(_name(x[0]) for x in writers) or writers[0][0] == writers[1][0]):
        raise MerkleClaimRejected("distinct claimed CAS contenders required")
    for i, (actor, gen, root, decision) in enumerate(writers):
        if (type(gen) is not int or gen != claims["old_generation"] or
                root != old_root or type(decision) is not str or
                decision != ("CLAIMED_WIN" if i == 0 else "CLAIMED_CONFLICT")):
            raise MerkleClaimRejected("two claimed winners, rollback or stale CAS")
    views = claims["provider_views"]
    if (type(views) is not tuple or len(views) != 2 or
            any(type(x) is not tuple or len(x) != 8 for x in views)):
        raise MerkleClaimRejected("two claimed OS views required")
    for i, (os, run, job, git, root, stamp, status, source) in enumerate(views):
        if (os != _PLATFORMS[i] or not _int(run) or not _int(job) or
                git != meta["git_sha"] or root != new_root or
                not _int(stamp) or not meta["issued_at"] <= stamp <= claims["observed_at"] or
                type(status) is not str or status != "NOT_VERIFIED" or
                source != meta["source_sha256"]):
            raise MerkleClaimRejected("forked, stale, or falsely signed OS view")
    if views[0][1] == views[1][1] or views[0][2] == views[1][2]:
        raise MerkleClaimRejected("duplicate host IDs")
    reviewers = claims["reviewer_views"]
    if (type(reviewers) is not tuple or len(reviewers) != 3 or
            any(type(x) is not tuple or len(x) != 7 for x in reviewers) or
            len(set(x[1] for x in reviewers)) != 3 or
            tuple(x[2] for x in reviewers) != pinned["reviewer_keys"]):
        raise MerkleClaimRejected("reviewer keys not independent")
    revocations = {k for k, ts in pinned["revocation_events"]
                   if ts <= claims["observed_at"]}
    for i, (role, actor, key, start, end, signed, status) in enumerate(reviewers):
        if (role != _ROLES[i] or not _name(actor) or not _sha(key) or
                any(not _int(t) for t in (start, end, signed)) or
                not start <= signed <= end or
                not meta["issued_at"] <= signed <= claims["observed_at"] or
                key in revocations or type(status) is not str or
                status != "NOT_VERIFIED"):
            raise MerkleClaimRejected("revoked, cloned or falsely verified reviewer")
    return {"status": "MERKLE_PREFIX_CLAIM_QUARANTINED_NOT_AUTHENTICATED",
            "old_root_sha256": old_root, "new_root_sha256": new_root,
            "lost_ack_unresolved": claims["ack_state"] == "ACK_LOST_UNRESOLVED",
            "trust_anchor_authenticated": False, "signatures_verified": False,
            "clock_verified": False, "provider_origin_verified": False,
            "atomic_cas_verified": False, "durable_write_verified": False,
            "release_ready": False, "live_trading_allowed": False}
