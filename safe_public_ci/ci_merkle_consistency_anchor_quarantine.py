"""RC680 bounded RFC6962-style synthetic consistency, NEVER signed provenance.

All roots, issuer identities, signatures, revocation times and CAS readbacks
are supplied by the caller and are NOT independently authenticated or stored.
"""
import hashlib
import hmac
import re


class AnchorClaimRejected(ValueError):
    """Malformed or self-contradictory synthetic anchor evidence."""


_H40 = re.compile(r"[0-9a-f]{40}\Z")
_H64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_MAX = (1 << 63) - 2
_FIELDS = (
    "repository", "branch", "git_sha", "source_sha256", "workflow_sha256",
    "roster_sha256", "old_root_sha256", "new_root_sha256",
    "old_size", "new_size", "nonce_sha256", "issued_at", "observed_at",
    "issuer_claims", "provider_claims", "writer_claims", "ack_state",
    "release_ready", "live_trading_allowed",
)
_PINS = (
    "git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
    "old_root_sha256", "new_root_sha256", "nonce_sha256",
    "issuer_key_fingerprints", "revocation_events", "spent_nonces",
    "seen_roots", "expected_statement_sha256",
)


def _sha(v, n=64):
    return type(v) is str and (_H40 if n == 40 else _H64).fullmatch(v) is not None


def _num(v):
    return type(v) is int and 1 <= v <= _MAX


def _id(v):
    return type(v) is str and _ID.fullmatch(v) is not None


def _history(values):
    return (type(values) is tuple and len(values) <= 128 and
            all(_sha(v) for v in values) and values == tuple(sorted(set(values))))


def _events(values):
    return (type(values) is tuple and len(values) <= 128 and
            all(type(v) is tuple and len(v) == 2 and _sha(v[0]) and _num(v[1])
                for v in values) and values == tuple(sorted(values)) and
            len({v[0] for v in values}) == len(values))


def _node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _root(leaves):
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + bytes.fromhex(leaves[0])).digest()
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    return _node(_root(leaves[:k]), _root(leaves[k:]))


def merkle_root(leaves):
    if (type(leaves) is not tuple or not 1 <= len(leaves) <= 128 or
            any(not _sha(leaf) for leaf in leaves) or
            len(set(leaves)) != len(leaves)):
        raise AnchorClaimRejected("invalid bounded Merkle leaf sequence")
    return _root(leaves).hex()


def consistency_path(leaves, old_size):
    """RFC6962 SUBPROOF audit nodes from a complete INVENTED history."""
    merkle_root(leaves)
    if not _num(old_size) or old_size > len(leaves):
        raise AnchorClaimRejected("invalid old tree size")

    def subproof(items, m, known):
        if m == len(items):
            return () if known else (_root(items).hex(),)
        k = 1 << ((len(items) - 1).bit_length() - 1)
        if m <= k:
            return (*subproof(items[:k], m, known), _root(items[k:]).hex())
        return (*subproof(items[k:], m - k, False), _root(items[:k]).hex())
    return subproof(leaves, old_size, True)


def verify_consistency(old_size, new_size, old_root, new_root, proof, *, full_history):
    """Verify compact RFC6962 consistency structure, not trust in roots."""
    if (not _num(old_size) or not _num(new_size) or
            new_size > 128 or old_size > new_size or
            not _sha(old_root) or not _sha(new_root) or
            type(proof) is not tuple or len(proof) > 8 or
            any(not _sha(item) for item in proof)):
        raise AnchorClaimRejected("invalid claimed consistency proof")
    # A compact path alone may be ambiguous about a terminal subtree's size.
    # Require the exact bounded full history and independently recompute both
    # size-specific roots; this still cannot authenticate the supplied leaves.
    if (type(full_history) is not tuple or len(full_history) != new_size or
            not hmac.compare_digest(merkle_root(full_history), new_root) or
            not hmac.compare_digest(merkle_root(full_history[:old_size]), old_root)):
        raise AnchorClaimRejected("missing or contradicted full-history witness")
    if old_size == new_size:
        if proof or not hmac.compare_digest(old_root, new_root):
            raise AnchorClaimRejected("equal-size split view")
        return True
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if old_size & (old_size - 1) == 0:
        fr = sr = bytes.fromhex(old_root)
        offset = 0
    else:
        if not proof:
            raise AnchorClaimRejected("truncated consistency proof")
        fr = sr = bytes.fromhex(proof[0])
        offset = 1
    for node in proof[offset:]:
        if sn == 0:
            raise AnchorClaimRejected("extraneous consistency node")
        h = bytes.fromhex(node)
        if fn & 1 or fn == sn:
            fr = _node(h, fr)
            sr = _node(h, sr)
            while fn != 0 and fn & 1 == 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _node(sr, h)
        fn >>= 1
        sn >>= 1
    if (sn != 0 or not hmac.compare_digest(fr.hex(), old_root) or
            not hmac.compare_digest(sr.hex(), new_root)):
        raise AnchorClaimRejected("consistency proof contradicts supplied roots")
    return True


def statement_sha256(claim):
    """Domain-separated caller claim hash, not signature verification."""
    if type(claim) is not dict or set(claim) != set(_FIELDS):
        raise AnchorClaimRejected("unexpected claim schema")
    if (claim["repository"] != _REPO or claim["branch"] != _BRANCH or
            not _sha(claim["git_sha"], 40) or
            any(not _sha(claim[k]) for k in (
                "source_sha256", "workflow_sha256", "roster_sha256",
                "old_root_sha256", "new_root_sha256", "nonce_sha256")) or
            any(not _num(claim[k]) for k in (
                "old_size", "new_size", "issued_at", "observed_at")) or
            not claim["old_size"] < claim["new_size"] <= 128 or
            claim["issued_at"] > claim["observed_at"] or
            type(claim["ack_state"]) is not str or
            claim["ack_state"] not in ("NOT_SENT", "ACK_LOST_UNRESOLVED") or
            claim["release_ready"] is not False or
            claim["live_trading_allowed"] is not False):
        raise AnchorClaimRejected("unsafe source, history or release claim")
    fields = ("RC680-UNAUTHENTICATED-MERKLE-ANCHOR-V1", claim["repository"],
              claim["branch"], claim["git_sha"], claim["source_sha256"],
              claim["workflow_sha256"], claim["roster_sha256"],
              claim["old_root_sha256"], claim["new_root_sha256"],
              str(claim["old_size"]), str(claim["new_size"]),
              claim["nonce_sha256"], str(claim["issued_at"]),
              str(claim["observed_at"]), claim["ack_state"],
              "release_ready=False", "live_trading_allowed=False")
    return hashlib.sha256("\n".join(fields).encode("ascii")).hexdigest()


def quarantine_anchor_consistency(claim, proof, *, pinned, full_history):
    """Structural-only claimed tree consistency, NO authentic approvals or CAS."""
    digest = statement_sha256(claim)
    verify_consistency(claim["old_size"], claim["new_size"],
                       claim["old_root_sha256"], claim["new_root_sha256"], proof,
                       full_history=full_history)
    if type(pinned) is not dict or set(pinned) != set(_PINS):
        raise AnchorClaimRejected("missing or extra expected pin")
    for k in ("source_sha256", "workflow_sha256", "roster_sha256",
              "old_root_sha256", "new_root_sha256", "nonce_sha256"):
        if not _sha(pinned[k]) or not hmac.compare_digest(claim[k], pinned[k]):
            raise AnchorClaimRejected("foreign expected root/source")
    if (not _sha(pinned["git_sha"], 40) or
            not hmac.compare_digest(claim["git_sha"], pinned["git_sha"]) or
            not _sha(pinned["expected_statement_sha256"]) or
            not hmac.compare_digest(digest, pinned["expected_statement_sha256"]) or
            not _history(pinned["spent_nonces"]) or
            not _history(pinned["seen_roots"]) or
            not _events(pinned["revocation_events"])):
        raise AnchorClaimRejected("invalid expected identity/history")
    if (claim["nonce_sha256"] in pinned["spent_nonces"] or
            claim["new_root_sha256"] in pinned["seen_roots"]):
        raise AnchorClaimRejected("nonce/root replay")
    issuers = claim["issuer_claims"]
    keys = pinned["issuer_key_fingerprints"]
    if (type(issuers) is not tuple or len(issuers) != 3 or
            type(keys) is not tuple or len(keys) != 3 or
            any(not _sha(k) for k in keys) or len(set(keys)) != 3 or
            any(type(row) is not tuple or len(row) != 5 for row in issuers) or
            len({row[1] for row in issuers}) != 3):
        raise AnchorClaimRejected("non-independent purported issuers")
    roles = ("owner", "independent_reviewer", "incumbent_custodian")
    revoked = {k for k, t in pinned["revocation_events"]
               if t <= claim["observed_at"]}
    for i, row in enumerate(issuers):
        role, actor, key, signed_at, state = row
        if (role != roles[i] or not _id(actor) or key != keys[i] or
                not _num(signed_at) or
                not claim["issued_at"] <= signed_at <= claim["observed_at"] or
                key in revoked or type(state) is not str or state != "NOT_VERIFIED"):
            raise AnchorClaimRejected("revoked or falsely signed issuer")
    providers = claim["provider_claims"]
    if (type(providers) is not tuple or len(providers) != 2 or
            any(type(x) is not tuple or len(x) != 7 for x in providers)):
        raise AnchorClaimRejected("missing OS evidence")
    for i, row in enumerate(providers):
        os, run, job, git, root, stamp, status = row
        if (os != ("ubuntu", "windows")[i] or not _num(run) or not _num(job) or
                git != claim["git_sha"] or root != claim["new_root_sha256"] or
                not _num(stamp) or
                not claim["issued_at"] <= stamp <= claim["observed_at"] or
                type(status) is not str or status != "NOT_VERIFIED"):
            raise AnchorClaimRejected("forked or forged provider readback")
    if (providers[0][1] == providers[1][1] or
            providers[0][2] == providers[1][2]):
        raise AnchorClaimRejected("duplicate provider ID")
    writers = claim["writer_claims"]
    if (type(writers) is not tuple or len(writers) != 2 or
            any(type(x) is not tuple or len(x) != 4 for x in writers) or
            not all(_id(x[0]) for x in writers) or writers[0][0] == writers[1][0]):
        raise AnchorClaimRejected("missing distinct CAS contenders")
    for i, row in enumerate(writers):
        actor, generation, root, result = row
        if (type(generation) is not int or generation != claim["old_size"] or
                root != claim["old_root_sha256"] or type(result) is not str or
                result != ("CLAIMED_WIN" if i == 0 else "CLAIMED_CONFLICT")):
            raise AnchorClaimRejected("double CAS winner, stale read or rollback")
    return {
        "status": "MERKLE_CONSISTENCY_CLAIM_QUARANTINED_NOT_AUTHENTICATED",
        "statement_sha256": digest,
        "lost_ack_unresolved": claim["ack_state"] == "ACK_LOST_UNRESOLVED",
        "authenticated_signatures": False,
        "authenticated_anchor": False,
        "authenticated_clock": False,
        "authenticated_provider_origin": False,
        "cas_atomicity_verified": False,
        "durable_write_verified": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }
