"""RC678 invented append-only receipt-history and split-view quarantine.

The SHA-256 commitment is locally reproducible, NOT an authentic signature,
trusted timestamp, genuine GitHub receipt or persistent atomic CAS write.
All receipts, roots, keys and expectations are caller-controlled. NO LIVE.
"""
import hashlib
import hmac
import re


class AppendOnlyClaimRejected(ValueError):
    """Malformed, conflicting, replayed or noncanonical claimed evidence."""


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_ROLES = ("owner", "independent_reviewer", "incumbent_custodian")
_OS = ("ubuntu", "windows")
_MAX = (1 << 63) - 2
_FIELDS = (
    "repository", "branch", "git_sha", "source_sha256", "workflow_sha256",
    "roster_sha256", "authority_root_sha256", "authority_epoch", "nonce_sha256",
    "issued_at", "observed_at", "prior_generation", "next_generation",
    "prior_history", "next_history", "prior_root_sha256", "next_root_sha256",
    "writer_views", "provider_views", "reviewer_views", "revocations_before",
    "revocations_after", "ack_state", "release_ready", "live_trading_allowed",
)
_PINS = (
    "git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
    "authority_root_sha256", "authority_epoch", "prior_generation",
    "prior_root_sha256", "next_root_sha256", "expected_leaf_sha256",
    "reviewer_keys", "seen_nonce_sha256", "seen_history_roots",
)


def _sha(x, size=64):
    return type(x) is str and (_SHA40 if size == 40 else _SHA64).fullmatch(x) is not None


def _num(x):
    return type(x) is int and 1 <= x <= _MAX


def _name(x):
    return type(x) is str and _ID.fullmatch(x) is not None


def _history(x):
    return (type(x) is tuple and len(x) <= 128 and
            all(_sha(v) for v in x) and len(set(x)) == len(x))


def _sorted_history(x):
    return (type(x) is tuple and len(x) <= 128 and
            all(_sha(v) for v in x) and x == tuple(sorted(set(x))))


def _revocations(x):
    return (type(x) is tuple and len(x) <= 128 and
            all(type(v) is tuple and len(v) == 2 and _sha(v[0]) and _num(v[1])
                for v in x) and x == tuple(sorted(x)) and
            len({v[0] for v in x}) == len(x))


def history_root_sha256(leaves):
    """Hash the full claimed ordered history; no external proof or I/O."""
    if not _history(leaves):
        raise AppendOnlyClaimRejected("invalid or repeated history leaf")
    header = b"RC678-FULL-RECEIPT-HISTORY-V1\x00" + len(leaves).to_bytes(2, "big")
    return hashlib.sha256(header + b"".join(bytes.fromhex(v) for v in leaves)).hexdigest()


def claim_leaf_sha256(claim):
    """Domain-separated synthetic proposed receipt; cannot verify origin."""
    if type(claim) is not dict or set(claim) != set(_FIELDS):
        raise AppendOnlyClaimRejected("unknown or missing claim fields")
    if (claim["repository"] != _REPO or claim["branch"] != _BRANCH or
            not _sha(claim["git_sha"], 40) or
            any(not _sha(claim[k]) for k in (
                "source_sha256", "workflow_sha256", "roster_sha256",
                "authority_root_sha256", "nonce_sha256")) or
            any(not _num(claim[k]) for k in (
                "authority_epoch", "issued_at", "observed_at",
                "prior_generation", "next_generation")) or
            claim["issued_at"] > claim["observed_at"] or
            claim["next_generation"] != claim["prior_generation"] + 1 or
            type(claim["ack_state"]) is not str or
            claim["ack_state"] not in ("NOT_SENT", "ACK_LOST_UNRESOLVED") or
            claim["release_ready"] is not False or
            claim["live_trading_allowed"] is not False):
        raise AppendOnlyClaimRejected("untrusted time, source or release state")
    fields = (
        "RC678-SYNTHETIC-RECEIPT-V1", claim["repository"], claim["branch"],
        claim["git_sha"], claim["source_sha256"], claim["workflow_sha256"],
        claim["roster_sha256"], claim["authority_root_sha256"],
        str(claim["authority_epoch"]), claim["nonce_sha256"],
        str(claim["issued_at"]), str(claim["observed_at"]),
        str(claim["prior_generation"]), str(claim["next_generation"]),
        claim["ack_state"], "release_ready=False", "live_trading_allowed=False",
    )
    return hashlib.sha256("\n".join(fields).encode("ascii")).hexdigest()


def quarantine_append_only_claim(claim, *, pinned):
    """Check supplied observations, NOT actual append-only or single-winner CAS.

    Two independent calls may both accept the same claimed transition.
    A malicious caller controlling observations plus pins may forge everything.
    """
    leaf = claim_leaf_sha256(claim)
    if type(pinned) is not dict or set(pinned) != set(_PINS):
        raise AppendOnlyClaimRejected("missing or foreign expectation schema")
    for k in ("source_sha256", "workflow_sha256", "roster_sha256",
              "authority_root_sha256", "prior_root_sha256", "next_root_sha256"):
        if not _sha(pinned[k]) or not _sha(claim[k]) or not hmac.compare_digest(pinned[k], claim[k]):
            raise AppendOnlyClaimRejected("unmatched source, authority or history root")
    if (not _sha(pinned["git_sha"], 40) or
            not hmac.compare_digest(pinned["git_sha"], claim["git_sha"]) or
            not _num(pinned["authority_epoch"]) or
            pinned["authority_epoch"] != claim["authority_epoch"] or
            not _num(pinned["prior_generation"]) or
            pinned["prior_generation"] != claim["prior_generation"] or
            not _sha(pinned["expected_leaf_sha256"]) or
            not hmac.compare_digest(pinned["expected_leaf_sha256"], leaf) or
            not _sorted_history(pinned["seen_nonce_sha256"]) or
            not _sorted_history(pinned["seen_history_roots"])):
        raise AppendOnlyClaimRejected("missing historical pin or stale generation")
    before, after = claim["prior_history"], claim["next_history"]
    if (not _history(before) or not _history(after) or
            len(after) != len(before) + 1 or
            after != (*before, leaf) or
            claim["prior_root_sha256"] != history_root_sha256(before) or
            claim["next_root_sha256"] != history_root_sha256(after) or
            claim["prior_root_sha256"] == claim["next_root_sha256"] or
            claim["nonce_sha256"] in pinned["seen_nonce_sha256"] or
            claim["next_root_sha256"] in pinned["seen_history_roots"]):
        raise AppendOnlyClaimRejected("rollback, replay, fork or missing receipt")
    writers = claim["writer_views"]
    if (type(writers) is not tuple or len(writers) != 2 or
            any(type(w) is not tuple or len(w) != 4 for w in writers) or
            not all(_name(w[0]) for w in writers) or writers[0][0] == writers[1][0]):
        raise AppendOnlyClaimRejected("two distinct claimed contenders required")
    for i, (worker, gen, root, verdict) in enumerate(writers):
        if (type(gen) is not int or gen != claim["prior_generation"] or
                root != claim["prior_root_sha256"] or type(verdict) is not str or
                verdict != ("CLAIMED_WIN" if i == 0 else "CLAIMED_CONFLICT")):
            raise AppendOnlyClaimRejected("claimed two winners or wrong source revision")
    providers = claim["provider_views"]
    if (type(providers) is not tuple or len(providers) != 2 or
            any(type(v) is not tuple or len(v) != 8 for v in providers)):
        raise AppendOnlyClaimRejected("missing split-view evidence")
    for i, (os, run, job, sha, gen, root, at, status) in enumerate(providers):
        if (os != _OS[i] or not _num(run) or not _num(job) or
                sha != claim["git_sha"] or type(gen) is not int or
                gen != claim["next_generation"] or root != claim["next_root_sha256"] or
                not _num(at) or not claim["issued_at"] <= at <= claim["observed_at"] or
                type(status) is not str or status != "NOT_VERIFIED"):
            raise AppendOnlyClaimRejected("provider fork, stale readback or signed-status spoof")
    if providers[0][1] == providers[1][1] or providers[0][2] == providers[1][2]:
        raise AppendOnlyClaimRejected("duplicate provider run or job identity")
    reviewers = claim["reviewer_views"]
    if (type(reviewers) is not tuple or len(reviewers) != 3 or
            any(type(r) is not tuple or len(r) != 7 for r in reviewers) or
            len({r[1] for r in reviewers}) != 3 or
            len({r[2] for r in reviewers}) != 3 or
            type(pinned["reviewer_keys"]) is not tuple or
            pinned["reviewer_keys"] != tuple(r[2] for r in reviewers)):
        raise AppendOnlyClaimRejected("cloned witness or foreign signing key")
    for i, (role, actor, key, start, end, signed, status) in enumerate(reviewers):
        if (role != _ROLES[i] or not _name(actor) or not _sha(key) or
                not _num(start) or not _num(end) or not _num(signed) or
                not start <= signed <= end or
                not claim["issued_at"] <= signed <= claim["observed_at"] or
                type(status) is not str or status != "NOT_VERIFIED"):
            raise AppendOnlyClaimRejected("invalid or falsely authenticated signer")
    prior_revoke, next_revoke = claim["revocations_before"], claim["revocations_after"]
    if (not _revocations(prior_revoke) or not _revocations(next_revoke) or
            not set(prior_revoke).issubset(next_revoke) or
            any(k in {key for key, at in next_revoke if at <= claim["observed_at"]}
                for k in pinned["reviewer_keys"])):
        raise AppendOnlyClaimRejected("revocation rollback or revoked witness")
    return {
        "status": "APPEND_ONLY_CLAIM_QUARANTINED_NOT_AUTHENTICATED",
        "leaf_sha256": leaf,
        "next_root_sha256": claim["next_root_sha256"],
        "lost_ack_unresolved": claim["ack_state"] == "ACK_LOST_UNRESOLVED",
        "trusted_anchor_verified": False,
        "signatures_verified": False,
        "clock_verified": False,
        "provider_origin_verified": False,
        "atomic_cas_verified": False,
        "durable_write_verified": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }
