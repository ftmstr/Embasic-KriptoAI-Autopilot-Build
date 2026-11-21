"""RC681: canonical synthetic evidence transcript binding; strictly NO AUTH.

The caller supplies every key, claimed signature, GitHub-like receipt, proof,
clock, full history and expected digest. Matching hashes do NOT authenticate
issuer or provider, do NOT execute CAS, and cannot authorize live trading.
"""
import hashlib
import hmac
import re


class TranscriptRejected(ValueError):
    """A synthetic transcript has an unsafe or contradictory claim."""


_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_ROLES = ("owner", "independent_reviewer", "incumbent_custodian")
_OS = ("ubuntu", "windows")
_LIMIT = (1 << 63) - 2
_MAX_LEAVES = 128
_DOMAIN = b"RC681-SYNTHETIC-FULL-TRANSCRIPT-BINDING-V1\x00"
_FIELDS = (
    "repository", "branch", "git_sha", "source_sha256", "workflow_sha256",
    "roster_sha256", "old_size", "new_size", "old_root_sha256",
    "new_root_sha256", "nonce_sha256", "issued_at", "observed_at",
    "full_history", "consistency_proof", "issuer_claims", "provider_claims",
    "writer_claims", "revocation_events", "spent_nonces", "seen_roots",
    "ack_state", "release_ready", "live_trading_allowed",
)
_PINS = (
    "git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
    "old_root_sha256", "new_root_sha256", "nonce_sha256",
    "issuer_key_fingerprints", "expected_transcript_sha256",
)


def _sha(s, n=64):
    return type(s) is str and (_HEX40 if n == 40 else _HEX64).fullmatch(s) is not None


def _num(x):
    return type(x) is int and 1 <= x <= _LIMIT


def _name(s):
    return type(s) is str and _NAME.fullmatch(s) is not None


def _history(v):
    return (type(v) is tuple and len(v) <= 128 and
            all(_sha(x) for x in v) and v == tuple(sorted(set(v))))


def _revoke(v):
    return (type(v) is tuple and len(v) <= 128 and
            all(type(x) is tuple and len(x) == 2 and _sha(x[0]) and _num(x[1])
                for x in v) and v == tuple(sorted(v)) and
            len(set(x[0] for x in v)) == len(v))


def _tree(leaves):
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + bytes.fromhex(leaves[0])).digest()
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + _tree(leaves[:k]) + _tree(leaves[k:])).digest()


def _consistency(leaves, n):
    def proof(items, old, known):
        if old == len(items):
            return () if known else (_tree(items).hex(),)
        k = 1 << ((len(items) - 1).bit_length() - 1)
        if old <= k:
            return (*proof(items[:k], old, known), _tree(items[k:]).hex())
        return (*proof(items[k:], old - k, False), _tree(items[:k]).hex())
    return proof(leaves, n, True)


def _canonical(part):
    """Length-prefixed typed encoding blocks type and separator ambiguity."""
    if type(part) is bool:
        return b"b1" if part else b"b0"
    if type(part) is int and 0 <= part <= _LIMIT:
        return b"i" + part.to_bytes(8, "big")
    if type(part) is str:
        value = part.encode("ascii")
        if len(value) > 256:
            raise TranscriptRejected("oversize transcript string")
        return b"s" + len(value).to_bytes(2, "big") + value
    if type(part) is tuple and len(part) <= 128:
        return (b"t" + len(part).to_bytes(2, "big") +
                b"".join(_canonical(x) for x in part))
    raise TranscriptRejected("noncanonical or unsupported transcript value")


def _check(claim):
    if type(claim) is not dict or set(claim) != set(_FIELDS):
        raise TranscriptRejected("unexpected or missing transcript field")
    if (claim["repository"] != _REPO or claim["branch"] != _BRANCH or
            not _sha(claim["git_sha"], 40) or
            any(not _sha(claim[k]) for k in (
                "source_sha256", "workflow_sha256", "roster_sha256",
                "old_root_sha256", "new_root_sha256", "nonce_sha256")) or
            any(not _num(claim[k]) for k in (
                "old_size", "new_size", "issued_at", "observed_at")) or
            not claim["old_size"] < claim["new_size"] <= _MAX_LEAVES or
            claim["issued_at"] > claim["observed_at"] or
            claim["ack_state"] not in ("NOT_SENT", "ACK_LOST_UNRESOLVED") or
            type(claim["ack_state"]) is not str or
            claim["release_ready"] is not False or
            claim["live_trading_allowed"] is not False):
        raise TranscriptRejected("invalid source, time, generation or release gate")
    leaves = claim["full_history"]
    if (type(leaves) is not tuple or len(leaves) != claim["new_size"] or
            any(not _sha(x) for x in leaves) or len(set(leaves)) != len(leaves)):
        raise TranscriptRejected("invalid full-history size or duplicate leaf")
    old_root, new_root = _tree(leaves[:claim["old_size"]]).hex(), _tree(leaves).hex()
    if (not hmac.compare_digest(old_root, claim["old_root_sha256"]) or
            not hmac.compare_digest(new_root, claim["new_root_sha256"]) or
            old_root == new_root):
        raise TranscriptRejected("old/new Merkle roots conflict with complete history")
    path = claim["consistency_proof"]
    if (type(path) is not tuple or len(path) > 8 or
            any(not _sha(x) for x in path) or
            path != _consistency(leaves, claim["old_size"])):
        raise TranscriptRejected("inconsistent, missing or extra Merkle proof")
    issuers = claim["issuer_claims"]
    if (type(issuers) is not tuple or len(issuers) != 3 or
            any(type(x) is not tuple or len(x) != 7 for x in issuers) or
            len(set(x[1] for x in issuers)) != 3 or
            len(set(x[2] for x in issuers)) != 3):
        raise TranscriptRejected("non-independent issuer claim")
    for i, (role, person, key, valid_from, valid_to, signed, status) in enumerate(issuers):
        if (role != _ROLES[i] or not _name(person) or not _sha(key) or
                any(not _num(v) for v in (valid_from, valid_to, signed)) or
                not valid_from <= signed <= valid_to or
                not claim["issued_at"] <= signed <= claim["observed_at"] or
                type(status) is not str or status != "NOT_VERIFIED"):
            raise TranscriptRejected("revoked or falsely signed issuer claim")
    views = claim["provider_claims"]
    if (type(views) is not tuple or len(views) != 2 or
            any(type(x) is not tuple or len(x) != 9 for x in views)):
        raise TranscriptRejected("two independent claimed provider views needed")
    for i, (os, run, job, git, source, before, after, stamp, status) in enumerate(views):
        if (os != _OS[i] or not _num(run) or not _num(job) or
                git != claim["git_sha"] or source != claim["source_sha256"] or
                before != old_root or after != new_root or not _num(stamp) or
                not claim["issued_at"] <= stamp <= claim["observed_at"] or
                type(status) is not str or status != "NOT_VERIFIED"):
            raise TranscriptRejected("provider source/identity split view")
    if views[0][1] == views[1][1] or views[0][2] == views[1][2]:
        raise TranscriptRejected("duplicate claimed GitHub run/job ID")
    writers = claim["writer_claims"]
    if (type(writers) is not tuple or len(writers) != 2 or
            any(type(x) is not tuple or len(x) != 5 for x in writers) or
            len(set(x[0] for x in writers)) != 2):
        raise TranscriptRejected("two distinct synthetic CAS contenders required")
    for i, (person, gen, base, proposed, status) in enumerate(writers):
        if (not _name(person) or type(gen) is not int or
                gen != claim["old_size"] or base != old_root or proposed != new_root or
                type(status) is not str or
                status != ("CLAIMED_WIN" if i == 0 else "CLAIMED_CONFLICT")):
            raise TranscriptRejected("CAS fork, false ACK or stale writer")
    if (not _revoke(claim["revocation_events"]) or
            not _history(claim["spent_nonces"]) or
            not _history(claim["seen_roots"]) or
            claim["nonce_sha256"] in claim["spent_nonces"] or
            new_root in claim["seen_roots"]):
        raise TranscriptRejected("malformed revocation or replayed root/nonce")
    revoked = {key for key, time in claim["revocation_events"]
               if time <= claim["observed_at"]}
    if any(x[2] in revoked for x in issuers):
        raise TranscriptRejected("claimed issuer key revoked at observed time")


def transcript_sha256(claim):
    """Bind ALL supplied claims, including witnesses, views and full history."""
    _check(claim)
    parts = tuple((field, claim[field]) for field in _FIELDS)
    return hashlib.sha256(_DOMAIN + _canonical(parts)).hexdigest()


def quarantine_bound_transcript(claim, *, pinned):
    """Structural verification ONLY. Caller-provided pins cannot prove origin."""
    digest = transcript_sha256(claim)
    if type(pinned) is not dict or set(pinned) != set(_PINS):
        raise TranscriptRejected("missing or extra expected trust field")
    for field in ("git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
                  "old_root_sha256", "new_root_sha256", "nonce_sha256"):
        if (not _sha(pinned[field], 40 if field == "git_sha" else 64) or
                not hmac.compare_digest(pinned[field], claim[field])):
            raise TranscriptRejected("unexpected source or pinned Merkle anchor")
    keys = pinned["issuer_key_fingerprints"]
    if (type(keys) is not tuple or len(keys) != 3 or
            any(not _sha(k) for k in keys) or len(set(keys)) != 3 or
            keys != tuple(x[2] for x in claim["issuer_claims"]) or
            not _sha(pinned["expected_transcript_sha256"]) or
            not hmac.compare_digest(pinned["expected_transcript_sha256"], digest)):
        raise TranscriptRejected("issuer keys or canonical transcript are unpinned")
    return {
        "status": "FULL_TRANSCRIPT_BOUND_QUARANTINED_NOT_AUTHENTICATED",
        "transcript_sha256": digest,
        "lost_ack_unresolved": claim["ack_state"] == "ACK_LOST_UNRESOLVED",
        "provider_origin_authenticated": False,
        "signatures_verified": False,
        "clock_verified": False,
        "merkle_anchor_authenticated": False,
        "cas_atomicity_verified": False,
        "durable_write_verified": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }
