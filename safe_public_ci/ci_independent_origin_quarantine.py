"""RC685: bounded syntactic cross-witness origin and Merkle claim quarantine.

Claimed owner/reviewer, provider and witness facts are all caller-controlled.
Hash consistency is not authentication. No networking, signing keys, filesystem,
trading, model fitting, persistent CAS, or clock service occurs in this module.
"""
import hashlib
import hmac
import re


class OriginRejected(ValueError):
    """Invalid or unsafe purported evidence or source binding."""


_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_H40 = re.compile(r"[0-9a-f]{40}\Z")
_H64 = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_MAX = (1 << 63) - 2
_DOMAIN = b"RC685-UNAUTHENTICATED-WITNESS-ORIGIN-V1\x00"
_FIELDS = (
    "repository", "branch", "git_sha", "source_sha256", "workflow_sha256",
    "roster_sha256", "rc683_checkpoint_sha256", "old_size", "new_size",
    "old_root_sha256", "new_root_sha256", "full_history", "consistency_proof",
    "nonce_sha256", "issued_at", "observed_at", "authority_claims",
    "provider_claims", "witness_claims", "revocations", "cas_attempts",
    "spent_nonces", "seen_roots", "ack_state", "release_ready",
    "live_trading_allowed",
)
_PINS = (
    "git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
    "rc683_checkpoint_sha256", "old_root_sha256", "new_root_sha256",
    "nonce_sha256", "authority_fingerprints", "witness_fingerprints",
    "expected_claim_sha256", "independent_root_authenticated",
    "provider_origin_authenticated", "durable_cas_authenticated",
)


def _sha(v, n=64):
    return type(v) is str and (_H40 if n == 40 else _H64).fullmatch(v) is not None


def _num(v):
    return type(v) is int and 1 <= v <= _MAX


def _name(v):
    return type(v) is str and _NAME.fullmatch(v) is not None


def _node(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def _root(items):
    if len(items) == 1:
        return hashlib.sha256(b"\x00" + bytes.fromhex(items[0])).digest()
    k = 1 << ((len(items) - 1).bit_length() - 1)
    return _node(_root(items[:k]), _root(items[k:]))


def _consistency(items, old):
    def work(leaves, n, known):
        if n == len(leaves):
            return () if known else (_root(leaves).hex(),)
        k = 1 << ((len(leaves) - 1).bit_length() - 1)
        if n <= k:
            return (*work(leaves[:k], n, known), _root(leaves[k:]).hex())
        return (*work(leaves[k:], n-k, False), _root(leaves[:k]).hex())
    return work(items, old, True)


def _canonical(v):
    if type(v) is bool:
        return b"b1" if v else b"b0"
    if type(v) is int and 0 <= v <= _MAX:
        return b"i" + v.to_bytes(8, "big")
    if type(v) is str:
        try:
            data = v.encode("ascii")
        except UnicodeEncodeError as exc:
            raise OriginRejected("nonascii claim") from exc
        if len(data) > 256:
            raise OriginRejected("oversize field")
        return b"s" + len(data).to_bytes(2, "big") + data
    if type(v) is tuple and len(v) <= 128:
        return b"t" + len(v).to_bytes(2, "big") + b"".join(_canonical(x) for x in v)
    raise OriginRejected("noncanonical type or collection")


def _history(t):
    return (type(t) is tuple and len(t) <= 128 and all(_sha(x) for x in t) and
            t == tuple(sorted(set(t))))


def _check(claim):
    if type(claim) is not dict or set(claim) != set(_FIELDS):
        raise OriginRejected("unexpected/missing evidence field")
    if (claim["repository"] != _REPO or claim["branch"] != _BRANCH or
            not _sha(claim["git_sha"], 40) or
            any(not _sha(claim[k]) for k in (
                "source_sha256", "workflow_sha256", "roster_sha256",
                "rc683_checkpoint_sha256", "old_root_sha256", "new_root_sha256",
                "nonce_sha256")) or
            any(not _num(claim[k]) for k in (
                "old_size", "new_size", "issued_at", "observed_at")) or
            not claim["old_size"] < claim["new_size"] <= 128 or
            claim["issued_at"] > claim["observed_at"] or
            type(claim["ack_state"]) is not str or
            claim["ack_state"] not in ("NOT_SENT", "ACK_LOST_UNRESOLVED") or
            claim["release_ready"] is not False or
            claim["live_trading_allowed"] is not False):
        raise OriginRejected("unsafe identity, chronology or release")
    leaves = claim["full_history"]
    if (type(leaves) is not tuple or len(leaves) != claim["new_size"] or
            any(not _sha(x) for x in leaves) or len(set(leaves)) != len(leaves)):
        raise OriginRejected("missing or conflicting complete leaf history")
    old, new = _root(leaves[:claim["old_size"]]).hex(), _root(leaves).hex()
    if (not hmac.compare_digest(old, claim["old_root_sha256"]) or
            not hmac.compare_digest(new, claim["new_root_sha256"]) or old == new):
        raise OriginRejected("full-history root split view")
    proof = claim["consistency_proof"]
    if (type(proof) is not tuple or len(proof) > 8 or
            any(not _sha(x) for x in proof) or
            proof != _consistency(leaves, claim["old_size"])):
        raise OriginRejected("incorrect size-bound Merkle consistency proof")
    auth = claim["authority_claims"]
    if (type(auth) is not tuple or len(auth) != 2 or
            any(type(row) is not tuple or len(row) != 6 for row in auth)):
        raise OriginRejected("exactly two claimed authorities needed")
    for i, (role, name, fp, since, until, signed) in enumerate(auth):
        if (role != ("owner", "independent_reviewer")[i] or not _name(name) or
                not _sha(fp) or any(not _num(v) for v in (since, until, signed)) or
                not since <= signed <= until or
                not claim["issued_at"] <= signed <= claim["observed_at"]):
            raise OriginRejected("invalid claimed authority role/key/clock")
    if auth[0][1] == auth[1][1] or auth[0][2] == auth[1][2]:
        raise OriginRejected("owner/reviewer not distinct")
    rev = claim["revocations"]
    if (type(rev) is not tuple or len(rev) > 128 or
            any(type(row) is not tuple or len(row) != 3 or
                not _sha(row[0]) or not _num(row[1]) or not _num(row[2])
                for row in rev) or
            tuple(sorted(rev, key=lambda r: r[2])) != rev or
            len(set(r[0] for r in rev)) != len(rev) or
            len(set(r[2] for r in rev)) != len(rev)):
        raise OriginRejected("noncanonical claimed revocation sequence")
    if any(fp in (auth[0][2], auth[1][2]) and when <= claim["observed_at"]
           for fp, when, epoch in rev):
        raise OriginRejected("claimed signer key revoked")
    providers = claim["provider_claims"]
    if (type(providers) is not tuple or len(providers) != 2 or
            any(type(row) is not tuple or len(row) != 8 for row in providers)):
        raise OriginRejected("two claimed OS provider records required")
    for i, (os, run, job, git, source, full_log, attempt, state) in enumerate(providers):
        if (os != ("ubuntu", "windows")[i] or not _num(run) or not _num(job) or
                git != claim["git_sha"] or source != claim["source_sha256"] or
                not _sha(full_log) or attempt != 1 or type(attempt) is not int or
                state != "NOT_VERIFIED" or type(state) is not str):
            raise OriginRejected("provider identity/attempt/log not independently verified")
    if providers[0][1] == providers[1][1] or providers[0][2] == providers[1][2]:
        raise OriginRejected("duplicated provider run/job")
    witnesses = claim["witness_claims"]
    if (type(witnesses) is not tuple or len(witnesses) != 2 or
            any(type(row) is not tuple or len(row) != 7 for row in witnesses)):
        raise OriginRejected("two claimed independent witness domains required")
    for i, (name, fingerprint, epoch, bound_root, provider_log, stamp, state) in enumerate(witnesses):
        if (not _name(name) or not _sha(fingerprint) or epoch != i + 1 or
                type(epoch) is not int or bound_root != new or
                provider_log != providers[i][5] or not _num(stamp) or
                not claim["issued_at"] <= stamp <= claim["observed_at"] or
                type(state) is not str or state != "NOT_VERIFIED"):
            raise OriginRejected("witness root/log/epoch split view")
    if witnesses[0][0] == witnesses[1][0] or witnesses[0][1] == witnesses[1][1]:
        raise OriginRejected("claimed witness identity duplicated")
    attempts = claim["cas_attempts"]
    if (type(attempts) is not tuple or len(attempts) != 3 or
            any(type(row) is not tuple or len(row) != 6 for row in attempts)):
        raise OriginRejected("three-stage restart CAS claims required")
    for i, (actor, epoch, generation, base, proposed, status) in enumerate(attempts):
        if (not _name(actor) or type(epoch) is not int or epoch != i+1 or
                type(generation) is not int or generation != claim["old_size"] or
                base != old or proposed != new or
                type(status) is not str or
                status != ("CLAIMED_WIN" if i == 0 else "CLAIMED_CONFLICT")):
            raise OriginRejected("double-winner/ABA/stale CAS assertion")
    if len(set(row[0] for row in attempts)) != 3:
        raise OriginRejected("CAS competitor aliases")
    if (not _history(claim["spent_nonces"]) or
            not _history(claim["seen_roots"]) or
            claim["nonce_sha256"] in claim["spent_nonces"] or
            new in claim["seen_roots"]):
        raise OriginRejected("claimed nonce/root replay")


def claim_sha256(claim):
    """Only structural SHA-256 binding: never provider/signer authentication."""
    _check(claim)
    return hashlib.sha256(_DOMAIN + _canonical(tuple((k, claim[k]) for k in _FIELDS))).hexdigest()


def quarantine_witness_origin(claim, pinned):
    """Reject self-asserted trust elevation, even for coherent hash histories."""
    digest = claim_sha256(claim)
    if type(pinned) is not dict or set(pinned) != set(_PINS):
        raise OriginRejected("incomplete or excessive expected trust pins")
    for k in ("git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
              "rc683_checkpoint_sha256", "old_root_sha256", "new_root_sha256",
              "nonce_sha256"):
        if (not _sha(pinned[k], 40 if k == "git_sha" else 64) or
                not hmac.compare_digest(pinned[k], claim[k])):
            raise OriginRejected("mismatched source or checkpoint pin")
    if (type(pinned["authority_fingerprints"]) is not tuple or
            pinned["authority_fingerprints"] != tuple(row[2] for row in claim["authority_claims"]) or
            type(pinned["witness_fingerprints"]) is not tuple or
            pinned["witness_fingerprints"] != tuple(row[1] for row in claim["witness_claims"]) or
            not _sha(pinned["expected_claim_sha256"]) or
            not hmac.compare_digest(pinned["expected_claim_sha256"], digest)):
        raise OriginRejected("unbound authority/witness digest")
    for field in ("independent_root_authenticated", "provider_origin_authenticated",
                  "durable_cas_authenticated"):
        if pinned[field] is not False:
            raise OriginRejected("self-asserted authority elevation forbidden")
    return {
        "status": "CLAIMED_CROSS_WITNESS_HISTORY_QUARANTINED_NOT_AUTHENTICATED",
        "claim_sha256": digest,
        "lost_ack_unresolved": claim["ack_state"] == "ACK_LOST_UNRESOLVED",
        "signature_authority_authenticated": False,
        "independent_trust_root_authenticated": False,
        "revocation_origin_authenticated": False,
        "provider_origin_authenticated": False,
        "full_history_authenticated": False,
        "durable_cas_verified": False,
        "restart_recovery_verified": False,
        "trusted_clock_verified": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }

# RC685 final fail-closed acceptance: no external signer/provider origin is
# authenticated; claims and two local SQLite copies cannot prove durable CAS.
