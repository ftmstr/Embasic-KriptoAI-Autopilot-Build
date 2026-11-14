"""RC684: untrusted off-band provenance claims stay quarantined.

A checksum or syntactically consistent independent-looking provider record is
NOT an authenticated authority, verified GitHub log, trusted clock or CAS.
This module has no filesystem, networking, signing, trading or import hooks.
"""
import hashlib
import hmac
import re


class ProvenanceRejected(ValueError):
    """Contradictory or overprivileged synthetic provenance proposal."""


_H40 = re.compile(r"[0-9a-f]{40}\Z")
_H64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_MAX = (1 << 63) - 2
_FIELDS = (
    "repository", "branch", "git_sha", "source_sha256", "workflow_sha256",
    "roster_sha256", "checkpoint_sha256", "nonce_sha256", "issued_at",
    "observed_at", "owners", "revocations", "providers", "cas_trace",
    "spent_nonces", "seen_roots", "ack_state", "release_ready",
    "live_trading_allowed",
)
_PINS = (
    "git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
    "checkpoint_sha256", "nonce_sha256", "issuer_fingerprints",
    "expected_digest_sha256", "verified_oob_issuers",
    "verified_provider_origin", "verified_revocation_origin",
    "verified_transactional_cas",
)
_DOMAIN = b"RC684-OOB-PROVENANCE-CLAIMS-NOT-AUTHORITY-V1\x00"


def _hash(s, n=64):
    return type(s) is str and (_H40 if n == 40 else _H64).fullmatch(s) is not None


def _positive(x):
    return type(x) is int and 1 <= x <= _MAX


def _history(v):
    return (type(v) is tuple and len(v) <= 128 and
            all(_hash(x) for x in v) and v == tuple(sorted(set(v))))


def _pack(v):
    if type(v) is bool:
        return b"b1" if v else b"b0"
    if type(v) is int and 0 <= v <= _MAX:
        return b"i" + v.to_bytes(8, "big")
    if type(v) is str:
        try:
            raw = v.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ProvenanceRejected("nonascii evidence field") from exc
        if len(raw) > 256:
            raise ProvenanceRejected("oversize evidence field")
        return b"s" + len(raw).to_bytes(2, "big") + raw
    if type(v) is tuple and len(v) <= 128:
        return b"t" + len(v).to_bytes(2, "big") + b"".join(_pack(x) for x in v)
    raise ProvenanceRejected("unsupported evidence type")


def evidence_digest(claim):
    """Fingerprint ALL caller assertions; never authenticate their origin."""
    if type(claim) is not dict or set(claim) != set(_FIELDS):
        raise ProvenanceRejected("missing/extra claim fields")
    if (claim["repository"] != _REPO or claim["branch"] != _BRANCH or
            not _hash(claim["git_sha"], 40) or
            any(not _hash(claim[x]) for x in (
                "source_sha256", "workflow_sha256", "roster_sha256",
                "checkpoint_sha256", "nonce_sha256")) or
            any(not _positive(claim[x]) for x in ("issued_at", "observed_at")) or
            claim["issued_at"] > claim["observed_at"] or
            type(claim["ack_state"]) is not str or
            claim["ack_state"] not in ("NOT_SENT", "ACK_LOST_UNRESOLVED") or
            claim["release_ready"] is not False or
            claim["live_trading_allowed"] is not False):
        raise ProvenanceRejected("invalid identity, time or release gate")
    owners = claim["owners"]
    if (type(owners) is not tuple or len(owners) != 2 or
            any(type(x) is not tuple or len(x) != 5 for x in owners)):
        raise ProvenanceRejected("exactly two claimed authorities required")
    for i, (role, name, fp, valid_from, valid_to) in enumerate(owners):
        if (role != ("owner", "independent_reviewer")[i] or
                type(name) is not str or _ID.fullmatch(name) is None or
                not _hash(fp) or not _positive(valid_from) or
                not _positive(valid_to) or
                not valid_from <= claim["issued_at"] <= valid_to):
            raise ProvenanceRejected("invalid authority claim")
    if owners[0][1] == owners[1][1] or owners[0][2] == owners[1][2]:
        raise ProvenanceRejected("same actor/key twice")
    rev = claim["revocations"]
    if (type(rev) is not tuple or len(rev) > 128 or
            any(type(x) is not tuple or len(x) != 2 or
                not _hash(x[0]) or not _positive(x[1]) for x in rev) or
            rev != tuple(sorted(rev)) or len({r[0] for r in rev}) != len(rev)):
        raise ProvenanceRejected("invalid synthetic revocation ledger")
    if any(fp in (owners[0][2], owners[1][2]) and time <= claim["observed_at"]
           for fp, time in rev):
        raise ProvenanceRejected("claimed active authority revoked")
    providers = claim["providers"]
    if (type(providers) is not tuple or len(providers) != 2 or
            any(type(x) is not tuple or len(x) != 6 for x in providers)):
        raise ProvenanceRejected("missing independent OS claim")
    for i, (os, run, job, git_sha, log_sha, verified) in enumerate(providers):
        if (os != ("ubuntu", "windows")[i] or not _positive(run) or
                not _positive(job) or git_sha != claim["git_sha"] or
                not _hash(log_sha) or verified is not False):
            raise ProvenanceRejected("unsupported provider attestation")
    if providers[0][1] == providers[1][1] or providers[0][2] == providers[1][2]:
        raise ProvenanceRejected("repeated provider identity")
    trace = claim["cas_trace"]
    if (type(trace) is not tuple or len(trace) != 2 or
            any(type(x) is not tuple or len(x) != 5 for x in trace)):
        raise ProvenanceRejected("missing two CAS claims")
    for i, (name, epoch, base_gen, root_sha, result) in enumerate(trace):
        if (type(name) is not str or _ID.fullmatch(name) is None or
                type(epoch) is not int or epoch != i + 1 or
                not _positive(base_gen) or base_gen != 3 or
                not _hash(root_sha) or
                result != ("CLAIMED_WIN", "CLAIMED_CONFLICT")[i] or
                type(result) is not str):
            raise ProvenanceRejected("not a durable single-winner proof")
    if trace[0][0] == trace[1][0] or trace[0][3] != trace[1][3]:
        raise ProvenanceRejected("inconsistent CAS actors/root")
    if (not _history(claim["spent_nonces"]) or
            not _history(claim["seen_roots"]) or
            claim["nonce_sha256"] in claim["spent_nonces"] or
            trace[0][3] in claim["seen_roots"]):
        raise ProvenanceRejected("replayed nonce/root history")
    canonical = _pack(tuple((field, claim[field]) for field in _FIELDS))
    return hashlib.sha256(_DOMAIN + canonical).hexdigest()


def quarantine_provenance(claim, pinned):
    """Self-pins are compared but never promoted to authentication."""
    digest = evidence_digest(claim)
    if type(pinned) is not dict or set(pinned) != set(_PINS):
        raise ProvenanceRejected("incomplete external trust-pin record")
    for k in ("git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
              "checkpoint_sha256", "nonce_sha256"):
        if (not _hash(pinned[k], 40 if k == "git_sha" else 64) or
                not hmac.compare_digest(pinned[k], claim[k])):
            raise ProvenanceRejected("foreign expected identity")
    expected_keys = tuple(x[2] for x in claim["owners"])
    if (type(pinned["issuer_fingerprints"]) is not tuple or
            pinned["issuer_fingerprints"] != expected_keys or
            not _hash(pinned["expected_digest_sha256"]) or
            not hmac.compare_digest(pinned["expected_digest_sha256"], digest)):
        raise ProvenanceRejected("unbound asserted issuer/checkpoint")
    for k in ("verified_oob_issuers", "verified_provider_origin",
              "verified_revocation_origin", "verified_transactional_cas"):
        if pinned[k] is not False:
            raise ProvenanceRejected("cannot promote caller assertion to trust")
    return {
        "status": "EXTERNAL_PROVENANCE_CLAIMS_QUARANTINED_NOT_AUTHENTICATED",
        "evidence_digest_sha256": digest,
        "lost_ack_unresolved": claim["ack_state"] == "ACK_LOST_UNRESOLVED",
        "out_of_band_issuer_authenticated": False,
        "provider_origin_authenticated": False,
        "revocation_origin_authenticated": False,
        "clock_authenticated": False,
        "merkle_anchor_authenticated": False,
        "durable_cas_verified": False,
        "restart_recovery_verified": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }

# TUR41 final gate: mathematical equality of caller pins is not trusted origin.
# Independent signer, provider, monotonic storage and ACK proof remain NO-GO.
