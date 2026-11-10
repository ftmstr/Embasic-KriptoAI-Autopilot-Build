"""RC675 synthetic revocation, multi-issuer, and CAS-ledger claim quarantine.

No signatures, authenticated trust roots, GitHub API receipts, or transactions
are verified here. All evidence AND expected pins are supplied by a caller.
A consistent envelope is *not* authority to rotate keys, release, or trade.
Only allowlisted stdlib; no I/O, dynamic evaluation, or persistent state.
"""
import hashlib
import hmac
import re


class LedgerQuarantineRejected(ValueError):
    """Malformed, stale, equivocated, or unreconciled invented evidence."""


_H40 = re.compile(r"[0-9a-f]{40}\Z")
_H64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_DOMAIN = "RC675-PUBLIC-REVOCATION-LEDGER-V1"
_MAX_NUM = (1 << 63) - 2
_MAX_SEEN = 1024
_ROLES = ("owner", "independent_reviewer", "incumbent_custodian")
_ENVELOPE = (
    "repository", "branch", "git_sha", "source_sha256", "workflow_sha256",
    "roster_sha256", "authority_epoch", "authority_root_sha256",
    "ledger_generation", "ledger_root_sha256", "proposed_generation",
    "proposed_root_sha256", "nonce_sha256", "log_sha256", "run_ids",
    "job_ids", "issuer_ids", "key_fingerprints", "approval_claims",
    "approval_state", "provider_state", "ack_state", "release_ready",
    "live_trading_allowed",
)
_PINS = (
    "git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
    "authority_epoch", "authority_root_sha256", "ledger_generation",
    "ledger_root_sha256", "run_ids", "job_ids", "log_sha256",
    "issuer_ids", "key_fingerprints", "revoked_key_fingerprints",
    "retired_authority_roots", "consumed_nonce_sha256", "seen_log_sha256",
    "seen_proposal_sha256", "expected_claim_sha256",
)


def _sha(v, length=64):
    return type(v) is str and (_H40 if length == 40 else _H64).fullmatch(v) is not None


def _number(v):
    return type(v) is int and 1 <= v <= _MAX_NUM


def _id(v):
    return type(v) is str and _ID.fullmatch(v) is not None


def _ids2(v):
    return (type(v) is tuple and len(v) == 2 and all(_number(x) for x in v)
            and v[0] != v[1])


def _sha2(v):
    return (type(v) is tuple and len(v) == 2 and all(_sha(x) for x in v)
            and v[0] != v[1])


def _ids3(v):
    return (type(v) is tuple and len(v) == 3 and all(_id(x) for x in v)
            and len(set(v)) == 3)


def _sha3(v):
    return (type(v) is tuple and len(v) == 3 and all(_sha(x) for x in v)
            and len(set(v)) == 3)


def _history(v):
    return (type(v) is tuple and len(v) <= _MAX_SEEN
            and all(_sha(x) for x in v) and v == tuple(sorted(set(v))))


def claim_sha256(envelope):
    """Domain-separated deterministic claim commitment; NEVER a signature."""
    if type(envelope) is not dict or set(envelope) != set(_ENVELOPE):
        raise LedgerQuarantineRejected("unexpected claim schema")
    if (envelope["repository"] != _REPO or envelope["branch"] != _BRANCH
            or not _sha(envelope["git_sha"], 40)
            or any(not _sha(envelope[k]) for k in (
                "source_sha256", "workflow_sha256", "roster_sha256",
                "authority_root_sha256", "ledger_root_sha256",
                "proposed_root_sha256", "nonce_sha256"))
            or not _number(envelope["authority_epoch"])
            or not _number(envelope["ledger_generation"])
            or not _number(envelope["proposed_generation"])
            or envelope["proposed_generation"] != envelope["ledger_generation"] + 1
            or envelope["proposed_root_sha256"] == envelope["ledger_root_sha256"]
            or not _sha2(envelope["log_sha256"])
            or not _ids2(envelope["run_ids"]) or not _ids2(envelope["job_ids"])
            or not _ids3(envelope["issuer_ids"])
            or not _sha3(envelope["key_fingerprints"])
            or type(envelope["approval_state"]) is not str
            or envelope["approval_state"] != "UNVERIFIED"
            or type(envelope["provider_state"]) is not str
            or envelope["provider_state"] != "UNVERIFIED"
            or type(envelope["ack_state"]) is not str
            or envelope["ack_state"] not in ("NOT_SENT", "ACK_LOST_UNRESOLVED")
            or envelope["release_ready"] is not False
            or envelope["live_trading_allowed"] is not False):
        raise LedgerQuarantineRejected("unsafe identity or generation transition")
    values = (
        _DOMAIN, envelope["repository"], envelope["branch"],
        envelope["git_sha"], envelope["source_sha256"],
        envelope["workflow_sha256"], envelope["roster_sha256"],
        str(envelope["authority_epoch"]), envelope["authority_root_sha256"],
        str(envelope["ledger_generation"]), envelope["ledger_root_sha256"],
        str(envelope["proposed_generation"]), envelope["proposed_root_sha256"],
        envelope["nonce_sha256"], *envelope["log_sha256"],
        *(str(x) for x in envelope["run_ids"]),
        *(str(x) for x in envelope["job_ids"]),
        *envelope["issuer_ids"], *envelope["key_fingerprints"],
        "approval_state=UNVERIFIED", "provider_state=UNVERIFIED",
        envelope["ack_state"], "release_ready=False", "live_trading_allowed=False",
    )
    return hashlib.sha256("\n".join(values).encode("ascii")).hexdigest()


def quarantine_synthetic_ledger(envelope, *, pinned):
    """Reject claims contradicting supplied anchors; no external ledger read.

    All histories may be fabricated; matching witness hashes authenticate no one.
    Parallel callers may both pass without a transactional CAS outside this code.
    """
    digest = claim_sha256(envelope)
    if type(pinned) is not dict or set(pinned) != set(_PINS):
        raise LedgerQuarantineRejected("missing or extra external expected field")
    for key in ("source_sha256", "workflow_sha256", "roster_sha256",
                "authority_root_sha256", "ledger_root_sha256"):
        if not _sha(pinned[key]) or not hmac.compare_digest(pinned[key], envelope[key]):
            raise LedgerQuarantineRejected("mismatched root/source/workflow anchor")
    if (not _sha(pinned["git_sha"], 40)
            or not hmac.compare_digest(pinned["git_sha"], envelope["git_sha"])
            or not _number(pinned["authority_epoch"])
            or pinned["authority_epoch"] != envelope["authority_epoch"]
            or not _number(pinned["ledger_generation"])
            or pinned["ledger_generation"] != envelope["ledger_generation"]
            or not _ids2(pinned["run_ids"]) or not _ids2(pinned["job_ids"])
            or not _sha2(pinned["log_sha256"])
            or envelope["run_ids"] != pinned["run_ids"]
            or envelope["job_ids"] != pinned["job_ids"]
            or envelope["log_sha256"] != pinned["log_sha256"]
            or not _ids3(pinned["issuer_ids"])
            or not _sha3(pinned["key_fingerprints"])
            or envelope["issuer_ids"] != pinned["issuer_ids"]
            or envelope["key_fingerprints"] != pinned["key_fingerprints"]
            or any(not _history(pinned[k]) for k in (
                "revoked_key_fingerprints", "retired_authority_roots",
                "consumed_nonce_sha256", "seen_log_sha256", "seen_proposal_sha256"))
            or not _sha(pinned["expected_claim_sha256"])
            or not hmac.compare_digest(digest, pinned["expected_claim_sha256"])):
        raise LedgerQuarantineRejected("malformed or contradicted pinned evidence")
    if (envelope["authority_root_sha256"] in pinned["retired_authority_roots"]
            or envelope["proposed_root_sha256"] in pinned["retired_authority_roots"]
            or envelope["nonce_sha256"] in pinned["consumed_nonce_sha256"]
            or envelope["proposed_root_sha256"] in pinned["seen_proposal_sha256"]
            or any(k in pinned["revoked_key_fingerprints"]
                   for k in envelope["key_fingerprints"])
            or any(log in pinned["seen_log_sha256"]
                   for log in envelope["log_sha256"])):
        raise LedgerQuarantineRejected("revoked key, retired root or replayed receipt")
    approval = envelope["approval_claims"]
    if type(approval) is not tuple or len(approval) != 3:
        raise LedgerQuarantineRejected("three claimed review roles required")
    for n, record in enumerate(approval):
        if (type(record) is not tuple or len(record) != 5
                or record[0] != _ROLES[n]
                or record[1] != envelope["issuer_ids"][n]
                or record[2] != envelope["key_fingerprints"][n]
                or not _sha(record[3])
                or not hmac.compare_digest(record[3], digest)
                or type(record[4]) is not str or record[4] != "NOT_VERIFIED"):
            raise LedgerQuarantineRejected("contradictory or fake signed witness")
    return {
        "status": "REVOKED_LEDGER_CLAIMS_QUARANTINED_NOT_AUTHENTICATED",
        "claim_sha256": digest,
        "external_root_authenticated": False,
        "signatures_verified": False,
        "cas_atomicity_verified": False,
        "ledger_write_performed": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }
