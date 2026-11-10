"""RC674 invented-evidence witness equivocation quarantine; NO authentication.

The caller supplies ALL observations, pins, identities and historical records.
Matching digests/actor strings/verification-status claims cannot prove a human
approval, signature validity, GitHub origin, CAS commit or single-use receipt.
Nothing here changes any durable state or permits live trading or release.
"""
import hashlib
import hmac
import re


class WitnessQuarantineRejected(ValueError):
    """Malformed, conflicting, replayed or unsafe synthetic witness claims."""


_H40 = re.compile(r"[0-9a-f]{40}\Z")
_H64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_MAX = (1 << 63) - 2
_MAX_HISTORY = 1024
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_DOMAIN = "RC674-PUBLIC-WITNESS-QUARANTINE-V1"
_KEYS = (
    "repository", "branch", "intent_sha256", "previous_context_sha256",
    "old_root_sha256", "new_root_sha256", "git_sha", "source_sha256",
    "workflow_sha256", "roster_sha256", "nonce_sha256", "cas_generation",
    "ack_state", "run_ids", "job_ids", "log_sha256", "approval_claims",
    "provider_claims", "release_ready", "live_trading_allowed",
)
_PIN_KEYS = (
    "intent_sha256", "previous_context_sha256", "old_root_sha256",
    "git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
    "cas_generation", "run_ids", "job_ids", "log_sha256",
    "spent_nonce_sha256", "seen_log_sha256", "old_root_history",
    "approver_ids", "approver_key_fingerprints",
)
_ROLES = ("owner", "independent_reviewer", "incumbent_custodian")
_OSES = ("ubuntu", "windows")


def _sha(v, n=64):
    return type(v) is str and (_H40 if n == 40 else _H64).fullmatch(v) is not None


def _id(v):
    return type(v) is str and _ID.fullmatch(v) is not None


def _number(v):
    return type(v) is int and 1 <= v <= _MAX


def _num_pair(v):
    return (type(v) is tuple and len(v) == 2 and
            all(_number(x) for x in v) and v[0] != v[1])


def _log_pair(v):
    return (type(v) is tuple and len(v) == 2 and
            all(_sha(x) for x in v) and v[0] != v[1])


def _history(v):
    return (type(v) is tuple and len(v) <= _MAX_HISTORY and
            all(_sha(x) for x in v) and v == tuple(sorted(set(v))))


def _ids(v):
    return (type(v) is tuple and len(v) == 3 and
            all(_id(x) for x in v) and len(set(v)) == 3)


def _keys(v):
    return (type(v) is tuple and len(v) == 3 and
            all(_sha(x) for x in v) and len(set(v)) == 3)


def claimed_witness_digest(envelope):
    """Deterministic domain-separated statement hash, NOT a signature."""
    if type(envelope) is not dict or set(envelope) != set(_KEYS):
        raise WitnessQuarantineRejected("unexpected envelope fields")
    if (envelope["repository"] != _REPO or envelope["branch"] != _BRANCH or
            any(not _sha(envelope[x]) for x in (
                "intent_sha256", "previous_context_sha256", "old_root_sha256",
                "new_root_sha256", "source_sha256", "workflow_sha256",
                "roster_sha256", "nonce_sha256")) or
            not _sha(envelope["git_sha"], 40) or
            envelope["old_root_sha256"] == envelope["new_root_sha256"] or
            not _number(envelope["cas_generation"]) or
            type(envelope["ack_state"]) is not str or
            envelope["ack_state"] not in ("NOT_SUBMITTED", "ACK_LOST_UNRESOLVED") or
            not _num_pair(envelope["run_ids"]) or
            not _num_pair(envelope["job_ids"]) or
            not _log_pair(envelope["log_sha256"]) or
            envelope["release_ready"] is not False or
            envelope["live_trading_allowed"] is not False):
        raise WitnessQuarantineRejected("invalid source, OS, CAS or live safety claim")
    values = (
        _DOMAIN, envelope["repository"], envelope["branch"],
        envelope["intent_sha256"], envelope["previous_context_sha256"],
        envelope["old_root_sha256"], envelope["new_root_sha256"],
        envelope["git_sha"], envelope["source_sha256"],
        envelope["workflow_sha256"], envelope["roster_sha256"],
        envelope["nonce_sha256"], str(envelope["cas_generation"]),
        envelope["ack_state"], str(envelope["run_ids"][0]),
        str(envelope["run_ids"][1]), str(envelope["job_ids"][0]),
        str(envelope["job_ids"][1]), envelope["log_sha256"][0],
        envelope["log_sha256"][1], "release_ready=False", "live_trading_allowed=False",
    )
    return hashlib.sha256("\n".join(values).encode("ascii")).hexdigest()


def quarantine_synthetic_witnesses(envelope, *, pinned):
    """Reject contradictory claimed approvals and OS receipts, never authorize.

    Actor IDs and public-key fingerprints are unverified STRINGS. The provider
    observations are caller-supplied, not API or signed receipt verification.
    """
    digest = claimed_witness_digest(envelope)
    if type(pinned) is not dict or set(pinned) != set(_PIN_KEYS):
        raise WitnessQuarantineRejected("missing or extra independent pin")
    for k in ("intent_sha256", "previous_context_sha256", "old_root_sha256",
              "source_sha256", "workflow_sha256", "roster_sha256"):
        if not _sha(pinned[k]) or not hmac.compare_digest(envelope[k], pinned[k]):
            raise WitnessQuarantineRejected("foreign source, root or evidence pin")
    if (not _sha(pinned["git_sha"], 40) or
            not hmac.compare_digest(envelope["git_sha"], pinned["git_sha"]) or
            not _number(pinned["cas_generation"]) or
            pinned["cas_generation"] != envelope["cas_generation"] or
            not _num_pair(pinned["run_ids"]) or
            not _num_pair(pinned["job_ids"]) or
            not _log_pair(pinned["log_sha256"]) or
            envelope["run_ids"] != pinned["run_ids"] or
            envelope["job_ids"] != pinned["job_ids"] or
            envelope["log_sha256"] != pinned["log_sha256"] or
            not _history(pinned["spent_nonce_sha256"]) or
            not _history(pinned["seen_log_sha256"]) or
            not _history(pinned["old_root_history"]) or
            not _ids(pinned["approver_ids"]) or
            not _keys(pinned["approver_key_fingerprints"])):
        raise WitnessQuarantineRejected("noncanonical pinned runner or witness identity")
    if (envelope["nonce_sha256"] in pinned["spent_nonce_sha256"] or
            envelope["new_root_sha256"] in pinned["old_root_history"] or
            any(x in pinned["seen_log_sha256"] for x in envelope["log_sha256"])):
        raise WitnessQuarantineRejected("replayed nonce, log or authority root")
    approvals = envelope["approval_claims"]
    if type(approvals) is not tuple or len(approvals) != 3:
        raise WitnessQuarantineRejected("three distinct claimed approvals required")
    for n, a in enumerate(approvals):
        # No authentic signature verifies here. An unverified signature/claim
        # is quarantined even when its digest matches every expected digest.
        if (type(a) is not tuple or len(a) != 5 or
                a[0] != _ROLES[n] or a[1] != pinned["approver_ids"][n] or
                a[2] != pinned["approver_key_fingerprints"][n] or
                not _sha(a[3]) or not hmac.compare_digest(a[3], digest) or
                a[4] != "NOT_VERIFIED" or type(a[4]) is not str):
            raise WitnessQuarantineRejected("conflicting or purportedly verified reviewer")
    provider = envelope["provider_claims"]
    if type(provider) is not tuple or len(provider) != 2:
        raise WitnessQuarantineRejected("two platform receipts required")
    for n, view in enumerate(provider):
        if (type(view) is not tuple or len(view) != 7 or
                view[0] != _OSES[n] or
                type(view[1]) is not int or view[1] != envelope["run_ids"][n] or
                type(view[2]) is not int or view[2] != envelope["job_ids"][n] or
                not _sha(view[3], 40) or view[3] != envelope["git_sha"] or
                not _sha(view[4]) or view[4] != envelope["log_sha256"][n] or
                not _sha(view[5]) or not hmac.compare_digest(view[5], digest) or
                view[6] != "NOT_VERIFIED" or type(view[6]) is not str):
            raise WitnessQuarantineRejected("platform equivocation or forged verified state")
    return {
        "status": "WITNESS_CLAIMS_QUARANTINED_NOT_AUTHENTICATED",
        "statement_sha256": digest,
        "claimed_approvers": 3,
        "claimed_platforms": 2,
        "independent_signatures_verified": False,
        "provider_origin_verified": False,
        "cas_atomicity_verified": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }
