"""RC676 synthetic fork and revocation checkpoint consistency, NO AUTHENTICATION.

Every observation, history, signer identity and expected pin is caller supplied.
Matching SHA-256 digests are not independently signed roots, provider proof,
atomic CAS, durable storage, or actual consumed receipts. Never release/trade.
No network/filesystem, dynamic execution, or state mutation.
"""
import hashlib
import hmac
import re


class CheckpointForkRejected(ValueError):
    """Noncanonical, forked, revocation-stale or purportedly signed claims."""


_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_IDENT = re.compile(r"[a-z][a-z0-9_]{0,23}\Z")
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_DOMAIN = "RC676-PUBLIC-SYNTHETIC-CHECKPOINT-FORK-V1"
_MAX_GEN = (1 << 63) - 2
_MAX_HISTORY = 512
_ROLES = ("owner", "independent_reviewer", "incumbent_custodian")
_FIELDS = (
    "repository", "branch", "git_sha", "source_sha256", "workflow_sha256",
    "roster_sha256", "authority_root_sha256", "authority_epoch",
    "before_generation", "before_root_sha256", "after_generation",
    "after_root_sha256", "nonce_sha256", "pair_sha256", "log_sha256",
    "writer_claims", "observer_claims", "approver_ids", "approver_keys",
    "approval_claims", "revoked_before", "revoked_after",
    "spent_before", "spent_after", "logs_before", "logs_after",
    "ack_state", "provider_status", "signature_status",
    "release_ready", "live_trading_allowed",
)
_PINS = (
    "git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
    "authority_root_sha256", "authority_epoch", "before_generation",
    "before_root_sha256", "after_root_sha256", "nonce_sha256",
    "pair_sha256", "log_sha256", "writer_ids", "observer_ids",
    "approver_ids", "approver_keys", "expected_claim_sha256",
)


def _sha(v, n=64):
    return type(v) is str and (_HEX40 if n == 40 else _HEX64).fullmatch(v) is not None


def _id(v):
    return type(v) is str and _IDENT.fullmatch(v) is not None


def _gen(v):
    return type(v) is int and 0 <= v <= _MAX_GEN


def _history(v):
    return (type(v) is tuple and len(v) <= _MAX_HISTORY and
            all(_sha(x) for x in v) and v == tuple(sorted(set(v))))


def _two_sha(v):
    return type(v) is tuple and len(v) == 2 and all(_sha(x) for x in v) and v[0] != v[1]


def _two_id(v):
    return type(v) is tuple and len(v) == 2 and all(_id(x) for x in v) and v[0] != v[1]


def _three_id(v):
    return type(v) is tuple and len(v) == 3 and all(_id(x) for x in v) and len(set(v)) == 3


def _three_sha(v):
    return type(v) is tuple and len(v) == 3 and all(_sha(x) for x in v) and len(set(v)) == 3


def _check_envelope(c):
    if type(c) is not dict or set(c) != set(_FIELDS):
        raise CheckpointForkRejected("unexpected or missing synthetic claim fields")
    if (c["repository"] != _REPO or c["branch"] != _BRANCH or
            not _sha(c["git_sha"], 40) or
            any(not _sha(c[k]) for k in (
                "source_sha256", "workflow_sha256", "roster_sha256",
                "authority_root_sha256", "before_root_sha256", "after_root_sha256",
                "nonce_sha256", "pair_sha256")) or
            not _gen(c["authority_epoch"]) or c["authority_epoch"] < 1 or
            not _gen(c["before_generation"]) or
            not _gen(c["after_generation"]) or
            c["after_generation"] != c["before_generation"] + 1 or
            c["after_root_sha256"] == c["before_root_sha256"] or
            not _two_sha(c["log_sha256"])):
        raise CheckpointForkRejected("invalid source, generation, receipt or writer identities")
    if (type(c["writer_claims"]) is not tuple or len(c["writer_claims"]) != 2 or
            not all(type(x) is tuple and len(x) == 6 for x in c["writer_claims"]) or
            not _two_id(tuple(x[0] for x in c["writer_claims"])) or
            type(c["observer_claims"]) is not tuple or len(c["observer_claims"]) != 2 or
            not all(type(x) is tuple and len(x) == 4 for x in c["observer_claims"]) or
            not _two_id(tuple(x[0] for x in c["observer_claims"])) or
            not _three_id(c["approver_ids"]) or not _three_sha(c["approver_keys"]) or
            type(c["approval_claims"]) is not tuple or len(c["approval_claims"]) != 3 or
            not all(type(x) is tuple and len(x) == 4 for x in c["approval_claims"]) or
            any(not _history(c[k]) for k in (
                "revoked_before", "revoked_after", "spent_before", "spent_after",
                "logs_before", "logs_after")) or
            type(c["ack_state"]) is not str or
            c["ack_state"] not in ("ACK_CLAIMED", "ACK_LOST_UNRESOLVED") or
            type(c["provider_status"]) is not str or c["provider_status"] != "NOT_VERIFIED" or
            type(c["signature_status"]) is not str or c["signature_status"] != "NOT_VERIFIED" or
            c["release_ready"] is not False or c["live_trading_allowed"] is not False):
        raise CheckpointForkRejected("invalid observers, authority or quarantined status")
    wids = tuple(x[0] for x in c["writer_claims"])
    for i, writer in enumerate(c["writer_claims"]):
        name, g, root, action, nonce, pair = writer
        if (name != wids[i] or type(g) is not int or g != c["before_generation"] or
                not _sha(root) or root != c["before_root_sha256"] or
                type(action) is not str or action != ("CLAIMED_WIN" if i == 0 else "CLAIMED_CONFLICT") or
                nonce != c["nonce_sha256"] or pair != c["pair_sha256"]):
            raise CheckpointForkRejected("two winners, false conflict or stale writer")
    for observer in c["observer_claims"]:
        name, g, root, status = observer
        if (not _id(name) or type(g) is not int or g != c["after_generation"] or
                root != c["after_root_sha256"] or type(status) is not str or
                status != "NOT_VERIFIED"):
            raise CheckpointForkRejected("forked, stale or falsely trusted observer")
    for i, record in enumerate(c["approval_claims"]):
        if (record[0] != _ROLES[i] or record[1] != c["approver_ids"][i] or
                record[2] != c["approver_keys"][i] or
                type(record[3]) is not str or record[3] != "NOT_VERIFIED"):
            raise CheckpointForkRejected("contradictory or fake signed reviewer")
    if (not set(c["revoked_before"]).issubset(c["revoked_after"]) or
            any(key in c["revoked_after"] for key in c["approver_keys"]) or
            not set(c["spent_before"]).issubset(c["spent_after"]) or
            c["nonce_sha256"] in c["spent_before"] or
            c["spent_after"] != tuple(sorted((*c["spent_before"], c["nonce_sha256"]))) or
            not set(c["logs_before"]).issubset(c["logs_after"]) or
            any(log in c["logs_before"] for log in c["log_sha256"]) or
            c["logs_after"] != tuple(sorted((*c["logs_before"], *c["log_sha256"])))):
        raise CheckpointForkRejected("revocation rollback or duplicate/missing receipt consumption")


def claimed_checkpoint_sha256(claim):
    """Bounded canonical local consistency digest; never an authenticated root."""
    _check_envelope(claim)
    values = [_DOMAIN, claim["repository"], claim["branch"], claim["git_sha"],
              claim["source_sha256"], claim["workflow_sha256"], claim["roster_sha256"],
              claim["authority_root_sha256"], str(claim["authority_epoch"]),
              str(claim["before_generation"]), claim["before_root_sha256"],
              str(claim["after_generation"]), claim["after_root_sha256"],
              claim["nonce_sha256"], claim["pair_sha256"], *claim["log_sha256"]]
    for row in claim["writer_claims"]:
        values.extend((row[0], str(row[1]), row[2], row[3], row[4], row[5]))
    for row in claim["observer_claims"]:
        values.extend((row[0], str(row[1]), row[2], row[3]))
    values.extend(claim["approver_ids"])
    values.extend(claim["approver_keys"])
    for row in claim["approval_claims"]:
        values.extend(row)
    for key in ("revoked_before", "revoked_after", "spent_before", "spent_after",
                "logs_before", "logs_after"):
        values.extend((key, str(len(claim[key])), *claim[key]))
    values.extend((claim["ack_state"], "provider=NOT_VERIFIED",
                   "signatures=NOT_VERIFIED", "release_ready=False", "live_trading_allowed=False"))
    return hashlib.sha256("\n".join(values).encode("ascii")).hexdigest()


def quarantine_synthetic_checkpoint(claim, *, pinned):
    """Compare synthetic claims to caller pins; NEVER assert a committed CAS.

    Matching claimed observers can both be fabricated. ACK_LOST is unresolved.
    Parallel pure calls may both pass: true single-winner needs external CAS.
    """
    digest = claimed_checkpoint_sha256(claim)
    if type(pinned) is not dict or set(pinned) != set(_PINS):
        raise CheckpointForkRejected("untrusted/missing external pin schema")
    for key in ("source_sha256", "workflow_sha256", "roster_sha256",
                "authority_root_sha256", "before_root_sha256", "after_root_sha256",
                "nonce_sha256", "pair_sha256"):
        if not _sha(pinned[key]) or not hmac.compare_digest(pinned[key], claim[key]):
            raise CheckpointForkRejected("foreign source, anchor or receipt pin")
    if (not _sha(pinned["git_sha"], 40) or
            not hmac.compare_digest(pinned["git_sha"], claim["git_sha"]) or
            not _gen(pinned["authority_epoch"]) or
            pinned["authority_epoch"] != claim["authority_epoch"] or
            not _gen(pinned["before_generation"]) or
            pinned["before_generation"] != claim["before_generation"] or
            not _two_sha(pinned["log_sha256"]) or
            pinned["log_sha256"] != claim["log_sha256"] or
            not _two_id(pinned["writer_ids"]) or
            pinned["writer_ids"] != tuple(x[0] for x in claim["writer_claims"]) or
            not _two_id(pinned["observer_ids"]) or
            pinned["observer_ids"] != tuple(x[0] for x in claim["observer_claims"]) or
            not _three_id(pinned["approver_ids"]) or
            pinned["approver_ids"] != claim["approver_ids"] or
            not _three_sha(pinned["approver_keys"]) or
            pinned["approver_keys"] != claim["approver_keys"] or
            not _sha(pinned["expected_claim_sha256"]) or
            not hmac.compare_digest(pinned["expected_claim_sha256"], digest)):
        raise CheckpointForkRejected("malformed or mismatched pinned state")
    return {
        "status": "CLAIMED_FORK_FREE_CHECKPOINT_QUARANTINED_NOT_AUTHENTICATED",
        "claim_sha256": digest,
        "claimed_winners": 1,
        "claimed_conflicts": 1,
        "lost_ack_unresolved": claim["ack_state"] == "ACK_LOST_UNRESOLVED",
        "provider_origin_verified": False,
        "signatures_verified": False,
        "cas_atomicity_verified": False,
        "ledger_write_performed": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }
