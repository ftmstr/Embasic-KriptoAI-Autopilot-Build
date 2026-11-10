"""RC673 synthetic authority-rotation quarantine, never an authorization gate.

All proposed approvals and pins are untrusted caller claims. SHA-256 binds
invented bytes but authenticates no identities/signatures or GitHub runs.
A real independently reviewed signed root-rotation protocol and durable CAS
are required OUTSIDE this offline validator. No IO, trading or dynamic code.
"""
import hashlib
import hmac
import re


class RotationQuarantined(ValueError):
    """An invented rotation envelope is malformed, stale or inconsistent."""


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_MAX_NUM = (1 << 63) - 2
_DOMAIN = "RC673-PUBLIC-ROTATION-QUARANTINE-V1"
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_ROLES = ("owner", "independent_reviewer", "incumbent_custodian")
_KEYS = (
    "repository", "branch", "previous_context_sha256", "old_authority_id",
    "old_authority_epoch", "old_authority_root_sha256", "new_authority_id",
    "new_authority_epoch", "new_authority_root_sha256", "git_sha",
    "source_sha256", "workflow_sha256", "roster_sha256", "cas_generation",
    "next_cas_generation", "next_cas_root_sha256", "run_ids", "job_ids",
    "log_sha256", "run_attempts", "nonce_sha256", "ack_state",
    "approval_claims", "release_ready", "live_trading_allowed",
)
_PINS = (
    "previous_context_sha256", "old_authority_id", "old_authority_epoch",
    "old_authority_root_sha256", "git_sha", "source_sha256",
    "workflow_sha256", "roster_sha256", "cas_generation",
    "previous_run_ids", "previous_job_ids", "run_ids", "job_ids",
    "log_sha256", "consumed_nonce_sha256", "previous_log_sha256",
    "recent_authority_root_sha256", "owner_actor", "reviewer_actor",
    "incumbent_actor", "intent_sha256",
)


def _hex(value, n=64):
    return type(value) is str and (
        _SHA40 if n == 40 else _SHA64).fullmatch(value) is not None


def _id(value):
    return type(value) is str and _ID.fullmatch(value) is not None


def _num(value):
    return type(value) is int and 1 <= value <= _MAX_NUM


def _ids(value):
    return (type(value) is tuple and len(value) == 2 and
            all(_num(x) for x in value) and value[0] != value[1])


def _logs(value):
    return (type(value) is tuple and len(value) == 2 and
            all(_hex(x) for x in value) and value[0] != value[1])


def _history(value):
    return (type(value) is tuple and len(value) <= 1024 and
            all(_hex(x) for x in value) and value == tuple(sorted(set(value))))


def rotation_intent_sha256(claim):
    """Offline proposal commitment; approval-claim hashes are NOT signatures."""
    if type(claim) is not dict or set(claim) != set(_KEYS):
        raise RotationQuarantined("unexpected proposal schema")
    if (claim["repository"] != _REPO or claim["branch"] != _BRANCH or
            any(not _hex(claim[x]) for x in (
                "previous_context_sha256", "old_authority_root_sha256",
                "new_authority_root_sha256", "source_sha256", "workflow_sha256",
                "roster_sha256", "next_cas_root_sha256", "nonce_sha256")) or
            not _hex(claim["git_sha"], 40) or
            not _id(claim["old_authority_id"]) or
            not _id(claim["new_authority_id"]) or
            claim["new_authority_id"] == claim["old_authority_id"] or
            not _num(claim["old_authority_epoch"]) or
            not _num(claim["new_authority_epoch"]) or
            claim["new_authority_epoch"] != claim["old_authority_epoch"] + 1 or
            claim["new_authority_root_sha256"] == claim["old_authority_root_sha256"] or
            not _num(claim["cas_generation"]) or
            not _num(claim["next_cas_generation"]) or
            claim["next_cas_generation"] != claim["cas_generation"] + 1 or
            not _ids(claim["run_ids"]) or not _ids(claim["job_ids"]) or
            not _logs(claim["log_sha256"]) or
            type(claim["run_attempts"]) is not tuple or
            claim["run_attempts"] != (1, 1) or
            any(type(v) is not int for v in claim["run_attempts"]) or
            type(claim["ack_state"]) is not str or
            claim["ack_state"] not in ("NOT_SUBMITTED", "ACK_LOST_UNRESOLVED") or
            claim["release_ready"] is not False or
            claim["live_trading_allowed"] is not False):
        raise RotationQuarantined("untrusted or unsafe rotation intent")
    # Every variable field is fixed ASCII, a strictly canonical integer or
    # a versioned constant; separator-free values make line framing unique.
    fields = (_DOMAIN, claim["repository"], claim["branch"],
              claim["previous_context_sha256"], claim["old_authority_id"],
              str(claim["old_authority_epoch"]),
              claim["old_authority_root_sha256"], claim["new_authority_id"],
              str(claim["new_authority_epoch"]), claim["new_authority_root_sha256"],
              claim["git_sha"], claim["source_sha256"],
              claim["workflow_sha256"], claim["roster_sha256"],
              str(claim["cas_generation"]), str(claim["next_cas_generation"]),
              claim["next_cas_root_sha256"], str(claim["run_ids"][0]),
              str(claim["run_ids"][1]), str(claim["job_ids"][0]),
              str(claim["job_ids"][1]), claim["log_sha256"][0],
              claim["log_sha256"][1], "attempt=1", "attempt=1",
              claim["nonce_sha256"], claim["ack_state"],
              "release_ready=False", "live_trading_allowed=False")
    return hashlib.sha256("\n".join(fields).encode("ascii")).hexdigest()


def check_synthetic_rotation_quarantine(claim, *, pinned):
    """Only verify claimed pin consistency; NEVER authorize authority rotation.

    Roles identify three *claimed* distinct humans, NOT signed attestations.
    A caller that controls pins/claims can forge the entire envelope. A real
    provider API/signature verification and independent source of truth are
    mandatory before ANY durable authority change, outside this function.
    """
    digest = rotation_intent_sha256(claim)
    if type(pinned) is not dict or set(pinned) != set(_PINS):
        raise RotationQuarantined("incomplete external pin schema")
    for key in ("previous_context_sha256", "old_authority_root_sha256",
                "source_sha256", "workflow_sha256", "roster_sha256"):
        if not _hex(pinned[key]) or not hmac.compare_digest(claim[key], pinned[key]):
            raise RotationQuarantined("externally pinned root/source mismatch")
    if (not _hex(pinned["git_sha"], 40) or
            not hmac.compare_digest(claim["git_sha"], pinned["git_sha"]) or
            not _id(pinned["old_authority_id"]) or
            pinned["old_authority_id"] != claim["old_authority_id"] or
            not _num(pinned["old_authority_epoch"]) or
            pinned["old_authority_epoch"] != claim["old_authority_epoch"] or
            not _num(pinned["cas_generation"]) or
            pinned["cas_generation"] != claim["cas_generation"] or
            not _ids(pinned["run_ids"]) or not _ids(pinned["job_ids"]) or
            not _ids(pinned["previous_run_ids"]) or
            not _ids(pinned["previous_job_ids"]) or
            not _logs(pinned["log_sha256"]) or
            not _history(pinned["consumed_nonce_sha256"]) or
            not _history(pinned["previous_log_sha256"]) or
            not _history(pinned["recent_authority_root_sha256"]) or
            not _hex(pinned["intent_sha256"]) or
            not hmac.compare_digest(digest, pinned["intent_sha256"])):
        raise RotationQuarantined("malformed or stale external expectations")
    if (claim["run_ids"] != pinned["run_ids"] or
            claim["job_ids"] != pinned["job_ids"] or
            claim["log_sha256"] != pinned["log_sha256"] or
            any(a <= b for a, b in zip(claim["run_ids"], pinned["previous_run_ids"])) or
            any(a <= b for a, b in zip(claim["job_ids"], pinned["previous_job_ids"])) or
            claim["nonce_sha256"] in pinned["consumed_nonce_sha256"] or
            any(x in pinned["previous_log_sha256"] for x in claim["log_sha256"]) or
            claim["new_authority_root_sha256"] in pinned["recent_authority_root_sha256"]):
        raise RotationQuarantined("reused nonce/log, stale CI job or ABA root")
    roles = (pinned["owner_actor"], pinned["reviewer_actor"],
             pinned["incumbent_actor"])
    if (not all(_id(x) for x in roles) or len(set(roles)) != 3 or
            type(claim["approval_claims"]) is not tuple or
            len(claim["approval_claims"]) != 3):
        raise RotationQuarantined("missing independent claimed reviewers")
    for index, item in enumerate(claim["approval_claims"]):
        if (type(item) is not tuple or len(item) != 3 or
                item[0] != _ROLES[index] or item[1] != roles[index] or
                not _hex(item[2]) or not hmac.compare_digest(item[2], digest)):
            raise RotationQuarantined("conflicted issuer role or intent claim")
    return {"status": "ROTATION_QUARANTINED_NOT_AUTHENTICATED",
            "intent_sha256": digest, "proposed_epoch": claim["new_authority_epoch"],
            "external_authorization_verified": False,
            "release_ready": False, "live_trading_allowed": False}
