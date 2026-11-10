"""RC672 synthetic context-chain checker; not provider authentication or CAS.

An attacker supplying both a claim and its purported trust anchors can forge a
consistent chain. All anchors MUST be separately authenticated and pinned by
an external owner; this module never reads or persists them. Never trades.
"""
import hashlib
import hmac
import re


class ContextChainRejected(ValueError):
    """Incomplete, stale, ambiguous or unsafe claimed CI evidence context."""


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_AUTHORITY = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_DOMAIN = "RC672-PUBLIC-CONTEXT-CHAIN-V1"
_FIELDS = (
    "repository", "branch", "git_sha", "source_sha256", "workflow_sha256",
    "roster_sha256", "authority_id", "authority_epoch", "authority_root_sha256",
    "previous_context_sha256", "run_ids", "job_ids", "log_sha256",
    "run_attempts", "cas_generation", "cas_root_sha256", "ack_state",
    "trace_status", "pair_status", "replay_status", "release_ready",
    "live_trading_allowed",
)
_TRACE = "CLAIMED_LINEARIZATION_CONSISTENT_NOT_AUTHENTICATED"
_PAIR = "HOSTED_PAIR_CONSISTENT_NOT_AUTHENTICATED"
_REPLAY = "NOT_REPLAYED_AGAINST_SUPPLIED_HISTORY_NOT_AUTHENTICATED"
_MAX_NUM = (1 << 63) - 2


def _hex(value, digits):
    return type(value) is str and (
        _SHA40 if digits == 40 else _SHA64).fullmatch(value) is not None


def _num(value, min_value=1):
    return type(value) is int and min_value <= value <= _MAX_NUM


def _pair_of_ids(value):
    return (type(value) is tuple and len(value) == 2 and
            all(_num(v) for v in value) and value[0] != value[1])


def _pair_of_digests(value):
    return (type(value) is tuple and len(value) == 2 and
            all(_hex(v, 64) for v in value) and value[0] != value[1])


def _valid(claim):
    if type(claim) is not dict or set(claim) != set(_FIELDS):
        raise ContextChainRejected("unexpected claim metadata or missing field")
    if (claim["repository"] != _REPO or claim["branch"] != _BRANCH or
            not _hex(claim["git_sha"], 40) or
            any(not _hex(claim[k], 64) for k in (
                "source_sha256", "workflow_sha256", "roster_sha256",
                "authority_root_sha256", "previous_context_sha256",
                "cas_root_sha256")) or
            type(claim["authority_id"]) is not str or
            _AUTHORITY.fullmatch(claim["authority_id"]) is None or
            not _num(claim["authority_epoch"]) or
            not _num(claim["cas_generation"]) or
            not _pair_of_ids(claim["run_ids"]) or
            not _pair_of_ids(claim["job_ids"]) or
            not _pair_of_digests(claim["log_sha256"]) or
            type(claim["run_attempts"]) is not tuple or
            claim["run_attempts"] != (1, 1) or
            any(type(attempt) is not int for attempt in claim["run_attempts"]) or
            claim["ack_state"] not in ("ACK_APPLIED", "ACK_LOST_READBACK_ONLY") or
            type(claim["ack_state"]) is not str or
            claim["trace_status"] != _TRACE or
            claim["pair_status"] != _PAIR or
            claim["replay_status"] != _REPLAY or
            claim["release_ready"] is not False or
            claim["live_trading_allowed"] is not False):
        raise ContextChainRejected("noncanonical, untrusted or release-unsafe context")


def context_sha256(claim):
    """Length-unambiguous canonical synthetic context digest; NOT a signature."""
    _valid(claim)
    values = (
        _DOMAIN, claim["repository"], claim["branch"], claim["git_sha"],
        claim["source_sha256"], claim["workflow_sha256"],
        claim["roster_sha256"], claim["authority_id"],
        str(claim["authority_epoch"]), claim["authority_root_sha256"],
        claim["previous_context_sha256"],
        str(claim["run_ids"][0]), str(claim["run_ids"][1]),
        str(claim["job_ids"][0]), str(claim["job_ids"][1]),
        claim["log_sha256"][0], claim["log_sha256"][1],
        "1", "1", str(claim["cas_generation"]),
        claim["cas_root_sha256"], claim["ack_state"],
        claim["trace_status"], claim["pair_status"], claim["replay_status"],
        "release_ready=False", "live_trading_allowed=False",
    )
    # Field values cannot contain delimiters: allowlisted constants, lowercase
    # ASCII digests and IDs. The version tag isolates this hash from other use.
    return hashlib.sha256("\n".join(values).encode("ascii")).hexdigest()


def check_synthetic_context_transition(previous, current, *,
                                       trusted_previous_context_sha256,
                                       trusted_authority_root_sha256,
                                       trusted_authority_epoch,
                                       trusted_current_git_sha,
                                       trusted_current_source_sha256,
                                       trusted_current_workflow_sha256,
                                       trusted_current_roster_sha256,
                                       trusted_current_run_ids,
                                       trusted_current_job_ids,
                                       trusted_current_log_sha256):
    """Pin successive *claims*, refusing silent authority rotation and rebind.

    Not proof of real GitHub run, provider CAS linearization, signed trust root,
    completed model fit, or single-use ledger. Lost ACK remains ambiguous.
    """
    prior_digest = context_sha256(previous)
    current_digest = context_sha256(current)
    if (not _hex(trusted_previous_context_sha256, 64) or
            not _hex(trusted_authority_root_sha256, 64) or
            not _num(trusted_authority_epoch) or
            not _hex(trusted_current_git_sha, 40) or
            any(not _hex(v, 64) for v in (
                trusted_current_source_sha256, trusted_current_workflow_sha256,
                trusted_current_roster_sha256)) or
            not _pair_of_ids(trusted_current_run_ids) or
            not _pair_of_ids(trusted_current_job_ids) or
            not _pair_of_digests(trusted_current_log_sha256)):
        raise ContextChainRejected("incomplete external trust expectations")
    if (not hmac.compare_digest(prior_digest, trusted_previous_context_sha256) or
            not hmac.compare_digest(current["previous_context_sha256"], prior_digest) or
            not hmac.compare_digest(previous["authority_root_sha256"],
                                    trusted_authority_root_sha256) or
            not hmac.compare_digest(current["authority_root_sha256"],
                                    trusted_authority_root_sha256) or
            previous["authority_epoch"] != trusted_authority_epoch or
            current["authority_epoch"] != trusted_authority_epoch or
            previous["authority_id"] != current["authority_id"]):
        raise ContextChainRejected("authority rotation or broken external chain")
    if (current["cas_generation"] != previous["cas_generation"] + 1 or
            current["cas_root_sha256"] == previous["cas_root_sha256"] or
            current["git_sha"] == previous["git_sha"] or
            current["run_ids"][0] <= previous["run_ids"][0] or
            current["run_ids"][1] <= previous["run_ids"][1] or
            current["job_ids"][0] <= previous["job_ids"][0] or
            current["job_ids"][1] <= previous["job_ids"][1] or
            set(previous["log_sha256"]) & set(current["log_sha256"])):
        raise ContextChainRejected("ABA, stale generation or reused CI evidence")
    expected = (
        (current["git_sha"], trusted_current_git_sha),
        (current["source_sha256"], trusted_current_source_sha256),
        (current["workflow_sha256"], trusted_current_workflow_sha256),
        (current["roster_sha256"], trusted_current_roster_sha256),
    )
    if (any(not hmac.compare_digest(a, b) for a, b in expected) or
            current["run_ids"] != trusted_current_run_ids or
            current["job_ids"] != trusted_current_job_ids or
            current["log_sha256"] != trusted_current_log_sha256):
        raise ContextChainRejected("foreign source/workflow/log/runner identity")
    return {
        "status": ("LOST_ACK_CONTEXT_CONSISTENT_NOT_AUTHENTICATED" if
                   current["ack_state"] == "ACK_LOST_READBACK_ONLY" else
                   "CONTEXT_CHAIN_CONSISTENT_NOT_AUTHENTICATED"),
        "context_sha256": current_digest,
        "expected_git_sha": current["git_sha"],
        "observed_generation": current["cas_generation"],
        "release_ready": False,
        "live_trading_allowed": False,
    }
