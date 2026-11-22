"""RC670 synthetic-only readback/compare-and-swap protocol checker.

NO CAS I/O OR AUTHENTICATION OCCURS HERE. A trusted external store must
provide transactional CAS, durable histories, monotonic revisions and an
independent authenticated readback. Returning a consistent observation does
not prove a commit, an ACK, GitHub origin or safe financial deployment.
No file/network access, no dynamic Python evaluation and no state mutation.
An untrusted matching readback never authorizes a release or trading.
"""
import hashlib
import hmac
import re


class CasEvidenceRejected(ValueError):
    """Invalid, inconsistent or stale synthetic CAS evidence."""


_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_MAX_HISTORY = 1024
_MAX_GENERATION = (1 << 63) - 2
_VERSION = "RC670-PUBLIC-SYNTHETIC-CAS-V1"


def _is_digest(value):
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _is_sha(value):
    return type(value) is str and _HEX40.fullmatch(value) is not None


def _history(value):
    return (type(value) is tuple and len(value) <= _MAX_HISTORY and
            all(_is_digest(v) for v in value) and
            value == tuple(sorted(set(value))))


def _is_generation(value):
    return type(value) is int and 0 <= value <= _MAX_GENERATION


def snapshot_digest(generation, pair_hashes, log_hashes):
    """Deterministic consistency digest, NEVER an authoritative state root."""
    if not _is_generation(generation) or not _history(pair_hashes) or not _history(log_hashes):
        raise CasEvidenceRejected("invalid bounded snapshot records")
    if len(pair_hashes) >= _MAX_HISTORY or len(log_hashes) > _MAX_HISTORY - 2:
        raise CasEvidenceRejected("insufficient bounded history capacity")
    fields = (_VERSION, str(generation), "PAIRS", str(len(pair_hashes)),
              *pair_hashes, "LOGS", str(len(log_hashes)), *log_hashes)
    return hashlib.sha256("\n".join(fields).encode("ascii")).hexdigest()


def _check_snapshot(snapshot, trusted_digest):
    if (type(snapshot) is not tuple or len(snapshot) != 4 or
            not _is_digest(trusted_digest)):
        raise CasEvidenceRejected("bad externally provided snapshot")
    generation, digest, pairs, logs = snapshot
    if not _is_digest(digest):
        raise CasEvidenceRejected("bad snapshot root shape")
    canonical = snapshot_digest(generation, pairs, logs)
    if (not hmac.compare_digest(canonical, digest) or
            not hmac.compare_digest(canonical, trusted_digest)):
        raise CasEvidenceRejected("snapshot root mismatch or stale expectation")
    return generation, pairs, logs


def prepare_synthetic_cas(snapshot, *, trusted_snapshot_digest,
                          expected_generation, expected_git_sha,
                          expected_source_sha256, pair_sha256, log_sha256):
    """Generate a bounded proposal only; cannot reserve or consume a receipt.

    Two workers presented the same snapshot can BOTH prepare the SAME proposal.
    Only an external independent atomic compare-and-swap can choose a winner.
    """
    generation, pairs, logs = _check_snapshot(snapshot, trusted_snapshot_digest)
    if (not _is_generation(expected_generation) or generation != expected_generation or
            not _is_sha(expected_git_sha) or not _is_digest(expected_source_sha256) or
            not _is_digest(pair_sha256) or type(log_sha256) is not tuple or
            len(log_sha256) != 2 or not all(_is_digest(v) for v in log_sha256) or
            len(set(log_sha256)) != 2):
        raise CasEvidenceRejected("invalid independent identity or generation pin")
    if (pair_sha256 in pairs or any(v in logs for v in log_sha256)):
        raise CasEvidenceRejected("repeated pair or individual log against supplied history")
    if generation == _MAX_GENERATION:
        raise CasEvidenceRejected("generation cannot increase")
    next_pairs = tuple(sorted((*pairs, pair_sha256)))
    next_logs = tuple(sorted((*logs, *log_sha256)))
    next_generation = generation + 1
    next_digest = snapshot_digest(next_generation, next_pairs, next_logs)
    return {
        "status": "PROPOSED_CAS_ONLY_NOT_AUTHENTICATED",
        "expected_generation": generation,
        "expected_snapshot_sha256": trusted_snapshot_digest,
        "proposed_generation": next_generation,
        "proposed_snapshot_sha256": next_digest,
        "expected_git_sha": expected_git_sha,
        "expected_source_sha256": expected_source_sha256,
        "pair_sha256": pair_sha256,
        "log_sha256": log_sha256,
        "proposed_pair_history": next_pairs,
        "proposed_log_history": next_logs,
        "release_ready": False,
        "live_trading_allowed": False,
    }


def check_synthetic_cas_readback(proposal, *, provider_ack_state,
                                 observed_snapshot, trusted_observed_digest):
    """Inspect claimed readback after external CAS, without performing I/O.

    ACK_LOST plus a matching readback only means *observed consistency*;
    a stale/forged provider readback cannot be authenticated by this module.
    CONFLICT and NOT_SENT are always hard NO_GO, even for matching readbacks.
    """
    keys = ("status", "expected_generation", "expected_snapshot_sha256",
            "proposed_generation", "proposed_snapshot_sha256", "expected_git_sha",
            "expected_source_sha256", "pair_sha256", "log_sha256",
            "proposed_pair_history", "proposed_log_history", "release_ready",
            "live_trading_allowed")
    if (type(proposal) is not dict or set(proposal) != set(keys) or
            proposal.get("status") != "PROPOSED_CAS_ONLY_NOT_AUTHENTICATED" or
            proposal.get("release_ready") is not False or
            proposal.get("live_trading_allowed") is not False or
            provider_ack_state not in ("ACK_APPLIED", "ACK_LOST", "CONFLICT", "NOT_SENT") or
            type(provider_ack_state) is not str):
        raise CasEvidenceRejected("malformed or unsafe CAS proposal/ACK")
    e, p = proposal["expected_generation"], proposal["proposed_generation"]
    if (not _is_generation(e) or not _is_generation(p) or p != e + 1 or
            not _is_digest(proposal["expected_snapshot_sha256"]) or
            not _is_digest(proposal["proposed_snapshot_sha256"]) or
            not _is_sha(proposal["expected_git_sha"]) or
            not _is_digest(proposal["expected_source_sha256"]) or
            not _is_digest(proposal["pair_sha256"]) or
            type(proposal["log_sha256"]) is not tuple or
            len(proposal["log_sha256"]) != 2 or
            not all(_is_digest(v) for v in proposal["log_sha256"]) or
            len(set(proposal["log_sha256"])) != 2):
        raise CasEvidenceRejected("stale or malformed CAS pins")
    pairs, logs = proposal["proposed_pair_history"], proposal["proposed_log_history"]
    if (not _history(pairs) or not _history(logs) or
            proposal["pair_sha256"] not in pairs or
            any(v not in logs for v in proposal["log_sha256"]) or
            not hmac.compare_digest(snapshot_digest(p, pairs, logs),
                                    proposal["proposed_snapshot_sha256"])):
        raise CasEvidenceRejected("forged or inconsistent proposed root")
    if provider_ack_state in ("CONFLICT", "NOT_SENT"):
        raise CasEvidenceRejected("no committed write claim: conflict or not sent")
    actual_generation, actual_pairs, actual_logs = _check_snapshot(
        observed_snapshot, trusted_observed_digest)
    if (actual_generation != p or
            not hmac.compare_digest(trusted_observed_digest,
                                    proposal["proposed_snapshot_sha256"]) or
            actual_pairs != pairs or actual_logs != logs):
        raise CasEvidenceRejected("stale or foreign external readback; retry prohibited")
    return {
        "status": ("ACK_READBACK_CONSISTENT_NOT_AUTHENTICATED" if
                   provider_ack_state == "ACK_APPLIED" else
                   "LOST_ACK_READBACK_CONSISTENT_NOT_AUTHENTICATED"),
        "observed_generation": actual_generation,
        "observed_snapshot_sha256": trusted_observed_digest,
        "release_ready": False,
        "live_trading_allowed": False,
    }
