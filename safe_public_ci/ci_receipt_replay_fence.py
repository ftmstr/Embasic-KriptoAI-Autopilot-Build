"""RC669 offline replay-fence for externally trusted synthetic CI receipts.

This is NOT proof that evidence originated from GitHub, or a durable replay
ledger. Caller must independently authenticate and persist the supplied
expectations and spent histories; NEVER enable live trading or releases.
No network, filesystem, dynamic execution, or third-party imports.
"""
import hashlib
import hmac
import re


class ReplayFenceRejected(ValueError):
    """Untrusted, duplicate, stale, malformed or replayed CI evidence."""


_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_HISTORY = 1024


def _positive_integer(value):
    return type(value) is int and value > 0


def _sha64(value):
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _history(values):
    return (type(values) is tuple and len(values) <= _MAX_HISTORY and
            all(_sha64(x) for x in values) and
            tuple(sorted(set(values))) == values)


def verify_synthetic_receipt_replay(
        receipts, *, expected_sha, expected_run_ids, expected_job_ids,
        expected_log_sha256, expected_roster_sha256, expected_source_sha256,
        trusted_seen_pair_sha256, trusted_seen_log_sha256):
    """Bound a two-host candidate to independently supplied consumed histories.

    Receipts: (("ubuntu", run_id, job_id, SHA, log_SHA256, roster_SHA256),
               ("windows", run_id, job_id, SHA, log_SHA256, roster_SHA256)).
    No caller-supplied history is assumed authentic; never mutates the history.
    Fail-closed only against *supplied* history, not an atomic external ledger.
    Successful output is only NOT_REPLAYED_AGAINST_SUPPLIED_HISTORY, never a
    proof of authenticity or a guarantee against replay on later invocations.
    """
    if type(expected_sha) is not str or not _HEX40.fullmatch(expected_sha):
        raise ReplayFenceRejected("untrusted expected commit shape")
    if (type(receipts) is not tuple or len(receipts) != 2 or
            type(expected_run_ids) is not tuple or len(expected_run_ids) != 2 or
            type(expected_job_ids) is not tuple or len(expected_job_ids) != 2 or
            type(expected_log_sha256) is not tuple or len(expected_log_sha256) != 2 or
            any(not _positive_integer(x) for x in expected_run_ids + expected_job_ids) or
            len(set(expected_run_ids)) != 2 or len(set(expected_job_ids)) != 2 or
            not all(_sha64(x) for x in expected_log_sha256) or
            len(set(expected_log_sha256)) != 2 or
            not _sha64(expected_roster_sha256) or not _sha64(expected_source_sha256) or
            not _history(trusted_seen_pair_sha256) or
            not _history(trusted_seen_log_sha256)):
        raise ReplayFenceRejected("malformed or duplicate trusted expectations")
    for i, os_name in enumerate(("ubuntu", "windows")):
        v = receipts[i]
        if type(v) is not tuple or len(v) != 6:
            raise ReplayFenceRejected("invalid receipt record")
        name, run, job, sha, log_hash, roster_hash = v
        if (name != os_name or type(name) is not str or
                not _positive_integer(run) or run != expected_run_ids[i] or
                not _positive_integer(job) or job != expected_job_ids[i] or
                type(sha) is not str or not hmac.compare_digest(sha, expected_sha) or
                not _sha64(log_hash) or
                not hmac.compare_digest(log_hash, expected_log_sha256[i]) or
                not _sha64(roster_hash) or
                not hmac.compare_digest(roster_hash, expected_roster_sha256)):
            raise ReplayFenceRejected("receipt identity, source or digest mismatch")
        if log_hash in trusted_seen_log_sha256:
            raise ReplayFenceRejected("log already consumed in trusted prior evidence")
    # All fields are bounded ASCII tokens. Versioned length-unambiguous tuple.
    fields = (
        "RC669-REPLAY-FENCE-V1", expected_sha,
        str(expected_run_ids[0]), str(expected_job_ids[0]),
        expected_log_sha256[0], str(expected_run_ids[1]),
        str(expected_job_ids[1]), expected_log_sha256[1],
        expected_roster_sha256, expected_source_sha256,
    )
    fingerprint = hashlib.sha256("\n".join(fields).encode("ascii")).hexdigest()
    if fingerprint in trusted_seen_pair_sha256:
        raise ReplayFenceRejected("pair fingerprint already consumed")
    return {
        "status": "NOT_REPLAYED_AGAINST_SUPPLIED_HISTORY_NOT_AUTHENTICATED",
        "fingerprint_sha256": fingerprint,
        "platforms": 2,
        "release_ready": False,
        "live_trading_allowed": False,
    }
