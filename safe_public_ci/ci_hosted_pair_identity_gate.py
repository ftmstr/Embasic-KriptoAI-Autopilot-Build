"""Fail-closed offline pairing of invented public CI metadata and log receipts.

No GitHub authentication: inputs, expected identities and SHA-256 digests must be
obtained from separately authenticated, independently reviewed channels.
Never reads files, fetches network data, executes arbitrary code, or trades.
"""
import hashlib
import hmac
import re


class HostedPairRejected(ValueError):
    """The proposed synthetic two-host CI receipt is inconsistent."""


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BYTES = 262144
_STEPS = {
    "ubuntu": (
        "Set up job", "Checkout Public Build only", "Pin CPython x64",
        "Check exact Python version", "Compile synthetic code and tests",
        "Run all isolated synthetic regression tests", "Post Pin CPython x64",
        "Post Checkout Public Build only", "Complete job",
    ),
    "windows": (
        "Set up job", "Checkout Public Build without credentials",
        "Install exact CPython x64", "Check interpreter version",
        "Compile synthetic-only modules and tests", "Run isolated synthetic suite on Windows",
        "Post Install exact CPython x64",
        "Post Checkout Public Build without credentials", "Complete job",
    ),
}
_LOG_MARKER = "HOSTED_LOG_STRUCTURE_ONLY_NOT_AUTHENTICATED"


def _integer(x):
    return type(x) is int and x > 0


def _keyset(obj, keys):
    return type(obj) is dict and set(obj) == set(keys)


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_synthetic_hosted_pair(receipts, *, expected_sha, expected_run_ids,
                                  expected_job_ids, expected_log_sha256,
                                  expected_roster_sha256, expected_tests):
    """Pair two completed synthetic CI receipts against independent expectations.

    This is a *consistency* gate, not a GitHub or signature authentication gate.
    Each receipt has platform, run, job, steps, raw_log and log_check fields.
    Actual provider provenance and permissions need independent verification.
    """
    if type(expected_sha) is not str or not _SHA40.fullmatch(expected_sha):
        raise HostedPairRejected("invalid pinned commit identity")
    if (type(receipts) is not tuple or len(receipts) != 2 or
            type(expected_run_ids) is not tuple or len(expected_run_ids) != 2 or
            type(expected_job_ids) is not tuple or len(expected_job_ids) != 2 or
            type(expected_log_sha256) is not tuple or len(expected_log_sha256) != 2 or
            not all(_integer(n) for n in expected_run_ids + expected_job_ids) or
            len(set(expected_run_ids)) != 2 or len(set(expected_job_ids)) != 2 or
            type(expected_roster_sha256) is not str or
            not _SHA64.fullmatch(expected_roster_sha256) or
            type(expected_tests) is not int or not 1 <= expected_tests <= 3000 or
            not all(type(d) is str and _SHA64.fullmatch(d)
                    for d in expected_log_sha256)):
        raise HostedPairRejected("invalid independent pair expectations")
    for idx, platform in enumerate(("ubuntu", "windows")):
        receipt = receipts[idx]
        if not _keyset(receipt, ("platform", "run", "job", "steps", "raw_log", "log_check")):
            raise HostedPairRejected("malformed receipt or unexpected metadata")
        if receipt["platform"] != platform:
            raise HostedPairRejected("missing or swapped hosted operating system")
        run, job, steps = receipt["run"], receipt["job"], receipt["steps"]
        if not _keyset(run, ("id", "head_sha", "event", "run_attempt", "status", "conclusion")):
            raise HostedPairRejected("malformed run identity")
        if (not _integer(run["id"]) or run["id"] != expected_run_ids[idx] or
                type(run["head_sha"]) is not str or
                not hmac.compare_digest(run["head_sha"], expected_sha) or
                run["event"] != "push" or type(run["run_attempt"]) is not int or
                run["run_attempt"] != 1 or run["status"] != "completed" or
                run["conclusion"] != "success"):
            raise HostedPairRejected("untrusted run SHA/event/attempt/conclusion")
        if not _keyset(job, ("id", "run_id", "status", "conclusion")):
            raise HostedPairRejected("malformed hosted job")
        if (not _integer(job["id"]) or job["id"] != expected_job_ids[idx] or
                type(job["run_id"]) is not int or job["run_id"] != run["id"] or
                job["status"] != "completed" or job["conclusion"] != "success"):
            raise HostedPairRejected("job not linked or completed successfully")
        if type(steps) is not tuple or len(steps) != 9:
            raise HostedPairRejected("missing or extra hosted job step")
        for step, expected_name in zip(steps, _STEPS[platform]):
            if (not _keyset(step, ("name", "status", "conclusion")) or
                    step["name"] != expected_name or
                    step["status"] != "completed" or
                    step["conclusion"] != "success"):
                raise HostedPairRejected("unexpected step, permissions or skipped step")
        raw = receipt["raw_log"]
        log_check = receipt["log_check"]
        if (type(raw) is not bytes or not 1 <= len(raw) <= _MAX_BYTES or
                not _keyset(log_check, ("status", "tests", "log_sha256", "roster_sha256",
                                        "release_ready", "live_trading_allowed"))):
            raise HostedPairRejected("invalid raw log or structure check")
        sha = _sha256(raw)
        if (not hmac.compare_digest(sha, expected_log_sha256[idx]) or
                log_check["status"] != _LOG_MARKER or
                type(log_check["tests"]) is not int or log_check["tests"] != expected_tests or
                type(log_check["log_sha256"]) is not str or
                not _SHA64.fullmatch(log_check["log_sha256"]) or
                not hmac.compare_digest(sha, log_check["log_sha256"]) or
                type(log_check["roster_sha256"]) is not str or
                not _SHA64.fullmatch(log_check["roster_sha256"]) or
                not hmac.compare_digest(expected_roster_sha256, log_check["roster_sha256"]) or
                log_check["release_ready"] is not False or
                log_check["live_trading_allowed"] is not False):
            raise HostedPairRejected("unbound log digest, result or source roster")
    return {"status": "HOSTED_PAIR_CONSISTENT_NOT_AUTHENTICATED",
            "expected_sha": expected_sha, "platforms": 2,
            "per_platform_tests": expected_tests, "release_ready": False,
            "live_trading_allowed": False}
