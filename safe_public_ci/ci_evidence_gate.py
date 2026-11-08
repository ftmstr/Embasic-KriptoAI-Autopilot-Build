"""Offline, synthetic-only dual-run metadata consistency check.

NO network, filesystem, trading, training, or production deployment.
Caller must independently authenticate GitHub run/job/step/log evidence;
matching caller-supplied metadata is NOT independent attestation.
"""
import re

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_PLATFORMS = frozenset({"ubuntu-24.04", "windows-latest"})
_FIELDS = frozenset({
    "platform", "sha", "run_id", "job_id", "status", "conclusion",
    "tests_run", "tests_passed", "failures", "errors", "skipped",
    "steps_total", "steps_passed",
})


class EvidenceRejected(ValueError):
    """Evidence is incomplete, inconsistent, or unsafe to promote."""


def verify_dual_platform_metadata(records, *, expected_sha, trusted_run_ids):
    """Check two metadata records against independently supplied expectations.

    Returns METADATA_CONSISTENT_NOT_AUTHENTICATED, never CI_VERIFIED or
    RELEASE_READY. Authentication, source review, and exact GitHub log
    verification must happen outside this offline toy control.
    """
    if type(expected_sha) is not str or not _SHA.fullmatch(expected_sha):
        raise EvidenceRejected("expected SHA must be a canonical Git hash")
    if (type(trusted_run_ids) is not dict or
            set(trusted_run_ids) != _PLATFORMS or
            any(type(n) is not int or n <= 0 for n in trusted_run_ids.values())):
        raise EvidenceRejected("trusted run mapping is absent or malformed")
    if type(records) is not tuple or len(records) != 2:
        raise EvidenceRejected("exactly two immutable evidence entries required")
    seen = set()
    job_ids = set()
    totals = set()
    for record in records:
        if type(record) is not dict or set(record) != _FIELDS:
            raise EvidenceRejected("missing or unexpected evidence fields")
        platform = record["platform"]
        if type(platform) is not str or platform not in _PLATFORMS or platform in seen:
            raise EvidenceRejected("duplicate or unapproved runner")
        seen.add(platform)
        if record["sha"] != expected_sha or type(record["sha"]) is not str:
            raise EvidenceRejected("different or untrusted commit SHA")
        for key in ("run_id", "job_id", "tests_run", "tests_passed",
                    "failures", "errors", "skipped", "steps_total", "steps_passed"):
            if type(record[key]) is not int or record[key] < 0:
                raise EvidenceRejected("invalid integer field: " + key)
        if (record["run_id"] <= 0 or record["job_id"] <= 0 or
                record["run_id"] != trusted_run_ids[platform] or
                record["job_id"] in job_ids):
            raise EvidenceRejected("untrusted run or duplicated job identity")
        job_ids.add(record["job_id"])
        if (record["status"] != "completed" or
                record["conclusion"] != "success" or
                type(record["status"]) is not str or
                type(record["conclusion"]) is not str):
            raise EvidenceRejected("workflow did not complete successfully")
        if (record["tests_run"] <= 0 or
                record["tests_passed"] != record["tests_run"] or
                any(record[k] != 0 for k in ("failures", "errors", "skipped")) or
                record["steps_total"] <= 0 or
                record["steps_passed"] != record["steps_total"]):
            raise EvidenceRejected("test or step outcomes incomplete")
        totals.add(record["tests_run"])
    if seen != _PLATFORMS or len(totals) != 1:
        raise EvidenceRejected("platform or test-suite parity mismatch")
    return {
        "status": "METADATA_CONSISTENT_NOT_AUTHENTICATED",
        "sha": expected_sha,
        "tests_per_platform": totals.pop(),
        "platforms": tuple(sorted(seen)),
        "release_ready": False,
        "live_trading_allowed": False,
    }
