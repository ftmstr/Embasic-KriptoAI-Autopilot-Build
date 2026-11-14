"""RC665 synthetic-only GitHub Actions unittest job-log envelope gate.

Structural checks only. Digests and expected roster must be supplied via an
independently authenticated channel. This module DOES NOT authenticate GitHub,
commit identity, CI job identity, signing, releases or financial performance.
No IO, filesystem, network, external clients, subprocesses or live orders.
"""
import hashlib
import hmac
import re


class HostedLogRejected(ValueError):
    """Untrusted, incomplete or noncanonical synthetic-hosted log evidence."""


MAX_LOG_BYTES = 262144
MAX_LINES = 4000
MAX_CASES = 3000
MAX_LINE = 4096
TEST_STEP = "##[group]Run python -m unittest discover -s tests -v"
TEST_COMMAND = "python -m unittest discover -s tests -v"
SPLIT_CASE = "test_rc656_snapshot_package.RC656SnapshotTests.test_integrity_actual_public_source_files_without_export"
SPLIT_MESSAGE = "Measure this checkout only; do not publish an artifact or include private code. ... ok"
STAMP = re.compile(r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{7}Z ")
CASE_ID = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_]*\.){2,}test_[A-Za-z0-9_]+\Z")
TEST_CASE = re.compile(r"\A(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\) \.\.\. ok\Z")
TEST_START = re.compile(r"\A(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\)\Z")
SUMMARY = re.compile(r"\ARan ([1-9][0-9]{0,3}) (test|tests) in (?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?s\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SGR = re.compile(r"\x1b\[[0-9;]{1,18}m")


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _stamp_ok(m):
    y, mo, day, hour, minute, sec = (int(v) for v in m.groups())
    if not (2000 <= y <= 2099 and 1 <= mo <= 12 and 0 <= hour <= 23 and
            0 <= minute <= 59 and 0 <= sec <= 59):
        return False
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    # Explicit twelve-month table: 2026 November/December regression gate.
    month_days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    return 1 <= day <= month_days[mo - 1]


def _roster_digest(case_ids):
    if (type(case_ids) is not tuple or not 1 <= len(case_ids) <= MAX_CASES or
            any(type(name) is not str or not CASE_ID.fullmatch(name) for name in case_ids) or
            tuple(sorted(set(case_ids))) != case_ids):
        raise HostedLogRejected("expected test roster must be sorted and unique")
    return _hash("\n".join(case_ids).encode("ascii"))


def verify_hosted_unittest_log(log, *, trusted_log_sha256, trusted_case_ids,
                               trusted_roster_sha256):
    """Fail-closed structure check for one synthetic GitHub-hosted job log.

    Does not certify CI success: run/job identity, GitHub API responses, source
    commit SHA, owner approval and digital signatures need separate review.
    """
    if type(log) is not bytes or not 1 <= len(log) <= MAX_LOG_BYTES:
        raise HostedLogRejected("log bytes and bounds")
    roster_hash = _roster_digest(trusted_case_ids)
    if (type(trusted_log_sha256) is not str or not HEX64.fullmatch(trusted_log_sha256) or
            type(trusted_roster_sha256) is not str or not HEX64.fullmatch(trusted_roster_sha256) or
            not hmac.compare_digest(_hash(log), trusted_log_sha256) or
            not hmac.compare_digest(roster_hash, trusted_roster_sha256)):
        raise HostedLogRejected("untrusted expected hashes")
    try:
        decoded = log.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise HostedLogRejected("non-UTF8 log") from exc
    if decoded.startswith("\ufeff"):
        decoded = decoded[1:]
    if any(v in decoded for v in ("\r", "\x00", "\ufeff")):
        raise HostedLogRejected("forbidden control characters")
    lines = decoded.splitlines()
    if (not 8 <= len(lines) <= MAX_LINES or
            any(len(line) > MAX_LINE for line in lines)):
        raise HostedLogRejected("bad line count or bound")

    stage = "prelude"
    last_stamp = ""
    seen = set()
    split_pending = None
    step_count = 0
    header_command = 0
    safe_env = 0
    post_cleanup = 0
    tail_cleanup = 0
    summary_count = None
    for line in lines:
        m = STAMP.match(line)
        if m is None or not _stamp_ok(m):
            raise HostedLogRejected("untrusted hosted timestamp")
        stamp = line[:m.end() - 1]
        if stamp < last_stamp:
            raise HostedLogRejected("hosted timestamps move backwards")
        last_stamp = stamp
        payload = line[m.end():]
        if ("##[error]" in payload or "Error: Process completed with exit code" in payload or
                payload.startswith("FAILED") or payload.startswith("ERROR:") or
                payload.startswith("FAIL:") or
                re.search(r"\.\.\. (?:FAIL|ERROR|skipped|expected failure|unexpected success)(?: \(.*\))?\Z", payload)):
            raise HostedLogRejected("failure, skip, or workflow error")
        if stage == "prelude":
            if payload == TEST_STEP:
                step_count += 1
                stage = "header"
            elif "\x1b" in payload and "\x1b" in SGR.sub("", payload):
                raise HostedLogRejected("unexpected terminal control")
        elif stage == "header":
            if payload == "##[endgroup]":
                if header_command != 1 or safe_env != 1:
                    raise HostedLogRejected("expected command or SAFE_TEST_ONLY missing")
                stage = "tests"
            elif payload == TEST_STEP or payload.startswith("##[group]"):
                raise HostedLogRejected("nested or duplicate test step")
            else:
                normalized = SGR.sub("", payload)
                if "\x1b" in normalized:
                    raise HostedLogRejected("non-SGR ANSI in test header")
                if normalized == TEST_COMMAND:
                    header_command += 1
                if payload.strip() == "SAFE_TEST_ONLY: 1":
                    safe_env += 1
        elif stage == "tests":
            if "\x1b" in payload:
                raise HostedLogRejected("terminal control inside unittest output")
            match = TEST_CASE.fullmatch(payload)
            beginning = TEST_START.fullmatch(payload)
            if split_pending is not None:
                if split_pending != SPLIT_CASE or payload != SPLIT_MESSAGE:
                    raise HostedLogRejected("unapproved split test completion")
                seen.add(split_pending)
                split_pending = None
            elif match is not None or beginning is not None:
                picked = match if match is not None else beginning
                name, identity = picked.groups()
                if (identity.rsplit(".", 1)[-1] != name or not CASE_ID.fullmatch(identity) or
                        identity in seen or len(seen) >= MAX_CASES):
                    raise HostedLogRejected("duplicated or malformed test case")
                if match is not None:
                    seen.add(identity)
                else:
                    split_pending = identity
            elif payload == "" or payload == "-" * 70:
                continue
            else:
                summ = SUMMARY.fullmatch(payload)
                if (summ is None or not seen or split_pending is not None):
                    raise HostedLogRejected("unrecognized unittest output")
                summary_count = int(summ.group(1))
                if (summary_count != len(seen) or summary_count != len(trusted_case_ids) or
                        summ.group(2) != ("test" if summary_count == 1 else "tests")):
                    raise HostedLogRejected("test total or grammar does not match")
                stage = "expect_ok"
        elif stage == "expect_ok":
            if payload == "":
                continue
            if payload != "OK":
                raise HostedLogRejected("missing unittest OK")
            stage = "postlude"
        else:
            if tail_cleanup and payload != "":
                raise HostedLogRejected("nonempty log after final cleanup marker")
            if payload == "Post job cleanup.":
                post_cleanup += 1
            if payload == "Cleaning up orphan processes":
                tail_cleanup += 1
            if (payload == TEST_STEP or payload.startswith("##[group]Run") or
                    payload.startswith("test_") or payload.startswith("Ran ") or
                    payload == "OK"):
                raise HostedLogRejected("extra testcase or duplicate summary after success")
            if "\x1b" in payload and "\x1b" in SGR.sub("", payload):
                raise HostedLogRejected("unexpected terminal control in footer")
    if (stage != "postlude" or step_count != 1 or post_cleanup < 1 or tail_cleanup != 1 or
            split_pending is not None or summary_count is None or
            tuple(sorted(seen)) != trusted_case_ids):
        raise HostedLogRejected("truncated job, duplicate test step, or roster mismatch")
    return {"status": "HOSTED_LOG_STRUCTURE_ONLY_NOT_AUTHENTICATED",
            "tests": summary_count, "log_sha256": trusted_log_sha256,
            "roster_sha256": trusted_roster_sha256,
            "release_ready": False, "live_trading_allowed": False}
