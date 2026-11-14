"""RC664 synthetic-only, fail-closed unittest roster cross-check.

Offline structural verification only: an expected roster/digest is trustworthy
only when separately authenticated by an independent authority. No network,
filesystem, order placement, release/signing, or scientific performance.
"""
import hashlib
import hmac
import re


class RosterRejected(ValueError):
    """Malformed, missing, contradictory, or untrusted synthetic test evidence."""


_MAX_BYTES = 262144
_MAX_LINES = 4000
_MAX_LINE = 4096
_MAX_CASES = 3000
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_STAMP = re.compile(r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{7}Z ")
_CASE_ID = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_]*\.){2,}test_[A-Za-z0-9_]+\Z")
_TEST = re.compile(r"\A(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\) \.\.\. ok\Z")
_START = re.compile(r"\A(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\)\Z")
_SUMMARY = re.compile(r"\ARan ([1-9][0-9]{0,3}) (test|tests) in (?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?s\Z")
_SPLIT_ID = "test_rc656_snapshot_package.RC656SnapshotTests.test_integrity_actual_public_source_files_without_export"
_SPLIT_MESSAGE = "Measure this checkout only; do not publish an artifact or include private code. ... ok"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _valid_stamp(match):
    y, month, day, hour, minute, sec = (int(v) for v in match.groups())
    if not 2000 <= y <= 2099 or not 1 <= month <= 12 or not 0 <= hour <= 23 or not 0 <= minute <= 59 or not 0 <= sec <= 59:
        return False
    days = (31, 29 if y % 4 == 0 and (y % 100 != 0 or y % 400 == 0) else 28,
            31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    return 1 <= day <= days[month - 1]


def canonical_roster_sha256(case_ids):
    """Hash a strictly sorted, unique, fully-qualified synthetic test roster."""
    if (type(case_ids) is not tuple or not 1 <= len(case_ids) <= _MAX_CASES or
            any(type(v) is not str or not _CASE_ID.fullmatch(v) for v in case_ids) or
            tuple(sorted(set(case_ids))) != case_ids):
        raise RosterRejected("case roster must be canonical, sorted, and unique")
    return _sha("\n".join(case_ids).encode("ascii"))


def verify_synthetic_unittest_roster(log, *, trusted_log_sha256,
                                     trusted_case_ids, trusted_roster_sha256):
    """Check exact test roster and raw log hash, WITHOUT authenticating origin."""
    if type(log) is not bytes or not 1 <= len(log) <= _MAX_BYTES:
        raise RosterRejected("invalid log bytes or size")
    expected = canonical_roster_sha256(trusted_case_ids)
    if (type(trusted_log_sha256) is not str or not _HEX64.fullmatch(trusted_log_sha256) or
            type(trusted_roster_sha256) is not str or not _HEX64.fullmatch(trusted_roster_sha256) or
            not hmac.compare_digest(expected, trusted_roster_sha256) or
            not hmac.compare_digest(_sha(log), trusted_log_sha256)):
        raise RosterRejected("untrusted or inconsistent out-of-band digests")
    try:
        decoded = log.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise RosterRejected("invalid UTF-8 log") from exc
    if decoded.startswith("\ufeff"):
        decoded = decoded[1:]
    if any(ch in decoded for ch in ("\r", "\x00", "\x1b", "\ufeff")):
        raise RosterRejected("embedded control or BOM")
    lines = decoded.splitlines()
    if not 2 <= len(lines) <= _MAX_LINES or any(len(v) > _MAX_LINE for v in lines):
        raise RosterRejected("oversized line or truncated log")
    observed = set()
    pending = None
    state = "tests"
    summary_count = None
    last_timestamp = ""
    for line in lines:
        stamp = _STAMP.match(line)
        if stamp is None or not _valid_stamp(stamp):
            raise RosterRejected("bad GitHub-hosted timestamp")
        stamp_text = line[:stamp.end() - 1]
        if stamp_text < last_timestamp:
            raise RosterRejected("nonmonotone GitHub-hosted timestamps")
        last_timestamp = stamp_text
        payload = line[stamp.end():]
        m = _TEST.fullmatch(payload)
        s = _START.fullmatch(payload)
        summ = _SUMMARY.fullmatch(payload)
        if (payload.startswith("##[error]") or payload.startswith("Error: Process completed with exit code") or
                payload.startswith("FAILED") or payload.startswith("ERROR:") or payload.startswith("FAIL:") or
                re.search(r"\.\.\. (?:FAIL|ERROR|skipped|expected failure|unexpected success)\Z", payload)):
            raise RosterRejected("failure, skip or workflow error present")
        if pending is not None:
            if pending != _SPLIT_ID or payload != _SPLIT_MESSAGE:
                raise RosterRejected("unapproved split stdout/fake test completion")
            observed.add(pending)
            pending = None
            continue
        if m is not None or s is not None:
            if state != "tests":
                raise RosterRejected("test found after unittest summary")
            case = m if m is not None else s
            name, identity = case.groups()
            if not _CASE_ID.fullmatch(identity) or identity.rsplit(".", 1)[-1] != name or identity in observed:
                raise RosterRejected("malformed, mismatched, or duplicated test identity")
            if m is not None:
                observed.add(identity)
            else:
                pending = identity
            if len(observed) > _MAX_CASES:
                raise RosterRejected("excess tests")
        elif summ is not None:
            if state != "tests" or not observed:
                raise RosterRejected("duplicate or misplaced unittest summary")
            summary_count = int(summ.group(1))
            if (summ.group(2) != ("test" if summary_count == 1 else "tests") or
                    summary_count != len(observed) or summary_count != len(trusted_case_ids)):
                raise RosterRejected("summary count/grammar mismatch")
            state = "expect_ok"
        elif payload == "OK":
            if state != "expect_ok":
                raise RosterRejected("unpaired or duplicate OK")
            state = "complete"
        elif (payload.startswith("test_") or payload.startswith("Ran ") or
                (state == "expect_ok" and payload != "")):
            raise RosterRejected("malformed test, summary, or completion")
    if pending is not None or state != "complete" or summary_count is None:
        raise RosterRejected("no complete passing run")
    if tuple(sorted(observed)) != trusted_case_ids:
        raise RosterRejected("observed and expected test rosters differ")
    if not hmac.compare_digest(canonical_roster_sha256(tuple(sorted(observed))), trusted_roster_sha256):
        raise RosterRejected("test set digest mismatch")
    return {"status": "ROSTER_STRUCTURALLY_CONSISTENT_NOT_AUTHENTICATED",
            "tests": summary_count, "log_sha256": trusted_log_sha256,
            "roster_sha256": trusted_roster_sha256,
            "release_ready": False, "live_trading_allowed": False}
