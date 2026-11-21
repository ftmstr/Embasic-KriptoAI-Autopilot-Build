"""Conservative synthetic-only GitHub-hosted unittest log structure check.

Does not authenticate logs, GitHub, Git commits, artifacts, signing, or trading.
Never reads disk, reaches network, invokes a shell, or authorizes deployment.
Expected digest and count must come from a separately authenticated channel.
"""
import hashlib
import hmac
import re


class LogEvidenceRejected(ValueError):
    """The purported synthetic test output is incomplete or malformed."""


_MAX_LOG_BYTES = 262144
_MAX_LINES = 4000
_MAX_LINE_LENGTH = 4096
_MAX_TESTS = 3000
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_PREFIX = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z ")
_CASE = re.compile(r"\A(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\) \.\.\. ok\Z")
_CASE_START = re.compile(r"\A(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\)\Z")
_SUMMARY = re.compile(r"\ARan ([1-9][0-9]{0,3}) tests in (?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?s\Z")


def check_synthetic_unittest_log(log, *, expected_sha256, expected_count):
    """Return *unverified* structural count; never certify a GitHub workflow.

    The input is a verbatim UTF-8 GitHub Actions job log, not an extracted or
    reconstituted summary. Each recorded test line must precede the lone
    unittest 'Ran N tests' summary immediately followed by its lone 'OK'.
    """
    if type(log) is not bytes or not 1 <= len(log) <= _MAX_LOG_BYTES:
        raise LogEvidenceRejected("invalid log bytes/size")
    if (type(expected_count) is not int or not 1 <= expected_count <= _MAX_TESTS or
            type(expected_sha256) is not str or not _HEX.fullmatch(expected_sha256)):
        raise LogEvidenceRejected("invalid expected count or digest")
    if not hmac.compare_digest(hashlib.sha256(log).hexdigest(), expected_sha256):
        raise LogEvidenceRejected("log digest mismatched")
    try:
        decoded = log.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise LogEvidenceRejected("non-UTF8 log") from exc
    if "\r" in decoded or "\x00" in decoded or "\x1b" in decoded :
        raise LogEvidenceRejected("control characters forbidden")
    if decoded.startswith("\ufeff"):
        decoded = decoded[1:]
    if "\ufeff" in decoded:
        raise LogEvidenceRejected("embedded BOM forbidden")
    lines = decoded.splitlines()
    if not 2 <= len(lines) <= _MAX_LINES or any(len(line) > _MAX_LINE_LENGTH for line in lines):
        raise LogEvidenceRejected("unbounded log lines")
    tests = set()
    total = None
    state = "tests"
    pending = None
    for line in lines:
        prefix = _PREFIX.match(line)
        if prefix is None:
            raise LogEvidenceRejected("missing hosted log timestamp")
        payload = line[prefix.end():]
        case = _CASE.fullmatch(payload)
        start = _CASE_START.fullmatch(payload)
        summary = _SUMMARY.fullmatch(payload)
        if pending is not None:
            if (case is not None or start is not None or summary is not None or
                    not payload.endswith(" ... ok") or
                    not 7 <= len(payload) <= 160 or
                    not payload.isascii() or
                    "FAILED" in payload or "ERROR" in payload):
                raise LogEvidenceRejected("unmatched split unittest output")
            tests.add(pending)
            pending = None
            continue
        if case is not None:
            if state != "tests":
                raise LogEvidenceRejected("case appears after test summary")
            ident = (case.group(1), case.group(2))
            if ident in tests:
                raise LogEvidenceRejected("duplicate test identity")
            tests.add(ident)
            if len(tests) > _MAX_TESTS:
                raise LogEvidenceRejected("too many tests")
        elif start is not None:
            if state != "tests":
                raise LogEvidenceRejected("test after summary")
            ident = (start.group(1), start.group(2))
            if ident in tests:
                raise LogEvidenceRejected("duplicate test identity")
            pending = ident
        elif summary is not None:
            if state != "tests" or not tests:
                raise LogEvidenceRejected("duplicate/premature summary")
            total = int(summary.group(1))
            if total != expected_count or total != len(tests):
                raise LogEvidenceRejected("unittest count mismatch")
            state = "needs_ok"
        elif payload.startswith("test_") and payload.endswith(" ... ok"):
            raise LogEvidenceRejected("malformed unittest case line")
        elif payload == "OK":
            if state != "needs_ok":
                raise LogEvidenceRejected("misplaced or duplicate OK")
            state = "complete"
        elif (payload.startswith("Ran ") or payload.startswith("FAILED") or
              payload.startswith("ERROR:") or payload.startswith("FAIL:") or
              re.search(r"\.\.\. (?:FAIL|ERROR|skipped|expected failure|unexpected success)\Z", payload)):
            raise LogEvidenceRejected("failed, skipped or malformed test outcome")
        elif state == "needs_ok" and payload != "":
            raise LogEvidenceRejected("test summary not followed by OK")
    if pending is not None or state != "complete" or total is None:
        raise LogEvidenceRejected("missing complete successful test summary")
    return {
        "status": "LOG_STRUCTURALLY_CONSISTENT_NOT_AUTHENTICATED",
        "tests": total,
        "sha256": expected_sha256,
        "release_ready": False,
        "live_trading_allowed": False,
    }
