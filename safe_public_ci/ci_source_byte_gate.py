"""Synthetic-only immutable source-byte checks for public CI handoffs.

The caller MUST authenticate expected commit and hashes independently.
Git blob SHA-1 and SHA-256 consistency is not a signed provenance claim.
This module has no filesystem, network, trading, or publishing capability.
"""
import hashlib
import hmac
import re


class SourceByteRejected(ValueError):
    """Untrusted, missing, changed, or noncanonical public source bytes."""


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_PUBLIC_PY = re.compile(r"(?:safe_public_ci|tests)/[a-z][a-z0-9_]*\.py\Z")
_MAX_FILES = 24
_MAX_FILE_SIZE = 131072
_MAX_TOTAL = 524288


def git_blob_sha1(raw):
    """Calculate Git's SHA-1 blob object identity for bytes, not provenance."""
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_FILE_SIZE:
        raise SourceByteRejected("invalid Git source bytes")
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw).hexdigest()


def _validate_path(path):
    return type(path) is str and _PUBLIC_PY.fullmatch(path) is not None


def _validate_utf8_python(raw):
    try:
        raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise SourceByteRejected("invalid source encoding") from exc
    if (raw.startswith(b"\xef\xbb\xbf") or not raw.endswith(b"\n") or
            any(ch < 32 and ch not in (9, 10) or ch == 127 for ch in raw)):
        raise SourceByteRejected("noncanonical source encoding or newline")


def verify_public_source_byte_claims(files, *, expected_commit_sha, trusted_claims):
    """Compare exact immutable public bytes with out-of-band expected digests.

    files: tuple of (repo-relative path, bytes), sorted by path.
    trusted_claims: tuple of (same path, SHA-256 hex, Git blob SHA-1 hex),
      sorted by path. These values are NOT generated or trusted in this module.
    This does not inspect actual GitHub metadata, checkout or CI job identity.
    """
    if type(expected_commit_sha) is not str or not _SHA40.fullmatch(expected_commit_sha):
        raise SourceByteRejected("invalid externally expected commit")
    if (type(files) is not tuple or type(trusted_claims) is not tuple or
            not 1 <= len(files) <= _MAX_FILES or len(files) != len(trusted_claims)):
        raise SourceByteRejected("incomplete or oversized file/claim tuple")
    previous = ""
    total = 0
    for pair, claim in zip(files, trusted_claims):
        if (type(pair) is not tuple or len(pair) != 2 or
                type(claim) is not tuple or len(claim) != 3):
            raise SourceByteRejected("wrong record shape")
        path, raw = pair
        trusted_path, trusted_sha256, trusted_blob = claim
        if (not _validate_path(path) or path <= previous or
                type(trusted_path) is not str or trusted_path != path):
            raise SourceByteRejected("unexpected, duplicated or reordered public path")
        previous = path
        if (type(raw) is not bytes or not 1 <= len(raw) <= _MAX_FILE_SIZE):
            raise SourceByteRejected("invalid source payload")
        total += len(raw)
        if total > _MAX_TOTAL:
            raise SourceByteRejected("unbounded total source size")
        if (type(trusted_sha256) is not str or not _SHA64.fullmatch(trusted_sha256) or
                type(trusted_blob) is not str or not _SHA40.fullmatch(trusted_blob)):
            raise SourceByteRejected("invalid external source digests")
        _validate_utf8_python(raw)
        if (not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), trusted_sha256) or
                not hmac.compare_digest(git_blob_sha1(raw), trusted_blob)):
            raise SourceByteRejected("Git/source byte drift detected")
    return {
        "status": "SOURCE_BYTES_CONSISTENT_NOT_AUTHENTICATED",
        "expected_commit_sha": expected_commit_sha,
        "verified_files": len(files),
        "release_ready": False,
        "live_trading_allowed": False,
    }
