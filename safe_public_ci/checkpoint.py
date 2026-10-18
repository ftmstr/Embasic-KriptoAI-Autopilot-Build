"""Only synthetic in-memory digests. Not a scientific checkpoint."""
import hashlib
import hmac

def checksum(data):
    if type(data) is not bytes or not 1 <= len(data) <= 65536:
        raise ValueError("invalid toy data")
    return hashlib.sha256(data).hexdigest()

def require_integrity(data, expected):
    actual = checksum(data)
    if (type(expected) is not str or len(expected) != 64 or
        any(c not in "0123456789abcdef" for c in expected)):
        raise ValueError("invalid expected digest")
    if not hmac.compare_digest(actual, expected):
        raise ValueError("toy data tampered")
    return True
