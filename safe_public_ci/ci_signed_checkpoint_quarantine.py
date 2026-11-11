"""RC682: strict offline Ed25519 math and synthetic checkpoint quarantine.

Mathematical signature verification is NOT issuer, trust anchor, GitHub, clock,
CAS, revocation-ledger or release provenance authentication. Nothing executes.
Only synthetic fixtures are accepted; no private keys are shipped here.
"""
import hashlib
import hmac
import re


class CheckpointRejected(ValueError):
    """Malformed, unbound, unsigned, revoked or unsafe checkpoint."""


_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_IDENTITY = (0, 1, 1, 0)
_H40 = re.compile(r"[0-9a-f]{40}\Z")
_H64 = re.compile(r"[0-9a-f]{64}\Z")
_H128 = re.compile(r"[0-9a-f]{128}\Z")
_MAXINT = (1 << 63) - 2
_DOMAIN = b"RC682-ONLY-SYNTHETIC-SIGNED-CHECKPOINT-V1\x00"
_FIELDS = (
    "git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
    "transcript_sha256", "old_size", "new_size", "old_root_sha256",
    "new_root_sha256", "nonce_sha256", "issued_at", "observed_at",
    "provider_claims", "writer_claims", "ack_state", "release_ready",
    "live_trading_allowed",
)
_TRUST = (
    "public_key_hex", "fingerprint_sha256", "not_before", "not_after",
    "revocations", "spent_nonces", "seen_roots",
)


def _hex(v, n=64):
    return type(v) is str and {40: _H40, 64: _H64, 128: _H128}[n].fullmatch(v) is not None


def _positive(v):
    return type(v) is int and 1 <= v <= _MAXINT


def _inverse(z):
    return pow(z, _Q - 2, _Q)


def _recover_x(y, sign):
    xx = ((y * y - 1) * _inverse((_D * y * y + 1) % _Q)) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q:
        x = x * _I % _Q
    if (x * x - xx) % _Q:
        raise CheckpointRejected("point is not on curve")
    if x == 0 and sign:
        raise CheckpointRejected("noncanonical sign of zero x")
    if (x & 1) != sign:
        x = (-x) % _Q
    return x


def _decode_point(data):
    if type(data) is not bytes or len(data) != 32:
        raise CheckpointRejected("invalid compressed point size")
    n = int.from_bytes(data, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= _Q:
        raise CheckpointRejected("noncanonical curve coordinate")
    x = _recover_x(y, sign)
    return (x, y, 1, x * y % _Q)


def _add(p, q):
    x, y, z, t = p
    X, Y, Z, T = q
    a = (y - x) * (Y - X) % _Q
    b = (y + x) * (Y + X) % _Q
    c = 2 * _D * t * T % _Q
    d = 2 * z * Z % _Q
    e, f, g, h = (b - a) % _Q, (d - c) % _Q, (d + c) % _Q, (b + a) % _Q
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _scalar(point, n):
    answer = _IDENTITY
    while n:
        if n & 1:
            answer = _add(answer, point)
        point = _add(point, point)
        n >>= 1
    return answer


def _encode_point(p):
    x, y, z, _ = p
    iz = _inverse(z)
    return ((y * iz % _Q) | ((x * iz % _Q & 1) << 255)).to_bytes(32, "little")


_BASE = _decode_point((4 * _inverse(5) % _Q).to_bytes(32, "little"))


def verify_ed25519(public_key_hex, message, signature_hex):
    """Strict RFC8032 pure-Python Ed25519 equation (not root provenance).

    Rejects noncanonical points, torsion/non-prime-subgroup points and S >= L.
    Does not support Ed25519ph/ctx, and is not a production crypto library.
    """
    if (not _hex(public_key_hex) or type(message) is not bytes or
            len(message) > 8192 or not _hex(signature_hex, 128)):
        return False
    key, sig = bytes.fromhex(public_key_hex), bytes.fromhex(signature_hex)
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    try:
        a, r = _decode_point(key), _decode_point(sig[:32])
        if (_encode_point(_scalar(a, 8)) == _encode_point(_IDENTITY) or
                _encode_point(_scalar(r, 8)) == _encode_point(_IDENTITY) or
                _encode_point(_scalar(a, _L)) != _encode_point(_IDENTITY) or
                _encode_point(_scalar(r, _L)) != _encode_point(_IDENTITY)):
            return False
        k = int.from_bytes(hashlib.sha512(sig[:32] + key + message).digest(), "little") % _L
        lhs = _encode_point(_scalar(_BASE, s))
        rhs = _encode_point(_add(r, _scalar(a, k)))
        return hmac.compare_digest(lhs, rhs)
    except (CheckpointRejected, ValueError, OverflowError):
        return False


def _pack(v):
    if type(v) is bool:
        return b"b1" if v else b"b0"
    if type(v) is int and 0 <= v <= _MAXINT:
        return b"i" + v.to_bytes(8, "big")
    if type(v) is str:
        try:
            raw = v.encode("ascii")
        except UnicodeEncodeError as exc:
            raise CheckpointRejected("nonascii checkpoint") from exc
        if len(raw) > 256:
            raise CheckpointRejected("oversize checkpoint")
        return b"s" + len(raw).to_bytes(2, "big") + raw
    if type(v) is tuple and len(v) <= 128:
        return b"t" + len(v).to_bytes(2, "big") + b"".join(_pack(x) for x in v)
    raise CheckpointRejected("unsupported checkpoint type")


def checkpoint_message(claim):
    """Bound exact schema; claim itself remains an untrusted assertion."""
    if type(claim) is not dict or set(claim) != set(_FIELDS):
        raise CheckpointRejected("wrong checkpoint schema")
    if (not _hex(claim["git_sha"], 40) or
            any(not _hex(claim[k]) for k in (
                "source_sha256", "workflow_sha256", "roster_sha256",
                "transcript_sha256", "old_root_sha256", "new_root_sha256",
                "nonce_sha256")) or
            any(not _positive(claim[k]) for k in (
                "old_size", "new_size", "issued_at", "observed_at")) or
            not claim["old_size"] < claim["new_size"] <= 128 or
            claim["issued_at"] > claim["observed_at"] or
            claim["old_root_sha256"] == claim["new_root_sha256"] or
            type(claim["ack_state"]) is not str or
            claim["ack_state"] not in ("NOT_SENT", "ACK_LOST_UNRESOLVED") or
            claim["release_ready"] is not False or
            claim["live_trading_allowed"] is not False):
        raise CheckpointRejected("invalid checkpoint identity or unsafe lifecycle")
    views = claim["provider_claims"]
    if (type(views) is not tuple or len(views) != 2 or
            any(type(v) is not tuple or len(v) != 7 for v in views)):
        raise CheckpointRejected("missing independent provider claims")
    for i, (os, run, job, git, source, log, status) in enumerate(views):
        if (os != ("ubuntu", "windows")[i] or
                not _positive(run) or not _positive(job) or
                git != claim["git_sha"] or source != claim["source_sha256"] or
                not _hex(log) or type(status) is not str or status != "NOT_VERIFIED"):
            raise CheckpointRejected("provider evidence is forged or split")
    if views[0][1] == views[1][1] or views[0][2] == views[1][2]:
        raise CheckpointRejected("duplicate GitHub run/job identity")
    writers = claim["writer_claims"]
    if (type(writers) is not tuple or len(writers) != 2 or
            any(type(row) is not tuple or len(row) != 4 for row in writers) or
            type(writers[0][0]) is not str or type(writers[1][0]) is not str or
            not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", writers[0][0]) or
            not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", writers[1][0]) or
            writers[0][0] == writers[1][0]):
        raise CheckpointRejected("duplicate or invalid CAS actors")
    for i, (actor, generation, base, result) in enumerate(writers):
        if (type(generation) is not int or generation != claim["old_size"] or
                base != claim["old_root_sha256"] or
                type(result) is not str or
                result != ("CLAIMED_WIN" if i == 0 else "CLAIMED_CONFLICT")):
            raise CheckpointRejected("claimed CAS atomicity cannot be established")
    return _DOMAIN + _pack(tuple((key, claim[key]) for key in _FIELDS))


def quarantine_signed_checkpoint(claim, trust, signature_hex, *, expected_transcript_sha256, expected_anchor_sha256):
    """Check actual Ed25519 equation, then preserve all provenance NO-GO flags.

    Trust is supplied by caller; this API CANNOT establish out-of-band origin,
    trusted time, provider signatures, append-only durability or transactional CAS.
    """
    message = checkpoint_message(claim)
    if type(trust) is not dict or set(trust) != set(_TRUST):
        raise CheckpointRejected("incomplete trust record")
    if (not _hex(expected_transcript_sha256) or
            not _hex(expected_anchor_sha256) or
            not hmac.compare_digest(expected_transcript_sha256, claim["transcript_sha256"]) or
            not _hex(trust["public_key_hex"]) or
            not _hex(trust["fingerprint_sha256"]) or
            not hmac.compare_digest(expected_anchor_sha256, trust["fingerprint_sha256"]) or
            not hmac.compare_digest(hashlib.sha256(bytes.fromhex(trust["public_key_hex"])).hexdigest(),
                                    trust["fingerprint_sha256"]) or
            not _positive(trust["not_before"]) or not _positive(trust["not_after"]) or
            not trust["not_before"] <= claim["issued_at"] <= trust["not_after"]):
        raise CheckpointRejected("unbound or invalid claimed trust anchor")
    revocations = trust["revocations"]
    if (type(revocations) is not tuple or len(revocations) > 128 or
            any(type(x) is not tuple or len(x) != 2 or
                not _hex(x[0]) or not _positive(x[1]) for x in revocations) or
            revocations != tuple(sorted(revocations)) or
            len({x[0] for x in revocations}) != len(revocations)):
        raise CheckpointRejected("invalid key-revocation ledger")
    if any(key == expected_anchor_sha256 and at <= claim["observed_at"]
           for key, at in revocations):
        raise CheckpointRejected("claimed key revoked before observation")
    for field, current in (("spent_nonces", claim["nonce_sha256"]),
                           ("seen_roots", claim["new_root_sha256"])):
        history = trust[field]
        if (type(history) is not tuple or len(history) > 128 or
                any(not _hex(x) for x in history) or
                history != tuple(sorted(set(history))) or current in history):
            raise CheckpointRejected("invalid or replayed checkpoint")
    if not verify_ed25519(trust["public_key_hex"], message, signature_hex):
        raise CheckpointRejected("invalid mathematical Ed25519 signature")
    return {
        "status": "ED25519_EQUATION_VALID_TRUST_PROVENANCE_UNVERIFIED",
        "signature_equation_valid": True,
        "checkpoint_message_sha256": hashlib.sha256(message).hexdigest(),
        "lost_ack_unresolved": claim["ack_state"] == "ACK_LOST_UNRESOLVED",
        "trust_anchor_provenance_authenticated": False,
        "issuer_independently_authenticated": False,
        "revocation_origin_authenticated": False,
        "provider_origin_authenticated": False,
        "full_history_independently_authenticated": False,
        "durable_cas_verified": False,
        "clock_verified": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }

# RC682 publication gate: mathematical signature validity is not authority.
# Caller-controlled anchor provenance, provider evidence and CAS stay NO-GO.
