"""RC683 — synthetic two-key Ed25519 + full-history/restart quarantine.

Correct signature *equations* do not establish authority, anchor distribution,
GitHub provider origin, trustworthy time, durable CAS or a financial result.
Only caller-supplied public facts and fabricated local witnesses are processed.
"""
import hashlib
import hmac
import re


class DualAuthorityRejected(ValueError):
    """Reject malformed or inconsistent synthetic dual-authority evidence."""


_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_IDENTITY = (0, 1, 1, 0)
_MAX = (1 << 63) - 2
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX128 = re.compile(r"[0-9a-f]{128}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_DOMAIN = b"RC683-QUARANTINED-DUAL-SIGNED-FULL-HISTORY-V1\x00"
_FIELDS = (
    "repository", "branch", "git_sha", "source_sha256", "workflow_sha256",
    "roster_sha256", "transcript_sha256", "old_size", "new_size",
    "old_root_sha256", "new_root_sha256", "full_history", "consistency_proof",
    "nonce_sha256", "issued_at", "observed_at", "authorities", "providers",
    "writers", "revocations", "spent_nonces", "seen_roots", "ack_state",
    "release_ready", "live_trading_allowed",
)
_PINS = (
    "git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
    "transcript_sha256", "old_root_sha256", "new_root_sha256",
    "nonce_sha256", "authority_fingerprints", "checkpoint_sha256",
    "out_of_band_trust_verified", "provider_attestation_verified",
    "durable_cas_verified",
)


def _hex(s, n=64):
    return type(s) is str and {40: _HEX40, 64: _HEX64, 128: _HEX128}[n].fullmatch(s) is not None


def _num(x):
    return type(x) is int and 1 <= x <= _MAX


def _name(x):
    return type(x) is str and _NAME.fullmatch(x) is not None


def _decode(value):
    if type(value) is not bytes or len(value) != 32:
        raise DualAuthorityRejected("invalid compressed-point length")
    v = int.from_bytes(value, "little")
    y, sign = v & ((1 << 255) - 1), v >> 255
    if y >= _Q:
        raise DualAuthorityRejected("noncanonical Edwards coordinate")
    yy = y*y % _Q
    xx = (yy-1)*pow((_D*yy+1) % _Q, _Q-2, _Q) % _Q
    x = pow(xx, (_Q+3)//8, _Q)
    if (x*x-xx) % _Q:
        x = x*_I % _Q
    if (x*x-xx) % _Q or x == 0 and sign:
        raise DualAuthorityRejected("non-curve or noncanonical sign")
    if x & 1 != sign:
        x = -x % _Q
    return x, y, 1, x*y % _Q


def _add(a, b):
    x,y,z,t = a
    X,Y,Z,T = b
    A = (y-x)*(Y-X) % _Q
    B = (y+x)*(Y+X) % _Q
    C = 2*_D*t*T % _Q
    D = 2*z*Z % _Q
    E,F,G,H = (B-A) % _Q,(D-C) % _Q,(D+C) % _Q,(B+A) % _Q
    return E*F%_Q,G*H%_Q,F*G%_Q,E*H%_Q


def _mul(point, scalar):
    result = _IDENTITY
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _encode(point):
    x,y,z,_ = point
    inv = pow(z, _Q-2, _Q)
    return ((y*inv%_Q) | (((x*inv%_Q) & 1) << 255)).to_bytes(32, "little")


_BASE = _decode((4*pow(5, _Q-2, _Q) % _Q).to_bytes(32, "little"))
_ENC_ID = _encode(_IDENTITY)


def ed25519_equation(public_hex, message, signature_hex):
    """Bounded RFC8032 Ed25519 equation; NOT public-key provenance."""
    if (not _hex(public_hex) or not _hex(signature_hex, 128) or
            type(message) is not bytes or len(message) > 32768):
        return False
    signature, key = bytes.fromhex(signature_hex), bytes.fromhex(public_hex)
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _L:
        return False
    try:
        A, R = _decode(key), _decode(signature[:32])
        if (_encode(_mul(A, 8)) == _ENC_ID or _encode(_mul(R, 8)) == _ENC_ID or
                _encode(_mul(A, _L)) != _ENC_ID or _encode(_mul(R, _L)) != _ENC_ID):
            return False
        k = int.from_bytes(hashlib.sha512(signature[:32]+key+message).digest(), "little") % _L
        return hmac.compare_digest(_encode(_mul(_BASE, scalar)),
                                   _encode(_add(R, _mul(A, k))))
    except (ValueError, OverflowError, DualAuthorityRejected):
        return False


def _node(left, right):
    return hashlib.sha256(b"\x01"+left+right).digest()


def _root(leaves):
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00"+bytes.fromhex(leaves[0])).digest()
    split = 1 << ((len(leaves)-1).bit_length()-1)
    return _node(_root(leaves[:split]), _root(leaves[split:]))


def _proof(leaves, old):
    def rec(items, n, known):
        if n == len(items):
            return () if known else (_root(items).hex(),)
        split = 1 << ((len(items)-1).bit_length()-1)
        if n <= split:
            return (*rec(items[:split], n, known), _root(items[split:]).hex())
        return (*rec(items[split:], n-split, False), _root(items[:split]).hex())
    return rec(leaves, old, True)


def _pack(v):
    if type(v) is bool:
        return b"b1" if v else b"b0"
    if type(v) is int and 0 <= v <= _MAX:
        return b"i"+v.to_bytes(8,"big")
    if type(v) is str:
        try:
            raw = v.encode("ascii")
        except UnicodeEncodeError as exc:
            raise DualAuthorityRejected("nonascii transcript") from exc
        if len(raw) > 256:
            raise DualAuthorityRejected("oversize transcript value")
        return b"s"+len(raw).to_bytes(2,"big")+raw
    if type(v) is tuple and len(v) <= 128:
        return b"t"+len(v).to_bytes(2,"big")+b"".join(_pack(x) for x in v)
    raise DualAuthorityRejected("invalid transcript type")


def _sorted_hash_history(history):
    return (type(history) is tuple and len(history) <= 128 and
            all(_hex(x) for x in history) and
            history == tuple(sorted(set(history))))


def checkpoint_bytes(claim):
    """Canonical bytes signed by both roles; no caller-supplied signature included."""
    if type(claim) is not dict or set(claim) != set(_FIELDS):
        raise DualAuthorityRejected("exact claim schema required")
    if (claim["repository"] != _REPO or claim["branch"] != _BRANCH or
            not _hex(claim["git_sha"],40) or
            any(not _hex(claim[x]) for x in (
                "source_sha256","workflow_sha256","roster_sha256",
                "transcript_sha256","old_root_sha256","new_root_sha256","nonce_sha256")) or
            any(not _num(claim[x]) for x in (
                "old_size","new_size","issued_at","observed_at")) or
            not claim["old_size"] < claim["new_size"] <= 128 or
            claim["issued_at"] > claim["observed_at"] or
            claim["release_ready"] is not False or
            claim["live_trading_allowed"] is not False or
            type(claim["ack_state"]) is not str or
            claim["ack_state"] not in ("NOT_SENT","ACK_LOST_UNRESOLVED")):
        raise DualAuthorityRejected("unsafe source, generation, clock or release")
    leaves=claim["full_history"]
    if (type(leaves) is not tuple or len(leaves) != claim["new_size"] or
            any(not _hex(x) for x in leaves) or len(set(leaves)) != len(leaves)):
        raise DualAuthorityRejected("full-history leaf count or hash mismatch")
    old_root,new_root=_root(leaves[:claim["old_size"]]).hex(),_root(leaves).hex()
    if (not hmac.compare_digest(old_root,claim["old_root_sha256"]) or
            not hmac.compare_digest(new_root,claim["new_root_sha256"]) or
            old_root == new_root):
        raise DualAuthorityRejected("Merkle full history contradicts claimed roots")
    proof=claim["consistency_proof"]
    if (type(proof) is not tuple or len(proof)>8 or
            any(not _hex(x) for x in proof) or
            proof != _proof(leaves,claim["old_size"])):
        raise DualAuthorityRejected("incorrect size-bound consistency proof")
    roles=claim["authorities"]
    if (type(roles) is not tuple or len(roles)!=2 or
            any(type(x) is not tuple or len(x)!=6 for x in roles)):
        raise DualAuthorityRejected("two issuer records required")
    for index,(role,actor,key,beg,end,signed_at) in enumerate(roles):
        if (role != ("owner","independent_reviewer")[index] or not _name(actor) or
                not _hex(key) or any(not _num(t) for t in (beg,end,signed_at)) or
                not beg <= signed_at <= end or
                not claim["issued_at"] <= signed_at <= claim["observed_at"]):
            raise DualAuthorityRejected("invalid authority role, key or claimed time")
    if roles[0][1]==roles[1][1] or roles[0][2]==roles[1][2]:
        raise DualAuthorityRejected("duplicate authority/key cannot meet threshold")
    rev=claim["revocations"]
    if (type(rev) is not tuple or len(rev)>128 or
            any(type(x) is not tuple or len(x)!=2 or not _hex(x[0]) or not _num(x[1])
                for x in rev) or rev != tuple(sorted(rev)) or
            len({x[0] for x in rev})!=len(rev)):
        raise DualAuthorityRejected("invalid claimed revocation ledger")
    fingerprints=tuple(hashlib.sha256(bytes.fromhex(x[2])).hexdigest() for x in roles)
    if any(key in fingerprints and when <= claim["observed_at"] for key,when in rev):
        raise DualAuthorityRejected("key revoked at claimed observation time")
    providers=claim["providers"]
    if (type(providers) is not tuple or len(providers)!=2 or
            any(type(x) is not tuple or len(x)!=7 for x in providers)):
        raise DualAuthorityRejected("both claimed OS runs required")
    for index,(os,run,job,git,source,log,state) in enumerate(providers):
        if (os != ("ubuntu","windows")[index] or not _num(run) or not _num(job) or
                git != claim["git_sha"] or source != claim["source_sha256"] or
                not _hex(log) or type(state) is not str or state!="NOT_VERIFIED"):
            raise DualAuthorityRejected("unbound/overstated provider receipt")
    if providers[0][1]==providers[1][1] or providers[0][2]==providers[1][2]:
        raise DualAuthorityRejected("duplicated provider run/job")
    writers=claim["writers"]
    if (type(writers) is not tuple or len(writers)!=2 or
            any(type(x) is not tuple or len(x)!=6 for x in writers)):
        raise DualAuthorityRejected("restart conflict trace required")
    for index,(actor,epoch,generation,base,new,status) in enumerate(writers):
        if (not _name(actor) or type(epoch) is not int or epoch!=index+1 or
                type(generation) is not int or generation!=claim["old_size"] or
                base != old_root or new != new_root or type(status) is not str or
                status != ("CLAIMED_WIN","CLAIMED_CONFLICT")[index]):
            raise DualAuthorityRejected("stale, ABA, rollback or double winner")
    if writers[0][0]==writers[1][0]:
        raise DualAuthorityRejected("same actor claiming independent race")
    if (not _sorted_hash_history(claim["spent_nonces"]) or
            not _sorted_hash_history(claim["seen_roots"]) or
            claim["nonce_sha256"] in claim["spent_nonces"] or
            new_root in claim["seen_roots"]):
        raise DualAuthorityRejected("replayed nonce/root or bad history")
    return _DOMAIN + _pack(tuple((field, claim[field]) for field in _FIELDS))


def audit_dual_authority(claim, signatures, pinned):
    """Equation verification and structural quarantine only; never AUTHENTICATED."""
    msg=checkpoint_bytes(claim)
    if type(signatures) is not tuple or len(signatures)!=2 or any(not _hex(s,128) for s in signatures):
        raise DualAuthorityRejected("two canonical signature encodings required")
    if type(pinned) is not dict or set(pinned)!=set(_PINS):
        raise DualAuthorityRejected("missing/extra trust pin")
    for name in ("git_sha","source_sha256","workflow_sha256","roster_sha256",
                 "transcript_sha256","old_root_sha256","new_root_sha256","nonce_sha256"):
        if (not _hex(pinned[name],40 if name=="git_sha" else 64) or
                not hmac.compare_digest(pinned[name],claim[name])):
            raise DualAuthorityRejected("foreign source/roster/transcript pin")
    keys=tuple(hashlib.sha256(bytes.fromhex(x[2])).hexdigest() for x in claim["authorities"])
    if (type(pinned["authority_fingerprints"]) is not tuple or
            pinned["authority_fingerprints"] != keys or
            not _hex(pinned["checkpoint_sha256"]) or
            not hmac.compare_digest(hashlib.sha256(msg).hexdigest(),pinned["checkpoint_sha256"])):
        raise DualAuthorityRejected("foreign asserted authority/digest")
    for field in ("out_of_band_trust_verified","provider_attestation_verified","durable_cas_verified"):
        if pinned[field] is not False:
            raise DualAuthorityRejected("caller cannot elevate unverified authority")
    if any(not ed25519_equation(role[2],msg,sig)
           for role,sig in zip(claim["authorities"],signatures)):
        raise DualAuthorityRejected("independent Ed25519 equation mismatch")
    return {
        "status":"DUAL_ED25519_EQUATIONS_VALID_ORIGIN_UNAUTHENTICATED",
        "signature_equations_valid":True,
        "checkpoint_sha256":hashlib.sha256(msg).hexdigest(),
        "lost_ack_unresolved":claim["ack_state"]=="ACK_LOST_UNRESOLVED",
        "authority_origin_authenticated":False,
        "trust_anchor_distribution_authenticated":False,
        "revocation_origin_authenticated":False,
        "provider_origin_authenticated":False,
        "merkle_history_authenticated":False,
        "durable_cas_verified":False,
        "restart_recovery_verified":False,
        "trusted_clock_verified":False,
        "release_ready":False,
        "live_trading_allowed":False,
    }

# TUR40 final gate: caller-controlled pins are never authenticated authority.
# No release, real exchange, model fit, durable CAS or resolved ACK is implied.
