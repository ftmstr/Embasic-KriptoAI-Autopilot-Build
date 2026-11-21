"""RC703: offline Ed25519 *candidate* signature equations and OOB trust boundary.

Educational, auditable RFC8032 arithmetic, not independently audited crypto,
not an independently pinned key, and not production authorization. Verifies
mathematical signatures only over caller-supplied candidate keys. No I/O.
"""
import hashlib
import hmac

from safe_public_ci import ci_rc702_c2sp_signature_preimages as c2sp
from safe_public_ci import ci_rc701_external_custody as custody

SOURCE_SHA = 'f00ca9355eb024f6db1fcafe2966b1ae83ffb178'
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P-2, P)) % P
I = pow(2, (P-1)//4, P)
IDENTITY = (0, 1, 1, 0)


class InvalidCandidate(ValueError):
    """Malformed / invalid candidate signature, never an authorization."""


def _point(x, y):
    return (x % P, y % P, 1, x*y % P)


def _decode(raw):
    if type(raw) is not bytes or len(raw) != 32:
        raise InvalidCandidate('bad_point_bytes')
    v = int.from_bytes(raw, 'little')
    y, sign = v & ((1 << 255)-1), v >> 255
    if y >= P:
        raise InvalidCandidate('noncanonical_y')
    yy = y*y % P
    denom = (D*yy + 1) % P
    if denom == 0:
        raise InvalidCandidate('invalid_denominator')
    x2 = (yy-1) * pow(denom, P-2, P) % P
    x = pow(x2, (P+3)//8, P)
    if x*x % P != x2:
        x = x*I % P
    if x*x % P != x2:
        raise InvalidCandidate('not_on_curve')
    if x & 1 != sign:
        x = P-x
    if x == 0 and sign:
        raise InvalidCandidate('noncanonical_x_sign')
    return _point(x,y)


def _add(a, b):
    x1,y1,z1,t1=a
    x2,y2,z2,t2=b
    aa=(y1-x1)*(y2-x2) % P
    bb=(y1+x1)*(y2+x2) % P
    cc=2*D*t1*t2 % P
    dd=2*z1*z2 % P
    ee=(bb-aa) % P
    ff=(dd-cc) % P
    gg=(dd+cc) % P
    hh=(bb+aa) % P
    return (ee*ff % P, gg*hh % P, ff*gg % P, ee*hh % P)


def _mul(k, point):
    out=IDENTITY
    while k:
        if k & 1:
            out=_add(out,point)
        point=_add(point,point)
        k >>= 1
    return out


def _same(a,b):
    return (a[0]*b[2]-b[0]*a[2]) % P == 0 and (a[1]*b[2]-b[1]*a[2]) % P == 0

BASE = _decode((4 * pow(5, P-2, P) % P).to_bytes(32,'little'))


def verify_candidate_ed25519(public_key, signature, message):
    """Strict RFC8032 Ed25519 math on untrusted, caller-selected keys.

    True denotes a valid arithmetic equation only, NEVER independent signing
    identity, trusted time, account ownership, revocation, or release approval.
    """
    if type(public_key) is not bytes or type(signature) is not bytes or type(message) is not bytes:
        return False
    if len(public_key)!=32 or len(signature)!=64 or len(message)>65536:
        return False
    s=int.from_bytes(signature[32:],'little')
    if s>=L:
        return False
    try:
        a=_decode(public_key)
        r=_decode(signature[:32])
    except InvalidCandidate:
        return False
    # Strict subgroup checks reject small-order/torsion candidate public keys.
    if _same(a,IDENTITY) or not _same(_mul(L,a),IDENTITY):
        return False
    if _same(r,IDENTITY) or not _same(_mul(L,r),IDENTITY):
        return False
    k=int.from_bytes(hashlib.sha512(signature[:32]+public_key+message).digest(),'little') % L
    return _same(_mul(s,BASE),_add(r,_mul(k,a)))


def examine_untrusted_c2sp_pair(request, *, verifier_source_sha):
    """Check real Ed25519 *math*; deliberately never accept OOB authority.

    Valid signatures under keys supplied *within the same request* are NOT
    independently pinned roots. The C2SP log and witness preimages differ.
    """
    if type(request) is not dict or verifier_source_sha != SOURCE_SHA:
        raise InvalidCandidate('rc703_exact_source_scope')
    # RC702 validates exact canonical note, signer name, key IDs and nonce.
    try:
        handoff=c2sp.prepare_signature_handoff(request)
        raw=custody.b64_bytes(request['note_b64'],65536)
        parsed=c2sp._split_checkpoint(raw)
    except (c2sp.EvidenceRejected,custody.CustodyRejected,KeyError,TypeError) as exc:
        raise InvalidCandidate('rc702_preflight_failed') from exc
    log_key=bytes.fromhex(request['log_public_key_hex'])
    witness_key=bytes.fromhex(request['witness_public_key_hex'])
    log_id=c2sp.key_identifier(request['log_name'],log_key,1)
    witness_id=c2sp.key_identifier(request['witness_name'],witness_key,4)
    log_sig=[]
    witness_sig=[]
    for name,payload in parsed['signatures']:
        if name==request['log_name'] and hmac.compare_digest(payload[:4],log_id):
            log_sig.append(payload[4:])
        if name==request['witness_name'] and hmac.compare_digest(payload[:4],witness_id):
            witness_sig.append((int.from_bytes(payload[4:12],'big'),payload[12:]))
    if len(log_sig)!=1 or len(witness_sig)!=1:
        raise InvalidCandidate('candidate_signature_missing')
    timestamp,witness_bytes=witness_sig[0]
    log_message=parsed['body']
    witness_message=b'cosignature/v1\ntime '+str(timestamp).encode('ascii')+b'\n'+log_message
    log_valid=verify_candidate_ed25519(log_key,log_sig[0],log_message)
    witness_valid=verify_candidate_ed25519(witness_key,witness_bytes,witness_message)
    if not log_valid or not witness_valid:
        raise InvalidCandidate('bad_candidate_ed25519_equation')
    # Do NOT accept a caller-supplied root, signer assertion or 'verified' field.
    return {'status':'VALID_CANDIDATE_MATH_UNTRUSTED_KEYS',
            'log_math_valid':True,'witness_math_valid':True,
            'log_preimage_sha256':handoff['log_preimage_sha256'],
            'witness_preimage_sha256':handoff['witness_preimage_sha256'],
            'signature_preimage_contract_sha256':handoff['handoff_sha256'],
            'oob_log_root_independently_pinned':False,
            'oob_witness_root_independently_pinned':False,
            'owner_and_reviewer_separate_admin_verified':False,
            'historical_checkpoint_and_consistency_authenticated':False,
            'provider_original_full_logs_authenticated':False,
            'mrsc_multi_host_fence_test_observed':False,
            'recipient_idempotent_ack_authenticated':False,
            'external_gates_verified':0,'auth':'NO-GO','live':'DISABLED',
            'final':'SEALED','single_fit':'UNUSED','net20':'NOT_TESTED'}
