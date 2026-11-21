"""RC696/TUR53: byte-bound Ed25519 candidate proofs, never authority.

A valid signature from a caller-provided key is NOT an independently authorized
owner/reviewer/provider signature. No pins, revocation service, trusted clock,
external Merkle anchor, remote CAS or remote ACK are accessible here.
A delegated Ed25519 verifier is OPTIONAL, untrusted, and never a root.
No IO, network, key generation, trading, fitting, or release mutation.
"""
import hashlib
import hmac
import json
import re

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_COUNTER = 2**63 - 1
_HEX = {40: re.compile(r'[0-9a-f]{40}\Z'),
        64: re.compile(r'[0-9a-f]{64}\Z'),
        128: re.compile(r'[0-9a-f]{128}\Z')}
_ENVELOPE = frozenset(('repository','branch','source_sha','platform',
    'workflow_blob_sha','run','job','attempt','log_sha256','log_length',
    'challenge_sha256','nonce_sha256','epoch','fence'))
_PLATFORMS = ('ubuntu','windows')
_GATES = ('owner_oob_key','reviewer_oob_key',
          'provider_ubuntu_attestation','provider_windows_attestation',
          'revocation_trusted_time','external_immutable_checkpoint',
          'external_antirollback_cas','remote_provider_ack')

class EvidenceRejected(ValueError):
    """Reject untrusted material without promoting release or authorization."""

def _check(ok, reason):
    if not ok:
        raise EvidenceRejected(reason)

def _hex(value, length):
    return type(value) is str and _HEX[length].fullmatch(value) is not None

def _num(value, positive=False):
    return type(value) is int and (0 < value <= MAX_COUNTER if positive
                                   else 0 <= value <= MAX_COUNTER)

def _bytes(value, allow_empty=True):
    return type(value) is bytes and len(value) <= MAX_LOG_BYTES and (allow_empty or len(value)>0)

def pending_gates():
    return tuple({'gate':g,'verified':False,'status':'BLOCKED',
                  'independent_authority_required':True} for g in _GATES)

def validate_envelope(e, full_log_bytes):
    """Binds *actual given bytes*, not a caller-provided log digest alone."""
    _check(type(e) is dict and e.keys() == _ENVELOPE, 'envelope_schema')
    _check(e['repository'] == REPO and type(e['repository']) is str and
           e['branch'] == BRANCH and type(e['branch']) is str, 'scope')
    _check(_hex(e['source_sha'],40) and _hex(e['workflow_blob_sha'],40), 'git_sha')
    _check(type(e['platform']) is str and e['platform'] in _PLATFORMS,'platform')
    for field in ('run','job','attempt','log_length','epoch','fence'):
        _check(_num(e[field], True),'positive_counter_'+field)
    for field in ('log_sha256','challenge_sha256','nonce_sha256'):
        _check(_hex(e[field],64),'sha256_'+field)
    _check(_bytes(full_log_bytes,False),'log_bytes_limit')
    _check(len(full_log_bytes)==e['log_length'],'log_length_mismatch')
    _check(hmac.compare_digest(hashlib.sha256(full_log_bytes).hexdigest(),e['log_sha256']),
           'full_log_bytes_mismatch')
    return True

def canonical_signed_scope(e, full_log_bytes):
    """No ambiguous concatenation; caller still must authenticate the signer."""
    validate_envelope(e,full_log_bytes)
    payload=json.dumps(e,ensure_ascii=True,sort_keys=True,
                       separators=(',',':'),allow_nan=False).encode('ascii')
    return b'KRYPTOAI-RC696-PROVIDER-LOG-V1\0'+len(payload).to_bytes(4,'big')+payload

def verify_detached_ed25519(payload, public_key_hex, signature_hex, verifier=None):
    """Delegated signature equation check, never authenticates the verifier/key."""
    _check(_bytes(payload),'payload_bytes_limit')
    _check(_hex(public_key_hex,64),'public_key_format')
    _check(_hex(signature_hex,128),'signature_format')
    if verifier is None:
        return {'status':'CRYPTO_BACKEND_UNAVAILABLE','signature_math_valid':False,
                'authorized':False,'external_gate_open':False}
    _check(callable(verifier), 'untrusted_verifier_type')
    try:
        equation_claim=verifier(payload, bytes.fromhex(public_key_hex),
                                bytes.fromhex(signature_hex))
    except Exception:
        return {'status':'DELEGATED_VERIFIER_ERROR','signature_math_valid':False,
                'authorized':False,'external_gate_open':False}
    _check(type(equation_claim) is bool,'verifier_result_type')
    return {'status':('UNTRUSTED_ED25519_EQUATION_CLAIM' if equation_claim
                      else 'INVALID_SIGNATURE'),
            'signature_math_valid':False,'authorized':False,
            'external_gate_open':False}

def inspect_provider_candidate(envelope, original_full_log, claimed_key_hex, signature_hex):
    """Provider status / timestamp / GitHub API are not signed log attestation."""
    signed_scope=canonical_signed_scope(envelope,original_full_log)
    result=verify_detached_ed25519(signed_scope,claimed_key_hex,signature_hex)
    return {'status':'QUARANTINED_PROVIDER_CANDIDATE',
            'crypto_status':result['status'],
            'verified_provider_origin':False,
            'independent_key_provenance':False,
            'whole_log_sha256':hashlib.sha256(original_full_log).hexdigest(),
            'scope_sha256':hashlib.sha256(signed_scope).hexdigest(),
            'external_verified':0,'authenticated':False,'live':False}

def compare_ubuntu_windows(a, log_a, b, log_b):
    """Actual byte identity and independence of purported two-platform claims."""
    validate_envelope(a,log_a);validate_envelope(b,log_b)
    _check(a['platform']=='ubuntu' and b['platform']=='windows','platform_pair')
    _check(a['source_sha']==b['source_sha'] and
           a['challenge_sha256']==b['challenge_sha256'],'pair_source_challenge_fork')
    _check((a['run'],a['job'])!=(b['run'],b['job']), 'provider_job_replay')
    _check(a['log_sha256']!=b['log_sha256'],'cross_platform_log_duplicate')
    _check(a['nonce_sha256']!=b['nonce_sha256'],'cross_platform_nonce_replay')
    return {'status':'TWO_HOSTED_CLAIMS_NO_SIGNED_PROVIDER_AUTH',
            'external_verified':0,'authenticated':False}

def inspect_external_sequence(events):
    """Detect claimed revocation/rotation replay, never trust its clock."""
    _check(type(events) is tuple and 0<len(events)<=64,'timeline_length')
    previous=-1;seen=set();revoked=set()
    for item in events:
        _check(type(item) is dict and item.keys()=={'key_sha256','counter','event','event_sha256'},
               'timeline_schema')
        _check(_hex(item['key_sha256'],64) and _hex(item['event_sha256'],64), 'timeline_digest')
        _check(_num(item['counter'],True) and item['counter']>previous,'timeline_rollback')
        _check(item['event_sha256'] not in seen,'timeline_replay')
        _check(type(item['event']) is str and item['event'] in ('ISSUE','REVOKE'),'timeline_type')
        if item['event']=='REVOKE':revoked.add(item['key_sha256'])
        else:_check(item['key_sha256'] not in revoked,'revoked_key_reintroduced')
        previous=item['counter'];seen.add(item['event_sha256'])
    return {'status':'SELF_ASSERTED_CHRONOLOGY_ONLY','revoked_key_claims':tuple(sorted(revoked)),
            'trusted_time':False,'revocation_authenticated':False}

def inspect_checkpoint_pair(earlier, later):
    """A locally plausible root chain is not independent immutable anchoring."""
    for a in (earlier,later):
        _check(type(a) is dict and a.keys()=={'size','root_sha256','witness_sha256'},'checkpoint_schema')
        _check(_num(a['size'],True) and _hex(a['root_sha256'],64) and
               _hex(a['witness_sha256'],64),'checkpoint_fields')
    if later['size'] < earlier['size']:
        return 'ROLLBACK_REQUIRES_EXTERNAL_ANCHOR'
    if later['size']==earlier['size'] and earlier['root_sha256']!=later['root_sha256']:
        return 'SPLIT_VIEW_BLOCKED'
    return 'EXTERNAL_SIGNED_CONSISTENCY_PROOF_REQUIRED'

def inspect_remote_cas_ack(previous, proposed, ack):
    """Fail closed on stale fences/ABA/lost ACK. No remote operation is issued."""
    fields={'generation','fence','idempotency_sha256','state_sha256'}
    for value in (previous,proposed):
        _check(type(value) is dict and value.keys()==fields,'cas_schema')
        _check(_num(value['generation'],True) and _num(value['fence'],True) and
               _hex(value['idempotency_sha256'],64) and
               _hex(value['state_sha256'],64),'cas_fields')
    _check(proposed['generation']==previous['generation']+1 and
           proposed['fence']>previous['fence'],'cas_stale_or_rollback')
    _check(proposed['idempotency_sha256']!=previous['idempotency_sha256'],
           'cas_aba_replayed_idempotency')
    _check(type(ack) is dict and ack.keys()=={'idempotency_sha256','fence','origin','signature_sha256'},'ack_schema')
    _check(_hex(ack['idempotency_sha256'],64) and _hex(ack['signature_sha256'],64)
           and _num(ack['fence'],True),'ack_fields')
    _check(ack['idempotency_sha256']==proposed['idempotency_sha256'] and
           ack['fence']==proposed['fence'],'ack_stale_or_lost')
    _check(ack['origin']=='UNTRUSTED_CLAIM' and type(ack['origin']) is str,'ack_forged_auth')
    return {'status':'PENDING_AUTHENTICATED_REMOTE_RECONCILIATION',
            'durable_external_cas_verified':False,'remote_ack_verified':False,
            'release_allowed':False,'live_allowed':False}

# Immutable guards: FINAL=SEALED, LIVE=DISABLED, SINGLE_FIT=UNUSED, NET20=NOT_TESTED.
