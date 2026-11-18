"""RC701: offline independent checkpoint custody intake and untrusted MRSC readback.

This module does NOT verify cryptographic note signatures, connect to Rekor/AWS,
accept caller-provided root keys, or authorize trading. A signed-looking note
and a typed AWS response remain UNAUTHENTICATED until checked by independent
pinned operators and external replay-resistant infrastructure.
"""
import hashlib
import hmac
import json
import re

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = '538a83d0037b1651dc0761dc40c76ffefe914d88'
GATES = ('owner_oob_key', 'reviewer_oob_key', 'provider_ubuntu_attestation',
         'provider_windows_attestation', 'revocation_trusted_time',
         'external_immutable_checkpoint', 'external_antirollback_cas',
         'remote_provider_ack')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
IDENT = re.compile(r'[A-Za-z][A-Za-z0-9_-]{1,62}\Z')
INT_MAX = 2**63-1
CHECKPOINT_FIELDS = frozenset(('tree_size', 'root_sha256', 'log_origin', 'note_b64',
                              'log_key_fingerprint_sha256',
                              'witness_key_fingerprint_sha256',
                              'witness_cosignature_b64'))
BUNDLE_FIELDS = frozenset(('repository', 'branch', 'source_sha',
                           'challenge_sha256', 'nonce_sha256', 'audience',
                           'historical', 'current', 'consistency_nodes_sha256',
                           'operator_separation_claim', 'verified'))
RECEIPT_FIELDS = frozenset(('source_sha', 'table', 'item_key', 'epoch',
                            'generation', 'fence', 'root_sha256',
                            'request_id_sha256', 'consistently_read',
                            'origin', 'provider_signature_verified'))
EXPECTED_FIELDS = frozenset(('source_sha', 'table', 'item_key', 'epoch',
                             'generation', 'fence', 'next_generation',
                             'next_fence', 'old_root_sha256',
                             'new_root_sha256', 'request_id_sha256'))

class CustodyRejected(ValueError):
    """Badly scoped evidence or attempt to manufacture authority."""

def require(v, reason):
    if not v:
        raise CustodyRejected(reason)

def ishex(v):
    return type(v) is str and HEX64.fullmatch(v) is not None

def number(v):
    return type(v) is int and 0 <= v <= INT_MAX

def identifier(v):
    return type(v) is str and IDENT.fullmatch(v) is not None

_BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def encode64(data):
    """Strict RFC4648 standard-base64 encoder using no extra imports."""
    out = []
    for i in range(0,len(data),3):
        chunk=data[i:i+3]
        n=int.from_bytes(chunk.ljust(3,b'\x00'),'big')
        out.append(_BASE64_ALPHABET[(n>>18)&63])
        out.append(_BASE64_ALPHABET[(n>>12)&63])
        out.append(_BASE64_ALPHABET[(n>>6)&63] if len(chunk)>1 else '=')
        out.append(_BASE64_ALPHABET[n&63] if len(chunk)>2 else '=')
    return ''.join(out)

def b64_bytes(v, max_len):
    require(type(v) is str and 0<len(v)<=max_len*2 and len(v)%4==0,
            'invalid_base64_material')
    out=bytearray()
    for i in range(0,len(v),4):
        chunk=v[i:i+4]
        padding=chunk.count('=')
        require(padding<=2 and chunk[0]!='=' and chunk[1]!='=' and
                (padding==0 or i==len(v)-4) and
                chunk.endswith('='*padding), 'invalid_base64_material')
        n=0
        for ch in chunk:
            k=0 if ch=='=' else _BASE64_ALPHABET.find(ch)
            require(k>=0,'invalid_base64_material')
            n=(n<<6)|k
        out.append((n>>16)&255)
        if padding<2:out.append((n>>8)&255)
        if padding<1:out.append(n&255)
        require(len(out)<=max_len,'encoded_material_size')
    data=bytes(out)
    require(encode64(data)==v, 'canonical_material_size')
    return data

def checkpoint_material(cp):
    require(type(cp) is dict and cp.keys()==CHECKPOINT_FIELDS, 'checkpoint_schema')
    require(number(cp['tree_size']) and cp['tree_size'] > 0, 'tree_size')
    require(ishex(cp['root_sha256']) and ishex(cp['log_key_fingerprint_sha256']) and
            ishex(cp['witness_key_fingerprint_sha256']), 'checkpoint_hashes')
    require(cp['log_key_fingerprint_sha256'] != cp['witness_key_fingerprint_sha256'],
            'independent_witness_key_required')
    note = b64_bytes(cp['note_b64'], 65536)
    # Validate C2SP tlog-checkpoint's exact three-line body and note envelope.
    # Parsing is NOT signature verification. No caller-supplied key is trusted.
    require(type(cp['log_origin']) is str and 1 <= len(cp['log_origin']) <= 256 and
            '\n' not in cp['log_origin'] and '\r' not in cp['log_origin'], 'log_origin')
    root_b64=encode64(bytes.fromhex(cp['root_sha256']))
    header=(cp['log_origin']+'\n'+str(cp['tree_size'])+'\n'+root_b64+'\n\n').encode('utf-8')
    require(note.startswith(header), 'checkpoint_body_not_bound_to_tree')
    try:
        sig_lines=note[len(header):].decode('utf-8').splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise CustodyRejected('malformed_note_signatures') from exc
    require(1 <= len(sig_lines) <= 32 and all(line.endswith('\n') for line in sig_lines),
            'malformed_note_signatures')
    for line in sig_lines:
        match=re.fullmatch(r'— ([A-Za-z0-9_.:/-]{1,128}) ([A-Za-z0-9+/]+={0,2})\n',line)
        require(match is not None,'malformed_note_signatures')
        b64_bytes(match.group(2), 2048)
    cosignature = b64_bytes(cp['witness_cosignature_b64'], 4096)
    # These are bytes of CANDIDATE evidence, not authenticated endorsements.
    return {'tree_size':cp['tree_size'], 'root_sha256':cp['root_sha256'],
            'note_sha256':hashlib.sha256(note).hexdigest(),
            'log_origin':cp['log_origin'],
            'witness_claim_sha256':hashlib.sha256(cosignature).hexdigest(),
            'note_bytes':len(note), 'witness_claim_bytes':len(cosignature),
            'log_root_pin_independent':False,
            'witness_root_pin_independent':False}

def prepare_custody_intake(bundle):
    """Evidence-preserving external verification handoff; NEVER self-authenticate."""
    require(type(bundle) is dict and bundle.keys()==BUNDLE_FIELDS, 'bundle_schema')
    require(bundle['repository']==REPO and bundle['branch']==BRANCH and
            bundle['source_sha']==BASE_SHA, 'source_scope')
    require(ishex(bundle['challenge_sha256']) and ishex(bundle['nonce_sha256']) and
            bundle['challenge_sha256'] != bundle['nonce_sha256'], 'nonce_challenge')
    require(bundle['audience'] in ('INDEPENDENT_LOG_AUDITOR', 'INDEPENDENT_REVIEWER') and
            type(bundle['audience']) is str, 'audience_scope')
    require(ishex(bundle['consistency_nodes_sha256']), 'consistency_digest')
    require(bundle['verified'] is False and bundle['operator_separation_claim'] is False,
            'caller_authority_promotion')
    old=checkpoint_material(bundle['historical'])
    new=checkpoint_material(bundle['current'])
    require(old['tree_size'] <= new['tree_size'], 'checkpoint_rollback')
    require(old['tree_size'] != new['tree_size'] or
            hmac.compare_digest(old['root_sha256'], new['root_sha256']),
            'checkpoint_split_view')
    require(old['log_origin'] == new['log_origin'], 'log_origin_splice')
    require(bundle['historical']['log_key_fingerprint_sha256'] ==
            bundle['current']['log_key_fingerprint_sha256'], 'log_key_rotation_untrusted')
    require(bundle['historical']['witness_key_fingerprint_sha256'] ==
            bundle['current']['witness_key_fingerprint_sha256'], 'witness_key_rotation_untrusted')
    require(old['note_sha256']!=new['note_sha256'] or
            old['tree_size']==new['tree_size'], 'replayed_checkpoint_note')
    canonical=json.dumps(bundle,sort_keys=True,separators=(',',':'),
                         ensure_ascii=True).encode('ascii')
    digest=hashlib.sha256(b'KRYPTOAI-RC701-UNVERIFIED-HANDOFF\x00'+
                          len(canonical).to_bytes(4,'big')+canonical).hexdigest()
    return {'classification':'DETACHED_UNTRUSTED_EVIDENCE_CUSTODY_ONLY',
            'handoff_sha256':digest, 'historical':old, 'current':new,
            'external_log_verification':'REQUIRES_PINNED_LOG_ROOT_AND_NOTE_SIGNATURE',
            'external_witness_verification':'REQUIRES_DIFFERENT_ADMIN_PINNED_WITNESS',
            'historical_consistency':'REQUIRES_AUTHENTICATED_RFC6962_MATH_AND_PRIOR_ROOT',
            'revocation_and_time':'REQUIRES_INDEPENDENT_TRUSTED_AUTHORITIES',
            'external_gates_verified':0, 'live_allowed':False}

def reconcile_untrusted_mrsc_read(expected, observation):
    """Classify one *caller-reported* strongly consistent GetItem after lost write ACK.

    This is not a network read or proof of authentic AWS origin. Never retry
    automatically: loss of a response leaves write outcome ambiguous. Recovery
    requires an independently credentialed operator and cross-host fence checks.
    """
    require(type(expected) is dict and expected.keys()==EXPECTED_FIELDS, 'expected_schema')
    require(type(observation) is dict and observation.keys()==RECEIPT_FIELDS,
            'observation_schema')
    require(expected['source_sha']==BASE_SHA and observation['source_sha']==BASE_SHA,
            'source_replay')
    require(identifier(expected['table']) and identifier(expected['item_key']) and
            observation['table']==expected['table'] and
            observation['item_key']==expected['item_key'], 'remote_item_scope')
    for k in ('epoch','generation','fence','next_generation','next_fence'):
        if k in expected: require(number(expected[k]), 'counter_type')
    for k in ('epoch','generation','fence'):
        require(number(observation[k]), 'counter_type')
    require(expected['epoch']>0 and expected['next_generation']==expected['generation']+1 and
            expected['next_fence']==expected['fence']+1, 'monotone_fence')
    for k in ('old_root_sha256','new_root_sha256','request_id_sha256'):
        require(ishex(expected[k]), 'request_digests')
    for k in ('root_sha256','request_id_sha256'):
        require(ishex(observation[k]), 'response_digests')
    require(observation['consistently_read'] is True and
            observation['provider_signature_verified'] is False and
            observation['origin']=='CALLER_REPORTED_AWS_JSON', 'fake_remote_attestation')
    require(observation['epoch']==expected['epoch'], 'remote_epoch_mismatch')
    current=(observation['generation'],observation['fence'],observation['root_sha256'])
    before=(expected['generation'],expected['fence'],expected['old_root_sha256'])
    after=(expected['next_generation'],expected['next_fence'],expected['new_root_sha256'])
    if current==after and observation['request_id_sha256']==expected['request_id_sha256']:
        state='CLAIMED_APPLIED_BUT_UNAUTHENTICATED'
    elif current==before:
        state='CLAIMED_OLD_STATE_RETRY_NOT_AUTHORIZED'
    else:
        state='CONFLICT_OR_ROLLBACK_NO_AUTOMATED_ACTION'
    return {'classification':state, 'remote_read_authenticated':False,
            'remote_cas_verified':False,'independent_admin_verified':False,
            'restore_resistance_verified':False,'remote_ack_authenticated':False,
            'automated_retry_authorized':False,'external_gates_verified':0,
            'live_allowed':False}

def external_gate_matrix():
    return tuple({'gate':g,'status':'BLOCKED','external_source_authenticated':False}
                 for g in GATES)
