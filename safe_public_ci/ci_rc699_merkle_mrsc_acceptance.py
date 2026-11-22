"""RC699/TUR56: RFC6962 inclusion math and MRSC provider acceptance boundary.

A valid Merkle inclusion equation does not authenticate a checkpoint, witness,
leaf signer, log origin, or historical consistency. All eight genuine external
proof authorities remain BLOCKED. No IO, crypto package, network, CAS write,
API credentials, time source, or exchange connection.
"""
import hashlib
import hmac
import json
import re

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = '68ef3bf1ced615008b2ab089265f85fe7d83dac3'
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
MAX = 2**63 - 1
MAX_ENTRY = 2**20
GATES = (
    'owner_oob_key', 'reviewer_oob_key', 'provider_ubuntu_attestation',
    'provider_windows_attestation', 'revocation_trusted_time',
    'external_immutable_checkpoint', 'external_antirollback_cas',
    'remote_provider_ack',
)
ACCEPTANCE = (
    'independent Ed25519 owner public-key pin, signed role delegation and out-of-band custody',
    'separate reviewer public-key pin, external independent signed review and revocation',
    'provider-issued signature over original unmodified Ubuntu full-job-log bytes',
    'provider-issued signature over original unmodified Windows full-job-log bytes',
    'authenticated non-rewindable time, key rotation and signed revocation chronology',
    'pinned origin/checkpoint signature plus RFC6962 inclusion, consistency and external witness',
    'actually provisioned distinct-admin CAS with durable fence and independent multi-host test',
    'independently authenticated recipient idempotency ACK after lost-reply recovery',
)
_PROOF_FIELDS = frozenset(('source_sha', 'log_origin', 'entry_sha256', 'leaf_index',
                           'tree_size', 'root_sha256', 'audit_path',
                           'checkpoint_text_sha256'))
_CAS_FIELDS = frozenset(('backend', 'consistency_mode', 'region_count',
                         'strong_read', 'conditional_write', 'transaction_api',
                         'restore_fence_tested', 'distinct_admin_verified'))
_REQ_FIELDS = frozenset(('repository', 'branch', 'source_sha', 'challenge_sha256',
                         'nonce_sha256', 'audience', 'gates', 'purpose'))

class ProofRejected(ValueError):
    """Invalid candidate, impossible tree or attempted false authorization."""

def require(ok, reason):
    if not ok:
        raise ProofRejected(reason)

def h64(v):
    return type(v) is str and HEX64.fullmatch(v) is not None

def positive(v):
    return type(v) is int and 0 < v <= MAX

def leaf_digest(entry):
    require(type(entry) is bytes and 0 < len(entry) <= MAX_ENTRY, 'entry_bytes')
    return hashlib.sha256(b'\x00' + entry).digest()

def parent_digest(left, right):
    require(type(left) is bytes and type(right) is bytes and
            len(left) == len(right) == 32, 'node_hash_bytes')
    return hashlib.sha256(b'\x01' + left + right).digest()

def audit_inclusion(proof, entry):
    """Real RFC6962 leaf/parent SHA-256 inclusion math; never authenticates root.

    audit_path is a leaf-to-root list of hex sibling node hashes.  Unlike an
    unauthenticated equality label, this function reconstructs the exact root
    using the canonical RFC6962 split at greatest power-of-two less than n.
    A separate authenticated checkpoint and consistency proof are REQUIRED.
    """
    require(type(proof) is dict and proof.keys() == _PROOF_FIELDS, 'proof_schema')
    require(proof['source_sha'] == BASE_SHA and type(proof['source_sha']) is str,
            'source_binding')
    require(type(proof['log_origin']) is str and
            4 <= len(proof['log_origin']) <= 128 and
            proof['log_origin'].isascii(), 'origin_shape')
    require(h64(proof['entry_sha256']) and h64(proof['root_sha256']) and
            h64(proof['checkpoint_text_sha256']), 'digest_shape')
    require(type(proof['leaf_index']) is int and 0 <= proof['leaf_index'] <= MAX and
            positive(proof['tree_size']) and
            proof['leaf_index'] < proof['tree_size'], 'tree_bounds')
    require(type(proof['audit_path']) is list and
            len(proof['audit_path']) <= 63 and
            all(h64(x) for x in proof['audit_path']), 'path_shape')
    original_hash = hashlib.sha256(entry).hexdigest() if type(entry) is bytes else ''
    require(type(entry) is bytes and hmac.compare_digest(
            original_hash, proof['entry_sha256']), 'raw_entry_digest')
    node = leaf_digest(entry)
    siblings = iter(proof['audit_path'])
    def path(index, size):
        if size == 1:
            return node
        k = 1 << (size-1).bit_length()-1
        if index < k:
            left = path(index, k)
            try:
                right = bytes.fromhex(next(siblings))
            except StopIteration as exc:
                raise ProofRejected('short_audit_path') from exc
        else:
            right = path(index-k, size-k)
            try:
                left = bytes.fromhex(next(siblings))
            except StopIteration as exc:
                raise ProofRejected('short_audit_path') from exc
        return parent_digest(left, right)
    # A proof for a 2**63 tree requires at most 63 entries.
    candidate_root = path(proof['leaf_index'], proof['tree_size']).hex()
    require(next(siblings, None) is None, 'extra_audit_nodes')
    require(hmac.compare_digest(candidate_root, proof['root_sha256']),
            'merkle_root_mismatch')
    return {'rfc6962_inclusion_math': 'VALID_UNTRUSTED_ROOT',
            'source_sha': BASE_SHA, 'computed_root_sha256': candidate_root,
            'checkpoint_signature_verified': False,
            'checkpoint_origin_authenticated': False,
            'history_consistency_verified': False,
            'independent_witness_verified': False,
            'subject_signer_authorized': False,
            'external_gates_verified': 0, 'live_allowed': False}

def assess_cas_provider(contract):
    """AWS MRSC is a feasible conditional-write primitive, NOT a verified CAS.

    MREC LWW is not cross-region strongly consistent. MRSC supports
    conditional writes and strongly consistent reads across three regions,
    but not DynamoDB transaction APIs. All caller assertions are untrusted.
    """
    require(type(contract) is dict and contract.keys() == _CAS_FIELDS,
            'cas_contract_schema')
    require(contract['backend'] == 'DYNAMODB' and
            type(contract['backend']) is str, 'cas_backend')
    require(type(contract['consistency_mode']) is str and
            contract['consistency_mode'] in ('MREC', 'MRSC'), 'cas_mode')
    require(type(contract['region_count']) is int and
            1 <= contract['region_count'] <= 30, 'region_count')
    for flag in ('strong_read', 'conditional_write', 'transaction_api',
                 'restore_fence_tested', 'distinct_admin_verified'):
        require(type(contract[flag]) is bool, 'cas_boolean_type')
    # No caller-supplied assertion can authenticate multi-host and admin proof.
    require(contract['restore_fence_tested'] is False and
            contract['distinct_admin_verified'] is False,
            'self_asserted_external_cas_proof')
    if contract['consistency_mode'] == 'MREC':
        reason = 'MREC_LWW_CROSS_REGION_NOT_LINEARIZABLE'
    elif contract['region_count'] != 3:
        reason = 'MRSC_REQUIRES_THREE_REGION_CONFIGURATION'
    elif contract['transaction_api']:
        reason = 'MRSC_DOES_NOT_SUPPORT_TRANSACTION_APIS'
    elif not contract['strong_read'] or not contract['conditional_write']:
        reason = 'MRSC_STRONG_READ_AND_CONDITIONAL_WRITE_REQUIRED'
    else:
        reason = 'MRSC_POTENTIAL_BACKEND_REAL_SERVICE_AND_FENCE_EVIDENCE_MISSING'
    return {'status': 'BLOCKED', 'candidate_reason': reason,
            'documented_candidate': reason.startswith('MRSC_POTENTIAL'),
            'account_or_service_connected': False,
            'cross_host_linearizability_observed': False,
            'external_durable_fencing_verified': False,
            'anti_restore_verified': False,
            'external_gate_verified': False}

def acquisition_contract():
    return tuple({'gate': k, 'acceptance': need, 'status': 'BLOCKED',
                  'external_evidence_present': False}
                 for k, need in zip(GATES, ACCEPTANCE))

def handoff_digest(request):
    """Exact domain-separated procurement scope; never a signed delegation."""
    require(type(request) is dict and request.keys() == _REQ_FIELDS,
            'request_schema')
    require(request['repository'] == REPO and request['branch'] == BRANCH and
            request['source_sha'] == BASE_SHA and type(request['source_sha']) is str,
            'request_scope')
    require(h64(request['challenge_sha256']) and h64(request['nonce_sha256']) and
            request['challenge_sha256'] != request['nonce_sha256'],
            'challenge_nonce')
    require(request['audience'] in ('OOB_OWNER', 'OOB_REVIEWER', 'EXTERNAL_AUDITOR')
            and type(request['audience']) is str and
            request['purpose'] == 'INDEPENDENT_PROOF_ACQUISITION_NO_AUTH',
            'request_audience')
    require(type(request['gates']) is list and request['gates'] == list(GATES),
            'request_gates')
    data = json.dumps(request, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':')).encode('ascii')
    return hashlib.sha256(b'RC699-UNTRUSTED-REQUEST-V1\x00' +
                          len(data).to_bytes(4, 'big') + data).hexdigest()
