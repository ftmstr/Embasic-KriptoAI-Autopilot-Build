"""RC705: deny proof-type downgrades across GitHub, Rekor, and AWS MRSC.

Only classifies *caller-reported* bytes and metadata. Product documentation
is not operational authorization. No IO, network, crypto key import, actual
AWS operations, experimental Ed25519 authorization, trading, or model fit.
"""
import hashlib
import hmac
import json
import re

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = 'b01a0544f828ec149178bf2b1eec62b573ae64c8'
GATES = ('owner_oob_ed25519', 'reviewer_oob_ed25519',
         'provider_raw_ubuntu', 'provider_raw_windows',
         'independent_time_revocation', 'witnessed_historical_merkle',
         'separate_admin_durable_mrsc_cas', 'authenticated_recipient_ack')
RUN_JOBS = {'provider_raw_ubuntu': (44384407457, 135084924784),
            'provider_raw_windows': (44384407494, 135084924161)}
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
CLAIM_KEYS = frozenset(('repository', 'branch', 'source_sha', 'gate',
                        'material_type', 'material_sha256', 'challenge_sha256',
                        'nonce_sha256', 'subject_run', 'subject_job',
                        'claim_authorized', 'claim_provider_signed_raw_log',
                        'claim_independent_custody', 'claim_origin_verified'))
RESTORE_EXPECTED = frozenset(('source_sha', 'table_arn', 'epoch', 'fence',
                              'generation', 'root_sha256', 'request_id_sha256'))
RESTORE_OBSERVED = frozenset(('source_sha', 'table_arn', 'epoch', 'fence',
                              'generation', 'root_sha256', 'request_id_sha256',
                              'provider_authenticated', 'independent_restore_attested'))

# These are *evidence types* obtainable as candidate material, not trust.
PROOF_TYPES = {
    GATES[0]: ('OWNER_OOB_KEY_CANDIDATE',),
    GATES[1]: ('REVIEWER_OOB_KEY_CANDIDATE',),
    GATES[2]: ('GITHUB_JOB_LOG_PLAINTEXT', 'GITHUB_ARTIFACT_SUBJECT_ATTESTATION',
               'PROVIDER_RAW_LOG_SIGNATURE_CANDIDATE'),
    GATES[3]: ('GITHUB_JOB_LOG_PLAINTEXT', 'GITHUB_ARTIFACT_SUBJECT_ATTESTATION',
               'PROVIDER_RAW_LOG_SIGNATURE_CANDIDATE'),
    GATES[4]: ('TRUSTED_TIME_AND_REVOCATION_CANDIDATE',),
    GATES[5]: ('REKOR_LOG_SIGNED_CHECKPOINT_CANDIDATE',
               'REKOR_WITNESSED_CHECKPOINT_CANDIDATE'),
    GATES[6]: ('AWS_MRSC_DESCRIBE_TABLE_CANDIDATE',
               'AWS_MRSC_CAS_RESULT_CANDIDATE'),
    GATES[7]: ('RECIPIENT_IDEMPOTENT_ACK_CANDIDATE',),
}
PROOF_CLASSIFICATION = {
    'OWNER_OOB_KEY_CANDIDATE': 'CANDIDATE_NOT_OOB_AUTHENTICATED',
    'REVIEWER_OOB_KEY_CANDIDATE': 'CANDIDATE_NOT_SEPARATE_ADMIN_VERIFIED',
    'GITHUB_JOB_LOG_PLAINTEXT': 'READABLE_LOG_NOT_PROVIDER_SIGNED_RAW',
    'GITHUB_ARTIFACT_SUBJECT_ATTESTATION': 'ARTIFACT_SUBJECT_NOT_PROVIDER_SIGNED_RAW_LOG',
    'PROVIDER_RAW_LOG_SIGNATURE_CANDIDATE': 'SIGNATURE_CANDIDATE_NO_INDEPENDENT_ISSUER_PIN',
    'TRUSTED_TIME_AND_REVOCATION_CANDIDATE': 'UNAUTHENTICATED_CLOCK_AND_REVOCATION',
    'REKOR_LOG_SIGNED_CHECKPOINT_CANDIDATE': 'NO_INDEPENDENT_WITNESS_OR_HISTORICAL_ROOT',
    'REKOR_WITNESSED_CHECKPOINT_CANDIDATE': 'UNVERIFIED_WITNESS_INDEPENDENCE_AND_HISTORY',
    'AWS_MRSC_DESCRIBE_TABLE_CANDIDATE': 'TABLE_METADATA_NOT_REMOTE_ANTIRESTORE_CAS',
    'AWS_MRSC_CAS_RESULT_CANDIDATE': 'REMOTE_RESULT_NOT_INDEPENDENTLY_AUTHENTICATED',
    'RECIPIENT_IDEMPOTENT_ACK_CANDIDATE': 'ACK_NOT_INDEPENDENTLY_AUTHENTICATED',
}
SOURCE_PAGES = {
    'github_job_logs': 'https://docs.github.com/en/rest/actions/workflow-jobs',
    'github_artifact_attestation': 'https://github.com/actions/attest',
    'rekor_clients': 'https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md',
    'rekor_verify': 'https://pkg.go.dev/github.com/sigstore/rekor-tiles/v2/pkg/verify',
    'aws_mrsc': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-global-table-design.html',
    'aws_pitr': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/pointintimerecovery_restores.html',
}

class ProofTypeBlocked(ValueError):
    """Invalid or misleading candidate metadata; no external approval."""

def require(test, reason):
    if not test:
        raise ProofTypeBlocked(reason)

def is_hex(value):
    return type(value) is str and HEX64.fullmatch(value) is not None

def is_counter(value):
    return type(value) is int and 0 <= value < (1 << 63)

def canonical_digest(label, payload):
    encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    require(len(encoded) <= 16384, 'candidate_metadata_too_large')
    return hashlib.sha256(b'KRIPTOAI-RC705-PROOF-TYPE-' + label.encode('ascii') +
                          b'\x00' + len(encoded).to_bytes(4, 'big') + encoded).hexdigest()

def procurement_matrix():
    """Static documented provider capabilities; NEVER provider evidence itself."""
    descriptions = (
        'Independent authorized owner key and OOB delegation required',
        'Separate legal/admin reviewer signer and OOB delegation required',
        'GitHub job logs endpoint documents plaintext redirect, NOT provider signed RAW log',
        'GitHub job logs endpoint documents plaintext redirect, NOT provider signed RAW log',
        'Independent trusted time and revocation chronology missing',
        'Real log/witness signatures, OOB pins, prior root and RFC6962 consistency missing',
        '3-region MRSC separate admin, durable CAS, multi-host race, restore drill missing',
        'Independent recipient authenticated idempotent remote ACK missing',
    )
    return tuple({'gate': gate, 'status': 'BLOCKED',
                  'required_external_acquisition': descriptions[i],
                  'provider_observation_is_authority': False}
                 for i, gate in enumerate(GATES))

def classify_untrusted_candidate(candidate):
    """Decide why a candidate DOES NOT meet gate admission requirements.

    A real provider-attested artifact could be externally verified in a
    separate trusted protocol, but no caller field can assert that here.
    """
    require(type(candidate) is dict and candidate.keys() == CLAIM_KEYS,
            'candidate_schema')
    require(candidate['repository'] == REPO and candidate['branch'] == BRANCH and
            candidate['source_sha'] == BASE_SHA, 'exact_repo_branch_source')
    gate = candidate['gate']
    require(type(gate) is str and gate in PROOF_TYPES, 'unknown_gate')
    typ = candidate['material_type']
    require(type(typ) is str and typ in PROOF_TYPES[gate], 'evidence_type_downgrade_or_splice')
    for key in ('material_sha256', 'challenge_sha256', 'nonce_sha256'):
        require(is_hex(candidate[key]), 'candidate_digest_shape')
    require(not hmac.compare_digest(candidate['challenge_sha256'], candidate['nonce_sha256']),
            'nonce_reuse')
    for key in ('claim_authorized', 'claim_provider_signed_raw_log',
                'claim_independent_custody', 'claim_origin_verified'):
        require(candidate[key] is False, 'self_asserted_external_authority')
    if gate in RUN_JOBS:
        run, job = RUN_JOBS[gate]
        require(type(candidate['subject_run']) is int and
                type(candidate['subject_job']) is int and
                candidate['subject_run'] == run and candidate['subject_job'] == job,
                'wrong_provider_run_job_scope')
    else:
        require(candidate['subject_run'] is None and candidate['subject_job'] is None,
                'job_scope_contamination')
    return {'classification': PROOF_CLASSIFICATION[typ],
            'gate': gate, 'material_type': typ,
            'quarantine_sha256': canonical_digest('CANDIDATE', candidate),
            'material_digest_is_proof': False,
            'raw_log_provider_signature_verified': False,
            'independent_oob_keys_verified': False,
            'independent_witness_and_historical_root_verified': False,
            'remote_mrsc_and_restore_fence_verified': False,
            'remote_ack_authenticated': False,
            'external_gates_verified': 0, 'auth': 'NO-GO', 'live': 'DISABLED'}

def classify_reported_restore(expected, observed):
    """Reason about hypothetical AWS PITR/table migration, NEVER trust an ARN.

    DynamoDB PITR restores to a NEW table; a historical fence must not be
    silently transferred to that table without a different-admin OOB rebase.
    A caller-supplied result is never authenticated by this classifier.
    """
    require(type(expected) is dict and expected.keys() == RESTORE_EXPECTED and
            type(observed) is dict and observed.keys() == RESTORE_OBSERVED,
            'restore_schema')
    require(expected['source_sha'] == BASE_SHA and observed['source_sha'] == BASE_SHA,
            'restore_source_scope')
    for obj in (expected, observed):
        require(type(obj['table_arn']) is str and
                obj['table_arn'].startswith('arn:aws:dynamodb:') and
                len(obj['table_arn']) <= 256 and '\n' not in obj['table_arn'],
                'table_identity_shape')
        require(all(is_counter(obj[k]) for k in ('epoch','fence','generation')),
                'fence_counter_shape')
        require(is_hex(obj['root_sha256']) and is_hex(obj['request_id_sha256']),
                'restore_proof_digest_shape')
    require(observed['provider_authenticated'] is False and
            observed['independent_restore_attested'] is False,
            'self_asserted_aws_provider_auth')
    if observed['table_arn'] != expected['table_arn']:
        status = 'NEW_RESTORED_TABLE_REQUIRES_DIFFERENT_ADMIN_REENROLLMENT'
    elif (observed['epoch'] < expected['epoch'] or
          observed['fence'] < expected['fence'] or
          observed['generation'] < expected['generation']):
        status = 'REPORTED_ROLLBACK_OR_OLD_SNAPSHOT_FENCE'
    elif any(observed[k] != expected[k] for k in ('epoch', 'fence', 'generation',
                                                  'root_sha256', 'request_id_sha256')):
        status = 'UNOBSERVED_INTERVENING_CHANGE_OR_REPLAY'
    else:
        status = 'MATCHING_CALLER_REPORTED_STATE_NOT_AWS_PROOF'
    return {'classification': status,
            'table_identity_custody_verified': False,
            'independent_restore_fence_authenticated': False,
            'multi_host_conditional_cas_observed': False,
            'remote_ack_authenticated': False,
            'external_gates_verified': 0, 'auth': 'NO-GO', 'live': 'DISABLED',
            'single_fit': 'UNUSED', 'net20': 'NOT_TESTED'}
