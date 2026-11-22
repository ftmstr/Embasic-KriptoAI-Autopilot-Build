"""RC704: replay-bound OOB evidence procurement, not an authorization engine.

Generates a precise independent-verifier handoff for 8 external gates.  It
accepts no untrusted 'verified' promotion, no candidate root as pinned trust,
and absolutely no real keys, tokens or credentials.  Pure stdlib; no I/O.
"""
import hashlib
import hmac
import json
import re

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = 'c5a14e89eea8ff1d41c3914e6b08d8789768b3d5'
GATES = ('owner_oob_ed25519', 'reviewer_oob_ed25519',
         'provider_raw_ubuntu', 'provider_raw_windows',
         'independent_time_revocation', 'witnessed_historical_merkle',
         'separate_admin_durable_mrsc_cas', 'authenticated_recipient_ack')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
RUNS = {
    'ubuntu': (44382073029, 135076777223),
    'windows': (44382073065, 135076777097),
}
REQUEST = frozenset(('repository', 'branch', 'source_sha', 'audience',
                     'challenge_sha256', 'nonce_sha256', 'requested_gates',
                     'ubuntu_run', 'ubuntu_job', 'windows_run', 'windows_job',
                     'operator_claims_verified', 'provider_raw_job_logs_present',
                     'mrsc_service_provisioned', 'remote_ack_received'))
RECEIPT = frozenset(('request_digest_sha256', 'role', 'subject_sha',
                     'response_nonce_sha256', 'issuer_name',
                     'issuer_admin_fingerprint_sha256', 'receipt_sha256',
                     'claimed_provider_verified', 'claimed_role_authorized'))

class ExternalProofBlocked(ValueError):
    """Malformed acquisition request, forgery attempt or replay."""

def demand(ok, reason):
    if not ok:
        raise ExternalProofBlocked(reason)

def sha64(x):
    return type(x) is str and HEX64.fullmatch(x) is not None

def stable_digest(kind, object_value):
    """Domain-separated SHA256 of fully canonical untrusted metadata."""
    data = json.dumps(object_value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')
    demand(len(data) <= 16_384, 'canonical_data_limit')
    return hashlib.sha256(b'RC704-OOB-' + kind.encode('ascii') + b'\x00' +
                          len(data).to_bytes(4, 'big') + data).hexdigest()

def canonical_request(req):
    """Bind procurement request to EXACT existing public branch, runs and nonce.

    This digest only scopes a future OOB verifier task; it is NOT signed or
    independently authenticated. No expected proof is automatically present.
    """
    demand(type(req) is dict and req.keys() == REQUEST, 'request_schema')
    demand(req['repository'] == REPO and req['branch'] == BRANCH and
           req['source_sha'] == BASE_SHA, 'exact_source_scope')
    demand(req['audience'] == 'INDEPENDENT_EXTERNAL_VERIFIER', 'oob_audience')
    demand(sha64(req['challenge_sha256']) and sha64(req['nonce_sha256']) and
           not hmac.compare_digest(req['challenge_sha256'], req['nonce_sha256']),
           'challenge_nonce_replay')
    demand(type(req['requested_gates']) is list and
           req['requested_gates'] == list(GATES), 'gate_order_or_scope')
    for field, value in [('ubuntu_run', RUNS['ubuntu'][0]),
                         ('ubuntu_job', RUNS['ubuntu'][1]),
                         ('windows_run', RUNS['windows'][0]),
                         ('windows_job', RUNS['windows'][1])]:
        demand(type(req[field]) is int and req[field] == value, 'run_job_scope')
    for field in ('operator_claims_verified', 'provider_raw_job_logs_present',
                  'mrsc_service_provisioned', 'remote_ack_received'):
        demand(req[field] is False, 'untrusted_authority_promotion')
    return stable_digest('REQUEST-V1', req)

def _proof_plan(req):
    """Exact source, subject and independent external-verifier prerequisites."""
    sha = req['source_sha']
    return (
        {'gate': GATES[0], 'subject': 'OWNER_OOB_ROLE_DELEGATION',
         'accept': 'OOB PIN, Ed25519 scope-bound signature, separate custody and revocation',
         'origin': 'INDEPENDENT_OWNER_AUTHORITY'},
        {'gate': GATES[1], 'subject': 'REVIEWER_INDEPENDENT_ROLE_DELEGATION',
         'accept': 'Different-admin OOB PIN, signed review, demonstrable distinct custody',
         'origin': 'INDEPENDENT_REVIEWER_AUTHORITY'},
        {'gate': GATES[2], 'subject': f'{REPO}:{sha}:actions/job/{req["ubuntu_job"]}',
         'accept': 'Provider-origin signature over EXACT ORIGINAL RAW complete Ubuntu job-log bytes',
         'origin': 'GITHUB_PROVIDER_SIGNATURE_REQUIRED_NOT_OBTAINED'},
        {'gate': GATES[3], 'subject': f'{REPO}:{sha}:actions/job/{req["windows_job"]}',
         'accept': 'Provider-origin signature over EXACT ORIGINAL RAW complete Windows job-log bytes',
         'origin': 'GITHUB_PROVIDER_SIGNATURE_REQUIRED_NOT_OBTAINED'},
        {'gate': GATES[4], 'subject': 'TRUSTED_TIME_REVOCATION_HISTORY',
         'accept': 'OOB authenticated non-rewindable time/issuer/revocation/rotation chronology',
         'origin': 'EXTERNAL_TIME_AND_KEY_CUSTODIAN'},
        {'gate': GATES[5], 'subject': 'REKOR_HISTORICAL_AND_LATEST_C2SP_CHECKPOINT',
         'accept': 'Vetted Ed25519 verifier with OOB-pinned log/witness roots, authenticated prior checkpoint, RFC6962 inclusion and consistency',
         'origin': 'EXTERNAL_LOG_PLUS_DIFFERENT_ADMIN_WITNESS'},
        {'gate': GATES[6], 'subject': 'AWS_THREE_REGION_MRSC_ANTIRESTORE_FENCING',
         'accept': 'Provisioned 3-region MRSC, separate admin IAM, 2+ competing hosts, durable conditional fence and physical restore drill',
         'origin': 'EXTERNALLY_OPERATED_AWS_ACCOUNT_AND_AUDITOR'},
        {'gate': GATES[7], 'subject': 'REMOTE_RECIPIENT_IDEMPOTENCY_ACK',
         'accept': 'Independently authenticated recipient ACK for same request ID, real remote consistency and lost-response reconciliation',
         'origin': 'EXTERNALLY_AUTHENTICATED_RECIPIENT'},
    )

def handoff(req):
    """Deterministic acquisition manifest (no invocation, authority or network)."""
    digest = canonical_request(req)
    plan = _proof_plan(req)
    return {'status': 'EXTERNAL_VERIFIER_HANDOFF_UNEXECUTED',
            'source_sha': BASE_SHA, 'request_digest_sha256': digest,
            'requested_evidence': tuple({**x, 'status': 'BLOCKED',
                                         'independently_verified': False}
                                        for x in plan),
            'github_readable_log_is_raw_provider_attestation': False,
            'github_artifact_attestation_is_full_raw_log_proof': False,
            'rekor_candidate_key_equals_oob_trust_root': False,
            'mrsc_offline_plan_is_live_cas': False,
            'recipient_ack_authenticated': False,
            'external_verified_count': 0, 'external_total': 8,
            'auth': 'NO-GO', 'live': 'DISABLED', 'final': 'SEALED',
            'single_fit': 'UNUSED', 'net20': 'NOT_TESTED'}

def quarantine_claimed_receipt(req, candidate):
    """Digest-link a CALLER CLAIM for *manual* independent acquisition only.

    Even a matching SHA-256, different-looking administrator fingerprint and
    provider-signed boolean cannot prove the origin, contents, custody, key
    authorization or reality of a remote service. Never promotes any gate.
    """
    request_hash = canonical_request(req)
    demand(type(candidate) is dict and candidate.keys() == RECEIPT,
           'untrusted_receipt_schema')
    demand(candidate['role'] in GATES and type(candidate['role']) is str,
           'unrecognized_evidence_role')
    demand(candidate['subject_sha'] == BASE_SHA and
           type(candidate['subject_sha']) is str, 'receipt_subject_scope')
    demand(sha64(candidate['request_digest_sha256']) and
           hmac.compare_digest(candidate['request_digest_sha256'], request_hash),
           'cross_request_or_replay')
    demand(sha64(candidate['response_nonce_sha256']) and
           not hmac.compare_digest(candidate['response_nonce_sha256'],
                                   req['nonce_sha256']) and
           not hmac.compare_digest(candidate['response_nonce_sha256'],
                                   req['challenge_sha256']), 'response_nonce_replay')
    demand(type(candidate['issuer_name']) is str and
           3 <= len(candidate['issuer_name']) <= 120 and
           candidate['issuer_name'].isascii(), 'issuer_label_shape')
    demand(sha64(candidate['issuer_admin_fingerprint_sha256']) and
           sha64(candidate['receipt_sha256']), 'claimed_proof_digest_shape')
    # A caller's self-asserted verified=true is not a reputable verifier output.
    demand(candidate['claimed_provider_verified'] is False and
           candidate['claimed_role_authorized'] is False,
           'caller_asserted_trust_is_forbidden')
    return {'classification': 'UNTRUSTED_PROOF_CLAIM_QUARANTINED',
            'role': candidate['role'], 'request_digest_sha256': request_hash,
            'claimed_evidence_digest_sha256': candidate['receipt_sha256'],
            'quarantine_record_sha256': stable_digest('QUARANTINE-V1', candidate),
            'independent_provider_signature_verified': False,
            'oob_authority_verified': False,
            'different_administrator_verified': False,
            'external_cas_verified': False,
            'recipient_ack_authenticated': False,
            'external_verified_count': 0,
            'auth': 'NO-GO', 'live': 'DISABLED'}
