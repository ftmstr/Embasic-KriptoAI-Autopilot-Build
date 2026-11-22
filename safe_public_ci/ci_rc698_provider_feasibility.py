"""RC698/TUR55: independently sourced service feasibility, NEVER authentication.

All prospective provider routes, 'signed' flags and authority labels are
caller-controlled until independently obtained/verified from trusted roots.
Never promote them. No file IO, network, key generation, remote CAS or trading.
"""
import hashlib
import hmac
import json
import re

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = '7939a9a81932a8307e9155edfa44cb772e1062a2'
GATES = (
    'owner_oob_key', 'reviewer_oob_key', 'provider_ubuntu_attestation',
    'provider_windows_attestation', 'revocation_trusted_time',
    'external_immutable_checkpoint', 'external_antirollback_cas',
    'remote_provider_ack',
)
ROUTES = (
    'EXTERNAL_OOB_KEY_CEREMONY', 'EXTERNAL_OOB_KEY_CEREMONY',
    'GITHUB_RAW_JOB_LOG_NOT_SIGNED', 'GITHUB_RAW_JOB_LOG_NOT_SIGNED',
    'INDEPENDENT_SIGNED_REVOCATION_TIME_REQUIRED',
    'SIGSTORE_REKOR_NOT_ANCHOR_FOR_THIS_BUILD',
    'DYNAMODB_SINGLE_REGION_PROVISION_NOT_DONE',
    'REMOTE_RECIPIENT_ACK_NOT_CONNECTED',
)
REQUIRED = (
    'independent owner Ed25519 public key + authorized scope and custody record',
    'different administrator reviewer Ed25519 key + signed review of exact build',
    'provider-signed original raw Ubuntu full log+run/job/attempt/workflow/source',
    'provider-signed original raw Windows full log+run/job/attempt/workflow/source',
    'independently signed revocation/rotation history and independently verified time',
    'externally witnessed signed Merkle checkpoint, inclusion and consistency',
    'independent durable linearizable multi-host fencing CAS and anti-restore test',
    'independently authenticated recipient ACK and idempotency reconciliation',
)
SOURCES = (
    'https://docs.github.com/en/rest/actions/workflow-jobs',
    'https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations',
    'https://docs.sigstore.dev/logging/overview/',
    'https://github.com/sigstore/architecture-docs/blob/main/rekor-spec.md',
    'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html',
)
BAD_ROUTES = {
    'GITHUB_JOB_LOG_DOWNLOAD': 'GITHUB_READABLE_LOG_NOT_SIGNED_PROVIDER_ATTESTATION',
    'GITHUB_ARTIFACT_ATTESTATION': 'ARTIFACT_SUBJECT_NOT_SIGNED_RAW_FULL_JOB_LOG',
    'SIGSTORE_REKOR_ENTRY': 'TRANSPARENCY_ENTRY_NOT_SUBJECT_SIGNER_AUTHORITY',
    'REKOR_SIGNED_ENTRY_TIMESTAMP': 'SET_PROMISE_NOT_INCLUSION_OR_GOSSIP_PROOF',
    'DYNAMODB_MREC_GLOBAL_TABLES': 'MREC_LAST_WRITER_WINS_NOT_CROSS_REGION_LINEARIZABLE',
    'LOCAL_SQLITE': 'LOCAL_SNAPSHOT_RESTORE_NOT_INDEPENDENT_CAS',
    'RFC3161_UNPINNED_TIME': 'TIMESTAMP_SHAPE_NOT_TRUSTED_CLOCK',
    'SELF_ASSERTED_SIGNER': 'LABEL_NOT_INDEPENDENT_ED25519_KEY_PROVENANCE',
    'FAKE_RECIPIENT_ACK': 'LOCAL_ACK_NOT_AUTHENTICATED_RECIPIENT',
}
ACCEPTABLE_PILOT = {
    'owner_oob_key': 'OOB_SIGNER_SETUP_NOT_ACQUIRED',
    'reviewer_oob_key': 'OOB_REVIEWER_SETUP_NOT_ACQUIRED',
    'provider_ubuntu_attestation': 'RAW_LOG_SIGNER_NOT_IDENTIFIED',
    'provider_windows_attestation': 'RAW_LOG_SIGNER_NOT_IDENTIFIED',
    'revocation_trusted_time': 'TRUSTED_REVOCATION_TSA_NOT_ACQUIRED',
    'external_immutable_checkpoint': 'WITNESSED_REKOR_CHECKPOINT_NOT_ACQUIRED',
    'external_antirollback_cas': 'SINGLE_REGION_CAS_OPERATOR_NOT_PROVISIONED',
    'remote_provider_ack': 'RECIPIENT_API_NOT_CONNECTED',
}
_PROPOSAL = frozenset(('gate', 'route', 'controller', 'failure_domain',
                       'source_sha', 'request_sha256', 'claimed_verified',
                       'origin', 'external_proof_sha256'))
_REQUEST = frozenset(('repository', 'branch', 'source_sha', 'challenge_sha256',
                      'nonce_sha256', 'audience', 'requested_gates',
                      'max_replies', 'mode'))
_HEX40 = re.compile(r'[0-9a-f]{40}\Z')
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_IDENT = re.compile(r'[a-z][a-z0-9_-]{1,62}\Z')

class CapabilityRejected(ValueError):
    """Invalid external-proof claim or attempted trust promotion."""

def require(condition, reason):
    if not condition:
        raise CapabilityRejected(reason)

def h40(value):
    return type(value) is str and _HEX40.fullmatch(value) is not None

def h64(value):
    return type(value) is str and _HEX64.fullmatch(value) is not None

def ident(value):
    return type(value) is str and _IDENT.fullmatch(value) is not None

def acquisition_matrix():
    """Service research/requirements are NOT provenance of any current build."""
    return tuple({'gate':gate, 'suggested_route':route,
                  'requires':required, 'actual_external_verified':False,
                  'status':'BLOCKED'}
                 for gate,route,required in zip(GATES, ROUTES, REQUIRED))

def make_challenge(challenge_sha256, nonce_sha256, audience):
    require(h64(challenge_sha256) and h64(nonce_sha256), 'challenge_nonce_shape')
    require(challenge_sha256 != nonce_sha256, 'challenge_nonce_replay')
    require(type(audience) is str and audience in
            ('OWNER', 'INDEPENDENT_REVIEWER', 'EXTERNAL_SECURITY_AUDITOR'), 'audience')
    return {'repository':REPO, 'branch':BRANCH, 'source_sha':BASE_SHA,
            'challenge_sha256':challenge_sha256, 'nonce_sha256':nonce_sha256,
            'audience':audience, 'requested_gates':list(GATES),
            'max_replies':8, 'mode':'REQUEST_ONLY_NEVER_AUTHENTICATES'}

def challenge_digest(request):
    require(type(request) is dict and request.keys()==_REQUEST,'request_schema')
    require(request['repository']==REPO and request['branch']==BRANCH and
            request['source_sha']==BASE_SHA and h40(request['source_sha']), 'request_scope')
    require(h64(request['challenge_sha256']) and h64(request['nonce_sha256']) and
            request['challenge_sha256'] != request['nonce_sha256'], 'challenge_nonce_replay')
    require(request['audience'] in ('OWNER','INDEPENDENT_REVIEWER','EXTERNAL_SECURITY_AUDITOR'),
            'audience')
    require(type(request['requested_gates']) is list and
            request['requested_gates']==list(GATES) and
            type(request['max_replies']) is int and request['max_replies']==8 and
            request['mode']=='REQUEST_ONLY_NEVER_AUTHENTICATES','request_cardinality')
    b=json.dumps(request,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    return hashlib.sha256(b'KRYPTOAI-RC698-EXTERNAL-REQUEST-ONLY\0'+len(b).to_bytes(4,'big')+b).hexdigest()

def evaluate_routes(request, proposals):
    """Exactly eight candidate handoffs; no caller can assert independent proof."""
    digest=challenge_digest(request)
    require(type(proposals) is list and len(proposals)==8,'proposal_cardinality')
    seen_controls=set();seen_domains=set();seen_artifacts=set();evaluated=[]
    for i,item in enumerate(proposals):
        require(type(item) is dict and item.keys()==_PROPOSAL, 'proposal_schema')
        require(item['gate']==GATES[i] and type(item['gate']) is str,'gate_order')
        require(ident(item['controller']) and ident(item['failure_domain']),'control_identifier')
        require(item['controller'] not in seen_controls and
                item['failure_domain'] not in seen_domains,'fake_quorum_domain')
        seen_controls.add(item['controller']);seen_domains.add(item['failure_domain'])
        require(item['source_sha']==BASE_SHA and h40(item['source_sha']),'source_replay')
        require(h64(item['request_sha256']) and
                hmac.compare_digest(item['request_sha256'],digest),'challenge_replay')
        require(item['claimed_verified'] is False and type(item['claimed_verified']) is bool,
                'untrusted_auth_promotion')
        require(item['origin']=='SELF_ASSERTED' and type(item['origin']) is str,
                'fake_origin')
        require(item['external_proof_sha256'] is None,'unverified_proof_injection')
        route=item['route']
        require(type(route) is str and (route in BAD_ROUTES or
                route == ACCEPTABLE_PILOT[item['gate']]),'unknown_route')
        reason=BAD_ROUTES.get(route,'INDEPENDENT_EXTERNAL_SERVICE_NOT_ACQUIRED')
        evaluated.append({'gate':GATES[i], 'route':route,
                          'status':'BLOCKED', 'reason':reason,
                          'real_external_verified':False})
    return {'status':'PROVIDER_FEASIBILITY_ONLY_NO_AUTHENTICATION',
            'request_sha256':digest, 'candidate_count':len(proposals),
            'real_external_gate_count':0,'blocked_gates':tuple(evaluated),
            'owner_reviewer_independent':False,'raw_logs_provider_signed':False,
            'revocation_clock_authenticated':False,'merkle_checkpoint_witnessed':False,
            'multi_host_cas_linearizable':False,'remote_ack_authenticated':False,
            'final':'SEALED','live':'DISABLED','single_fit':'UNUSED',
            'net20':'NOT_TESTED'}

# All paths are read-only contracts; no provider account, signature authority,
# durable remote CAS, private key or signed recipient ACK is connected here.
