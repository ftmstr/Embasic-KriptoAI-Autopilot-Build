"""RC695/TUR52: offline external-proof acquisition boundary, never authentication.

This code models independently sourced *requirements* and quarantines untrusted
observations. It performs no Ed25519 verification, network IO, remote CAS or ACK.
Only an independently operated authority with real trust roots could ever
provide those proofs; no caller-provided value grants release or live access.
"""
import hashlib
import hmac
import re

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
GATES = (
    'owner_oob_key', 'reviewer_oob_key', 'provider_ubuntu_attestation',
    'provider_windows_attestation', 'revocation_trusted_time',
    'external_immutable_checkpoint', 'external_antirollback_cas',
    'remote_provider_ack',
)
PROOF_TYPES = (
    'OOB_ED25519_OWNER_DELEGATION', 'OOB_ED25519_INDEPENDENT_REVIEW',
    'PROVIDER_SIGNED_UBUNTU_COMPLETE_JOB_LOG',
    'PROVIDER_SIGNED_WINDOWS_COMPLETE_JOB_LOG',
    'TRUSTED_TIME_REVOCATION_HISTORY', 'EXTERNALLY_IMMUTABLE_MERKLE_ROOT',
    'LINEARIZABLE_CROSS_HOST_DURABLE_CAS',
    'AUTHENTICATED_IDEMPOTENT_REMOTE_ACK',
)
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
IDENT = re.compile(r'[a-z][a-z0-9_-]{1,62}\Z')
MAX = 2**63-1
FIELDS = frozenset(('gate','proof_type','controller','domain','source_sha',
                    'challenge_sha','payload_sha','signature_sha','run','job',
                    'attempt','epoch','generation','fence','nonce_sha',
                    'checkpoint_root','ack_id','claimed_origin','verified'))

class EvidenceRejected(ValueError):
    """Evidence violates the strictly bounded quarantine contract."""

def require(ok, code):
    if not ok:
        raise EvidenceRejected(code)

def hexof(v, n=64):
    return type(v) is str and (HEX40 if n==40 else HEX64).fullmatch(v) is not None

def num(v, positive=False):
    return type(v) is int and (0 < v <= MAX if positive else 0 <= v <= MAX)

def name(v):
    return type(v) is str and IDENT.fullmatch(v) is not None

def digest(values):
    """Length-prefixed canonical observation digest, NOT a signed attestation."""
    h=hashlib.sha256(b'RC695-UNTRUSTED-ACQUISITION-V1\x00')
    for value in values:
        if value is None:
            b=b'N'
        elif type(value) is int:
            require(num(value), 'digest_integer')
            b=b'I'+str(value).encode('ascii')
        elif type(value) is str:
            require(value.isascii() and len(value)<=256, 'digest_ascii')
            b=b'S'+value.encode('ascii')
        else:
            raise EvidenceRejected('digest_type')
        h.update(len(b).to_bytes(4,'big'))
        h.update(b)
    return h.hexdigest()

def acquisition_requests(source_sha, challenge_sha, epoch, ubuntu, windows):
    """Exact scoped requests for an EXTERNAL verifier, not proof acquisition."""
    require(hexof(source_sha,40), 'source_sha')
    require(hexof(challenge_sha), 'challenge_sha')
    require(num(epoch,True), 'epoch')
    for label, job in (('ubuntu',ubuntu),('windows',windows)):
        require(type(job) is tuple and len(job)==3 and
                all(num(v,True) for v in job), label+'_run_job_attempt')
    require(ubuntu[:2] != windows[:2], 'provider_reused_job')
    out=[]
    for i,(gate,typ) in enumerate(zip(GATES,PROOF_TYPES)):
        run,job,attempt=(ubuntu if i==2 else windows) if i in (2,3) else (0,0,0)
        out.append({'gate':gate,'proof_type':typ,'repository':REPO,
                    'branch':BRANCH,'source_sha':source_sha,
                    'challenge_sha':challenge_sha,'epoch':epoch,
                    'run':run,'job':job,'attempt':attempt,
                    'status':'BLOCKED','external_evidence_acquired':False})
    return tuple(out)

def inspect_observations(requests, observations):
    """Strict evidence-intake lint; even well-formed claims remain QUARANTINED."""
    require(type(requests) is tuple and len(requests)==8,'request_count')
    require(type(observations) is tuple and len(observations)==8,'observation_count')
    domains=set();controllers=set();payloads=set();nonces=set()
    for req,obs in zip(requests,observations):
        require(type(req) is dict and req.get('gate') in GATES and
                req.get('status')=='BLOCKED' and
                req.get('external_evidence_acquired') is False,'untrusted_request')
        require(type(obs) is dict and obs.keys()==FIELDS,'observation_schema')
        require(obs['gate']==req['gate'] and obs['proof_type']==req['proof_type'], 'proof_type')
        require(name(obs['controller']) and name(obs['domain']), 'identity_shape')
        require(obs['controller'] not in controllers and obs['domain'] not in domains,'fake_quorum_sybil')
        controllers.add(obs['controller']);domains.add(obs['domain'])
        require(hexof(obs['source_sha'],40) and obs['source_sha']==req['source_sha'],'source_mismatch')
        require(hexof(obs['challenge_sha']) and
                hmac.compare_digest(obs['challenge_sha'],req['challenge_sha']),'challenge_replay')
        for key in ('payload_sha','signature_sha','nonce_sha','checkpoint_root'):
            require(hexof(obs[key]),'hash_shape_'+key)
        require(obs['payload_sha'] not in payloads,'duplicate_payload')
        require(obs['nonce_sha'] not in nonces,'nonce_replay')
        payloads.add(obs['payload_sha']);nonces.add(obs['nonce_sha'])
        require(all(num(obs[k],k in ('epoch','generation','fence') or (k=='attempt' and req['gate'].startswith('provider_')))
                    for k in ('run','job','attempt','epoch','generation','fence')),'counter_type')
        require(obs['epoch']==req['epoch'],'untrusted_time_claim')
        require((obs['run'],obs['job'],obs['attempt'])==
                (req['run'],req['job'],req['attempt']),'provider_job_scope')
        require(type(obs['ack_id']) is str and len(obs['ack_id'])<=128 and
                obs['ack_id'].isascii(),'ack_id')
        require(obs['claimed_origin']=='SELF_ASSERTED' and type(obs['claimed_origin']) is str,
                'fake_provider_origin')
        require(obs['verified'] is False and type(obs['verified']) is bool,
                'fake_authentication')
        require(obs['ack_id']=='' if req['gate']!='remote_provider_ack' else
                bool(obs['ack_id']), 'ack_scope')
    require(requests[0]['gate']=='owner_oob_key' and
            requests[1]['gate']=='reviewer_oob_key' and
            requests[0]['proof_type']!=requests[1]['proof_type'],'role_separation')
    return {'status':'QUARANTINED_CLAIMS_NOT_EXTERNAL_PROOF',
            'digest':digest([v for obs in observations for v in
                             (obs['gate'],obs['proof_type'],obs['controller'],
                              obs['domain'],obs['source_sha'],obs['challenge_sha'],
                              obs['payload_sha'],obs['signature_sha'],
                              obs['nonce_sha'],obs['checkpoint_root'],obs['ack_id'],
                              obs['generation'],obs['fence'])]),
            'external_verified':0,'blocked':GATES,
            'owner_reviewer_ed25519_authorized':False,
            'provider_signed_full_logs_authenticated':False,
            'trusted_clock_revocation':False,'immutable_merkle_anchor':False,
            'external_cross_host_cas':False,'authenticated_remote_ack':False,
            'final':'SEALED','live':'DISABLED','single_fit':'UNUSED',
            'net20':'NOT_TESTED'}

def compare_fork_views(requests, left, right):
    """Classify potentially conflicting data; cannot elect an authorized winner."""
    inspect_observations(requests,left)
    inspect_observations(requests,right)
    for a,b in zip(left,right):
        if a['source_sha']!=b['source_sha'] or a['challenge_sha']!=b['challenge_sha']:
            return 'SOURCE_OR_CHALLENGE_FORK_BLOCKED'
        if a['checkpoint_root']!=b['checkpoint_root']:
            return 'GOSSIP_SPLIT_VIEW_BLOCKED'
        if a['generation']!=b['generation'] or a['fence']!=b['fence']:
            return 'MULTI_HOST_CAS_FORK_BLOCKED'
        if a['payload_sha']!=b['payload_sha'] or a['signature_sha']!=b['signature_sha']:
            return 'EQUIVOCATING_CLAIMS_BLOCKED'
        if a['nonce_sha']!=b['nonce_sha'] or a['ack_id']!=b['ack_id']:
            return 'REPLAY_OR_LOST_ACK_AMBIGUOUS_BLOCKED'
    return 'EQUAL_CLAIMS_STILL_UNAUTHENTICATED'

def reconcile_remote_ack(pending, alleged_ack):
    """Even a matching ACK claim cannot resolve a lost network response."""
    require(type(pending) is dict and pending.keys()=={'source_sha','nonce_sha','idempotency_sha','fence'},
            'pending_schema')
    require(type(alleged_ack) is dict and alleged_ack.keys()==
            {'source_sha','nonce_sha','idempotency_sha','fence','signature_sha','claimed_origin'},
            'ack_schema')
    require(all(hexof(pending[k]) for k in ('nonce_sha','idempotency_sha')) and
            hexof(pending['source_sha'],40) and num(pending['fence'],True), 'pending_shape')
    require(all(alleged_ack[k]==pending[k] for k in pending),'ack_replay_or_fencing')
    require(hexof(alleged_ack['signature_sha']) and
            alleged_ack['claimed_origin']=='SELF_ASSERTED','ack_forged_origin')
    return 'PENDING_RECONCILIATION_REMOTE_AUTH_NOT_AVAILABLE'

# No live trading, model fit, binary ingress, Ed25519 key, network, or release API.
