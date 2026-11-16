"""RC697/TUR54: verify observed hosted CI *data*, never provider authority.

The manifest is a decoded connector/API observation. It is NOT a signed
GitHub-origin job log, owner/reviewer delegation, independently anchored ledger,
remote CAS, trusted time, remote ACK, or an authorization to trade.
All input is untrusted, all proof gates stay CLOSED; stdlib-only, no IO/network.
"""
import hashlib
import hmac
import json
import re

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = '1b7cd5a7bd4251e702e1d93d6b2ddf034d84bd8e'
MAX_LOG_BYTES = 2 * 1024 * 1024
_HEX40 = re.compile(r'[0-9a-f]{40}\Z')
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_POSITIVE_MAX = 2**63-1
GATES = (
    'owner_oob_key', 'reviewer_oob_key', 'provider_ubuntu_attestation',
    'provider_windows_attestation', 'revocation_trusted_time',
    'external_immutable_checkpoint', 'external_antirollback_cas',
    'remote_provider_ack',
)
OBLIGATIONS = (
    'Owner-signed scoped delegation plus OOB-pinned Ed25519 key and custody policy',
    'Independent reviewer-signed approval and different OOB trust-root administrator',
    'Provider-origin signature over exact Ubuntu run/job/attempt/source/workflow/full RAW job log',
    'Provider-origin signature over exact Windows run/job/attempt/source/workflow/full RAW job log',
    'External trusted time and independently signed append-only revocation history',
    'Externally witnessed immutable signed Merkle root with inclusion/consistency proofs',
    'Independently operated multi-host durable linearizable anti-rollback CAS and fencing',
    'Recipient-authenticated exact idempotency ACK and read-after-lost-response reconciliation',
)
_PLATFORMS = ('ubuntu', 'windows')
_PINNED = {
    'ubuntu': (43833630743, 133184729775, 1,
               '140264aaf07f3130a23606254f545b4ff77b1971',
               '4b5e6a8bfb8ba430709c53d4c473d8dbe99a33a62f7e95eff32b8e12bec4355a',
               502036, 502118),
    'windows': (43833630781, 133184729913, 1,
                '254ac4f4ea821a05ee4730c3828d4de1b96a0e72',
                '3955877ecedfb8f0deb4cb741cf263de9cfc154187e8b3abe7ad3e50f35ffed7',
                513496, 513498),
}

_OBSERVATION = frozenset(('platform','run','job','attempt','workflow_blob_sha',
                          'run_status','job_status','step_success','test_pass',
                          'test_rc696_pass','decoded_log_code_units',
                          'decoded_log_utf8_bytes','decoded_log_utf8_sha256',
                          'artifact_count','provider_signature_verified','evidence_kind'))
_MANIFEST = frozenset(('repository','branch','source_sha','tool_path',
                       'observation_mode','observations','external_gate_count',
                       'trusted_at','release_allowed','live_allowed'))
_REQUEST = frozenset(('repository','branch','source_sha','platform','run','job',
                      'attempt','workflow_blob_sha','decoded_log_utf8_sha256',
                      'challenge_sha256','nonce_sha256','audience','purpose'))
_CANDIDATE = frozenset(('gate','request_sha256','controller','domain','key_fingerprint_sha256',
                        'claimed_signature_sha256','claimed_origin','verified',
                        'trusted_time','remote_cas','remote_ack','immutable_root'))

class EvidenceRejected(ValueError):
    """A scoped observation/claim was invalid or attempted trust promotion."""

def need(ok, reason):
    if not ok:
        raise EvidenceRejected(reason)

def h40(v):
    return type(v) is str and _HEX40.fullmatch(v) is not None

def h64(v):
    return type(v) is str and _HEX64.fullmatch(v) is not None

def positive(v):
    return type(v) is int and 0 < v <= _POSITIVE_MAX

def observation_plan():
    """Operationally actionable missing proof acquisition matrix, 0/8 authenticated."""
    return tuple({'gate':g,'required_external':req,'status':'BLOCKED',
                  'verified':False,'authority_from_local_git_or_ci':False}
                 for g,req in zip(GATES,OBLIGATIONS))

def inspect_snapshot(manifest, decoded_logs=None):
    """Authenticate NOTHING. Optionally compare re-encoded decoded UTF8 log data.

    The digest is of re-encoding connector-decoded Unicode text; it is not
    necessarily the original GitHub download response's byte hash and cannot
    be substituted for an origin-signed complete raw transcript.
    """
    need(type(manifest) is dict and manifest.keys()==_MANIFEST,'manifest_schema')
    need(manifest['repository']==REPO and type(manifest['repository']) is str and
         manifest['branch']==BRANCH and type(manifest['branch']) is str,'repository_scope')
    need(manifest['source_sha']==BASE_SHA and h40(manifest['source_sha']),'source_scope')
    need(manifest['tool_path']=='GITHUB_API_READ_ONLY' and
         manifest['observation_mode']=='DECODED_UTF8_REENCODE_UNAUTHENTICATED', 'observation_origin')
    need(manifest['external_gate_count']==0 and type(manifest['external_gate_count']) is int and
         manifest['trusted_at'] is None and manifest['release_allowed'] is False and
         manifest['live_allowed'] is False,'forged_trust_promotion')
    items=manifest['observations']
    need(type(items) is list and len(items)==2,'observation_count')
    need([o.get('platform') if type(o) is dict else None for o in items]==list(_PLATFORMS),'platform_pair')
    digests=set();jobs=set()
    for o in items:
        need(type(o) is dict and o.keys()==_OBSERVATION,'observation_schema')
        need(positive(o['run']) and positive(o['job']) and positive(o['attempt']), 'provider_ids')
        need((o['run'],o['job'],o['attempt']) not in jobs,'duplicate_job')
        jobs.add((o['run'],o['job'],o['attempt']))
        need(h40(o['workflow_blob_sha']) and h64(o['decoded_log_utf8_sha256']),'observation_digests')
        need(o['decoded_log_utf8_sha256'] not in digests,'duplicate_log')
        digests.add(o['decoded_log_utf8_sha256'])
        need(o['run_status']=='completed/success' and o['job_status']=='completed/success' and
             o['step_success']==9 and type(o['step_success']) is int and
             o['test_pass']==3004 and type(o['test_pass']) is int and
             o['test_rc696_pass']==41 and type(o['test_rc696_pass']) is int, 'hosted_ci_observation')
        need(positive(o['decoded_log_code_units']) and positive(o['decoded_log_utf8_bytes']) and
             o['decoded_log_utf8_bytes']<=MAX_LOG_BYTES,'observed_log_size')
        need((o['run'],o['job'],o['attempt'],o['workflow_blob_sha'],
              o['decoded_log_utf8_sha256'],o['decoded_log_code_units'],
              o['decoded_log_utf8_bytes'])==_PINNED[o['platform']], 'historical_observation_pin')
        need(o['artifact_count']==0 and type(o['artifact_count']) is int and
             o['provider_signature_verified'] is False and
             o['evidence_kind']=='GITHUB_API_OPERATIONAL_LOG_ONLY', 'provider_signature_not_available')
    if decoded_logs is not None:
        need(type(decoded_logs) is dict and decoded_logs.keys()==set(_PLATFORMS),'decoded_logs_schema')
        for o in items:
            data=decoded_logs[o['platform']]
            need(type(data) is str,'decoded_log_type')
            b=data.encode('utf-8')
            need(len(data.encode('utf-16-le'))//2==o['decoded_log_code_units'] and
                 len(b)==o['decoded_log_utf8_bytes'],'decoded_log_length')
            need(hmac.compare_digest(hashlib.sha256(b).hexdigest(),o['decoded_log_utf8_sha256']),
                 'decoded_log_hash_mismatch')
    return {'status':'ACTUAL_GITHUB_OBSERVATIONS_NOT_AUTHENTICATION',
            'hosted_observation_count':2,'original_raw_log_signature_verified':False,
            'decoded_utf8_hashes_checked':decoded_logs is not None,
            'verified_external_gates':0,'blocked_gates':GATES,
            'release_ready':False,'authenticated':False,'live_allowed':False}

def make_handoff_request(manifest, platform, challenge_sha256, nonce_sha256, audience):
    """Define a detached *request* to real external authorities, not a signature."""
    inspect_snapshot(manifest)
    need(type(platform) is str and platform in _PLATFORMS,'platform')
    need(h64(challenge_sha256) and h64(nonce_sha256),'challenge_nonce')
    need(type(audience) is str and audience in ('OWNER','INDEPENDENT_REVIEWER','EXTERNAL_PROVENANCE_AUDITOR'),
         'audience')
    o=next(x for x in manifest['observations'] if x['platform']==platform)
    out={'repository':REPO,'branch':BRANCH,'source_sha':BASE_SHA,'platform':platform,
         'run':o['run'],'job':o['job'],'attempt':o['attempt'],
         'workflow_blob_sha':o['workflow_blob_sha'],
         'decoded_log_utf8_sha256':o['decoded_log_utf8_sha256'],
         'challenge_sha256':challenge_sha256,'nonce_sha256':nonce_sha256,
         'audience':audience,'purpose':'REQUEST_REAL_INDEPENDENT_RAW_LOG_ATTESTATION'}
    need(out.keys()==_REQUEST,'request_schema')
    return out

def handoff_sha256(request):
    """Domain-separated canonical request digest; self-hash NOT authority."""
    need(type(request) is dict and request.keys()==_REQUEST,'request_schema')
    need(request['repository']==REPO and request['branch']==BRANCH and
         request['source_sha']==BASE_SHA and h40(request['source_sha']),'request_scope')
    need(h64(request['challenge_sha256']) and h64(request['nonce_sha256']) and
         h64(request['decoded_log_utf8_sha256']) and h40(request['workflow_blob_sha']), 'request_digests')
    need(type(request['platform']) is str and request['platform'] in _PLATFORMS and
         all(positive(request[k]) for k in ('run','job','attempt')),'request_provider_scope')
    need((request['run'],request['job'],request['attempt'],
          request['workflow_blob_sha'],request['decoded_log_utf8_sha256'])==
         _PINNED[request['platform']][:5],'request_observation_pin')
    need(request['audience'] in ('OWNER','INDEPENDENT_REVIEWER','EXTERNAL_PROVENANCE_AUDITOR') and
         request['purpose']=='REQUEST_REAL_INDEPENDENT_RAW_LOG_ATTESTATION','request_audience')
    payload=json.dumps(request,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    return hashlib.sha256(b'KRYPTOAI-RC697-NONAUTHORITATIVE-HANDOFF\0'+len(payload).to_bytes(4,'big')+payload).hexdigest()

def inspect_untrusted_candidate(candidate, request):
    """Even an apparently perfect caller-supplied signature cannot open a gate."""
    digest=handoff_sha256(request)
    need(type(candidate) is dict and candidate.keys()==_CANDIDATE,'candidate_schema')
    need(candidate['gate'] in GATES and type(candidate['gate']) is str,'gate')
    need(h64(candidate['request_sha256']) and
         hmac.compare_digest(candidate['request_sha256'],digest),'request_replay')
    need(h64(candidate['key_fingerprint_sha256']) and
         h64(candidate['claimed_signature_sha256']),'claimed_hashes')
    need(type(candidate['controller']) is str and type(candidate['domain']) is str and
         2<=len(candidate['controller'])<=64 and 2<=len(candidate['domain'])<=64 and
         candidate['controller']!=candidate['domain'],'controller_claim')
    need(candidate['claimed_origin']=='SELF_ASSERTED' and type(candidate['claimed_origin']) is str,
         'forged_provider_origin')
    for key in ('verified','trusted_time','remote_cas','remote_ack','immutable_root'):
        need(type(candidate[key]) is bool and candidate[key] is False,'forged_external_authority')
    return {'status':'CLAIM_QUARANTINED_NOT_CRYPTO_AUTHENTICATED',
            'external_verified':0,'owner_reviewer_authorized':False,
            'provider_signed_raw_full_log_verified':False,
            'trusted_time_verified':False,'merkle_immutability_verified':False,
            'remote_cas_verified':False,'remote_ack_verified':False,
            'final':'SEALED','live':'DISABLED','single_fit':'UNUSED','net20':'NOT_TESTED'}

# No integration with actual exchange API, external signer, immutable log,
# durable multi-host CAS, external clock, or signature verifier is present.
