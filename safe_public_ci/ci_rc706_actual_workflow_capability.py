"""RC706: evidence-grounded, read-only GitHub capability gap handoff.

The only positive finding here is exact *file byte identity*, not GitHub's
cryptographic signature. Even valid workflow/job metadata has zero authority
to authenticate original RAW job logs, OOB signing keys, Rekor or AWS.
No filesystem/network access, AWS, trading, model fitting or credentials.
"""
import hashlib
import hmac
import json
import re

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = '83c45062e58c94d033621fecf40d23e3316a9811'
WORKFLOWS = {
    'ubuntu': ('.github/workflows/rc654-validation-synthetic.yml',
               '140264aaf07f3130a23606254f545b4ff77b1971'),
    'windows': ('.github/workflows/rc658-windows-synthetic.yml',
                '254ac4f4ea821a05ee4730c3828d4de1b96a0e72'),
}
RUNS = {'ubuntu': (44571231345, 135726515869),
        'windows': (44571231356, 135726515350)}
GATES = ('owner_oob_ed25519', 'reviewer_oob_ed25519',
         'provider_raw_ubuntu', 'provider_raw_windows',
         'independent_time_revocation', 'witnessed_historical_merkle',
         'separate_admin_durable_mrsc_cas', 'authenticated_recipient_ack')
TOP_KEYS = frozenset(('repository','branch','source_sha','workflows','observed_jobs'))
WORKFLOW_KEYS = frozenset(('path','content','git_blob_sha1'))
JOB_KEYS = frozenset(('run_id','job_id','head_sha','run_status','run_conclusion',
                       'job_status','job_conclusion','successful_steps',
                       'total_steps','distinct_test_passes','rc705_test_passes',
                       'workflow_artifact_count'))
ALLOWED_EXPLANATIONS = (
    ('owner_oob_ed25519','Obtain real separately custodied owner OOB key, signed scoped delegation and revocation'),
    ('reviewer_oob_ed25519','Obtain distinct-admin reviewer OOB-pinned key and signed approval'),
    ('provider_raw_ubuntu','Ask GitHub provider for verifiable signature over exact ORIGINAL RAW complete Ubuntu job log, not plaintext or artifact subject'),
    ('provider_raw_windows','Ask GitHub provider for verifiable signature over exact ORIGINAL RAW complete Windows job log, not plaintext or artifact subject'),
    ('independent_time_revocation','Secure independent non-rewindable timestamping and signed key revocation/rotation log'),
    ('witnessed_historical_merkle','Acquire historical anchored log-signed checkpoint, verified separate-admin witness cosignature and RFC6962 consistency'),
    ('separate_admin_durable_mrsc_cas','Provision 3-region separate-admin MRSC, observe 2+ physical hosts CAS race and independent restore/fence audit'),
    ('authenticated_recipient_ack','Obtain external recipient-signed idempotency ACK and reconcile actual lost-response state'),
)

class CapabilityRejected(ValueError):
    """Out of scope, changed workflow, unverifiable structure or bogus data."""

def require(value, reason):
    if not value:
        raise CapabilityRejected(reason)

def git_blob_sha1(data):
    """Git object identity for EXACT bytes, not a provider-origin signature."""
    require(type(data) is bytes and len(data) <= 131072, 'workflow_bytes_limit')
    return hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\x00' + data).hexdigest()

def _exact_workflow(platform, w):
    require(type(w) is dict and w.keys() == WORKFLOW_KEYS, 'workflow_schema')
    path, blob = WORKFLOWS[platform]
    require(w['path'] == path and w['git_blob_sha1'] == blob, 'protected_workflow_identity')
    require(type(w['content']) is str, 'workflow_type')
    data = w['content'].encode('utf-8')
    require(hmac.compare_digest(git_blob_sha1(data), blob), 'protected_workflow_bytes_changed')
    require(data.count(b'permissions:\n  contents: read\n') == 1 and
            data.count(b'    permissions:\n      contents: read\n') == 1,
            'unexpected_workflow_permissions')
    require(b'id-token: write' not in data and b'attestations: write' not in data and
            b'actions/attest@' not in data and b'gh attestation' not in data,
            'unexpected_attestation_capability')
    require(b'python-version: \'3.13.5\'' in data and
            b'safe_public_ci/**' in data and b'SAFE_TEST_ONLY: \'1\'' in data,
            'unexpected_workflow_safety')
    return {'path':path, 'protected_git_blob_sha1':blob,
            'sha256':hashlib.sha256(data).hexdigest(),
            'workflow_has_provider_signed_original_raw_job_log':False,
            'workflow_has_attestation_action':False,
            'workflow_attestation_write_permission':False,
            'workflow_oidc_write_permission':False,
            'read_only_contents_permissions_observed':True}

def _exact_observed_job(platform, job):
    require(type(job) is dict and job.keys() == JOB_KEYS, 'job_schema')
    run, job_id = RUNS[platform]
    require(type(job['run_id']) is int and job['run_id'] == run and
            type(job['job_id']) is int and job['job_id'] == job_id and
            job['head_sha'] == BASE_SHA, 'run_job_exact_subject')
    require(all(job[k] == 'completed' for k in ('run_status','job_status')) and
            all(job[k] == 'success' for k in ('run_conclusion','job_conclusion')),
            'observed_ci_not_success')
    for k, value in [('successful_steps',9),('total_steps',9),
                     ('distinct_test_passes',3194),('rc705_test_passes',12),
                     ('workflow_artifact_count',0)]:
        require(type(job[k]) is int and job[k] == value, 'observed_job_scope')
    # Metadata here was supplied by the caller, not provider-signed evidence.
    return {'run_id':run, 'job_id':job_id, 'head_sha':BASE_SHA,
            'self_reported_ci_success_is_independent_proof':False,
            'workflow_artifact_count_reported':0,
            'full_raw_log_provider_signature_present':False}

def assess_hosted_capabilities(snapshot):
    """Produce actionable *negative* evidence with a fixed factual scope.

    Inputs should be separately retrieved from GitHub and compared to this
    immutable TUR62 anchor by a human/auditor. They are not authenticated by
    this function. Any new HEAD/run requires a new, reviewed audit version.
    """
    require(type(snapshot) is dict and snapshot.keys() == TOP_KEYS,'snapshot_schema')
    require(snapshot['repository']==REPO and snapshot['branch']==BRANCH and
            snapshot['source_sha']==BASE_SHA,'source_scope')
    require(type(snapshot['workflows']) is dict and
            set(snapshot['workflows']) == set(WORKFLOWS),'workflow_hosts')
    require(type(snapshot['observed_jobs']) is dict and
            set(snapshot['observed_jobs']) == set(RUNS),'job_hosts')
    ws = {os:_exact_workflow(os,snapshot['workflows'][os]) for os in ('ubuntu','windows')}
    jobs={os:_exact_observed_job(os,snapshot['observed_jobs'][os]) for os in ('ubuntu','windows')}
    custody = {'source_sha':BASE_SHA,
               'workflow_blob_sha1':{os:ws[os]['protected_git_blob_sha1'] for os in ws},
               'workflow_sha256':{os:ws[os]['sha256'] for os in ws},
               'observed_jobs':{os:{'run':jobs[os]['run_id'],'job':jobs[os]['job_id']} for os in jobs}}
    packed=json.dumps(custody,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode('ascii')
    return {'classification':'VERIFIED_FILE_BYTES_BUT_UNTRUSTED_PROVIDER_METADATA',
            'acquisition_handoff_sha256':hashlib.sha256(b'RC706-OBSERVATION-NO-AUTH\x00'+packed).hexdigest(),
            'workflows':ws, 'historical_jobs':jobs,
            'provider_endpoint_documentation':'GITHUB_JOB_LOGS_PLAINTEXT_REDIRECT',
            'attested_artifact_is_original_raw_job_log':False,
            'missing_independent_evidence':tuple({'gate':gate,'next_external_action':action,
                                                  'status':'BLOCKED'} for gate,action in ALLOWED_EXPLANATIONS),
            'external_gates_verified':0, 'external_total':8,
            'oob_trust_roots_verified':False,'reliable_rekor_witness_verified':False,
            'mrsc_real_cas_verified':False,'recipient_real_ack_verified':False,
            'auth':'NO-GO','live':'DISABLED','final':'SEALED',
            'single_fit':'UNUSED','net20':'NOT_TESTED'}
