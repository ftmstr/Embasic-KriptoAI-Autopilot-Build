"""RC709: quarantine Rekor v2 integrated_time=0 and unverified time candidates.

Pure public metadata handling. Never fetches Rekor/TSA, verifies a signature,
accepts a claimed key, or authorizes provider logs, AWS, trading or model fit.
"""
import hashlib
import json

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = 'c106a314fc8ba6a07eb90a1da68e613a857fb7b9'
RUNS = {'ubuntu': (44626964180, 135923234434),
        'windows': (44626964302, 135923235552)}
KINDS = ('NONE', 'RFC3161_TIMESTAMP_CANDIDATE',
         'WITNESSED_C2SP_TIMESTAMP_CANDIDATE')
FIELDS = frozenset(('repository', 'branch', 'head_sha', 'platform',
                    'run_id', 'job_id', 'integrated_time', 'kind',
                    'candidate_sha256', 'claim_time_authenticated',
                    'claim_oob_witness_authenticated', 'claim_provider_raw_authenticated'))


class TimestampBoundaryBlocked(ValueError):
    """Malformed source identity or a self-asserted independent trust claim."""


def _ensure(ok, code):
    if not ok:
        raise TimestampBoundaryBlocked(code)


def _hash64(s):
    return type(s) is str and len(s) == 64 and all(c in '0123456789abcdef' for c in s)


def quarantine_rekor_time(candidate):
    """Generate an untrusted evidence-intake digest, NEVER a time proof.

    Rekor v2's integrated_time=0 is explicitly a non-timestamp. An RFC3161
    response or C2SP witness cosignature still needs separate independent
    cryptographic, custody, chronology and revocation verification.
    """
    _ensure(type(candidate) is dict and candidate.keys() == FIELDS, 'timestamp_schema')
    platform = candidate['platform']
    _ensure(type(platform) is str and platform in RUNS, 'platform_scope')
    run, job = RUNS[platform]
    _ensure(candidate['repository'] == REPO and candidate['branch'] == BRANCH and
            candidate['head_sha'] == BASE_SHA and
            type(candidate['run_id']) is int and candidate['run_id'] == run and
            type(candidate['job_id']) is int and candidate['job_id'] == job,
            'source_run_job_scope')
    _ensure(type(candidate['integrated_time']) is int and
            candidate['integrated_time'] == 0, 'rekor_v2_integrated_time_not_timestamp')
    kind = candidate['kind']
    _ensure(type(kind) is str and kind in KINDS, 'unrecognized_timestamp_kind')
    _ensure((candidate['candidate_sha256'] is None if kind == 'NONE' else
             _hash64(candidate['candidate_sha256'])), 'candidate_material_digest')
    for field in ('claim_time_authenticated', 'claim_oob_witness_authenticated',
                  'claim_provider_raw_authenticated'):
        _ensure(candidate[field] is False, 'self_asserted_external_trust')
    packed = json.dumps(candidate, sort_keys=True, ensure_ascii=True,
                        separators=(',', ':'), allow_nan=False).encode('ascii')
    digest = hashlib.sha256(b'RC709-UNTRUSTED-TIME-ONLY\x00' + packed).hexdigest()
    return {'classification': 'REKOR_V2_INTEGRATED_TIME_ZERO_NOT_A_TIMESTAMP',
            'candidate_kind': kind, 'source_sha': BASE_SHA,
            'public_candidate_digest_sha256': digest,
            'rfc3161_crypto_and_tsa_root_verified': False,
            'witness_crypto_and_independent_custody_verified': False,
            'historical_c2sp_rfc6962_verified': False,
            'trusted_time_or_revocation_verified': False,
            'provider_raw_logs_verified': False,
            'external_verified': 0, 'external_total': 8,
            'auth': 'NO-GO', 'final': 'SEALED', 'live': 'DISABLED',
            'single_fit': 'UNUSED', 'net20': 'NOT_TESTED'}
