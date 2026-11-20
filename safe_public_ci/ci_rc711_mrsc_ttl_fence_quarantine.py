"""RC711: quarantine DynamoDB MRSC TTL expiry as fencing authority.

MRSC cannot configure TTL. Even on other tables TTL deletion is asynchronous,
so deletion/elapsed time is not a lock-release proof. This module inspects
only caller-provided public candidate metadata; never connects to AWS,
verifies independent time, signs a receipt, or enables trading.
"""
import hashlib
import json
import re

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = '4d631593221b3537b1d0bdad2c5cfaaccdd57480'
HOSTS = {'ubuntu': (44709467778, 136197181580),
         'windows': (44709467752, 136197179925)}
ARN = re.compile(r'arn:aws:dynamodb:[a-z][a-z0-9-]{2,30}:[0-9]{12}:table/[A-Za-z0-9_.-]{3,255}\Z')
FIELDS = frozenset((
    'repository', 'branch', 'source_sha', 'ubuntu_run', 'ubuntu_job',
    'windows_run', 'windows_job', 'candidate_table_arn', 'consistency',
    'ttl_configured', 'ttl_support_claimed', 'ttl_expiry_releases_fence',
    'expired_item_deletion_observed', 'expiry_candidate_kind',
    'expiry_candidate_sha256', 'fence_epoch', 'fence_generation',
    'claim_time_authenticated', 'claim_cas_durable',
    'claim_admin_independent', 'claim_remote_ack_authenticated'))
EXPIRY_KINDS = ('NONE', 'CALLER_CLOCK_CANDIDATE', 'RFC3161_CANDIDATE')


class TtlFenceBlocked(ValueError):
    """Unsupported TTL feature, false authority, or malformed candidate."""


def need(ok, reason):
    if not ok:
        raise TtlFenceBlocked(reason)


def _counter(x):
    return type(x) is int and 0 <= x < 2**63


def _hex64(x):
    return type(x) is str and len(x) == 64 and all(c in '0123456789abcdef' for c in x)


def quarantine_ttl_fence(candidate):
    """Return an **unverified** handoff, never an MRSC lease release.

    TTL is unsupported for MRSC, and even when supported DynamoDB's expiry
    deletion is eventual, not proof that a stale contender cannot write.
    No field here admits third-party trust from this caller.
    """
    need(type(candidate) is dict and candidate.keys() == FIELDS, 'strict_schema')
    need(candidate['repository'] == REPO and candidate['branch'] == BRANCH and
         candidate['source_sha'] == BASE_SHA, 'source_scope')
    for platform in ('ubuntu', 'windows'):
        run, job = HOSTS[platform]
        need(type(candidate[platform + '_run']) is int and
             candidate[platform + '_run'] == run and
             type(candidate[platform + '_job']) is int and
             candidate[platform + '_job'] == job, 'actual_hosted_job_scope')
    need(candidate['consistency'] == 'MRSC', 'only_mrsc_service_contract')
    need(type(candidate['candidate_table_arn']) is str and
         ARN.fullmatch(candidate['candidate_table_arn']) is not None,
         'candidate_table_identity_shape')
    for flag in ('ttl_configured', 'ttl_support_claimed',
                 'ttl_expiry_releases_fence', 'expired_item_deletion_observed'):
        need(candidate[flag] is False, 'mrsc_ttl_or_expiry_as_fencing_authority')
    need(_counter(candidate['fence_epoch']) and candidate['fence_epoch'] > 0 and
         _counter(candidate['fence_generation']) and
         candidate['fence_generation'] > 0, 'claimed_fence_counter_shape')
    kind = candidate['expiry_candidate_kind']
    need(type(kind) is str and kind in EXPIRY_KINDS, 'expiry_candidate_kind')
    need((candidate['expiry_candidate_sha256'] is None if kind == 'NONE'
          else _hex64(candidate['expiry_candidate_sha256'])),
         'expiry_candidate_digest')
    for flag in ('claim_time_authenticated', 'claim_cas_durable',
                 'claim_admin_independent', 'claim_remote_ack_authenticated'):
        need(candidate[flag] is False, 'self_asserted_external_authority')
    data = json.dumps(candidate, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')
    need(len(data) <= 8192, 'candidate_too_large')
    digest = hashlib.sha256(b'RC711-UNTRUSTED-MRSC-TTL-FENCE\x00' + data).hexdigest()
    return {'classification': 'TTL_CANNOT_EXPIRE_OR_AUTHORIZE_MRSC_FENCE',
            'source_sha': BASE_SHA, 'candidate_digest_sha256': digest,
            'candidate_kind': kind, 'ttl_configurable_for_mrsc': False,
            'ttl_delayed_delete_is_a_fence_release': False,
            'external_time_and_revocation_verified': False,
            'separate_admin_durable_cas_verified': False,
            'external_remote_ack_verified': False,
            'provider_raw_logs_verified': False,
            'external_gates_verified': 0, 'external_required': 8,
            'auth': 'NO-GO', 'final': 'SEALED', 'live': 'DISABLED',
            'single_fit': 'UNUSED', 'net20': 'NOT_TESTED'}
