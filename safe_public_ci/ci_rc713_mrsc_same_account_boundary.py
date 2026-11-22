"""RC713: MRSC replicas MUST share an AWS account; admin roles are distinct.

All fields are untrusted public evidence candidates. No AWS calls, real signer,
provider RAW log proof, CAS, recipient ACK, trading or authorization occurs.
"""
import hashlib
import json
import re

REPOSITORY = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
SOURCE_SHA = 'cc5fbbffa79b25e5b27e17e5249672819ee860a3'
HOSTED = {'ubuntu': (44840891682, 136648671157),
          'windows': (44840891793, 136648670967)}
# AWS-supported MRSC Region sets, not evidence that a table exists.
REGION_SETS = (
    frozenset(('us-east-1', 'us-east-2', 'us-west-2')),
    frozenset(('eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1')),
    frozenset(('ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3')),
)
TABLE_ARN = re.compile(r'arn:aws:dynamodb:([a-z0-9-]+):([0-9]{12}):table/([A-Za-z0-9_.-]{3,255})\Z')
FIELDS = frozenset((
    'repository', 'branch', 'source_sha', 'ubuntu_run', 'ubuntu_job',
    'windows_run', 'windows_job', 'consistency_mode', 'account_model',
    'replica_table_arns', 'witness_region', 'claimed_provider_response_sha256',
    'request_id_sha256', 'claims_aws_describe_authenticated',
    'claims_distinct_admin_roles_verified', 'claims_independent_oob_reviewer',
    'claims_two_host_durable_cas', 'claims_restore_antireplay_verified',
    'claims_remote_recipient_ack_authenticated',
))


class MRSCAccountBoundaryBlocked(ValueError):
    """Unsafe account configuration or self-asserted external authority."""


def _require(condition, reason):
    if not condition:
        raise MRSCAccountBoundaryBlocked(reason)


def _hex64(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def quarantine_same_account_mrsc(record):
    """Classify a topology candidate; even valid shape means 0/8 external proof.

    AWS multi-account global tables use MREC, NOT MRSC. Separate-admin
    requirement is separate IAM / OOB human custody, not an AWS multi-account
    replication configuration. No caller-provided ARN proves actual custody.
    """
    _require(type(record) is dict and record.keys() == FIELDS, 'strict_schema')
    _require(record['repository'] == REPOSITORY and record['branch'] == BRANCH and
             record['source_sha'] == SOURCE_SHA, 'source_scope')
    for platform, (run, job) in HOSTED.items():
        _require(type(record[platform + '_run']) is int and
                 record[platform + '_run'] == run and
                 type(record[platform + '_job']) is int and
                 record[platform + '_job'] == job, 'exact_original_hosted_job')
    _require(record['consistency_mode'] == 'MRSC', 'mrec_cannot_supply_strong_cas')
    _require(record['account_model'] == 'SAME_ACCOUNT', 'mrsc_multi_account_not_supported')
    replicas = record['replica_table_arns']
    _require(type(replicas) is list and len(replicas) in (2, 3) and
             all(type(arn) is str and TABLE_ARN.fullmatch(arn) is not None
                 for arn in replicas), 'replica_table_arns')
    parsed = [TABLE_ARN.fullmatch(arn).groups() for arn in replicas]
    regions = [entry[0] for entry in parsed]
    _require(len(set(regions)) == len(regions), 'duplicate_replica_region')
    _require(len({entry[1] for entry in parsed}) == 1, 'mrsc_replica_aws_accounts_must_match')
    _require(len({entry[2] for entry in parsed}) == 1, 'global_replica_table_name_must_match')
    witness = record['witness_region']
    _require((len(regions) == 3 and witness is None) or
             (len(regions) == 2 and type(witness) is str and witness not in regions),
             'mrsc_three_region_shape')
    all_regions = frozenset(regions) | (frozenset((witness,)) if witness is not None else frozenset())
    _require(len(all_regions) == 3 and any(all_regions <= group for group in REGION_SETS),
             'mrsc_supported_region_set')
    _require(_hex64(record['claimed_provider_response_sha256']) and
             _hex64(record['request_id_sha256']) and
             record['claimed_provider_response_sha256'] != record['request_id_sha256'],
             'untrusted_material_digest_shape')
    for key in ('claims_aws_describe_authenticated', 'claims_distinct_admin_roles_verified',
                'claims_independent_oob_reviewer', 'claims_two_host_durable_cas',
                'claims_restore_antireplay_verified',
                'claims_remote_recipient_ack_authenticated'):
        _require(record[key] is False, 'self_asserted_provider_or_admin_proof')
    data = json.dumps(record, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')
    _require(len(data) <= 8192, 'candidate_metadata_oversize')
    digest = hashlib.sha256(b'RC713-UNTRUSTED-SAME-ACCOUNT-MRSC\x00' + data).hexdigest()
    return {'classification': 'VALID_SHAPE_SAME_ACCOUNT_MRSC_UNAUTHENTICATED',
            'request_sha256_not_a_signature': digest,
            'single_account_replica_shape_only': True,
            'aws_resource_or_admin_custody_verified': False,
            'separate_admin_oob_held_key_verified': False,
            'actual_multihost_durable_fence_and_antirestore_verified': False,
            'independently_authenticated_recipient_ack_verified': False,
            'provider_signed_original_raw_logs_verified': False,
            'external_gates_verified': 0, 'external_total': 8,
            'auth': 'NO-GO', 'final': 'SEALED', 'live': 'DISABLED',
            'single_fit': 'UNUSED', 'net20': 'NOT_TESTED'}
