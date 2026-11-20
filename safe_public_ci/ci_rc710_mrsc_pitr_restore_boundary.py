"""RC710: AWS PITR restore-to-MRSC identity and fencing safety quarantine.

Only classifies untrusted, public, hypothetical *metadata*. No AWS requests,
credentials, file IO, trading, remote ACK, signature verification or approvals.
A populated PITR-restored table cannot directly become an MRSC global table.
"""
import hashlib
import json
import re

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = '2904a2c0476e2aecb9d0e44ec852fddc9284d3ae'
HOSTS = {'ubuntu': (44688542971, 136128558122),
         'windows': (44688542996, 136128558909)}
ARN = re.compile(r'arn:aws:dynamodb:[a-z][a-z0-9-]{2,30}:[0-9]{12}:table/[A-Za-z0-9_.-]{3,255}\Z')
FIELDS = frozenset((
    'repository', 'branch', 'source_sha', 'ubuntu_run', 'ubuntu_job',
    'windows_run', 'windows_job', 'original_table_arn',
    'pitr_restored_table_arn', 'candidate_mrsc_table_arn',
    'reported_restored_item_count', 'migration_method', 'prior_epoch',
    'prior_fence', 'candidate_epoch', 'candidate_fence',
    'provider_provisioning_authenticated', 'separate_admin_reenrollment_authenticated',
    'two_host_cas_authenticated', 'restored_data_copy_authenticated',
    'remote_recipient_ack_authenticated'))
METHODS = ('POPULATED_PITR_DIRECT_MRSC_CONVERSION',
           'NEW_EMPTY_MRSC_THEN_CONTROLLED_DATA_COPY')


class RestoreBoundaryBlocked(ValueError):
    """Invalid, unsafe or self-authorized cloud migration claim."""


def require(ok, reason):
    if not ok:
        raise RestoreBoundaryBlocked(reason)


def _counter(n):
    return type(n) is int and 0 <= n < 2**63


def classify_pitr_mrsc_recovery(record):
    """Never authorize a recovery: require a NEW EMPTY MRSC table for data copy.

    Reported counters or distinct ARNs do not authenticate an external epoch;
    a verified separate-admin re-enrollment and multi-host durable fencing
    test would still be needed after any *real* service setup.
    """
    require(type(record) is dict and record.keys() == FIELDS, 'restore_schema')
    require(record['repository'] == REPO and record['branch'] == BRANCH and
            record['source_sha'] == BASE_SHA, 'source_scope')
    for system in HOSTS:
        run, job = HOSTS[system]
        require(type(record[system + '_run']) is int and record[system + '_run'] == run and
                type(record[system + '_job']) is int and record[system + '_job'] == job,
                'original_hosted_job_scope')
    for key in ('original_table_arn', 'pitr_restored_table_arn',
                'candidate_mrsc_table_arn'):
        value = record[key]
        require(type(value) is str and ARN.fullmatch(value) is not None,
                'aws_table_identity_shape')
    require(record['original_table_arn'] != record['pitr_restored_table_arn'],
            'pitr_must_create_new_table')
    require(type(record['migration_method']) is str and
            record['migration_method'] in METHODS, 'migration_method')
    require(_counter(record['reported_restored_item_count']) and
            record['reported_restored_item_count'] > 0,
            'reported_populated_restore_scope')
    if record['migration_method'] == METHODS[0]:
        raise RestoreBoundaryBlocked('populated_pitr_cannot_convert_directly_to_mrsc')
    require(len({record['original_table_arn'], record['pitr_restored_table_arn'],
                 record['candidate_mrsc_table_arn']}) == 3,
            'new_empty_mrsc_target_identity_required')
    for key in ('prior_epoch', 'prior_fence', 'candidate_epoch', 'candidate_fence'):
        require(_counter(record[key]), 'fencing_counter_type')
    require(record['candidate_epoch'] > record['prior_epoch'] and
            record['candidate_fence'] > record['prior_fence'],
            'new_table_requires_fresh_epoch_and_fence')
    for key in ('provider_provisioning_authenticated',
                'separate_admin_reenrollment_authenticated',
                'two_host_cas_authenticated', 'restored_data_copy_authenticated',
                'remote_recipient_ack_authenticated'):
        require(record[key] is False, 'self_asserted_independent_service_proof')
    payload = json.dumps(record, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    require(len(payload) <= 8192, 'oversize_restore_metadata')
    digest = hashlib.sha256(b'RC710-UNTRUSTED-AWS-RECOVERY\x00' + payload).hexdigest()
    return {'status': 'BLOCKED_UNVERIFIED_NEW_EMPTY_MRSC_COPY_AND_REENROLL',
            'documented_restore_constraint': 'POPULATED_PITR_RESTORE_NOT_DIRECT_MRSC',
            'request_digest_sha256': digest,
            'candidate_identity_is_aws_proof': False,
            'new_empty_mrsc_provisioned_and_verified': False,
            'data_copy_and_source_immutability_verified': False,
            'separate_admin_epoch_and_fence_reenrollment_verified': False,
            'two_physical_host_durable_cas_and_antirestore_verified': False,
            'remote_recipient_idempotent_ack_verified': False,
            'independent_external_gates_verified': 0, 'external_total': 8,
            'auth': 'NO-GO', 'final': 'SEALED', 'live': 'DISABLED',
            'single_fit': 'UNUSED', 'net20': 'NOT_TESTED'}
