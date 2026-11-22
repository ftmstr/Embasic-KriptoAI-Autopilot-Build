"""RC712: MRSC DB/Streams/metrics/witness are NOT external recipient ACK.

A bounded, public-only evidence candidate quarantine. No AWS APIs, network,
filesystem access, production crypto, live orders, or actual proof acceptance.
"""
import hashlib
import json

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = 'd0ef2232f7eef83f82b24b9d199863c34210653a'
HOSTS = {'ubuntu': (44712263026, 136206625554),
         'windows': (44712262558, 136206624211)}
# AWS 2026-09-23 MRSC expansion: any three distinct supported Regions,
# including cross-continent. Candidate shape is NOT provider authentication.
# https://aws.amazon.com/about-aws/whats-new/2026/09/dynamodb-mrsc-additional-regions/
SUPPORTED_MRSC_REGIONS = frozenset((
    'us-east-1', 'us-east-2', 'us-west-2', 'ca-central-1',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
    'eu-north-1', 'eu-south-2',
    'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ap-south-1', 'ap-southeast-1',
))
MATERIAL_TYPES = (
    'MRSC_CONDITIONAL_WRITE_RESULT', 'MRSC_STREAM_RECORD',
    'CLOUDWATCH_REPLICATION_LATENCY', 'MRSC_WITNESS_READ_RESULT',
    'RECIPIENT_SIGNED_ACK_CANDIDATE',
)
FIELDS = frozenset((
    'repository', 'branch', 'head_sha', 'ubuntu_run', 'ubuntu_job',
    'windows_run', 'windows_job', 'replica_regions', 'witness_region',
    'material_type', 'material_sha256', 'request_id_sha256',
    'claims_independent_recipient_auth', 'claims_durable_cas',
    'claims_external_time', 'claims_provider_original_raw_log',
))


class RecipientAckBlocked(ValueError):
    """Invalid, unsupported or falsely authenticated external candidate."""


def _need(condition, message):
    if not condition:
        raise RecipientAckBlocked(message)


def _hex64(s):
    return type(s) is str and len(s) == 64 and all(c in '0123456789abcdef' for c in s)


def inspect_candidate(value):
    """Classify *untrusted* public metadata; 0/8 external gates always.

    MRSC acknowledges its own database writes, not an independently authorized
    application recipient. MRSC does not use Streams for replication, does not
    expose MREC-only ReplicationLatency, and its witness is not an app endpoint.
    """
    _need(type(value) is dict and value.keys() == FIELDS, 'strict_schema')
    _need(value['repository'] == REPO and value['branch'] == BRANCH and
          value['head_sha'] == BASE_SHA, 'exact_source_scope')
    for os_name, (run, job) in HOSTS.items():
        _need(type(value[os_name + '_run']) is int and value[os_name + '_run'] == run and
              type(value[os_name + '_job']) is int and value[os_name + '_job'] == job,
              'actual_hosted_jobs')
    replicas = value['replica_regions']
    witness = value['witness_region']
    _need(type(replicas) is list and len(replicas) in (2, 3) and
          all(type(region) is str for region in replicas) and
          len(set(replicas)) == len(replicas), 'replica_regions')
    _need((len(replicas) == 3 and witness is None) or
          (len(replicas) == 2 and type(witness) is str and witness not in replicas),
          'three_region_mrsc_topology')
    regions = frozenset(replicas) | (frozenset((witness,)) if witness else frozenset())
    _need(len(regions) == 3 and regions <= SUPPORTED_MRSC_REGIONS,
          'unsupported_mrsc_region')
    material = value['material_type']
    _need(type(material) is str and material in MATERIAL_TYPES, 'material_type')
    if material == 'CLOUDWATCH_REPLICATION_LATENCY':
        raise RecipientAckBlocked('mrsc_does_not_publish_replication_latency')
    if material == 'MRSC_WITNESS_READ_RESULT':
        raise RecipientAckBlocked('mrsc_witness_cannot_be_read_or_written')
    _need(_hex64(value['material_sha256']) and _hex64(value['request_id_sha256']) and
          value['material_sha256'] != value['request_id_sha256'], 'candidate_digest_shape')
    for key in ('claims_independent_recipient_auth', 'claims_durable_cas',
                'claims_external_time', 'claims_provider_original_raw_log'):
        _need(value[key] is False, 'self_asserted_third_party_authority')
    classification = {
        'MRSC_CONDITIONAL_WRITE_RESULT': 'DATABASE_COMMIT_NOT_RECIPIENT_ACK',
        'MRSC_STREAM_RECORD': 'STREAM_EVENT_NOT_REPLICATION_OR_RECIPIENT_ACK',
        'RECIPIENT_SIGNED_ACK_CANDIDATE': 'UNVERIFIED_RECIPIENT_CANDIDATE_NEEDS_OOB_KEY_AND_REPLAY_PROOF',
    }[material]
    canonical = json.dumps(value, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=True, allow_nan=False).encode('ascii')
    _need(len(canonical) <= 8192, 'oversize_untrusted_metadata')
    digest = hashlib.sha256(b'RC712-MRSC-UNTRUSTED-RECIPIENT-ONLY\x00' + canonical).hexdigest()
    return {'classification': classification, 'untrusted_request_sha256': digest,
            'mrsc_aws_actual_service_authenticated': False,
            'remote_recipient_identity_and_signature_verified': False,
            'idempotent_recipient_ack_replay_reconciled': False,
            'provider_raw_full_logs_verified': False,
            'durable_multihost_cas_and_antirestore_verified': False,
            'external_gates_verified': 0, 'external_required': 8,
            'auth': 'NO-GO', 'final': 'SEALED', 'live': 'DISABLED',
            'single_fit': 'UNUSED', 'net20': 'NOT_TESTED'}
