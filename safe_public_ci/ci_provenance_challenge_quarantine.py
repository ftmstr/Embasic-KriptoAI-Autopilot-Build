"""RC694/TUR51: offline evidence-intake challenge contract (NO AUTHENTICATION).

All claims, challenge strings, signer labels and signatures are caller-supplied.
No provider-signed log, owner/reviewer key origin, trusted clock, immutable
checkpoint, external CAS or authenticated remote ACK is obtained by this module.
This module NEVER authorizes release, live trading or an authenticated result.
"""
import hashlib
import hmac
import re


class IntakeRejected(ValueError):
    """Invalid or promotion-seeking caller-controlled intake data."""


REPOSITORY = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
_GATES = (
    'owner_oob_key', 'reviewer_oob_key', 'provider_ubuntu_attestation',
    'provider_windows_attestation', 'revocation_trusted_time',
    'external_immutable_checkpoint', 'external_antirollback_cas',
    'remote_provider_ack',
)
_PREREQUISITES = (
    (), (), ('owner_oob_key', 'reviewer_oob_key'),
    ('owner_oob_key', 'reviewer_oob_key'),
    ('owner_oob_key', 'reviewer_oob_key'),
    ('owner_oob_key', 'reviewer_oob_key', 'revocation_trusted_time'),
    ('external_immutable_checkpoint', 'revocation_trusted_time'),
    ('external_antirollback_cas', 'provider_ubuntu_attestation',
     'provider_windows_attestation'),
)
_PROOF_NEEDED = (
    'independently delivered owner Ed25519 public key, authorization and delegation',
    'independently delivered reviewer Ed25519 public key and separate administrator',
    'actual provider-issued Ubuntu signed run/job/attempt/workflow/entire log transcript',
    'actual provider-issued Windows signed run/job/attempt/workflow/entire log transcript',
    'authorized key revocation and independently timestamped chronology',
    'independently immutable checkpoint and externally anchored Merkle consistency',
    'independent monotone multi-host CAS/fencing with rollback protection',
    'authentic remote recipient ACK and idempotent reconciliation mechanism',
)
_H40 = re.compile(r'[0-9a-f]{40}\Z')
_H64 = re.compile(r'[0-9a-f]{64}\Z')
_H128 = re.compile(r'[0-9a-f]{128}\Z')
_NAME = re.compile(r'[a-z][a-z0-9_-]{1,62}\Z')
_MAX = 2**63 - 1
_PACKET = frozenset(('repository','branch','source_sha','epoch','challenge_sha',
                     'phase','receipts','checkpoint','journal','release'))
_RECEIPT = frozenset(('gate','controller','domain','source_sha','artifact_sha',
                       'log_sha','workflow_sha','challenge_sha','signature_hex',
                       'signed_transcript_sha','run','job','attempt','issued_at',
                       'expires_at','revoked_at','claimed_verified','origin'))
_CHECKPOINT = frozenset(('previous_root','current_root','consistency_path',
                         'independently_anchored'))
_JOURNAL = frozenset(('generation','next_generation','fence','next_fence','nonce_sha',
                      'pending_outbox_sha','ack_sha','external_cas_verified',
                      'remote_ack_verified'))
_RELEASE = frozenset(('authenticated','live','final','single_fit_used','net20_tested'))


def _require(ok, code):
    if not ok:
        raise IntakeRejected(code)


def _keys(value, expected):
    return type(value) is dict and value.keys() == expected


def _hex(value, size=64):
    return type(value) is str and {40:_H40,64:_H64,128:_H128}[size].fullmatch(value) is not None


def _number(value):
    return type(value) is int and 0 <= value <= _MAX


def _positive(value):
    return type(value) is int and 0 < value <= _MAX


def _name(value):
    return type(value) is str and _NAME.fullmatch(value) is not None


def _transcript(items):
    """Typed-length digest is only a digest, NOT a signature verification."""
    d = hashlib.sha256(b'RC694-UNAUTHENTICATED-INTAKE-V1\0')
    for item in items:
        if item is None:
            b = b'n'
        elif type(item) is int:
            _require(_number(item), 'transcript_integer')
            b = b'i' + str(item).encode('ascii')
        elif type(item) is str:
            _require(item.isascii(), 'transcript_ascii')
            b = b's' + item.encode('ascii')
        else:
            raise IntakeRejected('transcript_type')
        d.update(len(b).to_bytes(4, 'big'))
        d.update(b)
    return d.hexdigest()


def receipt_transcript(repository, branch, epoch, receipt):
    """Bind a *claim* to its challenge/scope; not authority or anti-replay."""
    _require(_keys(receipt, _RECEIPT), 'receipt_schema')
    return _transcript((repository, branch, epoch, receipt['gate'],
                        receipt['controller'], receipt['domain'],
                        receipt['source_sha'], receipt['artifact_sha'],
                        receipt['log_sha'], receipt['workflow_sha'],
                        receipt['challenge_sha'], receipt['run'],receipt['job'],
                        receipt['attempt'],receipt['issued_at'],
                        receipt['expires_at'],receipt['revoked_at']))


def admission_dependencies():
    """A plan to obtain 8 external facts, NOT evidence they were obtained."""
    return tuple({'gate':name, 'needs_real_external':required,
                   'prerequisites':deps, 'verified':False, 'status':'BLOCKED',
                   'claim_only':True}
                  for name,required,deps in zip(_GATES,_PROOF_NEEDED,_PREREQUISITES))


def inspect(packet):
    """Validate strictly bounded self-claims; always return AUTHENTICATED=False."""
    _require(_keys(packet, _PACKET), 'packet_schema')
    _require(packet['repository'] == REPOSITORY and type(packet['repository']) is str, 'repository')
    _require(packet['branch'] == BRANCH and type(packet['branch']) is str, 'branch')
    _require(_hex(packet['source_sha'],40), 'source_sha')
    _require(_positive(packet['epoch']), 'epoch')
    _require(_hex(packet['challenge_sha']), 'challenge')
    _require(type(packet['phase']) is str and packet['phase'] == 'COLLECT_ONLY', 'phase')
    receipts = packet['receipts']
    _require(type(receipts) is list and len(receipts) == 8, 'receipt_count')
    _require([x.get('gate') if type(x) is dict else None for x in receipts] == list(_GATES), 'receipt_order')
    domains, controllers, artifact_ids, provider_runs = set(), set(), set(), set()
    revoked = []
    for receipt in receipts:
        _require(_keys(receipt,_RECEIPT), 'receipt_schema')
        _require(_name(receipt['gate']) and _name(receipt['controller']) and _name(receipt['domain']), 'identifiers')
        _require(receipt['controller'] not in controllers, 'controller_duplicate')
        _require(receipt['domain'] not in domains, 'domain_duplicate')
        controllers.add(receipt['controller']); domains.add(receipt['domain'])
        _require(receipt['source_sha'] == packet['source_sha'] and _hex(receipt['source_sha'],40), 'source_binding')
        _require(receipt['challenge_sha'] == packet['challenge_sha'] and _hex(receipt['challenge_sha']), 'challenge_binding')
        _require(all(_hex(receipt[field]) for field in ('artifact_sha','log_sha','workflow_sha','signed_transcript_sha')), 'receipt_hash')
        _require(receipt['artifact_sha'] not in artifact_ids, 'artifact_duplicate')
        artifact_ids.add(receipt['artifact_sha'])
        _require(_hex(receipt['signature_hex'],128), 'claimed_signature_format')
        _require(_number(receipt['run']) and _number(receipt['job']) and _positive(receipt['attempt']), 'provider_ids')
        provider = receipt['gate'].startswith('provider_')
        _require((receipt['run'] > 0 and receipt['job'] > 0) if provider else (receipt['run'] == 0 and receipt['job'] == 0), 'provider_binding')
        if provider:
            _require((receipt['run'],receipt['job']) not in provider_runs, 'provider_run_duplicate')
            provider_runs.add((receipt['run'],receipt['job']))
        _require(_number(receipt['issued_at']) and _number(receipt['expires_at']) and
                 receipt['issued_at'] <= packet['epoch'] <= receipt['expires_at'], 'untrusted_claim_clock')
        revoked_at=receipt['revoked_at']
        _require(revoked_at is None or (_number(revoked_at) and receipt['issued_at'] <= revoked_at <= receipt['expires_at']), 'revocation_type')
        if revoked_at is not None and revoked_at <= packet['epoch']:
            revoked.append(receipt['gate'])
        _require(receipt['claimed_verified'] is False and type(receipt['claimed_verified']) is bool, 'no_external_verification')
        _require(type(receipt['origin']) is str and receipt['origin'] == 'SELF_ASSERTED', 'no_forged_origin')
        expected=receipt_transcript(packet['repository'],packet['branch'],packet['epoch'],receipt)
        _require(hmac.compare_digest(receipt['signed_transcript_sha'],expected), 'transcript_mismatch')
    checkpoint=packet['checkpoint']
    _require(_keys(checkpoint,_CHECKPOINT), 'checkpoint_schema')
    _require(_hex(checkpoint['previous_root']) and _hex(checkpoint['current_root']), 'checkpoint_root')
    _require(type(checkpoint['consistency_path']) is list and len(checkpoint['consistency_path']) <= 16 and
             all(_hex(x) for x in checkpoint['consistency_path']), 'checkpoint_path')
    _require(checkpoint['independently_anchored'] is False and type(checkpoint['independently_anchored']) is bool, 'anchor_unverified')
    journal=packet['journal']
    _require(_keys(journal,_JOURNAL), 'journal_schema')
    _require(_number(journal['generation']) and _positive(journal['next_generation']) and
             journal['generation'] < _MAX and journal['next_generation'] == journal['generation']+1, 'generation')
    _require(_positive(journal['fence']) and journal['fence'] < _MAX and
             journal['next_fence'] == journal['fence']+1 and _positive(journal['next_fence']), 'fence')
    _require(_hex(journal['nonce_sha']) and _hex(journal['pending_outbox_sha']), 'journal_receipts')
    _require(journal['ack_sha'] is None, 'remote_ack_missing')
    for flag in ('external_cas_verified','remote_ack_verified'):
        _require(type(journal[flag]) is bool and journal[flag] is False, 'no_production_cas_or_ack')
    release=packet['release']
    _require(_keys(release,_RELEASE) and all(type(x) is bool and x is False for x in release.values()), 'release_locked')
    digest_parts=(packet['repository'],packet['branch'],packet['source_sha'],
                  packet['epoch'],packet['challenge_sha'])
    for x in receipts:
        digest_parts+=(x['gate'],x['signed_transcript_sha'],x['signature_hex'])
    digest_parts+=(checkpoint['previous_root'],checkpoint['current_root'],
                   journal['nonce_sha'],journal['pending_outbox_sha'],
                   journal['generation'],journal['fence'])
    return {'status':'CLAIMED_INTAKE_ONLY_NOT_AUTHENTICATED',
            'claim_digest':_transcript(digest_parts),
            'blocked_external_gates':_GATES,
            'verified_external_gates':0,
            'claimed_revocations':tuple(revoked),
            'independent_owner_reviewer_verified':False,
            'provider_signed_full_logs_verified':False,
            'trusted_clock_and_revocation_verified':False,
            'immutable_checkpoint_verified':False,
            'production_durable_cas_verified':False,
            'remote_ack_authenticated':False,
            'authenticated':False,'release_ready':False,'live_trading_allowed':False,
            'single_fit_used':False,'net20_tested':False}


def compare_intakes(a,b):
    """Classify contrary caller claims; never settle split view with external trust."""
    r1,r2=inspect(a),inspect(b)
    for key,label in (('repository','REPOSITORY'),('branch','BRANCH'),
                      ('source_sha','SOURCE'),('epoch','EPOCH'),
                      ('challenge_sha','CHALLENGE')):
        if a[key] != b[key]:
            return 'CLAIMED_'+label+'_FORK_NO_EXTERNAL_AUTH'
    if a['checkpoint'] != b['checkpoint']:
        return 'CLAIMED_CHECKPOINT_FORK_NO_EXTERNAL_ANCHOR'
    if a['receipts'] != b['receipts']:
        return 'CLAIMED_RECEIPT_FORK_NO_PROVIDER_SIGNED_PROOF'
    if a['journal'] != b['journal']:
        if a['journal']['nonce_sha'] == b['journal']['nonce_sha']:
            return 'CLAIMED_NONCE_ABA_FORK_NO_DURABLE_CAS'
        return 'CLAIMED_LOCAL_CAS_FORK_NO_EXTERNAL_FENCE'
    _require(r1['claim_digest'] == r2['claim_digest'], 'canonical_collision')
    return 'CLAIMED_EQUAL_UNAUTHENTICATED'

# Never promote caller-generated challenge responses to externally authenticated
# signatures, independently immutable Merkle checkpoints or production CAS.
