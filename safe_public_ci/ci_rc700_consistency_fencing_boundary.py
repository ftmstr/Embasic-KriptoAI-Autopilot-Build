"""RC700/TUR57: actual RFC6962 consistency *math* and inert MRSC CAS plans.

All checkpoint / witness / owner claims are untrusted until obtained from
independent trusted sources. No import of third-party crypto, IO, network,
keys, production state, real AWS operations, trading, or model fitting.
"""
import hashlib
import hmac
import json
import re

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = 'a33f2a0e8dd0ccca71667514c36df58cfcbd6fd1'
GATES = (
    'owner_oob_key', 'reviewer_oob_key', 'provider_ubuntu_attestation',
    'provider_windows_attestation', 'revocation_trusted_time',
    'external_immutable_checkpoint', 'external_antirollback_cas',
    'remote_provider_ack',
)
_SHA256 = re.compile(r'[0-9a-f]{64}\Z')
_ID = re.compile(r'[A-Za-z][A-Za-z0-9_-]{1,62}\Z')
_MAX_TREE = 2**63 - 1
_FIELDS = frozenset(('repository','branch','source_sha','old_size','new_size',
                     'old_root_sha256','new_root_sha256','log_identity_sha256',
                     'witness_identity_sha256','audit_path'))
_TOPOLOGY = frozenset(('service','consistency','replicas','witness_region',
                       'transaction_api','strong_reads','conditional_writes',
                       'restore_drill_verified','independent_admin_verified'))
_CAS = frozenset(('source_sha','table','key','epoch','generation','fence',
                  'next_generation','next_fence','expected_root_sha256',
                  'new_root_sha256','request_id_sha256'))

class ExternalEvidenceBlocked(ValueError):
    """Invalid claim, input, or a false authority-promotion attempt."""

def require(flag, reason):
    if not flag:
        raise ExternalEvidenceBlocked(reason)

def hex256(value):
    return type(value) is str and _SHA256.fullmatch(value) is not None

def nonnegative(value):
    return type(value) is int and 0 <= value <= _MAX_TREE

def node(left, right):
    return hashlib.sha256(b'\x01'+left+right).digest()

def _valid_path(path):
    return (type(path) is list and len(path) <= 64 and
            all(hex256(h) for h in path))

def verify_consistency(candidate):
    """RFC6962 minimal consistency-path verification; no trusted root claimed.

    Accepts the proof calculated by RFC6962 SUBPROOF(m,D[n],true) in
    bottom-to-top order. Reconstructs old and new roots *independently* and
    rejects split views and different-size rollback. Reconstructed roots are
    entirely from caller input and remain unauthenticated at this boundary.
    """
    require(type(candidate) is dict and candidate.keys()==_FIELDS, 'consistency_schema')
    require(candidate['repository']==REPO and candidate['branch']==BRANCH and
            candidate['source_sha']==BASE_SHA, 'source_scope')
    for k in ('old_root_sha256','new_root_sha256','log_identity_sha256',
              'witness_identity_sha256'):
        require(hex256(candidate[k]), 'digest_shape')
    require(candidate['log_identity_sha256']!=candidate['witness_identity_sha256'],
            'witness_must_differ_from_log')
    m=candidate['old_size']; n=candidate['new_size']
    require(nonnegative(m) and nonnegative(n) and m>0 and n>=m, 'rollback_or_invalid_size')
    path=candidate['audit_path']
    require(_valid_path(path), 'consistency_path_shape')
    old=bytes.fromhex(candidate['old_root_sha256'])
    new=bytes.fromhex(candidate['new_root_sha256'])
    if m==n:
        require(not path and hmac.compare_digest(old,new), 'same_size_fork_or_redundant_path')
        return _untrusted_result(m,n,old.hex(),new.hex())
    fn=m-1;sn=n-1
    while fn&1:
        fn//=2;sn//=2
    if fn==0:
        old_calc=old
        new_calc=old
        idx=0
    else:
        require(len(path)>0,'missing_consistency_node')
        old_calc=bytes.fromhex(path[0])
        new_calc=old_calc
        idx=1
    while idx<len(path):
        require(sn>0, 'excess_consistency_nodes')
        sibling=bytes.fromhex(path[idx])
        if fn&1 or fn==sn:
            old_calc=node(sibling,old_calc)
            new_calc=node(sibling,new_calc)
            while fn!=0 and fn%2==0:
                fn//=2;sn//=2
        else:
            new_calc=node(new_calc,sibling)
        fn//=2;sn//=2
        idx+=1
    require(sn==0 and hmac.compare_digest(old_calc,old) and
            hmac.compare_digest(new_calc,new), 'consistency_root_mismatch')
    return _untrusted_result(m,n,old_calc.hex(),new_calc.hex())

def _untrusted_result(old_size,new_size,old_root,new_root):
    return {'math_valid':True, 'classification':'CONSISTENT_UNTRUSTED_ROOTS',
            'old_size':old_size,'new_size':new_size,
            'computed_old_root_sha256':old_root,'computed_new_root_sha256':new_root,
            'log_origin_signature_verified':False,
            'witness_cosignature_verified':False,
            'historical_checkpoint_authenticated':False,
            'external_epoch_authenticated':False,
            'subject_signer_authorized':False,
            'external_gates_open':0, 'live_allowed':False}

def checkpoint_acceptance(candidate):
    """Evidence procurement checklist, never caller-supplied proof promotion."""
    math=verify_consistency(candidate)
    return {'status':'BLOCKED_EXTERNAL_LOG_AND_WITNESS_NOT_PRESENT',
            'math':math,
            'required':('independently pinned Rekor log root/key',
                        'log signature verified against exact checkpoint bytes',
                        'separate independently pinned witness key and valid cosignature',
                        'external historical checkpoint provenance and anti-rollback storage',
                        'signed trusted time, revocation and subject-signer authorization'),
            'signed_checkpoint_available':False,
            'independent_witness_available':False, 'external_gates_verified':0}

def assess_mrsc_topology(topology):
    """Offline provider-API design validation, no observation of AWS resources."""
    require(type(topology) is dict and topology.keys()==_TOPOLOGY,'topology_schema')
    require(topology['service']=='DYNAMODB' and topology['consistency'] in ('MREC','MRSC'),
            'provider_mode')
    replicas=topology['replicas'];witness=topology['witness_region']
    require(type(replicas) is list and len(replicas) in (2,3) and
            all(type(x) is str and _ID.fullmatch(x) for x in replicas) and
            len(set(replicas))==len(replicas), 'replica_topology')
    require(witness is None or type(witness) is str and _ID.fullmatch(witness), 'witness_region')
    for flag in ('transaction_api','strong_reads','conditional_writes',
                 'restore_drill_verified','independent_admin_verified'):
        require(type(topology[flag]) is bool,'topology_boolean_type')
    require(not topology['restore_drill_verified'] and not topology['independent_admin_verified'],
            'caller_proof_cannot_authorize_remote_service')
    if topology['consistency']=='MREC':
        reason='MREC_LWW_IS_NOT_LINEARIZABLE_CAS'
    elif not (len(replicas)==3 and witness is None or
              len(replicas)==2 and witness is not None and witness not in replicas):
        reason='MRSC_REQUIRES_THREE_DISTINCT_REGIONS'
    elif topology['transaction_api']:
        reason='MRSC_TRANSACTION_API_NOT_SUPPORTED'
    elif not topology['strong_reads'] or not topology['conditional_writes']:
        reason='MRSC_REQUIRES_STRONG_READ_AND_CONDITIONAL_WRITE'
    else:
        reason='MRSC_CANDIDATE_NOT_PROVISIONED_OR_EXTERNALLY_VERIFIED'
    return {'status':'BLOCKED','reason':reason,
            'api_design_compatible':reason.startswith('MRSC_CANDIDATE'),
            'table_provisioned':False,'distinct_admin_verified':False,
            'multi_host_fencing_verified':False,
            'snapshot_restore_resistance_verified':False,
            'remote_cas_verified':False}

def build_inert_cas_request(topology, request):
    """Construct a strongly conditional **UNEXECUTED** single-item update plan.

    Only a separately provisioned MRSC table and verified IAM administrator
    could make it real. A successful conditional write still would NOT prove
    external anti-restore fencing or independent authorisation.
    """
    check=assess_mrsc_topology(topology)
    require(check['api_design_compatible'], 'unsupported_mrsc_service_contract')
    require(type(request) is dict and request.keys()==_CAS, 'cas_request_schema')
    require(request['source_sha']==BASE_SHA, 'cas_source_scope')
    require(type(request['table']) is str and _ID.fullmatch(request['table']) and
            type(request['key']) is str and _ID.fullmatch(request['key']), 'cas_identifiers')
    require(all(nonnegative(request[k]) for k in ('epoch','generation','fence',
                                                  'next_generation','next_fence')),
            'cas_counter_type')
    require(request['epoch']>0 and request['next_generation']==request['generation']+1 and
            request['next_fence']==request['fence']+1 and
            request['generation']<_MAX_TREE and request['fence']<_MAX_TREE,
            'monotone_fence_expected')
    for k in ('expected_root_sha256','new_root_sha256','request_id_sha256'):
        require(hex256(request[k]), 'cas_digest_shape')
    require(request['expected_root_sha256']!=request['new_root_sha256'],
            'same_checkpoint_cannot_advance_fence')
    old={':epoch':{'N':str(request['epoch'])},
         ':generation':{'N':str(request['generation'])},
         ':fence':{'N':str(request['fence'])},
         ':old_root':{'S':request['expected_root_sha256']}}
    new={':next_generation':{'N':str(request['next_generation'])},
         ':next_fence':{'N':str(request['next_fence'])},
         ':new_root':{'S':request['new_root_sha256']},
         ':request_id':{'S':request['request_id_sha256']}}
    names={'#epoch':'epoch','#generation':'generation','#fence':'fence',
           '#root':'root_sha256','#request_id':'request_id_sha256'}
    update={'TableName':request['table'],
            'Key':{'pk':{'S':request['key']}},
            'ConditionExpression':'#epoch = :epoch AND #generation = :generation AND #fence = :fence AND #root = :old_root',
            'UpdateExpression':'SET #generation = :next_generation, #fence = :next_fence, #root = :new_root, #request_id = :request_id',
            'ExpressionAttributeNames':names,
            'ExpressionAttributeValues':{**old,**new},
            'ReturnValues':'ALL_NEW'}
    read={'TableName':request['table'],'Key':{'pk':{'S':request['key']}},
          'ConsistentRead':True}
    raw=json.dumps({'source_sha':BASE_SHA,'request':request,'update':update,'reconcile':read},
                   sort_keys=True,separators=(',',':')).encode('ascii')
    return {'status':'UNEXECUTED_MRSC_REQUEST_NO_AUTH', 'update_item':update,
            'reconcile_get_item':read,
            'request_sha256':hashlib.sha256(b'KRIPTOAI-RC700-CAS-PLAN\x00'+raw).hexdigest(),
            'raw_request_escrow_authorized':False,
            'remote_write_occurred':False, 'remote_ack_authenticated':False,
            'fence_anti_restore_verified':False, 'external_gates_open':0}

def acquire_external_proof_status():
    return {'external_verified':0, 'total':8,
            'gates':tuple({'gate':g,'status':'BLOCKED'} for g in GATES),
            'final':'SEALED','live':'DISABLED','single_fit':'UNUSED',
            'net20':'NOT_TESTED','auth':'NO-GO'}
