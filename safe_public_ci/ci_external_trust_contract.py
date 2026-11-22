"""RC693/TUR50: offline *contract requirements*, never provider authentication.

No external keys, signed GitHub runs, independent log, trusted clock, durable
cross-host CAS or remotely signed exchange ACK were obtained.  Every input is
caller-controlled, and all success/trading/authentication indicators stay false.
"""
import hashlib
import hmac
import re


class ContractRejected(ValueError):
    """Invalid claimed chain of custody; caller claims confer no authority."""


_REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
_BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
_H40 = re.compile(r'[0-9a-f]{40}\Z')
_H64 = re.compile(r'[0-9a-f]{64}\Z')
_IDENT = re.compile(r'[a-z][a-z0-9_-]{2,62}\Z')
_MAX = 2**63 - 1
_GATES = (
    'owner_oob_key', 'reviewer_oob_key', 'provider_ubuntu_attestation',
    'provider_windows_attestation', 'revocation_trusted_time',
    'external_immutable_checkpoint', 'external_antirollback_cas',
    'remote_provider_ack',
)
_REQUIRED = (
    'separately obtained owner Ed25519 public-key fingerprint, offline custody and signed delegation',
    'independently obtained reviewer Ed25519 public-key fingerprint and authority delegation',
    'provider-issued signature binding Ubuntu run ID, job ID, exact workflow, source SHA and FULL log bytes',
    'provider-issued signature binding Windows run ID, job ID, exact workflow, source SHA and FULL log bytes',
    'independent revocation evidence with validated chronology and trusted external clock',
    'third-party append-only checkpoint, independently anchored and consistency-verified',
    'separate administrator / failure domain with monotone CAS, rollback and split-brain defense',
    'remote recipient/exchange authenticated idempotency and ACK reconciliation contract',
)
_PACKET = frozenset(('repository', 'branch', 'source_sha', 'epoch', 'history', 'claims', 'gossip', 'journal', 'release'))
_HISTORY = frozenset(('leaves', 'previous_size', 'previous_root', 'current_root', 'included_index', 'inclusion_path'))
_CLAIM = frozenset(('kind', 'controller', 'control_domain', 'source_sha', 'full_log_digest',
                    'receipt_sha', 'signature_hex', 'issued_at', 'expires_at', 'run_id', 'job_id',
                    'attempt', 'revoked_at', 'claimed_external'))
_GOSSIP = frozenset(('from_domain', 'to_domain', 'epoch', 'root', 'receipt_sha'))
_JOURNAL = frozenset(('old_generation','new_generation','old_fence','new_fence',
                      'nonce_sha','pending_outbox_sha','claimed_ack','remote_ack_verified',
                      'external_cas_verified','immutable_checkpoint_verified'))
_RELEASE = frozenset(('authenticated','live','final','fitted','net20_tested'))


def _must(value, label):
    if not value:
        raise ContractRejected(label)


def _keys(d, ks):
    return type(d) is dict and d.keys() == ks


def _hex(v, n=64):
    return type(v) is str and (_H40 if n == 40 else _H64).fullmatch(v) is not None


def _id(v):
    return type(v) is str and _IDENT.fullmatch(v) is not None


def _num(v):
    return type(v) is int and 0 <= v <= _MAX


def _pos(v):
    return type(v) is int and 0 < v <= _MAX


def _sha(b):
    return hashlib.sha256(b).digest()


def _merkle(leaves):
    """RFC6962-style binary domain separation, *only* for claimed local bytes."""
    if len(leaves) == 1:
        return _sha(b'\x00' + bytes.fromhex(leaves[0]))
    half = 1 << ((len(leaves)-1).bit_length()-1)
    return _sha(b'\x01' + _merkle(leaves[:half]) + _merkle(leaves[half:]))


def inclusion_path(leaves, index):
    _must(type(leaves) is list and 1 <= len(leaves) <= 128 and all(_hex(x) for x in leaves),'leaves')
    _must(_num(index) and index < len(leaves),'index')
    if len(leaves) == 1:
        return []
    half = 1 << ((len(leaves)-1).bit_length()-1)
    if index < half:
        return inclusion_path(leaves[:half],index)+[_merkle(leaves[half:]).hex()]
    return inclusion_path(leaves[half:],index-half)+[_merkle(leaves[:half]).hex()]


def contract_matrix():
    """Concrete missing real evidence; no fabricated identities or approvals."""
    return tuple(dict(kind=k, required_external_evidence=v, source='NOT_ACQUIRED',
                      externally_verified=False, gate='BLOCKED') for k,v in zip(_GATES,_REQUIRED))


def audit(packet):
    """Validate finite *assertions*; explicitly NEVER authenticate them."""
    _must(_keys(packet,_PACKET),'packet-fields')
    _must(packet['repository']==_REPO and packet['branch']==_BRANCH,'scope')
    _must(_hex(packet['source_sha'],40),'source-pin')
    _must(_pos(packet['epoch']),'epoch')
    h=packet['history']
    _must(_keys(h,_HISTORY),'history-fields')
    leaves=h['leaves']
    _must(type(leaves) is list and 2<=len(leaves)<=128 and all(_hex(x) for x in leaves),'leaf-digests')
    _must(_pos(h['previous_size']) and h['previous_size']<len(leaves),'previous-size')
    _must(_num(h['included_index']) and h['included_index']<len(leaves),'included-index')
    _must(_hex(h['previous_root']) and _hex(h['current_root']),'root-digest')
    _must(h['previous_root']==_merkle(leaves[:h['previous_size']]).hex(),'false-prefix')
    _must(h['current_root']==_merkle(leaves).hex(),'false-root')
    _must(type(h['inclusion_path']) is list and h['inclusion_path']==inclusion_path(leaves,h['included_index']),'false-inclusion')
    claims=packet['claims']
    _must(type(claims) is list and len(claims)==len(_GATES),'claim-cardinality')
    domains=[];controllers=[];kinds=[]
    for c in claims:
        _must(_keys(c,_CLAIM),'claim-fields')
        _must(c['kind'] in _GATES,'claim-kind')
        _must(_id(c['controller']) and _id(c['control_domain']),'claimed-controller-domain')
        _must(_hex(c['source_sha'],40) and c['source_sha']==packet['source_sha'],'claim-build-pin')
        _must(all(_hex(c[f]) for f in ('full_log_digest','receipt_sha')),'claim-digest')
        _must(type(c['signature_hex']) is str and re.fullmatch(r'[0-9a-f]{128}\Z',c['signature_hex']) is not None,'signature-syntax')
        _must(_pos(c['issued_at']) and _pos(c['expires_at']) and c['issued_at']<c['expires_at'],'claimed-clock-window')
        _must(c['revoked_at'] is None or (_pos(c['revoked_at']) and c['revoked_at']>=c['issued_at']),'claimed-revocation')
        _must(_pos(c['run_id']) and _pos(c['job_id']) and _pos(c['attempt']),'claimed-run-job')
        _must(c['claimed_external'] is False,'external-authority-self-promotion')
        domains.append(c['control_domain']);controllers.append(c['controller']);kinds.append(c['kind'])
    _must(set(kinds)==set(_GATES),'missing-or-duplicated-gate')
    _must(len(set(domains))==len(_GATES) and len(set(controllers))==len(_GATES),'self-review-or-same-declared-domain')
    _must(set(domains).isdisjoint(set(controllers)),'declared-domain-actor-confusion')
    # Five distinct offline roles must not be made to look authentic by a common receipt.
    _must(len({c['receipt_sha'] for c in claims})==len(_GATES),'recycled-claim-receipt')
    g=packet['gossip']
    witness=domains[:3]
    _must(type(g) is list and len(g)==6,'gossip-cardinality')
    edge=set()
    for e in g:
        _must(_keys(e,_GOSSIP),'gossip-fields')
        _must(e['from_domain'] in witness and e['to_domain'] in witness and e['from_domain']!=e['to_domain'],'gossip-endpoints')
        _must(e['epoch']==packet['epoch'] and type(e['epoch']) is int,'gossip-epoch')
        _must(e['root']==h['current_root'] and _hex(e['receipt_sha']),'gossip-root-receipt')
        pair=(e['from_domain'],e['to_domain'])
        _must(pair not in edge,'duplicate-gossip-edge')
        edge.add(pair)
    _must(edge=={(x,y) for x in witness for y in witness if x!=y},'missing-gossip-edge')
    j=packet['journal']
    _must(_keys(j,_JOURNAL),'journal-fields')
    _must(_num(j['old_generation']) and _num(j['new_generation']) and j['new_generation']==j['old_generation']+1,'generation-fence')
    _must(_num(j['old_fence']) and _num(j['new_fence']) and j['new_fence']>j['old_fence'],'token-fence')
    _must(_hex(j['nonce_sha']) and _hex(j['pending_outbox_sha']),'journal-hashes')
    _must(j['claimed_ack'] is None and j['remote_ack_verified'] is False and j['external_cas_verified'] is False and j['immutable_checkpoint_verified'] is False,'forbidden-evidence-escalation')
    r=packet['release']
    _must(_keys(r,_RELEASE) and all(r[x] is False for x in _RELEASE),'release-self-promotion')
    # Content address binds each canonical scalar but not any externally trusted signer.
    transcript=b'RC693/UNTRUSTED/CLAIMS/V1\x00'
    for c in claims:
        for value in (c['kind'],c['control_domain'],c['source_sha'],c['full_log_digest'],c['receipt_sha']):
            b=value.encode('ascii'); transcript+=len(b).to_bytes(2,'big')+b
    return {'status':'CLAIM_ONLY_QUARANTINED','claimed_digest':_sha(transcript).hex(),
            'required_external_gates':len(_GATES),'independently_verified_gates':0,
            'authenticated':False,'release_ready':False,'live_trading_allowed':False,
            'durable_multihost_cas_verified':False,'provider_ack_verified':False,
            'merkle_authority_verified':False,'ed25519_origin_verified':False,
            'trusted_revocation_verified':False}


def compare_claims(left,right):
    audit(left);audit(right)
    if left['source_sha']!=right['source_sha']:
        return 'CLAIMED_SOURCE_FORK_NO_AUTH'
    if left['epoch']!=right['epoch']:
        return 'CLAIMED_EPOCH_GAP_NO_EXTERNAL_CLOCK'
    if left['history']['current_root']!=right['history']['current_root']:
        return 'CLAIMED_MERKLE_SPLIT_VIEW_NO_AUTH'
    for a,b in zip(left['claims'],right['claims']):
        if a['full_log_digest']!=b['full_log_digest']:
            return 'CLAIMED_PROVIDER_OR_KEY_RECEIPT_FORK_NO_AUTH'
    for a,b in zip(left['gossip'],right['gossip']):
        if a['receipt_sha']!=b['receipt_sha']:
            return 'CLAIMED_GOSSIP_EQUIVOCATION_NO_AUTH'
    if left['journal']['nonce_sha']==right['journal']['nonce_sha'] and left['journal']['old_generation']!=right['journal']['old_generation']:
        return 'CLAIMED_NONCE_ABA_NO_EXTERNAL_FENCE'
    if left['journal']['old_generation']!=right['journal']['old_generation']:
        return 'CLAIMED_GENERATION_GAP_NO_EXTERNAL_FENCE'
    return 'CLAIMED_VIEWS_EQUAL_BUT_UNAUTHENTICATED'


# Fail-closed by construction: claims are not Ed25519 signatures verified against
# independently sourced owner/reviewer keys or provider-origin signed log bytes.
# A correct Merkle equation does not attest who published or controlled the root.
# No real external anti-rollback CAS and no authenticated exchange ACK exist here.
