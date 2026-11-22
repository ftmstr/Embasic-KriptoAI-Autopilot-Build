"""RC692: bounded synthetic cross-domain chain-of-custody quarantine.

All purported keys, role controllers, Ed25519 signatures, provider logs,
revocation times, witness domains and third-party checkpoints are untrusted
caller inputs. Neither digest matching nor a consistent Merkle tree establishes
independent key provenance, network evidence or persistent cross-host CAS.
No filesystem, SQLite, network, signing, trading, fitting or clock side effects.
"""
import hashlib
import hmac
import re


class CustodyRejected(ValueError):
    """Unbounded, malformed or self-authorizing synthetic claim."""


_REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
_BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
_HEX40 = re.compile(r'[a-f0-9]{40}\Z')
_HEX64 = re.compile(r'[a-f0-9]{64}\Z')
_HEX128 = re.compile(r'[a-f0-9]{128}\Z')
_SLUG = re.compile(r'[a-z][a-z0-9_-]{0,39}\Z')
_MAX = (1 << 63) - 2
_FIELDS = frozenset(('repository','branch','source_sha','workflow_sha256',
                     'epoch','observed_at','authorities','revocations','providers',
                     'history','witnesses','gossip','anchor','journal','release'))
_AUTH = frozenset(('role','controller','fingerprint','ed25519_public_hex',
                   'signed_at','valid_from','valid_to','signature_hex'))
_REVOKE = frozenset(('fingerprint','effective_at','reason','claimed_authorizer'))
_PROVIDER = frozenset(('os','run','job','attempt','head_sha','workflow_sha256',
                       'full_log_sha256','job_sha256','signed_receipt_sha256',
                       'signature_hex','controller'))
_HISTORY = frozenset(('leaves','old_size','old_root','root','included_index',
                      'inclusion_proof','consistency_proof'))
_WITNESS = frozenset(('id','domain','controller','epoch','root','receipt_sha256',
                      'signature_hex'))
_GOSSIP = frozenset(('from','to','epoch','root','receipt_sha256'))
_ANCHOR = frozenset(('claimed_service','root','epoch','time','immutable_verified'))
_JOURNAL = frozenset(('epoch','generation','next_generation','fence','next_fence',
                       'nonce_sha256','state','ack_sha256','provider_seen',
                       'external_cas_verified','snapshot_root'))
_RELEASE = frozenset(('authenticated','live','final','fitted','net20_tested'))


def _require(v, msg):
    if not v:
        raise CustodyRejected(msg)


def _keys(v, expected, label):
    _require(type(v) is dict and v.keys() == expected, label + ': exact fields required')


def _hex(v, n=64):
    if type(v) is not str:
        return False
    return {40:_HEX40,64:_HEX64,128:_HEX128}[n].fullmatch(v) is not None


def _name(v):
    return type(v) is str and _SLUG.fullmatch(v) is not None


def _n(v, zero=False):
    return type(v) is int and (0 if zero else 1) <= v <= _MAX


def _h(data):
    return hashlib.sha256(data).digest()


def _root(items):
    _require(type(items) in (list,tuple) and 1 <= len(items) <= 128, 'tree size')
    if len(items) == 1:
        return _h(b'\x00' + bytes.fromhex(items[0]))
    k = 1 << ((len(items) - 1).bit_length() - 1)
    return _h(b'\x01' + _root(items[:k]) + _root(items[k:]))


def inclusion_proof(leaves, index):
    """Mathematical proof only; does NOT identify an independent tree operator."""
    _require(type(index) is int and 0 <= index < len(leaves), 'index')
    def walk(items, i):
        if len(items) == 1:
            return ()
        k = 1 << ((len(items) - 1).bit_length() - 1)
        if i < k:
            return (*walk(items[:k], i), _root(items[k:]).hex())
        return (*walk(items[k:], i-k), _root(items[:k]).hex())
    return walk(leaves,index)


def consistency_proof(leaves, old_size):
    """RFC6962-style prefix proof computed from caller-provided full history."""
    _require(type(old_size) is int and 1 <= old_size <= len(leaves), 'old size')
    def walk(items, n, complete):
        if n == len(items):
            return () if complete else (_root(items).hex(),)
        k = 1 << ((len(items) - 1).bit_length() - 1)
        if n <= k:
            return (*walk(items[:k],n,complete), _root(items[k:]).hex())
        return (*walk(items[k:],n-k,False), _root(items[:k]).hex())
    return walk(leaves,old_size,True)


def validate_claim(d):
    """Reject invalid syntax/mathematics; ALWAYS return unauthenticated."""
    _keys(d,_FIELDS,'claim')
    _require(d['repository'] == _REPO and d['branch'] == _BRANCH, 'wrong repo/ref')
    _require(_hex(d['source_sha'],40) and _hex(d['workflow_sha256']), 'source pin')
    epoch, observed = d['epoch'],d['observed_at']
    _require(_n(epoch) and _n(observed), 'epoch/clock type')

    authorities = d['authorities']
    _require(type(authorities) is list and len(authorities)==2, 'owner and reviewer')
    roles, controllers, fps, pubkeys = set(),set(),set(),set()
    for a in authorities:
        _keys(a,_AUTH,'authority')
        _require(a['role'] in ('owner','reviewer') and a['role'] not in roles, 'role')
        _require(_name(a['controller']) and a['controller'] not in controllers, 'controller')
        _require(_hex(a['fingerprint']) and a['fingerprint'] not in fps, 'fingerprint')
        _require(_hex(a['ed25519_public_hex']) and a['ed25519_public_hex'] not in pubkeys, 'claimed public key')
        _require(_hex(a['signature_hex'],128), 'syntactic signature')
        _require(all(_n(a[t]) for t in ('signed_at','valid_from','valid_to')), 'authority clocks')
        _require(a['valid_from'] <= a['signed_at'] <= a['valid_to'] and a['signed_at'] <= observed, 'key issuance window')
        roles.add(a['role']); controllers.add(a['controller']);fps.add(a['fingerprint']);pubkeys.add(a['ed25519_public_hex'])
    _require(roles == {'owner','reviewer'},'missing role')

    rev = d['revocations']
    _require(type(rev) is list and len(rev) <= 2, 'bounded revocations')
    revoked=set()
    for r in rev:
        _keys(r,_REVOKE,'revocation')
        _require(_hex(r['fingerprint']) and r['fingerprint'] in fps and r['fingerprint'] not in revoked, 'revocation target')
        _require(_name(r['reason']) and r['reason'] in ('lost','rotation','compromise'), 'revocation reason')
        _require(_name(r['claimed_authorizer']) and r['claimed_authorizer'] in controllers, 'claimed revoker')
        _require(_n(r['effective_at']), 'revocation clock')
        a=next(x for x in authorities if x['fingerprint']==r['fingerprint'])
        _require(r['effective_at'] > a['signed_at'] and r['effective_at'] > observed, 'claimed authority revoked at observation')
        revoked.add(r['fingerprint'])

    providers=d['providers']
    _require(type(providers) is list and len(providers)==2,'two provider claims')
    oses=set();pairs=set();provider_controllers=set()
    for p in providers:
        _keys(p,_PROVIDER,'provider')
        _require(p['os'] in ('ubuntu','windows') and p['os'] not in oses, 'provider os')
        _require(_n(p['run']) and _n(p['job']) and type(p['attempt']) is int and p['attempt']==1, 'job/run/attempt')
        _require((p['run'],p['job']) not in pairs, 'duplicate run/job')
        _require(_name(p['controller']) and p['controller'] not in provider_controllers, 'claimed provider independence')
        _require(p['head_sha'] == d['source_sha'] and p['workflow_sha256']==d['workflow_sha256'], 'provider pin mismatch')
        _require(all(_hex(p[x]) for x in ('full_log_sha256','job_sha256','signed_receipt_sha256')), 'provider digest')
        _require(_hex(p['signature_hex'],128), 'claimed provider signature')
        oses.add(p['os']);pairs.add((p['run'],p['job']));provider_controllers.add(p['controller'])
    _require(oses == {'ubuntu','windows'}, 'missing OS')

    h=d['history'];_keys(h,_HISTORY,'history')
    leaves=h['leaves'];_require(type(leaves) is list and 2<=len(leaves)<=128,'history bounds')
    _require(all(_hex(v) for v in leaves), 'leaf encodings')
    _require(_n(h['old_size']) and h['old_size'] < len(leaves), 'strict growth')
    _require(_n(h['included_index'],True) and h['included_index'] < len(leaves), 'index')
    _require(_hex(h['old_root']) and _hex(h['root']), 'roots')
    _require(hmac.compare_digest(h['old_root'],_root(leaves[:h['old_size']]).hex()),'old claimed root mismatch')
    _require(hmac.compare_digest(h['root'],_root(leaves).hex()), 'new claimed root mismatch')
    _require(type(h['inclusion_proof']) is list and h['inclusion_proof']==list(inclusion_proof(leaves,h['included_index'])),'inclusion math')
    _require(type(h['consistency_proof']) is list and h['consistency_proof']==list(consistency_proof(leaves,h['old_size'])),'prefix math')

    witnesses=d['witnesses']
    _require(type(witnesses) is list and len(witnesses)==3, 'three claimed witnesses')
    ids=set();domains=set();wcontrollers=set()
    for w in witnesses:
        _keys(w,_WITNESS,'witness')
        _require(_name(w['id']) and w['id'] not in ids, 'witness id')
        _require(_name(w['domain']) and w['domain'] not in domains, 'witness domain')
        _require(_name(w['controller']) and w['controller'] not in wcontrollers, 'witness controller')
        _require(w['epoch']==epoch and w['root']==h['root'], 'witness view fork')
        _require(_hex(w['receipt_sha256']) and _hex(w['signature_hex'],128), 'witness signed claim syntax')
        ids.add(w['id']);domains.add(w['domain']);wcontrollers.add(w['controller'])
    g=d['gossip']
    _require(type(g) is list and len(g)==6, 'full directed claimed gossip graph')
    edges=set()
    for r in g:
        _keys(r,_GOSSIP,'gossip')
        pair=(r['from'],r['to'])
        _require(r['from'] in ids and r['to'] in ids and pair[0]!=pair[1] and pair not in edges, 'gossip edge')
        _require(r['root']==h['root'] and r['epoch']==epoch and _hex(r['receipt_sha256']), 'gossip view')
        edges.add(pair)
    _require(len(edges)==6,'directed complete gossip')

    anchor=d['anchor'];_keys(anchor,_ANCHOR,'anchor')
    _require(_name(anchor['claimed_service']) and anchor['claimed_service']=='caller_only', 'no external service')
    _require(anchor['root']==h['root'] and anchor['epoch']==epoch and _n(anchor['time']) and anchor['time']>=observed, 'anchor claim')
    _require(anchor['immutable_verified'] is False,'no immutable external checkpoint authority')

    j=d['journal'];_keys(j,_JOURNAL,'journal')
    _require(j['epoch']==epoch and _n(j['generation']) and _n(j['next_generation']) and j['next_generation']==j['generation']+1, 'generation CAS')
    _require(_n(j['fence']) and _n(j['next_fence']) and j['next_fence']>j['fence'], 'fencing')
    _require(_hex(j['nonce_sha256']) and j['state']=='PENDING' and j['ack_sha256'] is None, 'outbox is not an ACK')
    _require(j['provider_seen'] is False and j['external_cas_verified'] is False, 'external CAS unauthorized')
    _require(j['snapshot_root']==h['old_root'], 'snapshot basis')

    release=d['release'];_keys(release,_RELEASE,'release')
    _require(all(release[k] is False for k in _RELEASE), 'never promote synthetic evidence')
    return {'status':'QUARANTINED_CLAIM_ONLY_NOT_AUTHENTICATED',
            'merkle_math':'CONSISTENT_CALLER_SUPPLIED_HISTORY',
            'ed25519_origin_verified':False,'provider_origin_verified':False,
            'trusted_revocation_clock':False,'immutable_external_checkpoint':False,
            'production_multihost_cas_verified':False,'remote_ack_verified':False,
            'release_ready':False,'live_trading_allowed':False}


def compare_views(left,right):
    """Classify two *self-claimed* valid views, never verify genuine provenance."""
    validate_claim(left);validate_claim(right)
    if left['source_sha'] != right['source_sha'] or left['workflow_sha256'] != right['workflow_sha256']:
        return 'CLAIMED_BUILD_PIN_FORK_NOT_AUTHENTICATED'
    if left['epoch'] == right['epoch'] and left['history']['root'] != right['history']['root']:
        return 'CLAIMED_SAME_EPOCH_MERKLE_FORK_NOT_AUTHENTICATED'
    if left['epoch'] == right['epoch'] and [x['full_log_sha256'] for x in left['providers']] != [x['full_log_sha256'] for x in right['providers']]:
        return 'CLAIMED_PROVIDER_FULL_LOG_FORK_NOT_AUTHENTICATED'
    if left['epoch'] == right['epoch'] and [x['receipt_sha256'] for x in left['witnesses']] != [x['receipt_sha256'] for x in right['witnesses']]:
        return 'CLAIMED_GOSSIP_RECEIPT_FORK_NOT_AUTHENTICATED'
    if left['journal']['nonce_sha256'] == right['journal']['nonce_sha256'] and left['journal']['generation'] != right['journal']['generation']:
        return 'CLAIMED_NONCE_ABA_REPLAY_NOT_AUTHENTICATED'
    if left['epoch']!=right['epoch']:
        return 'CLAIMED_DIFFERENT_EPOCH_NO_EXTERNAL_CONSISTENCY'
    return 'CLAIMED_EQUAL_VIEWS_NOT_AUTHENTICATED'
