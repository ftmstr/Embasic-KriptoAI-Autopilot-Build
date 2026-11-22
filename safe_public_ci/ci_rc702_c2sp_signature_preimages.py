"""RC702: exact C2SP Ed25519 log and witness preimage acquisition.

This is a *quarantine formatter*, not a signature verifier. All key bytes,
key IDs, signatures and timestamps are untrusted until a separately pinned,
independent cryptographic verifier validates them. No IO, networking or trading.
"""
import hashlib
import hmac
import json
import re

from safe_public_ci import ci_rc701_external_custody as custody

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = '164a8a9b27bad27e92778790e61b3e430d630b85'
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[A-Za-z0-9._/-]{1,128}\Z')
SIGN_LINE = re.compile(r'\u2014 ([A-Za-z0-9._/-]{1,128}) ([A-Za-z0-9+/]+={0,2})\n\Z')
REQUEST_KEYS = frozenset(('repository','branch','source_sha','challenge_sha256',
                          'nonce_sha256','audience','note_b64','log_name',
                          'log_public_key_hex','witness_name','witness_public_key_hex',
                          'old_size','old_root_sha256','consistency_proof_sha256'))

class EvidenceRejected(ValueError):
    """Invalid untrusted checkpoint candidate or asserted authority."""

def ensure(ok, reason):
    if not ok:
        raise EvidenceRejected(reason)

def is64(value):
    return type(value) is str and HEX64.fullmatch(value) is not None

def _split_checkpoint(raw):
    ensure(type(raw) is bytes and len(raw)<=65536, 'note_type_or_size')
    try:
        text=raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise EvidenceRejected('note_utf8') from exc
    ensure('\r' not in text and '\x00' not in text and '\t' not in text,
           'note_controls')
    point=raw.rfind(b'\n\n')
    ensure(point>0 and point<len(raw)-2, 'note_separator')
    note_body=raw[:point+1]
    lines=note_body.decode('utf-8').splitlines()
    ensure(len(lines)==3, 'checkpoint_extensions_unreviewed')
    origin, decimal, root64 = lines
    ensure(bool(NAME.fullmatch(origin)) and decimal.isascii() and
           re.fullmatch(r'[1-9][0-9]{0,18}', decimal) is not None and
           int(decimal) <= (2**63-1), 'checkpoint_origin_or_size')
    root=custody.b64_bytes(root64, 32)
    ensure(len(root)==32, 'checkpoint_root_bytes')
    signature_lines=raw[point+2:].decode('utf-8').splitlines(keepends=True)
    ensure(1<=len(signature_lines)<=32, 'signature_line_count')
    signatures=[]
    for line in signature_lines:
        m=SIGN_LINE.fullmatch(line)
        ensure(m is not None, 'signature_line_syntax')
        payload=custody.b64_bytes(m.group(2), 8192)
        ensure(len(payload)>=5, 'signature_envelope_length')
        signatures.append((m.group(1),payload))
    return {'origin':origin,'size':int(decimal),'root':root,
            'body':note_body,'signatures':signatures}

def key_identifier(name, public_key, algorithm):
    """Compute C2SP 32-bit key ID from *untrusted candidate* key material."""
    ensure(type(name) is str and NAME.fullmatch(name) is not None,'key_name')
    ensure(type(public_key) is bytes and len(public_key)==32,'ed25519_public_key_size')
    ensure(type(algorithm) is int and algorithm in (1,4), 'key_algorithm')
    return hashlib.sha256(name.encode('utf-8')+b'\n'+bytes([algorithm])+public_key).digest()[:4]

def prepare_signature_handoff(request):
    """Bind exact two signature preimages; NEVER verify origin or signature."""
    ensure(type(request) is dict and request.keys()==REQUEST_KEYS,'handoff_schema')
    ensure(request['repository']==REPO and request['branch']==BRANCH and
           request['source_sha']==BASE_SHA, 'handoff_scope')
    for key in ('challenge_sha256','nonce_sha256','old_root_sha256',
                'consistency_proof_sha256'):
        ensure(is64(request[key]), 'handoff_sha256')
    ensure(request['challenge_sha256']!=request['nonce_sha256'],'replay_nonce')
    ensure(request['audience']=='INDEPENDENT_EXTERNAL_VERIFIER','audience')
    ensure(type(request['log_name']) is str and NAME.fullmatch(request['log_name']) is not None and
           type(request['witness_name']) is str and NAME.fullmatch(request['witness_name']) is not None and
           request['log_name']!=request['witness_name'],'independent_names')
    ensure(type(request['old_size']) is int and 0<request['old_size']<=2**63-1,
           'historical_size')
    ensure(type(request['note_b64']) is str,'note_encoding')
    try:
        note=custody.b64_bytes(request['note_b64'],65536)
    except custody.CustodyRejected as exc:
        raise EvidenceRejected('invalid_note_encoding') from exc
    for key in ('log_public_key_hex','witness_public_key_hex'):
        ensure(is64(request[key]),'untrusted_candidate_key_shape')
    log_key=bytes.fromhex(request['log_public_key_hex'])
    witness_key=bytes.fromhex(request['witness_public_key_hex'])
    ensure(not hmac.compare_digest(log_key,witness_key),'same_candidate_key')
    parsed=_split_checkpoint(note)
    ensure(parsed['origin']==request['log_name'],'checkpoint_log_name')
    ensure(parsed['size']>=request['old_size'],'old_root_rollback')
    if parsed['size']==request['old_size']:
        ensure(hmac.compare_digest(parsed['root'].hex(),request['old_root_sha256']),
               'same_size_split_view')
    log_id=key_identifier(request['log_name'],log_key,1)
    witness_id=key_identifier(request['witness_name'],witness_key,4)
    log_sigs=[];wit_sigs=[]
    for name, payload in parsed['signatures']:
        if name==request['log_name'] and hmac.compare_digest(payload[:4],log_id):
            ensure(len(payload)==68,'log_signature_length')
            log_sigs.append(payload[4:])
        if name==request['witness_name'] and hmac.compare_digest(payload[:4],witness_id):
            ensure(len(payload)==76,'witness_signature_length')
            tick=int.from_bytes(payload[4:12],'big')
            ensure(tick<=2**63-1,'untrusted_witness_timestamp_range')
            wit_sigs.append((tick,payload[12:]))
    ensure(len(log_sigs)==1 and len(wit_sigs)==1,'expected_candidate_signatures_missing')
    timestamp, witness_sig=wit_sigs[0]
    witness_preimage=(b'cosignature/v1\ntime '+str(timestamp).encode('ascii')+
                      b'\n'+parsed['body'])
    # Note's body includes its final newline but NOT the separating empty line.
    log_preimage=parsed['body']
    canonical=json.dumps(request,sort_keys=True,separators=(',',':'),
                         ensure_ascii=True).encode('ascii')
    return {'status':'SIGNATURE_PREIMAGES_ONLY_NO_VERIFICATION',
            'handoff_sha256':hashlib.sha256(b'RC702-UNTRUSTED-PREIMAGE\x00'+canonical).hexdigest(),
            'note_sha256':hashlib.sha256(note).hexdigest(),
            'log_preimage_sha256':hashlib.sha256(log_preimage).hexdigest(),
            'witness_preimage_sha256':hashlib.sha256(witness_preimage).hexdigest(),
            'log_signature_sha256':hashlib.sha256(log_sigs[0]).hexdigest(),
            'witness_signature_sha256':hashlib.sha256(witness_sig).hexdigest(),
            'witness_timestamp_claim':timestamp,
            'tree_size':parsed['size'],'tree_root_sha256':parsed['root'].hex(),
            'candidate_log_key_id':log_id.hex(),
            'candidate_witness_key_id':witness_id.hex(),
            'requires':('independent out-of-band Ed25519 log key pin',
                        'cryptographic Ed25519 Verify over exact log preimage',
                        'different-admin Ed25519 witness pin and signature verification',
                        'externally authenticated historical root and RFC6962 consistency',
                        'trusted non-rewindable time and signed revocation record',
                        'provider-origin RAW full Ubuntu+Windows job-log signatures',
                        'durable multi-host fenced CAS and authenticated remote ACK'),
            'log_signature_verified':False,
            'witness_signature_verified':False,
            'key_ownership_verified':False,
            'independent_historical_consistency_verified':False,
            'external_proofs_verified':0,
            'auth':'NO-GO','live':'DISABLED'}
