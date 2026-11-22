"""RC689: detect finite claimed witness forks and fencing-token anomalies.

Every signer, provider, clock and append-only anchor is supplied by an untrusted
caller. Structural checks are NOT Ed25519 validation, external attestation,
independent trust or a durable production CAS implementation. No I/O.
"""
import hashlib
import hmac
import re


class QuarantineRejected(ValueError):
    """Malformed or unsafe evidence; fail closed."""


_H64 = re.compile(r"[0-9a-f]{64}\Z")
_H128 = re.compile(r"[0-9a-f]{128}\Z")
_ID = re.compile(r"[a-z][a-z0-9_]{2,31}\Z")
_DOMAIN = b"RC689-UNTRUSTED-QUORUM-FENCE-V1\x00"
_MAX = (1 << 63) - 1
_FIELDS = frozenset({"repo", "branch", "head", "issued", "witnesses", "providers",
                     "rotation", "revocations", "checkpoints", "fence", "ack",
                     "claims_authenticated", "allow_live"})
_W = frozenset({"id", "fingerprint", "seq", "epoch", "root", "prev_receipt",
                "signer_role", "signature", "reported_at"})
_P = frozenset({"platform", "run", "job", "attempt", "log_sha256", "signed_receipt",
                "provider_key_fingerprint"})
_C = frozenset({"size", "root", "old_size", "old_root", "history", "inclusion_index",
                "inclusion_leaf", "inclusion_proof", "external_anchor"})
_F = frozenset({"generation", "token", "lease_epoch", "previous_token", "nonce",
                "outbox_sequence", "writer_id", "ack_state"})
_ACK = frozenset({"provider", "nonce", "outbox_sequence", "claimed_ack_sha256",
                  "ack_authorized"})


def _check(ok, reason):
    if not ok:
        raise QuarantineRejected(reason)


def _hex(s, length=64):
    return type(s) is str and (_H128 if length == 128 else _H64).fullmatch(s) is not None


def _id(s):
    return type(s) is str and _ID.fullmatch(s) is not None


def _number(x):
    return type(x) is int and 0 <= x <= _MAX


def _positive(x):
    return _number(x) and x > 0


def _exact(obj, fields):
    return type(obj) is dict and obj.keys() == fields


def _leaf(h):
    return hashlib.sha256(b"\x00" + bytes.fromhex(h)).digest()


def _parent(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _root(items):
    _check(type(items) is list and 1 <= len(items) <= 32 and
           all(_hex(x) for x in items), "invalid bounded leaf history")
    if len(items) == 1:
        return _leaf(items[0]).hex()
    k = 1 << ((len(items) - 1).bit_length() - 1)
    return _parent(bytes.fromhex(_root(items[:k])), bytes.fromhex(_root(items[k:]))).hex()


def _inclusion(items, index):
    """Canonical RFC6962-style inclusion siblings for an invented full history."""
    _check(_number(index) and index < len(items), "invalid inclusion index")
    if len(items) == 1:
        return []
    k = 1 << ((len(items) - 1).bit_length() - 1)
    if index < k:
        return _inclusion(items[:k], index) + [_root(items[k:])]
    return _inclusion(items[k:], index - k) + [_root(items[:k])]


def _pack_atom(v):
    if type(v) is str:
        _check(v.isascii() and len(v) <= 500, "non-ascii/oversized atom")
        payload = b"s" + v.encode("ascii")
    elif type(v) is int:
        _check(_number(v), "invalid integer atom")
        payload = b"i" + str(v).encode("ascii")
    elif type(v) is bool:
        payload = b"b1" if v else b"b0"
    elif v is None:
        payload = b"n"
    elif type(v) in (tuple, list):
        _check(len(v) <= 128, "oversized list atom")
        payload = b"l" + str(len(v)).encode("ascii") + b":" + b"".join(
            _pack_atom(x) for x in v)
    elif type(v) is dict:
        _check(len(v) <= 32 and all(type(k) is str for k in v), "invalid map")
        payload = b"d" + str(len(v)).encode("ascii") + b":" + b"".join(
            _pack_atom(k) + _pack_atom(v[k]) for k in sorted(v))
    else:
        raise QuarantineRejected("unsupported noncanonical atom")
    return len(payload).to_bytes(4, "big") + payload


def _check_witnesses(witnesses):
    _check(type(witnesses) is list and len(witnesses) == 3, "need three claimed witnesses")
    ids, keys, receipts = set(), set(), set()
    for w in witnesses:
        _check(_exact(w, _W) and _id(w["id"]) and _hex(w["fingerprint"]) and
               _positive(w["seq"]) and _positive(w["epoch"]) and
               _hex(w["root"]) and _hex(w["prev_receipt"]) and
               w["signer_role"] in ("owner", "reviewer", "observer") and
               _hex(w["signature"], 128) and _positive(w["reported_at"]),
               "malformed witness claim")
        _check(w["id"] not in ids and w["fingerprint"] not in keys and
               w["signature"] not in receipts, "duplicate claimed identity/key/signature")
        ids.add(w["id"])
        keys.add(w["fingerprint"])
        receipts.add(w["signature"])
    _check({w["signer_role"] for w in witnesses} == {"owner", "reviewer", "observer"},
           "missing distinct claimed signer roles")
    return ids, keys


def _check_providers(providers):
    _check(type(providers) is list and len(providers) == 2, "need both claimed provider runs")
    platform, receipts, keys = set(), set(), set()
    for p in providers:
        _check(_exact(p, _P) and p["platform"] in ("ubuntu", "windows") and
               _positive(p["run"]) and _positive(p["job"]) and
               type(p["attempt"]) is int and p["attempt"] == 1 and
               _hex(p["log_sha256"]) and _hex(p["signed_receipt"], 128) and
               _hex(p["provider_key_fingerprint"]), "bad provider claim")
        _check(p["platform"] not in platform and p["signed_receipt"] not in receipts and
               p["provider_key_fingerprint"] not in keys, "duplicate claimed provider")
        platform.add(p["platform"])
        receipts.add(p["signed_receipt"])
        keys.add(p["provider_key_fingerprint"])
    _check(platform == {"ubuntu", "windows"}, "missing claimed platform")
    return keys


def _check_checkpoint(cp):
    _check(_exact(cp, _C), "checkpoint schema")
    hist = cp["history"]
    _check(type(hist) is list and 2 <= len(hist) <= 32 and
           len(hist) == cp["size"] and _number(cp["old_size"]) and
           1 <= cp["old_size"] < cp["size"] and all(_hex(x) for x in hist),
           "checkpoint sizes/history")
    _check(_hex(cp["root"]) and _hex(cp["old_root"]) and
           _hex(cp["inclusion_leaf"]) and _number(cp["inclusion_index"]) and
           cp["inclusion_index"] < len(hist) and type(cp["inclusion_proof"]) is list and
           type(cp["external_anchor"]) is str and _hex(cp["external_anchor"]),
           "malformed checkpoint input")
    _check(hmac.compare_digest(_root(hist), cp["root"]) and
           hmac.compare_digest(_root(hist[:cp["old_size"]]), cp["old_root"]),
           "invalid prefix consistency root")
    i = cp["inclusion_index"]
    _check(hist[i] == cp["inclusion_leaf"] and
           cp["inclusion_proof"] == _inclusion(hist, i),
           "invalid inclusion path or leaf")
    # Caller-supplied anchor is intentionally NOT an independent trusted root.
    _check(cp["external_anchor"] == cp["root"], "external claimed anchor mismatch")


def _check_fence(f, ack):
    _check(_exact(f, _F) and _exact(ack, _ACK), "CAS/ACK schema")
    _check(_positive(f["generation"]) and _positive(f["lease_epoch"]) and
           _positive(f["outbox_sequence"]) and _id(f["writer_id"]) and
           _hex(f["token"]) and _hex(f["previous_token"]) and
           f["token"] != f["previous_token"] and _hex(f["nonce"]) and
           f["ack_state"] in ("pending", "lost_ack", "claimed_ack"),
           "invalid lease/fence claim")
    _check(ack["provider"] in ("ubuntu", "windows") and
           _hex(ack["nonce"]) and _positive(ack["outbox_sequence"]) and
           _hex(ack["claimed_ack_sha256"]) and ack["ack_authorized"] is False and
           ack["nonce"] == f["nonce"] and
           ack["outbox_sequence"] == f["outbox_sequence"],
           "untrusted/mismatched ACK")
    _check(f["ack_state"] != "claimed_ack" or ack["ack_authorized"] is False,
           "unverified acknowledged claim")


def evaluate_untrusted_bundle(b, pins):
    """Accept bounded *claims*, never authenticate those claims or permit trading."""
    _check(_exact(b, _FIELDS), "bundle schema")
    _check(type(pins) is dict and pins.keys() == {"repo", "branch", "head", "expected_sha256",
           "trust_root_authenticated", "provider_signature_authenticated",
           "immutable_anchor_authenticated", "durable_cas_authenticated"}, "pin schema")
    _check(b["repo"] == pins["repo"] == "ftmstr/Embasic-KriptoAI-Autopilot-Build" and
           b["branch"] == pins["branch"] == "validation/rc654-pr1-rc653-combined-ci" and
           _hex(b["head"]) is False and type(b["head"]) is str and
           re.fullmatch(r"[a-f0-9]{40}", b["head"]) is not None and
           b["head"] == pins["head"] and _positive(b["issued"]) and
           b["claims_authenticated"] is False and b["allow_live"] is False,
           "untrusted repo or forbidden authorization")
    _check(all(pins[k] is False for k in ("trust_root_authenticated",
           "provider_signature_authenticated", "immutable_anchor_authenticated",
           "durable_cas_authenticated")), "self-declared trust rejected")
    _, keys = _check_witnesses(b["witnesses"])
    provider_keys = _check_providers(b["providers"])
    _check(keys.isdisjoint(provider_keys), "one fake signer presented as two domains")
    _check(type(b["rotation"]) is list and len(b["rotation"]) == 2 and
           all(_hex(x) for x in b["rotation"]) and len(set(b["rotation"])) == 2,
           "claimed key rotation")
    _check(type(b["revocations"]) is list and len(b["revocations"]) <= 4 and
           all(type(x) is dict and x.keys() == {"fingerprint", "revoked_at"} and
               _hex(x["fingerprint"]) and _positive(x["revoked_at"]) for x in b["revocations"]),
           "revocation declaration")
    _check(len({r["fingerprint"] for r in b["revocations"]}) == len(b["revocations"]),
           "duplicate revocation")
    _check_checkpoint(b["checkpoints"])
    _check_fence(b["fence"], b["ack"])
    _check(all(w["root"] == b["checkpoints"]["root"] for w in b["witnesses"]),
           "split-view within one claimed bundle")
    for w in b["witnesses"]:
        _check(not any(w["fingerprint"] == r["fingerprint"] and
                       w["reported_at"] >= r["revoked_at"] for r in b["revocations"]),
               "self-reported already revoked signing key")
    blob = _DOMAIN + _pack_atom(b)
    digest = hashlib.sha256(blob).hexdigest()
    _check(_hex(pins["expected_sha256"]) and
           hmac.compare_digest(digest, pins["expected_sha256"]),
           "full transcript digest mismatch")
    return {"claim_sha256": digest,
            "status": "CONSISTENT_CALLER_CLAIMS_QUARANTINED_NOT_AUTHENTICATED",
            "ed25519_owner_reviewer_authenticated": False,
            "provider_signed_log_authenticated": False,
            "revocation_clock_authenticated": False,
            "external_merkle_anchor_authenticated": False,
            "independent_gossip_authenticated": False,
            "durable_multihost_cas_verified": False,
            "lost_ack_resolved": False,
            "release_ready": False,
            "live_trading_allowed": False}


def claimed_digest(b):
    """Compute a deterministic untrusted commitment; not an authorization."""
    return hashlib.sha256(_DOMAIN + _pack_atom(b)).hexdigest()


def detect_claimed_fork(left, right):
    """Return a structural fork category, never a real-world authentication."""
    _check(type(left) is dict and type(right) is dict and
           left.keys() == right.keys() == {"witness", "fingerprint", "seq", "epoch",
                                            "root", "provider_log", "nonce", "token"},
           "fork-view schema")
    for view in (left, right):
        _check(_id(view["witness"]) and _hex(view["fingerprint"]) and
               _positive(view["seq"]) and _positive(view["epoch"]) and
               all(_hex(view[n]) for n in ("root", "provider_log", "nonce", "token")),
               "invalid view")
    _check(left["witness"] == right["witness"] and
           left["fingerprint"] == right["fingerprint"],
           "different identities cannot form same-witness fork")
    if left["seq"] == right["seq"] and left["epoch"] == right["epoch"]:
        if left["root"] != right["root"]:
            category = "CLAIMED_MERKLE_EQUIVOCATION"
        elif left["provider_log"] != right["provider_log"]:
            category = "CLAIMED_PROVIDER_LOG_EQUIVOCATION"
        elif left["token"] != right["token"]:
            category = "CLAIMED_FENCE_TOKEN_EQUIVOCATION"
        elif left["nonce"] != right["nonce"]:
            category = "CLAIMED_NONCE_REPLAY_FORK"
        else:
            category = "SAME_UNTRUSTED_VIEW"
    elif left["epoch"] != right["epoch"]:
        category = "UNAUTHENTICATED_EPOCH_TRANSITION"
    else:
        category = "UNAUTHENTICATED_SEQUENCE_TRANSITION"
    return {"category": category, "witness_authority_authenticated": False,
            "immutable_checkpoint_authenticated": False,
            "provider_origin_authenticated": False,
            "live_trading_allowed": False}
