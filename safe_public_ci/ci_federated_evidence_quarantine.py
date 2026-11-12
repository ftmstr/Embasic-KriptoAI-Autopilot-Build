"""RC687 — finite cross-domain evidence/equivocation quarantine, not authentication.

All keys, administrative domains, provider records, times, receipts and anchors
come from one caller. This is ONLY mathematical/structural anomaly detection.
No filesystem, HTTP, secret, trading, real issuer trust or persistence exists.
"""
import hashlib
import hmac
import re


class FederatedEvidenceRejected(ValueError):
    """Syntactically inconsistent or unsafe fabricated cross-domain evidence."""


_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_H40 = re.compile(r"[a-f0-9]{40}\Z")
_H64 = re.compile(r"[a-f0-9]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_MAX = 2**63 - 2
_DOMAIN = b"RC687-FEDERATED-UNTRUSTED-EVIDENCE-V1\x00"
_FIELDS = (
    "repository", "branch", "git_sha", "workflow_sha256", "source_sha256",
    "roster_sha256", "previous_checkpoint_sha256", "history", "old_size",
    "new_size", "old_root_sha256", "new_root_sha256", "inclusion_index",
    "inclusion_path", "consistency_path", "epoch", "nonce_sha256",
    "issued_at", "observed_at", "principals", "revocations", "providers",
    "witnesses", "cas_trace", "used_nonces", "prior_roots", "ack_state",
    "release_ready", "live_trading_allowed",
)
_PINS = (
    "git_sha", "workflow_sha256", "source_sha256", "roster_sha256",
    "previous_checkpoint_sha256", "old_root_sha256", "new_root_sha256",
    "nonce_sha256", "principals_sha256", "witnesses_sha256", "claim_sha256",
    "out_of_band_keys_authenticated", "provider_signature_authenticated",
    "revocation_origin_authenticated", "external_checkpoint_authenticated",
    "durable_cas_authenticated",
)


def _hex(s, n=64):
    return type(s) is str and (_H40 if n == 40 else _H64).fullmatch(s) is not None


def _num(x):
    return type(x) is int and 1 <= x <= _MAX


def _id(x):
    return type(x) is str and _NAME.fullmatch(x) is not None


def _node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _leaf(item):
    return hashlib.sha256(b"\x00" + bytes.fromhex(item)).digest()


def _root(history):
    if len(history) == 1:
        return _leaf(history[0])
    k = 1 << ((len(history) - 1).bit_length() - 1)
    return _node(_root(history[:k]), _root(history[k:]))


def _inclusion(history, index):
    if len(history) == 1:
        return ()
    k = 1 << ((len(history) - 1).bit_length() - 1)
    if index < k:
        return (*_inclusion(history[:k], index), _root(history[k:]).hex())
    return (*_inclusion(history[k:], index - k), _root(history[:k]).hex())


def _consistency(history, old):
    def walk(items, count, canonical):
        if count == len(items):
            return () if canonical else (_root(items).hex(),)
        k = 1 << ((len(items) - 1).bit_length() - 1)
        if count <= k:
            return (*walk(items[:k], count, canonical), _root(items[k:]).hex())
        return (*walk(items[k:], count-k, False), _root(items[:k]).hex())
    return walk(history, old, True)


def _pack(item):
    if type(item) is bool:
        return b"B1" if item else b"B0"
    if type(item) is int and 0 <= item <= _MAX:
        return b"I" + item.to_bytes(8, "big")
    if type(item) is str:
        try:
            raw = item.encode("ascii")
        except UnicodeError as exc:
            raise FederatedEvidenceRejected("nonascii evidence text") from exc
        if len(raw) > 256:
            raise FederatedEvidenceRejected("oversized evidence text")
        return b"S" + len(raw).to_bytes(2, "big") + raw
    if type(item) is tuple and len(item) <= 128:
        return b"T" + len(item).to_bytes(2, "big") + b"".join(_pack(x) for x in item)
    raise FederatedEvidenceRejected("noncanonical evidence type")


def _digest(item):
    return hashlib.sha256(_pack(item)).hexdigest()


def evidence_bytes(claim):
    """Canonical claim bytes, caller supplied; NOT a signed provider receipt."""
    if type(claim) is not dict or set(claim) != set(_FIELDS):
        raise FederatedEvidenceRejected("exact evidence schema required")
    if (claim["repository"] != _REPO or claim["branch"] != _BRANCH or
            not _hex(claim["git_sha"], 40) or
            any(not _hex(claim[x]) for x in (
                "workflow_sha256", "source_sha256", "roster_sha256",
                "previous_checkpoint_sha256", "old_root_sha256",
                "new_root_sha256", "nonce_sha256")) or
            any(not _num(claim[x]) for x in (
                "old_size", "new_size", "epoch", "issued_at", "observed_at")) or
            not claim["old_size"] < claim["new_size"] <= 128 or
            claim["issued_at"] > claim["observed_at"] or
            claim["release_ready"] is not False or
            claim["live_trading_allowed"] is not False or
            claim["ack_state"] not in ("NOT_SENT", "ACK_LOST_UNRESOLVED") or
            type(claim["ack_state"]) is not str):
        raise FederatedEvidenceRejected("source/time/size/release mismatch")
    history = claim["history"]
    if (type(history) is not tuple or len(history) != claim["new_size"] or
            any(not _hex(x) for x in history) or len(set(history)) != len(history)):
        raise FederatedEvidenceRejected("full history missing, duplicate or malformed")
    old = _root(history[:claim["old_size"]]).hex()
    new = _root(history).hex()
    if (not hmac.compare_digest(old, claim["old_root_sha256"]) or
            not hmac.compare_digest(new, claim["new_root_sha256"]) or old == new):
        raise FederatedEvidenceRejected("Merkle root does not match full history")
    idx = claim["inclusion_index"]
    if type(idx) is not int or not 0 <= idx < len(history):
        raise FederatedEvidenceRejected("invalid inclusion index")
    proof = claim["inclusion_path"]
    consistency = claim["consistency_path"]
    if (type(proof) is not tuple or type(consistency) is not tuple or
            any(not _hex(x) for x in (*proof, *consistency)) or
            len(proof) > 8 or len(consistency) > 8 or
            proof != _inclusion(history, idx) or
            consistency != _consistency(history, claim["old_size"])):
        raise FederatedEvidenceRejected("invalid independently recomputed proof")
    principals = claim["principals"]
    if type(principals) is not tuple or len(principals) != 2:
        raise FederatedEvidenceRejected("owner and independent reviewer claims required")
    for i, row in enumerate(principals):
        if (type(row) is not tuple or len(row) != 7):
            raise FederatedEvidenceRejected("invalid claimed principal record")
        role, actor, pubkey, admin, first, last, signed = row
        if (role != ("owner", "independent_reviewer")[i] or not _id(actor) or
                not _hex(pubkey) or not _id(admin) or
                any(not _num(n) for n in (first, last, signed)) or
                not first <= signed <= last or
                not claim["issued_at"] <= signed <= claim["observed_at"]):
            raise FederatedEvidenceRejected("invalid role or claimed signer chronology")
    if (principals[0][1] == principals[1][1] or
            principals[0][2] == principals[1][2] or
            principals[0][3] == principals[1][3]):
        raise FederatedEvidenceRejected("shared caller-stated actor, key or domain")
    revocations = claim["revocations"]
    if (type(revocations) is not tuple or len(revocations) > 128 or
            revocations != tuple(sorted(revocations)) or
            any(type(x) is not tuple or len(x) != 3 or not _hex(x[0]) or
                not _num(x[1]) or not _num(x[2]) for x in revocations) or
            len({x[0] for x in revocations}) != len(revocations)):
        raise FederatedEvidenceRejected("bad claimed revocation ledger")
    fingerprints = tuple(hashlib.sha256(bytes.fromhex(p[2])).hexdigest() for p in principals)
    if any(key in fingerprints and effective <= claim["observed_at"]
           for key, _, effective in revocations):
        raise FederatedEvidenceRejected("synthetically revoked signer")
    providers = claim["providers"]
    if type(providers) is not tuple or len(providers) != 2:
        raise FederatedEvidenceRejected("both claimed provider records required")
    for i, row in enumerate(providers):
        if (type(row) is not tuple or len(row) != 8):
            raise FederatedEvidenceRejected("invalid provider record")
        os, run, job, commit, source, workflow, log, status = row
        if (os != ("ubuntu", "windows")[i] or not _num(run) or not _num(job) or
                commit != claim["git_sha"] or source != claim["source_sha256"] or
                workflow != claim["workflow_sha256"] or not _hex(log) or
                status != "UNVERIFIED"):
            raise FederatedEvidenceRejected("falsely authenticated provider claim")
    if providers[0][1] == providers[1][1] or providers[0][2] == providers[1][2]:
        raise FederatedEvidenceRejected("duplicate provider run/job")
    combined_log = _digest(tuple(p[6] for p in providers))
    witnesses = claim["witnesses"]
    if type(witnesses) is not tuple or len(witnesses) != 2:
        raise FederatedEvidenceRejected("two witness assertions required")
    for i, row in enumerate(witnesses):
        if type(row) is not tuple or len(row) != 6:
            raise FederatedEvidenceRejected("malformed witness assertion")
        name, admin, epoch, root, logs, state = row
        if (not _id(name) or not _id(admin) or epoch != claim["epoch"] or
                root != new or logs != combined_log or state != "UNVERIFIED"):
            raise FederatedEvidenceRejected("conflicting or false witness statement")
    if witnesses[0][0] == witnesses[1][0] or witnesses[0][1] == witnesses[1][1]:
        raise FederatedEvidenceRejected("identical claimed witness/domain")
    cas = claim["cas_trace"]
    if (type(cas) is not tuple or len(cas) != 3 or
            len({x[0] for x in cas if type(x) is tuple and len(x) == 7}) != 3):
        raise FederatedEvidenceRejected("missing independent race candidates")
    for i, row in enumerate(cas):
        if type(row) is not tuple or len(row) != 7:
            raise FederatedEvidenceRejected("invalid CAS receipt")
        actor, epoch, generation, prior, nextroot, nonce, state = row
        if (not _id(actor) or epoch != claim["epoch"] + i or
                generation != claim["old_size"] or prior != old or
                nextroot != new or nonce != claim["nonce_sha256"] or
                state != ("CLAIMED_WIN" if i == 0 else "CLAIMED_CONFLICT")):
            raise FederatedEvidenceRejected("ABA/rollback/double winner receipt")
    for key in ("used_nonces", "prior_roots"):
        records = claim[key]
        if (type(records) is not tuple or len(records) > 128 or
                any(not _hex(x) for x in records) or
                records != tuple(sorted(set(records)))):
            raise FederatedEvidenceRejected("noncanonical replay history")
    if (claim["nonce_sha256"] in claim["used_nonces"] or
            new in claim["prior_roots"]):
        raise FederatedEvidenceRejected("replayed receipt or root")
    return _DOMAIN + _pack(tuple((name, claim[name]) for name in _FIELDS))


def quarantine_cross_domain(claim, asserted_pins):
    """Never authenticates issuer/provider/witness/clock or persistent state."""
    data = evidence_bytes(claim)
    if type(asserted_pins) is not dict or set(asserted_pins) != set(_PINS):
        raise FederatedEvidenceRejected("exact caller pin schema required")
    for name in ("git_sha", "workflow_sha256", "source_sha256", "roster_sha256",
                 "previous_checkpoint_sha256", "old_root_sha256", "new_root_sha256",
                 "nonce_sha256"):
        if (not _hex(asserted_pins[name], 40 if name == "git_sha" else 64) or
                not hmac.compare_digest(asserted_pins[name], claim[name])):
            raise FederatedEvidenceRejected("mismatched caller pin")
    fingerprints = tuple(hashlib.sha256(bytes.fromhex(x[2])).hexdigest() for x in claim["principals"])
    if (type(asserted_pins["principals_sha256"]) is not str or
            not hmac.compare_digest(asserted_pins["principals_sha256"], _digest(fingerprints)) or
            type(asserted_pins["witnesses_sha256"]) is not str or
            not hmac.compare_digest(asserted_pins["witnesses_sha256"], _digest(claim["witnesses"])) or
            type(asserted_pins["claim_sha256"]) is not str or
            not hmac.compare_digest(asserted_pins["claim_sha256"], hashlib.sha256(data).hexdigest())):
        raise FederatedEvidenceRejected("unbound principal, witness or claim")
    for flag in ("out_of_band_keys_authenticated", "provider_signature_authenticated",
                 "revocation_origin_authenticated", "external_checkpoint_authenticated",
                 "durable_cas_authenticated"):
        if asserted_pins[flag] is not False:
            raise FederatedEvidenceRejected("caller cannot self-certify security gates")
    return {
        "status": "COHERENT_CROSS_DOMAIN_CLAIMS_ORIGIN_UNAUTHENTICATED",
        "synthetic_claim_digest": hashlib.sha256(data).hexdigest(),
        "lost_ack_unresolved": claim["ack_state"] == "ACK_LOST_UNRESOLVED",
        "owner_reviewer_authority_authenticated": False,
        "independent_key_distribution_authenticated": False,
        "provider_signed_log_authenticated": False,
        "revocation_and_trusted_time_authenticated": False,
        "external_merkle_checkpoint_authenticated": False,
        "witness_administrative_independence_authenticated": False,
        "persistent_atomic_cas_verified": False,
        "restart_anti_rollback_verified": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }


def compare_quarantined_claims(first, second):
    """Find a split-view *claim*; cannot verify that its origins are real."""
    left = evidence_bytes(first)
    right = evidence_bytes(second)
    if (first["repository"], first["branch"], first["epoch"],
            first["old_size"], first["old_root_sha256"]) != (
            second["repository"], second["branch"], second["epoch"],
            second["old_size"], second["old_root_sha256"]):
        return "INCOMPARABLE_UNAUTHENTICATED_EPOCHS"
    if first["new_root_sha256"] != second["new_root_sha256"]:
        return "CLAIMED_MERKLE_SPLIT_VIEW_ORIGIN_UNAUTHENTICATED"
    if first["providers"] != second["providers"]:
        return "CLAIMED_PROVIDER_RECEIPT_SPLIT_VIEW_ORIGIN_UNAUTHENTICATED"
    if left != right:
        return "CLAIMED_TRANSCRIPT_FORK_ORIGIN_UNAUTHENTICATED"
    return "EQUAL_CALLER_SUPPLIED_CLAIMS_ORIGIN_UNAUTHENTICATED"
