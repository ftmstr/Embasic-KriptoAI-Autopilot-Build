"""RC686: strict RFC6962-style inclusion and *claimed* cross-domain anchors.

The mathematical inclusion check does not certify the root's provenance.
Neither caller-provided fingerprints nor two matching witness statements
establish independent authorities, immutable external state, or a provider
signature. This module has no filesystem, network, key, CAS, or trading I/O.
"""
import hashlib
import hmac
import re


class OriginCheckpointRejected(ValueError):
    """Fail closed on malformed claimed origin, inclusion or replay."""


_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_MAX_INT = (1 << 63) - 2
_MAX_LEAVES = 128
_DOMAIN = b"RC686-UNTRUSTED-INCLUSION-CROSS-ORIGIN-V1\x00"
_FIELDS = (
    "repository", "branch", "git_sha", "source_sha256", "workflow_sha256",
    "checkpoint_sha256", "previous_size", "tree_size", "previous_root",
    "tree_root", "leaf_sha256", "leaf_index", "inclusion_path",
    "owner", "reviewer", "provider", "witnesses", "revocations",
    "issued_at", "observed_at", "epoch", "nonce_sha256", "spent_nonces",
    "last_seen", "ack_state", "release_ready", "live_trading_allowed",
)
_PINS = (
    "git_sha", "source_sha256", "workflow_sha256", "checkpoint_sha256",
    "previous_root", "tree_root", "leaf_sha256", "nonce_sha256",
    "owner_fingerprint", "reviewer_fingerprint", "claim_sha256",
    "trusted_owner_origin", "trusted_reviewer_origin", "trusted_provider_origin",
    "trusted_revocations", "trusted_append_only_anchor", "trusted_durable_cas",
)


def _hex(s, n=64):
    return type(s) is str and (_HEX40 if n == 40 else _HEX64).fullmatch(s) is not None


def _positive(x):
    return type(x) is int and 1 <= x <= _MAX_INT


def _id(x):
    return type(x) is str and _NAME.fullmatch(x) is not None


def _hash_node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _leaf_hash(value):
    return hashlib.sha256(b"\x00" + bytes.fromhex(value)).digest()


def _encode(value):
    if type(value) is bool:
        return b"b1" if value else b"b0"
    if type(value) is int and 0 <= value <= _MAX_INT:
        return b"i" + value.to_bytes(8, "big")
    if type(value) is str:
        try:
            raw = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise OriginCheckpointRejected("nonascii fact") from exc
        if len(raw) > 256:
            raise OriginCheckpointRejected("oversize fact")
        return b"s" + len(raw).to_bytes(2, "big") + raw
    if type(value) is tuple and len(value) <= _MAX_LEAVES:
        encoded = [_encode(item) for item in value]
        if sum(map(len, encoded)) > 32768:
            raise OriginCheckpointRejected("oversize evidence")
        return b"t" + len(encoded).to_bytes(2, "big") + b"".join(encoded)
    raise OriginCheckpointRejected("noncanonical fact type")


def inclusion_root(leaf_hex, index, size, audit_path):
    """Rebuild an inclusion root from an *untrusted* leaf and bottom-up path.

    Unlike rebuilding from a supplied full list, this verifies a logarithmic
    proof and rejects too few or too many sibling nodes, even for odd widths.
    A matching root still proves no independently trusted checkpoint.
    """
    if (not _hex(leaf_hex) or type(index) is not int or type(size) is not int
            or not 1 <= size <= _MAX_LEAVES or not 0 <= index < size
            or type(audit_path) is not tuple or len(audit_path) > 8
            or any(not _hex(node) for node in audit_path)):
        raise OriginCheckpointRejected("invalid leaf index, tree width or proof")
    cursor = 0

    def rebuild(offset, width):
        nonlocal cursor
        if width == 1:
            return _leaf_hash(leaf_hex)
        split = 1 << ((width - 1).bit_length() - 1)
        if offset < split:
            nested = rebuild(offset, split)
            if cursor >= len(audit_path):
                raise OriginCheckpointRejected("missing right sibling")
            side = bytes.fromhex(audit_path[cursor])
            cursor += 1
            return _hash_node(nested, side)
        nested = rebuild(offset - split, width - split)
        if cursor >= len(audit_path):
            raise OriginCheckpointRejected("missing left sibling")
        side = bytes.fromhex(audit_path[cursor])
        cursor += 1
        return _hash_node(side, nested)

    result = rebuild(index, size).hex()
    if cursor != len(audit_path):
        raise OriginCheckpointRejected("extra sibling or ambivalent proof")
    return result


def _time_role(role, record, issued, observed):
    if (type(record) is not tuple or len(record) != 6
            or record[0] != role or not _id(record[1]) or not _hex(record[2])
            or not all(_positive(t) for t in record[3:])
            or not record[3] <= record[5] <= record[4]
            or not issued <= record[5] <= observed):
        raise OriginCheckpointRejected("invalid claimed signer role/time/key")


def canonical_claim(claim):
    """Canonical locally consistent claim, never externally authenticated."""
    if type(claim) is not dict or set(claim) != set(_FIELDS):
        raise OriginCheckpointRejected("exact claim schema required")
    if (claim["repository"] != _REPO or claim["branch"] != _BRANCH
            or not _hex(claim["git_sha"], 40)
            or any(not _hex(claim[k]) for k in (
                "source_sha256", "workflow_sha256", "checkpoint_sha256",
                "previous_root", "tree_root", "leaf_sha256", "nonce_sha256"))
            or type(claim["previous_size"]) is not int
            or type(claim["tree_size"]) is not int
            or not 1 <= claim["previous_size"] <= claim["tree_size"] <= _MAX_LEAVES
            or type(claim["leaf_index"]) is not int
            or not all(_positive(claim[k]) for k in (
                "issued_at", "observed_at", "epoch"))
            or claim["issued_at"] > claim["observed_at"]
            or claim["release_ready"] is not False
            or claim["live_trading_allowed"] is not False
            or claim["ack_state"] not in ("NOT_SENT", "ACK_LOST_UNRESOLVED")):
        raise OriginCheckpointRejected("unsafe source or epoch claims")
    if not hmac.compare_digest(inclusion_root(
            claim["leaf_sha256"], claim["leaf_index"],
            claim["tree_size"], claim["inclusion_path"]), claim["tree_root"]):
        raise OriginCheckpointRejected("inclusion root mismatch")
    if (claim["tree_size"] == claim["previous_size"]
            and claim["tree_root"] != claim["previous_root"]):
        raise OriginCheckpointRejected("same-sized Merkle fork")
    for role in ("owner", "reviewer"):
        _time_role(role, claim[role], claim["issued_at"], claim["observed_at"])
    owner, reviewer = claim["owner"], claim["reviewer"]
    if owner[1] == reviewer[1] or owner[2] == reviewer[2]:
        raise OriginCheckpointRejected("owner/reviewer cannot share actor or key")
    revocations = claim["revocations"]
    if (type(revocations) is not tuple or len(revocations) > 128
            or any(type(r) is not tuple or len(r) != 2
                   or not _hex(r[0]) or not _positive(r[1]) for r in revocations)
            or revocations != tuple(sorted(revocations))
            or len(set(x[0] for x in revocations)) != len(revocations)):
        raise OriginCheckpointRejected("ambiguous revocation list")
    if any(k in (owner[2], reviewer[2]) and t <= claim["observed_at"]
           for k, t in revocations):
        raise OriginCheckpointRejected("claimed signer already revoked")
    provider = claim["provider"]
    if (type(provider) is not tuple or len(provider) != 7
            or provider[0] != "github_actions" or not _positive(provider[1])
            or not _positive(provider[2]) or provider[3] != claim["git_sha"]
            or provider[4] != claim["source_sha256"] or not _hex(provider[5])
            or provider[6] != "UNVERIFIED"):
        raise OriginCheckpointRejected("unverifiable provider identity")
    witnesses = claim["witnesses"]
    if (type(witnesses) is not tuple or len(witnesses) != 2
            or any(type(row) is not tuple or len(row) != 6 for row in witnesses)):
        raise OriginCheckpointRejected("exactly two claimed witness records")
    for ix, item in enumerate(witnesses):
        domain, ident, fingerprint, size, root, provider_sha = item
        if (domain != ("owner_domain", "reviewer_domain")[ix]
                or not _id(ident) or not _hex(fingerprint)
                or type(size) is not int or size != claim["tree_size"]
                or root != claim["tree_root"] or provider_sha != provider[5]):
            raise OriginCheckpointRejected("cross-witness size/root/log binding")
    if witnesses[0][1] == witnesses[1][1] or witnesses[0][2] == witnesses[1][2]:
        raise OriginCheckpointRejected("duplicate witness identities")
    if (witnesses[0][2] in (owner[2], reviewer[2])
            or witnesses[1][2] in (owner[2], reviewer[2])):
        raise OriginCheckpointRejected("witness must not reuse signer fingerprint")
    nonces = claim["spent_nonces"]
    if (type(nonces) is not tuple or len(nonces) > 128
            or any(not _hex(x) for x in nonces)
            or tuple(sorted(set(nonces))) != nonces
            or claim["nonce_sha256"] in nonces):
        raise OriginCheckpointRejected("replay or noncanonical nonce history")
    previous_epoch, previous_size, previous_root = claim["last_seen"] if (
        type(claim["last_seen"]) is tuple and len(claim["last_seen"]) == 3
    ) else (None, None, None)
    if (type(previous_epoch) is not int or not 1 <= previous_epoch < claim["epoch"]
            or type(previous_size) is not int
            or previous_size != claim["previous_size"]
            or not _hex(previous_root) or previous_root != claim["previous_root"]):
        raise OriginCheckpointRejected("claimed epoch ABA or rollback")
    return _DOMAIN + _encode(tuple((name, claim[name]) for name in _FIELDS))


def quarantine_inclusion(claim, pins):
    """Reject all self-elevation; return ONLY mathematical/syntactic results."""
    msg = canonical_claim(claim)
    if type(pins) is not dict or set(pins) != set(_PINS):
        raise OriginCheckpointRejected("exact out-of-band pin schema required")
    for key in ("git_sha", "source_sha256", "workflow_sha256", "checkpoint_sha256",
                "previous_root", "tree_root", "leaf_sha256", "nonce_sha256"):
        if not _hex(pins[key], 40 if key == "git_sha" else 64) or not hmac.compare_digest(
                pins[key], claim[key]):
            raise OriginCheckpointRejected("unbound source or checkpoint pin")
    for role in ("owner", "reviewer"):
        fingerprint = pins[role + "_fingerprint"]
        if not _hex(fingerprint) or fingerprint != claim[role][2]:
            raise OriginCheckpointRejected("unbound signer fingerprint")
    if (not _hex(pins["claim_sha256"]) or not hmac.compare_digest(
            pins["claim_sha256"], hashlib.sha256(msg).hexdigest())):
        raise OriginCheckpointRejected("unbound canonical transcript")
    for name in _PINS[11:]:
        if pins[name] is not False:
            raise OriginCheckpointRejected("caller cannot claim authenticated origin")
    return {
        "status": "MERKLE_INCLUSION_EQUATION_VALID_ORIGIN_UNAUTHENTICATED",
        "inclusion_equation_valid": True,
        "claim_sha256": hashlib.sha256(msg).hexdigest(),
        "claimed_ack_lost": claim["ack_state"] == "ACK_LOST_UNRESOLVED",
        "owner_authority_authenticated": False,
        "reviewer_authority_authenticated": False,
        "provider_signature_authenticated": False,
        "revocation_origin_authenticated": False,
        "external_immutable_anchor_authenticated": False,
        "merkle_consistency_history_authenticated": False,
        "durable_cas_verified": False,
        "restart_recovery_verified": False,
        "trusted_clock_verified": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }

# RC686 final acceptance barrier: mathematical inclusion is not provider origin.
# Two caller-named witnesses and local SQLite tests cannot authorize LIVE,
# certify out-of-band signer keys, or supply a durable external CAS anchor.
