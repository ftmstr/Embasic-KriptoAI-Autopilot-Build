"""RC690: bounded cross-audience claimed checkpoint and lease fencing quarantine.

This module checks structural math and typed claims ONLY.  The owner, reviewer,
provider, witnesses and anchors are wholly supplied by an untrusted caller.
Their names, fingerprints, signatures and digests are NOT verified identities.
No real key handling, trusted clock, network, filesystem or exchange client.
"""
import hashlib
import hmac
import re


class AudienceRejected(ValueError):
    """Malformed, self-promoting or contradictory purported evidence."""


_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_H40 = re.compile(r"[0-9a-f]{40}\Z")
_H64 = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_TOKEN = re.compile(r"[a-z][a-z0-9_/-]{0,63}\Z")
_MAX = (1 << 63) - 1
_SENTINEL = b"RC690-CLAIMED-AUDIENCE-RECEIPT-V1\x00"
_FIELDS = frozenset((
    "repository", "branch", "source_sha", "source_digest", "roster_digest",
    "workflow_digest", "previous", "current", "leaves", "included_index",
    "inclusion_path", "prefix_proof", "authorities", "revocations",
    "providers", "witnesses", "gossip", "anchor", "fence", "release",
))
_AUTH = frozenset(("role", "subject", "pubkey", "fingerprint", "since", "until"))
_PROVIDER = frozenset(("os", "run", "job", "attempt", "log_sha256", "source_sha", "workflow_digest", "signed_claim"))
_WITNESS = frozenset(("id", "domain", "epoch", "size", "root", "time", "receipt_digest"))


def _require(ok, reason):
    if not ok:
        raise AudienceRejected(reason)


def _hex(x, length=64):
    return type(x) is str and (_H40 if length == 40 else _H64).fullmatch(x) is not None


def _pos(x):
    return type(x) is int and 0 < x <= _MAX


def _zero(x):
    return type(x) is int and 0 <= x <= _MAX


def _name(x):
    return type(x) is str and _NAME.fullmatch(x) is not None


def _keys(x, expected):
    return type(x) is dict and x.keys() == expected


def _sha(x):
    return hashlib.sha256(x).hexdigest()


def _root(leaves):
    """RFC6962-type split to largest strict power of two (bounded leaves)."""
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + bytes.fromhex(leaves[0])).digest()
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + _root(leaves[:k]) + _root(leaves[k:])).digest()


def _inclusion(leaves, index):
    if len(leaves) == 1:
        return ()
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < k:
        return (*_inclusion(leaves[:k], index), _root(leaves[k:]).hex())
    return (*_inclusion(leaves[k:], index-k), _root(leaves[:k]).hex())


def _consistency(leaves, old):
    """Compute deterministic RFC6962-style consistency path from full leaves.

    This does NOT make a root externally authenticated.
    """
    def path(part, prefix_size, known):
        if prefix_size == len(part):
            return () if known else (_root(part).hex(),)
        k = 1 << ((len(part) - 1).bit_length() - 1)
        if prefix_size <= k:
            return (*path(part[:k], prefix_size, known), _root(part[k:]).hex())
        return (*path(part[k:], prefix_size - k, False), _root(part[:k]).hex())
    return path(leaves, old, True)


def _encode(x, depth=0):
    _require(depth <= 9, "recursive claim")
    if type(x) is bool:
        return b"T" if x else b"F"
    if type(x) is int:
        _require(0 <= x <= _MAX, "bad number")
        return b"I" + str(x).encode("ascii") + b";"
    if type(x) is str:
        _require(x.isascii(), "non-ASCII untrusted claim")
        b = x.encode("ascii")
        _require(len(b) <= 2048, "oversized string")
        return b"S" + len(b).to_bytes(4, "big") + b
    if type(x) in (list, tuple):
        _require(len(x) <= 256, "oversized sequence")
        return b"L" + len(x).to_bytes(2, "big") + b"".join(_encode(v, depth+1) for v in x)
    if type(x) is dict:
        _require(len(x) <= 32 and all(type(k) is str for k in x), "bad mapping")
        return b"D" + len(x).to_bytes(2, "big") + b"".join(
            _encode(k, depth+1) + _encode(x[k], depth+1) for k in sorted(x))
    raise AudienceRejected("noncanonical type")


def claimed_digest(claim):
    """Stable digest of an untrusted claim, NOT an authentication receipt."""
    return _sha(_SENTINEL + _encode(claim))


def validate_claim(payload, *, expected):
    """Reject malformed or self-promoting records; never return AUTHENTICATED."""
    _require(_keys(payload, _FIELDS), "unexpected top-level keys")
    _require(payload["repository"] == _REPO and payload["branch"] == _BRANCH, "wrong origin scope")
    _require(type(expected) is dict and set(expected) == {
        "source_sha", "source_digest", "roster_digest", "workflow_digest",
        "previous_root", "current_root", "commit_digest"}, "invalid expected pins")
    _require(_hex(payload["source_sha"], 40), "bad source identity")
    for field in ("source_sha", "source_digest", "roster_digest", "workflow_digest"):
        _require(_hex(payload[field], 40 if field == "source_sha" else 64), "bad digest")
        _require(payload[field] == expected[field], "mismatched source pin")
    for key in ("previous_root", "current_root", "commit_digest"):
        _require(_hex(expected[key]), "bad expected pin")

    old, new, leaves = payload["previous"], payload["current"], payload["leaves"]
    _require(_keys(old, {"size", "root", "epoch"}) and _keys(new, {"size", "root", "epoch"}), "invalid checkpoint")
    _require(_pos(old["size"]) and _pos(new["size"]) and old["size"] < new["size"] <= 128, "invalid sizes")
    _require(_pos(old["epoch"]) and _pos(new["epoch"]) and old["epoch"] < new["epoch"], "epoch rollback")
    _require(type(leaves) is list and len(leaves) == new["size"] and all(_hex(x) for x in leaves), "unbounded leaves")
    _require(_hex(old["root"]) and _hex(new["root"]), "invalid roots")
    _require(hmac.compare_digest(_root(leaves[:old["size"]]).hex(), old["root"]), "inconsistent old root")
    _require(hmac.compare_digest(_root(leaves).hex(), new["root"]), "inconsistent new root")
    _require(old["root"] == expected["previous_root"] and new["root"] == expected["current_root"], "untrusted root pin")
    idx = payload["included_index"]
    _require(_zero(idx) and idx < len(leaves), "bad included index")
    _require(type(payload["inclusion_path"]) is list and tuple(payload["inclusion_path"]) == _inclusion(leaves, idx), "bad inclusion proof")
    _require(type(payload["prefix_proof"]) is list and tuple(payload["prefix_proof"]) == _consistency(leaves, old["size"]), "bad prefix proof")

    auth = payload["authorities"]
    _require(type(auth) is list and len(auth) == 2, "require claimed owner and reviewer")
    roles, fingerprints, subjects = set(), set(), set()
    for item in auth:
        _require(_keys(item, _AUTH), "bad authority keys")
        _require(item["role"] in ("owner", "reviewer") and item["role"] not in roles, "duplicate role")
        _require(_name(item["subject"]) and item["subject"] not in subjects, "duplicate actor")
        _require(_hex(item["pubkey"]) and _hex(item["fingerprint"]), "bad advertised key")
        _require(item["fingerprint"] not in fingerprints and item["fingerprint"] == _sha(bytes.fromhex(item["pubkey"])), "key claim mismatch")
        _require(_pos(item["since"]) and _pos(item["until"]) and item["since"] < item["until"], "invalid authority window")
        roles.add(item["role"]); subjects.add(item["subject"]); fingerprints.add(item["fingerprint"])
    _require(roles == {"owner", "reviewer"}, "incomplete roles")
    rev = payload["revocations"]
    _require(type(rev) is list and len(rev) <= 8, "unbounded revocation claims")
    seen_rev = set()
    for r in rev:
        _require(_keys(r, {"fingerprint", "at", "issuer"}) and _hex(r["fingerprint"]), "bad revocation")
        _require(_pos(r["at"]) and _name(r["issuer"]) and r["fingerprint"] not in seen_rev, "revocation replay")
        seen_rev.add(r["fingerprint"])
    for a in auth:
        _require(a["fingerprint"] not in seen_rev, "advertised signer revoked")

    providers = payload["providers"]
    _require(type(providers) is list and len(providers) == 2, "provider pair missing")
    seen_os, seen_job = set(), set()
    for provider in providers:
        _require(_keys(provider, _PROVIDER) and provider["os"] in ("ubuntu", "windows"), "invalid provider shape")
        _require(provider["os"] not in seen_os and _pos(provider["run"]) and _pos(provider["job"]) and
                 type(provider["attempt"]) is int and provider["attempt"] == 1, "duplicate provider / attempt")
        _require((provider["run"], provider["job"]) not in seen_job, "duplicated job")
        _require(_hex(provider["log_sha256"]) and provider["source_sha"] == expected["source_sha"] and
                 provider["workflow_digest"] == expected["workflow_digest"] and
                 provider["signed_claim"] is False, "fake signed provider claim")
        seen_os.add(provider["os"]); seen_job.add((provider["run"],provider["job"]))
    _require(seen_os == {"ubuntu", "windows"}, "wrong provider pair")

    witnesses = payload["witnesses"]
    _require(type(witnesses) is list and len(witnesses) == 3, "three claimed witness domains needed")
    ids, domains, receipts = set(), set(), set()
    for w in witnesses:
        _require(_keys(w, _WITNESS), "witness key mismatch")
        _require(_name(w["id"]) and _name(w["domain"]) and w["id"] not in ids and w["domain"] not in domains,
                 "witness sybil/duplicate")
        _require(w["epoch"] == new["epoch"] and w["size"] == new["size"] and w["root"] == new["root"],
                 "same-epoch split root")
        _require(_pos(w["time"]) and _hex(w["receipt_digest"]) and w["receipt_digest"] not in receipts,
                 "receipt replay")
        ids.add(w["id"]); domains.add(w["domain"]); receipts.add(w["receipt_digest"])
    gossip = payload["gossip"]
    _require(type(gossip) is list and len(gossip) == 6, "incomplete directed gossip mesh")
    edges = set()
    for g in gossip:
        _require(_keys(g, {"from", "to", "epoch", "root", "receipt_digest"}), "bad gossip")
        _require(g["from"] in ids and g["to"] in ids and g["from"] != g["to"], "invalid witness edge")
        _require((g["from"],g["to"]) not in edges and g["epoch"] == new["epoch"] and
                 g["root"] == new["root"], "gossip contradiction or replay")
        _require(g["receipt_digest"] in receipts, "unrecognized witness receipt")
        edges.add((g["from"],g["to"]))
    _require(len(edges) == 6, "missing independent gossip audience")

    anchor = payload["anchor"]
    _require(_keys(anchor, {"locator", "epoch", "root", "root_sha256", "independent_auth"}), "wrong anchor schema")
    _require(_NAME.fullmatch(anchor["locator"]) is not None and anchor["epoch"] == new["epoch"] and
             anchor["root"] == new["root"] and anchor["root_sha256"] == _sha(bytes.fromhex(new["root"])) and
             anchor["independent_auth"] is False, "fake immutable external checkpoint")

    fence = payload["fence"]
    _require(_keys(fence, {"old_generation", "generation", "token", "nonce", "lease_start", "lease_end", "observed_at", "outbox", "ack"}), "invalid fence")
    _require(_zero(fence["old_generation"]) and _pos(fence["generation"]) and
             fence["generation"] == fence["old_generation"]+1 and _pos(fence["token"]) and
             fence["token"] >= fence["generation"] and _hex(fence["nonce"]), "stale token or ABA")
    _require(_pos(fence["lease_start"]) and _pos(fence["lease_end"]) and _pos(fence["observed_at"]) and
             fence["lease_start"] <= fence["observed_at"] < fence["lease_end"], "expired/invalid local lease")
    _require(fence["outbox"] == "PENDING" and fence["ack"] == "LOST_UNRESOLVED", "forged remote ACK")
    _require(payload["release"] is False, "unsafe release")

    digest = claimed_digest(payload)
    _require(digest == expected["commit_digest"], "untrusted exact claim pin")
    return {"status": "RC690_COHERENT_CLAIMS_QUARANTINED_NO_EXTERNAL_TRUST",
            "claim_digest": digest, "inclusion_math_consistent": True,
            "prefix_math_consistent": True, "claimed_gossip_mesh_complete": True,
            "independent_owner_reviewer_authenticated": False,
            "real_ed25519_signer_authority": False,
            "external_provider_run_log_authenticated": False,
            "revocation_and_trusted_time_authenticated": False,
            "immutable_checkpoint_authenticated": False,
            "durable_multihost_cas_verified": False,
            "external_ack_verified": False, "release_ready": False,
            "live_trading_allowed": False}


def classify_views(left, right):
    """Classify apparent fork in two untrusted same-schema *views*."""
    fields = {"repository", "source_sha", "epoch", "size", "root", "provider_digest", "witness_digest", "nonce", "ack"}
    _require(_keys(left, fields) and _keys(right, fields), "wrong view schema")
    for v in (left, right):
        _require(v["repository"] == _REPO and _hex(v["source_sha"], 40) and
                 _pos(v["epoch"]) and _pos(v["size"]) and
                 all(_hex(v[k]) for k in ("root", "provider_digest", "witness_digest", "nonce")) and
                 v["ack"] in ("PENDING", "LOST_UNRESOLVED"), "bad peer claim")
    if left["source_sha"] != right["source_sha"]:
        return "CLAIMED_SOURCE_FORK_UNAUTHENTICATED"
    if left["epoch"] == right["epoch"] and left["size"] == right["size"] and left["root"] != right["root"]:
        return "CLAIMED_SAME_EPOCH_MERKLE_FORK_UNAUTHENTICATED"
    if left["root"] == right["root"] and left["provider_digest"] != right["provider_digest"]:
        return "CLAIMED_PROVIDER_LOG_SPLIT_UNAUTHENTICATED"
    if left["root"] == right["root"] and left["witness_digest"] != right["witness_digest"]:
        return "CLAIMED_WITNESS_RECEIPT_SPLIT_UNAUTHENTICATED"
    if left["nonce"] == right["nonce"] and (left["epoch"], left["root"]) != (right["epoch"], right["root"]):
        return "CLAIMED_NONCE_REPLAY_FORK_UNAUTHENTICATED"
    if left == right:
        return "CLAIMED_EQUAL_VIEWS_NOT_AUTHENTICATED"
    return "CLAIMED_INCOMPARABLE_VIEWS_NOT_AUTHENTICATED"
