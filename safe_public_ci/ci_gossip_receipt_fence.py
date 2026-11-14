"""RC688: bounded claimed cross-client gossip + outbox receipt fork detection.

Evidence is untrusted, including any alleged signatures, public keys, log
hashes and clocks. Never authenticate a provider, signer, nonce, or durable CAS.
No I/O, network, key material, orders, fitting, release or trusted clock.
"""
import hashlib
import hmac
import re


class GossipRejected(ValueError):
    """Unsafe, contradictory, oversized or otherwise invalid caller claim."""


_H40 = re.compile(r"[0-9a-f]{40}\Z")
_H64 = re.compile(r"[0-9a-f]{64}\Z")
_IDENT = re.compile(r"[a-z][a-z0-9_]{0,23}\Z")
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_DOMAIN = b"RC688-CLAIMED-GOSSIP-RECIPIENT-FORK-NO-AUTH\x00"
_U64 = (1 << 63) - 1
_BUNDLE_KEYS = frozenset({
    "repo", "branch", "head_sha", "source_sha256", "epoch_min", "epoch_max",
    "owner_reviewer", "providers", "observations", "revocations",
    "outbox", "prior_checkpoints", "safety_flags",
})
_PIN_KEYS = frozenset({
    "head_sha", "source_sha256", "ubuntu_log_sha256", "windows_log_sha256",
    "owner_fingerprint", "reviewer_fingerprint", "ack_root_sha256",
    "externally_authenticated", "provider_origin_authenticated",
    "independent_monotonic_anchor", "durable_cas_authenticated",
})
_AUTH_KEYS = frozenset({"role", "actor", "fingerprint", "claimed_key_origin"})
_PROVIDER_KEYS = frozenset({"os", "run_id", "job_id", "log_sha256", "head_sha", "attempt"})
_VIEW_KEYS = frozenset({
    "client", "domain", "fingerprint", "epoch", "tree_size", "root_sha256",
    "provider_os", "provider_log_sha256", "provider_receipt_sha256", "nonce_sha256", "ack_ref_sha256",
})
_REV_KEYS = frozenset({"fingerprint", "epoch", "reason_sha256"})
_OUTBOX_KEYS = frozenset({
    "transaction_sha256", "generation", "nonce_sha256", "pending_digest_sha256",
    "ack_state", "ack_digest_sha256", "claim_cas_winner_count",
})
_FLAGS_KEYS = frozenset({"final_unsealed", "live_enabled", "single_fit_used", "profit_verified"})


def _hex(value, n=64):
    return type(value) is str and (_H40 if n == 40 else _H64).fullmatch(value) is not None


def _ident(value):
    return type(value) is str and _IDENT.fullmatch(value) is not None


def _pos(value):
    return type(value) is int and 1 <= value <= _U64


def _record(value, keys):
    if type(value) is not dict or frozenset(value) != keys:
        raise GossipRejected("noncanonical or incomplete claimed evidence")
    return value


def _bind_value(v):
    """A typed, length-prefixed, bounded canonical claimed transcript, not a signature."""
    if type(v) is str:
        raw = v.encode("utf-8")
        if len(raw) > 4096:
            raise GossipRejected("oversized text claim")
        return b"s" + len(raw).to_bytes(4, "big") + raw
    if type(v) is bool:
        return b"t" if v else b"f"
    if type(v) is int:
        if not 0 <= v <= _U64:
            raise GossipRejected("integer outside bounded evidence range")
        return b"i" + v.to_bytes(8, "big")
    if type(v) in (tuple, list):
        if len(v) > 64:
            raise GossipRejected("too many elements")
        values = b"".join(_bind_value(item) for item in v)
        return b"l" + len(v).to_bytes(4, "big") + len(values).to_bytes(4, "big") + values
    if type(v) is dict:
        if len(v) > 64 or any(type(k) is not str for k in v):
            raise GossipRejected("unsupported mapping")
        pairs = b"".join(_bind_value(k) + _bind_value(v[k]) for k in sorted(v))
        return b"d" + len(v).to_bytes(4, "big") + len(pairs).to_bytes(4, "big") + pairs
    raise GossipRejected("unsupported claim type")


def _provider_claims(value, head, pins):
    if type(value) is not list or len(value) != 2:
        raise GossipRejected("missing Ubuntu/Windows claimed logs")
    found = {}
    ids = set()
    for rec in value:
        _record(rec, _PROVIDER_KEYS)
        osname = rec["os"]
        if osname not in ("ubuntu", "windows") or osname in found:
            raise GossipRejected("duplicate or unknown provider")
        if (not _pos(rec["run_id"]) or not _pos(rec["job_id"]) or
                rec["attempt"] != 1 or type(rec["attempt"]) is not int or
                rec["head_sha"] != head or not _hex(rec["log_sha256"])):
            raise GossipRejected("invalid claimed provider identity")
        if (rec["run_id"], rec["job_id"]) in ids:
            raise GossipRejected("duplicated run/job")
        ids.add((rec["run_id"], rec["job_id"]))
        if not hmac.compare_digest(rec["log_sha256"], pins[osname + "_log_sha256"]):
            raise GossipRejected("caller provider pin mismatch")
        found[osname] = rec
    if set(found) != {"ubuntu", "windows"}:
        raise GossipRejected("provider pair incomplete")
    return found


def _claimed_signers(value, pins):
    if type(value) is not list or len(value) != 2:
        raise GossipRejected("owner/reviewer claim pair missing")
    names = set()
    keys = set()
    actors = set()
    for rec in value:
        _record(rec, _AUTH_KEYS)
        role = rec["role"]
        if role not in ("owner", "reviewer") or role in names:
            raise GossipRejected("non-independent claimed signer roles")
        if (not _ident(rec["actor"]) or rec["actor"] in actors or
                not _hex(rec["fingerprint"])):
            raise GossipRejected("duplicate or invalid claimed signer")
        actors.add(rec["actor"])
        if rec["claimed_key_origin"] != "external_unverified":
            raise GossipRejected("caller cannot certify key origin")
        if not hmac.compare_digest(rec["fingerprint"], pins[role + "_fingerprint"]):
            raise GossipRejected("untrusted fingerprint pin mismatch")
        names.add(role)
        if rec["fingerprint"] in keys:
            raise GossipRejected("reused claimed signing key")
        keys.add(rec["fingerprint"])
    if names != {"owner", "reviewer"}:
        raise GossipRejected("missing signer role")
    return keys


def _observations(value, lo, hi, providers, revocations, ack_root):
    if type(value) is not list or not 4 <= len(value) <= 48:
        raise GossipRejected("bounded gossip sample required")
    unique = set()
    all_nonces = set()
    actor_domain = {}
    actor_fingerprint = {}
    per_actor = {}
    observations = []
    for rec in value:
        _record(rec, _VIEW_KEYS)
        name, domain = rec["client"], rec["domain"]
        if (not _ident(name) or not _ident(domain) or not _hex(rec["fingerprint"]) or
                not _pos(rec["epoch"]) or not lo <= rec["epoch"] <= hi or
                not _pos(rec["tree_size"]) or rec["tree_size"] > 128 or
                not all(_hex(rec[k]) for k in (
                    "root_sha256", "provider_log_sha256", "provider_receipt_sha256", "nonce_sha256", "ack_ref_sha256")) or
                rec["provider_os"] not in providers):
            raise GossipRejected("invalid bounded witness observation")
        if rec["fingerprint"] in revocations and rec["epoch"] >= revocations[rec["fingerprint"]]:
            raise GossipRejected("revoked witness fingerprint used")
        if (name, rec["epoch"], rec["provider_os"]) in unique:
            raise GossipRejected("duplicate client/epoch/provider")
        unique.add((name, rec["epoch"], rec["provider_os"]))
        if rec["nonce_sha256"] in all_nonces:
            raise GossipRejected("cross-recipient nonce replay")
        all_nonces.add(rec["nonce_sha256"])
        if name in actor_domain and actor_domain[name] != domain:
            raise GossipRejected("one client claims multiple domains")
        if name in actor_fingerprint and actor_fingerprint[name] != rec["fingerprint"]:
            raise GossipRejected("client key changed without external rotation")
        actor_domain[name] = domain
        actor_fingerprint[name] = rec["fingerprint"]
        if rec["provider_log_sha256"] != providers[rec["provider_os"]]["log_sha256"]:
            raise GossipRejected("claimed provider hash contradicts pinned provider")
        if rec["ack_ref_sha256"] != ack_root:
            raise GossipRejected("claimed ACK reference differs from pinned claimant")
        observations.append(rec)
        per_actor.setdefault(name, []).append(rec)
    if len(actor_domain) < 2 or len(set(actor_domain.values())) < 2:
        raise GossipRejected("at least two claimed administrative domains needed")
    if len(set(actor_fingerprint.values())) != len(actor_fingerprint):
        raise GossipRejected("sybil clients reusing claimed fingerprint")
    # A single client's tree size is monotone when comparing chronological epochs.
    for seen in per_actor.values():
        for a in seen:
            for b in seen:
                if a["epoch"] < b["epoch"] and a["tree_size"] > b["tree_size"]:
                    raise GossipRejected("claimed client history rolled backward")
    return observations, actor_domain


def audit_claimed_gossip(bundle, pins):
    """Detect *claimed* forks; always returns all authentication/release gates false.

    All pins, witness identities, purported Ed25519 fingerprints, provider IDs,
    revocations and ACK data are supplied by the same untrusted caller. No real
    provider signatures, key distribution, clock, durable write or remote ACK.
    """
    _record(bundle, _BUNDLE_KEYS)
    _record(pins, _PIN_KEYS)
    if any(pins[k] is not False for k in (
            "externally_authenticated", "provider_origin_authenticated",
            "independent_monotonic_anchor", "durable_cas_authenticated")):
        raise GossipRejected("caller requested forbidden authentication promotion")
    if bundle["repo"] != _REPO or bundle["branch"] != _BRANCH:
        raise GossipRejected("outside Public validation scope")
    if not _hex(bundle["head_sha"], 40) or not _hex(bundle["source_sha256"]):
        raise GossipRejected("invalid repository commitments")
    if not all(_hex(pins[k], 40 if k == "head_sha" else 64) for k in pins if k not in (
            "externally_authenticated", "provider_origin_authenticated",
            "independent_monotonic_anchor", "durable_cas_authenticated")):
        raise GossipRejected("invalid external-looking pins")
    if bundle["head_sha"] != pins["head_sha"] or not hmac.compare_digest(
            bundle["source_sha256"], pins["source_sha256"]):
        raise GossipRejected("pinned identity mismatch")
    lo, hi = bundle["epoch_min"], bundle["epoch_max"]
    if not _pos(lo) or not _pos(hi) or hi < lo or hi - lo > 8:
        raise GossipRejected("invalid bounded epoch range")
    signers = _claimed_signers(bundle["owner_reviewer"], pins)
    providers = _provider_claims(bundle["providers"], bundle["head_sha"], pins)
    if type(bundle["revocations"]) is not list or len(bundle["revocations"]) > 16:
        raise GossipRejected("invalid revocation sample")
    revoked = {}
    for rev in bundle["revocations"]:
        _record(rev, _REV_KEYS)
        fp = rev["fingerprint"]
        if not _hex(fp) or fp in revoked or not _pos(rev["epoch"]) or not _hex(rev["reason_sha256"]):
            raise GossipRejected("duplicate or invalid revocation")
        if fp in signers and rev["epoch"] <= hi:
            raise GossipRejected("claimed signer revoked during sampled window")
        revoked[fp] = rev["epoch"]
    if type(bundle["prior_checkpoints"]) is not list or not 1 <= len(bundle["prior_checkpoints"]) <= 12:
        raise GossipRejected("invalid predecessor roots")
    if not all(_hex(root) for root in bundle["prior_checkpoints"]):
        raise GossipRejected("invalid claimed checkpoint hash")
    if len(set(bundle["prior_checkpoints"])) != len(bundle["prior_checkpoints"]):
        raise GossipRejected("duplicate allegedly immutable checkpoint")
    _record(bundle["safety_flags"], _FLAGS_KEYS)
    if any(bundle["safety_flags"].values()) or any(type(v) is not bool for v in bundle["safety_flags"].values()):
        raise GossipRejected("unsafe FINAL/LIVE/FIT/profit promotion")
    _record(bundle["outbox"], _OUTBOX_KEYS)
    ob = bundle["outbox"]
    if (not all(_hex(ob[k]) for k in (
            "transaction_sha256", "nonce_sha256", "pending_digest_sha256", "ack_digest_sha256")) or
            not _pos(ob["generation"]) or ob["claim_cas_winner_count"] != 1 or
            type(ob["claim_cas_winner_count"]) is not int or
            ob["ack_state"] != "ACK_LOST_UNRESOLVED"):
        raise GossipRejected("outbox cannot claim provider-authenticated ACK")
    observations, domains = _observations(bundle["observations"], lo, hi, providers, revoked,
                                          pins["ack_root_sha256"])
    # Contradictions are classified instead of being promoted to a verified status.
    by_epoch = {}
    by_root = {}
    for rec in observations:
        by_epoch.setdefault((rec["epoch"], rec["tree_size"]), set()).add(rec["root_sha256"])
        by_root.setdefault((rec["epoch"], rec["tree_size"], rec["root_sha256"], rec["provider_os"]),
                           set()).add(rec["provider_receipt_sha256"])
    split = any(len(roots) > 1 for roots in by_epoch.values())
    # Provider contradictions cannot be hidden under equality of root claims.
    log_fork = any(len(logs) > 1 for logs in by_root.values())
    # Two distinct roots at a given epoch across different sizes are not in themselves
    # contradictions: verified Merkle consistency would need actual signed roots.
    bound = hashlib.sha256(_DOMAIN + _bind_value(bundle) + _bind_value(pins)).hexdigest()
    if split:
        status = "CLAIMED_SPLIT_VIEW_DETECTED_ORIGIN_UNAUTHENTICATED"
    elif log_fork:
        status = "CLAIMED_LOG_FORK_DETECTED_ORIGIN_UNAUTHENTICATED"
    else:
        status = "CLAIMED_GOSSIP_CONSISTENT_ORIGIN_UNAUTHENTICATED"
    return {
        "status": status,
        "claim_transcript_sha256": bound,
        "claimed_witness_count": len(domains),
        "claimed_distinct_domain_count": len(set(domains.values())),
        "claimed_split_view": split,
        "claimed_provider_log_fork": log_fork,
        "ed25519_owner_reviewer_origin_authenticated": False,
        "real_signed_revocation_and_clock_authenticated": False,
        "provider_run_job_full_log_authenticated": False,
        "merkle_external_immutable_anchor_authenticated": False,
        "durable_multihost_cas_verified": False,
        "outbox_ack_from_external_provider_verified": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }
