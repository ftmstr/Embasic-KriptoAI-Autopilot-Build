"""RC677 synthetic chronology and split-view quarantine. NO signed provenance.

Every timestamp, signer, provider receipt, root and pin is caller-supplied.
A matching claim is not cryptographic authentication, actual CAS, or a release.
No I/O, dynamic execution, keys, credentials, ledger mutation or trading.
"""
import hashlib
import hmac
import re


class TemporalOriginRejected(ValueError):
    """Malformed, expired, revoked, stale or conflicting invented evidence."""


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_IDENT = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_REPO = "ftmstr/Embasic-KriptoAI-Autopilot-Build"
_BRANCH = "validation/rc654-pr1-rc653-combined-ci"
_DOMAIN = "RC677-PUBLIC-TEMPORAL-ORIGIN-QUARANTINE-V1"
_ROLES = ("owner", "independent_reviewer", "incumbent_custodian")
_OS = ("ubuntu", "windows")
_MAX = (1 << 63) - 2
_FIELDS = (
    "repository", "branch", "git_sha", "source_sha256", "workflow_sha256",
    "roster_sha256", "authority_epoch", "authority_root_sha256",
    "before_generation", "before_root_sha256", "after_generation",
    "after_root_sha256", "issued_at", "observed_at", "nonce_sha256",
    "log_sha256", "writers", "witnesses", "providers", "ack_state",
    "release_ready", "live_trading_allowed",
)
_PINS = (
    "git_sha", "source_sha256", "workflow_sha256", "roster_sha256",
    "authority_epoch", "authority_root_sha256", "before_generation",
    "before_root_sha256", "after_root_sha256", "nonce_sha256",
    "log_sha256", "witness_keys", "revocation_history",
    "spent_nonces", "seen_logs", "seen_roots", "expected_claim_sha256",
)


def _hex(v, n=64):
    return type(v) is str and (_SHA40 if n == 40 else _SHA64).fullmatch(v) is not None


def _id(v):
    return type(v) is str and _IDENT.fullmatch(v) is not None


def _int(v):
    return type(v) is int and 1 <= v <= _MAX


def _history(v):
    return (type(v) is tuple and len(v) <= 512 and all(_hex(x) for x in v)
            and v == tuple(sorted(set(v))))


def _revoke_history(v):
    return (type(v) is tuple and len(v) <= 512 and
            all(type(x) is tuple and len(x) == 2 and _hex(x[0]) and _int(x[1])
                for x in v) and v == tuple(sorted(set(v))) and
            len({x[0] for x in v}) == len(v))


def _checked_claim(c):
    if type(c) is not dict or set(c) != set(_FIELDS):
        raise TemporalOriginRejected("unexpected claim schema")
    if (c["repository"] != _REPO or c["branch"] != _BRANCH or
            not _hex(c["git_sha"], 40) or
            any(not _hex(c[k]) for k in (
                "source_sha256", "workflow_sha256", "roster_sha256",
                "authority_root_sha256", "before_root_sha256", "after_root_sha256",
                "nonce_sha256")) or
            not _int(c["authority_epoch"]) or not _int(c["before_generation"]) or
            not _int(c["after_generation"]) or
            c["after_generation"] != c["before_generation"] + 1 or
            c["after_root_sha256"] == c["before_root_sha256"] or
            not _int(c["issued_at"]) or not _int(c["observed_at"]) or
            c["issued_at"] > c["observed_at"] or
            type(c["log_sha256"]) is not tuple or len(c["log_sha256"]) != 2 or
            any(not _hex(x) for x in c["log_sha256"]) or
            c["log_sha256"][0] == c["log_sha256"][1] or
            type(c["ack_state"]) is not str or
            c["ack_state"] not in ("ACK_CLAIMED", "ACK_LOST_UNRESOLVED") or
            c["release_ready"] is not False or c["live_trading_allowed"] is not False):
        raise TemporalOriginRejected("unsafe Git/source/clock/CAS fields")
    writers = c["writers"]
    if (type(writers) is not tuple or len(writers) != 2 or
            any(type(x) is not tuple or len(x) != 5 for x in writers) or
            not all(_id(x[0]) for x in writers) or writers[0][0] == writers[1][0]):
        raise TemporalOriginRejected("missing distinct write contenders")
    for i, (name, generation, root, nonce, outcome) in enumerate(writers):
        if (type(generation) is not int or generation != c["before_generation"] or
                root != c["before_root_sha256"] or nonce != c["nonce_sha256"] or
                type(outcome) is not str or
                outcome != ("CLAIMED_WIN" if i == 0 else "CLAIMED_CONFLICT")):
            raise TemporalOriginRejected("two winners, rollback or stale base")
    witnesses = c["witnesses"]
    if (type(witnesses) is not tuple or len(witnesses) != 3 or
            any(type(x) is not tuple or len(x) != 7 for x in witnesses) or
            len({x[1] for x in witnesses}) != 3 or
            len({x[2] for x in witnesses}) != 3):
        raise TemporalOriginRejected("witness role or key independence")
    for i, (role, actor, key, valid_from, valid_to, signed_at, status) in enumerate(witnesses):
        if (role != _ROLES[i] or not _id(actor) or not _hex(key) or
                not _int(valid_from) or not _int(valid_to) or not _int(signed_at) or
                not valid_from <= signed_at <= valid_to or
                not c["issued_at"] <= signed_at <= c["observed_at"] or
                type(status) is not str or status != "NOT_VERIFIED"):
            raise TemporalOriginRejected("unverifiable, expired or future-dated witness")
    providers = c["providers"]
    if (type(providers) is not tuple or len(providers) != 2 or
            any(type(x) is not tuple or len(x) != 9 for x in providers)):
        raise TemporalOriginRejected("two independent claimed OS observations required")
    for i, (os, run, job, git, log, gen, root, seen_at, status) in enumerate(providers):
        if (os != _OS[i] or not _int(run) or not _int(job) or
                git != c["git_sha"] or log != c["log_sha256"][i] or
                type(gen) is not int or gen != c["after_generation"] or
                root != c["after_root_sha256"] or not _int(seen_at) or
                not c["issued_at"] <= seen_at <= c["observed_at"] or
                type(status) is not str or status != "NOT_VERIFIED"):
            raise TemporalOriginRejected("forked, stale or fake signed provider observation")
    if (providers[0][1] == providers[1][1] or providers[0][2] == providers[1][2]):
        raise TemporalOriginRejected("duplicated provider run/job identity")


def temporal_claim_sha256(claim):
    """Domain-separated consistency checksum; it verifies NO real signatures."""
    _checked_claim(claim)
    fields = [
        _DOMAIN, claim["repository"], claim["branch"], claim["git_sha"],
        claim["source_sha256"], claim["workflow_sha256"], claim["roster_sha256"],
        str(claim["authority_epoch"]), claim["authority_root_sha256"],
        str(claim["before_generation"]), claim["before_root_sha256"],
        str(claim["after_generation"]), claim["after_root_sha256"],
        str(claim["issued_at"]), str(claim["observed_at"]),
        claim["nonce_sha256"], *claim["log_sha256"],
    ]
    for writer in claim["writers"]:
        fields.extend((writer[0], str(writer[1]), writer[2], writer[3], writer[4]))
    for role, actor, key, start, end, at, status in claim["witnesses"]:
        fields.extend((role, actor, key, str(start), str(end), str(at), status))
    for os, run, job, git, log, gen, root, at, status in claim["providers"]:
        fields.extend((os, str(run), str(job), git, log, str(gen), root, str(at), status))
    fields.extend((claim["ack_state"], "release_ready=False", "live_trading_allowed=False"))
    return hashlib.sha256("\n".join(fields).encode("ascii")).hexdigest()


def quarantine_temporal_origin(claim, *, pinned):
    """Reject temporal equivocation relative to supplied, unauthenticated pins.

    No clock, key revocation oracle, GitHub provenance, signer or CAS is checked.
    """
    digest = temporal_claim_sha256(claim)
    if type(pinned) is not dict or set(pinned) != set(_PINS):
        raise TemporalOriginRejected("missing or extra pinned source-of-truth field")
    for key in ("source_sha256", "workflow_sha256", "roster_sha256",
                "authority_root_sha256", "before_root_sha256", "after_root_sha256",
                "nonce_sha256"):
        if not _hex(pinned[key]) or not hmac.compare_digest(pinned[key], claim[key]):
            raise TemporalOriginRejected("foreign pinned source or trust anchor")
    if (not _hex(pinned["git_sha"], 40) or
            not hmac.compare_digest(pinned["git_sha"], claim["git_sha"]) or
            not _int(pinned["authority_epoch"]) or
            pinned["authority_epoch"] != claim["authority_epoch"] or
            not _int(pinned["before_generation"]) or
            pinned["before_generation"] != claim["before_generation"] or
            type(pinned["log_sha256"]) is not tuple or
            pinned["log_sha256"] != claim["log_sha256"] or
            type(pinned["witness_keys"]) is not tuple or
            pinned["witness_keys"] != tuple(w[2] for w in claim["witnesses"]) or
            not _revoke_history(pinned["revocation_history"]) or
            any(not _history(pinned[k]) for k in (
                "spent_nonces", "seen_logs", "seen_roots")) or
            not _hex(pinned["expected_claim_sha256"]) or
            not hmac.compare_digest(pinned["expected_claim_sha256"], digest)):
        raise TemporalOriginRejected("malformed, stale or self-conflicting provenance pins")
    revoked = {key for key, at in pinned["revocation_history"]
               if at <= claim["observed_at"]}
    if (any(key in revoked for key in pinned["witness_keys"]) or
            claim["authority_root_sha256"] in pinned["seen_roots"] or
            claim["after_root_sha256"] in pinned["seen_roots"] or
            claim["nonce_sha256"] in pinned["spent_nonces"] or
            any(log in pinned["seen_logs"] for log in claim["log_sha256"])):
        raise TemporalOriginRejected("revoked signer or replayed root, nonce or OS log")
    return {
        "status": "TEMPORAL_PROVIDER_CLAIMS_QUARANTINED_NOT_AUTHENTICATED",
        "claim_sha256": digest,
        "lost_ack_unresolved": claim["ack_state"] == "ACK_LOST_UNRESOLVED",
        "authenticated_signatures": False,
        "authenticated_clock": False,
        "provider_origin_verified": False,
        "atomic_cas_verified": False,
        "durable_receipts_consumed": False,
        "release_ready": False,
        "live_trading_allowed": False,
    }
