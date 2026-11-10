"""Synthetic-only trace checker for externally claimed CAS linearization.

All events are invented, caller-supplied claims, not a real atomic store, signed
ledger, GitHub provenance, real runner evidence, or permission to release/trade.
The source uses only authorized stdlib; it performs no IO or dynamic execution.
"""
import hashlib
import hmac
import re


class InterleavingRejected(ValueError):
    """Inconsistent, stale, ambiguous or noncanonical claimed CAS trace."""


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_WORKER = re.compile(r"[a-z][a-z0-9_]{0,23}\Z")
_VERSION = "RC670-PUBLIC-SYNTHETIC-CAS-V1"
_MAX_EVENTS = 96
_MAX_HISTORY = 1024
_MAX_GENERATION = (1 << 63) - 2


def _sha64(x):
    return type(x) is str and _SHA64.fullmatch(x) is not None


def _generation(x):
    return type(x) is int and 0 <= x <= _MAX_GENERATION


def _history(x):
    return (type(x) is tuple and len(x) <= _MAX_HISTORY and
            all(_sha64(y) for y in x) and x == tuple(sorted(set(x))))


def _root(g, pairs, logs):
    """Reproduce RC670's versioned root without bypassing import whitelist."""
    if (not _generation(g) or not _history(pairs) or not _history(logs) or
            len(pairs) >= _MAX_HISTORY or len(logs) > _MAX_HISTORY - 2):
        raise InterleavingRejected("noncanonical generation or history")
    fields = (_VERSION, str(g), "PAIRS", str(len(pairs)), *pairs,
              "LOGS", str(len(logs)), *logs)
    return hashlib.sha256("\n".join(fields).encode("ascii")).hexdigest()


def verify_synthetic_cas_trace(initial_snapshot, events, *, trusted_initial_digest,
                               expected_git_sha, expected_source_sha256,
                               expected_final_generation, trusted_final_digest):
    """Check a caller-declared total order, not actual cross-process atomicity.

    Event: (kind, worker, generation, root, pair, ubuntu_log, windows_log).
    PREPARE pins the worker to one old generation. COMMIT claims an atomic win;
    ACK_LOST + READBACK claims a match but is NOT independent authentication.
    CONFLICT requires a genuinely stale proposal; ROLLBACK is never a commit.
    No external state is read or modified, and no ledger is persistently consumed.
    """
    if (type(initial_snapshot) is not tuple or len(initial_snapshot) != 4 or
            type(events) is not tuple or not 1 <= len(events) <= _MAX_EVENTS or
            not _sha64(trusted_initial_digest) or not _sha64(trusted_final_digest) or
            type(expected_git_sha) is not str or _SHA40.fullmatch(expected_git_sha) is None or
            not _sha64(expected_source_sha256) or
            not _generation(expected_final_generation)):
        raise InterleavingRejected("invalid pinned trace or provider expectations")
    generation, claimed, pairs, logs = initial_snapshot
    initial_root = _root(generation, pairs, logs)
    if (not _sha64(claimed) or
            not hmac.compare_digest(initial_root, claimed) or
            not hmac.compare_digest(initial_root, trusted_initial_digest)):
        raise InterleavingRejected("untrusted initial snapshot root")
    root = initial_root
    workers = {}
    wins = 0
    observed_lost_acks = 0
    for event in events:
        if type(event) is not tuple or len(event) != 7:
            raise InterleavingRejected("malformed trace event")
        kind, worker, g, digest, pair, ubuntu, windows = event
        if (type(kind) is not str or kind not in
                ("PREPARE", "COMMIT", "CONFLICT", "ACK_LOST", "READBACK", "ROLLBACK") or
                type(worker) is not str or _WORKER.fullmatch(worker) is None or
                not _generation(g) or not _sha64(digest) or not _sha64(pair) or
                not _sha64(ubuntu) or not _sha64(windows) or ubuntu == windows):
            raise InterleavingRejected("unknown action, identity or malformed source digest")
        if kind == "PREPARE":
            if (worker in workers or g != generation or
                    not hmac.compare_digest(digest, root) or pair in pairs or
                    ubuntu in logs or windows in logs):
                raise InterleavingRejected("duplicate worker, stale base or consumed log")
            workers[worker] = ("pending", g, digest, pair, ubuntu, windows)
            continue
        previous = workers.get(worker)
        if previous is None or previous[0] not in ("pending", "uncertain"):
            raise InterleavingRejected("action has no active proposal")
        status, base_g, base_digest, wanted_pair, wanted_u, wanted_w = previous
        if (pair, ubuntu, windows) != (wanted_pair, wanted_u, wanted_w):
            raise InterleavingRejected("receipt mutation between stages")
        if kind == "ACK_LOST":
            if (status != "pending" or g != base_g or
                    not hmac.compare_digest(digest, base_digest)):
                raise InterleavingRejected("incoherent lost ACK")
            workers[worker] = ("uncertain", base_g, base_digest, pair, ubuntu, windows)
            continue
        if kind == "ROLLBACK":
            if (status != "pending" or g != base_g or
                    not hmac.compare_digest(digest, base_digest)):
                raise InterleavingRejected("rollback after an uncertain write")
            workers[worker] = ("rolled_back", base_g, base_digest, pair, ubuntu, windows)
            continue
        if kind == "CONFLICT":
            if ((generation == base_g and hmac.compare_digest(root, base_digest)) or
                    g != generation or not hmac.compare_digest(digest, root)):
                raise InterleavingRejected("false conflict or out-of-date observation")
            workers[worker] = ("conflicted", base_g, base_digest, pair, ubuntu, windows)
            continue
        if ((kind == "COMMIT" and status != "pending") or
                (kind == "READBACK" and status != "uncertain") or
                generation != base_g or not hmac.compare_digest(root, base_digest) or
                pair in pairs or ubuntu in logs or windows in logs):
            raise InterleavingRejected("not a unique next-state linearization")
        next_g = generation + 1
        next_pairs = tuple(sorted((*pairs, pair)))
        next_logs = tuple(sorted((*logs, ubuntu, windows)))
        next_root = _root(next_g, next_pairs, next_logs)
        if g != next_g or not hmac.compare_digest(digest, next_root):
            raise InterleavingRejected("commit or readback does not match next state")
        generation, pairs, logs, root = next_g, next_pairs, next_logs, next_root
        workers[worker] = ("claimed_win", base_g, base_digest, pair, ubuntu, windows)
        wins += 1
        if kind == "READBACK":
            observed_lost_acks += 1
    if (not wins or any(v[0] in ("pending", "uncertain") for v in workers.values()) or
            generation != expected_final_generation or
            not hmac.compare_digest(root, trusted_final_digest)):
        raise InterleavingRejected("incomplete or untrusted final trace")
    return {"status": "CLAIMED_LINEARIZATION_CONSISTENT_NOT_AUTHENTICATED",
            "claimed_wins": wins, "lost_ack_readback_claims": observed_lost_acks,
            "final_generation": generation, "final_root_sha256": root,
            "release_ready": False, "live_trading_allowed": False}
