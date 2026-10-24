"""Validate invented event-stream observations, with no exchange/network interfaces.

Independent stdlib implementation informed by event-time hygiene patterns.
This is *not* market-data validation or scientific model evaluation.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

MAX_ROWS = 64
MAX_MILLISECONDS = 10_000_000_000_000
_ID = re.compile(r"SYN-[0-9]{3,5}\Z", re.ASCII)


class SyntheticStreamRejected(ValueError):
    """A synthetic stream failed closed before being used for any downstream logic."""


@dataclass(frozen=True)
class SyntheticObservation:
    sequence: int
    event_time_ms: int
    observed_time_ms: int
    price_ticks: int
    synthetic_id: str


@dataclass(frozen=True)
class SyntheticStreamReceipt:
    kind: str
    observations: int
    last_event_time_ms: int
    max_transport_latency_ms: int
    canonical_sha256: str
    future_observations_allowed: bool = False
    verified_market_data: bool = False
    production_ready: bool = False
    scientific_validated: bool = False
    trading_enabled: bool = False


def validate_synthetic_stream(
    rows: tuple[SyntheticObservation, ...], *, as_of_ms: int,
    max_transport_latency_ms: int, max_last_event_age_ms: int
) -> SyntheticStreamReceipt:
    """Pure validation; O(n) time and memory (max 64 invented rows).

    All event and reception times must be <= as_of. The last *event* must be
    fresh enough; every event's transport latency must be bounded. Sequences
    must be 0..N-1 with strictly increasing event/reception times. No system
    clock, network, secrets, external packages or trading adapters are used.
    """
    if type(rows) is not tuple or not 1 <= len(rows) <= MAX_ROWS:
        raise SyntheticStreamRejected("synthetic row count/type")
    if (type(as_of_ms) is not int or not 0 < as_of_ms <= MAX_MILLISECONDS or
        type(max_transport_latency_ms) is not int or not 0 <= max_transport_latency_ms <= 60_000 or
        type(max_last_event_age_ms) is not int or not 0 <= max_last_event_age_ms <= 60_000):
        raise SyntheticStreamRejected("invalid time bounds")
    prior_event = -1
    prior_arrival = -1
    maximum_latency = 0
    seen_ids: set[str] = set()
    canonical_rows: list[tuple[int, int, int, int, str]] = []
    for expected, item in enumerate(rows):
        if type(item) is not SyntheticObservation:
            raise SyntheticStreamRejected("unexpected row class")
        if type(item.sequence) is not int or item.sequence != expected:
            raise SyntheticStreamRejected("sequence duplicate or gap")
        if (type(item.event_time_ms) is not int or type(item.observed_time_ms) is not int or
            not prior_event < item.event_time_ms <= item.observed_time_ms <= as_of_ms or
            not prior_arrival < item.observed_time_ms):
            raise SyntheticStreamRejected("time ordering or future observation")
        if type(item.price_ticks) is not int or not 1 <= item.price_ticks <= 1_000_000:
            raise SyntheticStreamRejected("invalid toy price")
        if type(item.synthetic_id) is not str or not _ID.fullmatch(item.synthetic_id) or item.synthetic_id in seen_ids:
            raise SyntheticStreamRejected("invalid/duplicate synthetic event id")
        lag = item.observed_time_ms - item.event_time_ms
        if lag > max_transport_latency_ms:
            raise SyntheticStreamRejected("stale transport observation")
        seen_ids.add(item.synthetic_id)
        maximum_latency = max(maximum_latency, lag)
        canonical_rows.append((item.sequence, item.event_time_ms, item.observed_time_ms,
                               item.price_ticks, item.synthetic_id))
        prior_event, prior_arrival = item.event_time_ms, item.observed_time_ms
    if as_of_ms - prior_event > max_last_event_age_ms:
        raise SyntheticStreamRejected("stale latest event")
    canonical = json.dumps(canonical_rows, separators=(",", ":"), ensure_ascii=True)
    return SyntheticStreamReceipt(
        kind="EMBASIC_PUBLIC_INVENTED_STREAM_ONLY",
        observations=len(rows), last_event_time_ms=prior_event,
        max_transport_latency_ms=maximum_latency,
        canonical_sha256=sha256(canonical.encode("ascii")).hexdigest(),
    )
