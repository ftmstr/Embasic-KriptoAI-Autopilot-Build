"""Original synthetic-only order-state-machine, no live exchange or network path.

Borrow design *ideas* (not code) from Hummingbot/CCXT/LEAN/NautilusTrader.
There are no API clients, credentials, model calls, market symbols or PnL.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re


class OfflineRefusal(ValueError):
    """Invalid or unsafe input is rejected before mutation."""


class LiveTradingDisabled(RuntimeError):
    """Live orders cannot be sent through this module."""


SEED_RE = re.compile(r"SYN-SEED-[A-Z0-9]{1,12}\Z", re.ASCII)
EVENT_RE = re.compile(r"SIM-EVT-[A-Z0-9]{1,20}\Z", re.ASCII)
TERMINAL = frozenset(("FILLED", "CANCELED", "REJECTED"))
EVENT_TYPES = frozenset(("ACK", "FILL", "CANCEL_REQUEST", "CANCEL_ACK", "REJECT", "TIMEOUT", "RECONCILE"))
RECONCILE_STATES = frozenset(("OPEN", "FILLED", "CANCELED", "REJECTED"))


def _int(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OfflineRefusal("invalid " + label)
    return value


def deterministic_client_id(seed: str, nonce: int) -> str:
    """Deterministic synthetic namespace, not an exchange-accepted ID."""
    if type(seed) is not str or not SEED_RE.fullmatch(seed):
        raise OfflineRefusal("synthetic seed required")
    _int(nonce, 0, 1_000_000_000, "nonce")
    digest = sha256(f"EMBASIC-SYNTH-ORDER-V1|{seed}|{nonce}".encode("ascii")).hexdigest()[:24].upper()
    return "SIM-" + digest


@dataclass(frozen=True)
class OfflineRiskPolicy:
    max_units_per_order: int = 10
    max_session_requested_units: int = 30
    max_unique_orders: int = 4
    max_market_age_ms: int = 500
    max_transport_lag_ms: int = 500

    def __post_init__(self) -> None:
        for key in ("max_units_per_order", "max_session_requested_units", "max_unique_orders"):
            _int(getattr(self, key), 1, 1_000_000, key)
        for key in ("max_market_age_ms", "max_transport_lag_ms"):
            _int(getattr(self, key), 0, 60_000, key)
        if self.max_units_per_order > self.max_session_requested_units:
            raise OfflineRefusal("policy order exposure exceeds session exposure")


@dataclass(frozen=True)
class SyntheticOrderIntent:
    client_id: str
    units: int
    created_ms: int
    market_observed_ms: int
    invented_pair: str = "SYN-PAIR"
    mode: str = "OFFLINE_SYNTHETIC_ONLY"


@dataclass(frozen=True)
class SyntheticOrderEvent:
    event_id: str
    sequence: int
    kind: str
    event_time_ms: int
    received_time_ms: int
    filled_increment: int = 0
    reconciliation_total_filled: int = 0
    exchange_state: str = ""


@dataclass(frozen=True)
class OrderSnapshot:
    client_id: str
    state: str
    requested_units: int
    filled_units: int
    remaining_units: int
    last_sequence: int
    audit_sha256: str
    mode: str = "OFFLINE_SYNTHETIC_ONLY"
    actual_exchange_order_id: None = None
    live_orders_allowed: bool = False
    signed_artifact_verified: bool = False
    scientific_performance_evaluated: bool = False


class _Record:
    def __init__(self, intent: SyntheticOrderIntent) -> None:
        self.intent = intent
        self.state = "PENDING_ACK"
        self.filled = 0
        self.seq = 0
        self.last_event_ms = intent.created_ms
        self.last_received_ms = intent.created_ms
        self.events: dict[str, SyntheticOrderEvent] = {}
        self.digest = sha256(("EMBASIC-OFFLINE-INITIAL|" + json.dumps(asdict(intent), sort_keys=True, separators=(",", ":"))).encode("ascii")).hexdigest()

    def snapshot(self) -> OrderSnapshot:
        return OrderSnapshot(self.intent.client_id, self.state, self.intent.units,
                             self.filled, self.intent.units - self.filled,
                             self.seq, self.digest)


class OfflineOrderSimulator:
    """Entirely memory-resident deterministic simulator. No side effects or I/O.

    Conservative: session exposure is cumulative submitted units and is NEVER
    decremented after cancellation/fill; this cannot undercount new session risk.
    Event IDs replay idempotently only for exact same payloads. Unknown network
    outcomes force an explicit invented reconciliation before later events.
    """
    def __init__(self, policy: OfflineRiskPolicy) -> None:
        if type(policy) is not OfflineRiskPolicy:
            raise OfflineRefusal("risk policy required")
        self._policy = policy
        self._records: dict[str, _Record] = {}
        self._cumulative_units = 0
        self._killed = False

    def kill_switch(self) -> None:
        """Permanently block new simulation entries; reconciliation remains possible."""
        self._killed = True

    def submit(self, intent: SyntheticOrderIntent, *, as_of_ms: int) -> OrderSnapshot:
        if type(intent) is not SyntheticOrderIntent:
            raise OfflineRefusal("synthetic intent required")
        if intent.mode != "OFFLINE_SYNTHETIC_ONLY" or intent.invented_pair != "SYN-PAIR":
            raise OfflineRefusal("live/noninvented pair or mode forbidden")
        if type(intent.client_id) is not str or not re.fullmatch(r"SIM-[0-9A-F]{24}", intent.client_id):
            raise OfflineRefusal("synthetic client order id required")
        _int(intent.units, 1, self._policy.max_units_per_order, "order units")
        _int(as_of_ms, 1, 10**13, "as_of_ms")
        _int(intent.created_ms, 1, as_of_ms, "created_ms")
        _int(intent.market_observed_ms, 1, as_of_ms, "market observed time")
        if intent.market_observed_ms > intent.created_ms:
            raise OfflineRefusal("future data at synthetic intent creation")
        if intent.created_ms - intent.market_observed_ms > self._policy.max_market_age_ms:
            raise OfflineRefusal("stale market data at synthetic submission")
        existing = self._records.get(intent.client_id)
        if existing is not None:
            if existing.intent != intent:
                raise OfflineRefusal("conflicting duplicate client id")
            return existing.snapshot()
        if self._killed:
            raise OfflineRefusal("hard kill-switch engaged")
        if len(self._records) >= self._policy.max_unique_orders:
            raise OfflineRefusal("session order count exceeded")
        if self._cumulative_units + intent.units > self._policy.max_session_requested_units:
            raise OfflineRefusal("cumulative session exposure exceeded")
        self._records[intent.client_id] = _Record(intent)
        self._cumulative_units += intent.units
        return self._records[intent.client_id].snapshot()

    def snapshot(self, client_id: str) -> OrderSnapshot:
        if client_id not in self._records:
            raise OfflineRefusal("unknown synthetic order")
        return self._records[client_id].snapshot()

    def apply(self, client_id: str, event: SyntheticOrderEvent, *, as_of_ms: int) -> OrderSnapshot:
        if client_id not in self._records or type(event) is not SyntheticOrderEvent:
            raise OfflineRefusal("unknown synthetic order or event")
        rec = self._records[client_id]
        if type(event.event_id) is not str or not EVENT_RE.fullmatch(event.event_id):
            raise OfflineRefusal("synthetic event id required")
        prior = rec.events.get(event.event_id)
        if prior is not None:
            if prior != event:
                raise OfflineRefusal("conflicting event replay")
            return rec.snapshot()
        _int(event.sequence, 1, 1_000_000, "event sequence")
        if event.sequence != rec.seq + 1:
            raise OfflineRefusal("out-of-order event or sequence gap")
        if event.kind not in EVENT_TYPES or type(event.kind) is not str:
            raise OfflineRefusal("unknown event kind")
        _int(as_of_ms, 1, 10**13, "as_of_ms")
        _int(event.event_time_ms, rec.last_event_ms, as_of_ms, "event time")
        _int(event.received_time_ms, max(event.event_time_ms, rec.last_received_ms), as_of_ms, "receive time")
        if event.received_time_ms - event.event_time_ms > self._policy.max_transport_lag_ms:
            raise OfflineRefusal("transport latency too large")
        _int(event.filled_increment, 0, rec.intent.units, "fill increment")
        _int(event.reconciliation_total_filled, 0, rec.intent.units, "reconciled total")
        if type(event.exchange_state) is not str:
            raise OfflineRefusal("exchange state type")
        if rec.state in TERMINAL:
            raise OfflineRefusal("terminal synthetic order immutable")
        if rec.state == "UNKNOWN" and event.kind != "RECONCILE":
            raise OfflineRefusal("unknown outcome requires reconciliation")
        if event.kind != "FILL" and event.filled_increment != 0:
            raise OfflineRefusal("fill amount on non-fill event")
        if event.kind != "RECONCILE" and (event.reconciliation_total_filled != 0 or event.exchange_state != ""):
            raise OfflineRefusal("reconciliation fields without reconcile event")
        state = rec.state
        filled = rec.filled
        if event.kind == "ACK":
            if state != "PENDING_ACK":
                raise OfflineRefusal("unexpected ACK")
            state = "OPEN"
        elif event.kind == "FILL":
            if state not in ("OPEN", "PARTIALLY_FILLED", "CANCEL_PENDING") or event.filled_increment == 0:
                raise OfflineRefusal("invalid incremental fill")
            if filled + event.filled_increment > rec.intent.units:
                raise OfflineRefusal("overfill")
            filled += event.filled_increment
            state = "FILLED" if filled == rec.intent.units else ("CANCEL_PENDING" if state == "CANCEL_PENDING" else "PARTIALLY_FILLED")
        elif event.kind == "CANCEL_REQUEST":
            if state not in ("OPEN", "PARTIALLY_FILLED"):
                raise OfflineRefusal("cancel before accepted/open order")
            state = "CANCEL_PENDING"
        elif event.kind == "CANCEL_ACK":
            if state != "CANCEL_PENDING":
                raise OfflineRefusal("unexpected cancel acknowledgment")
            state = "CANCELED"
        elif event.kind == "REJECT":
            if state not in ("PENDING_ACK", "OPEN") or filled != 0:
                raise OfflineRefusal("cannot reject partially filled order")
            state = "REJECTED"
        elif event.kind == "TIMEOUT":
            state = "UNKNOWN"
        elif event.kind == "RECONCILE":
            if state != "UNKNOWN" or event.exchange_state not in RECONCILE_STATES:
                raise OfflineRefusal("unsolicited/invalid reconciliation")
            if not filled <= event.reconciliation_total_filled <= rec.intent.units:
                raise OfflineRefusal("reconciliation rollback/overfill")
            filled = event.reconciliation_total_filled
            if event.exchange_state == "FILLED":
                if filled != rec.intent.units:
                    raise OfflineRefusal("reported FILLED without full quantity")
                state = "FILLED"
            elif event.exchange_state == "OPEN":
                if filled == rec.intent.units:
                    raise OfflineRefusal("reported OPEN with fully filled quantity")
                state = "PARTIALLY_FILLED" if filled else "OPEN"
            elif event.exchange_state == "REJECTED":
                if filled:
                    raise OfflineRefusal("reported REJECTED after fills")
                state = "REJECTED"
            else:
                state = "CANCELED"
        # Only mutate after all validation and transition checks have passed.
        canonical = json.dumps(asdict(event), sort_keys=True, separators=(",", ":"))
        new_digest = sha256((rec.digest + "|" + canonical + "|" + state + "|" + str(filled)).encode("ascii")).hexdigest()
        rec.state, rec.filled, rec.seq = state, filled, event.sequence
        rec.last_event_ms, rec.last_received_ms = event.event_time_ms, event.received_time_ms
        rec.events[event.event_id] = event
        rec.digest = new_digest
        return rec.snapshot()

    def place_real_order(self, *args: object, **kwargs: object) -> None:
        raise LiveTradingDisabled("real order pathway is structurally unavailable")

    def cancel_real_order(self, *args: object, **kwargs: object) -> None:
        raise LiveTradingDisabled("real cancellation pathway is structurally unavailable")
