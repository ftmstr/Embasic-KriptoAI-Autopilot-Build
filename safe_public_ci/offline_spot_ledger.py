"""Synthetic-only spot cash/reservation ledger composed with the RC651 offline FSM.

Original independent standard-library code. No exchange, credentials, filesystem,
network, scientific evaluation, real PnL or live execution capabilities.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re

from safe_public_ci.offline_order_fsm import (
    OfflineOrderSimulator, OfflineRiskPolicy, OfflineRefusal,
    SyntheticOrderEvent, SyntheticOrderIntent,
)


class LedgerRejected(ValueError):
    """Refusal of a synthetic input, transition or book-accounting violation."""


def exact_int(v: object, lo: int, hi: int, label: str) -> int:
    if type(v) is not int or not lo <= v <= hi:
        raise LedgerRejected("invalid " + label)
    return v


def fee_ceil(notional: int, bps: int) -> int:
    return (notional * bps + 9999) // 10000


@dataclass(frozen=True)
class SyntheticLedgerPolicy:
    quote_initial: int = 100_000
    base_initial: int = 20
    fee_bps: int = 10
    max_order_units: int = 10
    max_session_units: int = 40
    max_unique_orders: int = 8
    max_limit_price_ticks: int = 10_000
    max_notional: int = 50_000
    max_market_age_ms: int = 500
    max_transport_lag_ms: int = 500
    mode: str = "OFFLINE_SYNTHETIC_ONLY"

    def __post_init__(self) -> None:
        for k in ("quote_initial", "base_initial"):
            exact_int(getattr(self, k), 0, 10**12, k)
        exact_int(self.fee_bps, 0, 1000, "fee_bps")
        for k in ("max_order_units", "max_session_units", "max_unique_orders",
                  "max_limit_price_ticks", "max_notional"):
            exact_int(getattr(self, k), 1, 10**7, k)
        for k in ("max_market_age_ms", "max_transport_lag_ms"):
            exact_int(getattr(self, k), 0, 60000, k)
        if self.max_session_units < self.max_order_units or self.mode != "OFFLINE_SYNTHETIC_ONLY":
            raise LedgerRejected("locked policy limits/mode")


@dataclass(frozen=True)
class SyntheticSpotIntent:
    order: SyntheticOrderIntent
    side: str
    limit_price_ticks: int


@dataclass(frozen=True)
class SyntheticExecution:
    client_id: str
    event: SyntheticOrderEvent
    fill_price_ticks: int = 0


@dataclass(frozen=True)
class LedgerJournalEntry:
    index: int
    kind: str
    payload_json: str
    previous_digest: str
    digest: str


@dataclass(frozen=True)
class SyntheticLedgerSnapshot:
    quote_total: int
    quote_reserved: int
    quote_available: int
    base_total: int
    base_reserved: int
    base_available: int
    total_fee_quote: int
    order_count: int
    journal_count: int
    journal_digest: str
    live_trading_allowed: bool = False
    financial_performance_evaluated: bool = False
    production_ledger: bool = False


class _Booked:
    def __init__(self, request: SyntheticSpotIntent, reserve: int):
        self.request = request
        self.reserve = reserve
        self.filled_units = 0
        self.last_state = "PENDING_ACK"
        self.event_payloads: dict[str, str] = {}


class SyntheticSpotLedger:
    """Integer-only toy spot balances and FSM event bookkeeping.

    All mutating operations append hash-chained *in-memory* entries; replay
    verifies journal order and complete expected tip, not durable storage.
    No signed or independently attested evidence is generated.
    """
    def __init__(self, policy: SyntheticLedgerPolicy):
        if type(policy) is not SyntheticLedgerPolicy:
            raise LedgerRejected("immutable synthetic ledger policy required")
        self.policy = policy
        self._genesis = sha256(("SYNTHETIC-POLICY-V1|" + json.dumps(asdict(policy), sort_keys=True, separators=(",", ":"))).encode("ascii")).hexdigest()
        self.fsm = OfflineOrderSimulator(OfflineRiskPolicy(
            max_units_per_order=policy.max_order_units,
            max_session_requested_units=policy.max_session_units,
            max_unique_orders=policy.max_unique_orders,
            max_market_age_ms=policy.max_market_age_ms,
            max_transport_lag_ms=policy.max_transport_lag_ms,
        ))
        self.quote_total = policy.quote_initial
        self.base_total = policy.base_initial
        self.quote_reserved = 0
        self.base_reserved = 0
        self.total_fee_quote = 0
        self.booked: dict[str, _Booked] = {}
        self._killed = False
        self.journal: list[LedgerJournalEntry] = []

    def _append(self, kind: str, payload: dict) -> None:
        canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True)
        previous = self.journal[-1].digest if self.journal else self._genesis
        n = len(self.journal)
        digest = sha256(f"SYNTHETIC-LEDGER-V1|{n}|{kind}|{previous}|{canonical}".encode("ascii")).hexdigest()
        self.journal.append(LedgerJournalEntry(n, kind, canonical, previous, digest))

    def balances(self) -> SyntheticLedgerSnapshot:
        if (self.quote_reserved < 0 or self.base_reserved < 0 or
            self.quote_total < self.quote_reserved or self.base_total < self.base_reserved):
            raise LedgerRejected("ledger invariant failed")
        return SyntheticLedgerSnapshot(
            self.quote_total, self.quote_reserved, self.quote_total - self.quote_reserved,
            self.base_total, self.base_reserved, self.base_total - self.base_reserved,
            self.total_fee_quote, len(self.booked), len(self.journal),
            self.journal[-1].digest if self.journal else self._genesis,
        )

    def _reserve(self, request: SyntheticSpotIntent) -> int:
        if type(request) is not SyntheticSpotIntent or type(request.order) is not SyntheticOrderIntent:
            raise LedgerRejected("synthetic intent required")
        if request.order.mode != "OFFLINE_SYNTHETIC_ONLY" or request.order.invented_pair != "SYN-PAIR":
            raise LedgerRejected("real symbols or live execution forbidden")
        if request.side not in ("BUY", "SELL") or type(request.side) is not str:
            raise LedgerRejected("synthetic side required")
        price = exact_int(request.limit_price_ticks, 1, self.policy.max_limit_price_ticks, "limit price")
        units = exact_int(request.order.units, 1, self.policy.max_order_units, "requested units")
        notional = price * units
        if notional > self.policy.max_notional:
            raise LedgerRejected("maximum order notional")
        if request.side == "BUY":
            # Fee ceiling per single unit makes reserve safe for arbitrary partial fills.
            required = notional + units * fee_ceil(price, self.policy.fee_bps)
            if required > self.quote_total - self.quote_reserved:
                raise LedgerRejected("insufficient synthetic available quote")
        else:
            required = units
            if required > self.base_total - self.base_reserved:
                raise LedgerRejected("insufficient synthetic available base")
        return required

    def submit(self, request: SyntheticSpotIntent, *, as_of_ms: int) -> SyntheticLedgerSnapshot:
        if type(request) is not SyntheticSpotIntent or type(request.order) is not SyntheticOrderIntent:
            raise LedgerRejected("synthetic intent required")
        previous = self.booked.get(request.order.client_id)
        if previous:
            if previous.request != request:
                raise LedgerRejected("conflicting duplicate spot request")
            return self.balances()
        required = self._reserve(request)
        if self._killed:
            raise LedgerRejected("immutable kill switch engaged")
        try:
            self.fsm.submit(request.order, as_of_ms=as_of_ms)
        except OfflineRefusal as exc:
            raise LedgerRejected(str(exc)) from exc
        self.booked[request.order.client_id] = _Booked(request, required)
        if request.side == "BUY":
            self.quote_reserved += required
        else:
            self.base_reserved += required
        self._append("SUBMIT", {"request": {"order": asdict(request.order), "side": request.side,
                                         "limit_price_ticks": request.limit_price_ticks}, "as_of_ms": as_of_ms})
        return self.balances()

    def apply(self, execution: SyntheticExecution, *, as_of_ms: int) -> SyntheticLedgerSnapshot:
        if type(execution) is not SyntheticExecution or type(execution.event) is not SyntheticOrderEvent:
            raise LedgerRejected("invented execution required")
        book = self.booked.get(execution.client_id)
        if book is None or execution.client_id != book.request.order.client_id:
            raise LedgerRejected("unknown client id")
        ev = execution.event
        if type(ev.event_id) is not str or not re.fullmatch(r"SIM-EVT-[A-Z0-9]{1,20}", ev.event_id):
            raise LedgerRejected("invented event identity required")
        payload = json.dumps({"execution": {"client_id": execution.client_id,
                            "event": asdict(ev), "fill_price_ticks": execution.fill_price_ticks},
                              "as_of_ms": as_of_ms}, sort_keys=True, separators=(",", ":"))
        previous = book.event_payloads.get(ev.event_id)
        if previous is not None:
            if previous != payload:
                raise LedgerRejected("conflicting idempotent replay")
            return self.balances()
        if type(execution.fill_price_ticks) is not int or execution.fill_price_ticks < 0:
            raise LedgerRejected("invalid synthetic fill price")
        change_quote = change_base = fee = 0
        if ev.kind == "FILL":
            p = exact_int(execution.fill_price_ticks, 1, self.policy.max_limit_price_ticks, "fill price")
            limit = book.request.limit_price_ticks
            if (book.request.side == "BUY" and p > limit) or (book.request.side == "SELL" and p < limit):
                raise LedgerRejected("fill violates limit price")
            q = exact_int(ev.filled_increment, 1, book.request.order.units, "fill units")
            gross = q * p
            fee = fee_ceil(gross, self.policy.fee_bps)
            if book.request.side == "BUY":
                change_quote, change_base = -(gross + fee), q
                if -change_quote > book.reserve:
                    raise LedgerRejected("fill would exceed quoted reserved cash")
            else:
                if fee > gross:
                    raise LedgerRejected("fee greater than gross proceeds")
                change_quote, change_base = gross - fee, -q
                if q > book.reserve:
                    raise LedgerRejected("fill exceeds reserved base")
        elif execution.fill_price_ticks != 0:
            raise LedgerRejected("non-fill event with a price")
        if ev.kind == "RECONCILE" and ev.reconciliation_total_filled != book.filled_units:
            # Without individually priced fill receipts cash cannot be reconciled honestly.
            raise LedgerRejected("unknown priced reconciliation delta; review required")
        try:
            after = self.fsm.apply(execution.client_id, ev, as_of_ms=as_of_ms)
        except OfflineRefusal as exc:
            raise LedgerRejected(str(exc)) from exc
        if change_quote < 0:
            assert -change_quote <= book.reserve
        self.quote_total += change_quote
        self.base_total += change_base
        self.total_fee_quote += fee
        if ev.kind == "FILL":
            booked_release = -change_quote if book.request.side == "BUY" else -change_base
            if book.request.side == "BUY":
                self.quote_reserved -= booked_release
            else:
                self.base_reserved -= booked_release
            book.reserve -= booked_release
            book.filled_units += ev.filled_increment
        if after.state in ("FILLED", "CANCELED", "REJECTED"):
            if book.request.side == "BUY":
                self.quote_reserved -= book.reserve
            else:
                self.base_reserved -= book.reserve
            book.reserve = 0
        book.last_state = after.state
        book.event_payloads[ev.event_id] = payload
        self._append("EVENT", {"execution": {"client_id": execution.client_id,
                   "event": asdict(ev), "fill_price_ticks": execution.fill_price_ticks},
                   "as_of_ms": as_of_ms})
        return self.balances()

    def kill_switch(self) -> SyntheticLedgerSnapshot:
        if not self._killed:
            self._killed = True
            self.fsm.kill_switch()
            self._append("KILL", {})
        return self.balances()

    def verify_journal(self) -> bool:
        prev = self._genesis
        for i, entry in enumerate(self.journal):
            if type(entry) is not LedgerJournalEntry or entry.index != i or entry.previous_digest != prev:
                raise LedgerRejected("journal sequence or hash predecessor mismatch")
            try:
                x = json.loads(entry.payload_json)
                if json.dumps(x, separators=(",", ":"), sort_keys=True, ensure_ascii=True) != entry.payload_json:
                    raise LedgerRejected("noncanonical journal record")
            except (ValueError, TypeError) as exc:
                raise LedgerRejected("malformed journal record") from exc
            expected = sha256(f"SYNTHETIC-LEDGER-V1|{i}|{entry.kind}|{prev}|{entry.payload_json}".encode("ascii")).hexdigest()
            if expected != entry.digest:
                raise LedgerRejected("journal digest mismatch")
            prev = entry.digest
        return True

    @classmethod
    def replay(cls, policy: SyntheticLedgerPolicy, entries: tuple[LedgerJournalEntry, ...],
               *, expected_digest: str, expected_count: int) -> SyntheticSpotLedger:
        if type(entries) is not tuple or type(expected_count) is not int or len(entries) != expected_count:
            raise LedgerRejected("incomplete synthetic journal")
        if type(expected_digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
            raise LedgerRejected("missing expected external digest")
        obj = cls(policy)
        obj.journal = list(entries)
        obj.verify_journal()
        obj.journal = []
        for expected in entries:
            try:
                p = json.loads(expected.payload_json)
                if expected.kind == "SUBMIT":
                    req = p["request"]
                    intent = SyntheticSpotIntent(SyntheticOrderIntent(**req["order"]),req["side"],req["limit_price_ticks"])
                    obj.submit(intent,as_of_ms=p["as_of_ms"])
                elif expected.kind == "EVENT":
                    x=p["execution"]
                    obj.apply(SyntheticExecution(x["client_id"],SyntheticOrderEvent(**x["event"]),x["fill_price_ticks"]),as_of_ms=p["as_of_ms"])
                elif expected.kind == "KILL":
                    obj.kill_switch()
                else:
                    raise LedgerRejected("unknown journal action")
            except (KeyError, TypeError, OfflineRefusal) as exc:
                raise LedgerRejected("invalid replay action") from exc
            if obj.journal[-1] != expected:
                raise LedgerRejected("journal replay non-determinism")
        if obj.balances().journal_digest != expected_digest or len(obj.journal) != expected_count:
            raise LedgerRejected("journal final receipt mismatch")
        return obj
