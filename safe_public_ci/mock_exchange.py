"""Read-only toy quotes; there is no exchange or network adapter."""
from dataclasses import dataclass

class LiveTradingDisabled(RuntimeError):
    pass

@dataclass(frozen=True)
class ToyQuote:
    slot: int
    price: int

class OfflineExchange:
    def __init__(self, quotes: tuple[ToyQuote, ...]):
        if (type(quotes) is not tuple or not 1 <= len(quotes) <= 32 or
            any(type(q) is not ToyQuote or type(q.slot) is not int or
                q.slot != i or type(q.price) is not int or
                q.price <= 0 or q.price > 1000000 for i,q in enumerate(quotes))):
            raise ValueError("toy quotes only")
        self._quotes = quotes

    def read(self):
        return self._quotes

    def place_order(self, *args, **kwargs):
        raise LiveTradingDisabled("live orders structurally unavailable")

    def cancel_order(self, *args, **kwargs):
        raise LiveTradingDisabled("order endpoints structurally unavailable")
