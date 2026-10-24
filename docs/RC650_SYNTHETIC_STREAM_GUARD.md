# RC650 — Public synthetic event-time guard

Scope: public synthetic-only code. No private sources, strategy parameters, checkpoints, model, exchange data, credentials, trading SDK, APIs, network calls, financial evaluation, or real orders.

## Feature
`safe_public_ci/synthetic_stream_guard.py` is an original independent Python 3.13.5 standard-library implementation. The sole input is a tuple of invented `SYN-000`-style events. Validates fixed incremental sequence numbers, uniqueness, strict event/reception timestamp order, observation-time cutoff, stale last event, transport delay, positive integer toy ticks, bounded input count and value types. It emits a reproducible SHA-256 receipt of the accepted invented events. No external library is linked or source copied. The receipt explicitly sets market attestation, scientific validation, production readiness and trading to false.

`tests/test_synthetic_stream_guard.py` contains 25 independent deterministic synthetic tests, including future-data leakage, gap/duplicate events, bad types, stale events, and checksum stability. Run:
```sh
python -m compileall -q safe_public_ci tests
python -m unittest discover -s tests -p 'test_synthetic_stream_guard.py' -v
```
Only 25/25 RC650 local tests were directly executed; existing Public CI full-suite on this commit remains NOT RUN until GitHub Actions supplies a new status. Any previously published 41/41 CI number applies to an earlier commit and is not proof of this PR's pass.

## Scientific/production boundary
No historical or prospective original Binance archives are accessed. No model selection, training, score, +20% net return, backtest or PnL. This public repo is an independent synthetic engineering harness, not a verified live trading product. Never transplant Private repo code/data. A later private production deployment would require independent security and compliance review, full dependency/license inventory, a signed build, target-OS tests, a separately reviewed execution permission gate and explicit human approval.

## Prior art and licensing
The original design is inspired by engineering *ideas*, not copied code: Freqtrade's lookahead discipline (GPL-3.0); Hummingbot's tracked order state (Apache-2.0); NautilusTrader's deterministic event-driven execution (LGPL-3.0); CCXT exchange error typing (MIT); LEAN event-based simulation (Apache-2.0). No direct library integration or third-party code is included. Public repository still contains no open-source license grant; reusability by others and any later relabeling must be decided separately by the owner.

## Next small gates
1. Exact checkout Public GitHub Actions test and deterministic hash readback.
2. Separate offline fake-order state machine (no real connector), duplicate client order ID and ambiguous timeout cases.
3. Separate stale-data/latency reports and clock/cutoff tests. Do not tune strategies on final holdout.
4. Audit complete project dependencies and licensing before adding any real connectors.
