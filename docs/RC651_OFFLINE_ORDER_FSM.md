# RC651 / Tur 2 — Synthetic offline order state machine

**Repository**: PUBLIC `ftmstr/Embasic-KriptoAI-Autopilot-Build`. Based on RC650 Public Draft PR #2 at `af558d3f72fd953d151ffd7d030398677beab854`. All code in this change is independently authored, not imported from or mirrored from the PRIVATE research repository. No training, exchange API, secrets, market data, PnL or live orders.

## Source-inspired, independently developed design

- Hummingbot `hummingbot/core/data_type/in_flight_order.py` (Apache-2.0): track partial fills, cancellation and terminal statuses explicitly.
- Hummingbot `hummingbot/connector/exchange/mexc/mexc_exchange.py` (Apache-2.0): distinguish local client identifiers and exchange execution status; **no** MEXC adapter or real exchange order ID in our module.
- CCXT `python/ccxt/base/errors.py` (MIT): separate ambiguous timeouts, duplicate order ID and invalid order rather than treating them all as failed orders.
- NautilusTrader Rust execution engine `crates/execution/src/engine/mod.rs` (LGPL-3.0): deterministic event-driven state machine and recovery seam, implemented independently in Python.
- LEAN `Engine/TransactionHandlers/BrokerageTransactionHandler.cs` (Apache-2.0): ordered event audit, terminal-state handling and in-flight-order bookkeeping.

**No GPL, AGPL, LGPL, MIT or Apache third-party code was copied.** Repository itself currently grants no general open-source reuse license; conversion to private at a later date will not revoke preexisting clones/forks.

## Exact new safe functionality

1. `safe_public_ci/offline_order_fsm.py`: Python 3.13.5 stdlib-only, in-memory. Synthetic ID = domain-separated deterministic SHA-256. Inputs restricted to `SYN-SEED-...`, `SIM-...`, `SIM-EVT-...` and `SYN-PAIR`.
2. A recorded order begins `PENDING_ACK`; permitted transitions cover `OPEN`, `PARTIALLY_FILLED`, `CANCEL_PENDING`, `CANCELED`, `REJECTED`, `FILLED` and `UNKNOWN`. Completely invalid transitions cause an exception **before any state mutation**.
3. Unknown/ambiguous `TIMEOUT` freezes the order. A synthetic `RECONCILE` with monotone cumulative filled units is required to recover; the simulator never blindly retries an unknown request. Duplicate event IDs are accepted only for identical payloads and do not double count fills. Conflicting IDs, gaps, overfills, terminal fills, inconsistent cancellations and false rejections fail closed.
4. Deterministic `OfflineRiskPolicy`: hard per-order integer quantity, cumulative requested units and maximum unique orders; ignores model instructions. Freshness is checked at intent admission and transport latency at each event. Session exposure never releases after a simulated cancellation, which is intentionally conservative and not inventory-risk accounting.
5. Permanent `kill_switch()` disallows new entries, while allowing synthetic reconciliation of already-observed events. `place_real_order()` and `cancel_real_order()` raise `LiveTradingDisabled`. The class has no network client or real order paths.
6. In-memory append-style SHA-256 audit digest supports deterministic toy replay, **not** signed/nonrepudiable evidence, durable persistence or tamper-proof logging.

## Test coverage and discovered regression

Run from the Public repository root:

```sh
python -m compileall -q safe_public_ci tests
python -m unittest discover -s tests -v
```

Actual local Python 3.13.5 test count after source reconstruction and code fixes: **103/103 PASS**, comprising new RC651 order tests **53**, new static security guard tests **2**, RC650 synthetic-stream tests **25** and baseline older tests **23**. Source/test/updated-guard byte identities are verified using Git blob SHA-1. Existing guard `tests/test_guard.py` had an overly narrow import allowlist which rejected `re` and `__future__` already used by RC650. This stacked RC651 change allows these two **stdlib** modules but keeps arbitrary imports, network libraries and dynamic import/exec calls forbidden. **RC650 Draft PR #2 alone requires this follow-on fix before its combined suite can be treated as green.**

**Important CI qualification**: The existing `.github/workflows/synthetic-ci.yml` only runs automatically on `push: [main]` or explicit `workflow_dispatch`. A successful GitHub-hosted CI run for the RC650 or RC651 unmerged feature commits has NOT been verified. Local unit tests are not GitHub Actions CI.

## Explicit limitations / acceptance gates

- No actual Binance/MEXC Spot connectivity, exchange-specific precision, fees, funding, slippage, partial fill prices, ledger cash balance, portfolio risk, persisted crash recovery, out-of-process or multi-threaded concurrency, real exchange reconciliation or signed artifacts. Each requires independent future authorization and hardening.
- Model training / financial validation / PnL / +20% net tests **NOT RUN**.
- Private scientific reference: RC631; 29 frozen symbols, 16 features, exactly-one-fit UNUSED, FINAL LOCKED=SEALED, LIVE=DISABLED, canonical fresh-forward 0/28. This document asserts historical read-only reference, not a copied Private checkpoint in the Public repository.
- **PASS acceptance**: 53/53 new tests, 103/103 reconstructed local Public full-suite, Python compileall, in-memory deterministic and fail-closed transitions, exact Git blob hashes for new/updated sources, PR still DRAFT.
- **NOT RUN acceptance**: target OS native app tests, GitHub Actions successful run for exact feature commit, any live order/exchange credentials, independent Binance ZIP/CSV verification, economic trading performance.
- Rollback: close the Draft PR and delete the feature branch after review; no main or Private files modified. There is nothing to uninstall on a server.

## Next research cycle

Review the Draft PR and verify a safe read-only PR-triggered CI workflow or explicitly authorized manual workflow. Then research deterministic offline risk/quantity precision, order-book synthetic liquidity, order-fingerprint collision resistance and recovery snapshot persistence under independent tests. Real-money trading stays disabled.
