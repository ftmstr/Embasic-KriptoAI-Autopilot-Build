# RC652 — Public, synthetic-only spot reserve and journal (Tur 3)

**Date:** 2026-10-24. **Public repo:** `ftmstr/Embasic-KriptoAI-Autopilot-Build`. Source branch `research/rc652-synthetic-spot-reservations`, stacked on RC651 Draft PR #3 head `befdb43b5ac0bd89f57b867a1bb748d17f54fe87`. **This is not a real exchange, a trading application, a cryptographic signature, or investment-performance evidence.**

## Changes / design

- `safe_public_ci/offline_spot_ledger.py`: independent Python 3.13.5 **stdlib only**, *composes* with `safe_public_ci/offline_order_fsm.py` without adding a network or exchange interface.
- `tests/test_offline_spot_ledger.py`: **47** deterministic adversarial unit tests with strictly invented IDs, ticks, lots, fees and balances.
- `tests/test_guard.py`: strengthen the old fixed import whitelist to permit only the named RC651 FSM seam among `safe_public_ci.*` imports; Python `re` and `__future__` remain explicitly allowlisted standard-library imports; no arbitrary third-party or dynamic imports or `eval/exec/open/compile` in runtime modules.
- Every `SyntheticLedgerPolicy` is `frozen`, typed, bounded and hashed into the **genesis** of the journal chain; client-supplied mutable risk switches are not accepted. These are *in-process toy* policy controls, not cryptographically tamperproof permissions.

## Exact supported toy semantics

- **BUY:** at order acceptance, reserve `quantity × limitPrice + quantity × ceil(limitPrice × fee_bps / 10000)`, so rounding overhead remains covered for **arbitrary partial fill segmentation**. Debit actual fill price plus its fee; credit base units. Any unused reserve is released on terminal fill, cancellation or rejection.
- **SELL:** reserve base units, decrement base on fill and credit net synthetic quote proceeds after fee; release remaining base on cancel/reject. Fill price must not be worse than limit for either side.
- Exact duplicate synthetic client ID is idempotent even after the order fills or a kill switch has been activated. Conflicting duplicate IDs, event gaps, double fills, overfills, impossible negative balances, future/stale invented market observations and unsafe fields fail closed.
- **Timeout:** RC651 enters `UNKNOWN`, reserve stays held and no blind resubmission occurs. A synthetic reconciliation can release or unfreeze *only* when the cumulative fill amount agrees with all already priced fill receipts. Any **new, unpriced fill delta** is rejected instead of fabricating its execution price, fee or book balances. Integration with authenticated exchange reconciliation is NOT IMPLEMENTED.
- **Journal replay:** in-memory append-only-style hash chain binds canonical payload, event index, previous digest and policy genesis; a replay function checks order, journal hash, policy identity and an expected external final hash/count. A *trusted durable* external receipt source, crash-safe persistence and cross-process concurrency are **NOT IMPLEMENTED**. This is only ephemeral synthetic replay for test/research.
- Nonresettable toy `kill_switch()` refuses any new order, but allows reconciliation of existing unknown outcomes. No network, bourse API, live order, PnL, ML fit/evaluation, prospectively locked data or financial service usage.

## Tests and known limitations

Reconstructed Public exact source files through current GitHub plus the RC651 locally verified ZIP. Local CPython 3.13.5 commands:

```
python -m compileall -q safe_public_ci tests
python -m unittest discover -s tests -v
```

**150/150 local PASS = 103/103 predecessor Public + 47/47 new RC652**, not GitHub-hosted full checkout CI. New Python code and test files were read back from GitHub and compared to identical local Git blob SHAs. Existing CI workflow `.github/workflows/synthetic-ci.yml` only has `push: main` and `workflow_dispatch`, **not a PR trigger**, so fresh Draft PR check-run success is not implied. PR CI can be designed to use `pull_request` **not** `pull_request_target`, a GitHub-hosted runner, minimum read-only token permissions and SHA-pinned actions, but CI will be marked NOT RUN until the actual exact-commit run succeeds.

**Non-goals / gates:** no exchange precision/market metadata, order book, fees at real Binance/MEXC rates, slippage, funding, account balance authentication, signed build, independent PnL, credible net returns, recovery after actual process crash, persistence, concurrency, multi-process risk control, Windows/Ubuntu/server application installation or any trade permission. Because Public can be cloned even after later privacy changes, PRIVATE strategies/weights/checkpoints/keys/data are prohibited in all Public artifacts.

**Rollback:** close the Draft PR and delete the RC652 feature branch after review; `main` and the original Private research repo are unchanged.

**Private read-only scientific reference:** canonical RC631; 29 frozen symbols, 16 features, exactly-one-fit UNUSED, `FINAL LOCKED=SEALED`, `LIVE=DISABLED`, fresh-forward accepted 0/28, +20% net NOT TESTED, original provider archive independent 0/58 verification NOT RUN. These are reference facts, not transferred Private checkpoint source.
