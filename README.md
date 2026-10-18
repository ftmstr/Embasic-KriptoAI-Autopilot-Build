# Embasic KriptoAI Autopilot — Public Synthetic CI

This is a **standalone synthetic-only CI safety harness**, not the trading application. It contains no private strategy, real datasets, model weights, API keys, private checkpoint, trading adapter, or transferred Git history.

- Default SAFE_TEST_ONLY. No exchange client, network access, orders, model training/evaluation or financial-performance operations.
- Python 3.13.5, only Python standard library; synthetic JSON, ZIP metadata, Parquet envelope, offline mock exchange and toy checksum tests.
- GitHub Actions code PASS is not scientific validation or +20% return and does not authorize live trading.
- Canonical private research protocol retains FINAL LOCKED=SEALED, LIVE=DISABLED and exactly-one-fit unused.
- No open-source license or third-party reuse grant is given; licensing requires a separate owner decision.

## Local tests

    python -m compileall -q safe_public_ci tests
    python -m unittest discover -s tests -v

## Publication boundary

Never fork, mirror, import or checkout the private research repository here. No private Actions artifacts, account access, market APIs, external private code or real trading. Parquet check is envelope-only, not full validation.