# Public Build safety boundary

- This separate public repository has no copied private Git history.
- No private scientific checkpoints, strategies, model weights, raw market archives, API credentials, real accounts, orders, or custom trading implementation.
- All Python runtime data is invented in memory; no exchange SDK, HTTP client, or production adapter.
- The mock refuses every order and cancellation call; CI has no pathway to private trading.
- Run synthetic-only CI exclusively on GitHub-hosted Ubuntu and Windows runners (currently ubuntu-24.04 and windows-latest), never self-hosted or pull-request-triggered workflows. Keep all tokens read-only; do not persist checkout credentials. Cross-platform acceptance requires both jobs to pass at the EXACT SAME reviewed commit SHA; passing different commits is insufficient. CI does not authorize signing, uploading, deploying, trading, model training, or real rollback.
- No open source license is granted without a separate owner decision.
- Scientific locks: FINAL LOCKED=SEALED, LIVE=DISABLED, single-fit unused; +20% net NOT TESTED.
- CODE PASS does not establish SCIENTIFICALLY VALIDATED.
