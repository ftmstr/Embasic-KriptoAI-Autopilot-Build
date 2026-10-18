# Public Build safety boundary

- This separate public repository has no copied private Git history.
- No private scientific checkpoints, strategies, model weights, raw market archives, API credentials, real accounts, orders, or custom trading implementation.
- All Python runtime data is invented in memory; no exchange SDK, HTTP client, or production adapter.
- The mock refuses every order and cancellation call; CI has no pathway to private trading.
- Run only on GitHub-hosted ubuntu-latest; no self-hosted runner or pull-request triggered workflow. Keep token read-only and do not persist credentials.
- No open source license is granted without a separate owner decision.
- Scientific locks: FINAL LOCKED=SEALED, LIVE=DISABLED, single-fit unused; +20% net NOT TESTED.
- CODE PASS does not establish SCIENTIFICALLY VALIDATED.
