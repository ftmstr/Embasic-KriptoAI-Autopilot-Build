# RC658 — Synthetic Public Build release integrity / signature design gates

Status: DESIGN & REVIEW CHECKLIST ONLY — NO RELEASE, SIGNATURE, DEPLOYMENT OR RESTORE
Date: 2026-11-06. Scope: independently authored **public, synthetic-only** Python artifacts. This is not the private research, financial PnL or market-validation protocol.

## Immutable restrictions
- `LIVE=DISABLED`; `FINAL LOCKED=SEALED`; exactly-one-fit unused; `+20% NET NOT_TESTED`.
- No private repository history, checkpoints, balances, exchange credentials, real trades, models, strategy tuning, raw market data, proprietary parameters or production exchange adapters.
- **No real live orders, restores, model training or trading-evaluation runs in CI.**
- Public Build tests may use invented mock ledger and ZIP/JSON fixtures only.
- Public Build's separate open-source **license grant is not decided**; do not infer a grant from repository visibility.
- Five existing Draft PRs (#1–#5) must not be auto-merged. PR #1's 18 regression tests are not included in this validation branch, so combined PR #1 + RC650–RC653 regression remains NOT RUN.

## Artifact integrity acceptance, still PENDING
1. Choose the owner's redistribution/license decision and complete a file-by-file legal + independent security review, including current code AND full Git history and Actions artifact/log exposure.
2. Build a byte-reproducible, allowlisted source/package archive with fixed ZIP metadata, member type, max size, strict ASCII paths, and Windows reserved-name protection. Reject unsafe symlinks, absolute paths, `..`, UNC paths and ADS colons. No secret files or runtime adapters.
3. Produce a canonical JSON manifest: versioned format, every included file SHA-256 and size, archive SHA-256, exact source commit and explicit previous-release/rollback commit, explicit false values for live permission and scientific validation. Check duplicates, incorrect types and noncanonical encodings fail-closed.
4. Authenticate the release provenance separately: require an **independently trusted** signer identity/public key, verified signature over an approved manifest/provenance statement, and trusted source commit and digest. Hashes and 40-character strings **alone do not authenticate a publisher**. A possible future method is an owner-approved, pinned implementation of DSSE/in-toto or another reviewed signing scheme; do not introduce network, credentials, OIDC permission, keys or a new dependency in current CI.
5. Source provenance must bind reviewed source tree to CI exact commit, both GitHub-hosted Ubuntu and Windows job/run/log successes (plus later server smoke), fully reviewed PR integration, explicit license and release sign-off. Independent reviewer must check identity, authorized scope and workflow permissions.
6. Release materials must include checksums, SBOM/dependency inventory (including zero third-party Python requirements if applicable), rollback instructions, reproducibility metadata, and a release-blocking test report. Do not upload or publish an artifact automatically.
7. A rollback candidate must be **separately approved and signed**, checked with out-of-band expected digests, tested in a disposable, isolated environment, and verified to restore the intended synthetic state. An in-memory ZIP smoke or presence of `rollback_commit` is NOT an executed rollback.
8. A real Windows installer, Ubuntu package and server service startup must have their own isolated smoke/run/rollback/permission/secret checks before the packaging gate passes. Running unit tests on Windows is useful evidence but is not installer certification.

## Evidence discipline
- GitHub-hosted Python 3.13.5 Ubuntu synthetic tests: predecessor RC657 302/302 PASS, run 42261201627, commit 8222eadaf015615619bf94a4f82a5894c1a204aa.
- RC658 adds Windows-hosted synthetic unit test coverage and hardens the synthetic snapshot path allowlist. **Do not claim either platform PASS until each new run reaches completed/success and the test count is read from actual job logs.**
- No claim of PR #1 compatibility or private scientific performance / +20% return follows from CI.
- The ten-gate Public Build engineering checklist remains at **5/10**, until independent security/license review, PR merges, platform packaging, signed release/rollback and main branch combined CI are actually proven.

## Review disposition
Engineering/test design only. An independent person must explicitly approve license, source publication, signature identity, artifact provenance, package smoke and risk gates. This document itself grants no permission to trade, train, merge, issue a production release or publish proprietary research.
