# RC653 — Synthetic receipt integrity: security-first design review

Status: DESIGN ONLY / NO IMPLEMENTATION / NO CI CLAIM
Date: 2026-10-29
Base: RC652 Public Build commit 4ee0b2d2cacdb9cc1036f390c323f6d46b9f371d.
Scope: entirely invented, in-memory journal data. No private repository contents, exchange access, money, model evaluation or training.

## Verified predecessor evidence

The RC652 Public Draft PR #4 GitHub-hosted run 40113908877 completed successfully for commit 4ee0b2d2cacdb9cc1036f390c323f6d46b9f371d (154 tests / OK). RC652 is stacked on Draft PR #3 (RC651), which is stacked on Draft PR #2 (RC650); all remain unmerged. Draft PR #1 separately proposes 41 synthetic regression tests. Production main remains 0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471.

## Design invariants and unverified threats

1. Receiver must reject oversized bytes before JSON decoding; enforce fixed entry count, individual record size and nesting limits. Resource-exhaustion resistance requires measured limits, not a claim from a successful toy test.
2. Receipt must use a single strict canonical encoding with exactly defined fields and refuse duplicate keys, nonfinite numbers, incorrect types, noncanonical whitespace and unknown fields.
3. Reject missing, extra, reordered, duplicated or modified journal records; verify every index, predecessor digest, payload and final digest through deterministic replay.
4. Expected final digest and record count must originate from an independently trusted channel. If an attacker controls both payload and expected hash, an ordinary SHA-256 checksum is NOT authenticity or tamper-proof evidence.
5. Replay must bind the synthetic policy to the journal genesis. Accept no external real-account data, credentials or confidential strategy parameters.
6. Every synthetically simulated order or cancellation must remain in the closed mock; no transport adapter, SDK, network requests, credential input or real-market symbol.
7. Neither decode nor encode may touch a filesystem, execute programs, download dependencies or emit model/financial metrics.
8. Reconciliation of an unknown fill without a priced receipt must remain fail-closed; never invent a transaction or release reserve without authoritative synthetic state.
9. A hash chain is not a signed, durable, crash-safe or concurrency-safe transaction log. Those capabilities are OUT OF SCOPE.
10. Keep exact CPython 3.13.5, stdlib-only modules, GitHub-hosted runner, read-only token, immutable action pins and synthetic-only test fixtures.

## Proposed acceptance tests (NOT YET RUN)

- Valid toy receipt round-trip with externally supplied trusted digest and expected entry count.
- Missing record, duplicate index, record reordering and final-tip corruption are rejected.
- Wrong policy, altered initial balance, modified fee or changed journal kind are rejected.
- Oversized payload and entry, malformed UTF-8, unknown JSON fields, duplicate keys, NaN and excessive nesting are rejected without partial state publication.
- Completely identical input yields identical serialized bytes and checksums across repeated runs.
- Live trading, financial performance, private account and scientific-validation capabilities remain absent in code and CI.
- Full existing synthetic regression suite remains green on exact new commit SHA, with run / job / step / log evidence.

## Release blockers and disposition

The RC653 GitHub source-module and test-file creation requests in the previous turn were explicitly blocked by connection security controls. The denial is NOT bypassed. No RC653 source commit or CI PASS is claimed. This design document can be reviewed without opening an implementation path until tool permissions and the security boundary permit it.

No changes to Private ftmstr/KriptoAI-Autopilot. Its RC631 checkpoint remains the authoritative observed reference: FINAL LOCKED=SEALED; LIVE=DISABLED; exactly-one-fit unused; +20% NET NOT_TESTED. The checkpoint's 0/28 accepted days is historic and not proof of current advancement.

This note is not permission to merge, train, evaluate models, trade, or publish a final release.
