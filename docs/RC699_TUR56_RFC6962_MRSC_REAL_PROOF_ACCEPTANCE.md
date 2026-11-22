# KriptoAI Autopilot — TUR56 / RC699: authentic Merkle-inclusion arithmetic, MRSC limits, external authority NO-GO

**Date:** 2026-11-17 (Europe/Istanbul). **Authorized scope:** PUBLIC `ftmstr/Embasic-KriptoAI-Autopilot-Build`, branch `validation/rc654-pr1-rc653-combined-ci`, existing open Draft/unmerged PR #7. No private repo, merge, deploy, exchange execution, model fitting, profit claim, new root, workflow edit or changes to existing preflight.

## Independent TUR55 baseline readback

At start, Public validation HEAD and Draft PR #7 HEAD exactly `68ef3bf1ced615008b2ab089265f85fe7d83dac3`, 158 Git tree entries, **no RC699/TUR56 or later files**. Public main `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`; PR #1 remains Draft/unmerged with 18 unapproved tests isolated.

Original GitHub-hosted Ubuntu run `43930181696`, job `133520189057`, and Windows run `43930181680`, job `133520188699`, each completed/success on the same exact TUR55 source SHA, 9/9 real steps SUCCESS. Full fetched independent original job logs: Ubuntu 511906 characters, 3058/3058 unique `... ok`, 24 RC698 cases, `Ran 3058 tests in 10.535s; OK`; Windows 523457 characters, 3058/3058 unique `... ok`, 24 RC698 cases, `Ran 3058 tests in 37.690s; OK`. Both have no FAIL/ERROR/skip/ResourceWarning. Initial TUR54 failed runs `43848891904` and `43848891851` remain genuine failures; older failed runs also retained.

Protected workflow Git blob hashes: RC652 `28fedf1e76f1d26247fcb1897c176bc3b7009808`; RC653 `d7a08e1935b060d31feca2e1ef8db4184268858c`; RC654 Ubuntu `140264aaf07f3130a23606254f545b4ff77b1971`; RC658 Windows `254ac4f4ea821a05ee4730c3828d4de1b96a0e72`; general synthetic `1cd73e647401f75ae9a98f55d8adcd166a366fe3`. RC656 snapshot `7db54362bb627b26f9be0c09bb958a8601c961a2`, `MAX_ENTRIES=32`; RC655 preflight blob `74768b736b4356c580a45ade85f701363e6b4972`. No forbidden top-level directories.

## Primary source research: actual provider capability and genuine evidence boundary

**Rekor and Merkle verification.** Rekor's public specification explicitly calls for RFC6962 audit paths, signed checkpoints, append-only consistency and independent witnesses: https://github.com/sigstore/architecture-docs/blob/main/rekor-spec.md . Official RFC6962: https://www.rfc-editor.org/rfc/rfc6962 . Its formulas are `SHA256(0x00 || original_leaf_bytes)` for leaves and `SHA256(0x01 || left_subtree_hash || right_subtree_hash)` for internal nodes; splitting at the greatest power of two smaller than the subtree size. A cryptographically correct inclusion equation **does not** validate checkpoint origin/signature, witness cosignature, consistency with earlier checkpoints, original subject signer, or release authorization. As of the Sigstore Rekor V2 client architecture, include proof/checkpoint in the supplied bundle; do not assume online lookups/search are available: https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md . No such subject-specific bundle or externally witnessed checkpoint was acquired from a legitimate independent party in this turn.

**AWS DynamoDB correction and current source-grounded provider route.** Official documentation distinguishes MREC (eventually replicated, last-writer-wins) from **MRSC**, introduced in 2025, which synchronously replicates across a 3-region group, supports latest-version strongly consistent reads and conditional writes, but **does not support `TransactWriteItems`/`TransactGetItems`**. MRSC setup is limited to supported region groups and requires three regions with replicas/witness. It does not itself prove independent key custody, anti-restore fencing, different administrative authority, or absence of privileged rollback. No AWS account, DynamoDB table, physical multi-host run, recovery drill, or external audit was provisioned. Sources: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html and https://docs.aws.amazon.com/prescriptive-guidance/latest/dynamodb-global-tables/overview.html .

**GitHub raw job log vs artifact attestation.** GitHub REST `/actions/jobs/{job_id}/logs` returns a redirect to a downloadable plain-text job log, not an authenticated signature over its full raw contents; https://docs.github.com/en/rest/actions/workflow-jobs . GitHub artifact build provenance separately requires workflow `attest` action and `id-token: write` + `attestations: write`, prohibited changes under this task. Even a correct artifact attestation is not automatically a GitHub-origin signature over all raw job log bytes. https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations .

No actual independently approved owner/reviewer Ed25519 custody, trusted time/revocation issuer, provider-original full-job-log signatures, external root/witness authorization, remote linearizable CAS, or authenticated remote ACK has been verified. All **0/8 BLOCKED**; no synthetic assertion or good CI log is an external security attestation.

## Unique engineering deliverable

`safe_public_ci/ci_rc699_merkle_mrsc_acceptance.py` adds actual stdlib-only **RFC6962 Merkle inclusion arithmetic** on exact supplied entry bytes, strict source SHA, checked audit sibling hex values, leaf index/tree size, domain-separated leaf/parent SHA-256 and canonical subtree reconstruction; rejects tampering, under/overlong paths and invalid indices. Successful output is explicitly `VALID_UNTRUSTED_ROOT` with signed checkpoint, trusted log origin, independent witness, historical consistency and subject signer **all False**. This is arithmetic on untrusted input **not a real Rekor inclusion attestation**.

The same module evaluates a precisely constrained **MRSC conditional-write candidate** versus invalid MREC/global-LWW routes, wrong region cardinality, unsupported MRSC transaction APIs, weak-read/nonconditional settings and self-asserted independent-administrator or anti-restore tests. Valid MRSC design remains `BLOCKED` until independently provisioned and measured with multi-host contenders, durable fence and restore drills. An 8-slot genuine external proof-acquisition contract and domain-separated challenge/nonce/audience scope cannot promote any gate.

The 24 new targeted RC699 tests independently build real RFC6962 roots and audit paths across every leaf of trees of sizes 1–20 (210 correct-inclusion subcases), tamper paths/leaves/indices, and verify MRSC service-mode incompatibilities, and keep external authority blocked. **Local actual CPython 3.13.5**, `PYTHONWARNINGS=error`: 24/24 PASS, `compileall -q` PASS, AST parse PASS. Both source and tests use no IO/network/exchange operations.

### Exact local tested source byte identities

| New file | Bytes | Git blob SHA-1 | Raw SHA-256 |
|---|---:|---|---|
| `safe_public_ci/ci_rc699_merkle_mrsc_acceptance.py` | 9518 | `b8aea67ed1fee762a922c6134ce6fa99c45d294c` | `9279c8c3330f5bdcd4e7eb10ee914ea6a5a7aee48200e3429f6a09cc911b6b52` |
| `tests/test_rc699_merkle_mrsc_acceptance.py` | 8457 | `3d7a612f6d7bd0cea1be04d53e81f910066ad4ef` | `e677986ac7c73d35b05a3b387936983ffbf13a30060cc9c4e772a153e9ca99ad` |

Report first, tests second, **source committed last** so the unchanged GitHub Ubuntu/Windows workflow filters trigger at the same final source SHA. Expected full regression test count **3082 (3058 + 24)**, but **do not call it PASS until both final-HEAD original complete job logs independently confirm it**. Preserve all genuine failures as failures; annotate final native evidence in a PR #7 comment instead of modifying the source/report after CI.

**Hard locks:** `FINAL=SEALED`, `LIVE=DISABLED`, `SINGLE_FIT=UNUSED`, `+20% NET=NOT_TESTED`, `AUTH=NO-GO`. No release/merge/deploy/real order/fit/financial return claim.
