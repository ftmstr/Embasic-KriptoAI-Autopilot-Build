# KriptoAI Autopilot — TUR41 / RC684 — Out-of-Band Provenance Quarantine + Disposable Real SQLite CAS Crash Audit

**Date:** 2026-11-12. **Scope:** ONLY Public \`ftmstr/Embasic-KriptoAI-Autopilot-Build\` existing \`validation/rc654-pr1-rc653-combined-ci\`, open/unmerged Draft PR #7. Synthetic-only; no exchange API, trading, ML training, production deployment, or release.

## 1. Exact entry evidence and do-not-repeat check

- Draft PR #7 and validation branch started at RC683 final \`3dfba1a9d23df08975cbd9838a4c2ed82924d856\`; GitHub compare \`identical\`, ahead=0 and behind=0. RC684/TUR41 or a later tur was absent in entry tree. Public main \`0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471\` unchanged. PR #1 remains separately open/Draft at \`710517be3b4a0a671458b6e6cad0261138d0b3b0\`; its 18 approval-gated tests are NOT imported.
- TUR40 Ubuntu real run [#43201479202](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43201479202), job \`131125730519\`, push attempt=1, exact RC683 SHA, completed/success, **9/9 steps successful**, original full job log 279903 characters, **1637 unique \`... ok\` rows**, \`Ran 1637 tests in 9.894s\` and \`OK\`, 83 RC683 rows, zero failures.
- TUR40 Windows real run [#43201479162](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43201479162), job \`131125730790\`, push attempt=1, same exact SHA, completed/success, **9/9 steps successful**, original full log 290006 characters, **1637 unique \`... ok\` rows**, \`Ran 1637 tests in 11.168s\` and \`OK\`, 83 RC683 rows, zero failures. These are prior-TUR results, NOT RC684 final CI evidence.
- RC683 final source/test GitHub blobs \`1bfd211e01366e423d770c3545ce3e36e17dbdfe\` / \`e9a0842a59293e7cd092398c36267e2843dcfe90\`; RC683 report \`4bc8e9759a14188d285d450844a31253014376dc\`. Its independent local raw SHA-256 entries are preserved unchanged.

## 2. RC684 original implementation: no false out-of-band authority

New \`safe_public_ci/ci_external_provenance_quarantine.py\` uses only allowlisted \`hashlib\`, \`hmac\`, \`re\`, and has no network/filesystem/store, order client, credentials, model fitting or dynamic \`open/compile/eval/exec/__import__\` calls.

- Fixed-schema, bounded, typed, length-prefixed and domain-separated SHA-256 transcript of the **entire provided claim**, not a signature. Binds Git/source/workflow/roster, RC683 checkpoint digest, two syntactically distinct owner/reviewer fingerprints and role-validity windows, synthetic revocation chronology, Ubuntu/Windows run/job/full-log-hash claims, CAS epochs and claimed one winner, replay histories, nonce and ACK state, and permanent no-live flags.
- Disallows key/actor duplication, expired or syntactically revoked key at claimed observation time, duplicate run/job, foreign source, false \`verified\` flags, duplicate CAS actor/winner, stale generation, epoch-ABA, conflicting roots, nonce/root replay and false ACK / LIVE / release.
- Caller-supplied pinned expected SHA/fingerprints are structurally compared but **never** independent root provenance. Set \`verified_oob_issuers\`, \`verified_provider_origin\`, \`verified_revocation_origin\`, or \`verified_transactional_cas\` to true and the API **rejects**: users cannot self-assert a completed external gate.
- **Every valid claim** returns \`EXTERNAL_PROVENANCE_CLAIMS_QUARANTINED_NOT_AUTHENTICATED\` and all authority, origin, clock, Merkle anchor, durable CAS, restart recovery, release and trading flags false. \`ACK_LOST_UNRESOLVED\` remains unresolved.
- The checker neither fetches real GitHub signed run receipts nor authenticates out-of-band ownership, Ed25519 keys, revocation timestamp authority, independent witnesses, Merkle history or a persistent monotonic counter. RC683's mathematical two-signature verifier remains separately intact; no new AUTHENTICATED path is created.

## 3. Original local 94-test suite: evidence vs claims

New \`tests/test_rc684_provenance_and_sqlite.py\` has **76 fabricated provenance adversaries** + **18 real local SQLite disposable-CAS tests** = **94 new tests**.

SQLite harness lives ONLY under \`tests/\`, not \`safe_public_ci/\`; temporary directory/database; \`sqlite3\` with \`PRAGMA synchronous=FULL\`, \`BEGIN IMMEDIATE\`, conditional generation/root UPDATE, unique nonce table and \`COMMIT\`. Test cases include:
- two concurrent thread contenders accessing one temporary file: **one COMMITTED, the other STALE**, and generation increments exactly once;
- conditional generation + root CAS rejects stale readers, replayed nonce, duplicate contenders, epoch-ABA and rollback;
- subprocess with \`os._exit(61)\` **before COMMIT**, and \`os._exit(62)\` **after COMMIT but before acknowledgment**; reopening SQLite confirms correct transactional rollback/persistence and lost-ACK replay handling;
- an independent malicious DB-admin synthetic rollback that overwrites state and clears replay table **defeats** the local test store: a subsequent old-generation CAS can again commit. This is a deliberate **threat-model counterexample** demonstrating the absence of an external immutable monotonic trust anchor. Do not hide or treat as PASS for anti-rollback security.
- The test verifies disposable local SQLite under specific process termination and concurrency conditions. It is **NOT** an application production CAS implementation, multi-host proof, sudden power-loss proof, secure revocation service or cryptographic owner attestation.

Local CPython **3.13.5** executed:
\`\`\`sh
PYTHONPATH=/mnt/data/kripto_tur41 python3 -m unittest discover -s /mnt/data/kripto_tur41/tests -p 'test_rc684*.py' -q
# Ran 94 tests in 2.090s — OK
python3 -m compileall -q /mnt/data/kripto_tur41/safe_public_ci /mnt/data/kripto_tur41/tests
# PASS
\`\`\`

Python AST source import audit \`hashlib, hmac, re\` only; banned direct calls \`open, compile, eval, exec, __import__\` = zero.

| Locally tested exact new artifact | Git blob SHA-1 | raw SHA-256 |
|---|---|---|
| \`safe_public_ci/ci_external_provenance_quarantine.py\` | \`9ed299d4e9547967d803fc3e6c98215336ddab9a\` | \`3962e44647f40094c141808dbb74a6bff37212b1fa866f90a9e8bbc2bb7a2914\` |
| \`tests/test_rc684_provenance_and_sqlite.py\` | \`1b3edad07abc4291e775b7682d729ba1f67c9bf0\` | \`9b74b383b2b03515b405252f626b838160b82a00a093f14392e437cc4202c491\` |

GitHub exact-byte readback for **2/2** files was independently confirmed after Public validation writes. Any final source-only edit requires another local run and final blob readback. Temporary staging Library copies were removed after upload; no Private repo touched.

## 4. Hosted exact-final-SHA CI is a separate acceptance gate

Expected comprehensive unittest count = prior 1637 + 94 = **1731 per OS**. **Do not call this PASS until actual native Ubuntu and Windows runs on the exact final HEAD independently show**:
1. run \`completed/success\`, correct commit/push/attempt;
2. real OS job \`completed/success\`;
3. **9/9 successful steps** including postlude;
4. ORIGINAL complete verbose job log with **1731 distinct \`... ok\` lines**, \`Ran 1731 tests\` and \`OK\`; **94 RC684** new rows, no failures/skips mislabeled successes;
5. exact-final-Git-blob SHA-1/SHA-256 match.

Log unavailable, stale SHA, queued, no-job, in_progress, incomplete step or missing full-log = **NOT VERIFIED**. Add final run/job/log evidence to PR #7 after final head is fixed; do not advance that head afterwards.

## 5. Immutable NO-GO and TUR42 handoff

- **FINAL=SEALED, LIVE=DISABLED, SINGLE_FIT=UNUSED, +20% NET=NOT_TESTED**. No orders, real exchange integration, fit, deployment, merge, security-check bypass or profit claim. Public main, Private repo, workflow triggers/permissions and unsafe import/call bans remain untouched. Historical PR #7 body archive and all RC669–RC683 reports retained; no PR #1 approval-gated test integration.
- Native user-facing Windows/Ubuntu/server product acceptance remains 0/3; previously documented owner publication checklist 5/10=50% is **not** whole-product readiness, cryptographic attestation or return.
- The needed independent cryptographic **real** key-origin distribution, owner/reviewer authority, authentic signed revocation ledger/time, GitHub provider origin attestations, externally committed Merkle checkpoint, app-integrated multi-process persistent transactional CAS, external anti-rollback and lost ACK reconciliation remain **unverified**.
- **TUR42 priority:** verify externally distributed immutable real trust anchor and signer authorization without self-pins; obtain genuine provider-signed artifact provenance; extend crash/restart tests to an app-integrated disposable service with independently durable monotonic anchor (explicit NO-GO if absent); preserve all NO-LIVE gates.


## 3A. Final local correction / warning gate

After the initial passing 94-case test run, a \`ResourceWarning\` revealed that some SQLite helper connections were committed but not explicitly closed. \`setup()\` and the adversarial administrative rollback helper were corrected to use \`try/finally: db.close()\`. The source-only end-of-file NO-GO comment was added; it changes no logic.

The **final locally tested source and test file bytes** are the SHA-1 and SHA-256 values in the table above. Final pre-upload verification used:
\`\`\`sh
PYTHONWARNINGS=error PYTHONPATH=/mnt/data/kripto_tur41 python3 -m unittest discover -s /mnt/data/kripto_tur41/tests -p 'test_rc684*.py' -q
# Ran 94 tests in 2.405s -- OK, no ResourceWarning.
python3 -m compileall -q /mnt/data/kripto_tur41/safe_public_ci /mnt/data/kripto_tur41/tests
# PASS
\`\`\`
Any earlier pre-correction blob hashes are historical staging, not final acceptance identities. Hosted CI must run with the **final source SHA** and updated warning-free test file at the exact same commit.
