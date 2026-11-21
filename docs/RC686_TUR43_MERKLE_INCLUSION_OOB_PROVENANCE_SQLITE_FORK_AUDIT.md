# KriptoAI Autopilot — TUR43 / RC686: independent inclusion math vs. alleged authority; disposable SQLite fork/ACK audit

**Date:** 2026-11-12 (Europe/Istanbul). **Allowed scope:** *only* Public `ftmstr/Embasic-KriptoAI-Autopilot-Build`, branch `validation/rc654-pr1-rc653-combined-ci`, open/unmerged Draft PR #7. This report is synthetic-only. No real trading, model training, live deploy, securities exchange credentials, real private key, or public deployment.

## 1. Verified entry SHA and previous full hosted logs

- Entry Draft PR #7 HEAD **`718f53246ae298504f28fc32c3c256ff893dce61`**. GitHub commit comparison against the branch: `identical`, ahead=0, behind=0. No RC686/TUR43 or later files at entry. Public main unchanged at **`0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`**. PR #1 remains separate, open/Draft with SHA `710517be3b4a0a671458b6e6cad0261138d0b3b0`; its approval-gated 18 tests were NOT integrated.
- TUR42 **Ubuntu** [run #43266749307](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43266749307), real job `131352233678`: exact entry SHA, run/job completed/success, push attempt 1; all **9/9 steps** successful; independently fetched original **full** log **314000 chars**, **1858 unique `... ok` rows**, **127 RC685 rows**, `Ran 1858 tests in 10.835s` and `OK`, zero failures.
- TUR42 **Windows** [run #43266749263](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43266749263), real job `131352223846`: exact entry SHA, run/job completed/success, push attempt 1; all **9/9 steps** successful; full log **324348 chars**, **1858 unique `... ok` rows**, **127 RC685 rows**, `Ran 1858 tests in 14.778s` and `OK`, zero failures.
- RC685 final source `safe_public_ci/ci_independent_origin_quarantine.py` Git blob SHA-1 **`e63e473f1a8ba7a534a3760d26005fa287f4dd8c`**, raw SHA-256 `fd2d768d3042ec089d3f4cdf6345ab79794b2d9d6ec48f9849192d2bfed74e0c`; tests Git blob `b7b22f5a9406e9de19b70d24a90ac779d5c8d7ba`, raw SHA-256 `2a940bbd405839a66c21bd69169f26303e8e5443943803e5a6645ec57fd880b4`. Exact Git blobs were re-fetched, and corresponding SHA-256 records reviewed from RC685 report.
- TUR42 report `docs/RC685_TUR42_INDEPENDENT_WITNESS_ORIGIN_SQLITE_FORK_AUDIT.md` Git blob `a0de2e0cb47e7b4c9f5624d1b3825b09b5386452` preserved. The **first failed** TUR42 Ubuntu run `43266074902` / job `131349857300` and Windows run `43266074901` / job `131349857045` remain documented, never counted PASS.
- RC656 corrected synthetic snapshot test Git blob `a204b529bb7cd9fa29a9a59c8e0a81c1b96ddf05` continues to require a 33-file all-in-one snapshot to **reject**, then audits bounded disjoint batches. Engine `snapshot_package.MAX_ENTRIES=32` and other import/path limits are not weakened.

## 2. RC686 new actual source behavior, limits and nonclaims

New `safe_public_ci/ci_origin_checkpoint_inclusion_quarantine.py` is pure Python, no file or network I/O, no runtime key or trading client. Imports exactly `hashlib`, `hmac`, `re`; no direct `open`, `compile`, `eval`, `exec`, `__import__` calls. No security workflow changes.

- Independently rebuilds a **RFC6962-style SHA-256 Merkle inclusion root** from *one* supplied leaf, index, tree size (max 128), and **bottom-up audit path**. Validates sibling direction, non-power-of-two split, canonical lower-case digest, exact proof depth, rejects too-few/too-many siblings and malformed scalar bounds. This differs from simply recomputing a root from the claimant's full leaf list.
- Bounded typed/length-prefixed domain-separated transcript pins repository/branch/source SHA/workflow SHA/prior checkpoint SHA; historical root and size, new root, inclusion proof, claimed signer records, claimed provider run/job/source/log, two nominal witness domains and log bindings, syntactic key-revocation chronology, nonce and spent history, epoch/last-seen state, ACK state, and permanent no-release/no-live flags. Rejects duplicates, old-epoch ABA, false `ACK_COMMITTED`, spoofed `VERIFIED`, inconsistent witness size/root/log and key reuse.
- **A legitimate *mathematical* inclusion proof and two internally consistent witness claims do NOT authenticate the Merkle root's external provenance.** Claims and expected SHA pins are caller supplied. A fabricated owner/reviewer/public key name, revoked-after observation claim, GitHub run ID or provider-log checksum is not an independently signed authority/provenance statement.
- Output is only `MERKLE_INCLUSION_EQUATION_VALID_ORIGIN_UNAUTHENTICATED`, with `inclusion_equation_valid=True` but **every** authority, real provider signature, revocation origin, immutable external anchor, consistency history, durable CAS, restart recovery, trusted clock, release and live flag **False**. Self-upgrading `trusted_owner_origin=True`, `trusted_reviewer_origin=True`, `trusted_provider_origin=True`, `trusted_revocations=True`, `trusted_append_only_anchor=True` or `trusted_durable_cas=True` is explicitly **rejected**.
- No genuine out-of-band owner/reviewer Ed25519 trust-root provisioning or signed revocation record was available. The RC683 standalone Ed25519 *equation* checker remains unchanged but cannot establish who generated an arbitrary key. No provider-signed run/job/log or cryptographically authenticated external checkpoint was obtained. Missing evidence is **NO-GO**, not made up.

## 3. 98 new independent adversarial tests with 18 real disposable SQLite experiments

New `tests/test_rc686_inclusion_origin_sqlite.py` has **98** original cases (80 inclusion/witness/revocation/source-claims and **18 real SQLite** test-only CAS/OS process exercises). It is not an application-integrated trading CAS, and SQLite exists ONLY under `tests/`.

- RFC6962 inclusion recomputation across **tree sizes 1–128** and multiple indices per tree, including odd widths and singleton. Negative tests cover corrupted index/size, missing/extra/swapped sibling proof, different leaf/root, mismatched witness log or provider run/source, owner/reviewer key/actor overlap, revoked claimed signers, duplicate/noncanonical revocation, nonce replay, claimed epoch ABA, rollback, missing or extra schema, self-attested authority/LIVE/ACK.
- Test-only `sqlite3` harness uses `PRAGMA synchronous=FULL`, `journal_mode=DELETE`, `BEGIN IMMEDIATE`, conditional generation/root/epoch update, unique nonce receipts and `COMMIT`. A real 3-thread race and three **separate Python subprocesses** accept precisely one COMMIT and reject stale contenders; a process exits with `os._exit(61)` before COMMIT or `os._exit(62)` immediately after COMMIT before ACK. Reopening verifies rollback/persistence and nonce fence in that single database.
- **Counterexamples (security gaps, not security successes):** two disconnected snapshot copies can each independently commit, proving fork possibility; privileged local administrator can restore an old DB and replay an old nonce; an external-looking reference file detects rollback only while it is preserved; the same admin can roll back **both** the database and its locally controlled reference file. Therefore no independently administered immutable monotonic root, cluster-wide linearizability, or production outage durability is demonstrated.
- Local CPython **3.13.5** after final comment: `PYTHONWARNINGS=error PYTHONPATH=/mnt/data/kripto_tur43 python3 -m unittest discover -s /mnt/data/kripto_tur43/tests -p 'test_rc686*.py' -q` => **Ran 98 tests in 2.913s, OK**; no ResourceWarning. `python3 -m compileall -q /mnt/data/kripto_tur43/safe_public_ci /mnt/data/kripto_tur43/tests` => PASS. AST source allowed imports exactly `hashlib,hmac,re`; forbidden calls zero.

| Exact *final* tested code bytes | Git blob SHA-1 | Raw SHA-256 |
|---|---|---|
| `safe_public_ci/ci_origin_checkpoint_inclusion_quarantine.py` | `9fe2b9b8356619e7c161e8415ee9e713012568f7` | `5e04353ed59dd91a038e612868279ef5f2df330e0a5634084c14e7adef40c9ce` |
| `tests/test_rc686_inclusion_origin_sqlite.py` | `24c0094309477008c0abb11f5fa8ddf329c98e50` | `e4df6ced03e8ac7510d3d69e8260b01f61953bc59ef21fb55d92fde20479443b` |

Both GitHub exact-byte readbacks of these files **must match** these final values; any mismatch fail-closed. A pre-comment source blob `76018773a84f5f54c51f479eecdfccb2f6746f88` is an intermediate historical artifact, not the final source identity.

## 4. Final exact-HEAD CI verification gate

Previous successful synthetic regression **1858** + **98** new RC686 cases => **1956 tests expected per OS**. These counts cannot be called hosted PASS until **Ubuntu and Windows on exactly the final commit** show all:

1. real push run attempt 1 `completed/success` + exact HEAD SHA;
2. real job `completed/success` and **9/9 steps completed/success**, including setup/postludes;
3. independently fetched original complete verbose logs with **1956 distinct `... ok`** rows, **98 RC686** rows, `Ran 1956 tests` and `OK`, no unreported fail/error/skip;
4. final two code Git blob hashes and document match local tested sources, no newer commit after the test runs.

Incomplete/queued/no-job/unavailable full log, stale-head pass, or 1955 results => **NOT VERIFIED**. Preserve any failed initial attempts. Once verified, append actual run/job/log evidence to **Draft PR #7 description without further commit** because the report precedes final hosted runs.

## 5. Nonnegotiable no-release gates and TUR44 scope

`FINAL=SEALED`, `LIVE=DISABLED`, `SINGLE_FIT=UNUSED`, `+20% NET=NOT_TESTED`. No production or paper order execution, profit promise, model fit, deployment or automatic merge. Public `main`, Private repository, workflow paths/permissions, ban on dynamic execution and the on-approval 18 tests in PR #1 untouched. Previous publication checklist **5/10=50%** is *not* overall product readiness; native end-user Windows/Ubuntu/server acceptance **0/3**; independent real authenticated signer/clock/immutable checkpoint/provider/CAS acceptance **0**.

**TUR44 priority:** obtain true out-of-band signer/role/key ownership and signed revocation provenance if authorized; verify real provider-issued source/log attestations and cryptographic Merkle checkpoint anchors; move test-only SQLite semantics toward a deliberately isolated, reviewed application adapter without lifting no-trade gates, and demonstrate multi-node crash/recovery/ACK safety only when truly supported. No `AUTHENTICATED`, `LIVE` or `FINAL` by assertion.
