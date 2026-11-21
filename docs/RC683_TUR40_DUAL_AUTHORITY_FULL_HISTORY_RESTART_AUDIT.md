# KriptoAI Autopilot — TUR40 / RC683: Two Independent Ed25519 Equations, Full-History + Restart Quarantine

**Date:** 2026-11-12. **Scope:** ONLY Public \`ftmstr/Embasic-KriptoAI-Autopilot-Build\`, existing \`validation/rc654-pr1-rc653-combined-ci\`, open/unmerged Draft PR #7. All code and examples are invented offline synthetic fixtures. No real issuer authorization, crypto asset data, model fitting, orders, credentials, server deployment or trading.

## 1. Entry state verified from GitHub, not inferred

- Entry HEAD: \`489de090cedf5d9e3a7d50cf218bd336dcc21843\`; PR #7 \`open\`, \`draft=true\`, \`merged=false\`; no TUR40/RC683 files at entry.
- Main remains \`0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471\`. No main/Private repo writes. PR #1 remains open Draft at \`710517be3b4a0a671458b6e6cad0261138d0b3b0\`; its unapproved 18 tests NOT integrated.
- RC682 source blob \`d0227c6a4e08cfafd8b844a10ed0532ea6322a2c\`, tests blob \`81feb34a5f967b84bc90a1a31d2ffddb057bea04\`, TUR39 report blob \`ae85e952be060cfa2c75e1e26fdc319533c0d6a7\` independently read back.
- Native **entry exact-HEAD Ubuntu** [run 43100289417](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43100289417), real job \`130789419335\`, \`completed/success\`, **9/9 completed/success steps**, original full log 268024 chars, **1554 unique \`... ok\` rows**, \`Ran 1554 tests in 5.916s\` / \`OK\`, **57 RC682** test rows, no failures.
- Native **entry exact-HEAD Windows** [run 43100289517](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43100289517), real job \`130789396950\`, \`completed/success\`, **9/9 completed/success steps**, original full log 278003 chars, **1554 unique \`... ok\` rows**, \`Ran 1554 tests in 7.961s\` / \`OK\`, **57 RC682** test rows, no failures.
- Original older RC681 run IDs 43095501705 and 43095501766 were queued/no-job at previous TUR; neither constitutes a separately verified 1497 PASS. The later RC682 full 1554-hosted success is properly tied to the exact entry SHA.

## 2. Substantive RC683 source and threat boundary

New \`safe_public_ci/ci_dual_authority_quarantine.py\` preserves the original source import whitelist (only \`hashlib\`, \`hmac\`, \`re\`), static no-dynamic execution policy, no file/network/exchange/trading side effects and no private keys.

- Strict bounded RFC8032 Ed25519 *mathematical equation verification* of **two** different synthetic owner/reviewer public keys over the **same exact canonical, domain-separated, typed and length-prefixed checkpoint bytes**. Rejects noncanonical R/A, S >= subgroup order, small-order/torsion points and malformed signatures; unlike a signature-status claim, the equation is actually recomputed.
- Dual record source binding: repo/validation branch, Git SHA, code SHA256, workflow SHA256, roster SHA256, full RC681 transcript digest, nonce and alleged times, complete history, Merkle consistency proof and old/new sizes, two role/key/time claims, claimed revocation events, Ubuntu/Windows provider run/job/source/full-log SHA256 identifiers, two writer races separated by alleged restart epochs, seen roots/nonces, lost ACK and hard no-live/release.
- Required full history of exactly \`new_size <= 128\` synthetic leaves; independently rederive old/new SHA256 Merkle roots and canonical consistency path from exact leaf bytes. Invalid compact 3→7 proof / claimed 3→8, missing/extra nodes, reordered/duplicate leaves, altered root or false size rejected.
- Distinct owner and reviewer actor IDs and public keys; changed roles/identities/signing times are bound by the signature; duplicate keys rejected. Claimed expired/revoked keys at observation time rejected. **Revocation ledger is asserted by the caller, not an authenticated revocation service.**
- Claimed Ubuntu/Windows run/job/log digest and source must agree with the canonical message, but are **NOT** independently fetched or authenticated by this synthetic checker; real GitHub source proves no ownership of the claimed provider records.
- Bounded CAS epoch 1 claimed winner, epoch 2 claimed conflict; double winner, identical actors, claimed rollback, stale generation/ABA, changed root and false \`ACK_COMMITTED\` rejected. The synthetic trace is **not a persistent atomic CAS transaction**; replay histories are supplied by caller and cannot establish durable replay prevention. \`ACK_LOST_UNRESOLVED\` never becomes ACK applied.
- Even when both Ed25519 equations pass, result is exactly \`DUAL_ED25519_EQUATIONS_VALID_ORIGIN_UNAUTHENTICATED\`; explicitly false: authority origin, trust-anchor distribution, revocation origin, provider origin, Merkle history authenticity, durable CAS, restart recovery, trusted clock, release and trading. Self-asserted \`out_of_band_trust_verified=True\`, provider attestation or durable CAS trust pins are rejected instead of elevated.
- The crypto code is a **research-only, pure-Python mathematical verifier**, not an audited production implementation. Both synthetic private signing seeds appear exclusively in the tests, never in \`safe_public_ci\`. Two signatures by attacker-controlled keys are still *unauthenticated*.

## 3. New original adversarial tests and local runtime results

New \`tests/test_rc683_dual_authority.py\`: **83 original deterministic invented-only unittest cases** (16 direct plus 67 generated adversaries). Tests cover independent Ed25519 role/key binding, RFC8032 published vector, invalid scalars/torsion, signature mutation, full Merkle 1..128 boundaries, 3→7/3→8, forged provider run/job/log, unique actors, rotation/expiry/revocation, replay of root/nonce, full-transcript rebind, ABA, rollback, double CAS winner, restart epoch 1→2, lost ACK, failed trust-root self-attestation, false LIVE/release and duplicate history.

Exact local **CPython 3.13.5** after final source comments:
\`\`\`sh
PYTHONPATH=/mnt/data/kripto_tur40 python3 -m unittest discover -s /mnt/data/kripto_tur40/tests -p 'test_rc683*.py' -q
# Ran 83 tests in 1.160s — OK (83/83).
python3 -m compileall -q /mnt/data/kripto_tur40/safe_public_ci /mnt/data/kripto_tur40/tests
# PASS.
\`\`\`
- Static Python AST audit: source imports exactly \`hashlib\`, \`hmac\`, \`re\`; direct prohibited \`open/compile/eval/exec/__import__\` calls: 0.
- Independent \`cryptography\` library Ed25519 interoperability *only in the local test environment*: 24 distinct invented test seeds, 24 valid signatures accepted and 24 altered-message signatures rejected: **48/48 as designed**. The independent library is not used/imported by Public runtime module and conveys no human identity validation.
- The pre-existing 1554 case full regression suite was **not rerun locally** (complete repo not available in local staging); 83 local tests MUST NOT be mislabeled full regression.

| Final source artifact | Locally tested Git SHA-1 blob | Locally tested raw SHA-256 |
|---|---|---|
| \`safe_public_ci/ci_dual_authority_quarantine.py\` | \`1bfd211e01366e423d770c3545ce3e36e17dbdfe\` | \`ac69ee35e4bc71db2ea9ce27f29e4a40c9d0bd0a1f59c2e24f28eac754ff1950\` |
| \`tests/test_rc683_dual_authority.py\` | \`e9a0842a59293e7cd092398c36267e2843dcfe90\` | \`c11bc2db751f44f7a4be3eab3d505ae19c21b0ecb95d5f1f02bfd839057087f6\` |

GitHub readback must independently match **both final blobs** at final HEAD. Initial pre-final source \`6fb3ba7dff55d7443ce1574287d4da02c8a2a298\` and test \`e9a0842a59293e7cd092398c36267e2843dcfe90\` were successfully written/read back as locally tested bytes before the final source-only safety comment. A mismatch => fail-closed.

## 4. Final exact HEAD GitHub Actions — acceptance instructions, not preemptive PASS

Expected hosted test count = entry RC682 **1554 + new 83 = 1637 synthetic unittest cases PER OS**, not yet a claim of hosted success when report authored.

On **final code SHA only**, independently require two real hosted \`push\` workflows, completed/success run, real completed/success job, all 9 named setup/test/postlude steps completed/success, **full original log** with 1637 distinct test rows containing \`... ok\`, \`Ran 1637 tests\`, \`OK\`, and 83 distinct RC683 cases, with no failures/unchecked skips. \`queued\`, \`in_progress\`, \`no-job\`, \`skipped\`, or no full log are NOT PASS. Record actual run/job evidence as an *append-only Draft PR #7 description addendum after final code HEAD*, without additional commits. Preserve older PR evidence.

## 5. NO-GO scope and TUR41 handoff

A valid Ed25519 signature equation + caller-supplied key fingerprints and source pins **does not** authenticate real owners or independently distribute trust anchors. A locally consistent Merkle full-history is not an externally anchored append-only ledger. Two simulated CAS events are not durable atomic storage, and lost ACK remains unresolved. Provider metadata/log hash references are not independent provider origin attestations; synthetic reports do not establish independent trusted clocks or real signed provider receipts.

Permanent locks **FINAL=SEALED, LIVE=DISABLED, SINGLE_FIT=UNUSED, +20% NET=NOT_TESTED**. Owner publication checklist 5/10 = 50% (not readiness), native end-user Windows/Ubuntu/server acceptance 0/3, actual net profit NOT TESTED. No auto-merge, main changes, Private repo, workflow filter/permission changes, PR #1 test adoption, real trade or deployment.

**TUR41 priority:** independent out-of-band real signer/trust-root provisioning with signed revocation provenance; verified provider origin and full log artifacts; disposable actual durable atomic CAS under process crash/restart and lost ACK. No AUTHENTICATED/LIVE/FINAL until external evidence establishes each separate prerequisite.
