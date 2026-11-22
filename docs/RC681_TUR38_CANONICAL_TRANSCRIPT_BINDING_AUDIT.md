# KriptoAI Autopilot — TUR 38 / RC681 — Canonically Bound Complete Evidence Transcript

**Date:** 2026-11-11. **ONLY Public** `ftmstr/Embasic-KriptoAI-Autopilot-Build`, existing `validation/rc654-pr1-rc653-combined-ci` branch and **Draft PR #7**. Synthetic-only, no live trading, release or model fitting.

## 1. Entry GitHub baseline evidence, exact code identity and immutable scopes

Draft PR #7 original HEAD `c53b768e1d4fef64b6bf36b71b5bd0a0157b14da` matched the Public branch (compare status identical). Public main remains `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471` (unmodified). PR #7 open/Draft/unmerged, base `research/rc653-synthetic-receipt-envelope`; PR #1 open/Draft/unmerged at `710517be3b4a0a671458b6e6cad0261138d0b3b0`. PR #1's **18 tests are not integrated**; submitted independent reviews PR #1 = **0**, PR #7 = **0**.

Both real independent native GitHub Actions run metadata, job, step and original **full** verbose unittest logs were re-fetched for the same exact entry SHA:

| Runner | Real GitHub-hosted run | Real job | Original full log |
|---|---|---|---|
| Ubuntu | [#43063234436](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43063234436) | `130671150730` | completed/success, push attempt 1, **9/9** successful steps, **1395 distinct** `... ok` rows, `Ran 1395 tests` / `OK`, **81** RC680 |
| Windows | [#43063234380](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43063234380) | `130671150976` | same SHA/event/attempt, completed/success, **9/9** steps, **1395 distinct** `... ok` rows, `Ran 1395 tests` / `OK`, **81** RC680 |

**No** modifications to Public main, any Private repo, existing GitHub workflow triggers/permissions, existing import whitelist or `open/compile/eval/exec/__import__` rules. No PR1 code integration, credentials, orders, model fit, signing, production deployment or merge.

## 2. Actual source-driven new finding

Reviewed actual Public RC680 `ci_merkle_consistency_anchor_quarantine.py`, RC679 `ci_merkle_prefix_quarantine.py`, RC678 full-history receipt, RC669–RC677 prior synthetic provenance/replay/CAS layers and `tests/test_guard.py`.

**Material structural integrity gap:** RC680 `statement_sha256` commits to repository/branch, Git/source/workflow/roster, tree sizes/roots, nonce, claimed timestamps, ACK and no-live flags, but **does NOT commit the `issuer_claims`, `provider_claims`, `writer_claims` or revocation records**. Consequently changes to otherwise syntactically valid issuer names, provider run/job metadata and claimed CAS actor identities do not change the RC680 statement hash. RC680 may reject *inconsistent* metadata by other validators, yet a valid substitute actor/provider identity remains unbound to that statement hash. This is a **claim-binding gap**, not proof of actual compromise or live trading.

The RC680 fail-closed fix for compact Merkle 3→7 proof supporting a false 3→8 alleged size is preserved. Do not weaken required full-history size and root recomputation.

## 3. RC681 substantive implementation

New `safe_public_ci/ci_bound_transcript_quarantine.py`, all-in-memory; imports only allowlisted `hashlib`, `hmac`, `re`.

- Strict, versioned, **length-prefixed and typed canonical encoding**, SHA-256 domain separation, bounded exact-schema fields, strict tuple/str/int/bool distinctions, rejecting duplicate actor/key identities and noncanonical histories. The transcript hash commits to **all** metadata: repo/branch, Git/source/workflow/roster, 3->N old/new size and Merkle roots, nonce/timestamps, **complete ordered full history**, compact RFC6962 consistency proof, 3 purported issuer keys/roles/validity times, two OS claimed provider run/job/Git/source/old/new root views, two CAS contender identities/outcomes, revoked keys/times, spent nonces, seen roots, ACK and permanent NO-LIVE/NO-RELEASE flags.
- Recomputes both RFC6962-style old/new Merkle roots from the **exact complete bounded full history (max 128 leaves)**. Regenerates the canonical compact consistency proof and checks equality against the supplied proof; rejects missing/extra/wrong nodes and inconsistent tree size. The adversarial 3→7 compact proof **cannot** be rebadged as 3→8.
- Refuses forged `SIGNED/VERIFIED` issuer/provider, duplicate provider ID, duplicate issuer key/actor, revocation effective by observation time, future/stale claimed signed-at/CI timestamps, noncanonical replay histories, double CAS winners, substituted Git/source/root, invented `ACK_APPLIED`, and `release_ready/live_trading_allowed=True`.
- New `quarantine_bound_transcript` matches caller-supplied expected transcript SHA and other pins, but always returns `FULL_TRANSCRIPT_BOUND_QUARANTINED_NOT_AUTHENTICATED`, and `provider_origin_authenticated=False`, `signatures_verified=False`, `clock_verified=False`, `merkle_anchor_authenticated=False`, `cas_atomicity_verified=False`, `durable_write_verified=False`, `release_ready=False`, `live_trading_allowed=False`. Lost ACK is **always unresolved**.
- **Trust boundary:** This code does NOT actually verify any cryptographic signature, independent issuer/owner/reviewer identity, real trusted clock, origin of GitHub Actions records, immutable ledger, transactional CAS or actual consumed receipt. An adversary controlling both the evidence and expected pins can produce a perfectly matching SHA-256 transcript. Multiple stateless calls can accept the same claimed one-winner event. Therefore do not claim AUTHENTICATED, CAS, LIVE, FINAL or net return.

New `tests/test_rc681_bound_transcript.py`: **102 original all-invented unittest cases**. In addition to 86 dynamically named adversarial cases and 16 independent tests, assertions explicitly check that otherwise-valid changes to issuer identity, claimed signing time, provider run ID, CAS writer identity, and future revocation history **change** the canonical transcript digest. Boundaries exercise 1..128 tree leaves and a repeat of 3→7 vs 3→8, wrong paths, malformed type tags, replay, key revocation, false signed status, source SHA rebind, ABA/root substitutions, duplicate providers, lost ACK and parallel stateless invocations.

## 4. Local Python 3.13.5, byte identity

- `python3 --version`: **Python 3.13.5**.
- `PYTHONPATH=/mnt/data/rc681 python3 -m unittest discover -s /mnt/data/rc681/tests -p 'test_rc681*.py' -v`: **102/102 PASS**.
- `python3 -m compileall -q /mnt/data/rc681/safe_public_ci /mnt/data/rc681/tests`: **PASS**.
- Source Python AST imports exactly `hashlib`, `hmac`, `re` and direct prohibited calls `open/compile/eval/exec/__import__` **zero**.

| Artifact | Locally tested SHA-1 from `git hash-object` | Local SHA-256 |
|---|---|---|
| `safe_public_ci/ci_bound_transcript_quarantine.py` | `88503575e7691b9184fe8f9f7e460ecb13b55ed3` | `e9f6f78d63662f2fa74004b41bafb12c6e0f62f587685c3ff29e40e64a3d3c1d` |
| `tests/test_rc681_bound_transcript.py` | `ebd0242c2b18af79090db7584fe8ccc2735fc501` | `ad226bf03d3c28df323601cbfe8ad2503768803aa62df27f7a5a2c7b5cf92b31` |

Both artifacts MUST be uploaded **only to existing Public validation** and independently read back at exact final HEAD; incorrect byte identity requires fail-closed STOP.

## 5. Native final-SHA acceptance and immutable NO-GO

Baseline RC680 **1395** + new RC681 **102** = **1497 expected successful unit tests per OS**. Do **not** claim final-hosted PASS until actual same-final-SHA native Ubuntu and Windows run/job/step/full verbose logs independently show completed/success, **9/9** successful steps, 1497 distinct successful rows, `Ran 1497 tests`, `OK` and 102 new RC681 cases. Add actual final run/job IDs to Draft PR #7 **after** final HEAD is fixed without another code commit.

No signed external owner/reviewer key, independent authenticated trust root distribution, true cryptographic provider attestations, trustworthy revocation source/time, real durable atomic CAS, resolved lost ACK or live trading. PR1 18 tests remain unmerged/unapproved. Native end-user Windows/Ubuntu/server acceptance **0/3**, owner publication gate checklist **5/10 = 50%** (not general readiness, not financial performance). Immutable **FINAL=SEALED, LIVE=DISABLED, SINGLE_FIT=UNUSED, +20% NET=NOT_TESTED**.

## 6. Provenance preservation and TUR39 handoff

Retain the historic 63,747-character PR7 original description at `docs/RC679_TUR36_PR7_BODY_ARCHIVE_PRECOMPACTION.md`, and all earlier technical reports including RC680. Keep concise current Draft PR #7 links and facts, do not overwrite historical success and test-failure records. TUR39 should first recheck final exact-SHA 1497-test dual hosted CI, then investigate **independently cryptographically verifiable read-only signed checkpoint provenance** and separate external transactional CAS; do not mistakenly treat the new full-transcript SHA-256 as a signature.
