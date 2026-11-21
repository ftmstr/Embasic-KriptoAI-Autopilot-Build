# KriptoAI Autopilot — TUR 36 / RC679 — Merkle Prefix and Inclusion Audit

**Date:** 2026-11-10. **Public synthetic validation ONLY — NO AUTHENTICATION, NO CAS, NO LIVE trading, NO training, NO release.**

## 1. Canonical scope and immutable policy

- Sole repository: **Public** `ftmstr/Embasic-KriptoAI-Autopilot-Build`; existing `validation/rc654-pr1-rc653-combined-ci` validation branch, existing Draft PR #7 (open/unmerged), base `research/rc653-synthetic-receipt-envelope`.
- Required entry RC678 SHA `c5960e74f6538aff601084256c1c82ea664ad072` exactly matched PR head and Public validation branch at entry. No newer turn was present. Public main SHA `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`; **not modified**.
- PR #1 at `710517be3b4a0a671458b6e6cad0261138d0b3b0` remains separately Draft/unmerged. Its 18 tests NOT integrated. Submitted independent PR #1 and PR #7 review counts = **0**.
- Existing `tests/test_guard.py` import whitelist, `compile/eval/exec/open/__import__` bans, and existing GitHub workflow path filters/permissions MUST remain unchanged. No Private repo access, branch merge, actual market orders, ML fit, cloud deploy, signing or live release.
- Immutable: **FINAL=SEALED**, **LIVE=DISABLED**, **SINGLE_FIT=UNUSED**, **+20% NET=NOT_TESTED**.

## 2. Independently verified native GitHub Actions entry evidence

At **exact identical** RC678 SHA `c5960e74f6538aff601084256c1c82ea664ad072`, both real GitHub `push` runs were `completed/success`, `run_attempt=1`. For each, separately fetched provider run metadata, job payload, all nine step statuses, and full original raw verbose unittest job logs.

| Native OS | Run | Job | Independently checked original log |
|---|---|---|---|
| Ubuntu | [#42871928420](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42871928420) | `130025093404` | 9/9 successful steps; 1239/1239 **distinct** `... ok` lines; `Ran 1239 tests`, `OK`; 71 RC678 |
| Windows | [#42871928457](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42871928457) | `130025092596` | 9/9 successful steps; 1239/1239 distinct `... ok` lines; `Ran 1239 tests`, `OK`; 71 RC678 |

These provide **hosted synthetic test evidence**, not a provider-signed supply-chain receipt, release approval or trading-performance certification.

## 3. Source review: RC669–RC678 and demonstrated trust gap

Read the actual Public `safe_public_ci/` modules for RC669 replay, RC670 CAS readback, RC671 interleaving, RC672 context chain, RC673 root rotation, RC674 witness equivocation, RC675 revocation ledger, RC676 forked checkpoint, RC677 temporal origin and RC678 full-history receipts, together with `tests/test_guard.py`.

RC678's `history_root_sha256` hashes a *complete ordered tuple*; it is **not a Merkle inclusion proof**. Moreover all prior roots, claimed provider readbacks, witness fingerprints, key revocation timestamps, clock times and expected hashes are **supplied by the caller**, not independently signed or transparently anchored. Such matching claims are only internally consistent. Two parallel offline calls can both accept the same receipt; there is NO real durable single-winner CAS or authenticated lost-ACK recovery.

## 4. RC679 substantive addition (new paths, fully synthetic)

**`safe_public_ci/ci_merkle_prefix_quarantine.py`**

- Implements a bounded (maximum **128 leaves**) RFC6962-style domain-separated binary Merkle tree: empty SHA-256 root, leaf `SHA256(0x00 || 32-byte synthetic leaf)`, internal node `SHA256(0x01 || left32 || right32)`, with split at the largest power of two strictly less than subtree size. Distinguishes this structure from RC678's flat full-history hash.
- Generates and independently verifies a Merkle **inclusion audit path** for any index; rejects noncanonical index, false leaf, invalid tree size, truncated/extra/bad sibling hashes, and roots that do not match recomputed claimed full history.
- Enforces one unique receipt appended to an exact previous-history prefix; checks caller-pinned old and new Merkle root, commit/source/workflow/roster/authority SHA and nonce. The claimed receipt digest binds Public repository and branch and **no-live/no-release** invariants.
- Checks consecutive claimed generations, **two distinct writer decisions** (one `CLAIMED_WIN`, one `CLAIMED_CONFLICT`), ordered Ubuntu/Windows readbacks with distinct run/job IDs, identical claimed Git/source/new root, three distinct *claimed* owner/reviewer/custodian keys and claimed signed-at/validity windows, plus claimed key-revocation times, nonce/root replay, fake provider `SIGNED`, `ACK_APPLIED` and false production flags.
- Returns exclusively `MERKLE_PREFIX_CLAIM_QUARANTINED_NOT_AUTHENTICATED`, `trust_anchor_authenticated=False`, `signatures_verified=False`, `clock_verified=False`, `provider_origin_verified=False`, `atomic_cas_verified=False`, `durable_write_verified=False`, `release_ready=False`, `live_trading_allowed=False`; lost ACK remains unresolved.
- **NO independent source of root authority or actual transaction**. Hashes, audit paths, claimed signatures and OS receipts are caller-supplied; an attacker controlling both inputs and pins can fabricate a self-consistent audit. A Merkle inclusion proof validates the internal relationship, **not signed origin, log non-equivocation or append-only durability**. Two pure calls can both pass; not an atomic CAS.

**`tests/test_rc679_merkle_prefix_quarantine.py`**

- **75 original invented-data unittest cases**, including explicit checks for Merkle sizes 1 through 128 (positions first, middle and last), empty/singleton domain-separated roots, truncated/extra/incorrect siblings, wrong tree size/negative index/bool index, claimed prefix overwrite, duplicate leaf, fake old/new root, false Git/source/workflow/roster/authority pins, spent nonce/root, falsely signed or revoked reviewer, cloned actor/key, conflicting platform observations, stale provider time, double CAS winner, invalid ACK and no-live bypass attempts.
- Explicit negative test shows that maliciously changing both claimed source and matching pins **still returns NOT_AUTHENTICATED**. Separate test confirms repeated invocations do **not** consume the receipt. One initial local test incorrectly expected a different response for malformed inclusion size; it was **corrected** and the 75-test suite rerun to PASS before either file was uploaded.

## 5. Actual local Python 3.13.5, import gates and exact file identity

- `python3 --version`: **3.13.5**.
- `PYTHONPATH=/mnt/data/kripto_rc679 python3 -m unittest discover -s /mnt/data/kripto_rc679/tests -p 'test_rc679*.py' -q`: **75/75 PASS**, run again **after the final source comment change**.
- `python3 -m compileall -q /mnt/data/kripto_rc679/safe_public_ci /mnt/data/kripto_rc679/tests`: **PASS**.
- AST import audit: `hashlib`, `hmac`, `re` **ONLY**; prohibited direct `compile/eval/exec/open/__import__` calls **0**.

| File (final locally tested bytes) | Local `git hash-object` SHA-1 | Local SHA-256 |
|---|---|---|
| `safe_public_ci/ci_merkle_prefix_quarantine.py` | `498de38acb71c2c9d7c6604b305ae06cc15159b7` | `7b7c39bbd0665e896ee1720b4c6d80d8c3a73b5cefe403cf14de71c6e9a3277e` |
| `tests/test_rc679_merkle_prefix_quarantine.py` | `d1793c305acea87ff9c50fce1fd7e6a46588084a` | `526f62c9963c161fdcaa5673ef2f121695794cb296f9bfde02f5994401e6a9d4` |

The initial source GitHub blob `eb9f217ebf04365f90ecc07ef665ab8ca1b46495` and test GitHub blob `d1793c305acea87ff9c50fce1fd7e6a46588084a` each matched their locally tested prior bytes **2/2**. The final documented source comment changes the source blob to `498de38acb71c2c9d7c6604b305ae06cc15159b7`; **GitHub readback of that final source blob is REQUIRED after the report/archive commits**, not inferred. No summary should substitute an earlier GitHub blob for final bytes.

## 6. Draft PR #7 history preservation

PR #7 body had grown to **63,747 characters** through 35 staged turns. Before compacting the PR body, preserve its **complete existing text** as `docs/RC679_TUR36_PR7_BODY_ARCHIVE_PRECOMPACTION.md` on this same Public validation branch. Its exact byte identity must be checked by GitHub readback. Then replace the PR description with a readable concise current summary plus links to this immutable historical snapshot, the present full technical report, original prior TUR reports and final native-run evidence. No evidence or historic result may be silently discarded.

## 7. Final same-SHA hosted acceptance and remaining NO-GO

Expected suite: RC678 **1239** plus RC679 **75** = **1314 tests on EACH native OS**. This is an **expectation**, NOT a verified pass, until the final exact SHA GitHub-hosted Ubuntu and Windows `push` run, job, all nine successful steps, original verbose full log `Ran 1314 tests`, `OK`, 1314 distinct cases and 75 RC679 cases are independently checked. Place final actual run/job IDs in Draft PR #7 description **after** the final code HEAD is stable, without any further code commits.

**Hard NO-GO:** No independently authenticated GitHub provider-origin/signed attestations, verified signer identities or owner+independent reviewer approval, trusted revocation feed or clock, independently anchored Merkle root, real durable transactional CAS/ledger, native Windows/Ubuntu/server installation packages (0/3 accepted), signing/SBOM/license/security acceptance, or real financial model/strategy verification. PR1's 18 tests remain separate and unapproved. Owner publication checklist remains **5/10 = 50%**, **not** global project completion or financial profitability. **+20% NET=NOT_TESTED**.

## 8. TUR 37 handoff

First verify exact final RC679 SHA and the real dual-OS run/job/step/raw-log evidence. Then consider a deliberately separate **read-only externally signed anchor verification service** and externally controlled trust-root distribution, with transactionally durable CAS and signer-key revocation as independent projects. Do not infer provider authenticity, append-only non-equivocation, or single-use receipts merely from matching caller-provided Merkle roots.
