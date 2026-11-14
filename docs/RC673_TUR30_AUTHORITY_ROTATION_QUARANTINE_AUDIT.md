# KriptoAI Autopilot — TUR 30 / RC673 — Authority Rotation Quarantine
Date: 2026-11-10 • Public synthetic-only validation • No live operations.

## 1. Canonical Public scope and unmodified safety policy

- Repository: **Public** `ftmstr/Embasic-KriptoAI-Autopilot-Build`. Existing active validation branch `validation/rc654-pr1-rc653-combined-ci`, existing **Draft PR #7** (open/unmerged, base `research/rc653-synthetic-receipt-envelope`). Required entry SHA `b3ceb3ea4e1820c977927787396623d2c2e6f7d4` was reverified from actual PR/branch compare.
- Public `main` starting SHA `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`; never modified. No Private repository access, merge, public release, external API calls, secrets, market orders or model training.
- PR #1 Draft/unmerged at `710517be3b4a0a671458b6e6cad0261138d0b3b0`, 18 independent original tests **not integrated**; PR #1 and PR #7 have **zero** independent submitted reviews.
- `FINAL=SEALED`, `LIVE=DISABLED`, `SINGLE_FIT=UNUSED`, `+20% NET=NOT_TESTED`. Preserve existing `tests/test_guard.py` source import whitelist, `compile/eval/exec/open/__import__` bans and unchanged workflow path filters/permissions.

## 2. Baseline native hosted GitHub Actions verification — real job/steps/log evidence

Both actual run APIs, job metadata, **nine** step outcomes and complete verbose logs were checked independently for entry SHA `b3ceb3ea4e1820c977927787396623d2c2e6f7d4`, `event=push`, `run_attempt=1`:

| Native OS | Real run | Job | Step verdict | Unittest verbatim summary |
|---|---|---|---|---|
| Ubuntu | [42833923241](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42833923241) | `129890930286` | `completed/success`, 9/9 | **839** `... ok` rows; `Ran 839 tests`, `OK`, incl. 50 RC672 |
| Windows | [42833923153](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42833923153) | `129890928969` | `completed/success`, 9/9 | **839** `... ok` rows; `Ran 839 tests`, `OK`, incl. 50 RC672 |

These are real GitHub-hosted **synthetic** code tests; they establish no real trading, external key provenance or installable end-user package.

## 3. Specific RC672 / RC671 / RC670 / RC669 findings

Inspected actual `safe_public_ci/ci_context_chain_gate.py` (RC672), `ci_cas_interleaving_trace.py` (RC671), `ci_cas_readback_guard.py` (RC670), `ci_receipt_replay_fence.py` (RC669), plus source-byte, hosted log and CI pair gates. RC672 rightly **rejects unapproved trust-root rotation**. Those modules only check submitted receipt/trace/pin consistency; they do not authenticate GitHub provider origin or signed authority. A malicious submitter supplying both all data and all expected hashes can fabricate a coherent transcript. A transactionally durable signed external root/ledger, genuinely independent review, atomic CAS, trusted lost-ACK recovery and rollback safety cannot be obtained by rehashing self-supplied metadata.

The task is therefore **not to bypass RC672's hard reject**, but to add a distinct **quarantined rotation proposal** that cannot authorize any actual root change.

## 4. New original public development

New `safe_public_ci/ci_rotation_quarantine_gate.py` (synthetic-only stdlib, solely `hashlib`, `hmac`, `re`):

- Strict Public repository/validation-branch identity and exact canonical tuple/dict types, bounded/unique log and job IDs, SHA-1 commit claim, SHA-256 source/workflow/roster/old/new authority roots, prior context SHA-256, CAS generation/root, nonce and OS run/log claims.
- Versioned domain-separated **rotation intent SHA-256 commitment** binds old/new authority IDs and epochs, old/new roots, previous context, Git/source/workflow/roster, consecutive CAS generations, ordered OS run/job/log claims, nonce, limited ACK state and permanent `release_ready=False` / `live_trading_allowed=False` flags.
- Externally supplied (still **NOT authenticated**) independent pins are checked for old authority, source/workflow/roster, prior context, commit, monotonic run/job IDs, previous log receipts, spent nonces and recent historical roots. Silent epoch skips, same-root reissue, ABA root reuse, duplicate OS logs and replay are rejected.
- Three distinct *claimed actors* in ordered roles `owner`, `independent_reviewer`, `incumbent_custodian`, each attached to the same intent digest. **An actor string and matching hash are NOT a verified signature, external approval, identity authentication, or reviewer action.** The protocol *requires* external independent authenticated owner and reviewer control before any future real authority rotation.
- Rejects purported `ACK_APPLIED`; only `NOT_SUBMITTED` or `ACK_LOST_UNRESOLVED` are acceptable as **quarantined claims**. Lost ACK never silently becomes commit proof.
- Returns only `ROTATION_QUARANTINED_NOT_AUTHENTICATED`, `external_authorization_verified=False`, `release_ready=False`, `live_trading_allowed=False`. Never changes RC672 policy, external state, live trading or release flags.

New `tests/test_rc673_rotation_quarantine.py`: **60** fully invented synthetic adversarial cases: mismatched Git/source/workflow/roster, old or new authority issuer, epoch skip/rollback, reused root/nonce/log, parallel host receipt confusion, duplicate and inconsistent claimed reviewers, malformed types, fake successful ACK, replay, abnormal CAS generation and a deliberate attacker-controls-pins case that still cannot enable release.

## 5. Local CPython 3.13.5 test/guard execution and exact-byte manifests

Actual `python3 --version`: **3.13.5**. Local command `PYTHONPATH=/mnt/data/rc673 python3 -m unittest discover -s /mnt/data/rc673/tests -p 'test_rc673*.py' -q`: **60/60 PASS**; `python3 -m compileall -q /mnt/data/rc673/safe_public_ci /mnt/data/rc673/tests`: PASS. Independently parsed safe-module Python AST locally: imports **`hashlib`, `hmac`, `re` ONLY**; no forbidden `eval`, `exec`, `compile`, `open`, `__import__` calls.

Exact locally computed `git hash-object` and SHA-256:

| File | Git blob SHA-1 | SHA-256 |
|---|---|---|
| `safe_public_ci/ci_rotation_quarantine_gate.py` | `a84366a8ebee107bb8b35a86cd8a566f0da86042` | `6b2799e2d9391bfc993ac5ad0eb9b3f64dea169feeabf2b38bf911c45e21a210` |
| `tests/test_rc673_rotation_quarantine.py` | `dbd31f0e4fbd88ee007c73379ecd1950415124d5` | `5b2044df4d9790a14c3c141dfd471b140ec4c41ec6a58dfc332d319d821eecb3` |

Public GitHub contents readback for tests already matched its source blob. **The module must be uploaded and its GitHub blob independently compared to this exact local value**, not inferred from the test name. Source added last, after the report, to trigger unchanged native Public `push` CI at exact **final HEAD**.

## 6. Native same-SHA acceptance and remaining hard NO-GO

- Expected full native suite count = **839 inherited + 60 new = 899 per platform**. This is an **expectation, not PASS** until real GitHub Actions Ubuntu and Windows `push` run, job, 9 steps and full unittest logs confirm `Ran 899 tests` / `OK` on the exact final HEAD.
- Final full-log run/job IDs belong in Draft PR #7 body after verification; **do not move HEAD merely to update CI evidence**.
- No independent verified crypto signatures, trusted signing keys, authenticated issuer identity, durable CAS/append-only ledger, authenticated external readback, release signer, license/SBOM/security acceptance, Windows/Ubuntu/server installable end-user packages or PR #1 independent reviewer approval.
- Publication acceptance checklist remains **5/10 = 50%**, not overall product completion, strategy performance or any financial gain. Native signed package acceptance remains **0/3**. `+20% NET=NOT_TESTED`.

## 7. TUR 31 guidance

First verify RC673 exact final HEAD and authentic provider run/job/step/full-log for both native OS. Then revisit the *attacker-controls-both-evidence-and-pins* root trust problem and externally verifiable signed approval/atomic CAS design. Do not claim synthetic approvals are real or elevate NO-GO; no changes to Private, main, merge, live trading, actual model fit or +20% profit claims.
