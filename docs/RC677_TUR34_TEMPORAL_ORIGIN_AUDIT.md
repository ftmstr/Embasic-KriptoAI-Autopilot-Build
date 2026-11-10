# KriptoAI Autopilot — TUR 34 / RC677 — Temporal Origin, Key Validity and Split-View Quarantine

Date: 2026-11-10 • Public synthetic-only security work • NO LIVE / NO AUTH.

## Authorized scope and immutable gates

Sole canonical repository: Public `ftmstr/Embasic-KriptoAI-Autopilot-Build`, existing `validation/rc654-pr1-rc653-combined-ci` branch, Draft PR #7 open/unmerged, base `research/rc653-synthetic-receipt-envelope`. Required RC676 entry SHA `7d46e2c97e08489c70a4c4e4a5bfe32baca124e9` and PR head/branch exact identity independently checked. Public `main` at `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471` not modified. PR #1 remains Draft/unmerged at `710517be3b4a0a671458b6e6cad0261138d0b3b0`, its 18 original tests NOT integrated and both PR1/PR7 independently submitted reviews = 0. No Private access, workflow path filters/permissions or existing `tests/test_guard.py` whitelist changes. No trading orders, model training, live production, merging or profit claims.

**Immutable release science locks:** `FINAL=SEALED`; `LIVE=DISABLED`; `SINGLE_FIT=UNUSED`; `+20% NET=NOT_TESTED`.

## Entry exact-SHA dual GitHub-hosted evidence: run / job / steps / full logs

| Real native runner | GitHub Actions run | Job | Verified exact RC676 result |
|---|---|---|---|
| Ubuntu | [#42862598378](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42862598378) | `129992390522` | completed/success, push attempt 1; **9/9** individual successful steps; **1094 distinct** `... ok` cases, `Ran 1094 tests` + `OK`; 70 RC676 |
| Windows | [#42862598372](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42862598372) | `129992391182` | same SHA/event/attempt, completed/success; **9/9** steps; **1094 distinct** `... ok` cases, `Ran 1094 tests` + `OK`; 70 RC676 |

The above verifies genuine GitHub-hosted **synthetic unit testing**, not independently signed supply-chain provenance or live market performance.

## Source-driven security finding

Reviewed RC676 `ci_claimed_checkpoint_fork_quarantine.py`, RC675 `ci_revocation_ledger_quarantine.py`, RC674 `ci_witness_equivocation_quarantine.py`, RC673 `ci_rotation_quarantine_gate.py`, RC672 `ci_context_chain_gate.py`, RC671 `ci_cas_interleaving_trace.py`, RC670 `ci_cas_readback_guard.py`, RC669 `ci_receipt_replay_fence.py`, and unchanged `tests/test_guard.py`.

The existing guards correctly treat all matched roots, source SHA values, log records, supposed approvals and CAS states as **NOT_AUTHENTICATED**. None has access to an external owner-controlled verified clock, trusted key/issuer revocation feed or transactional CAS. In particular, key validity windows and provider readback timestamps can be made mutually consistent by an adversary that supplies both the purported facts and the expected pins. Two independent stateless checks can both return the same consistent synthetic receipt. Lost ACK cannot be resolved from a fabricated readback.

## TUR34 original RC677 development

New `safe_public_ci/ci_temporal_origin_quarantine.py` (no external IO; only **hashlib, hmac, re** allowed imports):
- Versioned domain-separated SHA-256 binds Public repo/branch, commit/source/workflow/test-roster identities, owner-authority epoch/root, CAS old/new generation/root, distinct log hashes, a nonce, issue/observation times, two same-base writer outcomes, **three** distinct claimed reviewer credentials and their validity windows, and both ordered OS provider run/job/source/root readbacks. All metadata are explicitly **caller claims**.
- Rejects generation ABA/rollback/jump, double claimed winners, wrong role or cloned claimed reviewer key, expired/not-yet-valid claimed signer timestamp, future or stale claimed provider observation, wrong Git/log/root/roster, duplicate platform job/run, false `VERIFIED`/signed status and fake `ACK_APPLIED`.
- Requires externally supplied **but not authenticated** matching digest/authority/source pins, sorted/unique bounded histories, and synthetic key revocation effective times. A key shown revoked by the claimed observation time is rejected. A key listed for future revocation remains **unauthenticated**, not authorized. Previously spent nonce, either seen log and previously seen root are rejected.
- Accepts `ACK_LOST_UNRESOLVED` only as an unresolved claim. **All** consistent outcomes retain `TEMPORAL_PROVIDER_CLAIMS_QUARANTINED_NOT_AUTHENTICATED`, `authenticated_signatures=False`, `authenticated_clock=False`, `provider_origin_verified=False`, `atomic_cas_verified=False`, `durable_receipts_consumed=False`, `release_ready=False`, `live_trading_allowed=False`.
- A forged pair of mutually consistent claimed provider receipts and provided pins is STILL not real GitHub provider signature or independent provenance. There is no signing verification, verified revocation oracle, trusted timestamp, persistent ledger, atomic CAS or real order gateway in this module.

New `tests/test_rc677_temporal_origin_quarantine.py`: **74** distinct locally executed synthetic unittest methods, including: chronology binding, future/past key revocation, expired/not-yet-valid credentials, three independent claimed reviewer keys, noncanonical booleans, cross-OS log/readback rebinding, duplicate platform identity, two competing writers, ABA, replayed nonce, altered workflow/source/roster and forged authenticated state. Explicit tests show both parallel pure calls can return identical quarantined results and attacker-controlled source pins cannot cause authentication. No test or code copied from PR1.

## Local Python 3.13.5 and exact byte identity

Local `python3 --version`: **3.13.5**. `PYTHONPATH=/mnt/data/rc677 python3 -m unittest discover -s /mnt/data/rc677/tests -p 'test_rc677*.py' -q`: **74/74 PASS**. `python3 -m compileall -q /mnt/data/rc677/safe_public_ci /mnt/data/rc677/tests`: PASS. Module AST import check: only `hashlib`, `hmac`, `re`; no forbidden direct `compile/eval/exec/open/__import__` call. Existing Public import/exec guard MUST remain intact.

| Artifact | Locally computed Git blob SHA-1 (`git hash-object`) | Local SHA-256 |
|---|---|---|
| `safe_public_ci/ci_temporal_origin_quarantine.py` | `5b379c3bf24253a9c5aa0dee3a4295590c9469fa` | `6a676b05624697631f4d8aeec696c73fa7d009e3d9f6dc809da37b57712953cf` |
| `tests/test_rc677_temporal_origin_quarantine.py` | `9495900f6da4422756ca90a9c221ef8594871214` | `6ca20f6bbdd335f8f36037316499e6fd2265ed659bb9ad9970c24d166b29ea10` |

Upload only tested bytes to Public validation branch and independently read back both Git blobs before counting as byte-exact remote delivery.

## Required final hosted verification and remaining NO-GO

Entry RC676 = **1094** native synthetic cases per OS, new RC677 = **74**, hence **1168 expected** cases per OS, **not PASS** until final exact HEAD Ubuntu AND Windows `push` run, job, 9/9 steps and full verbose job logs actually confirm `Ran 1168 tests` and `OK`. Put the verified final run/job IDs in Draft PR #7 body *after* successful provider readback, without another code commit.

Independent verified time/issuer provenance, cryptographic signature verification, signed key-revocation service, a durable external CAS and monotonic log, independently approved PR1 integration and real signed Windows/Ubuntu/server install-service acceptance remain **NO-GO**. Official Public Build owner publication acceptance is **5/10 = 50%** (NOT general code completion, trading readiness or returns); platform package acceptance **0/3**; real +20% net = **NOT_TESTED**.

## TUR35 focus

Revalidate RC677 final-SHA same-hosted dual OS evidence. Continue with distinct verified trust-source design and adversarial clock drift, revocation receipt signatures, freshness, cross-origin split views and transactionally durable single-winner semantics. Do not claim genuine authenticated, LIVE, FINAL or economic return from invented fixtures.
