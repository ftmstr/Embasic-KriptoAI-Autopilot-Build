# KriptoAI Autopilot — TUR 28 / RC671 — 2026-11-10

## Scope and hard boundaries

Only Public GitHub `ftmstr/Embasic-KriptoAI-Autopilot-Build`, Draft PR #7, branch `validation/rc654-pr1-rc653-combined-ci`. Baseline RC670 HEAD `b0bdd0a585bd565a5c051b64f93fc1096c3153ef`, base `research/rc653-synthetic-receipt-envelope`; Public main `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471` unchanged at baseline. No Private access, main merge, workflow filter/permission modifications, market order, model fit, production deploy, signing or performance assertion. Keep `FINAL=SEALED`, `LIVE=DISABLED`, `SINGLE_FIT=UNUSED`, `+20% NET=NOT_TESTED`.

PR #1 remains Draft with 18 unrelated original tests not merged/integrated; PR #1 and #7 submitted independent review count **0**. Preserve `tests/test_guard.py` and its safe-module import allowlist and compile/eval/exec/other dynamic execution bans.

## 1. Actual starting native hosted CI revalidation

The actual GitHub Actions run API, hosted job metadata, all step outcomes and raw verbose job logs were independently read for both baseline runs, each on the **same exact SHA** `b0bdd0a585bd565a5c051b64f93fc1096c3153ef` and `event=push`:

| OS | Real run | Job ID | Outcome | Verbose log |
|---|---|---|---|---|
| Ubuntu | [42797489293](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42797489293) | 129766267020 | completed/success, **9/9** steps | **743/743** passing lines, `Ran 743 tests`, `OK`, 50 RC670 cases |
| Windows | [42797489220](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42797489220) | 129766266747 | completed/success, **9/9** steps | **743/743** passing lines, `Ran 743 tests`, `OK`, 50 RC670 cases |

These are real hosted **synthetic tests**, not end-user platform package acceptance or actual trading results.

## 2. RC670/669/source/log/pair boundary review

Reviewed `safe_public_ci/ci_cas_readback_guard.py` (RC670), `ci_receipt_replay_fence.py` (RC669), `ci_source_byte_gate.py`, `ci_hosted_unittest_log_gate.py`, `ci_hosted_pair_identity_gate.py` and `tests/test_guard.py`. Existing standalone gates detect malformed local data but **cannot authenticate GitHub metadata, an independent trust root, a durable revision journal or atomic contention**. The RC670 proposal and readback guard intentionally do not mutate a provider.

Specific opportunities: demonstrate that two workers may hold the same base, that both cannot *consistently claim* an authoritative win in one supplied serial history, that generation numbers bind state roots to defend against ABA-style stale-root substitution, and that rollback, lost ACK and replay remain fail-closed. None proves a real provider's linearizability.

## 3. New RC671 public source and invented-only tests

Created `safe_public_ci/ci_cas_interleaving_trace.py`:

- Only existing allowlisted imports `hashlib`, `hmac`, `re`; no file IO, external API, state mutation or dynamic Python execution.
- Recomputes RC670's exact versioned `RC670-PUBLIC-SYNTHETIC-CAS-V1` root over bounded sorted unique pair/log SHA-256 histories and a monotonic generation; strict shape, type, event count and identity limits.
- Accepts an explicitly **caller-supplied** serial event trace: `PREPARE`, `COMMIT`, `CONFLICT`, `ROLLBACK`, `ACK_LOST`, `READBACK`. Forbids two same-generation winner claims, repeated pair or log consumption, worker reuse, stale baselines, altered receipt content, false conflict, rollback-after-uncertain-write, and readback with incorrect generation/root.
- A lost-ACK readback that matches the *claimed* expected next state only returns `CLAIMED_LINEARIZATION_CONSISTENT_NOT_AUTHENTICATED` with `release_ready=False` and `live_trading_allowed=False`. It **does not establish** a committed transaction or genuinely trusted provider origin. A malicious actor who controls the complete trace and expected hashes can forge a self-consistent transcript. No external CAS backend, auth or persistent journal is implemented.
- The source-Git-SHA and source SHA-256 inputs are **shape-validated**, not authenticated; trusted roots and provider run IDs must come from an external separately authorized source. This is explicitly a synthetic consistency checker.

Created `tests/test_rc671_cas_interleaving_trace.py`: **46 original invented adversarial tests** covering two contenders from one base, false double-winners, valid conflict, serial distinct wins, lost ACK with claimed match vs stale readback, stale late writer, ABA generation/root, duplicate worker/log/pair, rollback, wrong trust pin, malformed/oversized evidence, missing finalization, and nonproduction return flags. No PR #1 tests were copied.

## 4. Local Python 3.13.5 and exact-byte checks

`python3 --version`: **3.13.5**.

`PYTHONPATH=/mnt/data/rc671 python3 -m unittest discover -s /mnt/data/rc671/tests -p 'test_rc671*.py' -v`: **46/46 PASS**.

`python3 -m compileall -q /mnt/data/rc671/safe_public_ci /mnt/data/rc671/tests`: PASS.

| File | Exact local git hash-object SHA-1 | Exact local SHA-256 |
|---|---|---|
| `safe_public_ci/ci_cas_interleaving_trace.py` | `065ac65f767ba1fa7d85483b2fda726b928fdf20` | `771b4ced6b36676dba879005495d0934b33450f9ae494ce8499a226bef51edb2` |
| `tests/test_rc671_cas_interleaving_trace.py` | `6d3521601394c8261891a67efbe7c87efba62252` | `665417b716aa804860fc0c13eb5c957411355b0291b7e5cfef8e43559017319c` |

Public GitHub `fetch_file` readback matched **2/2** exact tested blobs. Do not repeat TUR22 local-to-remote transfer error.

## 5. Final GitHub Actions and blockers

Expected suite after RC671 = 743 inherited tests + 46 new synthetic cases = **789 per platform**. This is a **forecast only**, not a PASS claim until exact final SHA native `push` run/job/step/verbose-log results are checked for Ubuntu and Windows. Final run links, confirmed SHA and complete outcomes belong in Draft PR #7 after verification, to avoid moving HEAD merely to append evidence.

Remaining NO-GO: actual independently authenticated append-only CAS provider, durable journal with atomic contention, trusted provider-run provenance, actual release signing/history/security/license/SBOM approvals, independent PR #1 review and real installable/service lifecycle tests on Windows, Ubuntu and server. Public Build owner publication checklist remains **5/10 = 50%**, **not** overall product completion or expected investment returns. Net +20% is NOT_TESTED.

## 6. TUR 29 focus

Recheck RC671 exact-final-SHA Ubuntu/Windows CI and local/remote SHA evidence. Evaluate how an out-of-band authoritative CAS response/ledger might be verified without changing existing import/compile/CI permission gates; test forged conflicting readbacks, trusted root rotation, log identity re-binding and uncompensated rollbacks. No live exchange orders, model fits, private code, main merge or deployment.
