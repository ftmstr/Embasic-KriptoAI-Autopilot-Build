# KriptoAI Autopilot — TUR 22 / RC665 (2026-11-09)

## 1. Verified baseline

- Public-only branch `validation/rc654-pr1-rc653-combined-ci` at entry: `1718c54533632307071c2a729224f3fa1613d174`. Draft PR [#7](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/pull/7), not merged.
- Public `main` unchanged at `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`. Private research repository was neither fetched nor modified.
- Real GitHub Actions native `push` runs at **one exact RC664 SHA**:
  - Ubuntu 24.04: [run #42541739088](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42541739088), job `128917958916`, completed SUCCESS, 9/9 successful job steps, full job log `Ran 465 tests` and `OK`; 40 RC664 new cases present.
  - Windows hosted: [run #42541739015](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42541739015), job `128917958575`, completed SUCCESS, 9/9 successful job steps, full job log `Ran 465 tests` and `OK`; 40 RC664 new cases present.
- Both completed runs report `head_sha=1718c54533632307071c2a729224f3fa1613d174` and `event=push`. This corrects TUR21's earlier QUEUED / NOT_VERIFIED Windows status, **for RC664 only**.

## 2. RC664 adversarial finding and RC665 solution

- RC664 `ci_case_roster_guard.py` rejects all ASCII escape bytes anywhere in an input. Real GitHub-hosted full job logs contain SGR ANSI in the `##[group]Run python -m unittest discover -s tests -v` header. Therefore RC664 accepts simplified test excerpts but does **not** work as a full raw hosted-log verifier.
- Original RC665 `safe_public_ci/ci_hosted_unittest_log_gate.py` is a **separate** in-memory structural verifier for *complete* synthetic-shape GitHub job logs. It requires exactly one `Run python -m unittest discover -s tests -v` step, its command and `SAFE_TEST_ONLY: 1` header, accepts only validated SGR formatting outside the test-output section, strictly checks each qualified case name against an externally expected sorted canonical roster plus hashes, validates UTC log timestamps and test-summary order, rejects test substitutions, duplicated/missing/skipped/error cases, unexpected terminal control inside the unittest section and fake/tampered/truncated work, and demands the observed post-job cleanup footer.
- New `tests/test_rc665_hosted_unittest_log_gate.py`: **38 original invented-fixture adversarial unit tests** (successful, invalid and boundary cases), no real GitHub log or market data embedded.
- Local **CPython 3.13.5**: RC665 **38/38 PASS**, `python -m compileall -q safe_public_ci tests` PASS (on synthetic local module/tests). Compare exact Git blob SHA-1 against tested byte contents when reviewing the commits.
- Scope: this is *structure-only*, not proof that raw log bytes came from GitHub; digest and trusted roster require external authentication. The verifier deliberately returns `HOSTED_LOG_STRUCTURE_ONLY_NOT_AUTHENTICATED`, `release_ready=False`, `live_trading_allowed=False`. The existing RC664 verifier is preserved unmodified.
- **Expected RC665 full-suite hosted count if all regressions pass:** RC664 465 + RC665 38 = **503** per OS. This is a planned count, NOT real CI success until the native Windows/Ubuntu run/job/step/log results on the **final RC665 HEAD** are verified.

## 3. PR #1 review and release restrictions

- PR [#1](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/pull/1) is Draft, unmerged. Its 18 independently inventoried regressions cover strict JSON (7), ZIP (3), Parquet envelope (1), mock order/quote (5) and digest checks (2). Its only other modified file is the synthetic read-only GitHub workflow.
- GitHub submitted review list for PR #1 and PR #7 was empty. **No independent reviewer approval** or authorization to merge or integrate. None of PR #1's 18 tests was copied or included into RC664/RC665 suites.
- Preserve workflow `push` filters/permissions/actions/hosted runners; no bypass, self-hosted runners, arbitrary code execution, real orders, model training, market evaluations, deployment, signing, license grant, or release.
- Immutable scientific locks: `FINAL=SEALED`, `LIVE=DISABLED`, `SINGLE_FIT=UNUSED`, and `+20% NET=NOT_TESTED`.
- Original owner acceptance list remains **5/10 = 50%**; this is a Public Build publication-control fraction, NOT whole application completion or profitability. Independent source+history audit, security/license and SBOM review, reproducible signed artifact provenance, authorized PR1 merge and actual Windows/Ubuntu/Linux-server lifecycle acceptance remain blockers.

## 4. TUR 23 follow-up

Independently fetch **final RC665 HEAD** native GitHub-hosted `push` CI run/job/step/logs for both Windows and Ubuntu. Record actual result, not assumed 503 PASS. Deepen adversarial test coverage of RC665's ANSI sanitization, job-boundary semantics, timestamps and untrusted-roster provenance; verify full job log compatibility where available. Do not merge PR #7 or PR #1, do not modify `main` or Private research.

## 5. Actual hosted CI and RC665 defect postmortem

- Initial RC665 source commit `3bcbddd1cf33acc2b1e173ba7506effeae7723c3`: the uploaded `_stamp_ok` month length table accidentally omitted November and December even though local test source included all 12 months. The source blob SHA-1 **did not match** the tested local file (`27cc7ea931116e3ea83e10341f80e7ba61ac167c` versus expected `73a62a1f78b00211dcad98ae353328c2d1e85c0d`). Hosted Ubuntu [run #42544147223](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42544147223) exposed **503 tests, FAILED (31 errors)**: `IndexError: tuple index out of range` for month 11. Never count this as successful.
- Fixed source in commit `1e59782897b171935c05bc9fa7dc71e1ba3c5693`, now Git blob matches local-tested `73a62a1f78b00211dcad98ae353328c2d1e85c0d`. The first corrected same-SHA GitHub-hosted runs completed:
  - [Ubuntu #42544264335](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42544264335) job `128925736973`: 9/9 steps, **503/503 PASS**, `OK`, 38 RC665 tests.
  - [Windows #42544264307](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42544264307) job `128925736791`: 9/9 steps, **503/503 PASS**, `OK`, 38 RC665 tests.
- Prevention: append 4 targeted invented-input calendar regression tests (November, December, invalid month 13, February 29 in leap year 2028) bringing local RC665 module to **42/42 PASS** and expected full-host suite to **507** per platform, provided those tests run on the exact final reviewed commit. Do **not** transpose 503 PASS onto a later SHA.
- Do not change workflow paths/permissions, Main or Private repositories; no approval to merge or enable real trading. CI is synthetic-only.
