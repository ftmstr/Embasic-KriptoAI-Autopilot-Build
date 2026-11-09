# KriptoAI Autopilot — TUR 24 / RC667 — 2026-11-09

## Scope and immutable gates

- **Public only:** `ftmstr/Embasic-KriptoAI-Autopilot-Build`, existing `validation/rc654-pr1-rc653-combined-ci` and Draft PR #7. Baseline RC666 exact SHA `23d9fff596960e99f87559fb3c9d2b4d52a9887a`.
- The Public `main` remained `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471` during development. Private repository never read or modified. Do not merge, deploy, sign, activate exchanges, train on live data, or change workflow permission/filters/triggers.
- Immutable boundaries: `FINAL=SEALED`, `LIVE=DISABLED`, `SINGLE_FIT=UNUSED`, `+20% NET=NOT_TESTED`.

## Baseline same-SHA GitHub-hosted run / job / step / log validation

| Target | Native workflow run | Hosted job | Status | Verified actual unittest log |
|---|---|---|---|---|
| Ubuntu 24.04 | [42545887045](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42545887045) | `128930708591` | completed/success; 9/9 steps | `Ran 555 tests`, `OK`, 555/555 |
| Windows hosted | [42545887069](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42545887069) | `128930708637` | completed/success; 9/9 steps | `Ran 555 tests`, `OK`, 555/555 |

Both were event `push` with exact head SHA `23d9fff596960e99f87559fb3c9d2b4d52a9887a`. 36 source-byte and 12 hosted-log RC666 test rows were present in both logs.

## RC667 independent source-byte integrity investigation

The RC666 `safe_public_ci/ci_source_byte_gate.py` verified canonical raw byte formats and externally expected SHA-256 plus Git blob SHA-1, but accepted valid UTF-8 that contains visually deceptive invisible control characters (such as Unicode bidirectional overrides/isolates and zero-width format marks), and accepted syntactically invalid Python sources. That was a concrete fail-closed gap: caller-controlled trusted digests do not independently prevent malicious source bytes.

RC667 modifies **only this Public synthetic guard** to:
- Reject Unicode General Category `Cf` (format/invisible including bidi), `Cc` other than LF/tab, `Zl` and `Zp`, while allowing ordinary Turkish text and combining diacritics.
- Run `ast.parse(..., mode="exec")` on decoded source without importing or executing the represented Python program, rejecting SyntaxError, ValueError, RecursionError, MemoryError.
- Preserve the original exact-byte SHA-256 / Git blob SHA-1 check, canonical paths, UTF-8, LF and byte-size bounds; none of these claims independently authenticate GitHub, the source repository, a cryptographic signature or signer.
- `tests/test_rc667_unicode_ast_gate.py`: **36 original invented-input tests** targeting bidi, zero-width, Unicode separators, malformed source, deep nesting, valid Turkish UTF-8 and required nonproduction status.

## RC667 synthetic hosted log postlude investigation

The prior `ci_hosted_unittest_log_gate.py` postlude rejected `##[group]Run ` with a trailing ASCII space, but permitted equivalent tampered markers with a tab, a nonbreaking space, no space or suffix, as well as unrelated nonblank lines after the final `Cleaning up orphan processes`. On the unpatched local exact-baseline source, 5 of 16 focused adversarial tests failed (bad records were accepted). After repair all **16/16** passed.

RC667 modifies only the offline validator:
- Reject **any** postlude `##[group]Run` prefix, regardless of separator.
- After the final orphan-cleanup marker, reject any additional nonempty timestamped content; allow legitimate blank end marker.
- Preserve valid GitHub-header SGR in its existing controlled stage, fail-closed output counters and `HOSTED_LOG_STRUCTURE_ONLY_NOT_AUTHENTICATED` return.
- `tests/test_rc667_hosted_footer_adversarial.py`: 16 original invented-only cases, including successful normal/two-cleanup/synthetic SGR headers and spoofed run marker/tail/duplicate/invalid timestamp cases.

## Byte-for-byte local Python validation and GitHub readback

- Actual local runtime **CPython 3.13.5**, `PYTHONPATH=/mnt/data/kripto_tur24 python -m unittest discover -s /mnt/data/kripto_tur24/tests -p 'test_rc667*.py' -q`: **52/52 PASS** (36 source + 16 log), `python -m compileall -q /mnt/data/kripto_tur24`: PASS.
- Git source blobs matched local-tested byte-identities:
  - `safe_public_ci/ci_source_byte_gate.py`: `dedd451de174ff5c7b525be8047ae5fd23b697d1` (before final small explanatory comment, if any).
  - `tests/test_rc667_unicode_ast_gate.py`: `f5922de9219e93f3b2adf7829c04b3e85d956306`.
  - `safe_public_ci/ci_hosted_unittest_log_gate.py`: `8cafa56b76d4abeefd72271f0704ce288813a23d`.
  - `tests/test_rc667_hosted_footer_adversarial.py`: `9c815e7ed5bd3e0dc6a0f29734ff07b6e64440cd`.
- **Expected full combined native hosted CI: 607 tests/OS** = RC666 555 + RC667 52. Never claim exact-SHA RC667 Windows/Ubuntu success without fetching each new run, job, step and raw log. Workflow `push` path filters are preserved.

## PR #1 and remaining release blockers

- Draft PR #1 head `710517be3b4a0a671458b6e6cad0261138d0b3b0` remains unmerged. The 18 deterministic tests from `tests/test_regression_expanded.py` are not imported, merged or counted in Public RC667.
- Actual GitHub PR review lists for #1 and #7 returned **zero** independent reviewers/approvals. Owner-approved license/SBOM/history/security checks and signed binary + real Windows/Ubuntu/server installer/service lifecycle acceptance remain open.
- Official Public Build publication-control checklist remains **5/10 = 50%**. This is not an overall product completion estimate, investment performance or model quality indicator.
- Financial net +20% performance has not been tested or validated; no secret exchange adapter, orders, cancellation, private model research or live trading has been used.

## TUR 25 handoff

1. Recheck Draft PR #7 final RC667 SHA and Public main/Private boundaries. Query native `push` GitHub Actions via `/actions/runs?head_sha=<exact_sha>&event=push` and validate actual Ubuntu and Windows job/step/full logs. **607/607** is an expectation until confirmed.
2. Verify all changed Git blobs against locally tested byte hashes; do not repeat TUR22 transfer mismatch.
3. Test Unicode security treatment for legitimate source comments, inspect `ast.parse` CPU/resource bounds, and explore defenses against spoofing of CI metadata beyond caller-supplied hashes. Keep all provenance claims not-authenticated without independent authorized trust.
4. PR #1's 18 tests require separate independent review and express approval before integration; no main/Private merge, no live execution, no release.

