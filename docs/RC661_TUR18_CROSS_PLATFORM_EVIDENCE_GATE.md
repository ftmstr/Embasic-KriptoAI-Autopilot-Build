# KriptoAI Autopilot — TUR 18 / RC661: Dual-platform CI evidence gate (2026-11-09)

## Baseline (read-back verified before change)
- Public branch: `validation/rc654-pr1-rc653-combined-ci`
- Previous HEAD: `2761a86fd322d01db9d7fcfd79f179497f976f47` (RC660)
- Public main: `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471` (untouched)
- Previous Windows hosted #42339772960: 345/345 toy tests; Ubuntu #42262660834: 302/302 tests on another SHA.
- Draft PR #1–#5 remain separate; PR #1's 18 regressions have not been integrated.
- Issue #6 controls release blockers. No independent security/license sign-off.

## RC661 change
- `safe_public_ci/ci_evidence_gate.py`: independent stdlib-only *metadata consistency* gate that rejects mismatched Git SHA, runner IDs, job IDs, platform identities, test totals, failed/skipped cases and incomplete steps. It never reads files, performs network operations, accesses Private data, installs anything or trades.
- `tests/test_rc661_ci_evidence_gate.py`: twenty invented-data adversarial cases; local Python 3.13.5 run: 20/20 PASS.
- Source write occurs last so existing **authorized** Public hosted workflows, if they trigger on `safe_public_ci/**`, can evaluate the exact final source SHA. This does not override previous workflow path-filter denials or modify workflow configuration.
- Check result is always `METADATA_CONSISTENT_NOT_AUTHENTICATED`; source records, GitHub run/job/step/logs and independent signer identity require external review. Matching user-supplied metadata is NOT provider-signed attestation or real CI evidence.

## Claims prohibited
No deployment, installer, real rollback, real exchange traffic, model fitting, backtesting, PnL, or return proof. Private main/checkpoint unchanged. `FINAL=SEALED`, `LIVE=DISABLED`, `SINGLE_FIT=UNUSED`, `+20% NET=NOT_TESTED`.

## Acceptance / progress
Public Build release gates remain **5/10 = 50%** pending independent review and exact-commit cross-platform evidence. No progress score inflation from synthetic tests. End-of-turn results must be updated with **actual** GitHub CI run IDs, job IDs, SHA and logs if obtainable; otherwise classify NOT_VERIFIED.

## Required next actions
1. Independent source/history/secret/license review before any merge or public release.
2. Compare GitHub native Windows and Ubuntu run/job/step/log evidence for exactly one reviewed SHA; if no evidence, NOT_VERIFIED.
3. Review PR #1's 18 additional regressions and authorize integration separately; never silently count them.
4. Separately approve signing provenance, packaging and actual Windows/Ubuntu/server lifecycle smoke before release.
