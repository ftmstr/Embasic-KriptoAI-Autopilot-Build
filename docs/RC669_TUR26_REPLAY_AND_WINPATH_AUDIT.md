# KriptoAI Autopilot — TUR 26 / RC669 — 2026-11-10

## 1. Immutable baseline and audit scope

- Only Public `ftmstr/Embasic-KriptoAI-Autopilot-Build`, existing Draft PR #7 and `validation/rc654-pr1-rc653-combined-ci`. Entry HEAD: `4a44b24b11685f0f4cd6418013eb955657acc659`. PR remains open/draft/unmerged. Public main: `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`; never modified.
- PR #1 head `710517be3b4a0a671458b6e6cad0261138d0b3b0`, still draft/unmerged. Original 18 tests **not integrated**; PR #1 and #7 independent submitted reviews: **0**.
- No contact with Private repository, CI workflow filters/permissions, secret data, real market APIs, orders, deploys, model fit, release signing, Main merges or live operations.
- Locks **FINAL=SEALED, LIVE=DISABLED, SINGLE_FIT=UNUSED, +20% NET=NOT_TESTED**.

## 2. Revalidated real native GitHub Actions before coding

- Ubuntu: [run #42769409738](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42769409738), job `129673411183`, `event=push`, `run_attempt=1`, `head_sha=4a44b24b11685f0f4cd6418013eb955657acc659`, run/job **completed/success**, **9/9** successful steps, full log `Ran 647 tests` and `OK`, **647** individual successful lines, including all 40 RC668 tests.
- Windows: [run #42769409743](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42769409743), job `129673411400`, same exact SHA and event, **9/9** successful steps, full log `Ran 647 tests`, `OK` and **647** individual passing cases, including 40 RC668 tests.
- These are **synthetic public CI**, not an audited real-market trading model, signer provenance or product-ready package.

## 3. Actual findings and hardening

The pre-existing RC668 `ci_hosted_pair_identity_gate.py` checks two locally supplied sets of metadata, and the RC667 hosted unittest log guard checks structural result only. Neither can independently authenticate GitHub-origin metadata or guarantee that the same signed log receipt was not reused on a later call. In particular, **cross-invocation replay detection requires an external trustworthy consumed-history source**; this cannot be safely simulated by inventing a trusted memory in a stateless validator.

### New original `safe_public_ci/ci_receipt_replay_fence.py`

- Offline, fail-closed, explicitly **NOT_AUTHENTICATED** receipt-history consistency guard for one Ubuntu/Windows pair, exact externally expected SHA/run IDs/job IDs, distinct per-platform SHA-256 log digests, roster and source digests.
- Requires separately authenticated and externally stored, canonical, sorted, unique history inputs: consumed pair fingerprints and consumed log hashes. Rejects duplicate pair, reused log, repeated same-host log bytes across platforms, wrong identities/sha/roster/source shape, bad types and overlong histories (max 1024 digests).
- Versioned deterministic SHA-256 fingerprint bonds exact SHA + both OS run/job/log digests + roster + source digest; this does not make an attacker-provided history authoritative, does not persist history, and does not authenticate an actual GitHub API run.
- Only existing allowed stdlib `hashlib`, `hmac`, `re`, no disk, network, compile/eval/exec/open, exchange execution or private data.
- `tests/test_rc669_replay_fence.py`: **32 original adversarial in-memory invented-receipt tests**, including replay of pair, reused individual OS logs, duplicated IDs, foreign SHA, wrong roster and source digest, malformed noncanonical consumed history, type abuses, and explicit non-authenticated result.

### RC667 source-byte manifest Windows path compatibility

- `safe_public_ci/ci_source_byte_gate.py` now rejects cross-OS ambiguous Windows device paths (CON/PRN/AUX/NUL, COM1..9 and LPT1..9, even when suffixed `.py`), and source paths longer than 128 code points; preserves strict ASCII allowlist, sorted canonical tuple and exact SHA-256 plus Git blob checksum.
- `tests/test_rc669_cross_platform_paths.py`: **14 original adversarial invented source-path cases**, including reserved devices, traversal, overlong paths, valid ordinary test names and COM0.
- Existing `ci_hosted_unittest_log_gate.py` was inspected. Its structural status `HOSTED_LOG_STRUCTURE_ONLY_NOT_AUTHENTICATED` is retained unchanged; an independently authenticated provider and durable journal remain external blockers. No existing source import whitelist, compile/eval/exec guard, workflow path filter or job permission changed.

## 4. Local CPython 3.13.5 execution and exact source bytes

- Actual `python --version` = `Python 3.13.5`.
- `PYTHONPATH=/mnt/data/rc669 python -m unittest discover -s /mnt/data/rc669/tests -p 'test_rc669*.py' -v`: **46/46 PASS** (32 replay + 14 cross-platform source paths).
- `python -m compileall -q /mnt/data/rc669`: **PASS**.
- Before every GitHub write, exact local file bytes had Git SHA-1 blob and SHA-256 independently calculated. GitHub contents readback **4/4 blob matches**:
  - `safe_public_ci/ci_receipt_replay_fence.py`: Git blob `86c503aed4637367ec64c518e3f2d98c90becc11`, SHA-256 `3b7c917f8d2fa9739ebaff380e95d1b6d1a0b780cffc754e9541e988ab583209`.
  - `tests/test_rc669_replay_fence.py`: Git blob `a7419c71656245dcd5c059755509cff22daa6c6e`, SHA-256 `b5274f37b08655477671ed9b55db2bf4c505917bae00980f4f711f639ed10f2b`.
  - `safe_public_ci/ci_source_byte_gate.py`: Git blob `bee0b67514f6489b824251367e4b03715a8c937a`, SHA-256 `78d3f332b6718404df0f6d5cae07a32055f1ea46dd6e741b0316ff77bebc2996`.
  - `tests/test_rc669_cross_platform_paths.py`: Git blob `6e6eac8d4990dc771eee0c79cc6b1900226f582e`, SHA-256 `7508ce66a2d8f177f547d203ddfe6f166f23657d372b2d4e501c2902e3a13aa1`.
- Compared RC668 entry to last code commit: precisely these 4 files changed; no `.github/workflows/`, original PR #1 files or main changes.

## 5. Final hosted CI evidence state and TUR 27 handoff

- Expected native synthetic suite after RC669: **647 prior + 46 new = 693 per OS**. A forecast is not PASS.
- The later report commit changes HEAD; safe source-only explanatory comment will rerun **existing unchanged** public `push` workflows. Verify exact final SHA and both Ubuntu and Windows run/job/step/full-log outputs separately. A previously passing earlier SHA must NOT be represented as final.
- Permanent provenance/signature, independently trusted metadata/consumed-history service, license/SBOM/security reviewer approvals, reproducible signed installer plus Windows/Ubuntu/server acceptance, and PR #1 review are still blocked.
- Official Public Build owner publication checklist remains **5/10 = 50%**, not overall software completion, financial performance or trading readiness; Windows/Ubuntu/server end-user package acceptance **0/3**. Net +20% **NOT_TESTED**.

## 6. Next adversarial focus

For TUR 27, verify the final RC669 SHA and both native OS logs. Audit atomic external replay-history update, lost-ACK and parallel-read replay races and provider identity trust. A pure function cannot provide authoritative authentication or durable single-use consumption. Keep all original source, CI permission/compile/import and no-live locks, do not integrate PR #1 without explicit independent approval.
