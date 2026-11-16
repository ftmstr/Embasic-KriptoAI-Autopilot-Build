# KriptoAI Autopilot — TUR54 / RC697: actual hosted observation custody, trust-origin acquisition blockers

**Date:** 2026-11-16 (Europe/Istanbul). **Scope:** exclusively PUBLIC `ftmstr/Embasic-KriptoAI-Autopilot-Build`, branch `validation/rc654-pr1-rc653-combined-ci`, open/unmerged Draft PR #7. NO private repo, merge, deploy, live exchange, model fitting or profit assertion. Hard locks: **FINAL=SEALED, LIVE=DISABLED, SINGLE_FIT=UNUSED, +20% NET=NOT_TESTED**.

## 1. Independent TUR53 foundation verification

Prior final HEAD and branch/PR #7 both exactly `1b7cd5a7bd4251e702e1d93d6b2ddf034d84bd8e`. No RC697/TUR54 or later files existed in the 151-entry Git tree at baseline. PR #7 open, Draft, unmerged; PR #1 open, Draft, unmerged, no incorporation/authorization of its 18 additional tests; Public main `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`. Five unchanged workflow Git blob SHA-1 values: RC652 `28fedf1e76f1d26247fcb1897c176bc3b7009808`, RC653 `d7a08e1935b060d31feca2e1ef8db4184268858c`, RC654 Ubuntu `140264aaf07f3130a23606254f545b4ff77b1971`, RC658 Windows `254ac4f4ea821a05ee4730c3828d4de1b96a0e72`, general synthetic `1cd73e647401f75ae9a98f55d8adcd166a366fe3`. RC656 `safe_public_ci/snapshot_package.py` blob `7db54362bb627b26f9be0c09bb958a8601c961a2`, `MAX_ENTRIES=32` preserved.

Actual prior native Ubuntu [run 43833630743](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43833630743), job `133184729775`, and Windows [run 43833630781](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43833630781), job `133184729913`, both run/job `completed/success`, attempt 1, **9/9 real steps SUCCESS**, original independently fetched entire job log has **3004/3004 unique `... ok`**, **41 RC696** cases, no FAIL/ERROR/skipped/ResourceWarning; Ubuntu footer `Ran 3004 tests in 10.546s; OK`, Windows `Ran 3004 tests in 96.661s; OK`. First failure records are **retained** as failures: initial RC696 Ubuntu run `43833037862` and Windows run `43833038012`, each `completed/failure` due to the pre-fix stdlib import whitelist guard. They were corrected in a different SHA, not relabelled.

## 2. Actual external acquisition attempts and observed facts

Read-only public GitHub Actions API shows the above real runs, jobs, steps, full **decoded job-log strings**, and **zero workflow artifacts returned for each run**. The latest two logs were fetched independently, and their decoded-text content was re-encoded to UTF-8 and SHA-256 hashed; empty-string and `abc` SHA-256 test vectors verified the hashing implementation. The resulting exact observations are serialized in `docs/RC697_TUR54_HOSTED_OPERATIONAL_OBSERVATIONS.json`. These are **real operational data observations**, not provider-**signed** source attestations. The decoded UTF-8 re-encoding might not preserve the provider's original raw response bytes exactly, and so its digest is **not described as a SHA-256 of original RAW provider log bytes**. Source identity, scope and expected workflow blobs are explicitly pinned.

| Host | Run / job | Real steps and full-log tests | Decoded log length | Re-encoded UTF-8 bytes | SHA-256 of re-encoded decoded text |
|---|---|---|---:|---:|---|
| Ubuntu | `43833630743` / `133184729775` | 9/9; 3004/3004 PASS | 502036 UTF-16 code units | 502118 | `4b5e6a8bfb8ba430709c53d4c473d8dbe99a33a62f7e95eff32b8e12bec4355a` |
| Windows | `43833630781` / `133184729913` | 9/9; 3004/3004 PASS | 513496 UTF-16 code units | 513498 | `3955877ecedfb8f0deb4cb741cf263de9cfc154187e8b3abe7ad3e50f35ffed7` |

**Important provenance limit:** GitHub Docs provide read-only downloadable workflow job logs, whereas cryptographic **artifact attestations** are distinct; generating native attestations requires an `attest` action plus `id-token: write` and `attestations: write` permissions. Current five workflow permissions/filters must remain unchanged by user instruction. A build-artifact attestation would not automatically be a provider-origin signature over an entire *raw* GitHub job log. No independent signed full-log certificate was returned by the API reviewed here. Official docs: https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs and https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations . Absence of run artifacts does **not** prove the repository has never issued attestations elsewhere.

## 3. New, unique acquisition integration boundary

New stdlib-only module `safe_public_ci/ci_rc697_operational_evidence.py` inspects the **real** pinned GitHub operational-observation manifest, checks exact source/branch/workflow/run/job/attempt/log-encoding digest/steps/test counters, and optionally hashes independently supplied **decoded** log text bytes. Unlike the prior TUR53 synthetic provider-signature candidate module, it anchors real previously independently fetched metadata to a reproducible manifest, discriminating `GITHUB_API_OPERATIONAL_LOG_ONLY` from real verified provider-signed evidence. It produces an eight-item explicit external proof acquisition plan, never claims that a local content hash, role name, arbitrary signature, sender address or claim of trusted time authenticates an authority.

`make_handoff_request` produces a domain-separated, source/workflow/job/challenge/nonce/audience-scoped **request only**, which external owner, truly separate reviewer, or independent provenance auditor would need to process with **separate actual trust roots**. `inspect_untrusted_candidate` rejects forgery of `verified`, `trusted_time`, `remote_cas`, `remote_ack`, `immutable_root`, or `GITHUB_SIGNED` origin flags. It never opens any gate. No external signer or recipient is contacted, no private keys are generated, no network/trading is performed, no cross-host CAS, Merkle witness or remote ACK is impersonated.

**Concrete outstanding handoffs and decision boundaries:**

1. Owner OOB Ed25519 key: independent key administrator must physically/out-of-band pin a public key, provide scoped signed delegation and custody/rotation policy; not GitHub account identity alone.
2. Reviewer OOB Ed25519 key: *different administrative trust domain* must independently countersign the same request, and reviewer authority/rotation history must be independently authenticated.
3. Ubuntu provider raw-full-job-log attestation: demand verifiable provider-origin signature over exact **raw** bytes including run/job/attempt/source/workflow with documented trust root; decoded log GitHub API bytes alone insufficient.
4. Windows equivalent: independent full original job log and provider-origin signature, independently authenticated against corresponding run/job and source.
5. Revocation/trusted time: independent non-rewindable timestamp service and authenticated per-key revocation history; local epoch and a timestamp-shaped string are not trusted time.
6. External Merkle: separate append-only transparency/witness operator, pinned signed root, inclusion plus historical consistency and split-view detection; caller-submitted root is not immutable.
7. Durable cross-host CAS: remote distinct-admin linearizable service, monotonic fencing and stable anti-snapshot-restore checkpoint with tested multi-host failure semantics; local SQLite clone/backup cannot provide it.
8. Remote ACK: genuine independently authenticated recipient response with exact idempotency and reconciliation after lost response; local `PENDING`/`ACKED` status is not an exchange ACK. No order should be sent as part of this project phase.

**0/8 independent external gates remain `BLOCKED`**. In particular, GitHub run success and an Ed25519 equation involving a caller-supplied key alone authorize nothing. Without independent real external service participation, there is no safe technical route to upgrade any of the eight families to `VERIFIED` in this turn.

## 4. Local proof of source correctness and byte identities

Python **3.13.5**, `PYTHONWARNINGS=error`: **30/30 new RC697 tests PASS**, `compileall -q` PASS and AST parse PASS. These are targeted replay, branch/source forgery, host switch, wrong workflow/run/job, fake provider signature, log byte reencoding, snapshot reset, false origin, fake release, stale challenge, audience swap and claimed CAS/ACK attacks. No test of actual external signing infrastructure occurred; the whole test suite's final hosted test count must be **3034 (3004 prior +30)**. The data file is a reproducible record of observations, not a sealed external document.

| File | local tested bytes | Git blob SHA-1 | raw SHA-256 |
|---|---:|---|---|
| `docs/RC697_TUR54_HOSTED_OPERATIONAL_OBSERVATIONS.json` | 1620 | `9fc846f8ced272fafd858ba0ade14fdc7323c25a` | `dbc8ec2c8dac7b73e9a7e8001772225f70f8c19d4e316c39d10cbcff72350b20` |
| `tests/test_rc697_operational_evidence.py` | 9567 | `0a1d422570b20dd0ac0ca9c72ef2bd65904de7d4` | `518a6d80f7ee2fa49b82d89f3c93701b623d34dcb2ffcead9e664c807a18bc4b` |
| `safe_public_ci/ci_rc697_operational_evidence.py` | 12344 | `3d4820155be397a6f573a0ee3b4245d88329800a` | `4594c4fde47e159ec2bc359e14c3163a9348e09d0e1d7a4d3e4e2f08b113a8da` |

## 5. First genuine TUR54 hosted failure (retained, fixed without weakening guard)

Initial RC697 source SHA `3eae33c3432f61c426a148aa0b5b0f6fde2bab15` triggered real Ubuntu run `43848891904`, job `133236019144`, which completed **FAILURE** with 3034 tests attempted and **two existing RC655 preflight failures**: `test_no_private_data_directories` and `test_only_whitelisted_checkout_roots`. The new top-level `evidence/` directory violated the immutable allowlist and forbidden-roots policy. This directory was removed from the Public branch; its exact JSON blob is now stored in the sanctioned `docs/` directory. `tests/test_rc697_operational_evidence.py` was updated to read it from `docs/`; original RC655 guard and workflow filters/permissions remain untouched. The original failed run is not relabelled. The initial Windows run `43848891851`, job `133236019455`, also completed **FAILURE** with the same forbidden-root violation; it is preserved in the GitHub Actions run history.

Local corrected `PYTHONWARNINGS=error` RC697 30/30 PASS, compileall and AST PASS. The additional source contract `sanctioned_manifest_path` now explicitly rejects the forbidden `evidence/` root and pins the manifest to `docs/`; the existing RC655 preflight assertions were not modified. The next exact final source commit must independently trigger and pass new Ubuntu and Windows native full suites; earlier failures do not count as successful final-HEAD evidence.

Report itself and manifest/tests must be committed **before** the final safe source, so unmodified Ubuntu and Windows workflow `push.paths` both trigger on the exact last source commit. Final native run/job/step/full-log evidence is unknown when writing this report: record exact final SHA and all actual final-HEAD results **only after** completion, via a PR #7 conversation comment (no further source commit). Any failed final run is a real recorded failure, never a pass.

**Locks:** `FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED`. PR #7 Draft/open/unmerged, Public main and PR #1 unchanged, all five workflows and RC656 unchanged. Profit and live-ready status remain NOT TESTED / NO-GO.
