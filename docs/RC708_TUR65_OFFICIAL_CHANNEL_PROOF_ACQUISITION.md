# KriptoAI Autopilot — TUR65 / RC708: GitHub official-channel constrained external-proof procurement

**Date:** 2026-11-20 (Europe/Istanbul). **Public only:** repository `ftmstr/Embasic-KriptoAI-Autopilot-Build`, branch `validation/rc654-pr1-rc653-combined-ci`, PR #7 OPEN/DRAFT/UNMERGED. **FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH=NO-GO.**

## Independently verified TUR64 baseline before changes

Public validation branch and PR #7 both exact final SHA `f7cb5328ac1d7c83ab36744e6f83516f524a6881`, 185 entries in the Git tree, no RC708/TUR65 or later. Public main `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`; PR #1 OPEN/DRAFT/UNMERGED at `710517be3b4a0a671458b6e6cad0261138d0b3b0`.

- Ubuntu exact-SHA push attempt 1 run [44611783408](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/44611783408), job `135870006293`: run and job completed/success, **9/9 real steps**, full original GitHub-*decoded* log `Ran 3212 tests in 10.866s`, `OK`, **3212/3212 distinct PASS including 7/7 RC707**.
- Windows exact-SHA push attempt 1 run [44611783309](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/44611783309), job `135870006799`: run and job completed/success, **9/9 real steps**, full original GitHub-*decoded* log `Ran 3212 tests in 42.644s`, `OK`, **3212/3212 distinct PASS including 7/7 RC707**.
- One older RC656 test description is split over two log lines: 3211 regular distinct PASS rows plus that one split-line case = 3212 total. Zero FAIL, ERROR, SKIP or ResourceWarning observed.
- Five immutable workflow blob SHA-1 in order rc652,rc653,rc654,rc658,synthetic-ci: `28fedf1e76f1d26247fcb1897c176bc3b7009808`, `d7a08e1935b060d31feca2e1ef8db4184268858c`, `140264aaf07f3130a23606254f545b4ff77b1971`, `254ac4f4ea821a05ee4730c3828d4de1b96a0e72`, `1cd73e647401f75ae9a98f55d8adcd166a366fe3`. Import whitelist guard blob `c793e475afd4bb24bbb70c3b60728a4c89a2017e`. RC655 forbidden roots and RC656 `MAX_ENTRIES=32` unchanged.
- Historic TUR58 Ubuntu run `44359929767` and Windows run `44359927103` remain completed/**failure**, SHA `888444e6838c627dd59507456ae910f2d29e4bed`.

## Actual external capability evidence: no authority acquired

GitHub's official [job-log REST API](https://docs.github.com/en/rest/actions/workflow-jobs) explicitly documents a **temporary redirect to plain text**. [Artifact attestation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations) concerns a named artifact subject/digest; it is not a provider-origin signature over **ORIGINAL RAW COMPLETE job-log bytes**. No documented original RAW full-log provider-signing endpoint was identified and no signature or original RAW byte provenance was obtained.

**New operational finding:** the [official GitHub Support ticket instructions](https://docs.github.com/en/support/contacting-github-support/creating-a-support-ticket) distinguish access based on account plan. An eligible paid GitHub account may file technical questions through [GitHub Support](https://support.github.com/), whereas GitHub Free users generally use [GitHub Community](https://github.com/orgs/community/discussions) for technical questions and direct Support for account/security/abuse issues. The owner's actual GitHub plan is UNKNOWN; do not claim either route is available for that account. No ticket or public Community post was submitted. A forum reply or staff message is not an authenticated cryptographic provider-issued RAW log signature.

Rekor v2 [client witness guidance](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md) describes **initial-launch** unwitnessed status, not current project-authenticated witnesses. The required externally OOB-pinned historical C2SP checkpoints, witness cosignatures, RFC6962 consistency and independently authorized Ed25519 roots remain absent; RC703 math-only verifier is not audited production crypto.

[AWS MRSC](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html) supports three-Region strongly consistent conditional writes, but no actual separate-admin 2+ physical-host CAS race, independent durable anti-restore epoch/fence, or real recipient ACK was observed. [PITR restores to a NEW table](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/pointintimerecovery_restores.html); DynamoDB replication witness is not a cryptographic Rekor witness.

## TUR65 implementation: plan-aware official escalation, not further fabricated proof

New `safe_public_ci/ci_rc708_support_channel_handoff.py`: immutable **actual TUR64** run/job/commit/workflow subjects; generates ready-to-submit public-only inquiry for **paid_support** and **free_community** channels per OS. It asks for provider-issued signature binding exact ORIGINAL RAW complete log bytes to run, job, attempt, SHA and workflow, signing-key root, time/revocation, completeness and independent verification, or a formal *unsupported* answer. Its request SHA-256 is only a domain-separated hash of an **unsubmitted request**, never a signature. There is no network, credentials, support API, trading, model fit, cloud or filesystem I/O.

Incoming *untrusted answer classifications* (unsubmitted, user report, unauthenticated reply, documented unsupported, possible escalation) all preserve 0/8 and NO-GO; no caller-provided boolean may promote authority. No real GitHub account plan, case number, support reply, provider signature, OOB roots or external proof is claimed.

New `tests/test_rc708_support_channel_handoff.py`: **6 focused tests** covering exact actual TUR64 identities, plan ambiguity, strict RAW-not-plaintext/attestation, all reply classes fail-closed, wrong subjects and strict Python AST/import allowlist. Local CPython **3.13.5**, `PYTHONWARNINGS=error`: **6/6 PASS**, `compileall` and AST PASS. A local pre-publication constant typo was fixed before publication; no failing release commit was made.

Exact locally computed Git blob SHA-1 source `19a91a65b0b3addb708c121056e1597dea8b0316`, SHA-256 `8db70f41940870aeff6dba91b55e11a28e8587eef309c9bbe7770dcec637c3bf`; test blob `51c4e4c5f89a3ccca4d7896495b0f14a9fce87e7`, SHA-256 `89240886deab9b6ba276ac1196b704d26d5a4275a35c01ec3e93f32dedcadac6`. Recheck the actual GitHub readback bytes after publication; any mismatch invalidates local claims.

**Final-HEAD CI must not be claimed until observed:** real Ubuntu and Windows completed/success, 9/9 job steps and **3218/3218 distinct PASS** (3212+6) in both complete GitHub decoded job logs. Neither CI nor the readable job logs constitute original signed RAW log proof.

**Eight real external gates 0/8 VERIFIED / 8/8 BLOCKED:** owner OOB Ed25519; independently administered reviewer OOB Ed25519; provider signed ORIGINAL RAW Ubuntu complete log; equivalent Windows log; independent time/revocation; authenticated historical witnessed C2SP/RFC6962; actual separate-admin 3-Region MRSC multi-host fenced CAS/antirestore; independent authenticated recipient idempotent ACK.

**No merge/deploy/live trading/model fit/profit claim. FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH/LIVE NO-GO.**
