# KriptoAI Autopilot — TUR62 / RC705: External-provider proof-type firewall and immutable identity/fence requirements

**Date:** 2026-11-19 (Europe/Istanbul). **Only Public:** `ftmstr/Embasic-KriptoAI-Autopilot-Build`, `validation/rc654-pr1-rc653-combined-ci`, PR #7 OPEN / Draft / UNMERGED. **FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH=NO-GO.**

## Exact TUR61 baseline: independent verification, not self-report

Public validation branch and PR #7 both had SHA `b01a0544f828ec149178bf2b1eec62b573ae64c8`; tree 176 entries, no RC705 or later tour. Public main `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`, PR #1 OPEN/Draft/unmerged `710517be3b4a0a671458b6e6cad0261138d0b3b0`. Genuine Ubuntu run `44384407457`, job `135084924784`, and Windows run `44384407494`, job `135084924161`: exact same prior SHA, `completed/success`, attempt 1, 9/9 true job steps, full original decoded logs **533848** and **545481** characters, **3182/3182 distinct PASS on each**, **16/16 RC704**, zero FAIL/ERROR/skipped/ResourceWarnings. Ubuntu `Ran 3182 tests in 16.975s; OK`; Windows `Ran 3182 tests in 44.639s; OK`.

Existing genuine failed TUR58 Ubuntu `44359929767` / Windows `44359927103` remain `completed/failure`, as do all other historical failures. Original GitHub download is a readable CI observation, *not* a cryptographically provider-signed ORIGINAL RAW complete job log.

Five workflow Git blob SHA-1 unchanged: `28fedf1e76f1d26247fcb1897c176bc3b7009808`, `d7a08e1935b060d31feca2e1ef8db4184268858c`, `140264aaf07f3130a23606254f545b4ff77b1971`, `254ac4f4ea821a05ee4730c3828d4de1b96a0e72`, `1cd73e647401f75ae9a98f55d8adcd166a366fe3`. Import allowlist guard `tests/test_guard.py`: `c793e475afd4bb24bbb70c3b60728a4c89a2017e`; RC655 `74768b736b4356c580a45ade85f701363e6b4972`; RC656 `MAX_ENTRIES=32` module `7db54362bb627b26f9be0c09bb958a8601c961a2`.

## Verified provider capabilities — not acquired proof

**GitHub Actions, current actually configured workflows.** Read-only examination of `.github/workflows/rc654-validation-synthetic.yml` and `.github/workflows/rc658-windows-synthetic.yml` confirmed **only `contents: read` permissions**; neither workflow invokes an attestation action nor requests `id-token: write` or `attestations: write`. GitHub run artifact APIs for TUR61 Ubuntu and Windows returned **zero workflow artifacts**, not proof no artifact or proof could exist on a different service. Official REST endpoint [download job logs](https://docs.github.com/en/rest/actions/workflow-jobs) returns a redirect to a **plain-text file**, not an endpoint documented to issue a provider-signed RAW complete-log receipt. The [actions/attest](https://github.com/actions/attest) signature binds a **named artifact subject and digest**, not automatically the original RAW full workflow job log. The strict **provider-origin signed exact RAW full-log** gate remains BLOCKED for both OS. Merely adding a caller signature, local hash or artifact subject attestation would not satisfy that exact requirement. No workflow changes permitted.

**Sigstore/Rekor v2.** Official [Rekor Tiles client guidance](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md) states **the initial Rekor v2 launch did not have witnessed checkpoints** pending a public witness network. It is not evidence that witnessing remains unavailable at all times. The separate [Go verifier API](https://pkg.go.dev/github.com/sigstore/rekor-tiles/v2/pkg/verify) can check log signatures, independently witnessed checkpoints and historical consistency when appropriately provisioned. No current witnessed checkpoint for this project, no separately pinned log or witness key, no actual authenticated historical root, no independently verified owner/reviewer Ed25519 authority was obtained. Previous RC703 candidate-key Ed25519 equation checks are experimental, not audited production cryptography.

**DynamoDB MRSC.** Official [MRSC design](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-global-table-design.html) says strong-consistent reads and conditional writes evaluate the latest item version, MRSC requires **exactly three Regions** (3 replicas OR 2 replicas plus a DynamoDB replication witness) and has **no transaction APIs**. MREC last-writer-wins cannot substitute for cross-region durable CAS. A DynamoDB **replication witness is not** an independently pinned Rekor cryptographic witness. AWS [PITR restore](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/pointintimerecovery_restores.html) creates a **new table**; consequently a new ARN/epoch may not inherit the previously approved fence without separate-admin authenticated reenrollment. A caller-reported DescribeTable, matching ARN or higher counter is never a real multi-host/antirestore acceptance test. No AWS account, permission, table, write, multi-host race, restore drill or remote ACK was accessed.

**External owner/reviewer/time/recipient:** key fingerprints, synthetic signatures, claimed independent admins and local SHA records do not establish independent legal custody, trusted revocation, time, issuer identity or service side authenticated acknowledgements.

## TUR62 concrete new security change, not more synthetic PASS claims

New stdlib-only `safe_public_ci/ci_rc705_provider_proof_firewall.py` is a **provider-proof-type quarantine** that prevents accidental promotion of weaker evidence into stronger independent trust classes:

- Eight-gate immutable procurement matrix and documented provenance classification: readable GitHub job log vs artifact-subject attestation vs a provider-origin RAW-log signature candidate; log-signed Rekor checkpoint vs independently witnessed/historical checkpoint; AWS DescribeTable vs physically observed durable remote CAS/restore; recipient ACK vs reported ACK candidate.
- Binding of exact Public branch + TUR61 commit and genuine old Ubuntu/Windows run/job IDs. Source, challenge/nonce, declared role and expected proof type are strictly checked; any caller `claim_authorized=true`, `claim_provider_signed_raw_log=true` or independent-custody claim is **rejected**, even if an SHA-256 digest matches.
- Second unique fail-closed `classify_reported_restore` analyzes caller-reported table ARN, epoch/fence/generation/root/request identity. A changed DynamoDB table ARN is explicitly **NEW_RESTORED_TABLE_REQUIRES_DIFFERENT_ADMIN_REENROLLMENT**. A rolled-back fence or old snapshot is flagged, as is any unexpected state advance. A matching candidate state still cannot establish AWS identity or independent operator control.
- Results universally `external_gates_verified=0`, `AUTH=NO-GO`, `LIVE=DISABLED`, no real disk/network, AWS, crypto key generation, exchange, model fitting, profit testing or remote authenticated ACK. Existing import allowlist remains narrow: new source imports ONLY `hashlib,hmac,json,re`.

New `tests/test_rc705_provider_proof_firewall.py` has **12 focused regression checks** for proof-type downgrades, exact run/job scopes, cross-gate misclassification, nonce replay, witness/history confusion and restore identity/fence discontinuities. Local actual **Python 3.13.5 `PYTHONWARNINGS=error`: 12/12 PASS**, AST parse PASS, compileall PASS. These prove only implementation behaviour, **not** external provider availability or OOB trust.

Exact locally tested source: **10547 UTF-8 bytes**, Git blob SHA-1 `b4af3b90101c810d88f1820b103497238a4babef`, SHA-256 `130fe42e87f358fa19e4ba62a8b20bd272edffc3c5888cf70a4721baa46f97f6`.
Exact locally tested tests: **6755 UTF-8 bytes**, Git blob SHA-1 `f7be70964653778588b4f6497942644f6baf3464`, SHA-256 `f3c2e9fd09fdcb012c1c1053382742750d74feaeb1c6b8fa8380fbaeb6c3d473`.

## Practical owner/operator acquisition required before any gate can open

1. **Owner:** an independent custodial key ceremony, OOB pinned authorized Ed25519 root/delegation, signed scope/revocation. BLOCKED.
2. **Reviewer:** actually distinct legal/admin custodian, OOB key and scoped signed approval. BLOCKED.
3. **Ubuntu:** obtain provider-issued signature over **exact ORIGINAL RAW complete final-HEAD job log**, not an Actions API redirect, self-attested digest or build artifact attestation. Current documented endpoint/workflow offers no such proof. BLOCKED.
4. **Windows:** same distinct complete RAW job-log proof. BLOCKED.
5. **Time/revocation:** independent nonrewindable signed trusted time and key-revocation/rotation chronology. BLOCKED.
6. **Rekor:** OOB pin actual independent log/witness keys, externally held old checkpoint, independently verified signature and RFC6962 inclusion/consistency, actual different-admin witness. BLOCKED.
7. **Remote durable CAS:** separate-admin real AWS MRSC table configured across 3 Regions, two or more physical hosts, conditional-write race, restore/migration/rebase with externally held fence and independent auditor evidence. BLOCKED.
8. **Authenticated ACK:** recipient-owned, authenticated actual remote idempotent ACK tied to exact request and lost-response reconciliation. BLOCKED.

**No signed raw logs, no OOB custodian, no signed witnessed checkpoint, no cross-host AWS CAS, and no authenticated remote ACK were acquired. 0/8 independently verified.** Future work needs genuine operator/provider access instead of treating additional local tests as readiness.

## Release / publication protocol

Commit report first, then tests, then new `safe_public_ci` source **LAST** to trigger both unchanged workflows at the exact final SHA. Expected full suite = previous 3182 + 12 = **3194**; do not label native CI PASS until Ubuntu and Windows each independently show `completed/success`, 9/9 true steps and 3194 unique PASS in entire original job log. Verify exact-byte Git blob SHA-1 and UTF-8 SHA-256 of all three files; record final job IDs, source SHA and surviving historic failures in Draft PR #7. No merge, release, deploy or LIVE trading.

**FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH=NO-GO.**
