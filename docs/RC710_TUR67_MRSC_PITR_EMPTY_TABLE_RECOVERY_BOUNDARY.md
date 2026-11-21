# KriptoAI Autopilot — TUR67 / RC710: Populated PITR to MRSC recovery and fencing identity gate

**Date 2026-11-20 Europe/Istanbul. PUBLIC-only** `ftmstr/Embasic-KriptoAI-Autopilot-Build`, branch `validation/rc654-pr1-rc653-combined-ci`, existing PR #7 OPEN / Draft / Unmerged. **FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH/LIVE NO-GO.**

## Verified exact TUR66 baseline before code publication

At intake, branch HEAD and PR #7 HEAD both `2904a2c0476e2aecb9d0e44ec852fddc9284d3ae`, 191 Git tree entries; no RC710/TUR67 or later tour. Public main `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`, PR #1 OPEN/Draft/Unmerged `710517be3b4a0a671458b6e6cad0261138d0b3b0`.

GitHub's full original **decoded plaintext**, not provider-origin signed ORIGINAL RAW, job logs were independently re-fetched:
- Ubuntu [run 44688542971](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/44688542971), job `136128558122`, final exact TUR66 SHA, attempt 1, completed/success run and job, 9/9 genuine steps, **3222/3222 unique PASS** including 4/4 RC709, `Ran 3222 tests in 17.335s`, `OK`.
- Windows [run 44688542996](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/44688542996), job `136128558909`, same SHA, attempt 1, completed/success run and job, 9/9 genuine steps, **3222/3222 unique PASS** including 4/4 RC709, `Ran 3222 tests in 39.003s`, `OK`.
- Each log has 3221 individually named ordinary `... ok` cases and one preexisting RC656 two-line case; zero FAIL, ERROR, SKIPPED or ResourceWarnings. Both TUR66 run artifact-list endpoints returned zero workflow artifacts; this does not prove no external artifacts exist.
- Protected blobs unchanged: workflows rc652 `28fedf1e76f1d26247fcb1897c176bc3b7009808`, rc653 `d7a08e1935b060d31feca2e1ef8db4184268858c`, rc654 `140264aaf07f3130a23606254f545b4ff77b1971`, rc658 `254ac4f4ea821a05ee4730c3828d4de1b96a0e72`, synthetic-ci `1cd73e647401f75ae9a98f55d8adcd166a366fe3`; import whitelist `tests/test_guard.py` `c793e475afd4bb24bbb70c3b60728a4c89a2017e`, RC655 preflight `74768b736b4356c580a45ade85f701363e6b4972`, RC656 snapshot with `MAX_ENTRIES=32` `7db54362bb627b26f9be0c09bb958a8601c961a2`. No forbidden root directories, workflow, main or PR #1 edits. Historical TUR58 failure run IDs `44359929767` and `44359927103` remain recorded as failed.

## Material official AWS recovery constraint newly identified

AWS DynamoDB's [Recovery by initiating a table restore](https://docs.aws.amazon.com/us_en/amazondynamodb/latest/developerguide/bp-pitr-recovery-table-restore.html) states that PITR restores produce a **new table**, not an in-place rollback. Crucially: a **populated** PITR-restored table from an MRSC source cannot directly be made into MRSC; converting a single-Region table to MRSC requires an **empty table**. AWS describes restoring data, creating a new empty MRSC table and copying data into it as a possible procedure, subject to proper provisioning. This requirement is separately documented under [How DynamoDB global tables work](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html) and [Creating MRSC global tables](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables.tutorial.html).

This is a distinct **operator recovery/anti-rollback risk**, beyond RC705's existing "PITR creates a new ARN" defense: an operator cannot claim the populated restored single-Region table is already an approved MRSC replica or inherit prior fence/epoch. A fresh MRSC destination has a distinct identity; data copying, re-enrolling a new epoch and fence, independent IAM signoff, cross-Region two-physical-host CAS, anti-restore and recipient ACK must each be re-established and authenticated. A monotonically increasing *caller-provided* counter is not external proof.

The GitHub [job log REST API](https://docs.github.com/en/rest/actions/workflow-jobs) returns a redirect to plaintext, NOT a GitHub-origin cryptographically signed exact ORIGINAL RAW complete job log. GitHub artifact attestation cannot be silently substituted. Rekor v2 [Sigstore guidance](https://docs.sigstore.dev/cosign/verifying/timestamps/) confirms time requires independently verified RFC 3161 TSA or appropriate genuinely witnessed signed checkpoint; RC709's `integrated_time=0` quarantine remains unchanged. No independent original provider-signed RAW logs, OOB Ed25519, verified C2SP historical RFC6962, AWS MRSC account/hosts, or remote ACK could be obtained through available read-only public evidence.

## New RC710 engineering deliverable

New `safe_public_ci/ci_rc710_mrsc_pitr_restore_boundary.py` is a **pure, stdlib-only offline candidate quarantine**, pinned to exact TUR66 HEAD and real Ubuntu/Windows run/job identities. It:
- Rejects a reported populated PITR-restored table being directly converted to MRSC, as contrary to the documented provider constraint.
- Requires distinct original, restored and prospective new-empty MRSC table ARN identities, and strictly increasing *claimed* epoch/fence counters while never regarding those claims as authority.
- Rejects self-asserted cloud provisioning, independent-admin reenrollment, physical two-host CAS, completed data migration or signed idempotent ACK.
- Returns only a bounded, domain-separated SHA-256 **untrusted request** digest with `0/8 BLOCKED`, `AUTH=NO-GO`, `LIVE=DISABLED` and no service or trading access.

`tests/test_rc710_mrsc_pitr_restore_boundary.py`: **4 focused regression cases**, not another synthetic workload: populated direct-conversion prohibition, correctly distinguished recovery path still unauthenticated, identity/epoch/false-authority rejection and exact prior hosted run/job plus AST/import guard. Local CPython **3.13.5**, `PYTHONWARNINGS=error`: **4/4 PASS**, AST and `compileall` PASS. No AWS calls, OOB key handling, filesystem I/O, network, live trading, model fit or remote requests.

Locally computed exact original bytes (must recheck GitHub readback before declaring publication valid):
- Source Git blob SHA-1 `5d55ad5fc4b4f9dbeb9bbafb8e09504ff187757b`; SHA-256 `72a70714d6a6c70d58e97351602dbcf0083ba8413d00d51aa9c834786b0d5d03`.
- Tests Git blob SHA-1 `c0fdf97f3cad2b1c86a7d709941f04904130a753`; SHA-256 `27795f1e84866a47e75a790c1eb53ca8cb37027f24467d4daba9e041e06cb923`.

For newly published final-HEAD CI, **expected** 3226 distinct PASS = 3222 baseline + 4 new checks; DO NOT claim actual final-HEAD PASS until Ubuntu **and** Windows show exact final commit, push attempt 1, run/job completed/success, 9/9 real job steps and full original decoded log individually counting **3226** unique cases including 4 RC710. The decoded logs are still not provider-signed RAW receipts. Preserve all past failures.

## Eight independent external gates: still 0/8 VERIFIED, 8/8 BLOCKED

Owner separately pinned OOB Ed25519, independent reviewer OOB Ed25519, provider-signature over exact ORIGINAL RAW complete Ubuntu log, same Windows log, independent trusted time and revocation, historical separately witnessed authenticated C2SP/RFC6962, separate-admin real three-Region MRSC durable multi-host CAS/anti-restore, and remote recipient independently authenticated idempotent ACK all remain **BLOCKED**.

No GitHub Support case/Community post submitted, no real AWS access. No merge, deployment, release, live order, model fitting or profit claim. **FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH/LIVE NO-GO.**
