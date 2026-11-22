# KriptoAI Autopilot — TUR66 / RC709: Rekor v2 time-origin downgrade quarantine

**20 November 2026 (Europe/Istanbul). Public only:** `ftmstr/Embasic-KriptoAI-Autopilot-Build`, `validation/rc654-pr1-rc653-combined-ci`, PR #7 OPEN/DRAFT/UNMERGED. **FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH=NO-GO.**

## Independently reverified exact TUR65 baseline

At intake, branch and PR #7 HEAD both `c106a314fc8ba6a07eb90a1da68e613a857fb7b9`, 188 tree entries, no TUR66/RC709 or later. Public main `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`, PR #1 OPEN/DRAFT/UNMERGED SHA `710517be3b4a0a671458b6e6cad0261138d0b3b0`.

Original complete GitHub **decoded plaintext**, not GitHub-signed ORIGINAL RAW, job logs re-fetched:
- Ubuntu [run 44626964180](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/44626964180) / job `135923234434`: run/job completed/success, attempt 1, 9/9 real steps, **3218/3218 unique PASS** including 6/6 RC708; `Ran 3218 tests in 10.797s`, `OK`.
- Windows [run 44626964302](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/44626964302) / job `135923235552`: run/job completed/success, attempt 1, 9/9 real steps, **3218/3218 unique PASS** including 6/6 RC708; `Ran 3218 tests in 26.820s`, `OK`.
- Each decoded log contains 3217 single-line distinct PASS plus a previously existing RC656 test whose description and `... ok` are printed on adjacent lines. No FAIL/ERROR/SKIP/ResourceWarning in either.
- Exactly unchanged five protected workflow blob SHA-1 values (rc652,rc653,rc654,rc658,synthetic-ci): `28fedf1e76f1d26247fcb1897c176bc3b7009808`, `d7a08e1935b060d31feca2e1ef8db4184268858c`, `140264aaf07f3130a23606254f545b4ff77b1971`, `254ac4f4ea821a05ee4730c3828d4de1b96a0e72`, `1cd73e647401f75ae9a98f55d8adcd166a366fe3`. Import guard `tests/test_guard.py` blob `c793e475afd4bb24bbb70c3b60728a4c89a2017e`; RC655 preflight `74768b736b4356c580a45ade85f701363e6b4972`; RC656 MAX_ENTRIES=32 module `7db54362bb627b26f9be0c09bb958a8601c961a2`. No changed forbidden roots.
- Earlier failed runs including TUR58 Ubuntu `44359929767`, Windows `44359927103` remain failed. Native TUR65 Actions artifacts list API returned zero workflow artifacts for both runs; does not exclude unrelated external attestations.

## Actual independently documented provider risk: Rekor v2 zero integrated time

Official Sigstore [Rekor v2 CLIENTS.md](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md) states `TransparencyLogEntry.integrated_time` is always **0**, MUST be ignored, and a trustworthy time requires an independently verified RFC 3161 signed timestamp from an authorized TSA and its trusted roots. Future separately verified witnessed C2SP checkpoint signatures may provide an independently signed timestamp; a candidate witness value alone is not that evidence. Earlier RC701-708 addressed time as an external trust requirement, but had no narrow Rekor-v2-specific integer-zero quarantine.

Other hard constraints stay: [GitHub job log API](https://docs.github.com/en/rest/actions/workflow-jobs) issues redirects to plaintext, not documented signatures over EXACT ORIGINAL RAW COMPLETE full job log bytes. A generic [artifact attestation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations) cannot substitute. [GitHub Support](https://docs.github.com/en/support/contacting-github-support/creating-a-support-ticket) ticket availability depends on the owner's GitHub product, which was not checked; no support ticket or Community post was submitted. [AWS MRSC](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-global-table-design.html) requires three Regions, with real separate-admin multi-host CAS/anti-restore evidence; [PITR restores create a new table](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/pointintimerecovery_restores.html). No actual independent AWS provider proof or signed remote ACK was obtained.

## New scoped RC709 implementation

`safe_public_ci/ci_rc709_rekor_v2_time_boundary.py` is a pure stdlib, no-I/O evidence-candidate quarantine anchored to exact TUR65 HEAD and two genuine run/job IDs. Requires **integer 0** in Rekor v2 `integrated_time`; rejects nonzero, boolean, strings, cross-platform source/run/job mismatches, unsolicited extra fields and self-asserted time, witness or RAW-log authentication. RFC3161 or witnessed-C2SP timestamp materials, if ever presented, are represented solely by a lower-case SHA-256 *untrusted candidate digest*. Output always **0/8 BLOCKED**, not an origin, OOB signer, time or revocation verification. Domain-separated SHA-256 of request data is not a signature. No network, files, secrets, cloud, trading or model fit.

`tests/test_rc709_rekor_v2_time_boundary.py`: **4 focused tests** tied to actual TUR65 subjects and exact Rekor v2 behavior, forged external authority, malformed time and candidate types, and AST/import whitelist. Local CPython **3.13.5**, `PYTHONWARNINGS=error`: **4/4 PASS**; compileall + AST PASS.
- Module local Git blob SHA-1 `9ed85d43d993409fe00018b95c5bac2397b1f3ff`, SHA-256 `c177722001e5fa6e23305fa7ee104bb350ae283e0e7489bba9ff3a3f1a178f2f`.
- Test local Git blob SHA-1 `c6c8b99b614c5d01933b4f3535c168f26298a968`, SHA-256 `2d20fa4b8836e29667514871cf16acce3182107b9ce119b7021e016dc25efb22`.
- Exact GitHub byte readback MUST match both hashes. Expected new final-HEAD native CI is **3222 = 3218 + 4**, not a PASS claim until both actual Ubuntu/Windows runs/jobs complete/success, 9/9 steps and 3222 unique PASS in original complete decoded job logs.

**Eight external independent gates all BLOCKED:** distinct OOB owner/reviewer Ed25519, provider-original signed RAW Ubuntu and Windows complete job logs, independently signed time/revocation, witnessed authentic historical C2SP and RFC6962, separate-admin real MRSC three-region two-host fenced CAS and anti-restore, authenticated remote recipient idempotent ACK. **0/8 VERIFIED**. No merge, deployment, live trade, model training or return claim. **FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH/LIVE NO-GO.**
