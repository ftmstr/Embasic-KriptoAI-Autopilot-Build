# KriptoAI Autopilot — TUR71 / RC714

Date: 2026-11-22 Europe/Istanbul. Only Public ftmstr/Embasic-KriptoAI-Autopilot-Build, validation/rc654-pr1-rc653-combined-ci. PR #7 stays OPEN / DRAFT / UNMERGED.

## Verified prior exact HEAD

Branch and PR #7 original SHA: 50341649ef69f87c2ea00bb97d1078dc916b9329. Tree: 203 entries; no TUR71 or later. Original full GitHub-decoded readable Ubuntu run 45005402691 / job 137155786669: 9/9 real steps, 3238/3238 distinct PASS, 4 RC713, 16.374s. Windows run 45005402581 / job 137155786246: 9/9 real steps, 3238/3238 distinct PASS, 4 RC713, 38.831s. Both completed/success on exact SHA; no FAIL, ERROR, SKIP, ResourceWarning. Each 3237 ordinary and one preexisting wrapped RC656 case. These readable plaintext logs are NOT provider-signed ORIGINAL RAW logs. Both run artifact lists returned zero.

## New independently dated provider fact, correcting stale RC712/RC713 source contracts

Official AWS announcement of 2026-09-23: https://aws.amazon.com/about-aws/whats-new/2026/09/dynamodb-mrsc-additional-regions/
AWS developer guide update documented 2026-09-24: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DocumentHistory.html
Current region checklist: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-global-table-design.prescriptive-guidance.checklist-and-faq.html
MRSC now supports ANY three distinct Regions chosen from 15, including cross-continent. Previous RC712/RC713 hardcoded 3 isolated US/EU/AP sets, wrongly rejected valid configurations. Supported regions: us-east-1, us-east-2, us-west-2, ca-central-1, eu-west-1, eu-west-2, eu-west-3, eu-central-1, eu-north-1, eu-south-2, ap-northeast-1, ap-northeast-2, ap-northeast-3, ap-south-1, ap-southeast-1. Some old cached documentation or an October blog still carried superseded isolated-region descriptions; prefer explicit newer AWS release plus checklist.

## Precise fix without weakening the security gates

Correct both RC712 and RC713 to an identical allowlist of the 15 regions and exactly-three distinct-region rule; update the two preexisting suites to accept new 2026 regions and real cross-continent configurations, reject unsupported af-south-1, us-west-1, eu-central-2. No added synthetic test classes: all 3238 existing regression test cases remain. Preserve RC713 same-AWS-account and same-table-name restrictions; forbid MREC downgrade, fake admin / 2-host CAS / recipient ACK; RC712 keeps the telemetry-vs-remote-ACK distinction. RC709 zero-integrated-time, RC710 populated-PITR-to-MRSC, RC711 TTL/fencing unchanged.

## Protected Git objects and independent proof status

Workflow blobs rc652/rc653/rc654/rc658/synthetic: 28fedf1e76f1d26247fcb1897c176bc3b7009808 / d7a08e1935b060d31feca2e1ef8db4184268858c / 140264aaf07f3130a23606254f545b4ff77b1971 / 254ac4f4ea821a05ee4730c3828d4de1b96a0e72 / 1cd73e647401f75ae9a98f55d8adcd166a366fe3. tests/test_guard.py c793e475afd4bb24bbb70c3b60728a4c89a2017e. RC655 74768b736b4356c580a45ade85f701363e6b4972. RC656 snapshot 7db54362bb627b26f9be0c09bb958a8601c961a2, MAX_ENTRIES=32. Main 0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471; PR #1 710517be3b4a0a671458b6e6cad0261138d0b3b0 OPEN/DRAFT/UNMERGED. Historical failures unchanged.

No actual GitHub provider original signed RAW Ubuntu/Windows full logs, OOB owner and reviewer Ed25519, trusted RFC3161 time / historical Rekor C2SP witness, distinct IAM administrator held real 3-Region AWS MRSC multi-physical-host durable CAS and anti-restore, or external recipient authenticated idempotent ACK were acquired. No Support ticket or Community submission. Official job log API redirects to plaintext; artifact attestations bind artifact subjects, not full original job logs. Distinct region support is a catalog shape, NOT a real provider-authenticated table, and passing tests are NOT proof. All eight external gates still BLOCKED (0/8 verified); AUTH/LIVE NO-GO.

Required final check: exact Git SHA1/SHA256 byte readback for five changed paths; local Python 3.13.5 PYTHONWARNINGS=error, AST and compileall where accessible; genuine final-head Ubuntu/Windows full readable job logs, both 9/9 real steps and 3238/3238 PASS. No test result or commit success should be preclaimed.

FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED. No merge/deploy/live trading/model fit/profit claims.
