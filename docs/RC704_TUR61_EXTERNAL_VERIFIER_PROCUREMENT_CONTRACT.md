# TUR61 / RC704 — Independent-verifier evidence procurement; never self-authorize

**Date:** 2026-11-18 Europe/Istanbul. **Only Public:** ftmstr/Embasic-KriptoAI-Autopilot-Build, branch validation/rc654-pr1-rc653-combined-ci, OPEN/DRAFT/UNMERGED PR #7. **FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH=NO-GO.**

## Exact TUR60 baseline independently verified

Initial branch HEAD and PR #7 HEAD: c5a14e89eea8ff1d41c3914e6b08d8789768b3d5; 173 tree entries, no RC704 or later paths. Public main unchanged 0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471. PR #1 OPEN/DRAFT/UNMERGED at 710517be3b4a0a671458b6e6cad0261138d0b3b0; 18 unapproved PR #1 cases untouched.

Actual Ubuntu GitHub Actions run 44382073029, job 135076777223, and Windows run 44382073065, job 135076777097: both completed/success run AND job at the same exact prior SHA, 9/9 steps, original full independently retrieved decoded logs 530880 and 542507 characters, **3166/3166 unique PASS** including 18/18 RC703; Ubuntu "Ran 3166 tests in 12.507s; OK", Windows "Ran 3166 tests in 36.898s; OK"; zero FAIL/ERROR/skipped/ResourceWarning. Decoded readable job logs are **not** original RAW log bytes with provider-issued cryptographic signatures. Historic failed TUR58 Ubuntu run 44359929767 and Windows run 44359927103 remain failed; earlier failures also retained.

Protected five workflow Git blob SHA-1: 28fedf1e76f1d26247fcb1897c176bc3b7009808; d7a08e1935b060d31feca2e1ef8db4184268858c; 140264aaf07f3130a23606254f545b4ff77b1971; 254ac4f4ea821a05ee4730c3828d4de1b96a0e72; 1cd73e647401f75ae9a98f55d8adcd166a366fe3. Source import guard tests/test_guard.py c793e475afd4bb24bbb70c3b60728a4c89a2017e. RC655 preflight 74768b736b4356c580a45ade85f701363e6b4972; RC656 MAX_ENTRIES=32 snapshot 7db54362bb627b26f9be0c09bb958a8601c961a2. No forbidden top-level paths.

## Provider capabilities versus project-specific acquired evidence

**GitHub Actions job logs.** GitHub's job logs API returns a redirect to plain text file contents, not a signature over original complete RAW bytes (https://docs.github.com/en/rest/actions/workflow-jobs). Separate GitHub artifact attestations have their own subject and workflow permission requirements; they do not automatically sign full original job-log bytes (https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations). We cannot claim the required provider-issued full-log proof is obtainable from the documented job-log API alone.

**Sigstore Rekor v2.** Official clients documentation (https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md) describes TUF-backed trusted roots and warns initial Rekor v2 checkpoints were not witnessed pending a public witness network. The published verification API (https://pkg.go.dev/github.com/sigstore/rekor-tiles/v2/pkg/verify) exposes VerifyCheckpoint, VerifyWitnessedCheckpoint and VerifyConsistencyProofWithCheckpoints. Existence of this API is not possession of an independently witnessed *project-specific* checkpoint. Need actual signed old/new C2SP checkpoints, separately OOB authorized log and witness roots, independently held earlier root, proven inclusion and consistency. A log's key ID or signature bytes from the same caller are not OOB authorization.

**RC703 and RFC8032.** RFC8032 (https://www.rfc-editor.org/rfc/rfc8032), C2SP Signed Note (https://c2sp.org/signed-note@v1.0.0-rc.1) and timestamped cosignature (https://c2sp.org/tlog-cosignature@v1.0.1) provide signature mathematics. Existing RC703 is a useful experimental candidate mathematical verifier, NOT audited production cryptography or independently pinned owner/reviewer custody. No production decision may promote its math_valid result to trusted authority without genuine independently sourced OOB keys, external verifier review and temporal revocation.

**DynamoDB MRSC.** Official MRSC documentation confirms three-region strong reads and conditional single-item writes, versus MREC last-writer-wins, with MRSC transaction API limitations. https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html and https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-global-table-design.html . AWS announced added MRSC region support in September 2026: https://aws.amazon.com/about-aws/whats-new/2026/09/dynamodb-mrsc-additional-regions/ . Available features do not establish this project's live account, separate-admin IAM, multi-host anti-restore epoch/fence test or signed recipient ACK. AWS replication witness is not an independent Rekor signature witness.

## RC704 unique engineering deliverable

New safe_public_ci/ci_rc704_external_verifier_handoff.py is a bounded stdlib-only **provenance and evidence procurement contract**, not an untrusted proof-admission bypass. It constructs canonical SHA-256 domain-separated, nonce/challenge/audience-bound tasks scoped to the exact TUR60 public HEAD and genuine prior Ubuntu/Windows run+job IDs. Eight required roles have explicit independent provider, subject, issuer and acceptable-evidence definitions. Checksum identity does not prove who issued a receipt.

A separate quarantine function accepts only scoped *untrusted* receipt metadata to assist independent investigation; forged verified/authorized booleans, false source identity, cross-request nonce reuse, extra OOB-root fields, and wrong run/job binding are rejected. Even a matching claimed SHA-256 or different-looking administrator fingerprint leaves external_verified_count=0, AUTH=NO-GO and LIVE=DISABLED. **No credentials, cryptographic signing, network/IO, AWS writes, recipient ACK, live trading or fitting occur.** Source imports only hashlib,hmac,json,re, approved by unchanged import whitelist.

New tests/test_rc704_external_verifier_handoff.py has 16 focused tests for scope, exact baseline job binding, replay, nonce collision, role confusion, claimed provider signature and false authority. Local actual Python 3.13.5, PYTHONWARNINGS=error: **16/16 PASS**; AST PASS; compileall PASS. This proves only the offline software contract, not any genuine external service verification.

This initial procurement form binds the verified TUR60 baseline. New TUR61 final-HEAD run/job signatures must be independently acquired and verified in a future authorized external service workflow; never reuse an earlier job attestation as final-HEAD proof.

## All eight actual independent security proof gates remain 0/8 BLOCKED

1. Independent owner OOB Ed25519 root pin, role approval, separate key custody, delegation and revocation.
2. Separate-admin independent reviewer OOB Ed25519 root and explicit scoped signed approval.
3. Provider-origin signature over original RAW complete Ubuntu job-log bytes, bound to exact run/job/SHA.
4. Same provider-origin signature over original RAW complete Windows job-log bytes.
5. Independently authenticated non-rewindable time plus key revocation and rotation chronology.
6. Authenticated old/new Rekor signed checkpoint, independently pinned log and witness, different actual administrators, RFC6962 inclusion and consistency, externally held prior root.
7. Real deployed separately administered 3-region MRSC/equivalent durable CAS, >1 physical hosts, conditional-write race, persistent fencing and independently witnessed restore/rollback drill.
8. Authenticated remote recipient's idempotent ACK and actual lost-response recovery against externally owned service state.

No independent OOB principals, signed original RAW full logs, historically anchored witnessed checkpoints, real MRSC service or authenticated recipient ACK were acquired in this tour. Reading vendor docs and using hypothetical signatures cannot open any gate. **Production and real exchange access remain NO-GO.**

## Publication and CI proof procedure

Commit report, tests, then source LAST to trigger unchanged actual native Ubuntu and Windows path filters. Expected suite 3182 = TUR60 3166 + RC704 16, but DO NOT call final-HEAD PASS without complete real run/job SUCCESS (9/9 steps), and all 3182 unique PASS in independently fetched original complete decoded job logs. Verify exact Git blob SHA-1, raw UTF-8 SHA-256 and source report bytes; preserve all historical failures. Record evidence in a comment on existing Draft PR #7. No merge, release, deploy, private repository, real trade or profitability claim.

**FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH=NO-GO.**
