# TUR57 / RC700 — Real RFC6962 consistency mathematics and inert MRSC CAS acceptance
Date: 2026-11-17. Only PUBLIC ftmstr/Embasic-KriptoAI-Autopilot-Build, validation/rc654-pr1-rc653-combined-ci, Draft/unmerged PR #7. FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH=NO-GO.

## TUR56 independently reverified
At start, exact branch and PR #7 HEAD: a33f2a0e8dd0ccca71667514c36df58cfcbd6fd1; 161 tree entries, no RC700 or later paths. PR #7 open/Draft/unmerged. Public main was 0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471. PR #1 remained open/Draft/unmerged at 710517be3b4a0a671458b6e6cad0261138d0b3b0; its 18 unapproved tests untouched.

Original-hosted Ubuntu run 44070320151, job 133994582439: same prior SHA, completed/success, attempt 1, 9/9 steps, complete decoded original log 516236 characters, 3082/3082 distinct PASS, 24 RC699 cases; Ran 3082 tests in 10.574s; OK. Windows run 44070320155, job 133994582520: same prior SHA, completed/success, 9/9 steps, complete log 527745 characters, 3082/3082 unique PASS, 24 RC699; Ran 3082 tests in 46.731s; OK. Both no FAIL/ERROR/skipped/ResourceWarning. These are true operational observations, NOT GitHub-signed raw-job-log attestations. Historical failed runs including TUR54 Ubuntu 43848891904 and Windows 43848891851, and earlier failures, are preserved unchanged.

Five protected workflow Git blob SHA-1: 28fedf1e76f1d26247fcb1897c176bc3b7009808, d7a08e1935b060d31feca2e1ef8db4184268858c, 140264aaf07f3130a23606254f545b4ff77b1971, 254ac4f4ea821a05ee4730c3828d4de1b96a0e72, 1cd73e647401f75ae9a98f55d8adcd166a366fe3. RC655 preflight Git blob 74768b736b4356c580a45ade85f701363e6b4972, RC656 snapshot module Git blob 7db54362bb627b26f9be0c09bb958a8601c961a2 with MAX_ENTRIES=32. No new forbidden top-level repository root.

## Sources, observed provider capabilities and limits
RFC6962 defines SHA256(0x00 || leaf) for a Merkle leaf, SHA256(0x01 || left || right) for an internal node, and PROOF(m,D[n]) for append-only consistency between two tree heads. This TUR57 module reconstructs both old and new tree roots from the RFC minimal consistency path, rather than asserting status or equality. It rejects forks, old_size > new_size, malformed/extra/missing paths and mismatched historical root. A mathematical success on CALLER-SUPPLIED old/new roots is NOT a source-authenticated or witness-signed checkpoint. Source: https://www.rfc-editor.org/rfc/rfc6962 (sections 2.1.2 and 2.1.3).

Sigstore/Rekor supports checkpoint signatures and independent witnesses. The Rekor V2 verify package offers signed/witnessed checkpoint verification, but tool availability does not mean a real signed log checkpoint, witnessed historical root, subject-specific inclusion proof or identity delegation exists for this repository. Require separately pinned log public-key trust root, signature verification over exact checkpoint bytes, independently pinned witness cosignature, a previously independently authenticated checkpoint, chronological non-rollback/consistency, and authorized subject signer. Sources: https://github.com/sigstore/architecture-docs/blob/main/rekor-spec.md and https://pkg.go.dev/github.com/sigstore/rekor-tiles/v2/pkg/verify . A Rekor SET promise or self-declared log/witness fingerprint cannot open the gate. A Rekor witness is distinct from an AWS replication witness.

AWS DynamoDB MRSC supports strongly consistent reads and conditional single-item writes, with exactly three Regions configured as three replicas or two replicas plus a replication witness; it does not support transaction APIs. MREC uses last-writer-wins and is NOT cross-region linearizable CAS. An MRSC design on its own does NOT establish different-administrator custody, immunity to privileged restore/ABA, authenticated fencing epoch or remote recipient ACK. AWS documentation notes that a restored MRSC table cannot be directly converted to MRSC with existing data. No cloud account, MRSC table, multi-host test, fencing, restore drill or AWS write was performed. Sources: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html ; https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/globaltables-security.html ; https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-pitr-recovery-table-restore.html .

Downloading a GitHub job log is not receiving a provider-origin signature over the RAW full job log. GitHub artifact attestations sign artifact subjects, not automatically job log bytes, and require separately authorized workflow actions/permissions (not changed here). Sources: https://docs.github.com/en/rest/actions/workflow-jobs ; https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations .

## Unique substantive integration boundary
New safe_public_ci/ci_rc700_consistency_fencing_boundary.py implements:
1. RFC6962 consistency-proof reconstruction with strict exact source SHA, old/new sizes, historical root, sibling order and distinct log/witness labels, returning only CONSISTENT_UNTRUSTED_ROOTS, with genuine external verified gates still ZERO.
2. An explicit acquisition checklist for independently authenticated checkpoint log signatures, independent witness signatures, historical root custody, time/revocation, identity and authorization.
3. A strict, no-network MRSC topology candidate validator rejecting MREC, invalid 3-region structure, unsupported transaction API, weak reads/nonconditional writes, and fake caller-provided external proof booleans.
4. An inert exact-state DynamoDB single-item UpdateItem plan: compare expected epoch, generation, fence and root, increment generation/fence by one, bind request ID and updated root; a strongly consistent GetItem reconciliation plan for lost response. NO WriteItem is invoked, no remote ACK is received, and no actual anti-restore protection is established.

New tests/test_rc700_consistency_fencing_boundary.py implements 24 targeted tests, independently generating RFC SUBPROOF paths for 1,176 old/new tree pairs (1–48 leaves), checking source-scope, tampering, forks and extra/missing sibling proofs, MRSC configurations, stale fence/CAS and fake trust promotions. Real local Python 3.13.5 PYTHONWARNINGS=error: 24/24 PASS; AST PASS; compileall PASS. Source stdlib-only, no IO, network, key generation, live trade or fitting.

Exact locally tested new source: 11389 UTF-8 bytes, Git blob SHA-1 30aa2e2da746354cf9be22ed91286f8e1df07091, raw SHA-256 c2a75bb766cab3733510ac1021c34eea743d5ca88c20a053d7c4bd5000f16ad8.
Exact locally tested new tests: 10935 UTF-8 bytes, Git blob SHA-1 5ab2ff85caca397f07356058f549927d369620f8, raw SHA-256 d0ebd3f0a03176e81547098bcf2e6e37032ef393e7561c9db60d7e5d692fd333.

## Eight external authentic-proof gates (0/8 real evidence)
1 Owner independent OOB Ed25519 key/custody/delegation — BLOCKED.
2 Reviewer separate OOB Ed25519 key/independent signoff — BLOCKED.
3 Ubuntu provider-signed ORIGINAL complete RAW job log — BLOCKED.
4 Windows provider-signed ORIGINAL complete RAW job log — BLOCKED.
5 Independent revocation chronology and non-rewindable trusted time — BLOCKED.
6 Signed historical+latest checkpoint, independent witness and authenticated RFC6962 consistency — BLOCKED.
7 Actually provisioned, distinct-admin durable multi-host CAS and observed anti-restore fencing — BLOCKED.
8 Authenticated remote idempotent recipient ACK and lost-response reconciliation — BLOCKED.

First report commit, then tests, then safe source LAST to trigger unmodified Ubuntu/Windows workflow path filters. Expected full suite 3106 = 3082+24; this is NOT a PASS claim until both independent final-HEAD run/job results and entire original logs confirm it. Record real final-HEAD evidence in PR #7 comment AFTER CI, without post-CI commits. All historical failures retained; never rewrite any source gate, RC655 rule or RC656 MAX_ENTRIES=32. No merge, release, deploy, order, training, private repo, or financial profit claim.

FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH=NO-GO.
