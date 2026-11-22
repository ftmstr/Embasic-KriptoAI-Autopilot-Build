# KriptoAI Autopilot — TUR63 / RC706: Real GitHub workflow-byte capability audit

**19 November 2026 • PUBLIC-only** `ftmstr/Embasic-KriptoAI-Autopilot-Build`, branch `validation/rc654-pr1-rc653-combined-ci`, existing PR #7 OPEN/DRAFT/UNMERGED. **FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH=NO-GO.**

## Independently verified starting baseline

TUR62 Public validation branch HEAD and PR #7 exact SHA **`83c45062e58c94d033621fecf40d23e3316a9811`**, 179 repository tree entries, no TUR63/RC706 or later paths. Public main `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`; PR #1 open/draft/unmerged head `710517be3b4a0a671458b6e6cad0261138d0b3b0`.

Prior native Ubuntu run `44571231345`, job `135726515869`, and Windows run `44571231356`, job `135726515350`, each run/job completed/success, **9/9 real CI steps** at exact prior SHA. Entire original downloaded decoded logs: Ubuntu **536227 characters**, **3194/3194 distinct PASS**, **12 RC705**, `Ran 3194 tests in 21.775s; OK`; Windows **547874 characters**, **3194/3194 distinct PASS**, **12 RC705**, `Ran 3194 tests in 39.307s; OK`; zero FAIL/ERROR/skipped/ResourceWarning. Historical first failed TUR58 Ubuntu `44359929767` / Windows `44359927103` still completed/failure; all other historical failures retained.

**Immutable protected blobs:** five workflows: `28fedf1e76f1d26247fcb1897c176bc3b7009808`, `d7a08e1935b060d31feca2e1ef8db4184268858c`, `140264aaf07f3130a23606254f545b4ff77b1971`, `254ac4f4ea821a05ee4730c3828d4de1b96a0e72`, `1cd73e647401f75ae9a98f55d8adcd166a366fe3`. Import guard `c793e475afd4bb24bbb70c3b60728a4c89a2017e`, RC655 `74768b736b4356c580a45ade85f701363e6b4972`, RC656 MAX_ENTRIES=32 `7db54362bb627b26f9be0c09bb958a8601c961a2` remain unchanged. No forbidden top-level roots.

## Actually retrieved provider capability, not hypothetical authority

Read the **exact full workflow file bytes** from GitHub at TUR62 SHA and independently computed Git object blob SHA-1:
- `.github/workflows/rc654-validation-synthetic.yml`, **1364 UTF-8 bytes**, blob `140264aaf07f3130a23606254f545b4ff77b1971`.
- `.github/workflows/rc658-windows-synthetic.yml`, **1350 UTF-8 bytes**, blob `254ac4f4ea821a05ee4730c3828d4de1b96a0e72`.

Both have top-level and job-level `permissions: contents: read`, no `id-token: write`, `attestations: write`, or `actions/attest` step, and pinned CPython 3.13.5 with `SAFE_TEST_ONLY=1`. Separate real GitHub artifact-list API requests found **zero artifacts** on both TUR62 runs. This does not prove there are no external attestations elsewhere.

GitHub [job-log download API](https://docs.github.com/en/rest/actions/workflow-jobs) redirects to **plaintext**. The separate [artifact attestation mechanism](https://github.com/actions/attest) signs a specified artifact name/digest; [repository attestations lookup](https://docs.github.com/en/rest/repos/attestations) is subject-digest keyed, NOT a provider signature over original RAW complete job-log bytes. The strict Ubuntu and Windows provider-signed original RAW full-log gates remain **BLOCKED**. Vendor capabilities are not actual user-specific trust receipts.

[Sigstore Rekor Tiles client instructions](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md) mention its **initial** v2 launch was unwitnessed; that is not a claim of permanent or current lack of witnesses. The [independent verifier API](https://pkg.go.dev/github.com/sigstore/rekor-tiles/v2/pkg/verify) requires actual authentic externally anchored historical log checkpoint, separate-administrator OOB pinned witness, and RFC6962 consistency/inclusion data. No project-specific independent witness or owner/reviewer trust roots acquired. Experimental RC703 Ed25519 signature mathematics is NOT audited production cryptography.

[AWS MRSC design](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-global-table-design.html) supports three-Region strongly consistent reads and conditional writes; [PITR restore](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/pointintimerecovery_restores.html) creates a NEW table. No actual separate-admin AWS account, IAM, provisioned MRSC table, 2+ physical hosts, durable fenced CAS race, independently audited restore drill or authenticated remote recipient ACK exists for this project.

## New engineering deliverable: immutable observed-capability audit, not another fictitious proof

New `safe_public_ci/ci_rc706_actual_workflow_capability.py` verifies the **exact protected real workflow UTF-8 bytes** against Git blob SHA-1, then binds pre-observed TUR62 run/job/SHA, 9/9 real steps, 3194 distinct PASS, 12 RC705 passes and zero run artifacts. It records two workflow SHA-256 values and emits an actionable, canonical domain-separated SHA-256 acquisition handoff for each of the 8 external roles. A changed workflow, elevated permissions, fabricated job count or false source SHA fails closed. The new source is **stdlib only (`hashlib,hmac,json,re`) and no IO/network/cloud/trading/fit**; inputs are previously retrieved file text and job metadata, not provider-signed receipts.

`tests/test_rc706_actual_workflow_capability.py`: **11 focused checks that directly open the actual unchanged checked-out workflow files**, enforce their exact Git blob hash, reject changed YAML, false source/run/job, inflated test counts, fake job success, and injected owner-key claims; verify all 8 real external proof gates remain BLOCKED. Local actual **Python 3.13.5 `PYTHONWARNINGS=error` 11/11 PASS**, AST and compileall PASS.

### Eight real independent provider/operator actions (all BLOCKED)

1. Independently OOB-pin authorized owner Ed25519 key/role/delegation/revocation.
2. Obtain separate-administrator OOB-pinned reviewer key and signed approval.
3. Ask **GitHub as original provider** for a signature over ORIGINAL RAW complete Ubuntu log, bound to exact SHA/run/job; plaintext/artifact subject is insufficient.
4. Same provider-issued original complete RAW Windows job-log signature.
5. Acquire independently authenticated non-rewindable trusted time and key revocation/rotation history.
6. Authenticate independently anchored older/newer Rekor log-signed checkpoints, distinct actually independent witnessed cosignature and RFC6962 consistency.
7. Provision separate-admin real three-Region MRSC and independently observe two-host conditional CAS + anti-restore epoch/fence reenrollment.
8. Obtain independently authenticated remote recipient idempotent ACK and actual lost-response reconciliation.

**External independent trust: 0/8 BLOCKED.** No real OOB key custody, GitHub-provider RAW log signature, externally anchored witnessed checkpoint, live MRSC race or recipient ACK. Workflow byte identity is not a provider signature.

## Publication/CI acceptance

Report first, then tests, source LAST to trigger the two existing, **unchanged** native workflows at the exact final HEAD. Expected regression suite **3205** (=3194+11), not PASS unless actual final-HEAD Ubuntu **and** Windows CI both show completed/success 9/9 steps and 3205 unique PASS in complete original job logs. Exact file Git SHA-1/SHA-256 required; final PR #7 comment after verified CI; no merge, deploy, live trading, model fit or profit claim.

**FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH=NO-GO.**
