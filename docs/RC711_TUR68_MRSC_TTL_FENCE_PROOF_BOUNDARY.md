# KriptoAI Autopilot — TUR68 / RC711: MRSC TTL is not fencing authority

**2026-11-20 (Europe/Istanbul). Public-only** `ftmstr/Embasic-KriptoAI-Autopilot-Build`, `validation/rc654-pr1-rc653-combined-ci`, existing PR #7 OPEN / DRAFT / UNMERGED. **FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH/LIVE NO-GO.**

## Exact TUR67 baseline independently retrieved before work

- Validation branch and PR #7 HEAD both **`4d631593221b3537b1d0bdad2c5cfaaccdd57480`**; 194 Git tree entries, no TUR68/RC711 or later files. Public main **`0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`**; PR #1 OPEN/DRAFT/UNMERGED **`710517be3b4a0a671458b6e6cad0261138d0b3b0`**.
- Genuine native GitHub Actions at exact previous SHA: Ubuntu [run 44709467778](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/44709467778), job `136197181580`, and Windows [run 44709467752](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/44709467752), job `136197179925`: both run and job `completed/success`, `push`, attempt 1, **9/9 genuine steps**. Entire original **GitHub-decoded readable** job logs retrieved anew, **3226/3226 unique PASS on EACH** including **4/4 RC710**; `Ran 3226 tests in 16.458s` / `28.446s`, `OK`. There are 3225 ordinary unique `... ok` cases plus one pre-existing RC656 two-line long-description case. Zero FAIL/ERROR/SKIP/ResourceWarning. **Readable GitHub logs are NOT GitHub-provider cryptographically signed ORIGINAL RAW COMPLETE logs.**
- Immutable blobs: 5 workflows rc652 `28fedf1e76f1d26247fcb1897c176bc3b7009808`, rc653 `d7a08e1935b060d31feca2e1ef8db4184268858c`, rc654 `140264aaf07f3130a23606254f545b4ff77b1971`, rc658 `254ac4f4ea821a05ee4730c3828d4de1b96a0e72`, synthetic-ci `1cd73e647401f75ae9a98f55d8adcd166a366fe3`; import whitelist `tests/test_guard.py` `c793e475afd4bb24bbb70c3b60728a4c89a2017e`, RC655 `74768b736b4356c580a45ade85f701363e6b4972`, RC656 snapshot `MAX_ENTRIES=32` `7db54362bb627b26f9be0c09bb958a8601c961a2`. All unchanged; no forbidden roots, workflow, main or PR #1 mutation. Historic failures retained.

## New meaningful AWS provider limitation, distinct from RC710

Official AWS [How DynamoDB global tables work](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html) **explicitly prohibits Time to Live (TTL) on MRSC global tables**. The official [DynamoDB TTL guide](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html) explains that even on a supported table, expired items may only be deleted asynchronously, typically in the following days. Neither an alleged MRSC TTL setting nor an expired/deleted TTL item is cryptographic proof of an authorized lock/fence release. This complements, rather than repeats, RC710's separate PITR populated-to-MRSC migration prohibition and RC709's Rekor-v2 integrated-time-zero quarantine.

GitHub's [job-log REST endpoint](https://docs.github.com/en/rest/actions/workflow-jobs) provides redirected plain text, not a documented provider signature covering the exact ORIGINAL RAW COMPLETE job log. GitHub artifact attestation is not that RAW signature. No GitHub Support case or Community discussion was submitted; no OOB Ed25519 owner/reviewer, genuine RFC3161 signed time, authenticated historical witnessed C2SP RFC6962 checkpoint, AWS three-region separate-admin two-host durable CAS/antirestore, migration verification, or authenticated remote recipient ACK was obtained. Such unavailable proof must not be simulated or replaced by vendor documentation or caller-provided Boolean fields.

## RC711 targeted improvement and local proof

New `safe_public_ci/ci_rc711_mrsc_ttl_fence_quarantine.py` is a pure read-only Python stdlib **candidate policy quarantine** pinned to exact real TUR67 source SHA and Ubuntu/Windows run/job. It:
- Rejects any candidate claiming MRSC TTL is enabled/supported, automatic TTL expiry releases fencing authority, or observed expiration is proof of a safe lock release;
- Rejects false run/job/head SHA, unknown service mode, malformed table identity, invalid expiry-candidate digest, self-supplied timestamp/CAS/admin/ACK authentication;
- Allows only candidate metadata with TTL disabled and optional **untrusted** clock or RFC3161 digest; returns **always** 0/8 independent gates, NO-GO/SEALED/DISABLED, a domain-separated SHA-256 **request digest only**, never a signature or trusted timestamp;
- Performs **no AWS/cloud/API/network/IO/order/model fit**.

`tests/test_rc711_mrsc_ttl_fence_quarantine.py`: only **four narrowly targeted checks** (exact hosted job identity, TTL/fencing downgrade rejection, time/authority forgery rejection, AST/import whitelist). Local actual **CPython 3.13.5**, `PYTHONWARNINGS=error`, **4/4 PASS**, AST and `compileall` PASS.

Local exact new bytes, MUST re-read from GitHub after publication:
- Source blob Git SHA-1 `4ab80a2318775fda97755ad93a5da2733b156257`, SHA-256 `7f5b33d75e12be4e735b55fd2ecef618f4f00a846d1cfb46a8a42ce14d708593`.
- Tests blob Git SHA-1 `d82058b93373a7a0d0af1b3b2d2762c1c4f9ca23`, SHA-256 `e12fbc6a1ac304c870bdbe28b903f02beb348ea66f59229de4913c23677573f2`.

**Expected** after final public source change: same exact final HEAD, real Ubuntu and Windows job `completed/success`, real 9/9 steps and **3230/3230 unique PASS** (=3226+4) in complete original GitHub-decoded logs. These are expectations until independently verified; plain text does not satisfy the provider-signed RAW gate.

## Immutable trust and release result

The eight independent gates remain **0/8 VERIFIED; 8/8 BLOCKED**: out-of-band owner and independent reviewer Ed25519 authorities; GitHub-provider-signed ORIGINAL RAW full Ubuntu and Windows logs; independently signed time and revocation; authenticated witnessed historical Rekor C2SP/RFC6962; separate-admin actual 3-Region DynamoDB MRSC multi-host durable fence/CAS and anti-restore; independently authenticated recipient idempotent ACK. RC703 Ed25519 candidate equations are not audited production crypto. **No merge, deploy, model fitting, live trading or +20% profit claim. FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH/LIVE NO-GO.**
