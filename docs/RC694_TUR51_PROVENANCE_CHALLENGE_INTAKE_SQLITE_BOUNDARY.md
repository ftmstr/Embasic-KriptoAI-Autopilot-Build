# KriptoAI Autopilot — TUR51 / RC694: independent evidence-intake challenge and local SQLite anti-replay limits

**Date:** 2026-11-14 (Europe/Istanbul). **Only repository:** Public `ftmstr/Embasic-KriptoAI-Autopilot-Build`. **Only branch:** `validation/rc654-pr1-rc653-combined-ci`. **Only pull request:** open, unmerged **Draft PR #7**. **Never** deploy, merge, use Private repositories, place exchange orders, perform model fitting, or claim a +20% return. **Immutable locks:** `FINAL=SEALED`, `LIVE=DISABLED`, `SINGLE_FIT=UNUSED`, `+20% NET=NOT_TESTED`.

## 1. TUR50 closeout: independent genuine hosted evidence

The final TUR50/RC693 source SHA **`f1d9be58b60000cd3a632107135f8f2a3394eaa0`** matched the Public validation branch **exactly** (`compare=identical`, ahead/behind=0). Before starting TUR51, there was no TUR51/RC694+ file (142-tree-entry baseline). PR #7 was open, draft and unmerged. TUR50 Windows had already passed, while Ubuntu had previously been queued; we **did not** count the queued state as a success. The **same Ubuntu job** later completed on the same exact source SHA, with the following independent re-fetch of real run/job/steps/entire log:

| Platform | GitHub Actions run / job | Run + job / steps | Original complete job log | Distinct PASS / RC693 | Test footer |
|---|---|---|---:|---|---|
| Ubuntu | [43618364541](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43618364541) / `132518304326` | `completed/success`, **9/9 actual steps SUCCESS** | **467,076 characters** | **2804/2804**, 96 RC693 | `Ran 2804 tests in 12.439s`; `OK` |
| Windows | [43618364580](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43618364580) / `132518304357` | `completed/success`, **9/9 actual steps SUCCESS** | **478,376 characters** | **2804/2804**, 96 RC693 | `Ran 2804 tests in 33.639s`; `OK` |

Both jobs were `push`, attempt 1, original logs had **zero FAIL/ERROR/skipped/ResourceWarning**. TUR50 was closed by updating **only** Draft PR #7 metadata, without advancing the tested SHA. The prior eight genuine external-trust gates remain **0/8 BLOCKED**, irrespective of these excellent CI results.

Baseline source/test identity: RC693 source Git blob `0054e7d3824584a3df27638ccacba1f41fb2c400`, raw SHA-256 `47c8dec2a0f0090b097fe96746700d87e54ed31717b67d73b7fff30f07ea8f92`; RC693 test blob `ec5cc61276fb3e41ca6b5e1a4642858d4651fbad`, raw SHA-256 `32f9d50870f0189149c0361de079ae3f27463383df67f7ba77daf65d59d8778a`; prior TUR50 report blob `bbd461e034fb59248c7fb1e6ea4f0e56a2df8854`.

### Protected repository conditions

- Public `main` remains **`0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`**, with no merge, release or deployment.
- Approval-gated Draft PR #1 remains open, head **`710517be3b4a0a671458b6e6cad0261138d0b3b0`**. Its on-approval 18 tests are not imported or claimed accepted.
- Five GitHub workflow Git blob identities remain: RC652 `28fedf1e76f1d26247fcb1897c176bc3b7009808`, RC653 `d7a08e1935b060d31feca2e1ef8db4184268858c`, RC654 `140264aaf07f3130a23606254f545b4ff77b1971`, RC658 Windows `254ac4f4ea821a05ee4730c3828d4de1b96a0e72`, general synthetic CI `1cd73e647401f75ae9a98f55d8adcd166a366fe3`. The existing RC654/RC658 `push.paths` filter includes `safe_public_ci/**` and requires **writing the safe source last** to trigger both actual hosted jobs; DO NOT widen these filters or permissions.
- RC656 engine `safe_public_ci/snapshot_package.py` blob `7db54362bb627b26f9be0c09bb958a8601c961a2`, with **`MAX_ENTRIES=32`** fail-closed rejection; original bounded-partition test `tests/test_rc656_snapshot_package.py` blob `a204b529bb7cd9fa29a9a59c8e0a81c1b96ddf05`, unchanged. The extra TUR51 source/test/report are additive, not a relaxation of archive limits.
- Historical first FAILED TUR47 Ubuntu run `43495951082`, Windows run `43495950963` and first FAILED TUR42 Ubuntu `43266074902`, Windows `43266074901` remain recorded as failures, not retroactively relabelled.

## 2. Why TUR51 is not merely another copy of previous tests

TUR50 identified eight **external proof acquisition gates**. TUR51 adds a prospective **one-time evidence-request and handoff transcript** with explicit type-specific scope binding. This is a distinct handoff control: owner/reviewer/provider/revocation/checkpoint/CAS/ACK may respond to a review challenge, but the local verifier must **not** take their caller-controlled key IDs, alleged signatures, challenge digest, role label, time or digest equality as authentication. The candidate's acceptance scope now includes **the exact Public repo, branch, source HEAD, epoch, challenge digest, the intended evidence gate, controller/domain, signed payload transcript digest, provider run/job/attempt, full-log digest, workflow digest, and claimed validity interval**.

There are still no actual real external challenges issued by an independent authority, no independently distributed owner/reviewer public keys, no true provider-issued signed entire-log attestation, no trusted revocation clock, no externally immutable Merkle checkpoint, no external production CAS, and no real exchange/recipient acknowledgement. Even an apparently perfect synthetic challenge response **must be quarantined**.

### Eight gates and exact independent evidence required

| Gate | Concrete external input REQUIRED before genuine authentication | Current capability |
|---|---|---|
| `owner_oob_key` | Offline-distributed owner Ed25519 public key/fingerprint; independently evidenced custody, scoped delegation and key revocation history | NOT ACQUIRED / BLOCKED |
| `reviewer_oob_key` | *Different administrator / trust domain*, out-of-band reviewer key provenance and independently verifiable signed approval of the same scope | NOT ACQUIRED / BLOCKED |
| `provider_ubuntu_attestation` | Provider-origin signed certificate of **exact** Ubuntu run/job/attempt, workflow digest, exact Public source SHA and **whole raw log bytes** | NOT ACQUIRED / BLOCKED |
| `provider_windows_attestation` | Equivalent **provider-origin**, independently verifiable signed complete Windows run/job/attempt/workflow/log certificate | NOT ACQUIRED / BLOCKED |
| `revocation_trusted_time` | Authenticated revocation/rotation authority, non-rewindable chronology and independently sourced clock | NOT ACQUIRED / BLOCKED |
| `external_immutable_checkpoint` | Third-party append-only signed checkpoint, public root history and independently validated Merkle inclusion/consistency against historical roots | NOT ACQUIRED / BLOCKED |
| `external_antirollback_cas` | Separate administrator and failure domain; monotonic cross-host CAS/fencing with stable disk/quorum state, anti-restore, split-brain and ABA controls | NOT ACQUIRED / BLOCKED |
| `remote_provider_ack` | Authenticated real recipient/exchange ACK and exact idempotency key reconciliation after lost response/crash; no order is submitted in this project phase | NOT ACQUIRED / BLOCKED |

The dependency DAG in `admission_dependencies()` explicitly orders required verification **but does not claim** any gate can currently be verified. Notably, a GitHub API job status or downloaded Actions full log is valuable **operational evidence**, not automatically an Ed25519-signed certificate issued by GitHub. Product integrations or independent attestations must be evaluated using **actual documented availability** before any gate can change.

## 3. Exact RC694 source boundary and attack classes

`safe_public_ci/ci_provenance_challenge_quarantine.py` is deliberately pure: allowed source imports **exactly** `hashlib`, `hmac`, `re`; no direct dynamic `open`, `eval`, `exec`, `compile`, `__import__` calls; no file, SQLite, network, credential, HSM, API or trading access. The source accepts a tightly bounded canonical **self-asserted** proof-request bundle with eight precisely ordered receipts, provider job/run pair binding, claimed Ed25519 signature hex **format only**, strict receipt transcript (typed length-prefixed SHA-256), challenge nonce digest, claimed issued/expiry/revocation, self-reported checkpoint and ephemeral local outbox/fence. It *rejects* any attempted promotion of `claimed_verified`, `origin`, independently anchored checkpoint, external CAS, remote ACK, fitted status, authenticated status, live or release flag.

An attacker can fabricate the same valid hashes, challenge and eight apparently distinct controller/domain labels. Those names are **not independent identities**. The canonical digest only establishes equality of caller-controlled bytes, not authenticity. An attacker can write a syntactically valid claimed signature but cannot present a real independently checked public key through this module. Formally the result keeps `verified_external_gates=0`, `authenticated=false`, `release_ready=false`, `live_trading_allowed=false`, `single_fit_used=false`, `net20_tested=false`.

`compare_intakes()` labels distinct same-scope and different-scope disagreements: purported source fork, challenge replay/split, epoch/clock fork, checkpoint/root split, provider/role receipt change, duplicate nonce/ABA local generation fork and local CAS fork. These classifications are **claims**, not external adjudications of identity, authority, timestamp or causal ordering.

### Local tests and exact file identity before GitHub upload

Python **3.13.5** was tested with `PYTHONWARNINGS=error` using `python3 -m unittest discover -s .../tests -p 'test_rc694*.py' -q`, including from `/tmp` with **no** `PYTHONPATH`; **124/124 PASS**. `compileall -q safe_public_ci tests` passed, and AST confirmed exactly `hashlib/hmac/re` imports with zero banned dynamic direct calls. The test breakdown is 28 standalone behavior/contract checks, **80 independent per-gate hostile mutations (10 distinct attacks each across all 8 gates)**, and **16 actual disposable SQLite process/thread/crash/rollback tests**. Initial local test run passed but surfaced SQLite connection finalization ResourceWarnings; fixed explicit SQL connection closes and retested under `PYTHONWARNINGS=error` **124/124 with no warnings**, before uploading anything. No initial hosted failure is invented.

| File | Exact Git blob SHA-1 of tested bytes | Raw UTF-8 SHA-256 | Bytes |
|---|---|---|---:|
| `safe_public_ci/ci_provenance_challenge_quarantine.py` | `035cd407abc4b48aad55d643f5fd5b56c78b09a2` | `3753a2eea0b7e3bf4898d4cc84047be39e09f0e7e37e7a01b14ad8744603195c` | 12,502 |
| `tests/test_rc694_provenance_challenge_sqlite.py` | `e64bf286d60661042232905ef8fafd318aa0a845` | `a0f9bf7baa04f9f2c66b5501c2cc35e3bfe6d8411b80903bd80190f48222aad3` | 19,892 |

The Markdown report has its own Git SHA-1/SHA-256 computed before committing; it is written *before* the source to preserve exact hosted final SHA. A subsequent **PR metadata-only** addendum must carry the actual final Ubuntu/Windows run/job/9-step/full-log proof; this report deliberately cannot predict future hosted results.

## 4. Real SQLite failure-domain audit (TESTS ONLY)

The 16 test-only SQLite cases instantiate `PRAGMA synchronous=FULL`, `journal_mode=DELETE`, `BEGIN IMMEDIATE`, an UNUSED challenge, an atomic state/generation/fence update and same-COMMIT single unique PENDING outbox row. Two independently spawned Python child processes (using the Public source directory derived from `__file__` so no `PYTHONPATH` is needed) contend for the **same one local SQLite file**: exactly one commits, the other receives STALE. Three local threads have the same behavior. Real `os._exit(71)` **before COMMIT** leaves the challenge UNUSED; `os._exit(72)` **after COMMIT but before ACK** preserves a PENDING outbox and denies replay.

The counterexamples are equally important: **two disconnected SQLite clones** each independently commit a winner for the same purported challenge; a privileged operator who restores a backed-up DB can rewind spent challenge status and generation/fence, then replay a different claimed receipt; a privileged UPDATE of PENDING to ACKED is not any authentic remote acknowledgement. The database never gives a multi-host linearizability proof, an independent anti-rollback root or a power-loss recovery guarantee. A local nonce/challenge is not proven to have been issued by an independent authority. **No production app or trading connector integrates this test fixture.**

## 5. TUR51 gate to close this report and proceed

Commit in order **report → tests → offline safe source** on the existing Public validation branch **only**. Re-fetch each file from GitHub at the exact final SHA and verify Git blob SHA-1, raw SHA-256, protected workflow/RC656 SHA invariants and Draft PR #7. For that exact SHA, require **actual** newly triggered native Ubuntu RC654 and Windows RC658 GitHub Actions: each run/job `completed/success`, all **9/9 real steps** completed/success, and an independently fetched complete original verbose job log showing **2928 distinct passing tests (2804 prior +124 new)**, including all 124 new RC694, footer `Ran 2928 tests` and `OK`, without FAIL/ERROR/skipped/ResourceWarning. No `queued`/`in_progress` run may be called PASS. Any hosted failure remains on record, and the test-only problem is fixed fail-closed and revalidated against a **new final SHA**. Only *after* complete native proof, update PR metadata, not the passing code HEAD.

**No authority promotion even if those CI checks pass:** eight real independent external proof families are still missing, **0/8 BLOCKED**; no authenticated provider signed receipts, genuine Ed25519 authorization, verified long-lived CAS, external checkpoint, live order, fitted model or financial return has been demonstrated.
