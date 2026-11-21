# KriptoAI Autopilot — TUR47 / RC690: cross-audience Merkle/checkpoint provenance quarantine and disposable SQLite CAS

**Scope:** Public `ftmstr/Embasic-KriptoAI-Autopilot-Build` only, existing `validation/rc654-pr1-rc653-combined-ci` branch and open/unmerged Draft PR #7. No Private repository, production release, exchange access, model fit, real key signing, workflow permissions, filters, or main changes.

## 1. Exact entry, prior run and immutable safeguards

- Entry TUR46/RC689 final HEAD `363c739b23616b4cf0a5282edb0ba0b0019c5846` matched Draft PR #7 HEAD and validation branch (`compare: identical`, ahead 0 / behind 0). No TUR47/RC690 or newer file existed at entry. The Public main HEAD `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471` was unchanged. Draft PR #1 remained separate at `710517be3b4a0a671458b6e6cad0261138d0b3b0`; its 18 approval-gated cases were NOT imported.
- Ubuntu TUR46 real hosted [run 43493426392](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43493426392), job `132120212859`: exact TUR46 HEAD, run/job completed/success, 9/9 actual steps success, original full log **386168 characters**, **2299/2299 unique `... ok` rows**, **96 RC689** rows, `Ran 2299 tests in 9.672s`, `OK`.
- Windows TUR46 real hosted [run 43493425934](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43493425934), job `132120212398`: same exact TUR46 HEAD, run/job completed/success, 9/9 actual steps success, original full log **396990 characters**, **2299/2299 unique `... ok` rows**, **96 RC689** rows, `Ran 2299 tests in 22.479s`, `OK`. No errors/skipped/ResourceWarnings on either native host.
- RC689 source Git blob `6630730d90fe33c059fa6097469eb03c43feb662`, raw SHA-256 `1f29743b41b10635a611a44dda34f9b03ab0501e67b94f3db8ea7306a440459d`; RC689 tests blob `1d36b6c132e94e881b5865dcf4c2af70bfbad8c3`, raw SHA-256 `99aeee75623e1e743f091de96e5f8bcee6080eb943dbec60816e707aa9afc4b4`. TUR46 report blob `c5f2a4b0391b52ce9896c55267f43f5ec9805c21` read back at exact HEAD.
- `safe_public_ci/snapshot_package.py` retained Git blob `7db54362bb627b26f9be0c09bb958a8601c961a2` and strict **`MAX_ENTRIES=32`**; `tests/test_rc656_snapshot_package.py` retained blob `a204b529bb7cd9fa29a9a59c8e0a81c1b96ddf05` with fail-closed oversized-package rejection and deterministic bounded batching. Five existing `.github/workflows/*.yml` blobs and triggers/permissions are immutable.
- Historic failed TUR42 Ubuntu #43266074902 and Windows #43266074901 stay explicitly archived as failures in the Draft PR. No historical success is repurposed as RC690 acceptance.

## 2. New source: explicit cross-audience claimed-evidence quarantine

`safe_public_ci/ci_audience_epoch_quarantine.py` is stdlib-only, bounded (128 leaves, finite schema and size limits) and pure. It imports **only `hashlib`, `hmac`, `re`**, with **zero** AST direct `open`, `compile`, `eval`, `exec`, `__import__` calls; no networking, filesystem, mutable persistent DB, private key or production-trading methods. The source defines:

- Typed canonical domain-separated digest over an untrusted claim. Rejects unexpected JSON-like fields, unsupported types, recursive and non-ASCII text, ambiguous bool-as-int, oversized data. This digest detects byte changes but does **NOT** establish who created or signed the record.
- Two self-described owner/reviewer Ed25519-looking 32-byte public-key hex fingerprints; no actual Ed25519 signature verification, possession proof or out-of-band key delivery. Requires advertised role/key/time windows but no authenticated clock or revocation authority. Prevents a caller from setting `signed_claim=True` or an anchor's `independent_auth=True` to bypass safeguards. Two distinct owner/reviewer names or key fingerprints **do not** establish independently governed principals.
- Untrusted Ubuntu and Windows purported provider run/job/attempt/log hashes tied to one claimed source SHA/workflow digest. Real provider-signed API log attestation, GitHub identity and log-origin signatures are **NOT** fetched, trusted or asserted. Caller can create coherent false data.
- Deterministic RFC6962-like SHA-256 Merkle leaf and node domain separation; recomputes an entire bounded history, its inclusion path and consistency path from claimed leaves. Equal mathematical roots and consistency proofs **are not** a published, immutable external checkpoint, and supplied pins are caller controlled.
- Three purported independent witness domains with a six-edge directed gossip graph and receipt hashes. It checks claimed cross-audience shape but **does not** verify physical/administrative separation, signed gossip, Sybil resistance or immutable independent logs. Separate view classifier distinguishes same-epoch fork, provider full-log receipt split, witness receipt split, source fork, nonce replay-fork and incomparable views, every outcome stamped `...UNAUTHENTICATED` or `...NOT_AUTHENTICATED`.
- A claimed CAS fencing generation/token/nonce and lease interval. Only local shape is checked. A `PENDING` outbox with `LOST_UNRESOLVED` acknowledgment is mandatory; `ACKED` or `PROVIDER_SIGNED` strings do **not** become a trusted exchange receipt. `release=False` is mandatory. Returned status is `RC690_COHERENT_CLAIMS_QUARANTINED_NO_EXTERNAL_TRUST`, and nine real AUTH/production/release/live flags are all **false**.

## 3. New 133 original Python 3.13.5 tests

`tests/test_rc690_audience_epoch_sqlite.py` contains **133 separately named** newly authored unittest cases: **94 structural tests** (including 79 named schema/mutation adversaries), **12** independent cross-field/AST/list tests, **11** cross-audience view classifier tests and **16** actual disposable SQLite transaction/concurrency/rollback tests. Structural/claim/view = 117, SQLite = 16.

- Mutations cover wrong provider run/job/source/digest, fake signed claims, replayed witness domains/roles/receipts, revoked key, missing or duplicate directed gossip edge, false immutable checkpoint, wrong Merkle roots and path, time interval, old lease token, bool-as-int attempts, false release/ACK and source/branch pin mismatches. Mutation harness **recalculates its caller-controlled claim digest** before validation: failures are not merely a stale digest mismatch.
- Actual SQLite test-only adapter uses `BEGIN IMMEDIATE`, conditional old generation and higher fence, a durable **local** spent-nonce unique row, state update and pending outbox in a single COMMIT. Exercises 2 separate subprocess contenders, 3 threads, real process `os._exit` before and after COMMIT, reopen/replay, ABA protection while state is retained, pending ACK, whole-file snapshot rollback and two disconnected forks accepting two different winners. All normal code paths explicitly close SQLite connections.
- Adversarial **negative** evidence: with privileged access, a previously saved DB can be restored and a spent nonce reused; a local text "external" anchor can be restored by the same actor; two disconnected DB clones can commit independently; a forged local `CLAIMED_SIGNED_ACK` is not an externally signed ACK. A real provider may or may not have seen any operation after an ACK loss. This is **not** true multi-host production CAS, guaranteed power-loss durability, immutable/independent monotonic storage or application-integrated exchange order control.
- On first local run four cases failed: non-ASCII data raised the wrong error type; three view-classifier assertion helpers had an overly restrictive status-suffix check. Corrected the source to **fail closed** with `AudienceRejected` for non-ASCII, and corrected the helper to accept explicit `...NOT_AUTHENTICATED` statuses. Repeated full-suite tests **3 consecutive times PASS**, not a hidden flake or claimed hosted failure.
- Local CPython **3.13.5**, command `PYTHONWARNINGS=error PYTHONPATH=<RC690-root> python3 -m unittest discover -s tests -p 'test_rc690*.py' -q` -> **133/133 PASS**, 3 repetitions; `PYTHONWARNINGS=error python3 -m compileall -q safe_public_ci tests` **PASS**, no ResourceWarning. Explicit AST checks: `hashlib,hmac,re` exactly and banned direct calls `[]`.

## 4. Exact-byte source identities before GitHub upload

| Local tested file | Git blob SHA-1 | Raw file SHA-256 | Bytes |
|---|---|---|---:|
| `safe_public_ci/ci_audience_epoch_quarantine.py` | `90070b71f296d02ae1dc55a3345b64738a5b2da2` | `a8ba2a9a8e2f58c696baeb20b2c43e7ec6aea10936eba9bdcad654fbcd427234` | 14242 |
| `tests/test_rc690_audience_epoch_sqlite.py` | `4df44b1cd2989ef44e916dcad372814eaa8f6ce6` | `083dc3a691330d3fa06a86b637acd82e88b696aefdc748a4acfe56d35b27d874` | 26001 |

A **GitHub exact-HEAD readback** must independently confirm both exact Git blob SHA-1 values. If any blob differs, stop fail-closed, never relabel as complete.

## 5. Native CI acceptance protocol (MUST be completed, not inferred)

Baseline existing 2299 + new RC690 133 = **2432 expected tests per OS**. Trigger existing unchanged native Ubuntu and Windows validation workflows from the **last RC690 code commit**. Require independently: run and job `completed/success`, all **9/9 actual steps completed/success**, exact identical commit SHA and attempt, ORIGINAL complete full job logs, **2432 distinct `... ok`**, **133 distinct RC690 tests**, footer `Ran 2432 tests ... OK`, zero FAIL/ERROR/skip. Do not call an older-head run, a partial/queued run, missing step or incomplete log a pass. Put real run/job/log evidence into Draft PR #7 description as **post-CI addendum**, without moving the code HEAD. If failure, repair on the same Public validation branch, rerun and append failure evidence. Never invent job IDs or test metrics.

## 6. Prohibited promotion and TUR48 handoff

`FINAL=SEALED`, `LIVE=DISABLED`, `SINGLE_FIT=UNUSED`, `+20% NET=NOT_TESTED`. End-user deployable Windows/Ubuntu/server independently verified: **0/3**. Genuine independent owner/reviewer key trust, signed provider origin, authority revocation/time and independent immutable CAS checkpoint: **0/4**. Previous owner publication checklist **5/10** (50%) is a distinct control, not application/strategy completion. No authenticated signing or live trading, no real exchange orders, no fit or profit assertion, no auto-merge, and no Private repository access. Preserve all previous PR7 audit archive and historic first-failure records. TUR48 should prioritize *actual independently administered public trust anchors and real provider attestation*, cryptographic signer verification under revocation, monotonic public checkpoints and application transaction integration; if missing, refuse promotion.


## 5A. Actual first hosted CI failure — retained, never counted as PASS

**First exact RC690 source HEAD `ab68517fd3a2172c583e872d997f8b6b60c16886` FAILED on both native hosts.** Do not erase or mislabel these run IDs:
- **Ubuntu** [run #43495951082](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43495951082) / real job `132128969821`, completed/**failure**. Original full log **413192 chars**, `Ran 2432 tests in 13.557s`, `FAILED (failures=5)`. The five RC690 SQLite child-process cases failed; child stderr in logs shows `ModuleNotFoundError: No module named 'safe_public_ci'`. 2427 passed but do **not** call this run 2432/2432 PASS.
- **Windows** [run #43495950963](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/43495950963) / real job `132128969762`, completed/**failure**. Original full log **424082 chars**, `Ran 2432 tests in 31.817s`, `FAILED (failures=5)`. Same five subprocess import errors; 2427 passing rows are *not* a successful final run.

**Root cause:** launching `python <absolute-path-to-tests/test_rc690_audience_epoch_sqlite.py> --rc690-child` from hosted GitHub Actions changes Python's import search path to `tests/`, and the native child lacks the parent repository root. Local command with `PYTHONPATH` originally masked this gap. The test-only fix inserts precisely `Path(__file__).resolve().parents[1]` into `sys.path` BEFORE the safe package import. No source application code, import whitelist, main, workflows, credentials, test scopes or `MAX_ENTRIES=32` constraints change.

**Revalidation of the fixed test file before upload:**
- Python **3.13.5**, `PYTHONWARNINGS=error`; **133/133 PASS** from the repository root.
- Run from **`/tmp` with `PYTHONPATH` entirely unset** and `-m unittest discover -s /mnt/data/kripto_tur47/tests -p 'test_rc690*.py'`: **133/133 PASS**; thus the original CI subprocess import-path failure is reproduced/resolved without workflow changes.
- `python3 -m compileall -q safe_public_ci tests`: **PASS**. Banned runtime source imports/calls unchanged.
- **Corrected tested test-file blob SHA-1:** `19d26fd94e13872c9ddc0ac37f308e7f97b44b64`. **Corrected raw SHA-256:** `cdd3a33d4b54d9ebc6a49a12a88f44dbe09f29d5d97354c09f67dc591b105deb`. The identities in section 4 refer to the **first** unsuccessfully hosted attempt and are retained as historical evidence. The final successful tested file's identity is the corrected one here; verify exact GitHub readback.

**A NEW final HEAD and TWO NEW complete real native CI runs remain mandatory**. No completed final CI is claimed by this document. Publish actual run IDs/jobs/9-step/full-log/2432 case acceptance as a post-CI PR #7 metadata addendum without modifying the successful HEAD.


## 5B. Final source-head trigger without workflow changes

Both native workflow files were explicitly inspected; each trigger's `push.paths` includes `safe_public_ci/**` but **does not** include `tests/test_rc690_audience_epoch_sqlite.py`. Therefore the fixed test-file-only commit `61cddd2a1a8df26e58ce516c6f7a74cb75f234c8` correctly produced no new native validation runs. Do not count absence of runs as a success. Instead a test-verified **comment-only** change in the RC690 safe module must be committed *last* to create an exact new tested HEAD that matches both unchanged workflow path filters. Do NOT relax/modify either workflow.

Local finalized code file (after the safety-clarifying comment): tested Python3.13.5 **133/133 PASS**, `PYTHONWARNINGS=error`, `compileall PASS`, with no `PYTHONPATH`. Final **source Git blob SHA-1** `d5fcaf8cc00a0975b262f497cf6d221aaa66962a`, raw file **SHA-256** `5813408f4f319ba4c4dd23f080a8f7c14276b5975412ca420a3f1135e09170ae`, **14564 bytes**. Final test Git blob/SHA-256 in §5A remain `19d26fd94e13872c9ddc0ac37f308e7f97b44b64`/`cdd3a33d4b54d9ebc6a49a12a88f44dbe09f29d5d97354c09f67dc591b105deb`.

Final hosted CI is a distinct gate: require new Ubuntu and Windows complete job log and 9/9 success **at the final source commit SHA**. A report/PR addendum is not a substitute for final native full-log verification.
