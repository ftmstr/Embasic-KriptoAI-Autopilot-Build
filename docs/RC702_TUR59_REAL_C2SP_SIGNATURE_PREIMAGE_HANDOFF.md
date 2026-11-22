# KriptoAI Autopilot — TUR59 / RC702: real C2SP Ed25519 signature-message handoff, 0/8 external authorization

**2026-11-18, Europe/Istanbul. ONLY PUBLIC** `ftmstr/Embasic-KriptoAI-Autopilot-Build`, branch `validation/rc654-pr1-rc653-combined-ci`, existing OPEN/DRAFT/UNMERGED PR #7. No private repo, main merge, deployed service, AWS account, live crypto orders, model fit or profit statement.

## Original TUR58 final-HEAD validation rechecked

At startup the only permitted Public branch and PR #7 HEAD were exactly `164a8a9b27bad27e92778790e61b3e430d630b85`; 167 repository tree entries; zero TUR59/RC702 or later paths. Public main `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`, PR #1 HEAD `710517be3b4a0a671458b6e6cad0261138d0b3b0`, PR #1 and #7 both OPEN/DRAFT/UNMERGED.

Real Ubuntu [run 44360583237](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/44360583237), job `135000517283`, and Windows [run 44360582284](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/44360582284), job `135000512104`, have exact same prior SHA and `completed/success` run/job, attempt 1, **9/9 native steps SUCCESS**. Full independently fetched original decoded job logs contained **3130/3130 unique PASS** and **24/24 RC701** on both hosts: Ubuntu 524522 characters, `Ran 3130 tests in 16.005s; OK`, Windows 536110 characters, `Ran 3130 tests in 44.231s; OK`; no FAIL/ERROR/skipped/ResourceWarning. Historical real first TUR58 Ubuntu run `44359929767` and Windows `44359927103`, source SHA `888444e6838c627dd59507456ae910f2d29e4bed`, still `completed/failure`; earlier failures also retained.

Five protected workflow Git blob SHA-1: `28fedf1e76f1d26247fcb1897c176bc3b7009808`, `d7a08e1935b060d31feca2e1ef8db4184268858c`, `140264aaf07f3130a23606254f545b4ff77b1971`, `254ac4f4ea821a05ee4730c3828d4de1b96a0e72`, `1cd73e647401f75ae9a98f55d8adcd166a366fe3`; existing `tests/test_guard.py` blob `c793e475afd4bb24bbb70c3b60728a4c89a2017e` import whitelist unchanged; RC655 preflight blob `74768b736b4356c580a45ade85f701363e6b4972` and RC656 MAX_ENTRIES=32 snapshot blob `7db54362bb627b26f9be0c09bb958a8601c961a2` untouched. No forbidden root folders.

## What available providers can and cannot independently establish

**C2SP Signed Notes** `https://c2sp.org/signed-note@v1.0.0-rc.1`: an Ed25519 checkpoint signature signs the exact note text including its final newline, *excluding* the additional separating blank line and all signature lines; encoded as base64(4-byte key ID + 64-byte Ed25519 signature). The key identifier is `SHA256(name || 0x0A || 0x01 || 32-byte public key)[:4]`. A matching **caller-provided** key ID/signature payload is not cryptographic verification and does not establish independent provenance or role.

**C2SP timestamped cosignatures** `https://c2sp.org/tlog-cosignature@v1.0.1`: Ed25519 witness cosignatures instead sign `b'cosignature/v1\ntime <decimal-timestamp>\n' + original-note-body`, using 4-byte key ID `SHA256(name || 0x0A || 0x04 || 32-byte public key)[:4]`, plus eight-byte big-endian timestamp and a 64-byte Ed25519 signature. Timestamp shape is not a trusted clock or authenticated revocation history. Different key bytes and names are a *necessary* condition of claimed independence, never sufficient to prove different human, legal entity, custody or administration. Current C2SP editor specification also describes ML-DSA-44; this **strict RC702 implementation deliberately only handles Ed25519 type 0x01/0x04** and fails closed on extensions or other signature algorithms.

**Independent trusted signature verifier exists, but is NOT connected.** Sigstore Rekor Tiles [Go `verify` package](https://pkg.go.dev/github.com/sigstore/rekor-tiles/v2/pkg/verify), version v2.3.0, offers `VerifyCheckpoint`, `VerifyWitnessedCheckpoint`, `VerifyConsistencyProofWithCheckpoints` and `VerifyInclusionProof`, but only when authentically configured with independently distributed/pinned keys and actual checkpoint/proof bytes. This repository does not contain OOB owner/reviewer trusted Ed25519 custody, real Rekor witnessed historical proof bundle or provider-signed exact RAW original full GitHub Actions job logs. No external service was contacted with signing permission, no new workflow permissions were added, and no concrete verifier was run against actual authorized key material. **No key IDs, plaintext signatures or vendor product documentation open the 0/8 gates.**

**GitHub full log versus artifact attestation.** Real GitHub API job log download [reference](https://docs.github.com/en/rest/actions/workflow-jobs) is not provider-issued signature over its original RAW full log bytes. GitHub artifact attestation is subject-specific, [separate attestations/permissions](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations); even if present, it does not automatically sign raw job logs. For the prior successful TUR58 Ubuntu/Windows run IDs the real GitHub run artifact APIs returned **zero workflow artifacts**, not proof that no other external provider data could ever exist.

**MRSC genuine service capability, not actually acquired evidence:** AWS [global tables](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html) support latest-state conditional writes and strongly consistent reads across three regions; MRSC single-item design cannot use transaction APIs, default MREC is last-writer-wins, and AWS replication witness is NOT independent log-signature witness. No live table/IAM role/multi-host fencing/restore drill, no actual remote recipient idempotent ACK and no external signatures have been provided. Prior TUR57/58 safe `UpdateItem`/`GetItem` preflight and uncertain response classification remain unexecuted and NO-GO.

## Unique RC702 P0 code change

New `safe_public_ci/ci_rc702_c2sp_signature_preimages.py` is a narrowly scoped, **no IO/network** formatter of **two distinct exact C2SP signed-message preimages** from candidate Signed Note bytes, with:
- strict UTF-8, no CR or ASCII control characters, exact origin/decimal size/RFC6962 32-byte root, no unreviewed checkpoint extensions, canonical RFC4648 inherited from RC701, bounded signatures;
- canonical 4-byte Ed25519 key ID validation for the caller-supplied candidate log/witness public keys, 68-byte log and 76-byte timestamped witness signature payloads, timestamp upper bound, unique log/witness keys;
- nonce and audience source-binding plus safe exact digest handoff of each message and signature to an **independent external verifier** that must separately pin OOB trust roots, check actual Ed25519 signatures, authenticate the prior historical checkpoint and RFC6962 consistency and verify time/revocation;
- **hardcoded false** `log_signature_verified`, `witness_signature_verified`, `key_ownership_verified`, `independent_historical_consistency_verified`; `external_proofs_verified=0`; AUTH NO-GO/LIVE DISABLED.

Unlike previous RC701 structural-only parsing, RC702 produces both exact **algorithm-specific signature verification preimage hashes** and rejects incorrect key ID, wrong signature lengths, wrong timestamp, extension smuggling and swapped signer name. This is a useful real cryptographic integration boundary, **not cryptographic verification itself**. No new import permissions or extra crypto dependencies.

New `tests/test_rc702_c2sp_signature_preimages.py` contains **18 targeted regression tests**, including independent reference hashing of two signed-message formats, key-ID calculations with 0x01/0x04 domain separation, tamper/replay/mismatch and never-authorize cases. Local Python **3.13.5** `PYTHONWARNINGS=error` **18/18 PASS**, AST PASS, compileall PASS. Testing locally used a faithful minimal **test-only** shim of the existing RC701 RFC4648 encoder/decoder; the final genuine hosted CI imports the unmodified existing production RC701 module. The source imports only whitelisted `hashlib,hmac,json,re` and existing `safe_public_ci`; no network, subprocess, `base64` source import, trading or model fit.

Local exact source tested byte identity: 8087 UTF-8 bytes; Git blob SHA-1 `87eface514acf0de9c69252557dbf61378897e1b`, SHA-256 `5539dbc082353e1988a2973bc094ba82bca2829f932815326ddbe2cd4c16f469`.
Local exact test byte identity: 7617 UTF-8 bytes; Git blob SHA-1 `ae44255a9c00e7da33223d7cc9ecea196dd312b2`, SHA-256 `f4ca46bb22052438a812087a4ca617b4ead8223edd927ca89919a3647f712437`.

**Publication process:** commit report, then tests, then source LAST so already-unmodified native Ubuntu and Windows workflow `push.paths` trigger on exact final source SHA. Expected full suite 3148 (3130+18), not PASS until independently completed original Ubuntu+Windows run/job results and full logs show the exact final SHA, 9/9 steps, 3148 distinct passing tests, and zero failures. Git SHA-1/UTF-8 SHA-256 of **all three files** must be verified from final GitHub blob readback and the CI evidence comment posted to Draft PR #7.

## The eight actual external proof gates are STILL 0/8 BLOCKED

1. Independently out-of-band authorized/pinned Ed25519 **owner** key, role, custody, revocation: BLOCKED.
2. Separate-admin OOB authorized/pinned Ed25519 **reviewer** key/approval: BLOCKED.
3. Provider-signed exact RAW *complete original* Ubuntu job log: BLOCKED.
4. Provider-signed exact RAW *complete original* Windows job log: BLOCKED.
5. Independently trusted timestamp, auditable revocation/rotation history: BLOCKED.
6. Log-key-verified old/new C2SP checkpoint, distinct verified independent witness Ed25519 cosignature, externally authenticated historical root and RFC6962 inclusion/consistency: BLOCKED.
7. Actually deployed separately administered multi-host durable MRSC/equivalent antirollback fencing CAS and tested restoration resistance: BLOCKED.
8. Independently authenticated recipient idempotent remote ACK after real missing-response reconciliation: BLOCKED.

**FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED; AUTH=NO-GO.**
