# KriptoAI Autopilot — TUR53 / RC696: Ed25519 signature math and exact hosted-log byte binding, not external authority

**Date:** 2026-11-16, Europe/Istanbul. **Repository:** Public `ftmstr/Embasic-KriptoAI-Autopilot-Build`; only `validation/rc654-pr1-rc653-combined-ci`; open Draft/unmerged PR #7. No production, trading, model fit, deployment, merge or profit claim.

## Verified baseline / immutable protections

At start of TUR53 Public validation HEAD exactly `a5536e053e8b1c5cac8e02ffca1b7023884c5f7f`, and 148-entry Git tree contained no RC696/TUR53 or later work. PR #7 remained open/Draft/unmerged; PR #1 open/Draft/unmerged and its 18 unapproved cases remained separate. Public `main`: `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471`.

TUR52 original hosted Ubuntu run `43651207798`/job `132619853365` and Windows run `43651207796`/job `132619853563` both `completed/success` at the same exact source HEAD; both 9/9 real GitHub job steps SUCCESS. Entire independent job logs: Ubuntu 494253 characters and 2963/2963 distinct `... ok` (35 RC695, 124 RC694), `Ran 2963 tests in 14.848s; OK`; Windows 505739 characters and 2963/2963 distinct `... ok` (35 RC695, 124 RC694), `Ran 2963 tests in 39.246s; OK`. Neither contains FAIL/ERROR/skipped/ResourceWarning.

Five protected unchanged workflow blobs: RC652 `28fedf1e76f1d26247fcb1897c176bc3b7009808`, RC653 `d7a08e1935b060d31feca2e1ef8db4184268858c`, RC654 `140264aaf07f3130a23606254f545b4ff77b1971`, RC658 Windows `254ac4f4ea821a05ee4730c3828d4de1b96a0e72`, general synthetic `1cd73e647401f75ae9a98f55d8adcd166a366fe3`. RC656 snapshot module `7db54362bb627b26f9be0c09bb958a8601c961a2`, `MAX_ENTRIES=32`; earlier failed CI records must not be erased.

## RC696 unique engineering development

New `safe_public_ci/ci_rc696_detached_evidence_boundary.py` (standard-library-only at module load, no IO) introduces *real-byte-bound* typed proof inputs for provider complete run/job logs. `validate_envelope` hashes **the actual supplied full job log bytes**, validates exact UTF-8-independent length, SHA-256, source SHA-1, workflow blob SHA-1, run/job/attempt, platform, challenge SHA-256, unique nonce SHA-256, epoch and fence with exact schema and strict integer types. Maximum accepted original log: 2 MiB. `canonical_signed_scope` uses deterministic JSON, domain-separation prefix and length-prefixing, eliminating naive concatenation ambiguities. Signed scope changes when workflow, job, attempt, challenge, nonce or log content changes.

`verify_detached_ed25519` performs *actual cryptographic Ed25519 signature checking* using an optional `cryptography` backend if installed; absent backend fails closed (`CRYPTO_BACKEND_UNAVAILABLE`). Valid mathematics using an arbitrary supplied public key returns `VALID_SIGNATURE_UNTRUSTED_KEY` but **not independent key authorization**. A locally validated RFC8032 Ed25519 vector proves the mathematical path works under Python 3.13.5 with `cryptography`; hosted workflows do NOT install the optional backend, so their native passes cannot demonstrate the positive signature path. A claimed GitHub run or API status remains operational data, **not a GitHub-issued signed full-log attestation**.

Separate Ubuntu/Windows claimed-job pair inspection blocks same-job/log/nonce replay and source/challenge forks. Claimed revocation event sequencing rejects timestamp counter rollback, duplicate event IDs and revoked key reissuance, but *cannot* certify a trusted clock. Merkle root pair inspection detects equal-size split-view and snapshot size rollback, but cannot establish externally immutable consistency. Remote CAS/ACK structural checks reject stale generation/fence, replayed idempotency, lost/stale ACK, false signed-ACK origin, but **do not execute a remote CAS, provide power-loss durability, resolve a pending outbox or authenticate a recipient**. All outputs are quarantined; all eight trust gates remain **0/8 BLOCKED**.

The design is an integration point, not a completed production integration. To open any real trust gate, independent actors must supply independently distributed and audited key roots/roles; provider-signed whole-original-log payload and verification policy (where available); signed revocation chronology plus trusted time; externally witnessed immutable Merkle inclusion/consistency; cross-host linearizable remote CAS with independent trust domain and restore fencing; and remote independently authenticated idempotent ACK reconciliation. No new property or signature from synthetic fixtures is sufficient.

## Original local verification and exact tested byte identities

Python **3.13.5** with `PYTHONWARNINGS=error`: **41/41 new RC696 tests PASS**; `compileall -q` PASS; AST parsing PASS; local genuine RFC8032 vector signature result `VALID_SIGNATURE_UNTRUSTED_KEY / authorized=False`. Adversarial cases cover full-log byte substitution/truncation, fake auth, cross-host fake quorum, provider role/job/attempt substitution, nonce/challenge replay, revocation, Merkle gossip split-view and rollback, multi-host CAS/fencing/ABA, snapshot restore, stale/lost ACK, and untrusted provider origin. No tests are claimed to prove actual external provider origin, cryptographic key custody, internet connectivity, or live market functionality.

| Artifact | Git blob SHA-1 of the tested bytes | raw SHA-256 | Bytes |
| --- | --- | --- | ---: |
| `safe_public_ci/ci_rc696_detached_evidence_boundary.py` | `288f5c6b25762de8d53ba255193479531dfa2300` | `1e5436172c27c400ce6aa3ec69beb598fe9daafb49b884cc745b335d4c88190b` | 9411 |
| `tests/test_rc696_detached_evidence_boundary.py` | `60d98693c72ad9c6043fa0e017ce116c6ada4bd2` | `72e8bfaea1e7edd1e3d5f8cd9a74168014d27e978bc7446b7e0740c73ba5ac76` | 13126 |

This report itself is committed **before** test and source, so it cannot yet record the unknown final Git commit or future native job results. Append final run/job IDs and complete-log readback **only after** both jobs finish, in a PR #7 comment that does not modify tested source bytes. Source commit last to trigger unchanged Ubuntu and Windows workflow path filters. If either hosted job does not complete successfully on the final source SHA, TUR53 remains CI-NO-GO and historical failures are preserved.

**Hard locks:** `FINAL=SEALED`, `LIVE=DISABLED`, `SINGLE_FIT=UNUSED`, `+20% NET=NOT_TESTED`. No final user-ready software assertion; no percentage of financial profit demonstrated.
