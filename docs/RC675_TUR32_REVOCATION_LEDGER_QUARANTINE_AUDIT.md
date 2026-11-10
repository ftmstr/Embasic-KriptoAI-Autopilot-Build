# KriptoAI Autopilot — TUR 32 / RC675 — Revocation and Ledger-Claim Quarantine
Date: 2026-11-10. **Public, synthetic-only; no trading, model fit or release authority.**

## 1. Canonical source and immutable limits

- Repository: **Public** `ftmstr/Embasic-KriptoAI-Autopilot-Build`; only existing `validation/rc654-pr1-rc653-combined-ci` branch and open unmerged **Draft PR #7**, base `research/rc653-synthetic-receipt-envelope`. Starting RC674 HEAD: `1192e41a324c006cd8d5469aa682956023d6b239`.
- Public main baseline: `0f63e24e0decdb51c7fc39ecd3a7c1611cc0b471` (unmodified). No Private repository access, workflow trigger/permission changes, merge, signing, production deployment, exchange connectivity, order placement, model training or financial result.
- PR #1 remains separate Draft/unmerged at `710517be3b4a0a671458b6e6cad0261138d0b3b0`; **18** independent tests not copied or integrated, PR #1/#7 submitted independent review counts **0**.
- Preserve `tests/test_guard.py` whitelist and `compile/eval/exec/open/__import__` restrictions. **FINAL=SEALED; LIVE=DISABLED; SINGLE_FIT=UNUSED; +20% NET=NOT_TESTED.**

## 2. Actual RC674 native hosted CI baseline independently rechecked

- Ubuntu: [run #42856558516](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42856558516), job `129971051656`: actual GitHub provider run `push`, `run_attempt=1`, completed/success at exact SHA `1192e41a324c006cd8d5469aa682956023d6b239`; **9/9** successful steps. Original job log: **959 distinct `... ok` rows**, `Ran 959 tests`, `OK`; 60 RC674 cases.
- Windows: [run #42856558606](https://github.com/ftmstr/Embasic-KriptoAI-Autopilot-Build/actions/runs/42856558606), job `129971051443`: **same** exact SHA, event, attempt and completed/success; **9/9** successful steps, complete job log **959 distinct `... ok` rows**, `Ran 959 tests`, `OK`; 60 RC674 cases.
- These confirm **hosted synthetic unit testing only**, not cryptographic supply-chain authentication or a functioning trading model.

## 3. Source-driven security issue and RC675 design

Reviewed actual Public `ci_witness_equivocation_quarantine.py` (RC674), `ci_rotation_quarantine_gate.py` (RC673), `ci_context_chain_gate.py` (RC672), `ci_cas_interleaving_trace.py` (RC671), `ci_cas_readback_guard.py` (RC670) and `ci_receipt_replay_fence.py` (RC669). Prior safe modules reject unverified signer/issuer claims and inconsistent receipts, but a revocation decision (including all three claimed reviewer keys) and independently authoritative *consumed* ledger history were not available in the RC674 witness checker. Merely hash-matching fictional signatures/actor names with attacker-supplied pins is not a genuine independent owner approval or provider attestation.

**New** `safe_public_ci/ci_revocation_ledger_quarantine.py`:

- Uses only allowlisted `hashlib`, `hmac`, `re`; bounded, strict builtin input types; no external IO, cryptographic signing, wallet, broker, live trading, storage or dynamic compilation/evaluation.
- Constructs a versioned domain-separated SHA-256 **claim** hash binding exact Public repo/validation branch, Git SHA, source/workflow/roster digests, authority epoch/root, claimed CAS ledger generation/root, next-generation/root, nonce, ordered distinct Ubuntu/Windows log hashes, run/job IDs, three claimed distinct issuer identities/public-key fingerprints, constrained ACK state and permanent no-live/no-release flags.
- Requires independently provided **but NOT authenticated** expected fields and sorted/unique bounded histories. Rejects revoked owner/reviewer/incumbent key fingerprint, retired current/proposed authority root, consumed nonce, seen Ubuntu or Windows log digest, re-used proposed state root, malformed history, duplicate witness/runner identity, fake signed/verified status, stale/rollback generation, ABA root or false `ACK_APPLIED`.
- Requires three ordered *claimed* roles (owner, independent reviewer, incumbent custodian), each bound to the exact statement hash with state `NOT_VERIFIED`. Does **not** verify any actual cryptographic signature or person.
- Every consistent return is `REVOKED_LEDGER_CLAIMS_QUARANTINED_NOT_AUTHENTICATED`, `external_root_authenticated=False`, `signatures_verified=False`, `cas_atomicity_verified=False`, `ledger_write_performed=False`, `release_ready=False`, `live_trading_allowed=False`.
- A malicious actor who controls both the envelope and the pinned revocation/ledger histories can fabricate matching bytes; repeated invocations using the same supplied state can both appear valid. There is **no independently sourced trust root, transactional compare-and-swap, durable append-only ledger, revocation verification, actual signed key distribution, or authenticated lost-ACK readback**. Therefore this is a **quarantine-only structural improvement**, not real atomically consumed receipts or authority.

**New** `tests/test_rc675_revocation_ledger.py`: **65** original invented-source unit tests. Cases cover all three revoked reviewer keys, retired current/new root, consumed nonce, reused per-platform log, replayed proposed state, cloned keys/actors, wrong Git/source/workflow/roster pins, false signed owner/provider and `ACK_APPLIED`, ABA/rollback/jump, wrong generation/run/job, malformed history, implicit bool/int conversions, double contender, lost ACK, and the important *attacker also controls all expected pins* case retaining no-authentication flags. No PR #1 tests used.

## 4. Actual local Python 3.13.5, import and source-byte verification

- `python3 --version`: **3.13.5**.
- `PYTHONPATH=/mnt/data/rc675 python3 -m unittest discover -s /mnt/data/rc675/tests -p 'test_rc675*.py' -q`: **65/65 PASS**.
- `python3 -m compileall -q /mnt/data/rc675/safe_public_ci /mnt/data/rc675/tests`: **PASS**.
- Local source Python AST audit: imports are **hashlib, hmac, re only**, with **zero** `compile/eval/exec/open/__import__` calls.
- Actual locally tested file SHA-1 Git blobs and SHA-256 digests:

| File | `git hash-object` (SHA-1) | SHA-256 |
|---|---|---|
| `safe_public_ci/ci_revocation_ledger_quarantine.py` | `afe2c16524ff8a8930bc8895720787501e4b936e` | `6bed3acb730352c1f98f38611a0aac3c13f1fbb7c1614fe7ed8d17aca33b260d` |
| `tests/test_rc675_revocation_ledger.py` | `f0feb26695340f2a98fa54a9e89a441efaf65d08` | `286ec582c00438bf32a196f6697a5e1877beab387cc0923839ae8d8f86d5e294` |

Both Public GitHub `fetch_file` readbacks independently matched **2/2** locally tested Git blob identities, after the files were committed. Keep exact-file byte checks for every subsequent update.

## 5. Final GitHub-native CI and publication acceptance

- Previous RC674 **959** tests + new RC675 **65** = **1024 expected per OS** (NOT PASS unless actual final SHA GitHub-hosted Ubuntu/Windows `push` run/job/step/full-log validates all).
- This technical report is recorded **before** the final exact-head native CI; write final run IDs and verdict into Draft PR #7 metadata, which does not advance code HEAD.
- Keep owner publication-gate progress at **5/10 = 50%** only; **not** general software/strategy readiness, any rate of trading success or return. Final installable package/service acceptance remains **0/3** (Windows, Ubuntu, server).
- Remaining hard **NO-GO**: independent owner/reviewer approvals, real signature/key revocation provenance, signed trust root, standalone durable atomic CAS backend, full security/license/SBOM/signing and end-user platform installation tests, PR #1 approval, actual finance strategy validation.
- No genuine release, credentials, order execution, live trading, model fitting or financial gains performed.

## 6. TUR 33 focus

First reverify exact RC675 final HEAD and native dual-platform 1024-case CI proof. Then investigate a separate *read-only* verified source-of-truth design for revocation/issuer provenance with genuine independently managed signing and atomic CAS; never upgrade source-hash matching to `AUTHORIZED` without externally checked proof, and keep Private/main/merge/NO-LIVE guards immutable.
