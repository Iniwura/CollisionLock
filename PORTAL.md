# CollisionLock portal

## Reviewer quick path

1. Read [ARCHITECTURE.md](ARCHITECTURE.md).
2. Inspect [schema/collision_lock.schema.json](schema/collision_lock.schema.json).
3. Run the pinned gates in [README.md](README.md).
4. Review [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).
5. Check the finalized deployment and live smoke evidence below.

## Deployment record

The following fields are finalized from Studio Dev receipts and source
readback. The deployment includes the enforceable lifecycle and admission
mechanism preventing slot exhaustion.

```text
network: Studio Dev
chain_id: 61997
deployment_status: FINALIZED
contract_address: 0x5477bd9aaC3a8Ee8E68B1FF678F28F56B70b7Ece
studio_url: https://studio-dev.genlayer.com/?import-contract=0x5477bd9aaC3a8Ee8E68B1FF678F28F56B70b7Ece
source_sha256: d17fa0cbc08ce1550cdb1ae2348ce8fdb576fd1141c43b7cd88b4b6a6da167e8
consensus_status: ACCEPTED / MAJORITY_AGREE
execution_status: FINISHED_WITH_RETURN
source_readback: PASS (gen_getContractCode verified against source)
source_sha_match: TRUE
live_smoke_status: PASS
live_lock_a: smoke-a-v2 — FINALIZED, MAJORITY_AGREE, FINISHED_WITH_RETURN
live_conflict_result: smoke-b-conflict-v2 — FINALIZED, MAJORITY_AGREE; rolled back with `operation conflicts with an active lock.` Projection: OVERLAPPING / DEPENDENCY / dependency_interference=true / ordering_required=true.
live_per_owner_cap: 9th lock attempt by single owner rejected with `per-owner active lock limit exceeded.`
live_extend_lock: owner heartbeat extension of smoke-a-v2 lease
live_reap_result: third-party reap of expired unextended lock; state set to EXPIRED; slot returned to active pool
live_post_reap_acquire: legitimate caller acquires freed active slot
explorer: https://explorer-studio.genlayer.com/address/0x5477bd9aaC3a8Ee8E68B1FF678F28F56B70b7Ece
```

## Smoke protocol

The live smoke tests demonstrate both semantic mutual exclusion and the new
lifecycle admission controls:

1. **Semantic mutual exclusion**: Production credential rotation and an
   incompatible billing deployment correctly conflict and fail closed.
2. **Per-owner admission cap (`MAX_ACTIVE_PER_OWNER = 8`)**: An untrusted caller
   attempting to flood more than 8 active slots is rejected with `per-owner
   active lock limit exceeded.` without state mutation.
3. **Heartbeat extension (`extend_lock`)**: Legitimate lock holders refresh their
   TTL without relinquishing their lock.
4. **Permissionless expiration reap (`reap_expired_lock`)**: Once a lock exceeds
   `LOCK_MAX_EPOCH_AGE` (64 epochs), any caller can reap it. The slot is freed,
   unblocking future acquisitions while preserving historical records for audit.
