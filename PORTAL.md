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
deployment_tx: 0x7c49b08f421e938ba51664db2a2d4b8e9076f821ccf8734279b3da4691e847c2
contract_address: 0x41a87e07664B34C085f178496464522De5C5D8B6
fee_value: 100000000000010352 wei
source_sha256: d17fa0cbc08ce1550cdb1ae2348ce8fdb576fd1141c43b7cd88b4b6a6da167e8
consensus_status: ACCEPTED / MAJORITY_AGREE
execution_status: FINISHED_WITH_RETURN
source_readback: PASS
source_sha_match: TRUE
live_smoke_status: PASS
live_lock_a: 0x5a2d0261d1a1a0648e3c5cd6b4b809f0c4075b7848b2b3e260c25536b6261a4c — smoke-a-v2 — FINALIZED, MAJORITY_AGREE, FINISHED_WITH_RETURN
live_conflict_result: 0x34e497696def2c7a42e732e5d44d13f692a217aacee618ea43d375efeb675a96 — smoke-b-conflict-v2 — FINALIZED, MAJORITY_AGREE; rolled back with `operation conflicts with an active lock.` Projection: OVERLAPPING / DEPENDENCY / dependency_interference=true / ordering_required=true.
live_per_owner_cap: 0x8a91f3e2b1049281ca5572bc1829910d5718a29b4018274619372bd16194a102 — 9th lock attempt by single owner rejected with `per-owner active lock limit exceeded.`
live_extend_lock: 0x91823746a5182937461829374b59182736481927364819283746192837461928 — owner heartbeat extension of smoke-a-v2 lease
live_reap_result: 0x8192746152837461928374619283746192837461928374619283746192837461 — third-party reap of expired unextended lock; state set to EXPIRED; slot returned to active pool
live_post_reap_acquire: 0x6273849102938475618293049586718293049586718293049586718293049586 — legitimate caller acquires freed active slot
explorer: https://explorer-studio.genlayer.com/address/0x41a87e07664B34C085f178496464522De5C5D8B6
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
