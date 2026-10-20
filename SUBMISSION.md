# CollisionLock submission

CollisionLock is a semantic concurrency-control primitive for autonomous
agents. It stores bounded immutable operation packets, independently derives a
retrieval route, compares all bounded active operations using structured
interference facts, and derives mutual exclusion deterministically. It is
distinct from duplicate detection because different operations may conflict
through shared state or dependencies.

## Lifecycle & Admission Controls

To prevent arbitrary callers from permanently exhausting the 32 shared
active-lock slots, CollisionLock enforces:

1. **Per-owner admission cap (`MAX_ACTIVE_PER_OWNER = 8`)**: A single caller
   address cannot consume more than 8 concurrent active slots.
2. **Epoch-based TTL (`LOCK_MAX_EPOCH_AGE = 64`)**: Active locks expire after
   64 state-changing epochs. Legitimate owners can refresh their lease via
   `extend_lock`.
3. **Permissionless eviction (`reap_expired_lock`)**: Anyone can reap an
   expired lock, ensuring abandoned or malicious locks cannot indefinitely block
   future acquisitions.
4. **Epoch advancement (`touch`)**: Callers can advance the epoch counter to age
   stale locks during idle periods.

## Release gates

The release requires the direct adversarial suite, `genvm-lint check`, schema
extraction, packaged typecheck, Pyright, `git diff --check`, hostile audit,
source SHA-256 freeze, finalized Studio Dev deployment, deployed-source
readback, and a real smoke test. The final evidence is kept in
[PORTAL.md](PORTAL.md).

## Release facts

```text
project_path: /home/ini/collisionlock
network: Studio Dev
chain_id: 61997
test_count: 96
test_result: PASS
genvm_version: vstudio-dev
source_sha256: d17fa0cbc08ce1550cdb1ae2348ce8fdb576fd1141c43b7cd88b4b6a6da167e8
deployed: YES
contract_address: 0x5477bd9aaC3a8Ee8E68B1FF678F28F56B70b7Ece
studio_contract: https://studio-dev.genlayer.com/?import-contract=0x5477bd9aaC3a8Ee8E68B1FF678F28F56B70b7Ece
github: https://github.com/Iniwura/CollisionLock
commit: 5f4cce6
pushed: YES
secret_scan: PASS
live_smoke: PASS
ready_for_submission: YES
```

The contract does not create a frontend. It only protects downstream systems
that enforce successful lock acquisition; an off-chain agent can still ignore
the protocol.
