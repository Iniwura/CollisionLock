# CollisionLock portal

## Reviewer quick path

1. Read [ARCHITECTURE.md](ARCHITECTURE.md).
2. Inspect [schema/collision_lock.schema.json](schema/collision_lock.schema.json).
3. Run the pinned gates in [README.md](README.md).
4. Review [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).
5. Check the finalized deployment and live smoke evidence below.

## Deployment record

The following fields are intentionally blank until a real Studio Dev
deployment and source readback have completed. They must not be filled with
guessed or simulated values.

```text
network: Studio Dev
chain_id: 61997
deployment_status: PENDING
deployment_tx:
contract_address:
fee_value:
source_sha256:
consensus_status:
execution_status:
source_readback:
source_sha_match:
live_smoke_status: PENDING
live_lock_a:
live_conflict_result:
live_compatible_lock:
live_close_result:
live_post_close_result:
explorer:
```

## Smoke protocol

The real smoke uses three fresh lock IDs: a production credential rotation,
an incompatible billing deployment that depends on the current credential, and
an unrelated analytics backup. The first and third must acquire; the second
must fail closed. After the first lock is closed, a fresh equivalent of the
second may acquire. A failure to obtain finalized evidence is reported as a
deployment blocker rather than converted into a success claim.
