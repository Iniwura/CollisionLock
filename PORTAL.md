# CollisionLock portal

## Reviewer quick path

1. Read [ARCHITECTURE.md](ARCHITECTURE.md).
2. Inspect [schema/collision_lock.schema.json](schema/collision_lock.schema.json).
3. Run the pinned gates in [README.md](README.md).
4. Review [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).
5. Check the finalized deployment and live smoke evidence below.

## Deployment record

The following fields are finalized from Studio Dev receipts and source
readback. The smoke records use the corrected serialized transaction path;
the CLI-only fee-envelope failures are not counted as contract executions.

```text
network: Studio Dev
chain_id: 61997
deployment_status: FINALIZED
deployment_tx: 0xde45b566a396c513f245f0361d048b083bd355d6e261f1842c7f5405822dc598
contract_address: 0x1252E139623024A1c0e69ee8cFc1035E86810763
fee_value: 100000000000010352 wei
source_sha256: e85bcf9a58a7ed1e149127a1e67a7bcba7f1bc66b1bdc89386cc6937b63c8818
consensus_status: ACCEPTED / MAJORITY_AGREE
execution_status: FINISHED_WITH_RETURN
source_readback: PASS
source_sha_match: TRUE
live_smoke_status: PASS
live_lock_a: 0x5a2d0261d1a1a0648e3c5cd6b4b809f0c4075b7848b2b3e260c25536b6261a4c — smoke-a-corrected-20261013 — FINALIZED, MAJORITY_AGREE, FINISHED_WITH_RETURN
live_conflict_result: 0x34e497696def2c7a42e732e5d44d13f692a217aacee618ea43d375efeb675a96 — smoke-b-conflict2-20261013 — FINALIZED, MAJORITY_AGREE; rolled back with `operation conflicts with an active lock.` Projection: OVERLAPPING / DEPENDENCY / dependency_interference=true / ordering_required=true.
live_compatible_lock: 0x5cafad03a03adf1bb9bc3d51fb09efb10ac2bd86215b42ec653a0a6b85027737 — smoke-c-compatible-20261013 — FINALIZED, MAJORITY_AGREE, FINISHED_WITH_RETURN
live_close_result: 0xcdf405b185f1b7630bc9138e6b562344d17f2f7efd644e7f9ea09e8701639b71 — owner close of smoke-a-corrected-20261013 — FINALIZED, MAJORITY_AGREE, FINISHED_WITH_RETURN
live_post_close_result: 0x491e9d52f926b43a993e42738411a6a4e4ee136d57d7f73bb202565c4321d277 — smoke-b-postclose-20261013 — FINALIZED, MAJORITY_AGREE, FINISHED_WITH_RETURN
explorer: https://explorer-studio.genlayer.com/address/0x1252E139623024A1c0e69ee8cFc1035E86810763

The first conflict attempt (`0xe1577dc12645efa73cb5d2cdec3e99e9e59bf76890bb4a753a7132eefdb4dea3`)
was finalized undetermined because a routing model returned invalid JSON. It
did not commit state; a fresh retry produced the semantic rollback above.
```

## Smoke protocol

The real smoke uses a production credential rotation, an incompatible billing
deployment that depends on the current credential, and an unrelated analytics
backup. The first and third acquired; the second failed closed; after the first
lock was closed, a fresh equivalent of the second acquired.
