# CollisionLock submission

CollisionLock is a semantic concurrency-control primitive for autonomous
agents. It stores bounded immutable operation packets, independently derives a
retrieval route, compares all bounded active operations using structured
interference facts, and derives mutual exclusion deterministically. It is
distinct from duplicate detection because different operations may conflict
through shared state or dependencies.

## Release gates

The release requires the direct adversarial suite, `genvm-lint check`, schema
extraction, packaged typecheck, Pyright, `git diff --check`, hostile audit,
source SHA-256 freeze, finalized Studio Dev deployment, deployed-source
readback, and a real three-lock smoke test. The final evidence is kept in
[PORTAL.md](PORTAL.md).

## Release facts

```text
project_path: /home/ini/collisionlock
network: Studio Dev
chain_id: 61997
test_count: 81
test_result: PASS
genvm_version: vstudio-dev
source_sha256: e85bcf9a58a7ed1e149127a1e67a7bcba7f1bc66b1bdc89386cc6937b63c8818
deployed: PENDING
deployment_tx:
contract_address:
github: https://github.com/Iniwura/CollisionLock
commit:
pushed: PENDING
secret_scan: PENDING
ready_for_submission: PENDING
```

The contract does not create a frontend. It only protects downstream systems
that enforce successful lock acquisition; an off-chain agent can still ignore
the protocol.
