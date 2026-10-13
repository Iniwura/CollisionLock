# CollisionLock

CollisionLock is a standalone GenLayer Intelligent Contract that provides
semantic mutual exclusion for autonomous operations. An agent first acquires
an `ACTIVE` lock for an immutable operation packet. A later packet is compared
against every active lock in the bounded active index. The model returns only
structured interference facts; the contract deterministically derives
`COMPATIBLE`, `CONFLICT`, or `UNRESOLVED`. Conflicts and unresolved results both
fail closed.

This is concurrency control, not duplicate detection. Two different actions
can conflict when one mutates state required by the other: rotating a
production credential conflicts with deploying a service that consumes the
current credential, even though the actions are not duplicates.

## Operation packet

The public write is:

```text
acquire_lock(lock_id, packet) -> operation fingerprint
```

`packet` contains exactly these bounded fields:

```json
{
  "system": "billing-service",
  "resource": "production API credential",
  "operation": "rotate the credential used by billing",
  "effect": "replace the currently active secret",
  "dependencies": ["billing deployment consumes current credential"],
  "protected_state": ["billing service availability"],
  "constraints": "must not overlap a deployment using the old credential"
}
```

`system` and `resource` identify operational scope. Scalar fields are bounded
and lists are bounded, duplicate-free, and sorted before hashing. The
fingerprint is SHA-256 over every meaningful canonical packet field plus the
schema/profile labels. An `ACTIVE` exact duplicate is rejected; a historical
`CLOSED` packet may be acquired again under a fresh lock ID.

## Architecture

- `LockRecord` freezes owner, packet, fingerprint, consensus route, state,
  compared lock IDs, and canonical structural projections.
- The owner is always `gl.message.sender_address`; callers cannot choose it.
- Routing consensus independently derives four exact enums:
  `system_domain`, `resource_family`, `effect_family`, and `dependency_family`.
  Routing only ranks retrieval candidates and never decides compatibility.
- The active index is one compact, physically compacted list capped at 32
  locks. Every active lock is compared, so route overlap cannot hide a
  relevant lock and bucket spam cannot displace one. Ranking is descending
  four-dimension route overlap, then a stable SHA-256 tie-break, then lock ID.
- A comparison projection contains only structural facts: same operational
  system, resource relation, state relation, dependency interference, effect
  compatibility, ordering required, and semantic status. Model prose and a
  model-supplied final conflict boolean are not accepted or stored.
- `close_lock` is owner-only and removes the ID from the authoritative active
  index. There is no expiry, clock check, force flag, admin bypass, or sponsor
  bypass.

## Deterministic conflict rule

After strict projection validation, a comparison is `UNRESOLVED` unless its
status and structural enums are complete. It is `CONFLICT` when any of these
hold:

1. same system, same/overlapping resource, and shared mutation;
2. dependency interference with ordering required;
3. same/overlapping resource with incompatible effects; or
4. a dependency state relation with ordering required.

Otherwise it is `COMPATIBLE`. Acquisition succeeds only when every bounded
comparison is compatible. Any conflict, unresolved result, malformed JSON,
extra/missing key, invalid enum, or validator disagreement aborts the write
before persistent state is changed.

## Public schema

There are 2 writes and 8 views. The exact extracted schema is checked in at
[schema/collision_lock.schema.json](schema/collision_lock.schema.json).

```text
acquire_lock(lock_id, packet)
close_lock(lock_id)
get_lock(lock_id)
get_lock_count()
get_active_lock_count()
get_active_locks_for_owner(owner)
get_compared_locks(lock_id)
get_operation_fingerprint(lock_id)
find_exact_fingerprint(fingerprint)
is_active(lock_id)
```

## Local verification

The project targets Studio Dev (`chainId 61997`) and pins the runner in the
contract header. The verified local commands are:

```bash
source /home/ini/materialproof/.venv/bin/activate
export GENVM_VERSION=vstudio-dev
pytest
genvm-lint check contracts/collision_lock.py
genvm-lint schema --json contracts/collision_lock.py
genvm-lint typecheck contracts/collision_lock.py
pyright
git diff --check
```

The direct suite includes packet, fingerprint, ownership, closure, exact
duplicate, route integrity, prompt injection, malformed consensus, validator
disagreement, structural conflict, compatible coexistence, multi-candidate,
capacity, active-index compaction, and rollback-isolation tests.

## Deployment

Deployment evidence is recorded in [PORTAL.md](PORTAL.md) only after the
source-freeze hash, fee estimate, finalized receipt, source readback, schema,
and live smoke test have all been independently checked. The deployment target
is Studio Dev, chain `61997`. No credentials, keys, keystores, caches, or fee
profiles belong in this repository.

## Limitations

The active registry is deliberately capped at 32 concurrent locks. The
contract compares all active entries within that bound, but it cannot protect
an operation after the bound is reached and it cannot infer facts omitted from
an operation packet. Consensus classification can still be wrong or
unresolved. CollisionLock only protects downstream systems that actually
require successful lock acquisition before operating; it cannot stop an
off-chain agent from ignoring the protocol.
