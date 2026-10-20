# CollisionLock architecture

## State model

Each lock has one of three states:

```text
ACTIVE -> CLOSED   (voluntary by owner)
ACTIVE -> EXPIRED  (forced by anyone after epoch-based TTL)
```

Only the owner may perform the ACTIVE → CLOSED transition. Anyone may perform
the ACTIVE → EXPIRED transition once the lock's age in epochs reaches
`LOCK_MAX_EPOCH_AGE`. A closed or expired record remains readable for audit and
its packet may be acquired again with a new lock ID.

## Lifecycle mechanism

The contract enforces two admission controls to prevent permanent slot
exhaustion:

1. **Per-owner cap** (`MAX_ACTIVE_PER_OWNER = 8`): No single address may hold
   more than 8 active locks simultaneously. An attacker must use at least 4
   Sybil addresses (each paying gas) to fill all 32 slots.

2. **Epoch-based TTL** (`LOCK_MAX_EPOCH_AGE = 64`): A monotonic `epoch` counter
   advances on every successful public write (`acquire_lock`, `close_lock`,
   `extend_lock`, `reap_expired_lock`, `touch`). Each lock records its
   `acquired_at_epoch`. Once `epoch - acquired_at_epoch >= LOCK_MAX_EPOCH_AGE`,
   anyone may call `reap_expired_lock` to transition the lock to EXPIRED and
   free the active slot.

   - **`touch()`** advances the epoch with no other side effect. This allows
     any caller to age locks toward expiry when no other writes are occurring
     (e.g., during a DoS scenario where all slots are full).
   - **`extend_lock(lock_id)`** is owner-only and resets the lock's epoch to the
     current epoch, proving the owner still needs the lock. Legitimate owners
     only need one `extend_lock` call per TTL window.

### DoS recovery cost

If an attacker fills all 32 slots (requiring 4 addresses × 8 locks each = 32
acquire transactions), a legitimate user recovers by:

1. Calling `touch()` approximately `LOCK_MAX_EPOCH_AGE - 32 = 32` times.
2. Calling `reap_expired_lock()` on the oldest lock (1 transaction).
3. Calling `acquire_lock()` to take the freed slot (1 transaction).

Total recovery cost: ~34 transactions. After the first reap, subsequent expired
locks cascade — each successful reap advances the epoch, making the next lock
immediately reapable.

## Storage model

```text
locks: TreeMap[lock_id, LockRecord]
fingerprint_index: TreeMap[operation_sha256, latest_lock_id]
active_ids_json: compact list of currently ACTIVE lock IDs
epoch: monotonic interaction counter for TTL enforcement
```

The registry is capped at 1024 historical records and 32 active records.
`active_ids_json` is authoritative and is compacted on closure or reaping; a
non-active record in it is an invariant failure rather than a silently ignored
stale ID.

## Consensus boundaries

Each acquisition has one consensus assessment. Inside that single
`run_nondet` boundary, the leader and validators independently derive the
route, rank the complete active set, and return a comparison list aligned to
the exact candidate IDs. Neither model call returns a final lock decision.
Contract code validates shape, enum membership, booleans, status, count, and
ordering before deriving the final relation. Keeping both steps inside one
boundary is required by the Studio Dev runtime.

All operation text is delimited as untrusted data in prompts. Prompt
injection, fake role messages, requested answers, and model-provided final
booleans are treated as data or rejected as malformed output.

## Retrieval safety

The route has four dimensions and produces a stable ranking. Retrieval does
not filter on route and does not use caller-selected buckets. The contract
compares all current active IDs, at most 32, so the hard comparison bound is
the active capacity itself. This is intentionally more conservative than a
small top-K shortlist while remaining finite and storage-bounded.
