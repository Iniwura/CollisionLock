# CollisionLock architecture

## State model

Each lock has one of two states:

```text
ACTIVE -> CLOSED
```

Only the owner may perform the transition. There is no contract-enforced
expiry because Studio Dev does not expose an authoritative enforceable clock
for this purpose. A closed record remains readable for audit and its packet may
be acquired again with a new lock ID.

## Storage model

```text
locks: TreeMap[lock_id, LockRecord]
fingerprint_index: TreeMap[operation_sha256, latest_lock_id]
active_ids_json: compact list of currently ACTIVE lock IDs
```

The registry is capped at 1024 historical records and 32 active records.
`active_ids_json` is authoritative and is compacted on closure; a non-active
record in it is an invariant failure rather than a silently ignored stale ID.

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
