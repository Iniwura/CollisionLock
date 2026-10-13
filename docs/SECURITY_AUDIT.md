# Hostile security audit

## Scope

This audit covers packet validation, exact identity, consensus handling,
active-index maintenance, ownership, and semantic conflict derivation in the
v1 contract.

## Findings and controls

| Threat | Control | Result |
| --- | --- | --- |
| Caller chooses routing buckets | Route is derived by consensus from the packet; no route argument exists | Mitigated |
| Relevant lock falls outside top-K | The candidate set is every active ID, capped at 32; route only orders it | Mitigated within the documented bound |
| Bucket spam hides a conflict | There are no caller-controlled buckets and no route filtering | Mitigated |
| Closed lock keeps blocking | Close physically compacts `active_ids_json` and state is authoritative | Mitigated |
| Prompt injection changes route or projection | Untrusted-data delimiters, exact result shape, enum validation, validator recomputation | Mitigated subject to consensus quality |
| Same owner bypasses collision | No owner exemption or force flag; all active locks are compared | Mitigated |
| Dependency conflict has different resources | `dependency_interference` and `ordering_required` are independent conflict inputs | Mitigated when facts are correctly supplied |
| Unresolved result acquires | `UNRESOLVED` is derived and rejected | Mitigated |
| Validator disagreement acquires | `run_nondet` validator must reproduce exact normalized output | Mitigated |
| Rejected write mutates storage | Persistent writes occur only after all consensus and relation checks | Mitigated and regression-tested |
| Another wallet closes a lock | Owner is stored from `gl.message.sender_address` and checked on close | Mitigated |
| Exact fingerprints block history forever | Only an ACTIVE matching fingerprint is rejected; CLOSED history can be reacquired | Mitigated |
| Model directly decides final state | Model cannot return `relation` or `conflict`; contract derives it | Mitigated |

## Residual risks

The packet is an input commitment, not an omniscient description of an
off-chain system. A caller can omit a dependency or provide an ambiguous
description; the model may then return an incomplete or incorrect structural
projection. The 32-active bound is finite by design, and operations submitted
outside the protocol are not controlled. High-value integrations should add
off-chain policy checks and require successful lock acquisition before acting.
