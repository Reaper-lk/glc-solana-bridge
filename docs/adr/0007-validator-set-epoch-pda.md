# ADR-0007: Validator set in a separate, epoch-tracked singleton PDA

- Status: Accepted (owner decision, 2026-07-29)
- Phase: 1

## Context

The Phase 0 sketch placed the federation keys (`validators` + `threshold`)
inside `BridgeConfig`. Phase 1 had to fix the real layout. Considerations:
the validator set is the one piece of state whose *history* matters — a
Phase 3 M-of-N proof is only meaningful relative to the exact set it was
signed under, and a rotation must invalidate in-flight proofs; the set is
also by far the largest variable-size field, and mixing it into the
governance/config account couples unrelated write paths. A per-epoch PDA
family (one account per revision) was considered and rejected by the owner
in favor of a singleton.

## Decision

The federation lives in its own singleton PDA, `ValidatorSet`
(`SEED_VALIDATOR_SET`), separate from `BridgeConfig`:

- fields: `epoch: u64`, `threshold: u8`, `bump: u8`,
  `validators: Vec<Pubkey>`, `reserved: [u8; 32]`;
- the account is allocated once at `MAX_VALIDATORS = 16` capacity
  (`ValidatorSet::SPACE` = 566 bytes) so rotation never reallocs and rent is
  fixed at initialization;
- `epoch` starts at 0 and is incremented (checked) by every
  `update_validator_set`; the address never changes;
- every write path (initialize and rotation) enforces the same invariants:
  non-empty, ≤ 16, no duplicate keys, no all-zero (default) keys — the
  zero pubkey has no usable signing key, so counting it toward N could make
  the threshold unreachable and stall the bridge — `1 ≤ threshold ≤ len`;
- Phase 1 rotation authority is the interim single admin key (ADR-0008);
  threshold-gated + timelocked governance arrives with proof verification in
  Phase 3 (docs/threat-model.md).

## Consequences

- Phase 3 claim/proof payloads must bind to the epoch they were signed
  under; a rotation strictly invalidates everything signed before it.
- One account read gives the current federation; no per-epoch account
  garbage accumulates. The trade-off: historical sets are not kept on-chain
  (the event stream and L1 history of the config account cover audit needs).
- `MAX_VALIDATORS` is a protocol constant; raising it is a
  `PROTOCOL_VERSION` bump and a migration of the fixed-size account.
