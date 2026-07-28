# ADR-0006: Withdrawals are persistent accounts; events are advisory

- Status: Accepted
- Phase: 0 (implemented Phase 3)

## Context

The blueprint's outbound flow relies on relayers subscribing to
`BurnWrapped` log events. Solana logs are unfit as the sole record of a
payout obligation: log delivery over RPC subscriptions is best-effort,
transaction logs are truncated beyond a size cap, and history ages out of
non-archival nodes. A missed event would equal user funds burned with no
recorded obligation to pay out.

## Decision

`burn_wrapped` atomically burns AND creates a `WithdrawalRequest` PDA
(monotonic-index seed) holding amount, GLC destination, slot, and a status
field (`Pending → Broadcast → Completed`). Relayers treat account scans as
the source of truth; events exist only to cut latency and serve UIs.

## Consequences

- A relayer offline for any duration reconstructs the full outstanding
  payout queue from chain state alone.
- Every withdrawal is permanently auditable on-chain.
- Rent cost per withdrawal; whether records are ever closed/compressed after
  `Completed` (and who reclaims rent) is a Phase 3 decision.
- Status write-back authority (who may mark `Broadcast`/`Completed`) is a
  Phase 3 design point with governance implications.
