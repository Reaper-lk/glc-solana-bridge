# ADR-0003: Replay prevention via one PDA per processed claim

- Status: Accepted
- Phase: 0 (implemented Phase 2)

## Context

The blueprint proposed a `ClaimLedger` mapping account checked before
minting. On Solana that design fails structurally: a single account grows
unboundedly toward the 10 MB account cap, its rent must be provisioned up
front, and every mint write-locks the same account, serializing all bridge
throughput.

## Decision

Each processed deposit gets its own `DepositClaim` PDA, seeded by
`SEED_DEPOSIT_CLAIM ++ txid ++ vout_le`. `mint_wrapped` creates the account
in the same instruction that mints; the runtime's "account already exists"
failure IS the replay rejection. No lookup table, no scan.

## Consequences

- O(1) replay check; claims for different deposits execute in parallel.
- Rent per claim (~small, fixed) — funder policy set in Phase 1/2 alongside
  `min_deposit`, so dust deposits can't be used as a rent-drain DoS.
- The claim account doubles as a permanent, queryable audit record of the
  processed deposit.
