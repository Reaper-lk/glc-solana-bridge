# Withdrawal flow (wrapped GLC → GLC)

Status: design notes; on-chain part Phase 3, payout side gated on custody.md.

## On-chain (Phase 3)

`burn_wrapped(amount, glc_address)`:

1. Checks: not paused; `amount ≥ min_withdrawal`; `glc_address` well-formed
   (format/version bytes verified in Phase 2 → `goldcoin-rpc-notes.md`).
2. Burns `amount` from the caller's token account.
3. Creates `WithdrawalRequest` PDA seeded by a monotonic index from
   `BridgeConfig`: `{ index, amount, glc_address, requested_at_slot,
   status: Pending }`.
4. Emits `WithdrawalRequested` — convenience only; the ACCOUNT is the record
   (ADR-0006).

Burn-then-record in one atomic instruction: there is no state in which value
was burned without a persistent, queryable payout obligation.

## Off-chain (Phase 5+, signing gated on custody decisions)

1. Relayers discover requests by scanning program accounts — fully
   recoverable after arbitrary downtime, unlike event subscriptions.
2. Wait for finalized commitment on Solana.
3. Construct the GLC payout deterministically (identical across validators:
   canonical UTXO selection + fee policy — OPEN, custody.md #9), gather vault
   signatures (model OPEN, custody.md #3), broadcast.
4. Status transitions `Pending → Broadcast → Completed` (completed = payout
   at required GLC depth). Who writes status updates back on-chain, and under
   what authority, is a Phase 3 design point.

## Failure notes

- Solana finality before broadcast: no payout may be built from a
  non-finalized burn.
- GLC-side reorg after Broadcast: rebroadcast policy; `Completed` only at
  depth.
- Fee spikes: payout must never pay out more than `amount`; fee bearer OPEN.
