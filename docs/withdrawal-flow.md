# Withdrawal flow (wrapped GLC → GLC)

Status: on-chain part implemented in Phase 3; payout side gated on
custody.md.

## On-chain (implemented, Phase 3)

`burn_wrapped(amount, glc_address)`:

1. Checks: not paused; `amount > 0` and `≥ min_withdrawal`; `glc_address`
   is 1–64 opaque ASCII bytes (semantic format validation deferred to
   Phase 4 → `goldcoin-rpc-notes.md`); withdrawal counter increments with
   checked arithmetic.
2. Burns `amount` from the caller's associated token account
   (`BurnChecked`).
3. Creates the `WithdrawalRequest` PDA seeded by the monotonic index from
   `BridgeConfig`: `{ index, amount, requester, glc_address,
   requested_at_slot, status: Pending, … }` (180 bytes, ADR-0010).
4. Emits `WithdrawalRequested` — convenience only; the ACCOUNT is the record
   (ADR-0006). Status write-back (`Broadcast`/`Completed`) is deliberately
   not implemented yet; every record stays `Pending` until the payout side
   exists.

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
