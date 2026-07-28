# Deposit flow (GLC → wrapped GLC)

Status: design notes; implementation Phases 2–3.

## Identity

A deposit is the pair `(txid, vout)` of a confirmed Goldcoin output paying
the vault. Never txid alone (multi-output payments), never a relayer nonce
(not L1-derived). See ADR-0002.

## Recipient binding — OPEN (Phase 1 decision)

The depositor must bind a Solana recipient pubkey to the deposit. Options:

1. **`OP_RETURN` payload** in the deposit transaction carrying the 32-byte
   pubkey. Leading option. Requires verifying Goldcoin (~Bitcoin 0.14 era)
   relays standard `OP_RETURN` up to 80 bytes → Phase 2, recorded in
   `goldcoin-rpc-notes.md`. Malformed/missing payloads → deposit is
   unclaimable; refund policy needed.
2. **Deposit intents registered on Solana first** (user pre-declares an
   expected deposit). No L1 payload needed, but adds a state machine and
   an expiry/collision policy.

## Pipeline (per validator, once implemented)

1. Indexer follows blocks strictly in order; on reorg, rolls back to the fork
   point and re-scans (halts entirely if the reorg exceeds a safety bound).
2. A vault output becomes *claimable* only at depth ≥ N confirmations
   (N is OPEN — see threat-model.md; mempool is never consulted).
3. Validator signs the canonical `InboundClaim` bytes; signatures aggregate
   across the federation (ADR-0005); one relayer submits `mint_wrapped`.
4. Program-side checks, in order: not paused → proof valid for current
   validator set → `DepositClaim` PDA for `(txid, vout)` does not yet exist
   (create = claim; exists = replay, abort) → mint 1:1 to bound recipient.

## Edge cases to cover in tests (Phase 2+)

- Same txid, two vault vouts → two independent claims.
- Reorg drops a deposit after signing but before mint → claim must not
  execute against a vanished output; depth choice + re-check policy.
- Deposit below `min_deposit` → ignored, documented as unrecoverable dust.
- Vault payment with no valid recipient binding → parked; refund policy OPEN.
