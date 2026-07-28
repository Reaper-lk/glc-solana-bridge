# Architecture

Canonical system design. Supersedes the original blueprint where they differ;
each deliberate divergence has an ADR in `docs/adr/`.

## Components

```
Goldcoin L1 (unmodified) ──JSON-RPC──▶ relayer (×N validators) ──tx──▶ Solana
      ▲                                    │  ▲                          │
      └── payout (later phases) ───────────┘  └── p2p sig aggregation ───┘
```

- **`programs/glc-bridge`** — Anchor program. Sole authority over the wrapped
  GLC mint via a PDA. Verifies the federation's aggregated M-of-N proof,
  enforces replay prevention, records withdrawals persistently.
- **`shared`** — SBF-safe types crate; the only code linked into both worlds.
- **`relayer`** — one instance per federation member, run beside that
  member's own Goldcoin full node. Own Cargo workspace (ADR-0001).

## Inbound: GLC → wrapped GLC

1. User sends GLC to the federation vault address, binding their Solana
   recipient pubkey to the deposit (binding mechanism is an open Phase 1
   decision — leading option: 32-byte `OP_RETURN` payload; see
   `deposit-flow.md`).
2. Each relayer independently observes the deposit at **confirmed depth ≥ N**
   (mempool is never an input) and identifies it as `(txid, vout)`.
3. Relayers sign the `InboundClaim` and aggregate M-of-N signatures over the
   p2p layer (ADR-0005).
4. One relayer submits `mint_wrapped` with the aggregated proof. The program:
   verifies the proof against the registered validator set; creates the
   `DepositClaim` PDA seeded by `(txid, vout)` — creation failure = replay
   (ADR-0003); mints 1:1 to the recipient via the PDA mint authority
   (ADR-0004).

## Outbound: wrapped GLC → GLC

1. User calls `burn_wrapped(amount, glc_address)`: tokens are burned and a
   **persistent `WithdrawalRequest` account** is created with status
   `Pending` (ADR-0006). An event is emitted for UX only.
2. Relayers discover requests by scanning program accounts (recoverable after
   downtime), wait for Solana finality, then construct/sign/broadcast the GLC
   payout — the signing model is deliberately undecided (`custody.md`) and
   out of scope until then. Status advances `Pending → Broadcast → Completed`.

## Implementation phases

| Phase | Deliverable |
|---|---|
| 0 | This scaffold. No logic. |
| 1 | `shared` types finalized (borsh alignment), program state + `initialize` + admin/pause, litesvm tests |
| 2 | Deposit path on-chain: claim PDA lifecycle; Goldcoin RPC facts verified (`goldcoin-rpc-notes.md`) |
| 3 | Federation proof format + on-chain verification; `burn_wrapped` + withdrawal records |
| 4 | `relayer` Goldcoin indexer against regtest: depth tracking, reorg rollback |
| 5 | Relayer orchestration + p2p signature aggregation (no vault signing) |
| 6 | E2E harness: regtest deposit → localnet mint; burn → payout record |
| — | Vault custody design, audits, devnet/mainnet: gated on `custody.md`, outside this plan |
