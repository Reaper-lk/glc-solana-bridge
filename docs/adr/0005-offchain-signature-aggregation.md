# ADR-0005: Off-chain M-of-N signature aggregation (blueprint retained)

- Status: Accepted (owner decision, 2026-07-28)
- Phase: 0 (implemented Phases 3/5)

## Context

Two candidate federation-approval designs:

1. **Off-chain aggregation (blueprint):** relayers exchange signatures over a
   p2p layer; one relayer submits `mint_wrapped` carrying an aggregated
   M-of-N proof the program verifies.
2. **On-chain vote accumulation (proposed alternative):** each validator
   sends its own `approve_claim` transaction, natively signed; a claim PDA
   accumulates votes until threshold. Eliminates the p2p layer and on-chain
   signature-verification complexity, at the cost of N transactions per
   deposit.

## Decision

The owner chose to retain the blueprint's off-chain aggregation, keeping
Phase 0 a scaffolding exercise rather than a protocol redesign. The relayer
aggregates validator signatures and submits a single proof to the Anchor
program.

## Consequences

- One `mint_wrapped` transaction per deposit; p2p aggregation layer required
  (Phase 5).
- The proof encoding and its on-chain verification path are Phase 3's central
  design problem. Note for that phase: raw in-program ed25519 verification is
  not viable within compute limits — the design must use the ed25519
  precompile with instruction-sysvar introspection (or equivalent), which has
  known sharp edges and needs focused review.
- Option 2 remains documented as the fallback if Phase 3 verification proves
  too costly or risky; revisiting it would supersede this ADR.
