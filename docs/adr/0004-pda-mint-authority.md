# ADR-0004: PDA mint authority for the wrapped token

- Status: Accepted
- Phase: 0 (implemented Phase 1)

## Context

The blueprint says the program "holds exclusive mint and freeze authority".
Programs don't hold keys; the precise mechanism matters because any
keypair-based mint authority is a standing single-key custody risk.

## Decision

At `initialize`, the wrapped SPL mint's authority is set to a PDA
(`SEED_MINT_AUTHORITY`). Minting happens only via `invoke_signed` inside
`mint_wrapped` after proof + replay checks. No private key for the mint
authority exists anywhere.

Freeze authority is NOT decided here: `None` (censorship-resistance) vs a
governance PDA is custody question #6 (`custody.md`), resolved before
`initialize` is implemented.

## Consequences

- The only path to new supply is the program's own checked instruction; the
  mint cannot be operated out-of-band even by federation members.
- The remaining supply-inflation vector is the program upgrade authority —
  tracked separately (custody.md #5).
