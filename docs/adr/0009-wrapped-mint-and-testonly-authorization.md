# ADR-0009: Wrapped-mint creation, freeze authority None, test-only mint authorization

- Status: Accepted (owner decision, 2026-07-29)
- Phase: 2

## Context

Phase 2 implements the Solana side of the deposit path with test assets
only: the wrapped mint must exist, the `DepositClaim` lifecycle must be
real, but production federation proof verification is deliberately Phase 3
work (ADR-0005). Three questions followed:

1. How and when is the wrapped SPL mint created, and by whom?
2. Freeze authority (custody question #6) — required before the mint exists
   (ADR-0004).
3. How is minting authorized in the interim, without anything that could be
   mistaken for production federation verification?

## Decision

**Mint creation.** A dedicated one-time instruction `create_wrapped_mint`
(admin-gated) creates the mint under the classic SPL Token program:
decimals = `WRAPPED_GLC_DECIMALS` (8), mint authority = the data-less
mint-authority PDA (ADR-0004). The address is recorded in
`BridgeConfig.wrapped_mint`; `Pubkey::default()` is the "not yet created"
sentinel, rejected by every mint path. `initialize` stays mint-free
(ADR-0008); runbook order is deploy → initialize → create_wrapped_mint.

**Freeze authority = None** (custody #6, owner decision): the federation
must not be able to freeze user funds. Irreversible per mint by design;
zero cost to revisit before any persistent deployment exists.

**BridgeConfig layout.** `wrapped_mint: Pubkey` and
`mint_authority_bump: u8` were appended after `bump`, consuming 33 of the
64 reserved bytes (reserved is now 31). Every Phase 1 field keeps its byte
offset and total size is unchanged at 164 — pinned by unit test. No
on-chain migration exists to perform: nothing has ever been deployed
persistently, and `PROTOCOL_VERSION` stays 1 (owner decision — version
discipline starts at the first persistent deployment).

**Test-only authorization.** The Phase 2 mint path is the instruction
`mint_wrapped_testonly`, authorized by a plain **admin signature**. It is
explicitly NOT federation verification and is built to be impossible to
mistake for it:

- the `_testonly` suffix travels through the IDL, explorers, and client
  code;
- module and instruction docs open with a TEMPORARY-scaffolding warning;
- the threat model carries a standing row blocking deployment beyond
  localnet while it exists;
- in Phase 3 it is **deleted, not renamed** — the production `mint_wrapped`
  replaces the admin signature with aggregated M-of-N proof verification
  and everything else (claim PDA, pause, min-deposit, epoch binding, ATA
  checks, `MintToChecked` CPI) carries over unchanged.

**Claim semantics** (all enforced and tested): claim PDA seeded
`[SEED_DEPOSIT_CLAIM, txid, vout_le]` with the 32-byte txid used verbatim
(no on-chain byte-order interpretation; convention pinned off-chain,
verified against a real node in Phase 4); recipient's Associated Token
Account required (owner decision — arbitrary token accounts rejected);
amount in atomic GLC units with zero and below-`min_deposit` rejected;
claims bind the validator-set epoch and protocol version; `slot_created`
recorded; `MintToChecked` (not `MintTo`) so the token program re-verifies
decimals.

## Consequences

- Anyone holding the admin key can mint arbitrarily until Phase 3 — the
  dominant standing risk, accepted as scaffolding, mitigated by naming,
  docs, and the no-deployment policy.
- The mint keypair signs only its own creation; afterwards the address is
  fixed in config and the keypair is worthless (authority is the PDA).
- Freeze-authority None means no compliance-freeze capability ever, for
  this mint — revisiting the decision after a persistent deployment would
  require a new mint and a migration.
- ATA-only recipients simplify verification and indexing, at the cost of
  requiring recipients to have their ATA created before minting.
