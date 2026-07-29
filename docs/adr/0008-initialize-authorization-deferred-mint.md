# ADR-0008: Upgrade-authority-gated initialization; mint creation deferred

- Status: Accepted (owner decision, 2026-07-29)
- Phase: 1

## Context

Two Phase 1 questions about `initialize`:

1. **Who may call it?** The state PDAs are singletons with fixed seeds, so on
   a fresh deployment the first successful `initialize` wins. First-caller-
   wins would let anyone who front-runs the deployer become admin and set an
   attacker federation — rejected by the owner.
2. **Does it create the wrapped SPL mint?** ADR-0004 requires the
   freeze-authority question (docs/custody.md #6) to be resolved before the
   mint exists, and that custody decision is deliberately still open.

## Decision

- `initialize` is authorized against the loader-v3 **ProgramData** account:
  the signer must equal `program_data.upgrade_authority_address`, and the
  passed ProgramData account must be the one recorded in the program's own
  executable account (so it cannot be substituted). The initializer becomes
  the initial admin.
- The admin is an **interim single key**: it gates pause, validator-set
  rotation, and handover until the custody decisions (docs/custody.md #1/#7)
  replace or constrain it. Handover is two-step (`transfer_admin` →
  `accept_admin` by the proposed key) so a typoed pubkey cannot brick
  governance.
- Reinitialization is structurally impossible: both PDAs are created with
  Anchor `init`, which fails if the account exists. No `is_initialized`
  flag to get wrong.
- The wrapped SPL mint is **not** created in Phase 1. ADR-0004's PDA
  mint-authority mechanism is unchanged, but mint creation moves to Phase 2,
  after custody #6 (freeze authority) is decided. `BridgeConfig` reserves
  expansion space for the `wrapped_mint` field.

## Consequences

- A deployment whose upgrade authority has already been burned (immutable
  program) can never be initialized — the runbook order is deploy →
  initialize → hand over admin → (eventually) revoke upgrade authority
  (custody.md #5).
- Test harnesses must install the program under the upgradeable loader with
  a test-controlled upgrade authority (done via crafted loader-v3 accounts
  in litesvm).
- Phase 2's mint-creation instruction will carry its own ADR entry or amend
  ADR-0004 once custody #6 is decided.
