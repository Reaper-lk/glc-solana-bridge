# ADR-0010: Federation proof format and on-chain ed25519 verification

- Status: Accepted (owner decision, 2026-07-29)
- Phase: 3

## Context

ADR-0005 committed to off-chain M-of-N signature aggregation with a single
`mint_wrapped` submission, and flagged on-chain verification as Phase 3's
central design problem: raw in-program ed25519 is not viable within compute
limits, so the design must use the ed25519 precompile with
instruction-sysvar introspection — a mechanism with known sharp edges.
ADR-0009's admin-signed test scaffolding had to be deleted and replaced.

## Decision

**Canonical signed message** (`shared::claim`, 166 bytes, all integers LE,
txid verbatim): domain tag `"GLC_BRIDGE_CLAIM"` (16) ‖ protocol version (1)
‖ program id (32) ‖ validator-set epoch (8) ‖ action type (1,
`ACTION_MINT_DEPOSIT = 0x01`) ‖ txid (32) ‖ vout (4) ‖ amount (8) ‖
recipient (32) ‖ wrapped mint (32). A signature therefore authorizes exactly
one action on one deposit for one recipient/amount, on one deployment,
under one validator-set revision; any field change is a different byte
string. The builder lives in the shared crate (owner decision U6) — it is
the byte-exact contract between validators (Phase 5 relayer signing) and
the program. The layout is pinned by a golden-vector unit test; changing it
is a signature-breaking protocol event.

**Verification** (`verification.rs` + `mint_wrapped`): the transaction
carries one ed25519-precompile instruction **immediately before**
`mint_wrapped`. The runtime verifies all signatures before execution; the
program then proves what was verified:

- the instruction at relative −1 must be the ed25519 program (fixed
  position, no searching);
- strict parse of the precompile payload: every offset bounds-checked with
  checked arithmetic, padding byte enforced, at least one entry;
- every entry must be fully self-referential (`u16::MAX` instruction
  indices) — entries may never point into other instructions' data;
- every entry's message must be byte-identical to the expected message the
  program computes from its own state and the instruction arguments;
- every signer must be a current validator (unknown signer = hard error,
  not a skip) and duplicates are hard errors (u16 bitmask over validator
  indices, sound because `MAX_VALIDATORS = 16`);
- unique count ≥ threshold. No signature ordering is required (owner
  decision U5): the bitmask makes order irrelevant.

Extra unrelated ed25519 instructions elsewhere in the transaction are
ignored — they can neither contribute approvals nor break a valid proof.

**Submission** is permissionless (owner decision U7): a valid proof is the
only authority; the submitter pays fees and claim rent. All Phase 2 checks
(pause, min-deposit, zero amount, configured mint, ATA-only recipient,
claim-PDA replay guard, `MintToChecked`) carry over unchanged, and
`mint_wrapped_testonly` is deleted from the binary and IDL — a transaction
with its old discriminator fails at dispatch (tested).

**Transaction-size bound** (owner decision U1): each signature entry costs
110 bytes in the precompile payload (64 sig + 32 pubkey + 14 offsets) plus
a fixed ~168 (header + shared message). With the mint's account keys, a
legacy transaction fits **M ≤ 4** signatures; v0 + address lookup tables
reach **M ≈ 6–7**. This bounds the *threshold*, not the set size — N = 16
remains valid. It is a liveness bound only (too-large M = no mints, never
wrong mints). If a future federation needs a larger M, ADR-0005's
documented fallback (on-chain vote accumulation) supersedes this mechanism.

**Withdrawals** (same phase): `burn_wrapped` burns via `BurnChecked` from
the user's ATA (owner decision U4) and atomically creates the persistent
`WithdrawalRequest` PDA (`[b"withdrawal", index LE]`, 180 bytes) per
ADR-0006 — index from the checked-increment `withdrawal_count`. The GLC
destination is opaque ASCII ≤ 64 bytes until Phase 4 verifies the real
address format (owner decision U3). Status is always `Pending` in Phase 3:
write-back instructions and their authority model are deferred (owner
decision U2).

## Consequences

- Validator-set rotation is a cryptographic kill-switch: epoch is inside
  the signed bytes, so outstanding proofs die on rotation even if the keys
  are unchanged (tested), at the liveness cost of re-signing.
- Cross-deployment replay is impossible: the program id is inside the
  signed bytes (tested from the receiving side).
- The threshold a transaction can carry is size-bounded (above); the
  program enforces no extra cap, so governance must keep M within transport
  limits or mints stall.
- The admin retains governance only (pause, rotation, handover). Rotation
  remains an indirect mint capability for a compromised admin — unchanged
  since Phase 1, tracked in the threat model, resolved by the custody
  decisions.
- ADR-0009's authorization section is superseded; its mint-creation and
  freeze-authority decisions stand.
