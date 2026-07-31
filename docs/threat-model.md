# Threat model

Threat model and standing risks. Updated every phase; anything listed as
OPEN blocks deployment.

## Trust assumptions

- Users trust the federation: any M of N validators can mint wrapped GLC and
  (eventually) spend the vault. This is a federated bridge, not a trustless
  one — stated plainly everywhere user-facing.
- Each validator trusts only its OWN Goldcoin full node and Solana RPC.
- The Anchor program is the final arbiter of mint legitimacy (threshold
  verification + replay guard).

## Principal risks

| Risk | Mitigation (planned phase) |
|---|---|
| **Goldcoin deep reorg / 51%** — low-hashrate PoW; deposit double-spend is the dominant risk | Configurable confirmation depth + per-deposit/rolling-window value caps enforced before `ReadyForSignature`; indexer halts (no further writes) on a reorg deeper than `max_reorg_depth` rather than guessing a fork point (done, Phase 4, ADR-0011). **Production depth/cap numbers remain OPEN** — no built-in defaults exist by design (owner decision U6); this is a live security/ops decision, not an implementation gap. |
| **Upgrade authority = infinite mint** | Multisig custody of upgrade authority, immutability timeline — OPEN (custody.md) |
| **Federation capture (M collude)** | Phase 1: rotations admin-gated, epoch-tracked, invariant-checked (ADR-0007). Threshold-gated + timelocked governance lands with proof verification (3); federation composition OPEN |
| **Initialization front-running** — first caller on a fresh deployment becomes admin | `initialize` restricted to the program upgrade authority via ProgramData check; reinitialization structurally impossible (1, ADR-0008) |
| **Replay of processed deposits** | Per-claim PDA, existence = guard (done, Phase 2); claims additionally bind validator epoch + protocol version |
| **Lost withdrawal events** | Persistent `WithdrawalRequest` accounts are authoritative; events UX-only (3) |
| **Arithmetic overflow** | `overflow-checks = true` in release (done, Phase 0); checked math in program code (done for Phase 1 paths; ongoing) |
| **Dust/PDA-rent DoS** | `min_deposit` / `min_withdrawal` floors; rent funding policy (1) |
| **No emergency stop** | `paused` flag in `BridgeConfig` (done, Phase 1), checked by the mint & burn paths from Phase 2 on; interim pause authority = admin key, final authority/quorum OPEN (custody.md #7) |
| **Ed25519 introspection sharp edges** — instruction-sysvar verification is historically bug-prone | Fixed relative position, self-referential-offset-only entries, exact message equality, full bounds checks; parser unit-tested against malformed payloads (ADR-0010). Focused external review still required before deployment |
| **Threshold exceeds transaction capacity** — a single tx fits ~4 (legacy) / ~7 (v0+ALT) signatures | Liveness-only bound (mints stall, never mint wrongly); documented in ADR-0010; vote-accumulation fallback (ADR-0005) if a larger M is ever needed |
| **Admin rotates validator set to attacker keys** — governance key was an indirect mint capability | **CLOSED (7a, ADR-0014).** `update_validator_set` is deleted; rotation requires an M-of-N federation proof over a canonical governance message plus a configured timelock, and execution is permissionless once matured. No single key can move the federation. Residual: the admin key still gates pause and its own handover (custody #7 remains open) — neither confers a mint capability |
| **Key material leakage** | No keys in repo at any phase; signer code isolated in relayer; `.gitignore` guards; TSS/vault signing out of scope until custody decided |
| **Double payout of one withdrawal** | Four layers (ADR-0013): one payout row per withdrawal (schema PK); an outpoint funds at most one payout (`UNIQUE(txid,vout)`); a pre-signing guard sequence that refuses already-signed/confirmed/completed payouts and drifted reservations; and the Goldcoin UTXO set itself, where a spent input cannot be re-spent (RPC -25) and an identical rebroadcast is a no-op (RPC -27). Only the last is a true security boundary. Every guard is mutation-tested (6) |
| **Payout built from a reversible burn** | Withdrawal discovery is hard-required to run at Solana `finalized` commitment; any other value is a startup error (6, owner decision D5) |
| **Vault drained by the node wallet itself** | OPEN, Phase 6 limitation: the regtest vault address lives in the node wallet, which will spend vault UTXOs for unrelated sends (verified). Database reservations cannot prevent this. Operational rule: the vault wallet must not be used for anything else. Resolved properly only by custody #2/#3 |
| **Withdrawal completion state lost with the relayer database** | OPEN, Phase 6 limitation: on-chain `WithdrawalRequest.status` is never advanced (no write-back instruction exists), so a relayer with no database cannot distinguish paid from unpaid withdrawals from chain state alone (6, owner decision D1) |
| **Dependency/supply chain** | cargo-deny in CI on both workspaces (Phase 0); on-chain workspace structurally isolated from network deps (ADR-0001) |

## Standing invariants (testable from Phase 2 on)

1. Total wrapped supply ≤ total confirmed vault deposits − completed payouts.
2. A `(txid, vout)` pair mints at most once, ever.
3. Every burn has exactly one `WithdrawalRequest` account, forever queryable.
4. No instruction path mints without a valid M-of-N proof over the exact
   claim bytes. (Holds from Phase 3: the only mint path verifies threshold
   signatures over the canonical message via the ed25519 precompile;
   the admin-signed test path was deleted.)
5. A withdrawal is paid at most once. (Holds from Phase 6: one payout row
   per withdrawal and one payout per outpoint are schema constraints; the
   Goldcoin UTXO set is the final arbiter — ADR-0013.)
6. A payout output equals the burned amount exactly — the vault absorbs the
   fee, so a user never receives less than they burned (6, owner decision
   D3; enforced in the pre-signing guards).
7. A signed payout's bytes and txid are durable before any broadcast, so a
   lost broadcast response is always reconcilable and never re-derived.
8. The validator set changes only via an M-of-N-approved proposal that has
   sat through a configured timelock (7a, ADR-0014). No single key — admin
   included — can rotate the federation.
