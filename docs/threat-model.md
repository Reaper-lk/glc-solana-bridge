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
| **Admin rotates validator set to attacker keys** — governance key is an indirect mint capability | Unchanged interim risk since Phase 1: rotation is visible on-chain, epoch-bumping, and pause-independent; resolved by custody decisions #1/#7 (threshold-gated + timelocked governance) |
| **Key material leakage** | No keys in repo at any phase; signer code isolated in relayer; `.gitignore` guards; TSS/vault signing out of scope until custody decided |
| **Dependency/supply chain** | cargo-deny in CI on both workspaces (Phase 0); on-chain workspace structurally isolated from network deps (ADR-0001) |

## Standing invariants (testable from Phase 2 on)

1. Total wrapped supply ≤ total confirmed vault deposits − completed payouts.
2. A `(txid, vout)` pair mints at most once, ever.
3. Every burn has exactly one `WithdrawalRequest` account, forever queryable.
4. No instruction path mints without a valid M-of-N proof over the exact
   claim bytes. (Holds from Phase 3: the only mint path verifies threshold
   signatures over the canonical message via the ed25519 precompile;
   the admin-signed test path was deleted.)
