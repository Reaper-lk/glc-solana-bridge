# ADR-0001: Blueprint-shaped repo layout, two Cargo workspaces

- Status: Accepted (owner decision, 2026-07-28)
- Phase: 0

## Context

Two competing needs: (a) the original blueprint's readable top level
(`programs/ relayer/ shared/ tests/ docker/ docs/`); (b) a hard guarantee
that off-chain dependencies (tokio, reqwest, solana-client, …) can never be
unified into the SBF dependency graph of the on-chain program. A single
workspace satisfies (a) but leaves (b) to discipline; a fully split
`onchain/`/`offchain/` tree satisfies (b) but was rejected by the owner as
over-complicated at top level.

## Decision

Keep the blueprint's top-level directories. Enforce isolation with workspace
boundaries instead of directory boundaries:

- root `Cargo.toml` workspace = `programs/glc-bridge` + `shared` only, with
  `exclude = ["relayer"]`;
- `relayer/Cargo.toml` declares an empty `[workspace]`, making it its own
  workspace root;
- `shared` is a member of the ON-CHAIN workspace (so CI proves it builds for
  SBF) and is consumed by the relayer as a plain path dependency.

## Consequences

- Two lockfiles (root and `relayer/`) — updated independently; CI runs per
  workspace.
- Cargo cannot unify feature flags or versions across the boundary; the
  isolation rule is structural, not conventional.
- `cargo <cmd>` at repo root never touches relayer code and vice versa.
