/**
 * End-to-end integration suite — Phase 6 placeholder.
 *
 * No test harness dependencies (anchor TS client, mocha, package.json) are
 * added until Phase 6 to keep the scaffold lean; `anchor test` currently
 * prints a notice (see Anchor.toml [scripts]).
 *
 * Planned coverage (regtest Goldcoin + solana-test-validator; harness
 * composition documented in docker/README.md, implemented Phase 4/6):
 *  1. deposit lifecycle: fund regtest vault → mine N confirmations →
 *     federation proof → mint_wrapped → wrapped balance == deposit amount
 *  2. replay: resubmitting the same (txid, vout) proof fails
 *  3. multi-vout: one GLC tx paying the vault twice mints two claims
 *  4. withdrawal: burn_wrapped → persistent WithdrawalRequest with status
 *     Pending, correct amount + GLC address
 *  5. pause: paused bridge rejects mint and burn paths
 */

export {};
