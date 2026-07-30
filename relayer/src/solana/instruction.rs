//! Hand-built `mint_wrapped` instruction encoding (owner decision R1,
//! ADR-0012): discriminator + Borsh-encoded args + raw account metas, with
//! **no dependency on the on-chain `glc-bridge` crate**. This keeps the
//! relayer workspace genuinely independent of anchor-lang, matching
//! ADR-0001's isolation intent, and mirrors this codebase's established
//! preference for hand-rolled encodings over trusting an external shape
//! (the same choice already made for the Goldcoin RPC client, ADR-0011).
//!
//! Every seed byte string and account order below is a verbatim copy of
//! `programs/glc-bridge/src/constants.rs` and
//! `programs/glc-bridge/src/instructions/mint_wrapped.rs` — this is the
//! single place that copy must be kept in sync if the on-chain program's
//! accounts or seeds ever change.

use sha2::{Digest, Sha256};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
#[allow(deprecated)]
use solana_sdk::system_program;
use solana_sdk::sysvar;

/// Verbatim copies of `programs/glc-bridge/src/constants.rs`.
pub const SEED_BRIDGE_CONFIG: &[u8] = b"bridge_config";
pub const SEED_VALIDATOR_SET: &[u8] = b"validator_set";
pub const SEED_MINT_AUTHORITY: &[u8] = b"mint_authority";
pub const SEED_DEPOSIT_CLAIM: &[u8] = b"deposit_claim";

/// SPL Token program id (classic, not Token-2022 — owner decision U5,
/// Phase 2). Sourced from the `spl-token` crate's own constant rather than
/// a hand-typed base58 string, to eliminate any risk of a transcription
/// error in a 44-character address.
pub const TOKEN_PROGRAM_ID: Pubkey = spl_token::ID;
/// The Instructions sysvar address the on-chain program pins against,
/// sourced from `solana-sdk` directly for the same reason.
pub const INSTRUCTIONS_SYSVAR_ID: Pubkey = sysvar::instructions::ID;

pub fn bridge_config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_BRIDGE_CONFIG], program_id)
}

pub fn validator_set_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_VALIDATOR_SET], program_id)
}

pub fn mint_authority_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_MINT_AUTHORITY], program_id)
}

pub fn deposit_claim_pda(program_id: &Pubkey, txid: &[u8; 32], vout: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SEED_DEPOSIT_CLAIM, txid.as_slice(), &vout.to_le_bytes()],
        program_id,
    )
}

/// The 8-byte Anchor instruction discriminator: `sha256("global:<name>")[..8]`
/// — the exact convention this codebase already relies on elsewhere (e.g.
/// `relayer/tests/regtest_indexer.rs`'s discriminator computation from
/// Phase 4).
fn anchor_discriminator(name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}

#[allow(clippy::too_many_arguments)]
pub struct MintWrappedAccounts {
    pub submitter: Pubkey,
    pub bridge_config: Pubkey,
    pub validator_set: Pubkey,
    pub deposit_claim: Pubkey,
    pub wrapped_mint: Pubkey,
    pub mint_authority: Pubkey,
    pub recipient: Pubkey,
    pub recipient_token_account: Pubkey,
}

/// Builds the `mint_wrapped` instruction. Account order and mutability
/// flags are a verbatim copy of the on-chain `MintWrapped` accounts struct
/// (see module docs) — this must be kept in sync by hand since there is no
/// generated IDL dependency to enforce it automatically.
pub fn mint_wrapped_instruction(
    program_id: &Pubkey,
    accounts: &MintWrappedAccounts,
    txid: [u8; 32],
    vout: u32,
    amount: u64,
    epoch: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 4 + 8 + 8);
    data.extend_from_slice(&anchor_discriminator("mint_wrapped"));
    data.extend_from_slice(&txid);
    data.extend_from_slice(&vout.to_le_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&epoch.to_le_bytes());

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(accounts.submitter, true),
            AccountMeta::new_readonly(accounts.bridge_config, false),
            AccountMeta::new_readonly(accounts.validator_set, false),
            AccountMeta::new(accounts.deposit_claim, false),
            AccountMeta::new(accounts.wrapped_mint, false),
            AccountMeta::new_readonly(accounts.mint_authority, false),
            AccountMeta::new_readonly(accounts.recipient, false),
            AccountMeta::new(accounts.recipient_token_account, false),
            AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminator_matches_the_anchor_convention_used_elsewhere_in_this_repo() {
        // Cross-checked against the exact formula
        // relayer/tests/regtest_indexer.rs (Phase 4) used for the OLD
        // mint_wrapped_testonly discriminator: sha256("global:<name>")[..8].
        let d = anchor_discriminator("mint_wrapped");
        let expected = Sha256::digest(b"global:mint_wrapped");
        assert_eq!(d, expected[..8]);
    }

    #[test]
    fn instruction_data_layout_is_discriminator_then_borsh_args() {
        let program_id = Pubkey::new_unique();
        let accounts = MintWrappedAccounts {
            submitter: Pubkey::new_unique(),
            bridge_config: Pubkey::new_unique(),
            validator_set: Pubkey::new_unique(),
            deposit_claim: Pubkey::new_unique(),
            wrapped_mint: Pubkey::new_unique(),
            mint_authority: Pubkey::new_unique(),
            recipient: Pubkey::new_unique(),
            recipient_token_account: Pubkey::new_unique(),
        };
        let txid = [0xAB; 32];
        let ix = mint_wrapped_instruction(&program_id, &accounts, txid, 3, 50_000, 7);
        assert_eq!(ix.data.len(), 8 + 32 + 4 + 8 + 8);
        assert_eq!(&ix.data[8..40], &txid);
        assert_eq!(&ix.data[40..44], &3u32.to_le_bytes());
        assert_eq!(&ix.data[44..52], &50_000u64.to_le_bytes());
        assert_eq!(&ix.data[52..60], &7u64.to_le_bytes());
    }

    #[test]
    fn account_order_and_mutability_matches_onchain_struct() {
        let program_id = Pubkey::new_unique();
        let accounts = MintWrappedAccounts {
            submitter: Pubkey::new_unique(),
            bridge_config: Pubkey::new_unique(),
            validator_set: Pubkey::new_unique(),
            deposit_claim: Pubkey::new_unique(),
            wrapped_mint: Pubkey::new_unique(),
            mint_authority: Pubkey::new_unique(),
            recipient: Pubkey::new_unique(),
            recipient_token_account: Pubkey::new_unique(),
        };
        let ix = mint_wrapped_instruction(&program_id, &accounts, [0; 32], 0, 1, 0);
        assert_eq!(ix.accounts.len(), 11);
        let expect = [
            (accounts.submitter, true, true),
            (accounts.bridge_config, false, false),
            (accounts.validator_set, false, false),
            (accounts.deposit_claim, false, true),
            (accounts.wrapped_mint, false, true),
            (accounts.mint_authority, false, false),
            (accounts.recipient, false, false),
            (accounts.recipient_token_account, false, true),
            (INSTRUCTIONS_SYSVAR_ID, false, false),
            (TOKEN_PROGRAM_ID, false, false),
            (system_program::id(), false, false),
        ];
        for (i, (pubkey, is_signer, is_writable)) in expect.into_iter().enumerate() {
            assert_eq!(ix.accounts[i].pubkey, pubkey, "account {i} pubkey");
            assert_eq!(ix.accounts[i].is_signer, is_signer, "account {i} is_signer");
            assert_eq!(
                ix.accounts[i].is_writable, is_writable,
                "account {i} is_writable"
            );
        }
    }

    #[test]
    fn pda_derivations_are_deterministic() {
        let program_id = Pubkey::new_unique();
        assert_eq!(
            bridge_config_pda(&program_id),
            bridge_config_pda(&program_id)
        );
        assert_eq!(
            validator_set_pda(&program_id),
            validator_set_pda(&program_id)
        );
        assert_eq!(
            mint_authority_pda(&program_id),
            mint_authority_pda(&program_id)
        );
        let txid = [1u8; 32];
        assert_eq!(
            deposit_claim_pda(&program_id, &txid, 5),
            deposit_claim_pda(&program_id, &txid, 5)
        );
        assert_ne!(
            deposit_claim_pda(&program_id, &txid, 5).0,
            deposit_claim_pda(&program_id, &txid, 6).0,
            "different vout must derive a different claim PDA"
        );
    }
}
