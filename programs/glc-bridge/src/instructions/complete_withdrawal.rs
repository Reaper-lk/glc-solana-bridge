//! `complete_withdrawal` — records that a withdrawal was paid on Goldcoin
//! (Phase 7f, ADR-0018).
//!
//! # What this closes
//!
//! Until now nothing could advance `WithdrawalStatus` past `Pending`, so the
//! only record distinguishing a paid withdrawal from an unpaid one lived in
//! a relayer's local database. ADR-0006's stated property — reconstruct the
//! outstanding queue from chain state alone — held for deposits (the claim
//! PDA's existence is the mint record, ADR-0003) but not for payouts. This
//! instruction restores it.
//!
//! # Authorisation reuses the audited path verbatim
//!
//! Exactly as `mint_wrapped`: the instruction immediately before this one
//! must be the ed25519 precompile carrying >= threshold unique current
//! validators over the canonical completion message. No new authorisation
//! mechanism is introduced — a second one would double the surface Phase 7's
//! threat model has to cover.
//!
//! # Completion is terminal, deliberately
//!
//! There is no reversal path. One would let anyone able to force a Goldcoin
//! reorg *un-complete* a withdrawal and induce a second payout — strictly
//! worse than the problem it solves. A deep reorg after completion is a
//! halt-and-reconcile incident requiring operator judgement, not an
//! automatic on-chain state change (ADR-0018 D4).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::get_instruction_relative;

use glc_bridge_shared::claim::withdrawal_completion_message;

use crate::constants::{SEED_BRIDGE_CONFIG, SEED_VALIDATOR_SET, SEED_WITHDRAWAL};
use crate::errors::BridgeError;
use crate::events::WithdrawalCompleted;
use crate::state::{BridgeConfig, ValidatorSet, WithdrawalRequest, WithdrawalStatus};
use crate::verification::count_unique_validator_signers;

#[derive(Accounts)]
#[instruction(index: u64)]
pub struct CompleteWithdrawal<'info> {
    /// Pays the transaction fee. Confers **no** authority: the federation
    /// proof is what authorises, and this account is not consulted for it.
    #[account(mut)]
    pub submitter: Signer<'info>,

    #[account(seeds = [SEED_BRIDGE_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,

    #[account(seeds = [SEED_VALIDATOR_SET], bump = validator_set.bump)]
    pub validator_set: Account<'info, ValidatorSet>,

    /// The withdrawal being completed. Address-pinned to the PDA its own
    /// index derives, so a caller cannot substitute a different record.
    #[account(
        mut,
        seeds = [SEED_WITHDRAWAL, &index.to_le_bytes()],
        bump = withdrawal.bump,
    )]
    pub withdrawal: Account<'info, WithdrawalRequest>,

    /// CHECK: the Instructions sysvar, address-pinned; read to locate the
    /// ed25519 verification instruction in this transaction.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,
}

pub fn complete_withdrawal(
    ctx: Context<CompleteWithdrawal>,
    index: u64,
    payout_txid: [u8; 32],
    payout_height: u64,
    epoch: u64,
) -> Result<()> {
    let config = &ctx.accounts.bridge_config;
    let validator_set = &ctx.accounts.validator_set;

    require!(!config.paused, BridgeError::BridgePaused);
    require!(
        epoch == validator_set.epoch,
        BridgeError::StaleValidatorEpoch
    );

    // Terminal-state guard. The status field IS the replay guard —
    // structurally identical to the claim PDA's `init` constraint
    // (ADR-0003), and for the same reason: the cheapest replay guard is one
    // that falls out of state you already must store.
    let withdrawal = &ctx.accounts.withdrawal;
    require!(
        withdrawal.status != WithdrawalStatus::Completed,
        BridgeError::WithdrawalAlreadyCompleted
    );
    require!(
        withdrawal.status == WithdrawalStatus::Pending,
        BridgeError::WithdrawalNotPending
    );

    // A non-zero payout region on a Pending withdrawal means an unknown
    // migration already assigned meaning to these bytes. Overwriting them
    // blindly would destroy whatever it wrote, so refuse instead.
    require!(
        withdrawal.payout_record_is_unset(),
        BridgeError::PayoutRecordAlreadySet
    );

    // A zeroed txid or height would record a payout that cannot be looked
    // up on Goldcoin, defeating the auditability this instruction exists
    // for.
    require!(payout_txid != [0u8; 32], BridgeError::ZeroPayoutTxid);
    require!(payout_height > 0, BridgeError::ZeroPayoutHeight);

    // The federation proof, over a message that names the payment: the
    // amount and destination come from the WITHDRAWAL RECORD, never from
    // instruction arguments, so a caller cannot ask validators to attest to
    // one payout and record a different one.
    let verification_ix =
        get_instruction_relative(-1, &ctx.accounts.instructions_sysvar.to_account_info())
            .map_err(|_| BridgeError::MissingSignatureVerification)?;
    require!(
        verification_ix.program_id == anchor_lang::solana_program::ed25519_program::ID,
        BridgeError::MissingSignatureVerification
    );

    // The destination is committed by hashing the address bytes EXACTLY as
    // stored, so the program never needs to interpret an address format.
    // Base58-decoding on-chain to reach a hash160 would be real code and
    // real risk for no benefit: both sides already agree on these bytes.
    let len = usize::from(withdrawal.glc_address_len);
    require!(
        len >= 1 && len <= withdrawal.glc_address.len(),
        BridgeError::InvalidGlcAddressLength
    );
    let dest_commitment: [u8; 32] =
        anchor_lang::solana_program::hash::hash(&withdrawal.glc_address[..len]).to_bytes();

    let expected_message = withdrawal_completion_message(
        config.protocol_version,
        &crate::ID.to_bytes(),
        validator_set.epoch,
        index,
        &payout_txid,
        payout_height,
        withdrawal.amount,
        &dest_commitment,
    );
    let signer_count = count_unique_validator_signers(
        &verification_ix.data,
        &expected_message,
        &validator_set.validators,
    )?;
    require!(
        signer_count >= usize::from(validator_set.threshold),
        BridgeError::InsufficientSignatures
    );

    let amount = withdrawal.amount;
    let withdrawal = &mut ctx.accounts.withdrawal;
    withdrawal.set_payout_record(&payout_txid, payout_height);
    // Status last: every guard above reads it, and writing it earlier would
    // make the ordering of the remaining checks load-bearing.
    withdrawal.status = WithdrawalStatus::Completed;

    emit!(WithdrawalCompleted {
        index,
        payout_txid,
        payout_height,
        amount,
        epoch: validator_set.epoch,
    });

    Ok(())
}
