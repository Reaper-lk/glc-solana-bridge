//! Phase 2 integration tests: wrapped-mint creation and the deposit-claim
//! mint path (`mint_wrapped_testonly` — TEMPORARY admin-authorized test
//! scaffolding, see ADR-0009). Harness lives in `common`.

mod common;
use common::*;

use anchor_spl::associated_token::get_associated_token_address;
use anchor_spl::token::spl_token;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

use glc_bridge::constants::{PROTOCOL_VERSION, SEED_DEPOSIT_CLAIM, WRAPPED_GLC_DECIMALS};
use glc_bridge::errors::BridgeError;
use glc_bridge::state::DepositClaim;

const TXID_A: [u8; 32] = [0xAA; 32];

/// Full happy-path fixture: initialized bridge, wrapped mint, funded
/// recipient wallet with its ATA pre-created.
fn setup_ready(authority: &Keypair) -> (litesvm::LiteSVM, Pubkey, Pubkey, Pubkey) {
    let (mut svm, mint) = setup_with_mint(authority, 3, 2);
    let recipient = Pubkey::new_unique();
    let ata = create_ata(&mut svm, &recipient, &mint);
    (svm, mint, recipient, ata)
}

// ------------------------------------------------------ create_wrapped_mint --

#[test]
fn create_wrapped_mint_happy_path() {
    let authority = Keypair::new();
    let (svm, mint) = setup_with_mint(&authority, 3, 2);

    let config = get_config(&svm);
    assert_eq!(config.wrapped_mint, mint);
    let (expected_authority, expected_bump) = Pubkey::find_program_address(
        &[glc_bridge::constants::SEED_MINT_AUTHORITY],
        &glc_bridge::ID,
    );
    assert_eq!(expected_authority, mint_authority_pda());
    assert_eq!(config.mint_authority_bump, expected_bump);

    let state = mint_state(&svm, &mint);
    assert_eq!(state.decimals, WRAPPED_GLC_DECIMALS);
    assert_eq!(state.supply, 0);
    assert_eq!(
        state.mint_authority,
        Some(mint_authority_pda()).into(),
        "mint authority must be the PDA"
    );
    assert_eq!(
        state.freeze_authority,
        None.into(),
        "freeze authority must be None (custody #6)"
    );
}

#[test]
fn create_wrapped_mint_rejects_second_call() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_with_mint(&authority, 3, 2);
    let second = Keypair::new();
    assert_bridge_error(
        send(
            &mut svm,
            create_wrapped_mint_ix(&authority.pubkey(), &second.pubkey()),
            &authority,
            &[&second],
        ),
        BridgeError::MintAlreadyConfigured,
    );
}

#[test]
fn create_wrapped_mint_rejects_non_admin() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);
    let intruder = Keypair::new();
    svm.airdrop(&intruder.pubkey(), 10_000_000_000).unwrap();
    let mint = Keypair::new();
    assert_bridge_error(
        send(
            &mut svm,
            create_wrapped_mint_ix(&intruder.pubkey(), &mint.pubkey()),
            &intruder,
            &[&mint],
        ),
        BridgeError::UnauthorizedAdmin,
    );
    assert_eq!(get_config(&svm).wrapped_mint, Pubkey::default());
}

// ---------------------------------------------------- mint_wrapped_testonly --

#[test]
fn mint_testonly_happy_path() {
    let authority = Keypair::new();
    let (mut svm, mint, recipient, ata) = setup_ready(&authority);
    svm.warp_to_slot(4242);

    send(
        &mut svm,
        mint_testonly_ix(
            &authority.pubkey(),
            &mint,
            &recipient,
            &ata,
            TXID_A,
            1,
            50_000,
            0,
        ),
        &authority,
        &[],
    )
    .expect("mint should succeed");

    assert_eq!(token_balance(&svm, &ata), 50_000);
    assert_eq!(mint_state(&svm, &mint).supply, 50_000);

    let claim = get_claim(&svm, &TXID_A, 1);
    assert_eq!(claim.txid, TXID_A);
    assert_eq!(claim.vout, 1);
    assert_eq!(claim.amount, 50_000);
    assert_eq!(claim.recipient, recipient);
    assert_eq!(claim.epoch, 0);
    assert_eq!(claim.protocol_version, PROTOCOL_VERSION);
    assert_eq!(claim.slot_created, 4242);
    assert_eq!(claim.reserved, [0u8; 16]);
    let (_, expected_bump) = Pubkey::find_program_address(
        &[SEED_DEPOSIT_CLAIM, TXID_A.as_ref(), &1u32.to_le_bytes()],
        &glc_bridge::ID,
    );
    assert_eq!(claim.bump, expected_bump);
}

#[test]
fn claim_account_allocates_exactly_documented_space() {
    let authority = Keypair::new();
    let (mut svm, mint, recipient, ata) = setup_ready(&authority);
    send(
        &mut svm,
        mint_testonly_ix(
            &authority.pubkey(),
            &mint,
            &recipient,
            &ata,
            TXID_A,
            0,
            10_000,
            0,
        ),
        &authority,
        &[],
    )
    .unwrap();
    let account = svm.get_account(&claim_pda(&TXID_A, 0)).unwrap();
    assert_eq!(account.data.len(), DepositClaim::SPACE);
    assert_eq!(account.owner, glc_bridge::ID);
}

#[test]
fn replay_of_same_deposit_fails_and_mints_nothing_extra() {
    let authority = Keypair::new();
    let (mut svm, mint, recipient, ata) = setup_ready(&authority);
    let ix = |amount: u64| {
        mint_testonly_ix(
            &authority.pubkey(),
            &mint,
            &recipient,
            &ata,
            TXID_A,
            7,
            amount,
            0,
        )
    };
    send(&mut svm, ix(30_000), &authority, &[]).expect("first mint succeeds");

    svm.expire_blockhash();
    let result = send(&mut svm, ix(30_000), &authority, &[]);
    assert!(result.is_err(), "replay must fail at claim creation");
    // Different amount, same (txid, vout): still replay.
    let result = send(&mut svm, ix(99_999), &authority, &[]);
    assert!(result.is_err(), "replay with different amount must fail");

    assert_eq!(token_balance(&svm, &ata), 30_000);
    assert_eq!(mint_state(&svm, &mint).supply, 30_000);
    assert_eq!(get_claim(&svm, &TXID_A, 7).amount, 30_000);
}

#[test]
fn same_txid_different_vout_mints_independently() {
    let authority = Keypair::new();
    let (mut svm, mint, recipient, ata) = setup_ready(&authority);
    for (vout, amount) in [(0u32, 10_000u64), (1, 20_000)] {
        send(
            &mut svm,
            mint_testonly_ix(
                &authority.pubkey(),
                &mint,
                &recipient,
                &ata,
                TXID_A,
                vout,
                amount,
                0,
            ),
            &authority,
            &[],
        )
        .expect("each vout is an independent deposit");
    }
    assert_eq!(token_balance(&svm, &ata), 30_000);
    assert_eq!(get_claim(&svm, &TXID_A, 0).amount, 10_000);
    assert_eq!(get_claim(&svm, &TXID_A, 1).amount, 20_000);
}

#[test]
fn claim_pda_uses_little_endian_vout() {
    let authority = Keypair::new();
    let (mut svm, mint, recipient, ata) = setup_ready(&authority);
    // Non-palindromic vout: LE and BE derivations differ.
    let vout: u32 = 0x0102_0304;
    send(
        &mut svm,
        mint_testonly_ix(
            &authority.pubkey(),
            &mint,
            &recipient,
            &ata,
            TXID_A,
            vout,
            10_000,
            0,
        ),
        &authority,
        &[],
    )
    .unwrap();

    let le = Pubkey::find_program_address(
        &[SEED_DEPOSIT_CLAIM, TXID_A.as_ref(), &vout.to_le_bytes()],
        &glc_bridge::ID,
    )
    .0;
    let be = Pubkey::find_program_address(
        &[SEED_DEPOSIT_CLAIM, TXID_A.as_ref(), &vout.to_be_bytes()],
        &glc_bridge::ID,
    )
    .0;
    assert!(svm.get_account(&le).is_some(), "LE-derived claim exists");
    assert!(
        svm.get_account(&be).is_none(),
        "BE derivation must not match"
    );
}

#[test]
fn claim_pda_from_reordered_txid_bytes_does_not_resolve() {
    use anchor_lang::{InstructionData, ToAccountMetas};
    use solana_sdk::instruction::Instruction;

    let authority = Keypair::new();
    let (mut svm, mint, recipient, ata) = setup_ready(&authority);

    // Non-palindromic txid: reversing the bytes yields a different array.
    let mut txid = [0u8; 32];
    for (i, byte) in txid.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let mut reversed = txid;
    reversed.reverse();
    assert_ne!(txid, reversed);

    // The claim account is derived from the REVERSED byte order while the
    // instruction arguments carry the canonical txid — as would happen if a
    // client silently reinterpreted byte order.
    let wrong_claim = claim_pda(&reversed, 0);
    let ix = Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::MintWrappedTestonly {
            admin: authority.pubkey(),
            bridge_config: config_pda(),
            validator_set: validator_set_pda(),
            deposit_claim: wrong_claim,
            wrapped_mint: mint,
            mint_authority: mint_authority_pda(),
            recipient,
            recipient_token_account: ata,
            token_program: spl_token::ID,
            system_program: solana_sdk::system_program::id(),
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::MintWrappedTestonly {
            txid,
            vout: 0,
            amount: 10_000,
            epoch: 0,
        }
        .data(),
    };

    // The program re-derives the PDA from the canonical txid argument, so
    // the mismatched account fails the seeds constraint and nothing mints.
    let result = send(&mut svm, ix, &authority, &[]);
    assert_anchor_error(
        result,
        anchor_lang::error::ErrorCode::ConstraintSeeds as u32,
    );
    assert_eq!(token_balance(&svm, &ata), 0);
    assert_eq!(mint_state(&svm, &mint).supply, 0);
    assert!(
        svm.get_account(&wrong_claim).is_none(),
        "no claim may exist at the reordered-txid address"
    );
    assert!(
        svm.get_account(&claim_pda(&txid, 0)).is_none(),
        "no claim may exist at the canonical address either — the mint failed"
    );
}

#[test]
fn rejects_while_paused_and_recovers_on_unpause() {
    let authority = Keypair::new();
    let (mut svm, mint, recipient, ata) = setup_ready(&authority);
    send(
        &mut svm,
        set_paused_ix(&authority.pubkey(), true),
        &authority,
        &[],
    )
    .unwrap();

    let ix = mint_testonly_ix(
        &authority.pubkey(),
        &mint,
        &recipient,
        &ata,
        TXID_A,
        0,
        10_000,
        0,
    );
    assert_bridge_error(
        send(&mut svm, ix.clone(), &authority, &[]),
        BridgeError::BridgePaused,
    );
    assert_eq!(token_balance(&svm, &ata), 0);

    send(
        &mut svm,
        set_paused_ix(&authority.pubkey(), false),
        &authority,
        &[],
    )
    .unwrap();
    // Fresh blockhash: the retry is byte-identical to the failed attempt and
    // would otherwise be rejected as a duplicate transaction.
    svm.expire_blockhash();
    send(&mut svm, ix, &authority, &[]).expect("mint works again after unpause");
    assert_eq!(token_balance(&svm, &ata), 10_000);
}

#[test]
fn rejects_zero_amount() {
    let authority = Keypair::new();
    let (mut svm, mint, recipient, ata) = setup_ready(&authority);
    assert_bridge_error(
        send(
            &mut svm,
            mint_testonly_ix(
                &authority.pubkey(),
                &mint,
                &recipient,
                &ata,
                TXID_A,
                0,
                0,
                0,
            ),
            &authority,
            &[],
        ),
        BridgeError::ZeroDepositAmount,
    );
}

#[test]
fn rejects_below_min_deposit() {
    let authority = Keypair::new();
    let (mut svm, mint, recipient, ata) = setup_ready(&authority);
    // Harness initializes min_deposit = 1_000.
    assert_bridge_error(
        send(
            &mut svm,
            mint_testonly_ix(
                &authority.pubkey(),
                &mint,
                &recipient,
                &ata,
                TXID_A,
                0,
                999,
                0,
            ),
            &authority,
            &[],
        ),
        BridgeError::BelowMinimumDeposit,
    );
    assert_eq!(token_balance(&svm, &ata), 0);
}

#[test]
fn rejects_stale_epoch_after_rotation() {
    let authority = Keypair::new();
    let (mut svm, mint, recipient, ata) = setup_ready(&authority);
    send(
        &mut svm,
        update_validator_set_ix(&authority.pubkey(), keys(4), 3),
        &authority,
        &[],
    )
    .expect("rotation succeeds");

    // Claim authorized under epoch 0 is now stale.
    assert_bridge_error(
        send(
            &mut svm,
            mint_testonly_ix(
                &authority.pubkey(),
                &mint,
                &recipient,
                &ata,
                TXID_A,
                0,
                10_000,
                0,
            ),
            &authority,
            &[],
        ),
        BridgeError::StaleValidatorEpoch,
    );

    // Same claim under the current epoch succeeds.
    send(
        &mut svm,
        mint_testonly_ix(
            &authority.pubkey(),
            &mint,
            &recipient,
            &ata,
            TXID_A,
            0,
            10_000,
            1,
        ),
        &authority,
        &[],
    )
    .expect("current-epoch claim succeeds");
    assert_eq!(get_claim(&svm, &TXID_A, 0).epoch, 1);
}

#[test]
fn rejects_before_mint_is_created() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);
    // A structurally valid foreign mint stands in for the not-yet-configured
    // wrapped mint.
    let foreign_mint = Pubkey::new_unique();
    write_foreign_mint(&mut svm, &foreign_mint);
    let recipient = Pubkey::new_unique();
    let ata = create_ata(&mut svm, &recipient, &foreign_mint);
    assert_bridge_error(
        send(
            &mut svm,
            mint_testonly_ix(
                &authority.pubkey(),
                &foreign_mint,
                &recipient,
                &ata,
                TXID_A,
                0,
                10_000,
                0,
            ),
            &authority,
            &[],
        ),
        BridgeError::MintNotConfigured,
    );
}

#[test]
fn rejects_wrong_mint_account() {
    let authority = Keypair::new();
    let (mut svm, _mint, recipient, _) = setup_ready(&authority);
    let foreign_mint = Pubkey::new_unique();
    write_foreign_mint(&mut svm, &foreign_mint);
    let foreign_ata = create_ata(&mut svm, &recipient, &foreign_mint);
    assert_bridge_error(
        send(
            &mut svm,
            mint_testonly_ix(
                &authority.pubkey(),
                &foreign_mint,
                &recipient,
                &foreign_ata,
                TXID_A,
                0,
                10_000,
                0,
            ),
            &authority,
            &[],
        ),
        BridgeError::WrongWrappedMint,
    );
}

#[test]
fn rejects_non_admin_authorizer() {
    let authority = Keypair::new();
    let (mut svm, mint, recipient, ata) = setup_ready(&authority);
    let intruder = Keypair::new();
    svm.airdrop(&intruder.pubkey(), 10_000_000_000).unwrap();
    assert_bridge_error(
        send(
            &mut svm,
            mint_testonly_ix(
                &intruder.pubkey(),
                &mint,
                &recipient,
                &ata,
                TXID_A,
                0,
                10_000,
                0,
            ),
            &intruder,
            &[],
        ),
        BridgeError::UnauthorizedAdmin,
    );
    assert_eq!(token_balance(&svm, &ata), 0);
    assert!(svm.get_account(&claim_pda(&TXID_A, 0)).is_none());
}

#[test]
fn rejects_non_ata_token_account() {
    let authority = Keypair::new();
    let (mut svm, mint, recipient, _ata) = setup_ready(&authority);
    // Valid token account for (recipient, mint) — but NOT at the ATA address.
    let rogue = Pubkey::new_unique();
    write_token_account(&mut svm, &rogue, &recipient, &mint);
    let result = send(
        &mut svm,
        mint_testonly_ix(
            &authority.pubkey(),
            &mint,
            &recipient,
            &rogue,
            TXID_A,
            0,
            10_000,
            0,
        ),
        &authority,
        &[],
    );
    assert_anchor_error(
        result,
        anchor_lang::error::ErrorCode::ConstraintAssociated as u32,
    );
    assert_eq!(token_balance(&svm, &rogue), 0);
}

#[test]
fn rejects_other_wallets_ata() {
    let authority = Keypair::new();
    let (mut svm, mint, recipient, _ata) = setup_ready(&authority);
    // A different wallet's genuine ATA, passed with `recipient` as the
    // claimed owner.
    let other_wallet = Pubkey::new_unique();
    let other_ata = create_ata(&mut svm, &other_wallet, &mint);
    assert_eq!(
        other_ata,
        get_associated_token_address(&other_wallet, &mint)
    );
    let result = send(
        &mut svm,
        mint_testonly_ix(
            &authority.pubkey(),
            &mint,
            &recipient,
            &other_ata,
            TXID_A,
            0,
            10_000,
            0,
        ),
        &authority,
        &[],
    );
    // Anchor's associated_token constraints check the token account's owner
    // before the derived address, so this surfaces as ConstraintTokenOwner.
    assert_anchor_error(
        result,
        anchor_lang::error::ErrorCode::ConstraintTokenOwner as u32,
    );
    assert_eq!(token_balance(&svm, &other_ata), 0);
}

#[test]
fn forged_mint_authority_cannot_mint_directly() {
    // Defense-in-depth check at the token level: nobody can invoke the SPL
    // token program to mint with a non-PDA authority, because the mint's
    // authority is the PDA and no key exists for it.
    let authority = Keypair::new();
    let (mut svm, mint, _recipient, ata) = setup_ready(&authority);
    let forger = Keypair::new();
    svm.airdrop(&forger.pubkey(), 10_000_000_000).unwrap();
    let ix = spl_token::instruction::mint_to_checked(
        &spl_token::ID,
        &mint,
        &ata,
        &forger.pubkey(),
        &[],
        1_000_000,
        WRAPPED_GLC_DECIMALS,
    )
    .unwrap();
    let result = send(&mut svm, ix, &forger, &[]);
    assert!(
        result.is_err(),
        "direct mint with forged authority must fail"
    );
    assert_eq!(token_balance(&svm, &ata), 0);
    assert_eq!(mint_state(&svm, &mint).supply, 0);
}
