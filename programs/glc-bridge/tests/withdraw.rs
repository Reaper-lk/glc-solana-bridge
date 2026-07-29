//! Phase 3 integration tests: `burn_wrapped` and persistent
//! `WithdrawalRequest` records (ADR-0006). Harness lives in `common`.

mod common;
use common::*;

use anchor_lang::AccountSerialize;
use litesvm::LiteSVM;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

use glc_bridge::constants::PROTOCOL_VERSION;
use glc_bridge::errors::BridgeError;
use glc_bridge::state::{WithdrawalRequest, WithdrawalStatus};

const TXID: [u8; 32] = [0xCC; 32];
const GLC_ADDR: &[u8] = b"GLCtestDestinationAddress0000000001";

/// Bridge with a funded user holding `balance` wrapped GLC in their ATA,
/// minted through a real 2-of-3 federation proof.
fn ready(balance: u64) -> (LiteSVM, Keypair, Keypair, Pubkey, Pubkey) {
    let authority = Keypair::new();
    let validators: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
    let pubkeys: Vec<Pubkey> = validators.iter().map(|k| k.pubkey()).collect();
    let mut svm = setup_initialized_with(&authority, pubkeys, 2);

    let mint_kp = Keypair::new();
    send(
        &mut svm,
        create_wrapped_mint_ix(&authority.pubkey(), &mint_kp.pubkey()),
        &authority,
        &[&mint_kp],
    )
    .unwrap();
    let mint = mint_kp.pubkey();

    let user = Keypair::new();
    svm.airdrop(&user.pubkey(), 100_000_000_000).unwrap();
    let ata = create_ata(&mut svm, &user.pubkey(), &mint);

    let message = claim_message(0, &TXID, 0, balance, &user.pubkey(), &mint);
    let signers: Vec<&Keypair> = vec![&validators[0], &validators[1]];
    let ixs = vec![
        ed25519_proof_ix(&signers, &message),
        mint_wrapped_ix(
            &user.pubkey(),
            &mint,
            &user.pubkey(),
            &ata,
            TXID,
            0,
            balance,
            0,
        ),
    ];
    send_ixs(&mut svm, &ixs, &user, &[]).expect("funding mint must succeed");
    assert_eq!(token_balance(&svm, &ata), balance);

    (svm, authority, user, mint, ata)
}

#[test]
fn burn_happy_path_creates_persistent_record() {
    let (mut svm, _authority, user, mint, ata) = ready(100_000);
    svm.warp_to_slot(7777);

    send(
        &mut svm,
        burn_wrapped_ix(&user.pubkey(), &mint, &ata, 0, 30_000, GLC_ADDR.to_vec()),
        &user,
        &[],
    )
    .expect("burn should succeed");

    assert_eq!(token_balance(&svm, &ata), 70_000);
    assert_eq!(mint_state(&svm, &mint).supply, 70_000);
    assert_eq!(get_config(&svm).withdrawal_count, 1);

    let record = get_withdrawal(&svm, 0);
    assert_eq!(record.index, 0);
    assert_eq!(record.amount, 30_000);
    assert_eq!(record.requester, user.pubkey());
    let mut expected_addr = [0u8; 64];
    expected_addr[..GLC_ADDR.len()].copy_from_slice(GLC_ADDR);
    assert_eq!(record.glc_address, expected_addr);
    assert_eq!(record.glc_address_len as usize, GLC_ADDR.len());
    assert_eq!(record.status, WithdrawalStatus::Pending);
    assert_eq!(record.requested_at_slot, 7777);
    assert_eq!(record.protocol_version, PROTOCOL_VERSION);
    assert_eq!(record.reserved, [0u8; 48]);

    let account = svm.get_account(&withdrawal_pda(0)).unwrap();
    assert_eq!(account.data.len(), WithdrawalRequest::SPACE);
    assert_eq!(account.owner, glc_bridge::ID);
}

#[test]
fn sequential_burns_get_sequential_indices() {
    let (mut svm, _authority, user, mint, ata) = ready(100_000);
    send(
        &mut svm,
        burn_wrapped_ix(&user.pubkey(), &mint, &ata, 0, 10_000, GLC_ADDR.to_vec()),
        &user,
        &[],
    )
    .unwrap();
    send(
        &mut svm,
        burn_wrapped_ix(&user.pubkey(), &mint, &ata, 1, 5_000, GLC_ADDR.to_vec()),
        &user,
        &[],
    )
    .unwrap();

    assert_eq!(get_config(&svm).withdrawal_count, 2);
    assert_eq!(get_withdrawal(&svm, 0).amount, 10_000);
    assert_eq!(get_withdrawal(&svm, 1).amount, 5_000);
    assert_ne!(withdrawal_pda(0), withdrawal_pda(1));
    assert_eq!(token_balance(&svm, &ata), 85_000);
}

#[test]
fn rejects_zero_amount() {
    let (mut svm, _authority, user, mint, ata) = ready(100_000);
    assert_bridge_error(
        send(
            &mut svm,
            burn_wrapped_ix(&user.pubkey(), &mint, &ata, 0, 0, GLC_ADDR.to_vec()),
            &user,
            &[],
        ),
        BridgeError::ZeroWithdrawalAmount,
    );
}

#[test]
fn rejects_below_minimum_withdrawal() {
    // Harness initializes min_withdrawal = 2_000.
    let (mut svm, _authority, user, mint, ata) = ready(100_000);
    assert_bridge_error(
        send(
            &mut svm,
            burn_wrapped_ix(&user.pubkey(), &mint, &ata, 0, 1_999, GLC_ADDR.to_vec()),
            &user,
            &[],
        ),
        BridgeError::BelowMinimumWithdrawal,
    );
    assert_eq!(token_balance(&svm, &ata), 100_000);
}

#[test]
fn rejects_while_paused_and_recovers_on_unpause() {
    let (mut svm, authority, user, mint, ata) = ready(100_000);
    send(
        &mut svm,
        set_paused_ix(&authority.pubkey(), true),
        &authority,
        &[],
    )
    .unwrap();
    assert_bridge_error(
        send(
            &mut svm,
            burn_wrapped_ix(&user.pubkey(), &mint, &ata, 0, 10_000, GLC_ADDR.to_vec()),
            &user,
            &[],
        ),
        BridgeError::BridgePaused,
    );
    assert_eq!(token_balance(&svm, &ata), 100_000);

    send(
        &mut svm,
        set_paused_ix(&authority.pubkey(), false),
        &authority,
        &[],
    )
    .unwrap();
    svm.expire_blockhash();
    send(
        &mut svm,
        burn_wrapped_ix(&user.pubkey(), &mint, &ata, 0, 10_000, GLC_ADDR.to_vec()),
        &user,
        &[],
    )
    .expect("burn works again after unpause");
    assert_eq!(token_balance(&svm, &ata), 90_000);
}

#[test]
fn rejects_empty_and_oversized_addresses() {
    let (mut svm, _authority, user, mint, ata) = ready(100_000);
    assert_bridge_error(
        send(
            &mut svm,
            burn_wrapped_ix(&user.pubkey(), &mint, &ata, 0, 10_000, vec![]),
            &user,
            &[],
        ),
        BridgeError::InvalidGlcAddressLength,
    );
    assert_bridge_error(
        send(
            &mut svm,
            burn_wrapped_ix(&user.pubkey(), &mint, &ata, 0, 10_000, vec![b'G'; 65]),
            &user,
            &[],
        ),
        BridgeError::InvalidGlcAddressLength,
    );
    assert_eq!(token_balance(&svm, &ata), 100_000);
}

#[test]
fn accepts_maximum_length_address() {
    let (mut svm, _authority, user, mint, ata) = ready(100_000);
    send(
        &mut svm,
        burn_wrapped_ix(&user.pubkey(), &mint, &ata, 0, 10_000, vec![b'G'; 64]),
        &user,
        &[],
    )
    .expect("64-byte address is the inclusive maximum");
    let record = get_withdrawal(&svm, 0);
    assert_eq!(record.glc_address_len, 64);
    assert_eq!(record.glc_address, [b'G'; 64]);
}

#[test]
fn rejects_non_ata_token_account() {
    let (mut svm, _authority, user, mint, _ata) = ready(100_000);
    // Valid token account for (user, mint) — but not at the ATA address.
    let rogue = Pubkey::new_unique();
    write_token_account(&mut svm, &rogue, &user.pubkey(), &mint);
    let result = send(
        &mut svm,
        burn_wrapped_ix(&user.pubkey(), &mint, &rogue, 0, 10_000, GLC_ADDR.to_vec()),
        &user,
        &[],
    );
    assert_anchor_error(
        result,
        anchor_lang::error::ErrorCode::ConstraintAssociated as u32,
    );
}

#[test]
fn rejects_wrong_mint_account() {
    let (mut svm, _authority, user, _mint, _ata) = ready(100_000);
    let foreign_mint = Pubkey::new_unique();
    write_foreign_mint(&mut svm, &foreign_mint);
    let foreign_ata = create_ata(&mut svm, &user.pubkey(), &foreign_mint);
    assert_bridge_error(
        send(
            &mut svm,
            burn_wrapped_ix(
                &user.pubkey(),
                &foreign_mint,
                &foreign_ata,
                0,
                10_000,
                GLC_ADDR.to_vec(),
            ),
            &user,
            &[],
        ),
        BridgeError::WrongWrappedMint,
    );
}

#[test]
fn burning_more_than_balance_fails_and_records_nothing() {
    let (mut svm, _authority, user, mint, ata) = ready(10_000);
    let result = send(
        &mut svm,
        burn_wrapped_ix(&user.pubkey(), &mint, &ata, 0, 20_000, GLC_ADDR.to_vec()),
        &user,
        &[],
    );
    assert!(
        result.is_err(),
        "over-balance burn must fail in the token program"
    );
    assert_eq!(token_balance(&svm, &ata), 10_000);
    assert!(svm.get_account(&withdrawal_pda(0)).is_none());
    assert_eq!(get_config(&svm).withdrawal_count, 0);
}

#[test]
fn withdrawal_counter_overflow_rejected() {
    let (mut svm, _authority, user, mint, ata) = ready(100_000);

    // Force the counter to u64::MAX by rewriting the config account.
    let mut config = get_config(&svm);
    config.withdrawal_count = u64::MAX;
    let mut data = Vec::new();
    config.try_serialize(&mut data).unwrap();
    data.resize(glc_bridge::state::BridgeConfig::SPACE, 0);
    let mut account = svm.get_account(&config_pda()).unwrap();
    account.data = data;
    svm.set_account(config_pda(), account).unwrap();
    assert_eq!(get_config(&svm).withdrawal_count, u64::MAX);

    let result = send(
        &mut svm,
        burn_wrapped_ix(
            &user.pubkey(),
            &mint,
            &ata,
            u64::MAX,
            10_000,
            GLC_ADDR.to_vec(),
        ),
        &user,
        &[],
    );
    assert_bridge_error(result, BridgeError::ArithmeticOverflow);
    assert_eq!(token_balance(&svm, &ata), 100_000, "no burn on overflow");
    assert!(svm.get_account(&withdrawal_pda(u64::MAX)).is_none());
}
