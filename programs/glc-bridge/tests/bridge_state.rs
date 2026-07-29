//! Phase 1 integration tests: bridge state and governance — happy paths,
//! each validation rejection, authorization failures, and the structural
//! reinitialization guard. Harness lives in `common`.

mod common;
use common::*;

use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

use glc_bridge::constants::{
    MAX_VALIDATORS, PROTOCOL_VERSION, SEED_BRIDGE_CONFIG, SEED_VALIDATOR_SET,
};
use glc_bridge::errors::BridgeError;
use glc_bridge::state::{BridgeConfig, ValidatorSet};

// ------------------------------------------------------------- initialize --

#[test]
fn initialize_happy_path() {
    let authority = Keypair::new();
    let (svm, validators) = setup_initialized(&authority, 5, 3);

    let config = get_config(&svm);
    assert_eq!(config.protocol_version, PROTOCOL_VERSION);
    assert_eq!(config.admin, authority.pubkey());
    assert_eq!(config.pending_admin, None);
    assert!(!config.paused);
    assert_eq!(config.withdrawal_count, 0);
    assert_eq!(config.min_deposit, 1_000);
    assert_eq!(config.min_withdrawal, 2_000);
    assert_eq!(config.reserved, [0u8; 31]);
    assert_eq!(config.wrapped_mint, Pubkey::default());
    assert_eq!(config.mint_authority_bump, 0);
    let (expected_config, config_bump) =
        Pubkey::find_program_address(&[SEED_BRIDGE_CONFIG], &glc_bridge::ID);
    assert_eq!(expected_config, config_pda());
    assert_eq!(config.bump, config_bump);

    let set = get_validator_set(&svm);
    assert_eq!(set.epoch, 0);
    assert_eq!(set.threshold, 3);
    assert_eq!(set.validators, validators);
    assert_eq!(set.reserved, [0u8; 32]);
    let (_, set_bump) = Pubkey::find_program_address(&[SEED_VALIDATOR_SET], &glc_bridge::ID);
    assert_eq!(set.bump, set_bump);
}

#[test]
fn initialize_allocates_exactly_documented_space() {
    let authority = Keypair::new();
    let (svm, _) = setup_initialized(&authority, MAX_VALIDATORS, MAX_VALIDATORS as u8);

    let config_account = svm.get_account(&config_pda()).unwrap();
    assert_eq!(config_account.data.len(), BridgeConfig::SPACE);
    assert_eq!(config_account.owner, glc_bridge::ID);

    let set_account = svm.get_account(&validator_set_pda()).unwrap();
    assert_eq!(set_account.data.len(), ValidatorSet::SPACE);
    assert_eq!(set_account.owner, glc_bridge::ID);
}

#[test]
fn initialize_twice_fails() {
    let authority = Keypair::new();
    let (mut svm, validators) = setup_initialized(&authority, 3, 2);

    svm.expire_blockhash();
    let ix = initialize_ix(&authority.pubkey(), programdata_address(), validators, 2);
    let result = send(&mut svm, ix, &authority, &[]);
    assert!(result.is_err(), "reinitialization must fail");

    // State untouched by the failed attempt.
    let config = get_config(&svm);
    assert_eq!(config.admin, authority.pubkey());
    assert_eq!(get_validator_set(&svm).epoch, 0);
}

#[test]
fn initialize_rejects_non_upgrade_authority() {
    let authority = Keypair::new();
    let mut svm = setup(&authority);

    let intruder = Keypair::new();
    svm.airdrop(&intruder.pubkey(), 100_000_000_000).unwrap();
    let ix = initialize_ix(&intruder.pubkey(), programdata_address(), keys(3), 2);
    assert_bridge_error(
        send(&mut svm, ix, &intruder, &[]),
        BridgeError::UnauthorizedInitializer,
    );
    assert!(svm.get_account(&config_pda()).is_none());
}

#[test]
fn initialize_rejects_forged_program_data() {
    let authority = Keypair::new();
    let mut svm = setup(&authority);

    // Intruder crafts a structurally valid ProgramData account naming
    // themselves as upgrade authority — at the wrong address.
    let intruder = Keypair::new();
    svm.airdrop(&intruder.pubkey(), 100_000_000_000).unwrap();
    let forged = Pubkey::new_unique();
    svm.set_account(forged, programdata_account(Some(intruder.pubkey()), &[]))
        .unwrap();

    let ix = initialize_ix(&intruder.pubkey(), forged, keys(3), 2);
    assert_bridge_error(
        send(&mut svm, ix, &intruder, &[]),
        BridgeError::UnauthorizedInitializer,
    );
    assert!(svm.get_account(&config_pda()).is_none());
}

#[test]
fn initialize_rejects_empty_validator_set() {
    let authority = Keypair::new();
    let mut svm = setup(&authority);
    let ix = initialize_ix(&authority.pubkey(), programdata_address(), vec![], 1);
    assert_bridge_error(
        send(&mut svm, ix, &authority, &[]),
        BridgeError::EmptyValidatorSet,
    );
}

#[test]
fn initialize_rejects_too_many_validators() {
    let authority = Keypair::new();
    let mut svm = setup(&authority);
    let ix = initialize_ix(
        &authority.pubkey(),
        programdata_address(),
        keys(MAX_VALIDATORS + 1),
        1,
    );
    assert_bridge_error(
        send(&mut svm, ix, &authority, &[]),
        BridgeError::TooManyValidators,
    );
}

#[test]
fn initialize_rejects_duplicate_validator() {
    let authority = Keypair::new();
    let mut svm = setup(&authority);
    let mut validators = keys(3);
    validators[2] = validators[0];
    let ix = initialize_ix(&authority.pubkey(), programdata_address(), validators, 2);
    assert_bridge_error(
        send(&mut svm, ix, &authority, &[]),
        BridgeError::DuplicateValidator,
    );
}

#[test]
fn initialize_rejects_all_zero_validator_key() {
    let authority = Keypair::new();
    let mut svm = setup(&authority);
    let mut validators = keys(3);
    validators[1] = Pubkey::default();
    let ix = initialize_ix(&authority.pubkey(), programdata_address(), validators, 2);
    assert_bridge_error(
        send(&mut svm, ix, &authority, &[]),
        BridgeError::InvalidValidatorKey,
    );
    assert!(svm.get_account(&config_pda()).is_none());
}

#[test]
fn initialize_rejects_zero_threshold() {
    let authority = Keypair::new();
    let mut svm = setup(&authority);
    let ix = initialize_ix(&authority.pubkey(), programdata_address(), keys(3), 0);
    assert_bridge_error(
        send(&mut svm, ix, &authority, &[]),
        BridgeError::ZeroThreshold,
    );
}

#[test]
fn initialize_rejects_threshold_above_validator_count() {
    let authority = Keypair::new();
    let mut svm = setup(&authority);
    let ix = initialize_ix(&authority.pubkey(), programdata_address(), keys(3), 4);
    assert_bridge_error(
        send(&mut svm, ix, &authority, &[]),
        BridgeError::ThresholdExceedsValidatorCount,
    );
}

// -------------------------------------------------------------- set_paused --

#[test]
fn set_paused_pauses_and_unpauses() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);

    send(
        &mut svm,
        set_paused_ix(&authority.pubkey(), true),
        &authority,
        &[],
    )
    .expect("pause should succeed");
    assert!(get_config(&svm).paused);

    send(
        &mut svm,
        set_paused_ix(&authority.pubkey(), false),
        &authority,
        &[],
    )
    .expect("unpause should succeed");
    assert!(!get_config(&svm).paused);
}

#[test]
fn set_paused_rejects_noop() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);
    assert_bridge_error(
        send(
            &mut svm,
            set_paused_ix(&authority.pubkey(), false),
            &authority,
            &[],
        ),
        BridgeError::PauseStateUnchanged,
    );
}

#[test]
fn set_paused_rejects_non_admin() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);
    let intruder = Keypair::new();
    svm.airdrop(&intruder.pubkey(), 1_000_000_000).unwrap();
    assert_bridge_error(
        send(
            &mut svm,
            set_paused_ix(&intruder.pubkey(), true),
            &intruder,
            &[],
        ),
        BridgeError::UnauthorizedAdmin,
    );
    assert!(!get_config(&svm).paused);
}

// ---------------------------------------------------- update_validator_set --

#[test]
fn update_validator_set_rotates_and_increments_epoch() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);

    let next = keys(4);
    send(
        &mut svm,
        update_validator_set_ix(&authority.pubkey(), next.clone(), 4),
        &authority,
        &[],
    )
    .expect("rotation should succeed");

    let set = get_validator_set(&svm);
    assert_eq!(set.epoch, 1);
    assert_eq!(set.threshold, 4);
    assert_eq!(set.validators, next);

    // A second rotation advances the epoch again.
    let final_set = keys(2);
    send(
        &mut svm,
        update_validator_set_ix(&authority.pubkey(), final_set.clone(), 1),
        &authority,
        &[],
    )
    .expect("second rotation should succeed");
    let set = get_validator_set(&svm);
    assert_eq!(set.epoch, 2);
    assert_eq!(set.validators, final_set);
}

#[test]
fn update_validator_set_rejects_non_admin() {
    let authority = Keypair::new();
    let (mut svm, validators) = setup_initialized(&authority, 3, 2);
    let intruder = Keypair::new();
    svm.airdrop(&intruder.pubkey(), 1_000_000_000).unwrap();
    assert_bridge_error(
        send(
            &mut svm,
            update_validator_set_ix(&intruder.pubkey(), keys(3), 2),
            &intruder,
            &[],
        ),
        BridgeError::UnauthorizedAdmin,
    );
    let set = get_validator_set(&svm);
    assert_eq!(set.epoch, 0);
    assert_eq!(set.validators, validators);
}

#[test]
fn update_validator_set_enforces_same_invariants_as_initialize() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);
    let mut dup = keys(4);
    dup[3] = dup[1];
    assert_bridge_error(
        send(
            &mut svm,
            update_validator_set_ix(&authority.pubkey(), dup, 2),
            &authority,
            &[],
        ),
        BridgeError::DuplicateValidator,
    );
    assert_eq!(get_validator_set(&svm).epoch, 0);
}

#[test]
fn update_validator_set_rejects_all_zero_validator_key() {
    let authority = Keypair::new();
    let (mut svm, validators) = setup_initialized(&authority, 3, 2);
    let mut next = keys(4);
    next[0] = Pubkey::default();
    assert_bridge_error(
        send(
            &mut svm,
            update_validator_set_ix(&authority.pubkey(), next, 2),
            &authority,
            &[],
        ),
        BridgeError::InvalidValidatorKey,
    );
    let set = get_validator_set(&svm);
    assert_eq!(set.epoch, 0);
    assert_eq!(set.validators, validators);
}

// ---------------------------------------------------------- admin handover --

#[test]
fn admin_transfer_two_step_handover() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);
    let new_admin = Keypair::new();
    svm.airdrop(&new_admin.pubkey(), 1_000_000_000).unwrap();

    // Step 1: propose.
    send(
        &mut svm,
        transfer_admin_ix(&authority.pubkey(), new_admin.pubkey()),
        &authority,
        &[],
    )
    .expect("transfer_admin should succeed");
    let config = get_config(&svm);
    assert_eq!(
        config.admin,
        authority.pubkey(),
        "admin unchanged until accept"
    );
    assert_eq!(config.pending_admin, Some(new_admin.pubkey()));

    // Step 2: accept.
    send(
        &mut svm,
        accept_admin_ix(&new_admin.pubkey()),
        &new_admin,
        &[],
    )
    .expect("accept_admin should succeed");
    let config = get_config(&svm);
    assert_eq!(config.admin, new_admin.pubkey());
    assert_eq!(config.pending_admin, None);

    // Old admin lost governance; new admin has it.
    assert_bridge_error(
        send(
            &mut svm,
            set_paused_ix(&authority.pubkey(), true),
            &authority,
            &[],
        ),
        BridgeError::UnauthorizedAdmin,
    );
    send(
        &mut svm,
        set_paused_ix(&new_admin.pubkey(), true),
        &new_admin,
        &[],
    )
    .expect("new admin must hold governance");
    assert!(get_config(&svm).paused);
}

#[test]
fn accept_admin_rejects_wrong_signer() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);
    let new_admin = Keypair::new();
    let intruder = Keypair::new();
    svm.airdrop(&intruder.pubkey(), 1_000_000_000).unwrap();

    send(
        &mut svm,
        transfer_admin_ix(&authority.pubkey(), new_admin.pubkey()),
        &authority,
        &[],
    )
    .unwrap();
    assert_bridge_error(
        send(
            &mut svm,
            accept_admin_ix(&intruder.pubkey()),
            &intruder,
            &[],
        ),
        BridgeError::PendingAdminMismatch,
    );
    assert_eq!(get_config(&svm).admin, authority.pubkey());
}

#[test]
fn accept_admin_rejects_without_pending_transfer() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);
    let claimant = Keypair::new();
    svm.airdrop(&claimant.pubkey(), 1_000_000_000).unwrap();
    assert_bridge_error(
        send(
            &mut svm,
            accept_admin_ix(&claimant.pubkey()),
            &claimant,
            &[],
        ),
        BridgeError::NoPendingAdmin,
    );
}

#[test]
fn transfer_admin_rejects_non_admin() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);
    let intruder = Keypair::new();
    svm.airdrop(&intruder.pubkey(), 1_000_000_000).unwrap();
    assert_bridge_error(
        send(
            &mut svm,
            transfer_admin_ix(&intruder.pubkey(), intruder.pubkey()),
            &intruder,
            &[],
        ),
        BridgeError::UnauthorizedAdmin,
    );
}

#[test]
fn transfer_admin_rejects_current_admin_as_target() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);
    assert_bridge_error(
        send(
            &mut svm,
            transfer_admin_ix(&authority.pubkey(), authority.pubkey()),
            &authority,
            &[],
        ),
        BridgeError::AdminUnchanged,
    );
}

#[test]
fn transfer_admin_overwrites_pending_proposal() {
    let authority = Keypair::new();
    let (mut svm, _) = setup_initialized(&authority, 3, 2);
    let first = Pubkey::new_unique();
    let second = Pubkey::new_unique();

    send(
        &mut svm,
        transfer_admin_ix(&authority.pubkey(), first),
        &authority,
        &[],
    )
    .unwrap();
    send(
        &mut svm,
        transfer_admin_ix(&authority.pubkey(), second),
        &authority,
        &[],
    )
    .unwrap();
    assert_eq!(get_config(&svm).pending_admin, Some(second));
}
