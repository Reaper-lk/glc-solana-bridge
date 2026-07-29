//! Phase 1 integration tests: run the real SBF binary under litesvm and
//! exercise every instruction path — happy paths, each validation rejection,
//! authorization failures, and the structural reinitialization guard.
//!
//! Requires `anchor build` to have produced `target/deploy/glc_bridge.so`
//! (CI runs these tests in the anchor-build job for exactly that reason).
//!
//! The program is installed as a loader-v3 (upgradeable) program with a
//! test-controlled upgrade authority, because `initialize` authorization is
//! proven against the ProgramData account (ADR-0008).

use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use litesvm::LiteSVM;
use solana_sdk::{
    account::Account,
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    instruction::{Instruction, InstructionError},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};

use glc_bridge::constants::{
    MAX_VALIDATORS, PROTOCOL_VERSION, SEED_BRIDGE_CONFIG, SEED_VALIDATOR_SET,
};
use glc_bridge::errors::BridgeError;
use glc_bridge::state::{BridgeConfig, ValidatorSet};

// ---------------------------------------------------------------- harness --

fn program_bytes() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/deploy/glc_bridge.so"
    );
    std::fs::read(path).expect("target/deploy/glc_bridge.so missing — run `anchor build` first")
}

fn programdata_address() -> Pubkey {
    Pubkey::find_program_address(&[glc_bridge::ID.as_ref()], &bpf_loader_upgradeable::id()).0
}

fn config_pda() -> Pubkey {
    Pubkey::find_program_address(&[SEED_BRIDGE_CONFIG], &glc_bridge::ID).0
}

fn validator_set_pda() -> Pubkey {
    Pubkey::find_program_address(&[SEED_VALIDATOR_SET], &glc_bridge::ID).0
}

/// Serialized loader-v3 ProgramData account: 45-byte metadata header
/// followed by the ELF.
fn programdata_account(upgrade_authority: Option<Pubkey>, elf: &[u8]) -> Account {
    let mut data = bincode::serialize(&UpgradeableLoaderState::ProgramData {
        slot: 0,
        upgrade_authority_address: upgrade_authority,
    })
    .unwrap();
    data.resize(UpgradeableLoaderState::size_of_programdata_metadata(), 0);
    data.extend_from_slice(elf);
    Account {
        lamports: 10_000_000_000,
        data,
        owner: bpf_loader_upgradeable::id(),
        executable: false,
        rent_epoch: 0,
    }
}

/// Fresh VM with the program installed as upgradeable and `authority` as its
/// upgrade authority (funded).
fn setup(authority: &Keypair) -> LiteSVM {
    let mut svm = LiteSVM::new();
    svm.airdrop(&authority.pubkey(), 100_000_000_000).unwrap();

    let elf = program_bytes();
    // ProgramData must exist before the executable account: litesvm loads
    // the program the moment the executable account is set.
    svm.set_account(
        programdata_address(),
        programdata_account(Some(authority.pubkey()), &elf),
    )
    .unwrap();
    let program_state = bincode::serialize(&UpgradeableLoaderState::Program {
        programdata_address: programdata_address(),
    })
    .unwrap();
    svm.set_account(
        glc_bridge::ID,
        Account {
            lamports: 1_000_000_000,
            data: program_state,
            owner: bpf_loader_upgradeable::id(),
            executable: true,
            rent_epoch: 0,
        },
    )
    .unwrap();
    svm
}

fn keys(n: usize) -> Vec<Pubkey> {
    (0..n).map(|_| Pubkey::new_unique()).collect()
}

fn initialize_ix(
    authority: &Pubkey,
    program_data: Pubkey,
    validators: Vec<Pubkey>,
    threshold: u8,
) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::Initialize {
            authority: *authority,
            bridge_config: config_pda(),
            validator_set: validator_set_pda(),
            program: glc_bridge::ID,
            program_data,
            system_program: solana_sdk::system_program::id(),
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::Initialize {
            validators,
            threshold,
            min_deposit: 1_000,
            min_withdrawal: 2_000,
        }
        .data(),
    }
}

// The Err type is litesvm's own; its size is not ours to shrink.
#[allow(clippy::result_large_err)]
fn send(
    svm: &mut LiteSVM,
    ix: Instruction,
    payer: &Keypair,
    extra_signers: &[&Keypair],
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra_signers);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &signers,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
}

/// Sets up an initialized bridge with `authority` as upgrade authority and
/// admin, `n` validators at `threshold`.
fn setup_initialized(authority: &Keypair, n: usize, threshold: u8) -> (LiteSVM, Vec<Pubkey>) {
    let mut svm = setup(authority);
    let validators = keys(n);
    let ix = initialize_ix(
        &authority.pubkey(),
        programdata_address(),
        validators.clone(),
        threshold,
    );
    send(&mut svm, ix, authority, &[]).expect("initialize should succeed");
    (svm, validators)
}

fn expected_code(e: BridgeError) -> u32 {
    match anchor_lang::error::Error::from(e) {
        anchor_lang::error::Error::AnchorError(ae) => ae.error_code_number,
        _ => unreachable!(),
    }
}

#[track_caller]
fn assert_bridge_error(
    result: Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>,
    expected: BridgeError,
) {
    let err = result.expect_err("transaction should have failed").err;
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            assert_eq!(code, expected_code(expected), "wrong custom error code")
        }
        other => panic!("expected custom program error, got {other:?}"),
    }
}

fn get_config(svm: &LiteSVM) -> BridgeConfig {
    let account = svm.get_account(&config_pda()).expect("config must exist");
    BridgeConfig::try_deserialize(&mut account.data.as_slice()).unwrap()
}

fn get_validator_set(svm: &LiteSVM) -> ValidatorSet {
    let account = svm
        .get_account(&validator_set_pda())
        .expect("validator set must exist");
    ValidatorSet::try_deserialize(&mut account.data.as_slice()).unwrap()
}

fn admin_config_metas(admin: &Pubkey) -> Vec<solana_sdk::instruction::AccountMeta> {
    glc_bridge::accounts::AdminConfig {
        admin: *admin,
        bridge_config: config_pda(),
    }
    .to_account_metas(None)
}

fn set_paused_ix(admin: &Pubkey, paused: bool) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: admin_config_metas(admin),
        data: glc_bridge::instruction::SetPaused { paused }.data(),
    }
}

fn update_validator_set_ix(admin: &Pubkey, validators: Vec<Pubkey>, threshold: u8) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::UpdateValidatorSet {
            admin: *admin,
            bridge_config: config_pda(),
            validator_set: validator_set_pda(),
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::UpdateValidatorSet {
            validators,
            threshold,
        }
        .data(),
    }
}

fn transfer_admin_ix(admin: &Pubkey, new_admin: Pubkey) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: admin_config_metas(admin),
        data: glc_bridge::instruction::TransferAdmin { new_admin }.data(),
    }
}

fn accept_admin_ix(new_admin: &Pubkey) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::AcceptAdmin {
            new_admin: *new_admin,
            bridge_config: config_pda(),
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::AcceptAdmin {}.data(),
    }
}

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
    assert_eq!(config.reserved, [0u8; 64]);
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
