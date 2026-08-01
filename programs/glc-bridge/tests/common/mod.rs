//! Shared litesvm harness for all integration test files.
//!
//! The program is installed as a loader-v3 (upgradeable) program with a
//! test-controlled upgrade authority, because `initialize` authorization is
//! proven against the ProgramData account (ADR-0008).
//!
//! Each tests/*.rs file is its own crate, so not every helper is used by
//! every file.
#![allow(dead_code)]

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

use glc_bridge::constants::{SEED_BRIDGE_CONFIG, SEED_VALIDATOR_SET};
use glc_bridge::errors::BridgeError;
use glc_bridge::state::{BridgeConfig, ValidatorSet};

// ---------------------------------------------------------------- harness --

pub fn program_bytes() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/deploy/glc_bridge.so"
    );
    std::fs::read(path).expect("target/deploy/glc_bridge.so missing — run `anchor build` first")
}

pub fn programdata_address() -> Pubkey {
    Pubkey::find_program_address(&[glc_bridge::ID.as_ref()], &bpf_loader_upgradeable::id()).0
}

pub fn config_pda() -> Pubkey {
    Pubkey::find_program_address(&[SEED_BRIDGE_CONFIG], &glc_bridge::ID).0
}

pub fn validator_set_pda() -> Pubkey {
    Pubkey::find_program_address(&[SEED_VALIDATOR_SET], &glc_bridge::ID).0
}

/// Serialized loader-v3 ProgramData account: 45-byte metadata header
/// followed by the ELF.
pub fn programdata_account(upgrade_authority: Option<Pubkey>, elf: &[u8]) -> Account {
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
pub fn setup(authority: &Keypair) -> LiteSVM {
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

pub fn keys(n: usize) -> Vec<Pubkey> {
    (0..n).map(|_| Pubkey::new_unique()).collect()
}

/// A cap high enough that no existing test bumps into it, so the Phase
/// 7h-0 ceiling changes nothing for tests that are not about it.
pub const DEFAULT_TEST_SUPPLY_CAP: u64 = u64::MAX / 2;

/// `initialize_ix` with an explicit supply cap, for tests that exercise the
/// ceiling itself.
pub fn initialize_ix_with_cap(
    authority: &Pubkey,
    program_data: Pubkey,
    validators: Vec<Pubkey>,
    threshold: u8,
    max_wrapped_supply: u64,
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
            governance_timelock_seconds: DEFAULT_TEST_TIMELOCK,
            max_wrapped_supply,
        }
        .data(),
    }
}

pub fn initialize_ix(
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
            governance_timelock_seconds: DEFAULT_TEST_TIMELOCK,
            max_wrapped_supply: DEFAULT_TEST_SUPPLY_CAP,
        }
        .data(),
    }
}

/// `initialize_ix` with an explicit timelock, for tests that exercise the
/// zero-timelock rejection.
pub fn initialize_ix_with_timelock(
    authority: &Pubkey,
    program_data: Pubkey,
    validators: Vec<Pubkey>,
    threshold: u8,
    governance_timelock_seconds: i64,
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
            governance_timelock_seconds,
            max_wrapped_supply: DEFAULT_TEST_SUPPLY_CAP,
        }
        .data(),
    }
}

// The Err type is litesvm's own; its size is not ours to shrink.
#[allow(clippy::result_large_err)]
pub fn send(
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
/// admin, and the given validator pubkeys at `threshold`.
pub fn setup_initialized_with(
    authority: &Keypair,
    validators: Vec<Pubkey>,
    threshold: u8,
) -> LiteSVM {
    let mut svm = setup(authority);
    let ix = initialize_ix(
        &authority.pubkey(),
        programdata_address(),
        validators,
        threshold,
    );
    send(&mut svm, ix, authority, &[]).expect("initialize should succeed");
    svm
}

/// Sets up an initialized bridge with `authority` as upgrade authority and
/// admin, `n` random validators at `threshold`.
pub fn setup_initialized(authority: &Keypair, n: usize, threshold: u8) -> (LiteSVM, Vec<Pubkey>) {
    let validators = keys(n);
    let svm = setup_initialized_with(authority, validators.clone(), threshold);
    (svm, validators)
}

pub fn expected_code(e: BridgeError) -> u32 {
    match anchor_lang::error::Error::from(e) {
        anchor_lang::error::Error::AnchorError(ae) => ae.error_code_number,
        _ => unreachable!(),
    }
}

#[track_caller]
pub fn assert_bridge_error(
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

pub fn get_config(svm: &LiteSVM) -> BridgeConfig {
    let account = svm.get_account(&config_pda()).expect("config must exist");
    BridgeConfig::try_deserialize(&mut account.data.as_slice()).unwrap()
}

pub fn get_validator_set(svm: &LiteSVM) -> ValidatorSet {
    let account = svm
        .get_account(&validator_set_pda())
        .expect("validator set must exist");
    ValidatorSet::try_deserialize(&mut account.data.as_slice()).unwrap()
}

pub fn admin_config_metas(admin: &Pubkey) -> Vec<solana_sdk::instruction::AccountMeta> {
    glc_bridge::accounts::AdminConfig {
        admin: *admin,
        bridge_config: config_pda(),
    }
    .to_account_metas(None)
}

pub fn set_paused_ix(admin: &Pubkey, paused: bool) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: admin_config_metas(admin),
        data: glc_bridge::instruction::SetPaused { paused }.data(),
    }
}

/// Timelock used by the shared test fixtures. Deliberately non-zero: the
/// program refuses a zero timelock, and tests that need to execute warp the
/// clock forward rather than configuring the delay away.
pub const DEFAULT_TEST_TIMELOCK: i64 = 3_600;

pub fn governance_action_pda() -> Pubkey {
    Pubkey::find_program_address(&[b"governance_action"], &glc_bridge::ID).0
}

pub fn get_pending_action(svm: &LiteSVM) -> Option<glc_bridge::state::PendingGovernanceAction> {
    let account = svm.get_account(&governance_action_pda())?;
    if account.data.is_empty() {
        return None;
    }
    glc_bridge::state::PendingGovernanceAction::try_deserialize(&mut account.data.as_slice()).ok()
}

/// The canonical bytes validators sign to approve a rotation.
pub fn rotation_message(epoch: u64, validators: &[Pubkey], threshold: u8) -> Vec<u8> {
    let raw: Vec<[u8; 32]> = validators.iter().map(|v| v.to_bytes()).collect();
    let commitment = anchor_lang::solana_program::hash::hash(
        &glc_bridge_shared::governance::rotation_params(threshold, &raw),
    )
    .to_bytes();
    glc_bridge_shared::governance::governance_message(
        glc_bridge::constants::PROTOCOL_VERSION,
        &glc_bridge::ID.to_bytes(),
        epoch,
        glc_bridge_shared::governance::ACTION_PROPOSE_ROTATION,
        &commitment,
    )
    .to_vec()
}

/// The canonical bytes validators sign to approve a cancellation.
pub fn cancel_message(epoch: u64, pending_action: u8, pending_eta: i64) -> Vec<u8> {
    let commitment = anchor_lang::solana_program::hash::hash(
        &glc_bridge_shared::governance::cancel_params(pending_action, pending_eta),
    )
    .to_bytes();
    glc_bridge_shared::governance::governance_message(
        glc_bridge::constants::PROTOCOL_VERSION,
        &glc_bridge::ID.to_bytes(),
        epoch,
        glc_bridge_shared::governance::ACTION_CANCEL_ROTATION,
        &commitment,
    )
    .to_vec()
}

pub fn propose_rotation_ix(
    proposer: &Pubkey,
    validators: Vec<Pubkey>,
    threshold: u8,
) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::ProposeGovernanceAction {
            proposer: *proposer,
            bridge_config: config_pda(),
            validator_set: validator_set_pda(),
            pending_action: governance_action_pda(),
            instructions_sysvar: anchor_lang::solana_program::sysvar::instructions::ID,
            system_program: solana_sdk::system_program::id(),
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::ProposeValidatorRotation {
            validators,
            threshold,
        }
        .data(),
    }
}

pub fn execute_rotation_ix(executor: &Pubkey) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::ExecuteGovernanceAction {
            executor: *executor,
            bridge_config: config_pda(),
            validator_set: validator_set_pda(),
            pending_action: governance_action_pda(),
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::ExecuteValidatorRotation {}.data(),
    }
}

pub fn cancel_rotation_ix(canceller: &Pubkey) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::CancelGovernanceAction {
            canceller: *canceller,
            bridge_config: config_pda(),
            validator_set: validator_set_pda(),
            pending_action: governance_action_pda(),
            instructions_sysvar: anchor_lang::solana_program::sysvar::instructions::ID,
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::CancelValidatorRotation {}.data(),
    }
}

/// Moves the validator clock forward so a timelock can elapse.
///
/// Also expires the blockhash: time passing means new blocks, and without
/// this an otherwise-identical retry is rejected as a duplicate transaction
/// (`AlreadyProcessed`) before the program ever runs — which would silently
/// mask whatever the test was actually asserting.
pub fn warp_seconds(svm: &mut LiteSVM, seconds: i64) {
    let mut clock = svm.get_sysvar::<anchor_lang::solana_program::clock::Clock>();
    clock.unix_timestamp += seconds;
    svm.set_sysvar(&clock);
    svm.expire_blockhash();
}

pub fn transfer_admin_ix(admin: &Pubkey, new_admin: Pubkey) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: admin_config_metas(admin),
        data: glc_bridge::instruction::TransferAdmin { new_admin }.data(),
    }
}

pub fn accept_admin_ix(new_admin: &Pubkey) -> Instruction {
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

// ------------------------------------------------- Phase 2 (deposit/mint) --

use anchor_lang::solana_program::program_pack::Pack;
use anchor_spl::associated_token::get_associated_token_address;
use anchor_spl::token::spl_token;

use glc_bridge::constants::{SEED_DEPOSIT_CLAIM, SEED_MINT_AUTHORITY};
use glc_bridge::state::DepositClaim;

pub fn mint_authority_pda() -> Pubkey {
    Pubkey::find_program_address(&[SEED_MINT_AUTHORITY], &glc_bridge::ID).0
}

pub fn claim_pda(txid: &[u8; 32], vout: u32) -> Pubkey {
    Pubkey::find_program_address(
        &[SEED_DEPOSIT_CLAIM, txid.as_ref(), &vout.to_le_bytes()],
        &glc_bridge::ID,
    )
    .0
}

pub fn create_wrapped_mint_ix(admin: &Pubkey, mint: &Pubkey) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::CreateWrappedMint {
            admin: *admin,
            bridge_config: config_pda(),
            mint_authority: mint_authority_pda(),
            wrapped_mint: *mint,
            token_program: spl_token::ID,
            system_program: solana_sdk::system_program::id(),
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::CreateWrappedMint {}.data(),
    }
}

/// Initialized bridge + wrapped mint created; returns the mint address.
pub fn setup_with_mint(authority: &Keypair, n: usize, threshold: u8) -> (LiteSVM, Pubkey) {
    let (mut svm, _) = setup_initialized(authority, n, threshold);
    let mint = Keypair::new();
    let ix = create_wrapped_mint_ix(&authority.pubkey(), &mint.pubkey());
    send(&mut svm, ix, authority, &[&mint]).expect("create_wrapped_mint should succeed");
    (svm, mint.pubkey())
}

/// Writes a packed, initialized SPL token account at `address` — used both
/// to pre-create ATAs (at the derived ATA address) without invoking the ATA
/// program, and to fabricate non-ATA token accounts for negative tests.
pub fn write_token_account(svm: &mut LiteSVM, address: &Pubkey, wallet: &Pubkey, mint: &Pubkey) {
    let state = spl_token::state::Account {
        mint: *mint,
        owner: *wallet,
        amount: 0,
        delegate: None.into(),
        state: spl_token::state::AccountState::Initialized,
        is_native: None.into(),
        delegated_amount: 0,
        close_authority: None.into(),
    };
    let mut data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account::pack(state, &mut data).unwrap();
    svm.set_account(
        *address,
        Account {
            lamports: 10_000_000,
            data,
            owner: spl_token::ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

/// Pre-creates the wallet's ATA for `mint` and returns its address.
pub fn create_ata(svm: &mut LiteSVM, wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
    let ata = get_associated_token_address(wallet, mint);
    write_token_account(svm, &ata, wallet, mint);
    ata
}

/// Writes a packed SPL mint account at `address` that is NOT the configured
/// wrapped mint — for wrong-mint negative tests.
pub fn write_foreign_mint(svm: &mut LiteSVM, address: &Pubkey) {
    let state = spl_token::state::Mint {
        mint_authority: Some(mint_authority_pda()).into(),
        supply: 0,
        decimals: glc_bridge::constants::WRAPPED_GLC_DECIMALS,
        is_initialized: true,
        freeze_authority: None.into(),
    };
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint::pack(state, &mut data).unwrap();
    svm.set_account(
        *address,
        Account {
            lamports: 10_000_000,
            data,
            owner: spl_token::ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

pub fn token_balance(svm: &LiteSVM, token_account: &Pubkey) -> u64 {
    let account = svm.get_account(token_account).expect("token account");
    spl_token::state::Account::unpack(&account.data)
        .unwrap()
        .amount
}

pub fn mint_state(svm: &LiteSVM, mint: &Pubkey) -> spl_token::state::Mint {
    let account = svm.get_account(mint).expect("mint account");
    spl_token::state::Mint::unpack(&account.data).unwrap()
}

pub fn get_claim(svm: &LiteSVM, txid: &[u8; 32], vout: u32) -> DepositClaim {
    let account = svm
        .get_account(&claim_pda(txid, vout))
        .expect("claim must exist");
    DepositClaim::try_deserialize(&mut account.data.as_slice()).unwrap()
}

/// Asserts a failed transaction surfaced a specific non-custom Anchor
/// framework error code (e.g. constraint violations).
#[track_caller]
pub fn assert_anchor_error(
    result: Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>,
    expected_code: u32,
) {
    let err = result.expect_err("transaction should have failed").err;
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            assert_eq!(code, expected_code, "wrong anchor error code")
        }
        other => panic!("expected anchor framework error, got {other:?}"),
    }
}

// ------------------------------------------- Phase 3 (proofs/withdrawals) --

use glc_bridge::constants::{PROTOCOL_VERSION, SEED_WITHDRAWAL};
use glc_bridge::state::WithdrawalRequest;
use glc_bridge_shared::claim::deposit_claim_message;
use solana_sdk::ed25519_program;

/// Sends several instructions in one transaction (proof + mint pattern).
#[allow(clippy::result_large_err)]
pub fn send_ixs(
    svm: &mut LiteSVM,
    ixs: &[Instruction],
    payer: &Keypair,
    extra_signers: &[&Keypair],
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra_signers);
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&payer.pubkey()),
        &signers,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
}

/// Canonical claim message for THIS deployment/protocol version.
pub fn claim_message(
    epoch: u64,
    txid: &[u8; 32],
    vout: u32,
    amount: u64,
    recipient: &Pubkey,
    mint: &Pubkey,
) -> Vec<u8> {
    deposit_claim_message(
        PROTOCOL_VERSION,
        &glc_bridge::ID.to_bytes(),
        epoch,
        txid,
        vout,
        amount,
        &recipient.to_bytes(),
        &mint.to_bytes(),
    )
    .to_vec()
}

/// Builds an ed25519-precompile instruction: one shared message, one entry
/// per signer, all offsets self-referential (`u16::MAX`) like production
/// relayers will produce.
pub fn ed25519_proof_ix(signers: &[&Keypair], message: &[u8]) -> Instruction {
    ed25519_proof_ix_with_index(signers, message, u16::MAX)
}

/// Variant with an explicit instruction-index field, for tests that exercise
/// the parser's self-reference requirement.
pub fn ed25519_proof_ix_with_index(
    signers: &[&Keypair],
    message: &[u8],
    ix_index: u16,
) -> Instruction {
    let n = signers.len();
    let entries_end = 2 + n * 14;
    let keys_end = entries_end + n * 32;
    let sigs_end = keys_end + n * 64;
    let msg_off = sigs_end;
    let mut data = vec![0u8; msg_off + message.len()];
    data[0] = n as u8;
    data[1] = 0;
    for (i, kp) in signers.iter().enumerate() {
        let base = 2 + i * 14;
        let pk_off = (entries_end + i * 32) as u16;
        let sig_off = (keys_end + i * 64) as u16;
        data[base..base + 2].copy_from_slice(&sig_off.to_le_bytes());
        data[base + 2..base + 4].copy_from_slice(&ix_index.to_le_bytes());
        data[base + 4..base + 6].copy_from_slice(&pk_off.to_le_bytes());
        data[base + 6..base + 8].copy_from_slice(&ix_index.to_le_bytes());
        data[base + 8..base + 10].copy_from_slice(&(msg_off as u16).to_le_bytes());
        data[base + 10..base + 12].copy_from_slice(&(message.len() as u16).to_le_bytes());
        data[base + 12..base + 14].copy_from_slice(&ix_index.to_le_bytes());
        let pk_pos = entries_end + i * 32;
        data[pk_pos..pk_pos + 32].copy_from_slice(kp.pubkey().as_ref());
        let sig = kp.sign_message(message);
        let sig_pos = keys_end + i * 64;
        data[sig_pos..sig_pos + 64].copy_from_slice(sig.as_ref());
    }
    data[msg_off..].copy_from_slice(message);
    Instruction {
        program_id: ed25519_program::id(),
        accounts: vec![],
        data,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn mint_wrapped_ix(
    submitter: &Pubkey,
    mint: &Pubkey,
    recipient: &Pubkey,
    recipient_token_account: &Pubkey,
    txid: [u8; 32],
    vout: u32,
    amount: u64,
    epoch: u64,
) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::MintWrapped {
            submitter: *submitter,
            bridge_config: config_pda(),
            validator_set: validator_set_pda(),
            deposit_claim: claim_pda(&txid, vout),
            wrapped_mint: *mint,
            mint_authority: mint_authority_pda(),
            recipient: *recipient,
            recipient_token_account: *recipient_token_account,
            instructions_sysvar: solana_sdk::sysvar::instructions::id(),
            token_program: spl_token::ID,
            system_program: solana_sdk::system_program::id(),
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::MintWrapped {
            txid,
            vout,
            amount,
            epoch,
        }
        .data(),
    }
}

pub fn withdrawal_pda(index: u64) -> Pubkey {
    Pubkey::find_program_address(&[SEED_WITHDRAWAL, &index.to_le_bytes()], &glc_bridge::ID).0
}

pub fn burn_wrapped_ix(
    user: &Pubkey,
    mint: &Pubkey,
    user_token_account: &Pubkey,
    withdrawal_index: u64,
    amount: u64,
    glc_address: Vec<u8>,
) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::BurnWrapped {
            user: *user,
            bridge_config: config_pda(),
            wrapped_mint: *mint,
            user_token_account: *user_token_account,
            withdrawal_request: withdrawal_pda(withdrawal_index),
            token_program: spl_token::ID,
            system_program: solana_sdk::system_program::id(),
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::BurnWrapped {
            amount,
            glc_address,
        }
        .data(),
    }
}

pub fn get_withdrawal(svm: &LiteSVM, index: u64) -> WithdrawalRequest {
    let account = svm
        .get_account(&withdrawal_pda(index))
        .expect("withdrawal record must exist");
    WithdrawalRequest::try_deserialize(&mut account.data.as_slice()).unwrap()
}

/// Canonical withdrawal-completion message for THIS deployment (ADR-0018).
///
/// `dest_commitment` is sha256 over the address bytes exactly as the account
/// stores them — the program never decodes base58, so neither does this.
pub fn completion_message(
    epoch: u64,
    index: u64,
    payout_txid: &[u8; 32],
    payout_height: u64,
    amount: u64,
    glc_address: &[u8],
) -> Vec<u8> {
    let dest_commitment: [u8; 32] = anchor_lang::solana_program::hash::hash(glc_address).to_bytes();
    glc_bridge_shared::claim::withdrawal_completion_message(
        PROTOCOL_VERSION,
        &glc_bridge::ID.to_bytes(),
        epoch,
        index,
        payout_txid,
        payout_height,
        amount,
        &dest_commitment,
    )
    .to_vec()
}

pub fn complete_withdrawal_ix(
    submitter: &Pubkey,
    index: u64,
    payout_txid: [u8; 32],
    payout_height: u64,
    epoch: u64,
) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::CompleteWithdrawal {
            submitter: *submitter,
            bridge_config: config_pda(),
            validator_set: validator_set_pda(),
            withdrawal: withdrawal_pda(index),
            instructions_sysvar: solana_sdk::sysvar::instructions::ID,
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::CompleteWithdrawal {
            index,
            payout_txid,
            payout_height,
            epoch,
        }
        .data(),
    }
}

// ---- Wrapped-supply cap (Phase 7h-0, ADR-0014 §11) ----

/// The canonical bytes validators sign to approve a cap INCREASE.
pub fn tvl_raise_message(epoch: u64, new_max: u64) -> Vec<u8> {
    let commitment = anchor_lang::solana_program::hash::hash(
        &glc_bridge_shared::governance::tvl_raise_params(new_max),
    )
    .to_bytes();
    glc_bridge_shared::governance::governance_message(
        glc_bridge::constants::PROTOCOL_VERSION,
        &glc_bridge::ID.to_bytes(),
        epoch,
        glc_bridge_shared::governance::ACTION_PROPOSE_TVL_RAISE,
        &commitment,
    )
    .to_vec()
}

pub fn lower_cap_ix(admin: &Pubkey, new_max: u64) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: admin_config_metas(admin),
        data: glc_bridge::instruction::LowerWrappedSupplyCap { new_max }.data(),
    }
}

pub fn propose_cap_raise_ix(proposer: &Pubkey, new_max: u64) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::ProposeGovernanceAction {
            proposer: *proposer,
            bridge_config: config_pda(),
            validator_set: validator_set_pda(),
            pending_action: governance_action_pda(),
            instructions_sysvar: anchor_lang::solana_program::sysvar::instructions::ID,
            system_program: solana_sdk::system_program::id(),
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::ProposeWrappedSupplyCapRaise { new_max }.data(),
    }
}

pub fn execute_cap_raise_ix(executor: &Pubkey) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::ExecuteCapRaise {
            executor: *executor,
            bridge_config: config_pda(),
            validator_set: validator_set_pda(),
            pending_action: governance_action_pda(),
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::ExecuteWrappedSupplyCapRaise {}.data(),
    }
}
