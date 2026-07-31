//! Phase 3 integration tests: wrapped-mint creation and the production
//! `mint_wrapped` path authorized by M-of-N federation proofs carried in an
//! ed25519-precompile instruction (ADR-0010). Harness lives in `common`.

mod common;
use common::*;

use anchor_lang::{InstructionData, ToAccountMetas};
use anchor_spl::token::spl_token;
use litesvm::LiteSVM;
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
};

use glc_bridge::constants::{PROTOCOL_VERSION, SEED_DEPOSIT_CLAIM, WRAPPED_GLC_DECIMALS};
use glc_bridge::errors::BridgeError;
use glc_bridge::state::DepositClaim;
use glc_bridge_shared::claim::deposit_claim_message;

const TXID_A: [u8; 32] = [0xAA; 32];
const TXID_B: [u8; 32] = [0xBB; 32];

/// Full proof-capable fixture: initialized bridge with real validator
/// keypairs, wrapped mint, an arbitrary funded submitter (decision U7: any
/// fee payer), and a funded recipient wallet with its ATA pre-created.
struct Fx {
    svm: LiteSVM,
    authority: Keypair,
    submitter: Keypair,
    validators: Vec<Keypair>,
    mint: Pubkey,
    recipient: Keypair,
    ata: Pubkey,
}

fn fx(n: usize, threshold: u8) -> Fx {
    let authority = Keypair::new();
    let validators: Vec<Keypair> = (0..n).map(|_| Keypair::new()).collect();
    let pubkeys: Vec<Pubkey> = validators.iter().map(|k| k.pubkey()).collect();
    let mut svm = setup_initialized_with(&authority, pubkeys, threshold);

    let mint_kp = Keypair::new();
    send(
        &mut svm,
        create_wrapped_mint_ix(&authority.pubkey(), &mint_kp.pubkey()),
        &authority,
        &[&mint_kp],
    )
    .expect("create_wrapped_mint should succeed");
    let mint = mint_kp.pubkey();

    let submitter = Keypair::new();
    svm.airdrop(&submitter.pubkey(), 100_000_000_000).unwrap();
    let recipient = Keypair::new();
    svm.airdrop(&recipient.pubkey(), 100_000_000_000).unwrap();
    let ata = create_ata(&mut svm, &recipient.pubkey(), &mint);

    Fx {
        svm,
        authority,
        submitter,
        validators,
        mint,
        recipient,
        ata,
    }
}

impl Fx {
    fn signers(&self, idx: &[usize]) -> Vec<&Keypair> {
        idx.iter().map(|&i| &self.validators[i]).collect()
    }

    fn message(&self, epoch: u64, txid: &[u8; 32], vout: u32, amount: u64) -> Vec<u8> {
        claim_message(
            epoch,
            txid,
            vout,
            amount,
            &self.recipient.pubkey(),
            &self.mint,
        )
    }

    fn mint_ix(&self, txid: [u8; 32], vout: u32, amount: u64, epoch: u64) -> Instruction {
        mint_wrapped_ix(
            &self.submitter.pubkey(),
            &self.mint,
            &self.recipient.pubkey(),
            &self.ata,
            txid,
            vout,
            amount,
            epoch,
        )
    }

    /// [ed25519 proof, mint_wrapped] with the proof signed by the given
    /// validators over the canonical message for exactly these arguments.
    fn proof_mint_ixs(
        &self,
        signer_idx: &[usize],
        txid: [u8; 32],
        vout: u32,
        amount: u64,
        epoch: u64,
    ) -> Vec<Instruction> {
        let message = self.message(epoch, &txid, vout, amount);
        vec![
            ed25519_proof_ix(&self.signers(signer_idx), &message),
            self.mint_ix(txid, vout, amount, epoch),
        ]
    }

    #[allow(clippy::result_large_err)]
    fn try_mint(
        &mut self,
        signer_idx: &[usize],
        txid: [u8; 32],
        vout: u32,
        amount: u64,
        epoch: u64,
    ) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>
    {
        let ixs = self.proof_mint_ixs(signer_idx, txid, vout, amount, epoch);
        send_ixs(&mut self.svm, &ixs, &self.submitter, &[])
    }
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

// -------------------------------------------------- mint_wrapped: happy paths --

#[test]
fn mint_happy_path_3_of_5() {
    let mut f = fx(5, 3);
    f.svm.warp_to_slot(4242);
    f.try_mint(&[0, 2, 4], TXID_A, 1, 50_000, 0)
        .expect("3-of-5 proof should mint");

    assert_eq!(token_balance(&f.svm, &f.ata), 50_000);
    assert_eq!(mint_state(&f.svm, &f.mint).supply, 50_000);

    let claim = get_claim(&f.svm, &TXID_A, 1);
    assert_eq!(claim.txid, TXID_A);
    assert_eq!(claim.vout, 1);
    assert_eq!(claim.amount, 50_000);
    assert_eq!(claim.recipient, f.recipient.pubkey());
    assert_eq!(claim.epoch, 0);
    assert_eq!(claim.protocol_version, PROTOCOL_VERSION);
    assert_eq!(claim.slot_created, 4242);
    let account = f.svm.get_account(&claim_pda(&TXID_A, 1)).unwrap();
    assert_eq!(account.data.len(), DepositClaim::SPACE);
    assert_eq!(account.owner, glc_bridge::ID);
}

#[test]
fn mint_exact_threshold_2_of_3() {
    let mut f = fx(3, 2);
    f.try_mint(&[1, 2], TXID_A, 0, 10_000, 0)
        .expect("exact threshold should mint");
    assert_eq!(token_balance(&f.svm, &f.ata), 10_000);
}

#[test]
fn mint_with_more_than_threshold_signatures() {
    let mut f = fx(3, 2);
    f.try_mint(&[0, 1, 2], TXID_A, 0, 10_000, 0)
        .expect("all three signatures should also mint");
    assert_eq!(token_balance(&f.svm, &f.ata), 10_000);
}

#[test]
fn any_fee_payer_may_submit_valid_proof() {
    // The fixture's submitter is already a random wallet with no role; this
    // makes the U7 property explicit with a second, freshly created payer.
    let mut f = fx(3, 2);
    let random_payer = Keypair::new();
    f.svm
        .airdrop(&random_payer.pubkey(), 10_000_000_000)
        .unwrap();
    let message = f.message(0, &TXID_A, 0, 10_000);
    let ixs = vec![
        ed25519_proof_ix(&f.signers(&[0, 1]), &message),
        mint_wrapped_ix(
            &random_payer.pubkey(),
            &f.mint,
            &f.recipient.pubkey(),
            &f.ata,
            TXID_A,
            0,
            10_000,
            0,
        ),
    ];
    send_ixs(&mut f.svm, &ixs, &random_payer, &[]).expect("any payer with a valid proof mints");
    assert_eq!(token_balance(&f.svm, &f.ata), 10_000);
}

#[test]
fn same_txid_different_vout_mints_independently() {
    let mut f = fx(3, 2);
    f.try_mint(&[0, 1], TXID_A, 0, 10_000, 0).unwrap();
    f.try_mint(&[0, 1], TXID_A, 1, 20_000, 0).unwrap();
    assert_eq!(token_balance(&f.svm, &f.ata), 30_000);
    assert_eq!(get_claim(&f.svm, &TXID_A, 0).amount, 10_000);
    assert_eq!(get_claim(&f.svm, &TXID_A, 1).amount, 20_000);
}

// ------------------------------------------- mint_wrapped: proof rejections --

#[test]
fn insufficient_signatures_rejected() {
    let mut f = fx(5, 3);
    assert_bridge_error(
        f.try_mint(&[0, 1], TXID_A, 0, 10_000, 0),
        BridgeError::InsufficientSignatures,
    );
    assert!(f.svm.get_account(&claim_pda(&TXID_A, 0)).is_none());
    assert_eq!(token_balance(&f.svm, &f.ata), 0);
}

#[test]
fn duplicate_signer_does_not_count_twice() {
    let mut f = fx(5, 3);
    // Three entries but only two distinct validators.
    assert_bridge_error(
        f.try_mint(&[0, 1, 0], TXID_A, 0, 10_000, 0),
        BridgeError::DuplicateValidatorSignature,
    );
    assert_eq!(token_balance(&f.svm, &f.ata), 0);
}

#[test]
fn unknown_signer_rejected() {
    let mut f = fx(3, 2);
    let outsider = Keypair::new();
    let message = f.message(0, &TXID_A, 0, 10_000);
    let signers: Vec<&Keypair> = vec![&f.validators[0], &outsider];
    let ixs = vec![
        ed25519_proof_ix(&signers, &message),
        f.mint_ix(TXID_A, 0, 10_000, 0),
    ];
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::UnknownValidatorSignature);
    assert_eq!(token_balance(&f.svm, &f.ata), 0);
}

/// Owner-required domain-separation test: signatures produced for one
/// program id are dead against another deployment even when every other
/// field is identical.
#[test]
fn signatures_for_other_program_id_cannot_replay() {
    let mut f = fx(5, 3);
    let other_deployment = Pubkey::new_unique();

    // Byte-identical message except offsets 17..49 (program id).
    let foreign_message = deposit_claim_message(
        PROTOCOL_VERSION,
        &other_deployment.to_bytes(),
        0,
        &TXID_A,
        0,
        10_000,
        &f.recipient.pubkey().to_bytes(),
        &f.mint.to_bytes(),
    );
    let ixs = vec![
        ed25519_proof_ix(&f.signers(&[0, 1, 2]), &foreign_message),
        f.mint_ix(TXID_A, 0, 10_000, 0),
    ];
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::SignatureMessageMismatch);
    assert_eq!(token_balance(&f.svm, &f.ata), 0);
    assert_eq!(mint_state(&f.svm, &f.mint).supply, 0);
    assert!(f.svm.get_account(&claim_pda(&TXID_A, 0)).is_none());

    // Control: the same validators over the same fields with the CORRECT
    // program id mint successfully — the program id bytes alone gated it.
    f.try_mint(&[0, 1, 2], TXID_A, 0, 10_000, 0)
        .expect("correct-domain proof must mint");
    assert_eq!(token_balance(&f.svm, &f.ata), 10_000);
}

/// Owner-required epoch-binding test: rotation kills outstanding proofs
/// even when the validator keys themselves are unchanged.
#[test]
fn epoch_rotation_invalidates_proofs_even_with_unchanged_keys() {
    let mut f = fx(5, 3);

    // Signed while epoch 0 was current.
    let epoch0_message = f.message(0, &TXID_A, 0, 10_000);
    let epoch0_proof = ed25519_proof_ix(&f.signers(&[0, 1, 2]), &epoch0_message);

    // Rotate to the IDENTICAL set and threshold: epoch 0 -> 1, keys unchanged.
    // Rotation now runs through the Phase 7a governance flow (ADR-0014):
    // threshold-approved proposal, timelock, then permissionless execution.
    let same_keys: Vec<Pubkey> = f.validators.iter().map(|k| k.pubkey()).collect();
    let gov_msg = rotation_message(0, &same_keys, 3);
    let gov_ixs = vec![
        ed25519_proof_ix(&f.signers(&[0, 1, 2]), &gov_msg),
        propose_rotation_ix(&f.authority.pubkey(), same_keys.clone(), 3),
    ];
    send_ixs(&mut f.svm, &gov_ixs, &f.authority, &[])
        .expect("same-membership rotation proposal succeeds");
    warp_seconds(&mut f.svm, DEFAULT_TEST_TIMELOCK);
    send(
        &mut f.svm,
        execute_rotation_ix(&f.authority.pubkey()),
        &f.authority,
        &[],
    )
    .expect("same-membership rotation executes");
    let set = get_validator_set(&f.svm);
    assert_eq!(set.epoch, 1);
    assert_eq!(set.validators, same_keys);
    assert_eq!(set.threshold, 3);

    // Leg (a): epoch argument 0 -> rejected at the freshness gate.
    let ixs = vec![epoch0_proof.clone(), f.mint_ix(TXID_A, 0, 10_000, 0)];
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::StaleValidatorEpoch);

    // Leg (b): epoch argument 1 with the old signatures -> the expected
    // message now carries epoch 1, the signed bytes carry epoch 0.
    let ixs = vec![epoch0_proof, f.mint_ix(TXID_A, 0, 10_000, 1)];
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::SignatureMessageMismatch);

    assert_eq!(token_balance(&f.svm, &f.ata), 0);
    assert_eq!(mint_state(&f.svm, &f.mint).supply, 0);
    assert!(f.svm.get_account(&claim_pda(&TXID_A, 0)).is_none());

    // Control: the SAME keys re-sign with epoch 1 -> mints.
    f.try_mint(&[0, 1, 2], TXID_A, 0, 10_000, 1)
        .expect("re-signed current-epoch proof must mint");
    assert_eq!(get_claim(&f.svm, &TXID_A, 0).epoch, 1);
}

#[test]
fn wrong_recipient_in_signed_message() {
    let mut f = fx(3, 2);
    // Validators signed for the fixture recipient; the submitter tries to
    // redirect the mint to another wallet.
    let thief = Keypair::new();
    let thief_ata = create_ata(&mut f.svm, &thief.pubkey(), &f.mint);
    let message = f.message(0, &TXID_A, 0, 10_000); // recipient = fixture wallet
    let ixs = vec![
        ed25519_proof_ix(&f.signers(&[0, 1]), &message),
        mint_wrapped_ix(
            &f.submitter.pubkey(),
            &f.mint,
            &thief.pubkey(),
            &thief_ata,
            TXID_A,
            0,
            10_000,
            0,
        ),
    ];
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::SignatureMessageMismatch);
    assert_eq!(token_balance(&f.svm, &thief_ata), 0);
}

#[test]
fn wrong_amount_in_signed_message() {
    let mut f = fx(3, 2);
    let message = f.message(0, &TXID_A, 0, 10_000);
    let ixs = vec![
        ed25519_proof_ix(&f.signers(&[0, 1]), &message),
        f.mint_ix(TXID_A, 0, 999_999, 0), // inflated amount
    ];
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::SignatureMessageMismatch);
    assert_eq!(token_balance(&f.svm, &f.ata), 0);
}

#[test]
fn wrong_txid_in_signed_message() {
    let mut f = fx(3, 2);
    let message = f.message(0, &TXID_A, 0, 10_000);
    let ixs = vec![
        ed25519_proof_ix(&f.signers(&[0, 1]), &message),
        f.mint_ix(TXID_B, 0, 10_000, 0),
    ];
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::SignatureMessageMismatch);
}

#[test]
fn wrong_vout_in_signed_message() {
    let mut f = fx(3, 2);
    let message = f.message(0, &TXID_A, 0, 10_000);
    let ixs = vec![
        ed25519_proof_ix(&f.signers(&[0, 1]), &message),
        f.mint_ix(TXID_A, 1, 10_000, 0),
    ];
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::SignatureMessageMismatch);
}

// --------------------------------------- mint_wrapped: structural rejections --

#[test]
fn replay_of_fully_valid_proof_rejected() {
    let mut f = fx(3, 2);
    let ixs = f.proof_mint_ixs(&[0, 1], TXID_A, 7, 30_000, 0);
    send_ixs(&mut f.svm, &ixs, &f.submitter, &[]).expect("first mint succeeds");

    f.svm.expire_blockhash();
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert!(result.is_err(), "replaying the same valid proof must fail");
    assert_eq!(token_balance(&f.svm, &f.ata), 30_000);
    assert_eq!(mint_state(&f.svm, &f.mint).supply, 30_000);
}

#[test]
fn missing_verification_instruction_rejected() {
    let mut f = fx(3, 2);
    let ix = f.mint_ix(TXID_A, 0, 10_000, 0);
    let result = send_ixs(&mut f.svm, &[ix], &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::MissingSignatureVerification);
}

#[test]
fn admin_signature_alone_mints_nothing() {
    // The Phase 2 admin bypass is gone: the admin submitting without a
    // federation proof is just another submitter with no proof.
    let mut f = fx(3, 2);
    let ix = mint_wrapped_ix(
        &f.authority.pubkey(),
        &f.mint,
        &f.recipient.pubkey(),
        &f.ata,
        TXID_A,
        0,
        10_000,
        0,
    );
    let authority = f.authority.insecure_clone();
    let result = send_ixs(&mut f.svm, &[ix], &authority, &[]);
    assert_bridge_error(result, BridgeError::MissingSignatureVerification);
    assert_eq!(token_balance(&f.svm, &f.ata), 0);
}

#[test]
fn verification_instruction_must_be_adjacent() {
    let mut f = fx(3, 2);
    let message = f.message(0, &TXID_A, 0, 10_000);
    let ixs = vec![
        ed25519_proof_ix(&f.signers(&[0, 1]), &message),
        // An unrelated instruction sits at relative -1 of the mint.
        system_instruction::transfer(&f.submitter.pubkey(), &f.recipient.pubkey(), 1),
        f.mint_ix(TXID_A, 0, 10_000, 0),
    ];
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::MissingSignatureVerification);
}

#[test]
fn extra_unrelated_ed25519_instruction_is_benign() {
    let mut f = fx(3, 2);
    // A valid-but-irrelevant ed25519 instruction elsewhere in the
    // transaction neither helps nor hurts; the proof at relative -1 rules.
    let junk_signer = Keypair::new();
    let junk = ed25519_proof_ix(&[&junk_signer], b"completely unrelated bytes");
    let message = f.message(0, &TXID_A, 0, 10_000);
    let ixs = vec![
        junk,
        ed25519_proof_ix(&f.signers(&[0, 1]), &message),
        f.mint_ix(TXID_A, 0, 10_000, 0),
    ];
    send_ixs(&mut f.svm, &ixs, &f.submitter, &[])
        .expect("unrelated ed25519 instruction must not break a valid proof");
    assert_eq!(token_balance(&f.svm, &f.ata), 10_000);
}

#[test]
fn non_self_referential_entries_rejected() {
    let mut f = fx(3, 2);
    let message = f.message(0, &TXID_A, 0, 10_000);
    // Entries reference instruction index 0 — which IS the ed25519
    // instruction itself, so the precompile verifies fine — but the program
    // requires the self-reference sentinel and must reject.
    let ixs = vec![
        ed25519_proof_ix_with_index(&f.signers(&[0, 1]), &message, 0),
        f.mint_ix(TXID_A, 0, 10_000, 0),
    ];
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::MalformedSignatureVerification);
    assert_eq!(token_balance(&f.svm, &f.ata), 0);
}

// ------------------------------------------ mint_wrapped: state rejections --

#[test]
fn rejects_while_paused_and_recovers_on_unpause() {
    let mut f = fx(3, 2);
    let authority = f.authority.insecure_clone();
    send(
        &mut f.svm,
        set_paused_ix(&authority.pubkey(), true),
        &authority,
        &[],
    )
    .unwrap();

    let ixs = f.proof_mint_ixs(&[0, 1], TXID_A, 0, 10_000, 0);
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::BridgePaused);
    assert_eq!(token_balance(&f.svm, &f.ata), 0);

    send(
        &mut f.svm,
        set_paused_ix(&authority.pubkey(), false),
        &authority,
        &[],
    )
    .unwrap();
    f.svm.expire_blockhash();
    let ixs = f.proof_mint_ixs(&[0, 1], TXID_A, 0, 10_000, 0);
    send_ixs(&mut f.svm, &ixs, &f.submitter, &[]).expect("mint works again after unpause");
    assert_eq!(token_balance(&f.svm, &f.ata), 10_000);
}

#[test]
fn rejects_zero_amount() {
    let mut f = fx(3, 2);
    assert_bridge_error(
        f.try_mint(&[0, 1], TXID_A, 0, 0, 0),
        BridgeError::ZeroDepositAmount,
    );
}

#[test]
fn rejects_below_min_deposit() {
    let mut f = fx(3, 2);
    // Harness initializes min_deposit = 1_000.
    assert_bridge_error(
        f.try_mint(&[0, 1], TXID_A, 0, 999, 0),
        BridgeError::BelowMinimumDeposit,
    );
    assert_eq!(token_balance(&f.svm, &f.ata), 0);
}

#[test]
fn rejects_before_mint_is_created() {
    let authority = Keypair::new();
    let validators: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
    let pubkeys: Vec<Pubkey> = validators.iter().map(|k| k.pubkey()).collect();
    let mut svm = setup_initialized_with(&authority, pubkeys, 2);
    let foreign_mint = Pubkey::new_unique();
    write_foreign_mint(&mut svm, &foreign_mint);
    let recipient = Pubkey::new_unique();
    let ata = create_ata(&mut svm, &recipient, &foreign_mint);
    let ix = mint_wrapped_ix(
        &authority.pubkey(),
        &foreign_mint,
        &recipient,
        &ata,
        TXID_A,
        0,
        10_000,
        0,
    );
    assert_bridge_error(
        send(&mut svm, ix, &authority, &[]),
        BridgeError::MintNotConfigured,
    );
}

#[test]
fn rejects_wrong_mint_account() {
    let mut f = fx(3, 2);
    let foreign_mint = Pubkey::new_unique();
    write_foreign_mint(&mut f.svm, &foreign_mint);
    let foreign_ata = create_ata(&mut f.svm, &f.recipient.pubkey(), &foreign_mint);
    let message = f.message(0, &TXID_A, 0, 10_000);
    let ixs = vec![
        ed25519_proof_ix(&f.signers(&[0, 1]), &message),
        mint_wrapped_ix(
            &f.submitter.pubkey(),
            &foreign_mint,
            &f.recipient.pubkey(),
            &foreign_ata,
            TXID_A,
            0,
            10_000,
            0,
        ),
    ];
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_bridge_error(result, BridgeError::WrongWrappedMint);
}

#[test]
fn claim_pda_uses_little_endian_vout() {
    let mut f = fx(3, 2);
    let vout: u32 = 0x0102_0304;
    f.try_mint(&[0, 1], TXID_A, vout, 10_000, 0).unwrap();

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
    assert!(f.svm.get_account(&le).is_some(), "LE-derived claim exists");
    assert!(
        f.svm.get_account(&be).is_none(),
        "BE derivation must not match"
    );
}

#[test]
fn claim_pda_from_reordered_txid_bytes_does_not_resolve() {
    let mut f = fx(3, 2);
    let mut txid = [0u8; 32];
    for (i, byte) in txid.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let mut reversed = txid;
    reversed.reverse();
    assert_ne!(txid, reversed);

    // Proof over the canonical txid; claim account derived from the
    // reversed byte order, as a byte-order-confused client would.
    let message = f.message(0, &txid, 0, 10_000);
    let wrong_claim = claim_pda(&reversed, 0);
    let mint_ix = Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::MintWrapped {
            submitter: f.submitter.pubkey(),
            bridge_config: config_pda(),
            validator_set: validator_set_pda(),
            deposit_claim: wrong_claim,
            wrapped_mint: f.mint,
            mint_authority: mint_authority_pda(),
            recipient: f.recipient.pubkey(),
            recipient_token_account: f.ata,
            instructions_sysvar: solana_sdk::sysvar::instructions::id(),
            token_program: spl_token::ID,
            system_program: solana_sdk::system_program::id(),
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::MintWrapped {
            txid,
            vout: 0,
            amount: 10_000,
            epoch: 0,
        }
        .data(),
    };
    let ixs = vec![ed25519_proof_ix(&f.signers(&[0, 1]), &message), mint_ix];
    let result = send_ixs(&mut f.svm, &ixs, &f.submitter, &[]);
    assert_anchor_error(
        result,
        anchor_lang::error::ErrorCode::ConstraintSeeds as u32,
    );
    assert!(f.svm.get_account(&wrong_claim).is_none());
    assert!(f.svm.get_account(&claim_pda(&txid, 0)).is_none());
    assert_eq!(mint_state(&f.svm, &f.mint).supply, 0);
}

// ----------------------------------------------------------- legacy surface --

#[test]
fn testonly_instruction_no_longer_exists() {
    let mut f = fx(3, 2);
    // Old Phase 2 discriminator: sha256("global:mint_wrapped_testonly")[..8].
    let digest = solana_sdk::hash::hash(b"global:mint_wrapped_testonly");
    let mut data = digest.to_bytes()[..8].to_vec();
    data.extend_from_slice(&TXID_A);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&10_000u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());

    // The old account list, admin-signed, exactly as Phase 2 clients built it.
    let authority = f.authority.insecure_clone();
    let ix = Instruction {
        program_id: glc_bridge::ID,
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(authority.pubkey(), true),
            solana_sdk::instruction::AccountMeta::new_readonly(config_pda(), false),
            solana_sdk::instruction::AccountMeta::new_readonly(validator_set_pda(), false),
            solana_sdk::instruction::AccountMeta::new(claim_pda(&TXID_A, 0), false),
            solana_sdk::instruction::AccountMeta::new(f.mint, false),
            solana_sdk::instruction::AccountMeta::new_readonly(mint_authority_pda(), false),
            solana_sdk::instruction::AccountMeta::new_readonly(f.recipient.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(f.ata, false),
            solana_sdk::instruction::AccountMeta::new_readonly(spl_token::ID, false),
            solana_sdk::instruction::AccountMeta::new_readonly(
                solana_sdk::system_program::id(),
                false,
            ),
        ],
        data,
    };
    let result = send_ixs(&mut f.svm, &[ix], &authority, &[]);
    assert_anchor_error(
        result,
        anchor_lang::error::ErrorCode::InstructionFallbackNotFound as u32,
    );
    assert_eq!(token_balance(&f.svm, &f.ata), 0);
    assert_eq!(mint_state(&f.svm, &f.mint).supply, 0);
}

#[test]
fn forged_mint_authority_cannot_mint_directly() {
    let mut f = fx(3, 2);
    let forger = Keypair::new();
    f.svm.airdrop(&forger.pubkey(), 10_000_000_000).unwrap();
    let ix = spl_token::instruction::mint_to_checked(
        &spl_token::ID,
        &f.mint,
        &f.ata,
        &forger.pubkey(),
        &[],
        1_000_000,
        WRAPPED_GLC_DECIMALS,
    )
    .unwrap();
    let result = send(&mut f.svm, ix, &forger, &[]);
    assert!(
        result.is_err(),
        "direct mint with forged authority must fail"
    );
    assert_eq!(mint_state(&f.svm, &f.mint).supply, 0);
}
