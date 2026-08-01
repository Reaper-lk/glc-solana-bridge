//! Phase 7f integration tests: `complete_withdrawal` (ADR-0018).
//!
//! Completion is **terminal and irreversible** by design, so these tests are
//! weighted toward what must NOT be possible: completing twice, completing
//! something never paid, and completing a payout other than the one the
//! federation actually attested to.

mod common;
use common::*;

use litesvm::LiteSVM;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

use glc_bridge::errors::BridgeError;
use glc_bridge::state::WithdrawalStatus;
use glc_bridge_shared::claim::ACTION_COMPLETE_WITHDRAWAL;

const TXID: [u8; 32] = [0xCC; 32];
/// A real regtest P2PKH address. The Goldcoin side never sees it here, but
/// using a genuine one keeps the fixture consistent with what the relayer
/// would actually accept.
const GLC_ADDR: &[u8] = b"mimgHRXobzhMFWkXH46awwtiAQLhKRxxbt";
const PAYOUT_TXID: [u8; 32] = [0x7A; 32];
const PAYOUT_HEIGHT: u64 = 4_242;
const WITHDRAW_AMOUNT: u64 = 30_000;

struct Fixture {
    svm: LiteSVM,
    validators: Vec<Keypair>,
    user: Keypair,
    authority: Keypair,
}

/// A bridge with one `Pending` withdrawal at index 0, ready to complete.
fn pending_withdrawal() -> Fixture {
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

    let message = claim_message(0, &TXID, 0, 100_000, &user.pubkey(), &mint);
    let signers: Vec<&Keypair> = vec![&validators[0], &validators[1]];
    send_ixs(
        &mut svm,
        &[
            ed25519_proof_ix(&signers, &message),
            mint_wrapped_ix(
                &user.pubkey(),
                &mint,
                &user.pubkey(),
                &ata,
                TXID,
                0,
                100_000,
                0,
            ),
        ],
        &user,
        &[],
    )
    .expect("funding mint");

    send_ixs(
        &mut svm,
        &[burn_wrapped_ix(
            &user.pubkey(),
            &mint,
            &ata,
            0,
            WITHDRAW_AMOUNT,
            GLC_ADDR.to_vec(),
        )],
        &user,
        &[],
    )
    .expect("burn");

    assert_eq!(get_withdrawal(&svm, 0).status, WithdrawalStatus::Pending);
    Fixture {
        svm,
        validators,
        user,
        authority,
    }
}

/// litesvm's result type. Aliased because the error variant is large and
/// clippy rightly objects to spelling it out at every call site.
type TxResult = std::result::Result<
    litesvm::types::TransactionMetadata,
    litesvm::types::FailedTransactionMetadata,
>;

/// Completes with `n` signers over the canonical message.
#[allow(clippy::result_large_err)]
fn complete_with(
    f: &mut Fixture,
    signer_idx: &[usize],
    index: u64,
    payout_txid: [u8; 32],
    payout_height: u64,
    epoch: u64,
) -> TxResult {
    let message = completion_message(
        epoch,
        index,
        &payout_txid,
        payout_height,
        WITHDRAW_AMOUNT,
        GLC_ADDR,
    );
    let signers: Vec<&Keypair> = signer_idx.iter().map(|i| &f.validators[*i]).collect();
    let user = f.user.insecure_clone();
    send_ixs(
        &mut f.svm,
        &[
            ed25519_proof_ix(&signers, &message),
            complete_withdrawal_ix(&user.pubkey(), index, payout_txid, payout_height, epoch),
        ],
        &user,
        &[],
    )
}

// ---------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------

#[test]
fn completes_a_pending_withdrawal_and_records_the_payout() {
    let mut f = pending_withdrawal();
    complete_with(&mut f, &[0, 1], 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0).expect("completion");

    let w = get_withdrawal(&f.svm, 0);
    assert_eq!(w.status, WithdrawalStatus::Completed);
    assert_eq!(
        w.payout_record(),
        Some((PAYOUT_TXID, PAYOUT_HEIGHT)),
        "the payout identity must be readable from chain state alone"
    );
    assert_eq!(w.amount, WITHDRAW_AMOUNT, "the obligation is unchanged");
}

#[test]
fn the_spare_reserved_bytes_stay_zero() {
    // 40 of 48 bytes are used; the remainder must stay reserved so a later
    // phase can still claim them without a migration.
    let mut f = pending_withdrawal();
    complete_with(&mut f, &[0, 1], 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0).unwrap();
    let w = get_withdrawal(&f.svm, 0);
    assert!(
        w.reserved[40..].iter().all(|b| *b == 0),
        "bytes past the payout record must remain zero: {:?}",
        &w.reserved[40..]
    );
}

#[test]
fn any_quorum_of_threshold_size_completes() {
    for pair in [[0, 1], [0, 2], [1, 2]] {
        let mut f = pending_withdrawal();
        complete_with(&mut f, &pair, 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0)
            .unwrap_or_else(|e| panic!("quorum {pair:?} must complete: {e:?}"));
        assert_eq!(
            get_withdrawal(&f.svm, 0).status,
            WithdrawalStatus::Completed
        );
    }
}

// ---------------------------------------------------------------------
// Replay / terminality — the guards that matter most
// ---------------------------------------------------------------------

#[test]
fn a_second_completion_is_refused_and_changes_nothing() {
    let mut f = pending_withdrawal();
    complete_with(&mut f, &[0, 1], 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0).unwrap();
    let before = get_withdrawal(&f.svm, 0);

    // A DIFFERENT payout, correctly signed: the replay guard must be the
    // status field, not a coincidence about the arguments matching.
    let other_txid = [0x5B; 32];
    assert_bridge_error(
        complete_with(&mut f, &[0, 1], 0, other_txid, 9_999, 0),
        BridgeError::WithdrawalAlreadyCompleted,
    );

    let after = get_withdrawal(&f.svm, 0);
    assert_eq!(after.status, WithdrawalStatus::Completed);
    assert_eq!(
        after.payout_record(),
        before.payout_record(),
        "the original payout record must be untouched"
    );
}

#[test]
fn an_identical_replay_is_also_refused() {
    // Idempotence is NOT the property here: completion is terminal, so even
    // the identical call must fail rather than silently succeed.
    let mut f = pending_withdrawal();
    complete_with(&mut f, &[0, 1], 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0).unwrap();
    // A byte-identical transaction would be rejected by the RUNTIME as
    // already-processed, which is a real defence but not the one under test.
    // Expiring the blockhash forces the call to actually reach the program,
    // so what fails is the status guard itself.
    f.svm.expire_blockhash();
    assert_bridge_error(
        complete_with(&mut f, &[0, 1], 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0),
        BridgeError::WithdrawalAlreadyCompleted,
    );
}

#[test]
fn a_pending_withdrawal_with_a_dirty_payout_region_is_refused() {
    // A non-zero payout region on a Pending withdrawal means an unknown
    // migration already assigned meaning to these bytes. Overwriting them
    // blindly would destroy whatever it wrote, so the instruction refuses
    // rather than guessing.
    let mut f = pending_withdrawal();
    let pda = withdrawal_pda(0);
    let mut account = f.svm.get_account(&pda).unwrap();

    // `reserved` starts at body offset 124, i.e. 132 with the discriminator.
    const RESERVED_OFF: usize = 8 + 124;
    account.data[RESERVED_OFF] = 0x01;
    f.svm.set_account(pda, account).unwrap();
    assert_eq!(
        get_withdrawal(&f.svm, 0).status,
        WithdrawalStatus::Pending,
        "still Pending — only the reserved region was disturbed"
    );

    assert_bridge_error(
        complete_with(&mut f, &[0, 1], 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0),
        BridgeError::PayoutRecordAlreadySet,
    );
    assert_eq!(get_withdrawal(&f.svm, 0).status, WithdrawalStatus::Pending);
}

#[test]
fn a_dirty_byte_anywhere_in_the_payout_region_is_refused() {
    // Every byte of the 40-byte record is checked, not just the first.
    for offset in [0usize, 31, 32, 39] {
        let mut f = pending_withdrawal();
        let pda = withdrawal_pda(0);
        let mut account = f.svm.get_account(&pda).unwrap();
        account.data[8 + 124 + offset] = 0xFF;
        f.svm.set_account(pda, account).unwrap();
        assert_bridge_error(
            complete_with(&mut f, &[0, 1], 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0),
            BridgeError::PayoutRecordAlreadySet,
        );
    }
}

#[test]
fn dirt_in_the_spare_bytes_does_not_block_completion() {
    // Only the 40 bytes the payout record occupies are guarded. The spare 8
    // are still reserved for a future phase, and a future migration writing
    // there must not make completion impossible.
    let mut f = pending_withdrawal();
    let pda = withdrawal_pda(0);
    let mut account = f.svm.get_account(&pda).unwrap();
    account.data[8 + 124 + 40] = 0xAB;
    f.svm.set_account(pda, account).unwrap();
    complete_with(&mut f, &[0, 1], 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0)
        .expect("spare-byte dirt must not block completion");
    assert_eq!(
        get_withdrawal(&f.svm, 0).status,
        WithdrawalStatus::Completed
    );
}

// ---------------------------------------------------------------------
// The federation proof
// ---------------------------------------------------------------------

#[test]
fn below_threshold_signatures_are_refused() {
    let mut f = pending_withdrawal();
    assert_bridge_error(
        complete_with(&mut f, &[0], 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0),
        BridgeError::InsufficientSignatures,
    );
    assert_eq!(get_withdrawal(&f.svm, 0).status, WithdrawalStatus::Pending);
}

#[test]
fn a_duplicated_signer_does_not_reach_threshold() {
    let mut f = pending_withdrawal();
    assert_bridge_error(
        complete_with(&mut f, &[0, 0], 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0),
        BridgeError::DuplicateValidatorSignature,
    );
    assert_eq!(get_withdrawal(&f.svm, 0).status, WithdrawalStatus::Pending);
}

#[test]
fn a_non_validator_signature_is_refused() {
    let mut f = pending_withdrawal();
    let stranger = Keypair::new();
    let message = completion_message(0, 0, &PAYOUT_TXID, PAYOUT_HEIGHT, WITHDRAW_AMOUNT, GLC_ADDR);
    let user = f.user.insecure_clone();
    assert_bridge_error(
        send_ixs(
            &mut f.svm,
            &[
                ed25519_proof_ix(&[&f.validators[0], &stranger], &message),
                complete_withdrawal_ix(&user.pubkey(), 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0),
            ],
            &user,
            &[],
        ),
        BridgeError::UnknownValidatorSignature,
    );
}

#[test]
fn a_stale_epoch_is_refused() {
    let mut f = pending_withdrawal();
    assert_bridge_error(
        complete_with(&mut f, &[0, 1], 0, PAYOUT_TXID, PAYOUT_HEIGHT, 1),
        BridgeError::StaleValidatorEpoch,
    );
}

#[test]
fn a_missing_proof_instruction_is_refused() {
    // The completion instruction alone, with no ed25519 precompile before it.
    let mut f = pending_withdrawal();
    let user = f.user.insecure_clone();
    assert_bridge_error(
        send_ixs(
            &mut f.svm,
            &[complete_withdrawal_ix(
                &user.pubkey(),
                0,
                PAYOUT_TXID,
                PAYOUT_HEIGHT,
                0,
            )],
            &user,
            &[],
        ),
        BridgeError::MissingSignatureVerification,
    );
}

// ---------------------------------------------------------------------
// The message must name the payment (D2)
// ---------------------------------------------------------------------

#[test]
fn a_signature_over_a_different_payout_txid_does_not_authorise() {
    // Validators attested to one payout; the caller submits another.
    let mut f = pending_withdrawal();
    let attested = completion_message(0, 0, &[0x11; 32], PAYOUT_HEIGHT, WITHDRAW_AMOUNT, GLC_ADDR);
    let user = f.user.insecure_clone();
    assert_bridge_error(
        send_ixs(
            &mut f.svm,
            &[
                ed25519_proof_ix(&[&f.validators[0], &f.validators[1]], &attested),
                complete_withdrawal_ix(&user.pubkey(), 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0),
            ],
            &user,
            &[],
        ),
        BridgeError::SignatureMessageMismatch,
    );
    assert_eq!(get_withdrawal(&f.svm, 0).status, WithdrawalStatus::Pending);
}

#[test]
fn a_signature_over_a_different_height_does_not_authorise() {
    let mut f = pending_withdrawal();
    let attested = completion_message(0, 0, &PAYOUT_TXID, 1, WITHDRAW_AMOUNT, GLC_ADDR);
    let user = f.user.insecure_clone();
    assert_bridge_error(
        send_ixs(
            &mut f.svm,
            &[
                ed25519_proof_ix(&[&f.validators[0], &f.validators[1]], &attested),
                complete_withdrawal_ix(&user.pubkey(), 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0),
            ],
            &user,
            &[],
        ),
        BridgeError::SignatureMessageMismatch,
    );
}

#[test]
fn a_signature_over_a_different_amount_does_not_authorise() {
    // The amount comes from the withdrawal record, so a signature naming a
    // different one simply does not match what the program derives.
    let mut f = pending_withdrawal();
    let attested = completion_message(
        0,
        0,
        &PAYOUT_TXID,
        PAYOUT_HEIGHT,
        WITHDRAW_AMOUNT + 1,
        GLC_ADDR,
    );
    let user = f.user.insecure_clone();
    assert_bridge_error(
        send_ixs(
            &mut f.svm,
            &[
                ed25519_proof_ix(&[&f.validators[0], &f.validators[1]], &attested),
                complete_withdrawal_ix(&user.pubkey(), 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0),
            ],
            &user,
            &[],
        ),
        BridgeError::SignatureMessageMismatch,
    );
}

#[test]
fn a_signature_over_a_different_destination_does_not_authorise() {
    // The destination commitment comes from the withdrawal record too.
    let mut f = pending_withdrawal();
    let attested = completion_message(
        0,
        0,
        &PAYOUT_TXID,
        PAYOUT_HEIGHT,
        WITHDRAW_AMOUNT,
        b"mzBc4XEFSdzCDcTxAgf6EZXgsZWpztRhef",
    );
    let user = f.user.insecure_clone();
    assert_bridge_error(
        send_ixs(
            &mut f.svm,
            &[
                ed25519_proof_ix(&[&f.validators[0], &f.validators[1]], &attested),
                complete_withdrawal_ix(&user.pubkey(), 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0),
            ],
            &user,
            &[],
        ),
        BridgeError::SignatureMessageMismatch,
    );
}

#[test]
fn a_deposit_mint_signature_cannot_be_replayed_as_a_completion() {
    // The whole point of the action byte at offset 57 (ADR-0018 D2).
    let mut f = pending_withdrawal();
    let deposit_msg = claim_message(
        0,
        &TXID,
        0,
        WITHDRAW_AMOUNT,
        &f.user.pubkey(),
        &Pubkey::new_unique(),
    );
    let completion_msg =
        completion_message(0, 0, &PAYOUT_TXID, PAYOUT_HEIGHT, WITHDRAW_AMOUNT, GLC_ADDR);
    assert_ne!(deposit_msg[57], completion_msg[57]);
    assert_eq!(completion_msg[57], ACTION_COMPLETE_WITHDRAWAL);

    let user = f.user.insecure_clone();
    assert_bridge_error(
        send_ixs(
            &mut f.svm,
            &[
                ed25519_proof_ix(&[&f.validators[0], &f.validators[1]], &deposit_msg),
                complete_withdrawal_ix(&user.pubkey(), 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0),
            ],
            &user,
            &[],
        ),
        BridgeError::SignatureMessageMismatch,
    );
}

// ---------------------------------------------------------------------
// Argument sanity
// ---------------------------------------------------------------------

#[test]
fn a_zero_payout_txid_is_refused() {
    // A zeroed txid records a payout nobody can look up, defeating the
    // auditability this instruction exists for.
    let mut f = pending_withdrawal();
    assert_bridge_error(
        complete_with(&mut f, &[0, 1], 0, [0u8; 32], PAYOUT_HEIGHT, 0),
        BridgeError::ZeroPayoutTxid,
    );
}

#[test]
fn a_zero_payout_height_is_refused() {
    let mut f = pending_withdrawal();
    assert_bridge_error(
        complete_with(&mut f, &[0, 1], 0, PAYOUT_TXID, 0, 0),
        BridgeError::ZeroPayoutHeight,
    );
}

#[test]
fn completion_is_refused_while_the_bridge_is_paused() {
    let mut f = pending_withdrawal();
    // The admin pauses; completion must stop like every other value flow.
    let authority = f.authority.insecure_clone();
    send(
        &mut f.svm,
        set_paused_ix(&authority.pubkey(), true),
        &authority,
        &[],
    )
    .expect("pause");
    assert_bridge_error(
        complete_with(&mut f, &[0, 1], 0, PAYOUT_TXID, PAYOUT_HEIGHT, 0),
        BridgeError::BridgePaused,
    );
}

#[test]
fn an_unknown_withdrawal_index_cannot_be_completed() {
    let mut f = pending_withdrawal();
    // Index 9 has no account, so the PDA constraint fails before anything
    // else is considered.
    assert!(complete_with(&mut f, &[0, 1], 9, PAYOUT_TXID, PAYOUT_HEIGHT, 0).is_err());
}
