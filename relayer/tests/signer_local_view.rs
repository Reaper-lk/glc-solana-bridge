//! What a real signer will and will not derive (Phase 7d, ADR-0016).
//!
//! [`DbLocalView`] is the concrete [`LocalView`] `signer-server` runs on, and
//! it is where the federation's central guarantee actually lands: a signing
//! request is answered from *this* validator's persisted observations, never
//! from anything the requester said.
//!
//! These tests drive it against a real SQLite database (a file, never
//! `:memory:`, matching the rest of the suite) so the answers come from the
//! same code path production uses — including the reload-and-recompute
//! integrity safeguards, which a signer must run rather than trust.

use std::sync::Arc;

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};

use glc_relayer::glc::db::{Db, DepositState, NewBlock, NewCandidate, NewClaimArtifact};
use glc_relayer::glc::deposit::build_claim_message;
use glc_relayer::glc::withdrawal_db::{
    canonical_payout_intent, payout_commitment, NewPayout, NewWithdrawalRequest, ObservedUtxo,
    VaultUtxo, WithdrawalState,
};
use glc_relayer::p2p::policy::{
    evaluate, Action, Decision, LocalView, Refusal, SeenSet, SigningIdentity, SigningRequest,
};
use glc_relayer::p2p::service::{mint_request, SignerService};
use glc_relayer::p2p::view::{DbLocalView, EpochObservation, MAX_VIEW_STALENESS};

const TXID: [u8; 32] = [0xAA; 32];
const VOUT: u32 = 2;
const EPOCH: u64 = 3;
const PROTOCOL_VERSION: u8 = 1;
const AMOUNT: u64 = 75_000;

struct Seeded {
    _dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    message: Vec<u8>,
    deposit_id: i64,
}

/// Seeds one `ReadyForSignature` deposit with a consistent claim artifact.
fn seed(state: DepositState) -> Seeded {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("signer.sqlite");
    let mut db = Db::open(&db_path).unwrap();

    let program_id = Pubkey::new_unique();
    let wrapped_mint = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();

    let ids = db
        .ingest_block(
            &NewBlock {
                height: 1,
                hash: [0x11; 32],
                prev_hash: [0u8; 32],
                block_time: 0,
                indexed_at: 0,
            },
            &[NewCandidate {
                txid: TXID,
                vout: VOUT as i64,
                amount_atomic: AMOUNT,
                recipient: recipient.to_bytes(),
                block_height: 1,
                block_hash: [0x11; 32],
                raw_tx_hex: "deadbeef".to_string(),
                discovered_at: 0,
                initial_state: DepositState::Candidate,
                failure_reason: None,
            }],
        )
        .unwrap();
    let deposit_id = ids[0];

    let message = build_claim_message(
        PROTOCOL_VERSION,
        &program_id.to_bytes(),
        EPOCH,
        &TXID,
        VOUT,
        AMOUNT,
        &recipient.to_bytes(),
        &wrapped_mint.to_bytes(),
    );
    let message_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(message).into()
    };
    let artifact = NewClaimArtifact {
        deposit_id,
        canonical_message: message,
        message_hash,
        protocol_version: PROTOCOL_VERSION,
        validator_epoch: EPOCH,
        program_id: program_id.to_bytes(),
        wrapped_mint: wrapped_mint.to_bytes(),
        created_at: 0,
    };
    db.transition_state(deposit_id, DepositState::Confirming, 1, None, None)
        .unwrap();
    db.transition_state(
        deposit_id,
        DepositState::ReadyForSignature,
        2,
        None,
        Some(&artifact),
    )
    .unwrap();

    if state != DepositState::ReadyForSignature {
        db.transition_state(deposit_id, state, 3, None, None)
            .unwrap();
    }

    Seeded {
        _dir: dir,
        db_path,
        message: message.to_vec(),
        deposit_id,
    }
}

fn view_at(seeded: &Seeded, observed_at: i64) -> DbLocalView {
    let db = Db::open(&seeded.db_path).unwrap();
    DbLocalView::new(db, Arc::new(EpochObservation::seeded(EPOCH, observed_at)))
}

fn fresh_view(seeded: &Seeded) -> DbLocalView {
    view_at(seeded, now_unix())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn deposit_identity() -> SigningIdentity {
    SigningIdentity::Deposit {
        txid: TXID,
        vout: VOUT,
    }
}

#[test]
fn derives_the_canonical_message_for_a_deposit_it_has_itself_observed() {
    let s = seed(DepositState::ReadyForSignature);
    let v = fresh_view(&s);
    assert_eq!(
        v.derive_message(Action::MintDeposit, &deposit_identity()),
        Some(s.message.clone()),
        "the view must reproduce the claim message from its own persisted state"
    );
    assert_eq!(v.observed_epoch(), EPOCH);
    assert!(v.view_is_fresh());
}

#[test]
fn derives_nothing_for_a_deposit_it_has_never_seen() {
    // The property that makes a compromised requester harmless: it cannot
    // invent a deposit and have a validator authorize a mint for it.
    let s = seed(DepositState::ReadyForSignature);
    let v = fresh_view(&s);
    let stranger = SigningIdentity::Deposit {
        txid: [0x99; 32],
        vout: 0,
    };
    assert_eq!(v.derive_message(Action::MintDeposit, &stranger), None);
}

#[test]
fn derives_nothing_for_the_same_txid_at_a_different_vout() {
    // A deposit is identified by its outpoint, not its transaction: signing
    // for the wrong vout would authorize a mint against an output that was
    // never verified.
    let s = seed(DepositState::ReadyForSignature);
    let v = fresh_view(&s);
    let other_vout = SigningIdentity::Deposit {
        txid: TXID,
        vout: VOUT + 1,
    };
    assert_eq!(v.derive_message(Action::MintDeposit, &other_vout), None);
}

#[test]
fn a_submitted_deposit_is_still_derivable_so_a_resubmission_can_be_signed() {
    // Phase 5's recovery model re-signs `Submitted` deposits whose claim PDA
    // does not yet exist. A signer that refused them would strand exactly
    // the deposits that most need recovering.
    let s = seed(DepositState::Submitted);
    let v = fresh_view(&s);
    assert_eq!(
        v.derive_message(Action::MintDeposit, &deposit_identity()),
        Some(s.message.clone())
    );
}

#[test]
fn a_completed_or_terminal_deposit_is_not_derivable() {
    // `Minted` in particular: the claim PDA already exists, so a fresh
    // signature could only ever serve a replay.
    for state in [
        DepositState::Minted,
        DepositState::Failed,
        DepositState::Orphaned,
        DepositState::IntegrityHalted,
    ] {
        let s = seed(state);
        let v = fresh_view(&s);
        assert_eq!(
            v.derive_message(Action::MintDeposit, &deposit_identity()),
            None,
            "a {state:?} deposit must not be signable"
        );
    }
}

#[test]
fn a_deposit_still_confirming_is_not_derivable() {
    // It has not reached the confirmation depth this validator requires, so
    // it has not been verified — regardless of what a peer claims.
    let s = seed(DepositState::Confirming);
    let v = fresh_view(&s);
    assert_eq!(
        v.derive_message(Action::MintDeposit, &deposit_identity()),
        None
    );
}

#[test]
fn tampered_persisted_state_halts_the_deposit_instead_of_being_signed() {
    // The signer runs the reload-and-recompute safeguard rather than reading
    // the stored message: if its own database has drifted, it must not
    // authorize a mint, and the anomaly must be recorded as such.
    let s = seed(DepositState::ReadyForSignature);
    {
        // A second connection to the same file, as the existing
        // reload-and-recompute tests do: change the amount out from under
        // the frozen commitment.
        let conn = rusqlite::Connection::open(&s.db_path).unwrap();
        conn.execute(
            "UPDATE deposit_candidates SET amount_atomic = ?1 WHERE id = ?2",
            rusqlite::params![(AMOUNT + 1).to_le_bytes().to_vec(), s.deposit_id],
        )
        .unwrap();
    }

    let v = fresh_view(&s);
    assert_eq!(
        v.derive_message(Action::MintDeposit, &deposit_identity()),
        None,
        "drifted state must never yield a signable message"
    );

    let db = Db::open(&s.db_path).unwrap();
    let row = db.get_by_id(s.deposit_id).unwrap().unwrap();
    assert_eq!(
        row.state,
        DepositState::IntegrityHalted,
        "the signer must halt the anomaly, not merely decline it"
    );
}

#[test]
fn a_stale_view_refuses_a_request_it_would_otherwise_have_signed() {
    // Same database, same deposit, same epoch — only the observation's age
    // differs. A validator that has stopped hearing from the chain cannot
    // tell a current epoch from a superseded one.
    let s = seed(DepositState::ReadyForSignature);
    let request = SigningRequest {
        request_id: vec![1],
        action: Action::MintDeposit,
        epoch: EPOCH,
        canonical_message: s.message.clone(),
        identity: deposit_identity(),
        expiry_unix: now_unix() + 60,
    };

    let fresh = fresh_view(&s);
    assert!(matches!(
        evaluate(&request, &fresh, &SeenSet::new(), now_unix()),
        Decision::Sign(_)
    ));

    let stale = view_at(&s, now_unix() - MAX_VIEW_STALENESS.as_secs() as i64 - 1);
    assert!(!stale.view_is_fresh());
    assert_eq!(
        evaluate(&request, &stale, &SeenSet::new(), now_unix()),
        Decision::Refuse(Refusal::StaleView)
    );
}

#[test]
fn an_action_that_does_not_match_its_identity_derives_nothing() {
    // A payout action carrying a deposit identity is a protocol error, and
    // must refuse rather than fall through to something plausible.
    let s = seed(DepositState::ReadyForSignature);
    let v = fresh_view(&s);
    assert_eq!(v.derive_message(Action::Payout, &deposit_identity()), None);
    assert_eq!(
        v.derive_message(
            Action::MintDeposit,
            &SigningIdentity::Payout {
                withdrawal_index: 0,
                quorum_attempt: 0
            }
        ),
        None
    );
}

#[test]
fn governance_is_not_signable_through_this_view() {
    let s = seed(DepositState::ReadyForSignature);
    let v = fresh_view(&s);
    assert_eq!(
        v.derive_message(
            Action::Governance,
            &SigningIdentity::Governance { epoch: EPOCH }
        ),
        None
    );
}

#[test]
fn a_payout_for_a_withdrawal_this_validator_does_not_have_is_not_derivable() {
    let s = seed(DepositState::ReadyForSignature);
    let v = fresh_view(&s);
    assert_eq!(
        v.derive_message(
            Action::Payout,
            &SigningIdentity::Payout {
                withdrawal_index: 42,
                quorum_attempt: 0
            }
        ),
        None
    );
}

#[test]
fn the_full_service_signs_only_what_this_view_derives() {
    // End to end through `SignerService`: the requester's bytes are compared
    // against the view's, and the signature covers the view's.
    let s = seed(DepositState::ReadyForSignature);
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();
    let service = SignerService::new(keypair, fresh_view(&s));

    let resp = service
        .handle(mint_request(vec![1], EPOCH, s.message.clone(), TXID, VOUT))
        .expect("a matching request is signed");
    let sig = solana_sdk::signature::Signature::try_from(resp.signature.as_slice()).unwrap();
    assert!(
        sig.verify(pubkey.as_ref(), &s.message),
        "the signature must verify over the locally derived message"
    );

    let forged = service.handle(mint_request(
        vec![2],
        EPOCH,
        b"attacker-supplied-bytes".to_vec(),
        TXID,
        VOUT,
    ));
    assert_eq!(forged.unwrap_err(), Refusal::MessageMismatch);
}

// ---------------------------------------------------------------------
// Payout intent derivation (ADR-0015)
// ---------------------------------------------------------------------

const VAULT_HASH: [u8; 20] = [0x77; 20];
const DEST: [u8; 20] = [0x33; 20];
const CHANGE: [u8; 20] = [0x44; 20];
const WITHDRAWAL_INDEX: i64 = 4;
const WITHDRAWAL_AMOUNT: u64 = 500_000;
const QUORUM: &[u8] = &[0, 2];

/// Seeds a withdrawal advanced to `Signing` with a self-consistent payout
/// at `quorum_attempt`, returning the canonical intent a signer must derive.
fn seed_payout(quorum_attempt: u32, state: WithdrawalState) -> (Seeded, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("signer.sqlite");
    let mut db = Db::open(&db_path).unwrap();

    db.observe_withdrawal(&NewWithdrawalRequest {
        withdrawal_index: WITHDRAWAL_INDEX,
        pda: [0x55; 32],
        amount_atomic: WITHDRAWAL_AMOUNT,
        requester: [0x11; 32],
        glc_address: glc_relayer::withdrawal::address::encode_p2pkh(&DEST),
        glc_address_hash160: DEST,
        requested_at_slot: 100,
        protocol_version: PROTOCOL_VERSION,
        observed_at: 1_000,
        observed_at_slot: 100,
    })
    .unwrap();

    let inputs = vec![VaultUtxo {
        txid: [0x66; 32],
        txid_hex: "66".repeat(32),
        vout: 0,
        amount_atomic: WITHDRAWAL_AMOUNT + 100_000,
        script_pubkey_hex: glc_relayer::withdrawal::address::p2pkh_script_hex(&CHANGE),
        confirmations: 10,
    }];
    let observed: Vec<ObservedUtxo> = inputs
        .iter()
        .map(|u| ObservedUtxo {
            txid: u.txid,
            vout: u.vout,
            amount_atomic: u.amount_atomic,
            script_pubkey_hex: u.script_pubkey_hex.clone(),
            confirmations: u.confirmations,
        })
        .collect();
    db.sync_vault_utxos(&observed, 1, 1_000).unwrap();
    db.reserve_utxos(WITHDRAWAL_INDEX, &inputs, 1_000).unwrap();

    let fee = 20_000u64;
    let change = inputs[0].amount_atomic - WITHDRAWAL_AMOUNT - fee;
    let intent = canonical_payout_intent(
        PROTOCOL_VERSION,
        WITHDRAWAL_INDEX,
        &VAULT_HASH,
        &DEST,
        WITHDRAWAL_AMOUNT,
        fee,
        change,
        &CHANGE,
        quorum_attempt,
        QUORUM,
        &inputs,
    );
    db.create_payout(&NewPayout {
        withdrawal_index: WITHDRAWAL_INDEX,
        vault_script_hash: VAULT_HASH,
        quorum_indices: QUORUM.to_vec(),
        quorum_attempt,
        commitment_hash: payout_commitment(&intent),
        intent_bytes: intent.clone(),
        fee_atomic: fee,
        payout_atomic: WITHDRAWAL_AMOUNT,
        change_atomic: change,
        change_address: Some(glc_relayer::withdrawal::address::encode_p2pkh(&CHANGE)),
        unsigned_tx_hex: "0100000001deadbeef".to_string(),
        inputs,
        built_at: 1_100,
    })
    .unwrap();
    db.transition_withdrawal(WITHDRAWAL_INDEX, WithdrawalState::Validated, 1_010, None)
        .unwrap();
    db.transition_withdrawal(WITHDRAWAL_INDEX, WithdrawalState::Building, 1_020, None)
        .unwrap();
    // Walk the legal ladder rather than jumping: the state machine rejects
    // illegal transitions, and a fixture that bypassed it would not
    // represent any state the executor can actually produce.
    for (step, at) in [
        (WithdrawalState::Signing, 1_030),
        (WithdrawalState::Broadcast, 1_040),
        (WithdrawalState::Confirming, 1_050),
        (WithdrawalState::Completed, 1_060),
    ] {
        if state == WithdrawalState::Building {
            break;
        }
        db.transition_withdrawal(WITHDRAWAL_INDEX, step, at, None)
            .unwrap();
        if step == state {
            break;
        }
    }

    (
        Seeded {
            _dir: dir,
            db_path,
            message: Vec::new(),
            deposit_id: 0,
        },
        intent,
    )
}

fn payout_identity(quorum_attempt: u32) -> SigningIdentity {
    SigningIdentity::Payout {
        withdrawal_index: WITHDRAWAL_INDEX as u64,
        quorum_attempt,
    }
}

#[test]
fn derives_the_canonical_payout_intent_for_the_designated_attempt() {
    let (s, intent) = seed_payout(0, WithdrawalState::Signing);
    let v = fresh_view(&s);
    assert_eq!(
        v.derive_message(Action::Payout, &payout_identity(0)),
        Some(intent),
        "the derived bytes must be the recomputed canonical intent"
    );
}

#[test]
fn refuses_a_payout_for_a_quorum_attempt_this_validator_has_not_designated() {
    // ADR-0015: the txid depends on which quorum signs, so a superseded
    // designation is a DIFFERENT thing to authorize. Attesting to a stale
    // attempt would undermine the deterministic-txid recovery model.
    let (s, _) = seed_payout(1, WithdrawalState::Signing);
    let v = fresh_view(&s);
    assert_eq!(
        v.derive_message(Action::Payout, &payout_identity(0)),
        None,
        "a superseded attempt must not be signable"
    );
    assert_eq!(
        v.derive_message(Action::Payout, &payout_identity(2)),
        None,
        "an attempt this validator has not reached must not be signable either"
    );
    assert!(v
        .derive_message(Action::Payout, &payout_identity(1))
        .is_some());
}

#[test]
fn a_payout_past_the_signing_window_is_not_derivable() {
    // Once broadcast, the transaction is committed; a fresh attestation
    // could only serve a replay or a conflicting spend.
    for state in [
        WithdrawalState::Broadcast,
        WithdrawalState::Confirming,
        WithdrawalState::Completed,
    ] {
        let (s, _) = seed_payout(0, state);
        let v = fresh_view(&s);
        assert_eq!(
            v.derive_message(Action::Payout, &payout_identity(0)),
            None,
            "a {state:?} payout must not be signable"
        );
    }
}

#[test]
fn tampered_payout_state_halts_the_withdrawal_instead_of_being_attested() {
    let (s, _) = seed_payout(0, WithdrawalState::Signing);
    {
        let conn = rusqlite::Connection::open(&s.db_path).unwrap();
        conn.execute(
            "UPDATE withdrawal_payouts SET fee_atomic = ?1 WHERE withdrawal_index = ?2",
            rusqlite::params![(999_999u64).to_le_bytes().to_vec(), WITHDRAWAL_INDEX],
        )
        .unwrap();
    }

    let v = fresh_view(&s);
    assert_eq!(
        v.derive_message(Action::Payout, &payout_identity(0)),
        None,
        "drifted payout state must never yield attestable bytes"
    );

    let db = Db::open(&s.db_path).unwrap();
    assert_eq!(
        db.get_withdrawal(WITHDRAWAL_INDEX).unwrap().unwrap().state,
        WithdrawalState::IntegrityHalted,
        "the signer must halt the anomaly, not merely decline it"
    );
}
