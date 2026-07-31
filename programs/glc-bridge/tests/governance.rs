//! Threshold-gated, timelocked governance (Phase 7a, ADR-0014).
//!
//! These tests exist because the validator set *is* the mint authority: a
//! defect here is an infinite-mint defect. Every guard is therefore tested
//! both for the property it provides and for the failure it must produce.

mod common;

use common::*;
use glc_bridge::errors::BridgeError;
use glc_bridge_shared::governance::{ACTION_CANCEL_ROTATION, ACTION_PROPOSE_ROTATION};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};

/// A bridge initialized with `n` validator keypairs at `threshold`, so
/// governance proofs can actually be produced.
struct Gov {
    svm: litesvm::LiteSVM,
    authority: Keypair,
    validators: Vec<Keypair>,
}

fn gov(n: usize, threshold: u8) -> Gov {
    let authority = Keypair::new();
    let validators: Vec<Keypair> = (0..n).map(|_| Keypair::new()).collect();
    let pubkeys: Vec<Pubkey> = validators.iter().map(|k| k.pubkey()).collect();
    let svm = setup_initialized_with(&authority, pubkeys, threshold);
    Gov {
        svm,
        authority,
        validators,
    }
}

impl Gov {
    fn signers(&self, idx: &[usize]) -> Vec<&Keypair> {
        idx.iter().map(|&i| &self.validators[i]).collect()
    }
    fn pubkeys(&self) -> Vec<Pubkey> {
        self.validators.iter().map(|k| k.pubkey()).collect()
    }
    /// Proposes a rotation signed by `idx`, at the current epoch.
    // The Err type is litesvm's own; its size is not ours to shrink.
    #[allow(clippy::result_large_err)]
    fn propose(
        &mut self,
        idx: &[usize],
        new_set: &[Pubkey],
        threshold: u8,
    ) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>
    {
        let epoch = get_validator_set(&self.svm).epoch;
        let msg = rotation_message(epoch, new_set, threshold);
        let ixs = vec![
            ed25519_proof_ix(&self.signers(idx), &msg),
            propose_rotation_ix(&self.authority.pubkey(), new_set.to_vec(), threshold),
        ];
        let authority = self.authority.insecure_clone();
        send_ixs(&mut self.svm, &ixs, &authority, &[])
    }
    #[allow(clippy::result_large_err)]
    fn execute(
        &mut self,
    ) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>
    {
        let authority = self.authority.insecure_clone();
        send(
            &mut self.svm,
            execute_rotation_ix(&authority.pubkey()),
            &authority,
            &[],
        )
    }
}

// ------------------------------------------------------------ happy path --

#[test]
fn propose_wait_execute_rotates_the_set_and_bumps_the_epoch() {
    let mut g = gov(5, 3);
    let next: Vec<Pubkey> = (0..4).map(|_| Keypair::new().pubkey()).collect();

    g.propose(&[0, 1, 2], &next, 2).expect("proposal succeeds");

    // Queued but NOT applied: the whole point of the delay.
    let pending = get_pending_action(&g.svm).expect("action is pending");
    assert_eq!(pending.action, ACTION_PROPOSE_ROTATION);
    assert_eq!(pending.proposed_under_epoch, 0);
    assert_eq!(pending.threshold, 2);
    assert_eq!(pending.validators, next);
    let set = get_validator_set(&g.svm);
    assert_eq!(
        set.epoch, 0,
        "the live set must not change at proposal time"
    );
    assert_eq!(set.validators, g.pubkeys());

    warp_seconds(&mut g.svm, DEFAULT_TEST_TIMELOCK);
    g.execute().expect("execution succeeds after the timelock");

    let set = get_validator_set(&g.svm);
    assert_eq!(
        set.epoch, 1,
        "epoch advances, invalidating in-flight proofs"
    );
    assert_eq!(set.validators, next);
    assert_eq!(set.threshold, 2);
    assert!(
        get_pending_action(&g.svm).is_none(),
        "the pending account is closed, freeing the singleton slot"
    );
}

#[test]
fn execution_is_permissionless_once_the_timelock_elapses() {
    let mut g = gov(5, 3);
    let next: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1, 2], &next, 2).unwrap();
    warp_seconds(&mut g.svm, DEFAULT_TEST_TIMELOCK);

    // A wholly unrelated party executes: authorization was the threshold
    // proof at proposal time, so a minority cannot veto by going quiet.
    let stranger = Keypair::new();
    g.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    send(
        &mut g.svm,
        execute_rotation_ix(&stranger.pubkey()),
        &stranger,
        &[],
    )
    .expect("anyone may execute a matured action");
    assert_eq!(get_validator_set(&g.svm).epoch, 1);
}

// --------------------------------------------------- the F1 property -------

#[test]
fn no_single_key_can_rotate_the_validator_set() {
    // The Phase 7a reason for existing: before ADR-0014 the admin key alone
    // could rotate the federation, which is an indirect infinite-mint
    // capability. A lone signer must now be unable to move the set.
    let mut g = gov(5, 3);
    let attacker_set: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();

    // One validator's signature is not enough.
    let result = g.propose(&[0], &attacker_set, 1);
    assert_bridge_error(result, BridgeError::InsufficientSignatures);

    // Neither is the admin acting with no federation proof at all.
    let ix = propose_rotation_ix(&g.authority.pubkey(), attacker_set.clone(), 1);
    let authority = g.authority.insecure_clone();
    let result = send(&mut g.svm, ix, &authority, &[]);
    assert_bridge_error(result, BridgeError::MissingSignatureVerification);

    assert!(get_pending_action(&g.svm).is_none());
    assert_eq!(get_validator_set(&g.svm).validators, g.pubkeys());
}

#[test]
fn the_deleted_admin_rotation_instruction_is_gone_from_the_program() {
    // `update_validator_set` was removed, not merely restricted. Its old
    // Anchor discriminator must no longer dispatch to anything.
    let mut g = gov(3, 2);
    let disc = anchor_lang::solana_program::hash::hash(b"global:update_validator_set").to_bytes();
    let ix = solana_sdk::instruction::Instruction {
        program_id: glc_bridge::ID,
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(g.authority.pubkey(), true),
            solana_sdk::instruction::AccountMeta::new(config_pda(), false),
            solana_sdk::instruction::AccountMeta::new(validator_set_pda(), false),
        ],
        data: disc[..8].to_vec(),
    };
    let authority = g.authority.insecure_clone();
    assert!(
        send(&mut g.svm, ix, &authority, &[]).is_err(),
        "the removed instruction must not dispatch"
    );
}

// ------------------------------------------------------------- timelock ----

#[test]
fn execution_before_the_timelock_elapses_is_rejected() {
    let mut g = gov(5, 3);
    let next: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1, 2], &next, 2).unwrap();

    assert_bridge_error(g.execute(), BridgeError::GovernanceTimelockNotElapsed);
    assert_eq!(get_validator_set(&g.svm).epoch, 0);

    // One second short is still short.
    warp_seconds(&mut g.svm, DEFAULT_TEST_TIMELOCK - 1);
    assert_bridge_error(g.execute(), BridgeError::GovernanceTimelockNotElapsed);
    assert_eq!(get_validator_set(&g.svm).epoch, 0);

    // Exactly at the eta it becomes executable.
    warp_seconds(&mut g.svm, 1);
    g.execute().expect("executable at exactly eta");
    assert_eq!(get_validator_set(&g.svm).epoch, 1);
}

#[test]
fn initialize_refuses_a_zero_timelock() {
    // No silent default: an instant rotation removes the public window that
    // is the entire point of the delay.
    let authority = Keypair::new();
    let mut svm = setup(&authority);
    let ix = initialize_ix_with_timelock(&authority.pubkey(), programdata_address(), keys(3), 2, 0);
    assert_bridge_error(
        send(&mut svm, ix, &authority, &[]),
        BridgeError::ZeroGovernanceTimelock,
    );
}

// ------------------------------------------------------- proof integrity ---

#[test]
fn a_proposal_signed_for_different_parameters_is_rejected() {
    // The signed commitment binds the exact parameter set. Signatures
    // collected for one rotation must not authorize another.
    let mut g = gov(5, 3);
    let approved: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    let substituted: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();

    let epoch = get_validator_set(&g.svm).epoch;
    let msg = rotation_message(epoch, &approved, 2);
    let ixs = vec![
        ed25519_proof_ix(&g.signers(&[0, 1, 2]), &msg),
        // ...but the instruction proposes a DIFFERENT set.
        propose_rotation_ix(&g.authority.pubkey(), substituted, 2),
    ];
    let authority = g.authority.insecure_clone();
    assert_bridge_error(
        send_ixs(&mut g.svm, &ixs, &authority, &[]),
        BridgeError::SignatureMessageMismatch,
    );
    assert!(get_pending_action(&g.svm).is_none());
}

#[test]
fn a_proposal_signed_for_a_different_threshold_is_rejected() {
    let mut g = gov(5, 3);
    let next: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    let epoch = get_validator_set(&g.svm).epoch;
    let msg = rotation_message(epoch, &next, 2);
    let ixs = vec![
        ed25519_proof_ix(&g.signers(&[0, 1, 2]), &msg),
        propose_rotation_ix(&g.authority.pubkey(), next, 3), // threshold differs
    ];
    let authority = g.authority.insecure_clone();
    assert_bridge_error(
        send_ixs(&mut g.svm, &ixs, &authority, &[]),
        BridgeError::SignatureMessageMismatch,
    );
}

#[test]
fn validator_order_is_part_of_the_commitment() {
    let mut g = gov(5, 3);
    let a = Keypair::new().pubkey();
    let b = Keypair::new().pubkey();
    let epoch = get_validator_set(&g.svm).epoch;
    let msg = rotation_message(epoch, &[a, b], 2);
    let ixs = vec![
        ed25519_proof_ix(&g.signers(&[0, 1, 2]), &msg),
        propose_rotation_ix(&g.authority.pubkey(), vec![b, a], 2), // reordered
    ];
    let authority = g.authority.insecure_clone();
    assert_bridge_error(
        send_ixs(&mut g.svm, &ixs, &authority, &[]),
        BridgeError::SignatureMessageMismatch,
    );
}

#[test]
fn a_proposal_signed_under_a_stale_epoch_is_rejected() {
    let mut g = gov(5, 3);
    // Sign for epoch 0...
    let next: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    let stale_msg = rotation_message(0, &next, 2);

    // ...but first let a rotation land, moving the chain to epoch 1.
    let interim: Vec<Pubkey> = g.pubkeys();
    g.propose(&[0, 1, 2], &interim, 3).unwrap();
    warp_seconds(&mut g.svm, DEFAULT_TEST_TIMELOCK);
    g.execute().unwrap();
    assert_eq!(get_validator_set(&g.svm).epoch, 1);

    let ixs = vec![
        ed25519_proof_ix(&g.signers(&[0, 1, 2]), &stale_msg),
        propose_rotation_ix(&g.authority.pubkey(), next, 2),
    ];
    let authority = g.authority.insecure_clone();
    assert_bridge_error(
        send_ixs(&mut g.svm, &ixs, &authority, &[]),
        BridgeError::SignatureMessageMismatch,
    );
}

#[test]
fn a_non_validator_signature_does_not_count_toward_threshold() {
    let mut g = gov(5, 3);
    let outsider = Keypair::new();
    let next: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    let epoch = get_validator_set(&g.svm).epoch;
    let msg = rotation_message(epoch, &next, 2);
    let mut signers = g.signers(&[0, 1]);
    signers.push(&outsider);
    let ixs = vec![
        ed25519_proof_ix(&signers, &msg),
        propose_rotation_ix(&g.authority.pubkey(), next, 2),
    ];
    let authority = g.authority.insecure_clone();
    assert_bridge_error(
        send_ixs(&mut g.svm, &ixs, &authority, &[]),
        BridgeError::UnknownValidatorSignature,
    );
}

#[test]
fn the_same_validator_signing_twice_does_not_reach_threshold() {
    let mut g = gov(5, 3);
    let next: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    let epoch = get_validator_set(&g.svm).epoch;
    let msg = rotation_message(epoch, &next, 2);
    let ixs = vec![
        ed25519_proof_ix(&g.signers(&[0, 1, 1]), &msg),
        propose_rotation_ix(&g.authority.pubkey(), next, 2),
    ];
    let authority = g.authority.insecure_clone();
    assert_bridge_error(
        send_ixs(&mut g.svm, &ixs, &authority, &[]),
        BridgeError::DuplicateValidatorSignature,
    );
}

// ------------------------------------------------------- set invariants ----

#[test]
fn an_invalid_proposed_set_is_rejected_at_proposal_time() {
    // An unexecutable proposal must never sit in the queue looking
    // legitimate, nor be discovered broken only after the delay.
    let mut g = gov(5, 3);
    let dup = Keypair::new().pubkey();

    assert_bridge_error(
        g.propose(&[0, 1, 2], &[dup, dup], 2),
        BridgeError::DuplicateValidator,
    );
    assert_bridge_error(
        g.propose(&[0, 1, 2], &[], 1),
        BridgeError::EmptyValidatorSet,
    );
    assert_bridge_error(
        g.propose(&[0, 1, 2], &[Pubkey::default(), Keypair::new().pubkey()], 2),
        BridgeError::InvalidValidatorKey,
    );
    let one = vec![Keypair::new().pubkey()];
    assert_bridge_error(
        g.propose(&[0, 1, 2], &one, 2),
        BridgeError::ThresholdExceedsValidatorCount,
    );
    assert_bridge_error(g.propose(&[0, 1, 2], &one, 0), BridgeError::ZeroThreshold);

    assert!(get_pending_action(&g.svm).is_none());
}

// ------------------------------------------------------------- singleton ---

#[test]
fn only_one_action_may_be_pending_at_a_time() {
    let mut g = gov(5, 3);
    let first: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    let second: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1, 2], &first, 2).unwrap();

    // A second proposal cannot queue behind the first: no backlog of
    // actions that all mature later.
    assert!(
        g.propose(&[0, 1, 2], &second, 2).is_err(),
        "the singleton slot is occupied"
    );
    assert_eq!(get_pending_action(&g.svm).unwrap().validators, first);
}

#[test]
fn a_matured_action_cannot_be_executed_twice() {
    let mut g = gov(5, 3);
    let next: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1, 2], &next, 2).unwrap();
    warp_seconds(&mut g.svm, DEFAULT_TEST_TIMELOCK);
    g.execute().unwrap();
    assert_eq!(get_validator_set(&g.svm).epoch, 1);

    // The account is closed, so a replay finds nothing to execute.
    assert!(g.execute().is_err(), "a closed action cannot re-execute");
    assert_eq!(
        get_validator_set(&g.svm).epoch,
        1,
        "epoch bumped exactly once"
    );
}

// ---------------------------------------------------------------- cancel ---

#[test]
fn cancel_requires_a_fresh_threshold_proof_and_frees_the_slot() {
    let mut g = gov(5, 3);
    let hostile: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1, 2], &hostile, 1).unwrap();
    let pending = get_pending_action(&g.svm).unwrap();

    let epoch = get_validator_set(&g.svm).epoch;
    let msg = cancel_message(epoch, pending.action, pending.eta);
    let ixs = vec![
        ed25519_proof_ix(&g.signers(&[0, 1, 2]), &msg),
        cancel_rotation_ix(&g.authority.pubkey()),
    ];
    let authority = g.authority.insecure_clone();
    send_ixs(&mut g.svm, &ixs, &authority, &[]).expect("cancellation succeeds");

    assert!(get_pending_action(&g.svm).is_none(), "slot is freed");
    assert_eq!(get_validator_set(&g.svm).epoch, 0, "nothing was applied");

    // And the slot is genuinely reusable afterwards.
    let benign: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1, 2], &benign, 2)
        .expect("a new proposal may take the freed slot");
}

#[test]
fn cancel_without_a_threshold_proof_is_rejected() {
    let mut g = gov(5, 3);
    let next: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1, 2], &next, 2).unwrap();
    let pending = get_pending_action(&g.svm).unwrap();
    let epoch = get_validator_set(&g.svm).epoch;

    // No proof instruction at all.
    let authority = g.authority.insecure_clone();
    assert_bridge_error(
        send(
            &mut g.svm,
            cancel_rotation_ix(&authority.pubkey()),
            &authority,
            &[],
        ),
        BridgeError::MissingSignatureVerification,
    );

    // Below threshold.
    let msg = cancel_message(epoch, pending.action, pending.eta);
    let ixs = vec![
        ed25519_proof_ix(&g.signers(&[0]), &msg),
        cancel_rotation_ix(&authority.pubkey()),
    ];
    assert_bridge_error(
        send_ixs(&mut g.svm, &ixs, &authority, &[]),
        BridgeError::InsufficientSignatures,
    );

    assert!(
        get_pending_action(&g.svm).is_some(),
        "the action survives every refused cancellation"
    );
}

#[test]
fn a_cancel_signature_cannot_be_replayed_against_a_re_proposal() {
    // The cancel commitment binds the pending action's eta, so signatures
    // gathered to stop one proposal cannot silently stop its successor.
    let mut g = gov(5, 3);
    let first: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1, 2], &first, 2).unwrap();
    let first_pending = get_pending_action(&g.svm).unwrap();
    let epoch = get_validator_set(&g.svm).epoch;
    let stale_cancel = cancel_message(epoch, first_pending.action, first_pending.eta);

    // Cancel it legitimately, then re-propose at a later clock so the new
    // action has a different eta.
    let ixs = vec![
        ed25519_proof_ix(&g.signers(&[0, 1, 2]), &stale_cancel),
        cancel_rotation_ix(&g.authority.pubkey()),
    ];
    let authority = g.authority.insecure_clone();
    send_ixs(&mut g.svm, &ixs, &authority, &[]).unwrap();

    warp_seconds(&mut g.svm, 60);
    let second: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1, 2], &second, 2).unwrap();

    // Replaying the old cancellation must fail: different eta.
    let ixs = vec![
        ed25519_proof_ix(&g.signers(&[0, 1, 2]), &stale_cancel),
        cancel_rotation_ix(&authority.pubkey()),
    ];
    assert_bridge_error(
        send_ixs(&mut g.svm, &ixs, &authority, &[]),
        BridgeError::SignatureMessageMismatch,
    );
    assert!(
        get_pending_action(&g.svm).is_some(),
        "the live proposal survives the replayed cancellation"
    );
}

#[test]
fn a_proposal_signature_cannot_be_used_to_cancel() {
    // Distinct action bytes keep the two governance messages apart even
    // when every other field coincides.
    let mut g = gov(5, 3);
    let next: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1, 2], &next, 2).unwrap();
    let epoch = get_validator_set(&g.svm).epoch;

    let propose_msg = rotation_message(epoch, &next, 2);
    let ixs = vec![
        ed25519_proof_ix(&g.signers(&[0, 1, 2]), &propose_msg),
        cancel_rotation_ix(&g.authority.pubkey()),
    ];
    let authority = g.authority.insecure_clone();
    assert_bridge_error(
        send_ixs(&mut g.svm, &ixs, &authority, &[]),
        BridgeError::SignatureMessageMismatch,
    );
    assert_ne!(ACTION_PROPOSE_ROTATION, ACTION_CANCEL_ROTATION);
}

// --------------------------------------------------------- rotation math ---

#[test]
fn rotating_to_a_larger_threshold_requires_only_the_old_threshold_to_approve() {
    // Approval is judged against the CURRENT set, not the proposed one —
    // otherwise a federation could never raise its own threshold.
    let mut g = gov(5, 2);
    let next: Vec<Pubkey> = (0..5).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1], &next, 5)
        .expect("2 of 5 approve a move to 5-of-5");
    warp_seconds(&mut g.svm, DEFAULT_TEST_TIMELOCK);
    g.execute().unwrap();
    let set = get_validator_set(&g.svm);
    assert_eq!(set.threshold, 5);
    assert_eq!(set.validators, next);
}

#[test]
fn a_rotation_that_ejects_a_signer_still_executes() {
    // The outgoing validator's approval remains valid: it was judged
    // against the set that was live when it signed.
    let mut g = gov(3, 2);
    let survivors: Vec<Pubkey> = g.pubkeys()[..2].to_vec();
    g.propose(&[0, 2], &survivors, 2).unwrap();
    warp_seconds(&mut g.svm, DEFAULT_TEST_TIMELOCK);
    g.execute().unwrap();
    assert_eq!(get_validator_set(&g.svm).validators, survivors);
}

// ------------------------------------------------- defence-in-depth guards --
//
// The two guards below are not reachable through the current instruction
// surface: only one action type exists, and nothing can bump the epoch while
// an action is pending. They exist to fail closed if a future instruction
// changes either assumption. Rather than leave them as untested defensive
// code, these tests construct the offending account state directly.

/// Patches raw bytes of the pending-action account, preserving its Anchor
/// discriminator. Layout after the 8-byte discriminator: `action` (1),
/// `proposed_under_epoch` (8), `eta` (8), `threshold` (1), ...
fn patch_pending_action(svm: &mut litesvm::LiteSVM, offset: usize, bytes: &[u8]) {
    let pda = governance_action_pda();
    let mut account = svm.get_account(&pda).expect("pending action exists");
    account.data[offset..offset + bytes.len()].copy_from_slice(bytes);
    svm.set_account(pda, account).unwrap();
}

#[test]
fn execute_rejects_a_pending_action_of_an_unexpected_type() {
    let mut g = gov(5, 3);
    let next: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1, 2], &next, 2).unwrap();

    // Rewrite the action byte to a type this handler was not written for.
    patch_pending_action(&mut g.svm, 8, &[ACTION_CANCEL_ROTATION]);
    warp_seconds(&mut g.svm, DEFAULT_TEST_TIMELOCK);

    assert_bridge_error(g.execute(), BridgeError::WrongGovernanceAction);
    assert_eq!(
        get_validator_set(&g.svm).epoch,
        0,
        "a mistyped action must not rotate the federation"
    );
}

#[test]
fn execute_rejects_a_proposal_approved_under_a_different_epoch() {
    let mut g = gov(5, 3);
    let next: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    g.propose(&[0, 1, 2], &next, 2).unwrap();

    // Claim the proposal was approved by a federation revision other than
    // the live one.
    patch_pending_action(&mut g.svm, 9, &7u64.to_le_bytes());
    warp_seconds(&mut g.svm, DEFAULT_TEST_TIMELOCK);

    assert_bridge_error(g.execute(), BridgeError::StaleGovernanceProposal);
    assert_eq!(
        get_validator_set(&g.svm).epoch,
        0,
        "a proposal approved by a different federation must never apply"
    );
}
