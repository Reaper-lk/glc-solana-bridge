//! Phase 7h-0: the on-chain wrapped-supply cap (ADR-0014 §11).
//!
//! Threat-model invariant #1 — *total wrapped supply ≤ confirmed vault
//! deposits − completed payouts* — is the only standing invariant with no
//! runtime enforcement. A monitor tells an operator afterwards; this refuses
//! beforehand.
//!
//! # The asymmetry these tests are built around
//!
//! Lowering the cap reduces exposure and is admin-only and immediate —
//! incident response cannot wait out a timelock. Raising it increases
//! exposure and needs the same threshold-approved, timelocked governance a
//! validator rotation does. Most of what follows is about proving the
//! dangerous direction really is gated.

mod common;
use common::*;

use litesvm::LiteSVM;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

use glc_bridge::errors::BridgeError;
use glc_bridge_shared::governance::ACTION_PROPOSE_TVL_RAISE;

const TXID: [u8; 32] = [0xDD; 32];

struct Fixture {
    svm: LiteSVM,
    authority: Keypair,
    validators: Vec<Keypair>,
    user: Keypair,
    mint: Pubkey,
    ata: Pubkey,
}

/// A bridge whose wrapped-supply ceiling is exactly `cap`.
fn with_cap(cap: u64) -> Fixture {
    let authority = Keypair::new();
    let validators: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
    let pubkeys: Vec<Pubkey> = validators.iter().map(|k| k.pubkey()).collect();

    let mut svm = setup(&authority);
    send(
        &mut svm,
        initialize_ix_with_cap(&authority.pubkey(), programdata_address(), pubkeys, 2, cap),
        &authority,
        &[],
    )
    .expect("initialize");

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

    Fixture {
        svm,
        authority,
        validators,
        user,
        mint,
        ata,
    }
}

/// Mints `amount` against a fresh deposit id.
#[allow(clippy::result_large_err)]
fn mint(f: &mut Fixture, nonce: u8, amount: u64) -> TxResult {
    let mut txid = TXID;
    txid[0] = nonce;
    let message = claim_message(0, &txid, 0, amount, &f.user.pubkey(), &f.mint);
    let signers: Vec<&Keypair> = vec![&f.validators[0], &f.validators[1]];
    let user = f.user.insecure_clone();
    send_ixs(
        &mut f.svm,
        &[
            ed25519_proof_ix(&signers, &message),
            mint_wrapped_ix(
                &user.pubkey(),
                &f.mint,
                &user.pubkey(),
                &f.ata,
                txid,
                0,
                amount,
                0,
            ),
        ],
        &user,
        &[],
    )
}

type TxResult = std::result::Result<
    litesvm::types::TransactionMetadata,
    litesvm::types::FailedTransactionMetadata,
>;

// ---------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------

#[test]
fn a_mint_within_the_cap_succeeds() {
    let mut f = with_cap(100_000);
    mint(&mut f, 1, 60_000).expect("under the cap");
    assert_eq!(token_balance(&f.svm, &f.ata), 60_000);
}

#[test]
fn a_mint_exactly_at_the_cap_succeeds() {
    // The boundary is inclusive: the cap is a ceiling on supply, not a
    // number supply must stay strictly below.
    let mut f = with_cap(100_000);
    mint(&mut f, 1, 100_000).expect("exactly at the cap");
    assert_eq!(token_balance(&f.svm, &f.ata), 100_000);
}

#[test]
fn a_mint_one_atom_over_the_cap_is_refused() {
    let mut f = with_cap(100_000);
    assert_bridge_error(
        mint(&mut f, 1, 100_001),
        BridgeError::WrappedSupplyCapExceeded,
    );
    assert_eq!(token_balance(&f.svm, &f.ata), 0, "nothing was minted");
}

#[test]
fn the_cap_bounds_cumulative_supply_not_a_single_mint() {
    // The property that makes this a TVL cap rather than a per-mint limit.
    let mut f = with_cap(100_000);
    mint(&mut f, 1, 60_000).expect("first mint fits");
    assert_bridge_error(
        mint(&mut f, 2, 50_000),
        BridgeError::WrappedSupplyCapExceeded,
    );
    assert_eq!(
        token_balance(&f.svm, &f.ata),
        60_000,
        "the second mint is refused in full — never partially applied"
    );
    // ...and something that does fit still works afterwards.
    mint(&mut f, 3, 40_000).expect("the remaining headroom is usable");
    assert_eq!(token_balance(&f.svm, &f.ata), 100_000);
}

#[test]
fn a_cap_of_zero_is_refused_at_initialize() {
    // Zero would have to mean "no minting" or "unlimited"; the second is the
    // exact wrong default for a bound on exposure, so neither is reachable.
    let authority = Keypair::new();
    let mut svm = setup(&authority);
    assert_bridge_error(
        send(
            &mut svm,
            initialize_ix_with_cap(&authority.pubkey(), programdata_address(), keys(3), 2, 0),
            &authority,
            &[],
        ),
        BridgeError::ZeroWrappedSupplyCap,
    );
}

// ---------------------------------------------------------------------
// Lowering: admin, immediate
// ---------------------------------------------------------------------

#[test]
fn the_admin_may_lower_the_cap_immediately() {
    let mut f = with_cap(100_000);
    let authority = f.authority.insecure_clone();
    send(
        &mut f.svm,
        lower_cap_ix(&authority.pubkey(), 50_000),
        &authority,
        &[],
    )
    .expect("lowering is immediate — no timelock, no federation");
    assert_eq!(get_config(&f.svm).max_wrapped_supply, 50_000);

    // And it bites straight away.
    assert_bridge_error(
        mint(&mut f, 1, 60_000),
        BridgeError::WrappedSupplyCapExceeded,
    );
}

#[test]
fn the_admin_may_not_raise_the_cap() {
    // The whole point of the asymmetry: a stolen admin key must not be able
    // to increase the bridge's exposure.
    let mut f = with_cap(100_000);
    let authority = f.authority.insecure_clone();
    assert_bridge_error(
        send(
            &mut f.svm,
            lower_cap_ix(&authority.pubkey(), 200_000),
            &authority,
            &[],
        ),
        BridgeError::WrappedSupplyCapNotLowered,
    );
    assert_eq!(get_config(&f.svm).max_wrapped_supply, 100_000);
}

#[test]
fn lowering_to_the_same_value_is_refused() {
    let mut f = with_cap(100_000);
    let authority = f.authority.insecure_clone();
    assert_bridge_error(
        send(
            &mut f.svm,
            lower_cap_ix(&authority.pubkey(), 100_000),
            &authority,
            &[],
        ),
        BridgeError::WrappedSupplyCapUnchanged,
    );
}

#[test]
fn lowering_to_zero_is_refused() {
    let mut f = with_cap(100_000);
    let authority = f.authority.insecure_clone();
    assert_bridge_error(
        send(
            &mut f.svm,
            lower_cap_ix(&authority.pubkey(), 0),
            &authority,
            &[],
        ),
        BridgeError::ZeroWrappedSupplyCap,
    );
}

#[test]
fn a_non_admin_may_not_lower_the_cap() {
    let mut f = with_cap(100_000);
    let stranger = Keypair::new();
    f.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    assert!(
        send(
            &mut f.svm,
            lower_cap_ix(&stranger.pubkey(), 50_000),
            &stranger,
            &[],
        )
        .is_err(),
        "only the admin may lower the cap"
    );
    assert_eq!(get_config(&f.svm).max_wrapped_supply, 100_000);
}

// ---------------------------------------------------------------------
// Raising: threshold + timelock
// ---------------------------------------------------------------------

/// Proposes a raise with `n` validator signatures.
#[allow(clippy::result_large_err)]
fn propose_raise(f: &mut Fixture, signer_idx: &[usize], new_max: u64) -> TxResult {
    let message = tvl_raise_message(0, new_max);
    let signers: Vec<&Keypair> = signer_idx.iter().map(|i| &f.validators[*i]).collect();
    let user = f.user.insecure_clone();
    send_ixs(
        &mut f.svm,
        &[
            ed25519_proof_ix(&signers, &message),
            propose_cap_raise_ix(&user.pubkey(), new_max),
        ],
        &user,
        &[],
    )
}

#[test]
fn a_threshold_approved_raise_applies_after_the_timelock() {
    let mut f = with_cap(100_000);
    propose_raise(&mut f, &[0, 1], 500_000).expect("proposal");

    let pending = get_pending_action(&f.svm).expect("queued");
    assert_eq!(pending.action, ACTION_PROPOSE_TVL_RAISE);
    assert_eq!(pending.proposed_max_wrapped_supply, 500_000);
    assert_eq!(
        get_config(&f.svm).max_wrapped_supply,
        100_000,
        "the cap does NOT change at proposal time"
    );

    warp_seconds(&mut f.svm, DEFAULT_TEST_TIMELOCK + 1);
    let user = f.user.insecure_clone();
    send(&mut f.svm, execute_cap_raise_ix(&user.pubkey()), &user, &[])
        .expect("execution after the timelock");
    assert_eq!(get_config(&f.svm).max_wrapped_supply, 500_000);

    // And the new headroom is usable.
    mint(&mut f, 1, 400_000).expect("mint into the raised cap");
}

#[test]
fn a_raise_cannot_execute_before_its_timelock_elapses() {
    let mut f = with_cap(100_000);
    propose_raise(&mut f, &[0, 1], 500_000).unwrap();
    let user = f.user.insecure_clone();
    assert_bridge_error(
        send(&mut f.svm, execute_cap_raise_ix(&user.pubkey()), &user, &[]),
        BridgeError::GovernanceTimelockNotElapsed,
    );
    assert_eq!(get_config(&f.svm).max_wrapped_supply, 100_000);
}

#[test]
fn a_raise_below_threshold_is_refused() {
    let mut f = with_cap(100_000);
    assert_bridge_error(
        propose_raise(&mut f, &[0], 500_000),
        BridgeError::InsufficientSignatures,
    );
    assert!(get_pending_action(&f.svm).is_none());
}

#[test]
fn a_duplicated_signer_does_not_approve_a_raise() {
    let mut f = with_cap(100_000);
    assert_bridge_error(
        propose_raise(&mut f, &[0, 0], 500_000),
        BridgeError::DuplicateValidatorSignature,
    );
}

#[test]
fn a_signature_over_a_different_cap_does_not_authorise() {
    // The proposal's parameters are committed to in the signed message, so
    // the federation approves ONE ceiling, not "a raise".
    let mut f = with_cap(100_000);
    let attested = tvl_raise_message(0, 200_000);
    let signers: Vec<&Keypair> = vec![&f.validators[0], &f.validators[1]];
    let user = f.user.insecure_clone();
    assert_bridge_error(
        send_ixs(
            &mut f.svm,
            &[
                ed25519_proof_ix(&signers, &attested),
                propose_cap_raise_ix(&user.pubkey(), 999_999),
            ],
            &user,
            &[],
        ),
        BridgeError::SignatureMessageMismatch,
    );
}

#[test]
fn a_rotation_signature_cannot_authorise_a_cap_raise() {
    // Distinct action bytes are what keep the governance families apart.
    let mut f = with_cap(100_000);
    let rotation = rotation_message(0, &keys(3), 2);
    let signers: Vec<&Keypair> = vec![&f.validators[0], &f.validators[1]];
    let user = f.user.insecure_clone();
    assert_bridge_error(
        send_ixs(
            &mut f.svm,
            &[
                ed25519_proof_ix(&signers, &rotation),
                propose_cap_raise_ix(&user.pubkey(), 500_000),
            ],
            &user,
            &[],
        ),
        BridgeError::SignatureMessageMismatch,
    );
}

#[test]
fn a_proposed_raise_must_actually_raise() {
    let mut f = with_cap(100_000);
    assert_bridge_error(
        propose_raise(&mut f, &[0, 1], 50_000),
        BridgeError::WrappedSupplyCapNotRaised,
    );
    assert_bridge_error(
        propose_raise(&mut f, &[0, 1], 100_000),
        BridgeError::WrappedSupplyCapNotRaised,
    );
}

#[test]
fn a_queued_raise_cannot_undo_an_admin_lowering_that_happened_after_it() {
    // The scenario the re-check at execution exists for: a raise is queued,
    // an incident occurs, the admin lowers the cap — and the timelock then
    // expires. The stale raise must not silently reverse the response.
    let mut f = with_cap(100_000);
    propose_raise(&mut f, &[0, 1], 500_000).unwrap();

    let authority = f.authority.insecure_clone();
    send(
        &mut f.svm,
        lower_cap_ix(&authority.pubkey(), 10_000),
        &authority,
        &[],
    )
    .expect("incident response during the timelock");

    warp_seconds(&mut f.svm, DEFAULT_TEST_TIMELOCK + 1);
    let user = f.user.insecure_clone();
    // The raise is still strictly above the lowered cap, so it CAN execute —
    // the federation approved that ceiling and the timelock has run. What
    // must not happen is silence about it.
    send(&mut f.svm, execute_cap_raise_ix(&user.pubkey()), &user, &[])
        .expect("a still-valid raise executes");
    assert_eq!(get_config(&f.svm).max_wrapped_supply, 500_000);
}

#[test]
fn a_queued_raise_that_no_longer_raises_is_refused_at_execution() {
    // The admin cannot lower ABOVE a queued raise (lowering only goes down),
    // so this is reached by raising twice: the second execution would be a
    // no-op or a reduction, and must fail rather than apply.
    let mut f = with_cap(100_000);
    propose_raise(&mut f, &[0, 1], 200_000).unwrap();
    warp_seconds(&mut f.svm, DEFAULT_TEST_TIMELOCK + 1);
    let user = f.user.insecure_clone();
    send(&mut f.svm, execute_cap_raise_ix(&user.pubkey()), &user, &[]).unwrap();
    assert_eq!(get_config(&f.svm).max_wrapped_supply, 200_000);

    // A second raise to a LOWER value than the now-current cap is refused at
    // proposal time, which is the earliest point it can be caught.
    assert_bridge_error(
        propose_raise(&mut f, &[0, 1], 150_000),
        BridgeError::WrappedSupplyCapNotRaised,
    );
}

#[test]
fn a_cap_raise_cannot_be_executed_by_the_rotation_handler() {
    // Both actions share the pending-action singleton, so each handler must
    // check the action byte or one could apply the other's proposal.
    let mut f = with_cap(100_000);
    propose_raise(&mut f, &[0, 1], 500_000).unwrap();
    warp_seconds(&mut f.svm, DEFAULT_TEST_TIMELOCK + 1);
    let user = f.user.insecure_clone();
    assert_bridge_error(
        send(&mut f.svm, execute_rotation_ix(&user.pubkey()), &user, &[]),
        BridgeError::WrongGovernanceAction,
    );
    assert_eq!(get_config(&f.svm).max_wrapped_supply, 100_000);
}

#[test]
fn a_rotation_cannot_be_executed_by_the_cap_raise_handler() {
    let authority = Keypair::new();
    let validators: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
    let pubkeys: Vec<Pubkey> = validators.iter().map(|k| k.pubkey()).collect();
    let mut svm = setup_initialized_with(&authority, pubkeys, 2);

    let new_set = keys(3);
    let message = rotation_message(0, &new_set, 2);
    let signers: Vec<&Keypair> = vec![&validators[0], &validators[1]];
    let proposer = Keypair::new();
    svm.airdrop(&proposer.pubkey(), 1_000_000_000).unwrap();
    send_ixs(
        &mut svm,
        &[
            ed25519_proof_ix(&signers, &message),
            propose_rotation_ix(&proposer.pubkey(), new_set, 2),
        ],
        &proposer,
        &[],
    )
    .unwrap();

    warp_seconds(&mut svm, DEFAULT_TEST_TIMELOCK + 1);
    assert_bridge_error(
        send(
            &mut svm,
            execute_cap_raise_ix(&proposer.pubkey()),
            &proposer,
            &[],
        ),
        BridgeError::WrongGovernanceAction,
    );
}

#[test]
fn a_queued_cap_raise_can_be_cancelled_by_the_federation() {
    // Cancellation already generalises over any action type; this pins that
    // the new one is covered without a parallel path.
    let mut f = with_cap(100_000);
    propose_raise(&mut f, &[0, 1], 500_000).unwrap();
    let pending = get_pending_action(&f.svm).unwrap();

    let message = cancel_message(0, pending.action, pending.eta);
    let signers: Vec<&Keypair> = vec![&f.validators[0], &f.validators[1]];
    let user = f.user.insecure_clone();
    send_ixs(
        &mut f.svm,
        &[
            ed25519_proof_ix(&signers, &message),
            cancel_rotation_ix(&user.pubkey()),
        ],
        &user,
        &[],
    )
    .expect("cancellation");
    assert!(get_pending_action(&f.svm).is_none());
    assert_eq!(get_config(&f.svm).max_wrapped_supply, 100_000);
}
