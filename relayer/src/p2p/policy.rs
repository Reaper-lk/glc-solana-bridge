//! The decision a validator makes when asked to sign (Phase 7c, ADR-0016).
//!
//! Deliberately free of gRPC, TLS, and I/O types so the security-critical
//! logic is unit-testable against fabricated requests — the same separation
//! `verification.rs` uses on-chain and `builder.rs` uses for payouts.
//!
//! # The load-bearing property
//!
//! A responder **never trusts the requester's description of the world**.
//! The request carries the bytes it wants signed, but those are only ever
//! *compared*: the responder independently re-derives the canonical message
//! from its own chain observations and refuses unless the two are
//! byte-identical. A fully compromised requester therefore cannot induce a
//! signature over anything this validator has not itself verified.
//!
//! This is the constraint recorded in `p2p/mod.rs` since Phase 0 — the
//! layer moves signatures, not truth — made concrete.

use std::collections::HashMap;

use thiserror::Error;

/// Why a signing request was refused.
///
/// Every variant is an **alarm**, not routine noise: a refusal means this
/// validator's view of the chain disagrees with a peer's, which is either a
/// bug or an attack.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Refusal {
    #[error("request expired at {expiry_unix}, now {now}")]
    Expired { expiry_unix: i64, now: i64 },
    #[error("action 0 is never valid")]
    UnspecifiedAction,
    #[error(
        "requester claims epoch {requested}, this validator observes {observed} — refusing to \
         sign under a federation revision it does not agree with"
    )]
    EpochMismatch { requested: u64, observed: u64 },
    #[error(
        "the requested bytes are not what this validator independently derives for that identity"
    )]
    MessageMismatch,
    #[error("this validator cannot derive the message for that identity: {0}")]
    Underivable(&'static str),
    #[error(
        "already signed a DIFFERENT message for this identity — refusing to produce a second, \
         conflicting signature"
    )]
    ConflictingRequest,
    #[error("request is not from a known federation peer")]
    UnknownPeer,
    #[error("peer exceeded its request rate limit")]
    RateLimited,
    #[error("vault payout refused: {0}")]
    PayoutRefused(String),
    #[error("withdrawal completion refused: {0}")]
    CompletionRefused(String),
    #[error("governance action refused: {0}")]
    GovernanceRefused(String),
    #[error("vault sweep refused: {0}")]
    SweepRefused(String),
    #[error(
        "this validator's observation of the chain is stale — refusing to sign rather than \
         authorize under a federation revision it may no longer be current with"
    )]
    StaleView,
}

/// What a request is asking to sign. Mirrors the wire `Action`, and the
/// discriminants match the on-chain canonical-message action bytes so a
/// signature can never be repurposed across action types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    MintDeposit,
    Payout,
    Governance,
}

impl Action {
    pub fn from_wire(v: i32) -> Result<Self, Refusal> {
        match v {
            1 => Ok(Action::MintDeposit),
            2 => Ok(Action::Payout),
            3 => Ok(Action::Governance),
            _ => Err(Refusal::UnspecifiedAction),
        }
    }
}

/// The identity a request refers to. Two requests with the same identity are
/// "the same logical thing"; signing two *different* messages for one
/// identity is a conflict and is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SigningIdentity {
    /// A deposit mint, keyed by its Goldcoin outpoint (ADR-0002).
    Deposit { txid: [u8; 32], vout: u32 },
    /// A vault payout, keyed by withdrawal index AND quorum attempt — a
    /// superseded designation is a different thing to sign for (ADR-0015).
    Payout {
        withdrawal_index: u64,
        quorum_attempt: u32,
    },
    /// A governance action, keyed by the epoch it was proposed under.
    Governance { epoch: u64 },
}

/// What this validator independently believes, supplied by the caller from
/// its own chain observations. The policy never fetches anything itself.
pub trait LocalView {
    /// The validator-set epoch this validator currently observes.
    fn observed_epoch(&self) -> u64;

    /// Whether that observation is recent enough to act on.
    ///
    /// A validator whose link to the chain has been down cannot tell a
    /// *matching* epoch from a *superseded* one: it would keep answering
    /// with a remembered value and keep agreeing with requesters who quote
    /// it back. Distinguishing "current" from "last known" is what stops a
    /// partitioned signer from authorizing under a federation revision it
    /// has fallen behind.
    ///
    /// Defaults to `true` for views that are inherently current — an
    /// in-memory test view, for instance, cannot be stale.
    fn view_is_fresh(&self) -> bool {
        true
    }

    /// The canonical bytes this validator derives for `identity`, or `None`
    /// if it cannot derive them (has not seen the deposit, does not have the
    /// payout, disagrees that it exists).
    fn derive_message(&self, action: Action, identity: &SigningIdentity) -> Option<Vec<u8>>;
}

/// A request, already parsed off the wire.
#[derive(Debug, Clone)]
pub struct SigningRequest {
    pub request_id: Vec<u8>,
    pub action: Action,
    pub epoch: u64,
    pub canonical_message: Vec<u8>,
    pub identity: SigningIdentity,
    pub expiry_unix: i64,
}

/// Records what has already been signed, so a retry is idempotent and a
/// conflicting request is refused.
///
/// Keyed by `(action, identity)` rather than by message, because the
/// question that matters is "have I already committed to something for this
/// thing?" — not "have I seen these exact bytes?".
#[derive(Debug, Default)]
pub struct SeenSet {
    signed: HashMap<(Action, SigningIdentity), Vec<u8>>,
}

impl SeenSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// The message previously signed for this identity, if any.
    pub fn previously_signed(
        &self,
        action: Action,
        identity: &SigningIdentity,
    ) -> Option<&Vec<u8>> {
        self.signed.get(&(action, identity.clone()))
    }

    pub fn record(&mut self, action: Action, identity: SigningIdentity, message: Vec<u8>) {
        self.signed.insert((action, identity), message);
    }

    pub fn len(&self) -> usize {
        self.signed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signed.is_empty()
    }
}

/// The outcome of evaluating a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Sign exactly these bytes — the ones this validator derived itself,
    /// never the ones supplied by the requester.
    Sign(Vec<u8>),
    /// This exact message was already signed; return the same signature.
    /// Retries are therefore free and cannot be used to extract a second,
    /// different signature.
    AlreadySigned(Vec<u8>),
    Refuse(Refusal),
}

/// Decides whether to sign, and over which bytes.
///
/// Order matters: cheap checks first, then the independent derivation, then
/// the conflict check. The derivation is the expensive step and is bounded
/// by this validator's own chain access, so an attacker cannot amplify work
/// beyond their rate limit.
pub fn evaluate(
    request: &SigningRequest,
    view: &impl LocalView,
    seen: &SeenSet,
    now_unix: i64,
) -> Decision {
    if now_unix > request.expiry_unix {
        return Decision::Refuse(Refusal::Expired {
            expiry_unix: request.expiry_unix,
            now: now_unix,
        });
    }

    // Before comparing epochs, establish that this validator's epoch is
    // worth comparing against. A stale view would otherwise let a
    // partitioned signer agree with anyone quoting its last known value.
    if !view.view_is_fresh() {
        return Decision::Refuse(Refusal::StaleView);
    }

    let observed = view.observed_epoch();
    if request.epoch != observed {
        return Decision::Refuse(Refusal::EpochMismatch {
            requested: request.epoch,
            observed,
        });
    }

    // Independent derivation. The requester's bytes are compared, never
    // adopted.
    let Some(derived) = view.derive_message(request.action, &request.identity) else {
        return Decision::Refuse(Refusal::Underivable(
            "this validator has no verified record of that identity",
        ));
    };
    if derived != request.canonical_message {
        return Decision::Refuse(Refusal::MessageMismatch);
    }

    // Idempotent retry vs. genuine conflict.
    match seen.previously_signed(request.action, &request.identity) {
        Some(prev) if *prev == derived => Decision::AlreadySigned(derived),
        Some(_) => Decision::Refuse(Refusal::ConflictingRequest),
        None => Decision::Sign(derived),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct View {
        epoch: u64,
        messages: HashMap<SigningIdentity, Vec<u8>>,
    }

    impl LocalView for View {
        fn observed_epoch(&self) -> u64 {
            self.epoch
        }
        fn derive_message(&self, _a: Action, id: &SigningIdentity) -> Option<Vec<u8>> {
            self.messages.get(id).cloned()
        }
    }

    /// A view whose chain observation has gone stale.
    struct StaleView(View);
    impl LocalView for StaleView {
        fn observed_epoch(&self) -> u64 {
            self.0.observed_epoch()
        }
        fn view_is_fresh(&self) -> bool {
            false
        }
        fn derive_message(&self, a: Action, id: &SigningIdentity) -> Option<Vec<u8>> {
            self.0.derive_message(a, id)
        }
    }

    fn deposit() -> SigningIdentity {
        SigningIdentity::Deposit {
            txid: [0xAA; 32],
            vout: 1,
        }
    }

    fn view_with(msg: Vec<u8>) -> View {
        let mut m = HashMap::new();
        m.insert(deposit(), msg);
        View {
            epoch: 7,
            messages: m,
        }
    }

    fn req(message: Vec<u8>) -> SigningRequest {
        SigningRequest {
            request_id: vec![1, 2, 3],
            action: Action::MintDeposit,
            epoch: 7,
            canonical_message: message,
            identity: deposit(),
            expiry_unix: 1_000,
        }
    }

    #[test]
    fn signs_when_the_request_matches_what_this_validator_derives() {
        let v = view_with(b"canonical".to_vec());
        let d = evaluate(&req(b"canonical".to_vec()), &v, &SeenSet::new(), 500);
        assert_eq!(d, Decision::Sign(b"canonical".to_vec()));
    }

    #[test]
    fn signs_its_own_derived_bytes_not_the_requesters() {
        // The returned bytes must come from the local derivation. Here they
        // are equal, but the decision carries the derived value, which is
        // what the caller signs.
        let v = view_with(b"canonical".to_vec());
        match evaluate(&req(b"canonical".to_vec()), &v, &SeenSet::new(), 500) {
            Decision::Sign(bytes) => assert_eq!(bytes, b"canonical".to_vec()),
            other => panic!("expected Sign, got {other:?}"),
        }
    }

    #[test]
    fn refuses_bytes_that_differ_from_the_local_derivation() {
        // The core property: a compromised requester cannot get a signature
        // over anything this validator did not itself derive.
        let v = view_with(b"canonical".to_vec());
        let d = evaluate(
            &req(b"attacker-supplied".to_vec()),
            &v,
            &SeenSet::new(),
            500,
        );
        assert_eq!(d, Decision::Refuse(Refusal::MessageMismatch));
    }

    #[test]
    fn refuses_a_message_that_is_a_prefix_or_extension_of_the_real_one() {
        let v = view_with(b"canonical".to_vec());
        for forged in [b"canonica".to_vec(), b"canonical!".to_vec()] {
            assert_eq!(
                evaluate(&req(forged), &v, &SeenSet::new(), 500),
                Decision::Refuse(Refusal::MessageMismatch)
            );
        }
    }

    #[test]
    fn refuses_when_this_validator_cannot_derive_the_identity() {
        // Never seen the deposit -> never signs for it, regardless of how
        // convincing the request looks.
        let v = View {
            epoch: 7,
            messages: HashMap::new(),
        };
        assert!(matches!(
            evaluate(&req(b"anything".to_vec()), &v, &SeenSet::new(), 500),
            Decision::Refuse(Refusal::Underivable(_))
        ));
    }

    #[test]
    fn refuses_a_stale_or_future_epoch() {
        let v = view_with(b"canonical".to_vec());
        let mut r = req(b"canonical".to_vec());
        r.epoch = 6;
        assert_eq!(
            evaluate(&r, &v, &SeenSet::new(), 500),
            Decision::Refuse(Refusal::EpochMismatch {
                requested: 6,
                observed: 7
            })
        );
        r.epoch = 8;
        assert!(matches!(
            evaluate(&r, &v, &SeenSet::new(), 500),
            Decision::Refuse(Refusal::EpochMismatch { .. })
        ));
    }

    #[test]
    fn refuses_an_expired_request() {
        let v = view_with(b"canonical".to_vec());
        assert!(matches!(
            evaluate(&req(b"canonical".to_vec()), &v, &SeenSet::new(), 1_001),
            Decision::Refuse(Refusal::Expired { .. })
        ));
        // Exactly at expiry is still valid.
        assert!(matches!(
            evaluate(&req(b"canonical".to_vec()), &v, &SeenSet::new(), 1_000),
            Decision::Sign(_)
        ));
    }

    #[test]
    fn a_retry_of_the_same_request_is_idempotent() {
        let v = view_with(b"canonical".to_vec());
        let mut seen = SeenSet::new();
        seen.record(Action::MintDeposit, deposit(), b"canonical".to_vec());
        assert_eq!(
            evaluate(&req(b"canonical".to_vec()), &v, &seen, 500),
            Decision::AlreadySigned(b"canonical".to_vec()),
            "retries must be free, not a second distinct signature"
        );
    }

    #[test]
    fn a_second_different_message_for_one_identity_is_refused() {
        // The equivocation guard: having signed one thing for a deposit,
        // this validator must never sign a conflicting one.
        let mut seen = SeenSet::new();
        seen.record(Action::MintDeposit, deposit(), b"first".to_vec());
        let v = view_with(b"second".to_vec()); // local view now derives something else
        assert_eq!(
            evaluate(&req(b"second".to_vec()), &v, &seen, 500),
            Decision::Refuse(Refusal::ConflictingRequest)
        );
    }

    #[test]
    fn the_same_bytes_under_a_different_action_are_tracked_separately() {
        let mut seen = SeenSet::new();
        seen.record(Action::MintDeposit, deposit(), b"m".to_vec());
        assert!(seen.previously_signed(Action::Payout, &deposit()).is_none());
    }

    #[test]
    fn a_superseded_quorum_attempt_is_a_distinct_identity() {
        // ADR-0015: reassignment is explicit. Signing for attempt 0 must
        // not satisfy — or conflict with — a request for attempt 1.
        let a0 = SigningIdentity::Payout {
            withdrawal_index: 3,
            quorum_attempt: 0,
        };
        let a1 = SigningIdentity::Payout {
            withdrawal_index: 3,
            quorum_attempt: 1,
        };
        assert_ne!(a0, a1);
        let mut seen = SeenSet::new();
        seen.record(Action::Payout, a0.clone(), b"x".to_vec());
        assert!(seen.previously_signed(Action::Payout, &a1).is_none());
    }

    #[test]
    fn action_zero_is_never_valid() {
        assert_eq!(Action::from_wire(0), Err(Refusal::UnspecifiedAction));
        assert_eq!(Action::from_wire(99), Err(Refusal::UnspecifiedAction));
        assert_eq!(Action::from_wire(1), Ok(Action::MintDeposit));
        assert_eq!(Action::from_wire(2), Ok(Action::Payout));
        assert_eq!(Action::from_wire(3), Ok(Action::Governance));
    }

    #[test]
    fn refuses_when_this_validators_view_of_the_chain_is_stale() {
        // The request is otherwise perfect — matching epoch, matching bytes.
        // A signer that has lost its link to the chain must still refuse:
        // it cannot tell a current epoch from a superseded one.
        let v = StaleView(view_with(b"canonical".to_vec()));
        assert_eq!(
            evaluate(&req(b"canonical".to_vec()), &v, &SeenSet::new(), 500),
            Decision::Refuse(Refusal::StaleView)
        );
    }

    #[test]
    fn a_stale_view_is_refused_before_any_epoch_or_derivation_work() {
        // Ordering matters: staleness must not be masked by a coincidentally
        // matching epoch, and must not cost derivation work either.
        struct Stale;
        impl LocalView for Stale {
            fn observed_epoch(&self) -> u64 {
                panic!("a stale view must be refused before its epoch is consulted");
            }
            fn view_is_fresh(&self) -> bool {
                false
            }
            fn derive_message(&self, _: Action, _: &SigningIdentity) -> Option<Vec<u8>> {
                panic!("a stale view must be refused before derivation");
            }
        }
        assert_eq!(
            evaluate(&req(b"canonical".to_vec()), &Stale, &SeenSet::new(), 500),
            Decision::Refuse(Refusal::StaleView)
        );
    }

    #[test]
    fn an_expired_request_is_refused_even_when_the_view_is_stale() {
        // Expiry is the cheapest check and stays first; staleness does not
        // displace it.
        let v = StaleView(view_with(b"canonical".to_vec()));
        assert!(matches!(
            evaluate(&req(b"canonical".to_vec()), &v, &SeenSet::new(), 1_001),
            Decision::Refuse(Refusal::Expired { .. })
        ));
    }

    #[test]
    fn a_fresh_view_is_the_default_so_existing_views_are_unaffected() {
        // `view_is_fresh` has a default impl; a view that does not override
        // it must behave exactly as before this guard existed.
        let v = view_with(b"canonical".to_vec());
        assert!(v.view_is_fresh());
        assert!(matches!(
            evaluate(&req(b"canonical".to_vec()), &v, &SeenSet::new(), 500),
            Decision::Sign(_)
        ));
    }

    #[test]
    fn checks_are_ordered_so_cheap_refusals_precede_derivation() {
        // An expired or wrong-epoch request must be refused without the
        // responder doing derivation work an attacker could amplify.
        struct Exploding;
        impl LocalView for Exploding {
            fn observed_epoch(&self) -> u64 {
                7
            }
            fn derive_message(&self, _: Action, _: &SigningIdentity) -> Option<Vec<u8>> {
                panic!("derivation must not be reached for a cheaply-refusable request");
            }
        }
        let mut r = req(b"x".to_vec());
        r.expiry_unix = 10;
        assert!(matches!(
            evaluate(&r, &Exploding, &SeenSet::new(), 500),
            Decision::Refuse(Refusal::Expired { .. })
        ));
        let mut r2 = req(b"x".to_vec());
        r2.epoch = 99;
        assert!(matches!(
            evaluate(&r2, &Exploding, &SeenSet::new(), 500),
            Decision::Refuse(Refusal::EpochMismatch { .. })
        ));
    }
}
