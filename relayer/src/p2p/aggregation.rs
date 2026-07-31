//! Signature collection, timeout, and failover policy (Phase 7d).
//!
//! Separated from the transport so the rules that decide *when a collection
//! round is done* are unit-testable without a network — the same split
//! `policy.rs` uses for the signing decision.
//!
//! # What this does not change
//!
//! Nothing here alters the signing model. Peers still independently
//! re-derive every message and sign only what they derived
//! ([`super::policy`]); only signatures cross the network. This module
//! decides how long to wait, who to ask, and when enough has arrived.

use std::collections::HashSet;
use std::time::Duration;

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;

/// How long a single peer has to answer before it is treated as
/// unavailable for this round.
///
/// A slow peer must not hold up a round indefinitely: with a threshold of M
/// out of N, waiting on one unresponsive peer can stall a mint that M others
/// were ready to authorize.
pub const PER_PEER_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on a whole collection round, independent of peer count.
pub const ROUND_TIMEOUT: Duration = Duration::from_secs(20);

/// What a peer produced in one round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerOutcome {
    Signed(Signature),
    /// The peer answered, and said no. Its view of the chain disagrees with
    /// ours — an alarm, and notably NOT something a retry will fix.
    Refused(String),
    /// Unreachable, timed out, or answered unusably.
    Unavailable(String),
}

/// The result of asking the federation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round {
    pub signatures: Vec<(Pubkey, Signature)>,
    pub refused: Vec<(Pubkey, String)>,
    pub unavailable: Vec<(Pubkey, String)>,
}

impl Round {
    pub fn new() -> Self {
        Round {
            signatures: Vec::new(),
            refused: Vec::new(),
            unavailable: Vec::new(),
        }
    }

    pub fn record(&mut self, peer: Pubkey, outcome: PeerOutcome) {
        match outcome {
            PeerOutcome::Signed(sig) => self.signatures.push((peer, sig)),
            PeerOutcome::Refused(why) => self.refused.push((peer, why)),
            PeerOutcome::Unavailable(why) => self.unavailable.push((peer, why)),
        }
    }

    /// Unique signers among the collected signatures.
    ///
    /// Counts distinct pubkeys, not entries: the same peer answering twice
    /// must never look like two independent approvals.
    pub fn unique_signers(&self) -> usize {
        self.signatures
            .iter()
            .map(|(pk, _)| pk)
            .collect::<HashSet<_>>()
            .len()
    }

    pub fn reached(&self, threshold: usize) -> bool {
        self.unique_signers() >= threshold
    }

    /// Whether asking again could plausibly help.
    ///
    /// A refusal means that peer independently disagreed about what should
    /// be signed — retrying asks the same question and gets the same answer.
    /// Only unavailability is worth another round. If the shortfall cannot
    /// be closed even if every unavailable peer returned, the round is
    /// hopeless and the caller should surface that rather than spin.
    pub fn retry_could_help(&self, threshold: usize) -> bool {
        if self.reached(threshold) {
            return false;
        }
        let shortfall = threshold - self.unique_signers();
        self.unavailable.len() >= shortfall
    }

    /// A one-line summary for operator logs.
    pub fn summary(&self) -> String {
        format!(
            "{} signed, {} refused, {} unavailable",
            self.unique_signers(),
            self.refused.len(),
            self.unavailable.len()
        )
    }
}

impl Default for Round {
    fn default() -> Self {
        Self::new()
    }
}

/// Chooses which peers to ask, and in what order.
///
/// Deterministic by `seed` (the deposit or withdrawal identity) so every
/// validator independently derives the same order without negotiating, and
/// so a replay asks the same peers — preserving the determinism ADR-0015
/// relies on for payouts.
///
/// **Every** peer is included, not just the first M: asking only the minimum
/// means one unavailable peer costs a whole round-trip timeout before
/// anything can proceed. Ordering still matters for the payout path, where
/// the designated quorum must be asked first.
pub fn ask_order(peers: &[Pubkey], seed: u64) -> Vec<Pubkey> {
    if peers.is_empty() {
        return Vec::new();
    }
    let start = (seed % peers.len() as u64) as usize;
    (0..peers.len())
        .map(|i| peers[(start + i) % peers.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::{Keypair, Signer};

    fn pk() -> Pubkey {
        Keypair::new().pubkey()
    }
    fn sig() -> Signature {
        Keypair::new().sign_message(b"x")
    }

    #[test]
    fn counts_unique_signers_not_entries() {
        // A peer answering twice must not look like two approvals.
        let a = pk();
        let mut r = Round::new();
        r.record(a, PeerOutcome::Signed(sig()));
        r.record(a, PeerOutcome::Signed(sig()));
        assert_eq!(r.unique_signers(), 1);
        assert!(!r.reached(2));
    }

    #[test]
    fn reaches_threshold_on_distinct_signers() {
        let mut r = Round::new();
        r.record(pk(), PeerOutcome::Signed(sig()));
        r.record(pk(), PeerOutcome::Signed(sig()));
        assert!(r.reached(2));
        assert!(!r.reached(3));
    }

    #[test]
    fn a_refusal_does_not_make_a_retry_worthwhile() {
        // The peer disagreed about what should be signed. Asking again gets
        // the same answer; only an operator can resolve a genuine
        // disagreement.
        let mut r = Round::new();
        r.record(pk(), PeerOutcome::Signed(sig()));
        r.record(pk(), PeerOutcome::Refused("epoch mismatch".into()));
        assert!(!r.reached(2));
        assert!(
            !r.retry_could_help(2),
            "a refusal is not a transient failure"
        );
    }

    #[test]
    fn unavailability_makes_a_retry_worthwhile() {
        let mut r = Round::new();
        r.record(pk(), PeerOutcome::Signed(sig()));
        r.record(pk(), PeerOutcome::Unavailable("timeout".into()));
        assert!(!r.reached(2));
        assert!(r.retry_could_help(2), "an unreachable peer may come back");
    }

    #[test]
    fn a_shortfall_larger_than_the_unavailable_set_is_hopeless() {
        // Two more signatures needed, only one peer that might return.
        let mut r = Round::new();
        r.record(pk(), PeerOutcome::Signed(sig()));
        r.record(pk(), PeerOutcome::Refused("no".into()));
        r.record(pk(), PeerOutcome::Unavailable("down".into()));
        assert!(
            !r.retry_could_help(3),
            "retrying cannot close a gap the remaining peers could not fill"
        );
    }

    #[test]
    fn a_reached_round_never_asks_for_a_retry() {
        let mut r = Round::new();
        r.record(pk(), PeerOutcome::Signed(sig()));
        r.record(pk(), PeerOutcome::Unavailable("down".into()));
        assert!(r.reached(1));
        assert!(!r.retry_could_help(1));
    }

    #[test]
    fn ask_order_is_deterministic_and_covers_every_peer() {
        let peers: Vec<Pubkey> = (0..5).map(|_| pk()).collect();
        let a = ask_order(&peers, 7);
        let b = ask_order(&peers, 7);
        assert_eq!(a, b, "same seed must give the same order on every node");
        assert_eq!(a.len(), peers.len(), "every peer is asked, not just M");
        assert_eq!(
            a.iter().collect::<HashSet<_>>(),
            peers.iter().collect::<HashSet<_>>(),
            "no peer is dropped or duplicated"
        );
    }

    #[test]
    fn ask_order_spreads_the_starting_point_across_identities() {
        let peers: Vec<Pubkey> = (0..4).map(|_| pk()).collect();
        let starts: HashSet<Pubkey> = (0..4).map(|s| ask_order(&peers, s)[0]).collect();
        assert_eq!(starts.len(), 4, "load is spread rather than always first");
    }

    #[test]
    fn ask_order_handles_an_empty_peer_set() {
        assert!(ask_order(&[], 3).is_empty());
    }

    #[test]
    fn timeouts_are_bounded_and_per_peer_is_shorter_than_the_round() {
        // One slow peer must not consume the whole round budget.
        assert!(PER_PEER_TIMEOUT < ROUND_TIMEOUT);
        assert!(PER_PEER_TIMEOUT > Duration::ZERO);
    }

    #[test]
    fn summary_reports_all_three_outcome_classes() {
        let mut r = Round::new();
        r.record(pk(), PeerOutcome::Signed(sig()));
        r.record(pk(), PeerOutcome::Refused("x".into()));
        r.record(pk(), PeerOutcome::Unavailable("y".into()));
        assert_eq!(r.summary(), "1 signed, 1 refused, 1 unavailable");
    }
}
