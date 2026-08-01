//! What a validator will sign for a governance action (Phase 7i-0).
//!
//! # Governance is different from everything else this signer does
//!
//! Every other signing decision is *derivable*: a deposit mint, a vault
//! payout and a withdrawal completion are all statements about chain facts,
//! so a validator re-derives them from its own observations and refuses
//! anything that does not match ([`super::view`], [`super::payout_view`],
//! [`super::completion_view`]).
//!
//! A governance action is not a statement about the chain. "Should the
//! federation rotate to this validator set?" and "should the supply ceiling
//! rise to this number?" have no on-chain answer to check against. There is
//! nothing to derive.
//!
//! So the trust model has to be different, and pretending otherwise would be
//! worse than saying so plainly: **a governance signature requires explicit
//! human intent from that validator's own operator.**
//!
//! # Staged approvals
//!
//! An operator stages an approval out of band (`glc-admin approve`), naming
//! the exact action and its exact parameters. The signer will then sign
//! **that and nothing else**, once, before it expires.
//!
//! This keeps the federation's threshold meaningful: M signatures mean M
//! operators each independently decided to approve this specific change,
//! rather than M processes automatically agreeing with whoever asked first.
//!
//! # What the staging file is and is not
//!
//! It is an instruction from the operator to their own signer. It is **not**
//! a security boundary against a compromised host: an attacker who can write
//! it can also read the key beside it. Its purpose is to make governance
//! signing *deliberate*, not to defend the key.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// How long a staged approval stays usable.
///
/// Bounded so an approval staged for one incident cannot be used weeks later
/// for a different one. An operator re-stages if a proposal is delayed.
pub const APPROVAL_TTL_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GovernanceRefusal {
    #[error("action {0} is not a governance action")]
    NotAGovernanceAction(u8),
    #[error(
        "this validator's operator has not approved action {action} with those exact parameters"
    )]
    NotApproved { action: u8 },
    #[error("the approval for action {action} expired at {expiry}, now {now}")]
    ApprovalExpired { action: u8, expiry: i64, now: i64 },
    #[error("this validator has already signed a DIFFERENT proposal for action {action}")]
    AlreadySignedAnother { action: u8 },
    #[error(
        "requester claims epoch {requested}, this validator observes {observed} — a governance \
         signature must not outlive the federation revision it was made under"
    )]
    EpochMismatch { requested: u64, observed: u64 },
    #[error("approval store is unreadable: {0}")]
    StoreUnreadable(String),
}

/// One operator-staged approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub action: u8,
    /// SHA-256 over the canonical parameter bytes — the same commitment the
    /// on-chain program recomputes. Committing to the hash rather than the
    /// parameters keeps this file small and its comparison exact.
    pub params_commitment: [u8; 32],
    /// The validator-set epoch this approval was staged under. An approval
    /// does not survive a rotation, for the same reason a governance
    /// signature does not.
    pub epoch: u64,
    /// Unix seconds after which it is refused.
    pub expiry_unix: i64,
    /// Free text recorded for the audit trail — why the operator approved.
    pub note: String,
}

/// The staged approvals a signer will honour, loaded from a file the
/// operator writes.
///
/// One approval per action: staging a second for the same action replaces
/// the first, which is how an operator corrects a mistake.
#[derive(Debug, Default, Clone)]
pub struct ApprovalStore {
    by_action: HashMap<u8, Approval>,
}

impl ApprovalStore {
    pub fn new() -> Self {
        ApprovalStore::default()
    }

    pub fn stage(&mut self, approval: Approval) {
        self.by_action.insert(approval.action, approval);
    }

    pub fn get(&self, action: u8) -> Option<&Approval> {
        self.by_action.get(&action)
    }

    pub fn len(&self) -> usize {
        self.by_action.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_action.is_empty()
    }

    /// Serialises to the on-disk form: one approval per line,
    /// `action hex_commitment epoch expiry note`.
    ///
    /// A plain text line format rather than JSON so an operator can read,
    /// diff and audit it without tooling — this file is meant to be looked
    /// at during an incident.
    pub fn to_text(&self) -> String {
        let mut actions: Vec<&u8> = self.by_action.keys().collect();
        actions.sort_unstable();
        let mut out = String::new();
        for a in actions {
            let ap = &self.by_action[a];
            out.push_str(&format!(
                "{} {} {} {} {}\n",
                ap.action,
                crate::glc::hex::encode(&ap.params_commitment),
                ap.epoch,
                ap.expiry_unix,
                ap.note.replace('\n', " ")
            ));
        }
        out
    }

    pub fn from_text(text: &str) -> Result<Self, GovernanceRefusal> {
        let mut store = ApprovalStore::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(5, ' ');
            let bad =
                |what: &str| GovernanceRefusal::StoreUnreadable(format!("line {}: {what}", n + 1));
            let action: u8 = parts
                .next()
                .ok_or_else(|| bad("missing action"))?
                .parse()
                .map_err(|_| bad("action is not a u8"))?;
            let commitment = crate::glc::hex::decode_exact::<32>(
                parts.next().ok_or_else(|| bad("missing commitment"))?,
            )
            .map_err(|_| bad("commitment is not 32 hex bytes"))?;
            let epoch: u64 = parts
                .next()
                .ok_or_else(|| bad("missing epoch"))?
                .parse()
                .map_err(|_| bad("epoch is not a u64"))?;
            let expiry: i64 = parts
                .next()
                .ok_or_else(|| bad("missing expiry"))?
                .parse()
                .map_err(|_| bad("expiry is not an i64"))?;
            store.stage(Approval {
                action,
                params_commitment: commitment,
                epoch,
                expiry_unix: expiry,
                note: parts.next().unwrap_or("").to_string(),
            });
        }
        Ok(store)
    }

    /// Reads the store, treating a missing file as **no approvals**.
    ///
    /// Absent is not an error: a validator with nothing staged simply
    /// refuses every governance request, which is the correct default.
    pub fn load(path: &Path) -> Result<Self, GovernanceRefusal> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_text(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(GovernanceRefusal::StoreUnreadable(e.to_string())),
        }
    }
}

/// A validator's governance signing view.
pub struct GovernanceView {
    approvals_path: PathBuf,
    /// What has already been signed, so a retry is idempotent and a second,
    /// conflicting proposal for the same action is refused — the same
    /// equivocation guard the mint path has.
    signed: std::sync::Mutex<HashMap<u8, [u8; 32]>>,
}

impl GovernanceView {
    pub fn new(approvals_path: PathBuf) -> Self {
        GovernanceView {
            approvals_path,
            signed: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Decides whether this validator will sign the governance action
    /// committing to `params_commitment`.
    ///
    /// Re-reads the approval file every time rather than caching it: an
    /// operator revoking an approval mid-incident must take effect
    /// immediately, and a cached copy would silently ignore them.
    pub fn approve(
        &self,
        action: u8,
        params_commitment: &[u8; 32],
        requested_epoch: u64,
        observed_epoch: u64,
        now_unix: i64,
    ) -> Result<(), GovernanceRefusal> {
        if !is_governance_action(action) {
            return Err(GovernanceRefusal::NotAGovernanceAction(action));
        }
        // Cheapest check first, and it needs no file access: a signature made
        // under one federation must never apply under another.
        if requested_epoch != observed_epoch {
            return Err(GovernanceRefusal::EpochMismatch {
                requested: requested_epoch,
                observed: observed_epoch,
            });
        }

        let store = ApprovalStore::load(&self.approvals_path)?;
        let approval = store
            .get(action)
            .ok_or(GovernanceRefusal::NotApproved { action })?;

        // The commitment must match EXACTLY. This is the whole point: the
        // operator approved one specific parameter set, not "a rotation".
        if approval.params_commitment != *params_commitment {
            return Err(GovernanceRefusal::NotApproved { action });
        }
        if approval.epoch != observed_epoch {
            return Err(GovernanceRefusal::EpochMismatch {
                requested: approval.epoch,
                observed: observed_epoch,
            });
        }
        if now_unix > approval.expiry_unix {
            return Err(GovernanceRefusal::ApprovalExpired {
                action,
                expiry: approval.expiry_unix,
                now: now_unix,
            });
        }

        // Equivocation guard: having signed one proposal for an action, this
        // validator must never sign a different one. A retry of the SAME
        // proposal is free.
        let mut signed = self.signed.lock().unwrap();
        match signed.get(&action) {
            Some(prev) if prev == params_commitment => Ok(()),
            Some(_) => Err(GovernanceRefusal::AlreadySignedAnother { action }),
            None => {
                signed.insert(action, *params_commitment);
                Ok(())
            }
        }
    }
}

/// The action bytes that are governance actions, and only those.
///
/// A mint or payout action reaching this path would mean a signature made
/// under the governance domain tag for something that is not governance.
pub fn is_governance_action(action: u8) -> bool {
    matches!(
        action,
        glc_bridge_shared::governance::ACTION_PROPOSE_ROTATION
            | glc_bridge_shared::governance::ACTION_CANCEL_ROTATION
            | glc_bridge_shared::governance::ACTION_PROPOSE_TVL_RAISE
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use glc_bridge_shared::governance::{
        ACTION_CANCEL_ROTATION, ACTION_PROPOSE_ROTATION, ACTION_PROPOSE_TVL_RAISE,
    };

    const NOW: i64 = 1_000_000;

    fn approval(action: u8, commitment: [u8; 32], epoch: u64) -> Approval {
        Approval {
            action,
            params_commitment: commitment,
            epoch,
            expiry_unix: NOW + APPROVAL_TTL_SECONDS,
            note: "rehearsed on testnet 2026-08-01".to_string(),
        }
    }

    fn view_with(approvals: &[Approval]) -> (GovernanceView, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals");
        let mut store = ApprovalStore::new();
        for a in approvals {
            store.stage(a.clone());
        }
        std::fs::write(&path, store.to_text()).unwrap();
        (GovernanceView::new(path), dir)
    }

    #[test]
    fn signs_exactly_what_the_operator_approved() {
        let c = [0xAA; 32];
        let (v, _d) = view_with(&[approval(ACTION_PROPOSE_ROTATION, c, 7)]);
        assert_eq!(v.approve(ACTION_PROPOSE_ROTATION, &c, 7, 7, NOW), Ok(()));
    }

    #[test]
    fn refuses_a_proposal_the_operator_did_not_approve() {
        // The load-bearing property: approving "a rotation" is not a thing.
        // The operator approves ONE parameter set.
        let (v, _d) = view_with(&[approval(ACTION_PROPOSE_ROTATION, [0xAA; 32], 7)]);
        assert_eq!(
            v.approve(ACTION_PROPOSE_ROTATION, &[0xBB; 32], 7, 7, NOW),
            Err(GovernanceRefusal::NotApproved {
                action: ACTION_PROPOSE_ROTATION
            })
        );
    }

    #[test]
    fn refuses_everything_when_nothing_is_staged() {
        // A validator with no approvals refuses all governance — the correct
        // default, and what a fresh deployment does.
        let dir = tempfile::tempdir().unwrap();
        let v = GovernanceView::new(dir.path().join("does-not-exist"));
        assert_eq!(
            v.approve(ACTION_PROPOSE_ROTATION, &[0xAA; 32], 7, 7, NOW),
            Err(GovernanceRefusal::NotApproved {
                action: ACTION_PROPOSE_ROTATION
            })
        );
    }

    #[test]
    fn an_approval_for_one_action_does_not_authorise_another() {
        let c = [0xAA; 32];
        let (v, _d) = view_with(&[approval(ACTION_PROPOSE_ROTATION, c, 7)]);
        assert!(v.approve(ACTION_PROPOSE_TVL_RAISE, &c, 7, 7, NOW).is_err());
        assert!(v.approve(ACTION_CANCEL_ROTATION, &c, 7, 7, NOW).is_err());
    }

    #[test]
    fn an_expired_approval_is_refused() {
        // An approval staged for one incident must not be usable weeks later
        // for a different one.
        let c = [0xAA; 32];
        let (v, _d) = view_with(&[approval(ACTION_PROPOSE_ROTATION, c, 7)]);
        let past = NOW + APPROVAL_TTL_SECONDS + 1;
        assert!(matches!(
            v.approve(ACTION_PROPOSE_ROTATION, &c, 7, 7, past),
            Err(GovernanceRefusal::ApprovalExpired { .. })
        ));
    }

    #[test]
    fn an_approval_does_not_survive_a_rotation() {
        // Staged under epoch 7, the federation is now at 8. The approval was
        // a decision about a different federation.
        let c = [0xAA; 32];
        let (v, _d) = view_with(&[approval(ACTION_PROPOSE_ROTATION, c, 7)]);
        assert!(matches!(
            v.approve(ACTION_PROPOSE_ROTATION, &c, 8, 8, NOW),
            Err(GovernanceRefusal::EpochMismatch { .. })
        ));
    }

    #[test]
    fn a_requester_claiming_the_wrong_epoch_is_refused_without_touching_the_file() {
        // Cheapest check first: no file access for a request that cannot be
        // valid.
        let v = GovernanceView::new(PathBuf::from("/nonexistent/approvals"));
        assert!(matches!(
            v.approve(ACTION_PROPOSE_ROTATION, &[0xAA; 32], 6, 7, NOW),
            Err(GovernanceRefusal::EpochMismatch {
                requested: 6,
                observed: 7
            })
        ));
    }

    #[test]
    fn a_retry_of_the_same_proposal_is_idempotent() {
        let c = [0xAA; 32];
        let (v, _d) = view_with(&[approval(ACTION_PROPOSE_ROTATION, c, 7)]);
        assert_eq!(v.approve(ACTION_PROPOSE_ROTATION, &c, 7, 7, NOW), Ok(()));
        assert_eq!(
            v.approve(ACTION_PROPOSE_ROTATION, &c, 7, 7, NOW),
            Ok(()),
            "retries must be free"
        );
    }

    #[test]
    fn a_second_conflicting_proposal_for_one_action_is_refused() {
        // The equivocation guard. Having signed one rotation, this validator
        // must not also sign a different one — even if the operator later
        // stages it, which would otherwise let one validator support two
        // competing proposals at once.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals");
        let mut store = ApprovalStore::new();
        store.stage(approval(ACTION_PROPOSE_ROTATION, [0xAA; 32], 7));
        std::fs::write(&path, store.to_text()).unwrap();
        let v = GovernanceView::new(path.clone());
        assert_eq!(
            v.approve(ACTION_PROPOSE_ROTATION, &[0xAA; 32], 7, 7, NOW),
            Ok(())
        );

        // Operator re-stages a DIFFERENT proposal for the same action.
        let mut store2 = ApprovalStore::new();
        store2.stage(approval(ACTION_PROPOSE_ROTATION, [0xBB; 32], 7));
        std::fs::write(&path, store2.to_text()).unwrap();
        assert_eq!(
            v.approve(ACTION_PROPOSE_ROTATION, &[0xBB; 32], 7, 7, NOW),
            Err(GovernanceRefusal::AlreadySignedAnother {
                action: ACTION_PROPOSE_ROTATION
            })
        );
    }

    #[test]
    fn revoking_an_approval_takes_effect_immediately() {
        // The file is re-read every time. An operator who realises mid-
        // incident that a proposal is wrong must be able to stop their
        // signer without restarting it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals");
        let mut store = ApprovalStore::new();
        store.stage(approval(ACTION_PROPOSE_TVL_RAISE, [0xCC; 32], 7));
        std::fs::write(&path, store.to_text()).unwrap();
        let v = GovernanceView::new(path.clone());

        std::fs::write(&path, "").unwrap();
        assert!(
            v.approve(ACTION_PROPOSE_TVL_RAISE, &[0xCC; 32], 7, 7, NOW)
                .is_err(),
            "a revoked approval must stop working without a restart"
        );
    }

    #[test]
    fn only_governance_actions_reach_this_path() {
        let (v, _d) = view_with(&[approval(ACTION_PROPOSE_ROTATION, [0xAA; 32], 7)]);
        for not_governance in [0x00u8, 0x01, 0x02, 0x06, 0xFF] {
            assert!(
                matches!(
                    v.approve(not_governance, &[0xAA; 32], 7, 7, NOW),
                    Err(GovernanceRefusal::NotAGovernanceAction(_))
                ),
                "action {not_governance:#x} must not be treated as governance"
            );
        }
        assert!(is_governance_action(ACTION_PROPOSE_ROTATION));
        assert!(is_governance_action(ACTION_CANCEL_ROTATION));
        assert!(is_governance_action(ACTION_PROPOSE_TVL_RAISE));
    }

    #[test]
    fn the_store_round_trips_through_its_text_form() {
        // Operators read and diff this file during incidents; it must be
        // stable and parseable.
        let mut store = ApprovalStore::new();
        store.stage(approval(ACTION_PROPOSE_ROTATION, [0x11; 32], 7));
        store.stage(approval(ACTION_PROPOSE_TVL_RAISE, [0x22; 32], 7));
        let text = store.to_text();
        let back = ApprovalStore::from_text(&text).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(
            back.get(ACTION_PROPOSE_ROTATION).unwrap().params_commitment,
            [0x11; 32]
        );
        assert_eq!(back.to_text(), text, "encoding is stable");
    }

    #[test]
    fn the_store_tolerates_comments_and_blank_lines_but_not_corruption() {
        let ok = ApprovalStore::from_text("# staged for the 2026-08 rotation\n\n3 1111111111111111111111111111111111111111111111111111111111111111 7 999 note here\n").unwrap();
        assert_eq!(ok.len(), 1);
        for bad in [
            "notanumber aa 7 999 x",
            "3 nothex 7 999 x",
            "3 11 7 999 x",
            "3",
        ] {
            assert!(
                ApprovalStore::from_text(bad).is_err(),
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn staging_the_same_action_twice_replaces_rather_than_accumulates() {
        // How an operator corrects a typo. Two live approvals for one action
        // would make "what did I approve?" unanswerable.
        let mut store = ApprovalStore::new();
        store.stage(approval(ACTION_PROPOSE_ROTATION, [0x11; 32], 7));
        store.stage(approval(ACTION_PROPOSE_ROTATION, [0x22; 32], 7));
        assert_eq!(store.len(), 1);
        assert_eq!(
            store
                .get(ACTION_PROPOSE_ROTATION)
                .unwrap()
                .params_commitment,
            [0x22; 32]
        );
    }
}
