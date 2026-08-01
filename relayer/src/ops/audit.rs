//! The offline integrity auditor (ADR-0014 §13.4).
//!
//! Re-verifies every stored commitment using the **same recompute-and-compare
//! logic the signing guards implement** (ADR-0012, ADR-0015), and reports.
//!
//! # Why an auditor exists when the signing guards already check
//!
//! `verify_and_load_signable_message` and `verify_and_load_signable_payout`
//! check one record, at the moment it is about to be signed. That is the
//! right place for a guard and the wrong place for an audit: a deposit that
//! was minted last month is never re-examined, and corruption in a row
//! nothing is about to sign is invisible until it is too late to matter.
//!
//! This walks **every** row, on demand, and is the thing an operator runs
//! against an hourly snapshot to learn whether the snapshot is worth keeping.
//!
//! # It is strictly read-only, and that is a design decision
//!
//! The guards halt the record they find a problem in. This does not, for two
//! reasons:
//!
//! - it is meant to run against a **backup**, possibly on another host.
//!   Halting a copy achieves nothing, and writing to a file an operator is
//!   about to restore from is actively harmful;
//! - an auditor that mutates cannot be run casually, and one that cannot be
//!   run casually does not get run.
//!
//! Findings are reported for a human to act on with `glc-admin`, which is
//! where the audit trail belongs.

use sha2::{Digest, Sha256};

use crate::glc::db::{Db, StoredClaim};
use crate::glc::deposit::build_claim_message;
use crate::glc::withdrawal_db::{canonical_payout_intent, payout_commitment, StoredPayoutIntent};

/// One thing that does not add up. Every variant names the record so an
/// operator can go straight to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// SQLite's own structural check failed. Everything below is suspect.
    DatabaseCorrupt(String),
    /// `sha256(stored_message) != stored_hash` — the frozen commitment is
    /// not even internally consistent, so one of the two was altered
    /// independently of the other.
    ClaimSelfInconsistent { deposit_id: i64 },
    /// Recomputing from the persisted fields does not reproduce the frozen
    /// message: some field drifted after the commitment was taken.
    ClaimRecomputeMismatch {
        deposit_id: i64,
        differing: &'static str,
    },
    /// `sha256(stored_intent) != stored_commitment`, the payout analogue.
    PayoutSelfInconsistent { withdrawal_index: i64 },
    /// The recomputed intent differs from the stored one.
    PayoutRecomputeMismatch { withdrawal_index: i64 },
    /// A payout's committed inputs are gone, so the intent cannot be
    /// recomputed at all. Reported rather than skipped: silence about a
    /// record that cannot be checked is indistinguishable from a pass.
    PayoutInputsMissing { withdrawal_index: i64 },
    /// A stored change address that no longer decodes. The intent commits to
    /// its hash160, so this makes the payout unverifiable.
    PayoutChangeAddressUndecodable { withdrawal_index: i64 },
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Finding::DatabaseCorrupt(d) => {
                write!(f, "SQLite integrity_check failed: {d}")
            }
            Finding::ClaimSelfInconsistent { deposit_id } => write!(
                f,
                "deposit {deposit_id}: the frozen claim commitment does not hash to its \
                 stored hash — the two were altered independently"
            ),
            Finding::ClaimRecomputeMismatch {
                deposit_id,
                differing,
            } => write!(
                f,
                "deposit {deposit_id}: recomputing from persisted fields does not reproduce \
                 the frozen message ({differing})"
            ),
            Finding::PayoutSelfInconsistent { withdrawal_index } => write!(
                f,
                "withdrawal {withdrawal_index}: the stored payout intent does not hash to \
                 its stored commitment"
            ),
            Finding::PayoutRecomputeMismatch { withdrawal_index } => write!(
                f,
                "withdrawal {withdrawal_index}: the recomputed payout intent differs from \
                 the stored one"
            ),
            Finding::PayoutInputsMissing { withdrawal_index } => write!(
                f,
                "withdrawal {withdrawal_index}: committed inputs are absent, so the intent \
                 cannot be re-verified"
            ),
            Finding::PayoutChangeAddressUndecodable { withdrawal_index } => write!(
                f,
                "withdrawal {withdrawal_index}: the stored change address no longer decodes"
            ),
        }
    }
}

/// What the audit looked at and what it found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditReport {
    pub integrity_check: String,
    pub claims_checked: usize,
    pub payouts_checked: usize,
    pub findings: Vec<Finding>,
}

impl AuditReport {
    /// Clean means **something was checked and nothing was wrong**.
    ///
    /// An empty database is reported as clean and says so in the summary;
    /// what must never happen is a report that looks clean because the audit
    /// silently examined nothing.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn summary(&self) -> String {
        format!(
            "integrity_check: {}\nclaims checked: {}\npayouts checked: {}\nfindings: {}",
            self.integrity_check,
            self.claims_checked,
            self.payouts_checked,
            self.findings.len()
        )
    }
}

/// Checks one stored claim exactly as the signing guard would.
///
/// Split out so the comparison itself is testable without a database, and so
/// the two checks stay in the order the guard uses: self-consistency first,
/// because if the frozen pair disagrees with itself there is no meaningful
/// "expected" value to compare a recompute against.
pub fn check_claim(c: &StoredClaim) -> Option<Finding> {
    let actual: [u8; 32] = Sha256::digest(&c.canonical_message).into();
    if actual.as_slice() != c.message_hash.as_slice() {
        return Some(Finding::ClaimSelfInconsistent {
            deposit_id: c.deposit_id,
        });
    }
    let recomputed = build_claim_message(
        c.protocol_version,
        &c.program_id,
        c.validator_epoch,
        &c.txid,
        c.vout as u32,
        c.amount_atomic,
        &c.recipient,
        &c.wrapped_mint,
    );
    if recomputed.as_slice() != c.canonical_message.as_slice() {
        return Some(Finding::ClaimRecomputeMismatch {
            deposit_id: c.deposit_id,
            differing: first_differing_claim_field(recomputed.as_slice(), &c.canonical_message),
        });
    }
    None
}

/// Names the first field whose bytes differ, using the canonical layout
/// (ADR-0010). A byte offset is not something an operator can act on at 3am.
fn first_differing_claim_field(recomputed: &[u8], stored: &[u8]) -> &'static str {
    // tag(16) version(1) program_id(32) epoch(8) txid(32) vout(4)
    // amount(8) recipient(32) wrapped_mint(32)
    const FIELDS: [(usize, usize, &str); 9] = [
        (0, 16, "domain tag"),
        (16, 17, "protocol version"),
        (17, 49, "program id"),
        (49, 57, "validator epoch"),
        (57, 89, "txid"),
        (89, 93, "vout"),
        (93, 101, "amount"),
        (101, 133, "recipient"),
        (133, 165, "wrapped mint"),
    ];
    for (start, end, name) in FIELDS {
        let a = recomputed.get(start..end);
        let b = stored.get(start..end);
        if a != b {
            return name;
        }
    }
    "length or trailing bytes"
}

/// Checks one stored payout intent exactly as the signing guard would.
pub fn check_payout(
    p: &StoredPayoutIntent,
    inputs: &[crate::glc::withdrawal_db::VaultUtxo],
) -> Option<Finding> {
    if payout_commitment(&p.intent_bytes).as_slice() != p.commitment_hash.as_slice() {
        return Some(Finding::PayoutSelfInconsistent {
            withdrawal_index: p.withdrawal_index,
        });
    }
    if inputs.is_empty() {
        return Some(Finding::PayoutInputsMissing {
            withdrawal_index: p.withdrawal_index,
        });
    }
    // Mirrors `change_hash160_of`: absent address means no change output,
    // which the intent encodes as twenty zero bytes.
    let change_hash160 = match &p.change_address {
        None => [0u8; 20],
        Some(a) => match crate::withdrawal::address::base58check_decode(a) {
            Ok((_version, h)) => h,
            Err(_) => {
                return Some(Finding::PayoutChangeAddressUndecodable {
                    withdrawal_index: p.withdrawal_index,
                })
            }
        },
    };
    let recomputed = canonical_payout_intent(
        p.protocol_version,
        p.withdrawal_index,
        &p.vault_script_hash,
        &p.dest_hash160,
        p.payout_atomic,
        p.fee_atomic,
        p.change_atomic,
        &change_hash160,
        p.quorum_attempt,
        &p.quorum_indices,
        inputs,
    );
    if recomputed != p.intent_bytes {
        return Some(Finding::PayoutRecomputeMismatch {
            withdrawal_index: p.withdrawal_index,
        });
    }
    None
}

/// Audits a whole database, read-only.
pub fn audit(db: &Db) -> Result<AuditReport, crate::glc::db::DbError> {
    let mut report = AuditReport {
        integrity_check: db.integrity_check()?,
        ..Default::default()
    };
    if report.integrity_check != "ok" {
        // Reported, and the walk still runs: the operator wants to know how
        // much is affected, not merely that something is.
        report
            .findings
            .push(Finding::DatabaseCorrupt(report.integrity_check.clone()));
    }

    for c in db.all_claim_artifacts()? {
        report.claims_checked += 1;
        if let Some(f) = check_claim(&c) {
            report.findings.push(f);
        }
    }

    for p in db.all_payout_intents()? {
        report.payouts_checked += 1;
        let inputs = db.committed_payout_inputs(p.withdrawal_index)?;
        if let Some(f) = check_payout(&p, &inputs) {
            report.findings.push(f);
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim() -> StoredClaim {
        let mut c = StoredClaim {
            deposit_id: 1,
            txid: [0xAB; 32],
            vout: 3,
            amount_atomic: 500_000,
            recipient: [0x11; 32],
            state: "Minted".into(),
            canonical_message: Vec::new(),
            message_hash: Vec::new(),
            protocol_version: 1,
            validator_epoch: 7,
            program_id: [0x22; 32],
            wrapped_mint: [0x33; 32],
        };
        let m = build_claim_message(
            c.protocol_version,
            &c.program_id,
            c.validator_epoch,
            &c.txid,
            c.vout as u32,
            c.amount_atomic,
            &c.recipient,
            &c.wrapped_mint,
        );
        c.message_hash = Sha256::digest(m.as_slice()).to_vec();
        c.canonical_message = m.to_vec();
        c
    }

    #[test]
    fn a_consistent_claim_produces_no_finding() {
        assert_eq!(check_claim(&claim()), None);
    }

    #[test]
    fn a_tampered_stored_hash_is_caught_before_anything_else() {
        // Self-consistency first: with the pair disagreeing there is no
        // meaningful expected value to compare a recompute against.
        let mut c = claim();
        c.message_hash = vec![0xFF; 32];
        assert_eq!(
            check_claim(&c),
            Some(Finding::ClaimSelfInconsistent { deposit_id: 1 })
        );
    }

    #[test]
    fn a_drifted_amount_is_caught_and_named() {
        // The field an operator most needs identified: the amount is what
        // the mint pays out.
        let mut c = claim();
        c.amount_atomic += 1;
        assert_eq!(
            check_claim(&c),
            Some(Finding::ClaimRecomputeMismatch {
                deposit_id: 1,
                differing: "amount"
            })
        );
    }

    #[test]
    fn every_committed_field_is_covered_and_named_correctly() {
        // A drift in any one of them must be caught, and named as itself —
        // a mismatch reported against the wrong field sends an operator to
        // the wrong place.
        type Mutate = Box<dyn Fn(&mut StoredClaim)>;
        let cases: Vec<(&str, Mutate)> = vec![
            (
                "protocol version",
                Box::new(|c: &mut StoredClaim| c.protocol_version = 9),
            ),
            (
                "program id",
                Box::new(|c: &mut StoredClaim| c.program_id = [0x99; 32]),
            ),
            (
                "validator epoch",
                Box::new(|c: &mut StoredClaim| c.validator_epoch = 99),
            ),
            ("txid", Box::new(|c: &mut StoredClaim| c.txid = [0x99; 32])),
            ("vout", Box::new(|c: &mut StoredClaim| c.vout = 9)),
            (
                "amount",
                Box::new(|c: &mut StoredClaim| c.amount_atomic = 9),
            ),
            (
                "recipient",
                Box::new(|c: &mut StoredClaim| c.recipient = [0x99; 32]),
            ),
            (
                "wrapped mint",
                Box::new(|c: &mut StoredClaim| c.wrapped_mint = [0x99; 32]),
            ),
        ];
        for (expected, mutate) in cases {
            let mut c = claim();
            mutate(&mut c);
            assert_eq!(
                check_claim(&c),
                Some(Finding::ClaimRecomputeMismatch {
                    deposit_id: 1,
                    differing: expected
                }),
                "drift in {expected} must be caught and named"
            );
        }
    }

    #[test]
    fn a_truncated_message_is_caught_rather_than_panicking() {
        // Corruption does not respect field boundaries; slicing must not
        // index out of range on a short blob.
        let mut c = claim();
        c.canonical_message.truncate(20);
        c.message_hash = Sha256::digest(&c.canonical_message).to_vec();
        assert!(matches!(
            check_claim(&c),
            Some(Finding::ClaimRecomputeMismatch { .. })
        ));
    }

    #[test]
    fn an_empty_message_is_caught_rather_than_panicking() {
        let mut c = claim();
        c.canonical_message = Vec::new();
        c.message_hash = Sha256::digest(&c.canonical_message).to_vec();
        assert!(matches!(
            check_claim(&c),
            Some(Finding::ClaimRecomputeMismatch { .. })
        ));
    }

    #[test]
    fn a_report_with_no_findings_is_clean_and_says_what_it_checked() {
        // The failure mode that matters: a report must never look clean
        // because it examined nothing. `summary` always states the counts.
        let r = AuditReport {
            integrity_check: "ok".into(),
            claims_checked: 0,
            payouts_checked: 0,
            findings: Vec::new(),
        };
        assert!(r.is_clean());
        assert!(r.summary().contains("claims checked: 0"), "{}", r.summary());
    }

    #[test]
    fn a_report_with_findings_is_not_clean() {
        let r = AuditReport {
            integrity_check: "ok".into(),
            claims_checked: 1,
            payouts_checked: 0,
            findings: vec![Finding::ClaimSelfInconsistent { deposit_id: 4 }],
        };
        assert!(!r.is_clean());
        assert!(r.findings[0].to_string().contains("deposit 4"));
    }

    #[test]
    fn every_finding_renders_something_an_operator_can_act_on() {
        for f in [
            Finding::DatabaseCorrupt("row 3 missing".into()),
            Finding::ClaimSelfInconsistent { deposit_id: 1 },
            Finding::ClaimRecomputeMismatch {
                deposit_id: 1,
                differing: "amount",
            },
            Finding::PayoutSelfInconsistent {
                withdrawal_index: 2,
            },
            Finding::PayoutRecomputeMismatch {
                withdrawal_index: 2,
            },
            Finding::PayoutInputsMissing {
                withdrawal_index: 2,
            },
            Finding::PayoutChangeAddressUndecodable {
                withdrawal_index: 2,
            },
        ] {
            let s = f.to_string();
            assert!(s.len() > 30, "finding renders too tersely: {s}");
            assert!(
                s.contains("deposit") || s.contains("withdrawal") || s.contains("SQLite"),
                "a finding must name what it is about: {s}"
            );
        }
    }
}
