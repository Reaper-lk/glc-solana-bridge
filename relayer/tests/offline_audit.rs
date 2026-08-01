//! The offline auditor against a real database (ADR-0014 §13.4).
//!
//! The unit tests in `ops::audit` check the comparison logic on constructed
//! records. This checks the thing an operator actually does: point
//! `glc-audit` at a database file and believe the answer.
//!
//! It matters because the auditor's value is entirely in whether it *catches*
//! corruption, and corruption in a test that constructs its own rows can
//! always be arranged to be caught. Here the rows are written by the real
//! persistence layer and then damaged by writing to the file directly —
//! which is what disk corruption, a bad restore, or tampering actually look
//! like.

use rusqlite::params;

use glc_relayer::glc::db::{Db, DepositState, NewBlock, NewCandidate, NewClaimArtifact};
use glc_relayer::glc::deposit::build_claim_message;
use glc_relayer::ops::audit::{self, Finding};

const PROGRAM_ID: [u8; 32] = [0x22; 32];
const WRAPPED_MINT: [u8; 32] = [0x33; 32];

/// A database with one sound deposit and its frozen claim artifact, written
/// through the ordinary write path.
fn seeded(dir: &std::path::Path) -> (std::path::PathBuf, i64) {
    let path = dir.join("relayer.sqlite3");
    let mut db = Db::open(&path).unwrap();

    let ids = db
        .ingest_block(
            &NewBlock {
                height: 100,
                hash: [0x01; 32],
                prev_hash: [0x00; 32],
                block_time: 1_000,
                indexed_at: 1_000,
            },
            &[NewCandidate {
                txid: [0xAB; 32],
                vout: 0,
                amount_atomic: 500_000,
                recipient: [0x11; 32],
                block_height: 100,
                block_hash: [0x01; 32],
                raw_tx_hex: "00".into(),
                initial_state: DepositState::Confirming,
                discovered_at: 1_000,
                failure_reason: None,
            }],
        )
        .unwrap();
    let id = ids[0];

    let message = build_claim_message(
        1,
        &PROGRAM_ID,
        7,
        &[0xAB; 32],
        0,
        500_000,
        &[0x11; 32],
        &WRAPPED_MINT,
    );
    let hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(message.as_slice()).into()
    };
    db.transition_state(
        id,
        DepositState::ReadyForSignature,
        1_100,
        None,
        Some(&NewClaimArtifact {
            deposit_id: id,
            canonical_message: message,
            message_hash: hash,
            protocol_version: 1,
            validator_epoch: 7,
            program_id: PROGRAM_ID,
            wrapped_mint: WRAPPED_MINT,
            created_at: 1_100,
        }),
    )
    .unwrap();
    (path, id)
}

/// Damages the file the way corruption does: behind the application's back.
fn tamper(path: &std::path::Path, sql: &str) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute(sql, params![]).unwrap();
}

#[test]
fn a_sound_database_audits_clean_and_says_what_it_checked() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = seeded(dir.path());
    let db = Db::open(&path).unwrap();

    let report = audit::audit(&db).unwrap();
    assert_eq!(report.integrity_check, "ok");
    assert_eq!(
        report.claims_checked, 1,
        "the audit must actually examine it"
    );
    assert!(report.is_clean(), "{:?}", report.findings);
    // Clean over zero records is a different statement from clean over one.
    assert!(report.summary().contains("claims checked: 1"));
}

#[test]
fn an_amount_altered_behind_the_applications_back_is_caught() {
    // The case that matters: the row a mint would pay out from no longer
    // matches the commitment the federation signed over. The signing guard
    // would catch this the next time it signed — but a minted deposit is
    // never signed again, so without an audit nothing would ever look.
    let dir = tempfile::tempdir().unwrap();
    let (path, id) = seeded(dir.path());
    tamper(
        &path,
        &format!(
            "UPDATE deposit_candidates SET amount_atomic = x'{}' WHERE id = {id}",
            hex_of(&999_999u64.to_le_bytes())
        ),
    );

    let db = Db::open(&path).unwrap();
    let report = audit::audit(&db).unwrap();
    assert!(!report.is_clean());
    assert_eq!(
        report.findings,
        vec![Finding::ClaimRecomputeMismatch {
            deposit_id: id,
            differing: "amount"
        }]
    );
}

#[test]
fn a_rewritten_commitment_hash_is_caught_as_self_inconsistency() {
    let dir = tempfile::tempdir().unwrap();
    let (path, id) = seeded(dir.path());
    tamper(
        &path,
        &format!(
            "UPDATE claim_artifacts SET message_hash = x'{}' WHERE deposit_id = {id}",
            hex_of(&[0xFF; 32])
        ),
    );

    let db = Db::open(&path).unwrap();
    let report = audit::audit(&db).unwrap();
    assert_eq!(
        report.findings,
        vec![Finding::ClaimSelfInconsistent { deposit_id: id }]
    );
}

#[test]
fn a_rewritten_message_and_matching_hash_is_still_caught() {
    // The sophisticated case: an attacker who rewrites the message AND
    // recomputes its hash defeats the self-consistency check. Only the
    // recompute-from-fields check catches it, which is why both exist.
    let dir = tempfile::tempdir().unwrap();
    let (path, id) = seeded(dir.path());

    let forged = build_claim_message(
        1,
        &PROGRAM_ID,
        7,
        &[0xAB; 32],
        0,
        999_999, // a different amount
        &[0x11; 32],
        &WRAPPED_MINT,
    );
    let forged_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(forged.as_slice()).into()
    };
    tamper(
        &path,
        &format!(
            "UPDATE claim_artifacts SET canonical_message = x'{}', message_hash = x'{}' \
             WHERE deposit_id = {id}",
            hex_of(forged.as_slice()),
            hex_of(&forged_hash)
        ),
    );

    let db = Db::open(&path).unwrap();
    let report = audit::audit(&db).unwrap();
    assert_eq!(
        report.findings,
        vec![Finding::ClaimRecomputeMismatch {
            deposit_id: id,
            differing: "amount"
        }],
        "a self-consistent forgery must still fail the recompute"
    );
}

#[test]
fn the_audit_writes_nothing() {
    // It is meant to run against a backup, possibly one being restored from.
    // Writing to that file would be worse than not auditing it.
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = seeded(dir.path());

    let before = std::fs::read(&path).unwrap();
    {
        let db = Db::open(&path).unwrap();
        let _ = audit::audit(&db).unwrap();
    }
    let after = std::fs::read(&path).unwrap();
    assert_eq!(
        before, after,
        "the auditor modified the database file it was pointed at"
    );
}

#[test]
fn an_empty_database_is_clean_but_reports_zero_checked() {
    // The failure mode this guards: a report that looks like a pass because
    // it examined nothing. `is_clean` is true, and the summary says why.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.sqlite3");
    let db = Db::open(&path).unwrap();

    let report = audit::audit(&db).unwrap();
    assert!(report.is_clean());
    assert_eq!(report.claims_checked, 0);
    assert_eq!(report.payouts_checked, 0);
    assert!(report.summary().contains("claims checked: 0"));
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
