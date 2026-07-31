//! Persistent, transactional storage for the Goldcoin indexer (ADR-0011).
//!
//! SQLite via `rusqlite` (bundled), owner decision U1. Every operation that
//! changes chain-tracking state (`ingest_block`, `rollback_reorg`,
//! `promote_state`) runs inside one SQL transaction — commit or full
//! rollback, never partial writes (owner requirement: "keep every
//! chain-state-changing database operation transactional").
//!
//! History is never deleted (owner decision U7): superseded rows move to
//! the terminal `Orphaned`/`Failed` states rather than being removed, so the
//! full deposit history remains queryable forever.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;

use super::hex;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database schema version {found} is newer than this build supports ({supported}); refusing to start against unrecognized schema")]
    UnsupportedSchemaVersion { found: i64, supported: i64 },
    #[error("unknown deposit state {0:?} in database row")]
    UnknownState(String),
    #[error("claim message integrity mismatch for deposit {deposit_id}: recomputed message no longer matches the stored commitment (field: {field})")]
    MessageIntegrityMismatch {
        deposit_id: i64,
        field: &'static str,
    },
    #[error("no claim artifact found for deposit {0} — cannot verify or sign")]
    MissingClaimArtifact(i64),
    #[error("operator recovery of deposit {0} requires a non-empty operator note")]
    OperatorNoteRequired(i64),
    #[error(
        "deposit {deposit_id} cannot be recovered directly to {to_state}: an operator may only \
         return an integrity-halted deposit to ReadyForSignature or Failed"
    )]
    InvalidIntegrityRecoveryTarget {
        deposit_id: i64,
        to_state: &'static str,
    },
    #[error(
        "deposit {deposit_id} is in state {found}, not IntegrityHalted — operator integrity \
         recovery does not apply"
    )]
    NotIntegrityHalted { deposit_id: i64, found: String },

    // ---- Withdrawal side (Phase 6, ADR-0013) ----
    #[error("unknown withdrawal state {0:?} in database row")]
    UnknownWithdrawalState(String),
    #[error("no withdrawal request {0} in database")]
    WithdrawalNotFound(i64),
    #[error("no payout row for withdrawal {0} — cannot verify or sign")]
    MissingPayout(i64),
    #[error(
        "payout integrity mismatch for withdrawal {withdrawal_index}: recomputed canonical payout \
         no longer matches the stored commitment (field: {field})"
    )]
    PayoutIntegrityMismatch {
        withdrawal_index: i64,
        field: &'static str,
    },
    #[error(
        "withdrawal {withdrawal_index} reservation is no longer valid ({reason}) — refusing to sign"
    )]
    ReservationInvalid {
        withdrawal_index: i64,
        reason: &'static str,
    },
    #[error("withdrawal {0} already has a completed payout — refusing to sign again")]
    PayoutAlreadyCompleted(i64),
    #[error("withdrawal {0} already has a confirmed payout transaction — refusing to sign again")]
    PayoutAlreadyConfirmed(i64),
    #[error("insufficient spendable vault funds: need {required} atomic, have {available}")]
    InsufficientVaultFunds { required: u64, available: u64 },
    #[error("operator recovery of withdrawal {0} requires a non-empty operator note")]
    WithdrawalOperatorNoteRequired(i64),
    #[error(
        "withdrawal {withdrawal_index} cannot be recovered directly to {to_state}: an operator may \
         only return an integrity-halted withdrawal to Validated or Failed"
    )]
    InvalidWithdrawalRecoveryTarget {
        withdrawal_index: i64,
        to_state: &'static str,
    },
    #[error(
        "withdrawal {withdrawal_index} is in state {found}, not IntegrityHalted — operator \
         integrity recovery does not apply"
    )]
    NotWithdrawalIntegrityHalted {
        withdrawal_index: i64,
        found: String,
    },
}

/// Current schema version this build understands. Bumping this must be
/// paired with a migration step in [`Db::run_migrations`].
const CURRENT_SCHEMA_VERSION: i64 = 4;

/// The eight states of the deposit lifecycle (ADR-0011, extended by
/// ADR-0012 with `IntegrityHalted`). `Submitted`/`Minted` are written from
/// Phase 5 onward (`orchestrator.rs`); Phase 4's indexer never produces
/// them (no Solana RPC existed then, see `glc::config`'s owner decision U4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositState {
    Candidate,
    Confirming,
    ReadyForSignature,
    Orphaned,
    Submitted,
    Minted,
    Failed,
    /// Terminal, reached ONLY when the reload-and-recompute safeguard
    /// (`Db::verify_and_load_signable_message`) detects that a deposit's
    /// persisted fields — or the frozen `claim_artifacts` commitment itself
    /// — no longer match what was recorded at `ReadyForSignature` time.
    /// This is never an ordinary/expected outcome (unlike `Failed`, which
    /// covers routine rejections like a malformed binding or dust amount):
    /// it indicates a bug, database corruption, or tampering, and is never
    /// automatically retried. Distinguished from `Failed` deliberately, per
    /// owner instruction, so an anomaly this serious is never silently
    /// filed alongside routine rejections — it requires manual operator
    /// investigation (ADR-0012).
    IntegrityHalted,
}

impl DepositState {
    pub fn as_str(self) -> &'static str {
        match self {
            DepositState::Candidate => "Candidate",
            DepositState::Confirming => "Confirming",
            DepositState::ReadyForSignature => "ReadyForSignature",
            DepositState::Orphaned => "Orphaned",
            DepositState::Submitted => "Submitted",
            DepositState::Minted => "Minted",
            DepositState::Failed => "Failed",
            DepositState::IntegrityHalted => "IntegrityHalted",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DbError> {
        match s {
            "Candidate" => Ok(DepositState::Candidate),
            "Confirming" => Ok(DepositState::Confirming),
            "ReadyForSignature" => Ok(DepositState::ReadyForSignature),
            "Orphaned" => Ok(DepositState::Orphaned),
            "Submitted" => Ok(DepositState::Submitted),
            "Minted" => Ok(DepositState::Minted),
            "Failed" => Ok(DepositState::Failed),
            "IntegrityHalted" => Ok(DepositState::IntegrityHalted),
            other => Err(DbError::UnknownState(other.to_string())),
        }
    }

    /// States that are neither terminal history (`Orphaned`, `Failed`,
    /// `IntegrityHalted`) nor fully complete (`Minted`) — i.e. still subject
    /// to reorg rollback and further progression.
    #[allow(dead_code)]
    pub fn is_active(self) -> bool {
        matches!(
            self,
            DepositState::Candidate
                | DepositState::Confirming
                | DepositState::ReadyForSignature
                | DepositState::Submitted
        )
    }
}

/// A newly indexed block, ready to be committed with its deposit candidates.
pub struct NewBlock {
    pub height: i64,
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub block_time: i64,
    pub indexed_at: i64,
}

/// A vault-paying output discovered while ingesting a block: either a valid
/// candidate deposit, or one recorded straight to `Failed` with a reason
/// (malformed binding, below the configured minimum — owner decision U3).
pub struct NewCandidate {
    pub txid: [u8; 32],
    pub vout: i64,
    pub amount_atomic: u64,
    pub recipient: [u8; 32],
    pub block_height: i64,
    pub block_hash: [u8; 32],
    pub raw_tx_hex: String,
    pub discovered_at: i64,
    /// `Candidate` for a well-formed, above-minimum deposit; `Failed` (with
    /// `failure_reason` set) for anything ingestion already knows is unusable.
    pub initial_state: DepositState,
    pub failure_reason: Option<String>,
}

/// A full query-result row. Not every field is read by every caller (e.g.
/// `state` is redundant when the row came from a state-filtered query) —
/// this is a general read-model, not a narrow per-use-site projection.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DepositRow {
    pub id: i64,
    pub txid: [u8; 32],
    pub txid_hex: String,
    pub vout: i64,
    pub amount_atomic: u64,
    pub recipient: [u8; 32],
    pub block_height: i64,
    pub block_hash: [u8; 32],
    pub raw_tx_hex: String,
    pub state: DepositState,
    pub discovered_at: i64,
    pub ready_at: Option<i64>,
    pub failure_reason: Option<String>,
    /// Set by `mark_submitted` (Phase 5); the last transaction signature
    /// this deposit was submitted under. Audit/reconciliation aid only —
    /// the claim PDA's existence is the authoritative "minted" signal.
    pub submitted_signature: Option<String>,
}

/// Unsigned canonical claim artifact for a `ReadyForSignature` deposit —
/// exactly the Phase 3 message format (`glc_bridge_shared::claim`). Never
/// signed or submitted in Phase 4.
pub struct NewClaimArtifact {
    pub deposit_id: i64,
    pub canonical_message: [u8; 166],
    pub message_hash: [u8; 32],
    pub protocol_version: u8,
    pub validator_epoch: u64,
    pub program_id: [u8; 32],
    pub wrapped_mint: [u8; 32],
    pub created_at: i64,
}

/// The verified, freshly recomputed message and fields to sign — the
/// output of [`Db::verify_and_load_signable_message`]. Never constructed
/// from a cached/stored blob directly (ADR-0012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableClaim {
    pub deposit_id: i64,
    pub message: [u8; 166],
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount_atomic: u64,
    pub recipient: [u8; 32],
    /// From the frozen `claim_artifacts` commitment — lets the caller
    /// sanity-check the claim was built for the deployment it's about to
    /// submit to, before ever signing.
    pub program_id: [u8; 32],
    pub wrapped_mint: [u8; 32],
    pub validator_epoch: u64,
}

/// The canonical claim message's field layout (`glc_bridge_shared::claim`,
/// ADR-0010), used ONLY to attribute an integrity mismatch to specific
/// field(s) for the audit trail. Kept as a plain table rather than derived
/// from the shared crate because it is deliberately a diagnostic view, not
/// part of the signing path — nothing here can influence which bytes get
/// signed.
const CLAIM_FIELD_LAYOUT: &[(&str, usize, usize)] = &[
    ("domain_tag", 0, 16),
    ("protocol_version", 16, 17),
    ("program_id", 17, 49),
    ("validator_epoch", 49, 57),
    ("action_type", 57, 58),
    ("txid", 58, 90),
    ("vout", 90, 94),
    ("amount_atomic", 94, 102),
    ("recipient", 102, 134),
    ("wrapped_mint", 134, 166),
];

/// Names the canonical-message field(s) in which `recomputed` and `stored`
/// differ, comma-separated, for the `IntegrityHalted` audit record.
///
/// Returns `None` when attribution is not possible — specifically when
/// `stored` is not a full-length message (e.g. truncated corruption), since
/// then per-field offsets are meaningless. A field-level answer is a
/// forensic aid for the operator; the halt itself never depends on it.
fn diff_claim_fields(recomputed: &[u8], stored: &[u8]) -> Option<String> {
    if stored.len() != recomputed.len() || stored.len() != 166 {
        return None;
    }
    let differing: Vec<&str> = CLAIM_FIELD_LAYOUT
        .iter()
        .filter(|(_, start, end)| recomputed[*start..*end] != stored[*start..*end])
        .map(|(name, _, _)| *name)
        .collect();
    if differing.is_empty() {
        None
    } else {
        Some(differing.join(","))
    }
}

pub struct Db {
    pub(super) conn: Connection,
}

impl Db {
    /// Opens (creating if absent) the database at `path` and applies any
    /// pending migrations. `":memory:"` opens a private in-memory database
    /// (used by unit tests).
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Phase 5 (ADR-0012) opens a second connection to this same file
        // from the orchestrator alongside the indexer's. WAL mode lets a
        // reader/writer overlap with a writer instead of failing outright,
        // and the busy_timeout absorbs the remaining writer/writer overlap
        // window instead of surfacing a spurious "database is locked"
        // error on an ordinary tick.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let mut db = Db { conn };
        db.run_migrations()?;
        Ok(db)
    }

    fn run_migrations(&mut self) -> Result<(), DbError> {
        let tx = self.conn.transaction()?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")?;
        let current: Option<i64> = tx
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| {
                r.get(0)
            })
            .optional()?;

        if let Some(v) = current {
            if v > CURRENT_SCHEMA_VERSION {
                return Err(DbError::UnsupportedSchemaVersion {
                    found: v,
                    supported: CURRENT_SCHEMA_VERSION,
                });
            }
        }

        // A sequential ladder rather than per-version branches: a database
        // at any supported version applies exactly the steps above it, in
        // order, so v1 -> v3 and v2 -> v3 are both handled by construction
        // and adding v4 means appending one arm. A fresh database (`None`)
        // starts at 0 and runs every step.
        let from_version = current.unwrap_or(0);
        for step in (from_version + 1)..=CURRENT_SCHEMA_VERSION {
            match step {
                1 => apply_v1_schema(&tx)?,
                2 => apply_v2_schema(&tx)?,
                3 => apply_v3_schema(&tx)?,
                4 => super::withdrawal_db::apply_v4_schema(&tx)?,
                other => unreachable!("no migration defined for schema version {other}"),
            }
        }

        if from_version != CURRENT_SCHEMA_VERSION {
            if current.is_none() {
                tx.execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    params![CURRENT_SCHEMA_VERSION],
                )?;
            } else {
                tx.execute(
                    "UPDATE schema_version SET version = ?1",
                    params![CURRENT_SCHEMA_VERSION],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Commits one newly indexed block and every deposit candidate/failure
    /// discovered in it, transactionally, along with a state-log row per
    /// candidate and the updated chain tip.
    ///
    /// Idempotent when called twice with an identical `(height, hash)` —
    /// this is what makes restart-resume and duplicate-tick processing
    /// safe. Precondition: the caller must never call this for a `height`
    /// that already has a DIFFERENT stored hash — the reorg walk-back
    /// (indexer.rs) must call [`Db::rollback_reorg`] first in that case.
    pub fn ingest_block(
        &mut self,
        block: &NewBlock,
        candidates: &[NewCandidate],
    ) -> Result<Vec<i64>, DbError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO indexed_blocks (height, hash, prev_hash, block_time, indexed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                block.height,
                block.hash.as_slice(),
                block.prev_hash.as_slice(),
                block.block_time,
                block.indexed_at
            ],
        )?;
        tx.execute(
            "INSERT INTO chain_state (id, tip_height, tip_hash) VALUES (0, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET tip_height = excluded.tip_height, tip_hash = excluded.tip_hash",
            params![block.height, block.hash.as_slice()],
        )?;

        let mut ids = Vec::with_capacity(candidates.len());
        for c in candidates {
            let txid_hex = hex::encode(&c.txid);
            tx.execute(
                "INSERT OR IGNORE INTO deposit_candidates
                    (txid, txid_hex, vout, amount_atomic, recipient, block_height, block_hash,
                     raw_tx_hex, state, discovered_at, ready_at, failure_reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11)",
                params![
                    c.txid.as_slice(),
                    txid_hex,
                    c.vout,
                    c.amount_atomic.to_le_bytes().as_slice(),
                    c.recipient.as_slice(),
                    c.block_height,
                    c.block_hash.as_slice(),
                    c.raw_tx_hex,
                    c.initial_state.as_str(),
                    c.discovered_at,
                    c.failure_reason,
                ],
            )?;
            // rowid of the row whether just-inserted or pre-existing
            // (INSERT OR IGNORE leaves last_insert_rowid unchanged on a
            // no-op, so look the row up explicitly by its unique key).
            let id: i64 = tx.query_row(
                "SELECT id FROM deposit_candidates WHERE txid = ?1 AND vout = ?2 AND block_hash = ?3",
                params![c.txid.as_slice(), c.vout, c.block_hash.as_slice()],
                |r| r.get(0),
            )?;
            tx.execute(
                "INSERT INTO deposit_state_log (deposit_id, from_state, to_state, at, reason, block_hash)
                 VALUES (?1, NULL, ?2, ?3, ?4, ?5)",
                params![
                    id,
                    c.initial_state.as_str(),
                    c.discovered_at,
                    c.failure_reason,
                    c.block_hash.as_slice()
                ],
            )?;
            ids.push(id);
        }
        tx.commit()?;
        Ok(ids)
    }

    /// Rolls back every indexed block and active deposit candidate above
    /// `fork_height` to `Orphaned`, transactionally, and records the event.
    pub fn rollback_reorg(
        &mut self,
        fork_height: i64,
        new_tip_height: i64,
        new_tip_hash: [u8; 32],
        old_tip_height: i64,
        old_tip_hash: [u8; 32],
        at: i64,
    ) -> Result<i64, DbError> {
        let tx = self.conn.transaction()?;

        let mut stmt = tx.prepare(
            "SELECT id, state, block_hash FROM deposit_candidates
             WHERE block_height > ?1 AND state IN ('Candidate','Confirming','ReadyForSignature','Submitted')",
        )?;
        let rows: Vec<(i64, String, Vec<u8>)> = stmt
            .query_map(params![fork_height], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<Result<_, _>>()?;
        drop(stmt);

        let orphaned_count = rows.len() as i64;
        for (id, from_state, block_hash) in &rows {
            tx.execute(
                "UPDATE deposit_candidates SET state = 'Orphaned' WHERE id = ?1",
                params![id],
            )?;
            tx.execute(
                "INSERT INTO deposit_state_log (deposit_id, from_state, to_state, at, reason, block_hash)
                 VALUES (?1, ?2, 'Orphaned', ?3, 'reorg_rollback', ?4)",
                params![id, from_state, at, block_hash],
            )?;
        }

        tx.execute(
            "DELETE FROM indexed_blocks WHERE height > ?1",
            params![fork_height],
        )?;
        tx.execute(
            "INSERT INTO chain_state (id, tip_height, tip_hash) VALUES (0, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET tip_height = excluded.tip_height, tip_hash = excluded.tip_hash",
            params![new_tip_height, new_tip_hash.as_slice()],
        )?;
        tx.execute(
            "INSERT INTO reorg_events
                (detected_at, fork_height, old_tip_height, old_tip_hash, new_tip_height, new_tip_hash, orphaned_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                at,
                fork_height,
                old_tip_height,
                old_tip_hash.as_slice(),
                new_tip_height,
                new_tip_hash.as_slice(),
                orphaned_count
            ],
        )?;

        tx.commit()?;
        Ok(orphaned_count)
    }

    /// Transitions one deposit's state, logging the transition, and — when
    /// promoting to `ReadyForSignature` — inserting its claim artifact in
    /// the same transaction (state change and artifact creation are
    /// atomic: never one without the other).
    pub fn transition_state(
        &mut self,
        deposit_id: i64,
        to_state: DepositState,
        at: i64,
        reason: Option<&str>,
        artifact: Option<&NewClaimArtifact>,
    ) -> Result<(), DbError> {
        let tx = self.conn.transaction()?;
        let (from_state, block_hash): (String, Vec<u8>) = tx.query_row(
            "SELECT state, block_hash FROM deposit_candidates WHERE id = ?1",
            params![deposit_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let ready_at_clause_val: Option<i64> = if to_state == DepositState::ReadyForSignature {
            Some(at)
        } else {
            None
        };
        tx.execute(
            "UPDATE deposit_candidates SET state = ?1, ready_at = COALESCE(?2, ready_at), failure_reason = COALESCE(?3, failure_reason)
             WHERE id = ?4",
            params![to_state.as_str(), ready_at_clause_val, reason, deposit_id],
        )?;
        tx.execute(
            "INSERT INTO deposit_state_log (deposit_id, from_state, to_state, at, reason, block_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![deposit_id, from_state, to_state.as_str(), at, reason, block_hash],
        )?;
        if let Some(a) = artifact {
            tx.execute(
                "INSERT INTO claim_artifacts
                    (deposit_id, canonical_message, message_hash, protocol_version,
                     validator_epoch, program_id, wrapped_mint, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    a.deposit_id,
                    a.canonical_message.as_slice(),
                    a.message_hash.as_slice(),
                    a.protocol_version,
                    a.validator_epoch.to_le_bytes().as_slice(),
                    a.program_id.as_slice(),
                    a.wrapped_mint.as_slice(),
                    a.created_at
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The reload-and-recompute signing safeguard (ADR-0012, owner
    /// requirement). Immediately before signing a claim — never earlier,
    /// never cached — this:
    ///
    /// 1. reloads the deposit's CURRENT `txid`/`vout`/`amount_atomic`/
    ///    `recipient` fresh from `deposit_candidates`;
    /// 2. reloads the FROZEN `claim_artifacts` commitment (the
    ///    `protocol_version`/`validator_epoch`/`program_id`/`wrapped_mint`
    ///    it was built under, plus the stored `canonical_message` and
    ///    `message_hash`);
    /// 3. verifies the commitment is internally self-consistent
    ///    (`sha256(stored canonical_message) == stored message_hash`) —
    ///    catches independent corruption of either stored field;
    /// 4. recomputes the canonical message from the live fields in (1) and
    ///    the frozen fields in (2), and verifies it is byte-identical to
    ///    the stored `canonical_message` — catches drift in any of the
    ///    eight fields the message embeds;
    ///
    /// all inside one SQLite transaction, so no writer can mutate the row
    /// between the reload and the moment its bytes are used to sign.
    ///
    /// On success, returns the message to sign — always the freshly
    /// recomputed bytes, never the stored blob read as-is. On any failure,
    /// the deposit transitions to the terminal `IntegrityHalted` state (NOT
    /// `Failed` — owner instruction: a state-machine-documented anomalous
    /// halt, distinct from routine rejections, audited via
    /// `deposit_state_log`) and no message is returned — the caller must
    /// not sign or submit anything.
    pub fn verify_and_load_signable_message(
        &mut self,
        deposit_id: i64,
        at: i64,
    ) -> Result<SignableClaim, DbError> {
        use sha2::{Digest, Sha256};

        let tx = self.conn.transaction()?;

        let (txid, vout, amount_bytes, recipient): (Vec<u8>, i64, Vec<u8>, Vec<u8>) = tx
            .query_row(
                "SELECT txid, vout, amount_atomic, recipient FROM deposit_candidates WHERE id = ?1",
                params![deposit_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .ok_or(DbError::MissingClaimArtifact(deposit_id))?;
        let txid = to_array32(&txid);
        let amount_atomic = u64::from_le_bytes(amount_bytes.try_into().unwrap());
        let recipient = to_array32(&recipient);

        #[allow(clippy::type_complexity)]
        let (stored_message, stored_hash, protocol_version, epoch_bytes, program_id, wrapped_mint): (
            Vec<u8>,
            Vec<u8>,
            u8,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        ) = tx
            .query_row(
                "SELECT canonical_message, message_hash, protocol_version, validator_epoch, program_id, wrapped_mint
                 FROM claim_artifacts WHERE deposit_id = ?1",
                params![deposit_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .optional()?
            .ok_or(DbError::MissingClaimArtifact(deposit_id))?;
        let validator_epoch = u64::from_le_bytes(epoch_bytes.try_into().unwrap());
        let program_id = to_array32(&program_id);
        let wrapped_mint = to_array32(&wrapped_mint);

        // Check 1: the frozen commitment must be internally self-consistent.
        let stored_message_actual_hash = Sha256::digest(&stored_message);
        let self_consistent = stored_message_actual_hash.as_slice() == stored_hash.as_slice();

        // Check 2: recomputing from the live/frozen fields must reproduce
        // exactly the stored commitment.
        let recomputed = super::deposit::build_claim_message(
            protocol_version,
            &program_id,
            validator_epoch,
            &txid,
            vout as u32,
            amount_atomic,
            &recipient,
            &wrapped_mint,
        );
        let recomputed_matches_stored = recomputed.as_slice() == stored_message.as_slice();

        if !self_consistent || !recomputed_matches_stored {
            let reason = if !self_consistent {
                "claim_artifact_self_inconsistent"
            } else {
                "claim_message_recomputed_mismatch"
            };
            // Forensic detail for the operator investigating this halt
            // (schema v3): the commitment that was expected, what was
            // actually recomputed from current persisted state, and which
            // field(s) drifted where attributable.
            let recomputed_hash: [u8; 32] = Sha256::digest(recomputed).into();
            let differing_fields = diff_claim_fields(recomputed.as_slice(), &stored_message);
            let (from_state, block_hash): (String, Vec<u8>) = tx.query_row(
                "SELECT state, block_hash FROM deposit_candidates WHERE id = ?1",
                params![deposit_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            tx.execute(
                "UPDATE deposit_candidates SET state = ?1, failure_reason = ?2 WHERE id = ?3",
                params![DepositState::IntegrityHalted.as_str(), reason, deposit_id],
            )?;
            tx.execute(
                "INSERT INTO deposit_state_log
                    (deposit_id, from_state, to_state, at, reason, block_hash,
                     expected_message_hash, recomputed_message_hash, differing_fields)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    deposit_id,
                    from_state,
                    DepositState::IntegrityHalted.as_str(),
                    at,
                    reason,
                    block_hash,
                    stored_hash.as_slice(),
                    recomputed_hash.as_slice(),
                    differing_fields,
                ],
            )?;
            tx.commit()?;
            return Err(DbError::MessageIntegrityMismatch {
                deposit_id,
                field: reason,
            });
        }

        tx.commit()?;
        Ok(SignableClaim {
            deposit_id,
            message: recomputed,
            txid,
            vout: vout as u32,
            amount_atomic,
            recipient,
            program_id,
            wrapped_mint,
            validator_epoch,
        })
    }

    /// **The only sanctioned exit from `IntegrityHalted`** (ADR-0012).
    ///
    /// Deliberately not reachable from any automatic path: nothing in the
    /// orchestrator, the indexer, or any tick loop calls this — it exists
    /// solely for an operator who has investigated the halt (using the
    /// `expected_message_hash`/`recomputed_message_hash`/`differing_fields`
    /// recorded in `deposit_state_log`) and has decided, deliberately, what
    /// the correct disposition is.
    ///
    /// `operator_note` is mandatory and non-empty: a recovery from a
    /// suspected-corruption halt must never be an anonymous state edit. The
    /// halt record itself is never deleted or rewritten — the audit trail is
    /// strictly append-only, so the original anomaly stays visible forever
    /// alongside the recovery.
    ///
    /// `to_state` is restricted to states that cannot themselves cause a
    /// mint on the operator's behalf: a deposit may be sent back to
    /// `ReadyForSignature` (re-verify and, if genuinely sound, proceed — the
    /// reload-and-recompute safeguard runs again from scratch and will halt
    /// it right back if the anomaly persists) or retired to `Failed`. It can
    /// never be moved directly to `Submitted` or `Minted` by hand.
    pub fn operator_clear_integrity_halt(
        &mut self,
        deposit_id: i64,
        to_state: DepositState,
        operator_note: &str,
        at: i64,
    ) -> Result<(), DbError> {
        if operator_note.trim().is_empty() {
            return Err(DbError::OperatorNoteRequired(deposit_id));
        }
        if !matches!(
            to_state,
            DepositState::ReadyForSignature | DepositState::Failed
        ) {
            return Err(DbError::InvalidIntegrityRecoveryTarget {
                deposit_id,
                to_state: to_state.as_str(),
            });
        }

        let tx = self.conn.transaction()?;
        let (from_state, block_hash): (String, Vec<u8>) = tx
            .query_row(
                "SELECT state, block_hash FROM deposit_candidates WHERE id = ?1",
                params![deposit_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(DbError::MissingClaimArtifact(deposit_id))?;
        // Only ever applicable to a genuinely halted deposit — this must not
        // become a general-purpose "force any state" backdoor.
        if from_state != DepositState::IntegrityHalted.as_str() {
            return Err(DbError::NotIntegrityHalted {
                deposit_id,
                found: from_state,
            });
        }
        tx.execute(
            "UPDATE deposit_candidates SET state = ?1, failure_reason = ?2 WHERE id = ?3",
            params![to_state.as_str(), operator_note, deposit_id],
        )?;
        tx.execute(
            "INSERT INTO deposit_state_log (deposit_id, from_state, to_state, at, reason, block_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                deposit_id,
                from_state,
                to_state.as_str(),
                at,
                format!("operator_recovery: {operator_note}"),
                block_hash
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Records that `deposit_id` was submitted under `signature`
    /// (`ReadyForSignature` -> `Submitted`). Audit-only column; the claim
    /// PDA's existence remains authoritative.
    pub fn mark_submitted(
        &mut self,
        deposit_id: i64,
        signature: &str,
        at: i64,
    ) -> Result<(), DbError> {
        let tx = self.conn.transaction()?;
        let (from_state, block_hash): (String, Vec<u8>) = tx.query_row(
            "SELECT state, block_hash FROM deposit_candidates WHERE id = ?1",
            params![deposit_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        tx.execute(
            "UPDATE deposit_candidates SET state = ?1, submitted_signature = ?2 WHERE id = ?3",
            params![DepositState::Submitted.as_str(), signature, deposit_id],
        )?;
        tx.execute(
            "INSERT INTO deposit_state_log (deposit_id, from_state, to_state, at, reason, block_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                deposit_id,
                from_state,
                DepositState::Submitted.as_str(),
                at,
                signature,
                block_hash
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Marks `deposit_id` `Minted` — called only once the on-chain claim
    /// PDA is observed to exist (ADR-0003: existence IS the record),
    /// regardless of which relayer instance actually submitted it.
    pub fn mark_minted(&mut self, deposit_id: i64, at: i64) -> Result<(), DbError> {
        self.transition_state(deposit_id, DepositState::Minted, at, None, None)
    }

    pub fn chain_tip(&self) -> Result<Option<(i64, [u8; 32])>, DbError> {
        let row: Option<(i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT tip_height, tip_hash FROM chain_state WHERE id = 0",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.map(|(h, hash)| (h, to_array32(&hash))))
    }

    pub fn block_hash_at_height(&self, height: i64) -> Result<Option<[u8; 32]>, DbError> {
        let row: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT hash FROM indexed_blocks WHERE height = ?1",
                params![height],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row.map(|h| to_array32(&h)))
    }

    pub fn candidates_by_state(&self, state: DepositState) -> Result<Vec<DepositRow>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, txid, txid_hex, vout, amount_atomic, recipient, block_height, block_hash,
                    raw_tx_hex, state, discovered_at, ready_at, failure_reason, submitted_signature
             FROM deposit_candidates WHERE state = ?1",
        )?;
        let rows = stmt
            .query_map(params![state.as_str()], row_to_deposit)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Every row for a given `(txid, vout)` across all block hashes it has
    /// ever appeared under. Used to enforce/verify the "at most one active
    /// row" application-level invariant (exercised by tests); reserved
    /// production surface for a future audit/reconciliation path.
    #[allow(dead_code)]
    pub fn history_for(&self, txid: &[u8; 32], vout: i64) -> Result<Vec<DepositRow>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, txid, txid_hex, vout, amount_atomic, recipient, block_height, block_hash,
                    raw_tx_hex, state, discovered_at, ready_at, failure_reason, submitted_signature
             FROM deposit_candidates WHERE txid = ?1 AND vout = ?2",
        )?;
        let rows = stmt
            .query_map(params![txid.as_slice(), vout], row_to_deposit)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Fetches one deposit row by id, freshly from disk — the reload half
    /// of the reload-and-recompute signing safeguard (ADR-0012).
    pub fn get_by_id(&self, deposit_id: i64) -> Result<Option<DepositRow>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, txid, txid_hex, vout, amount_atomic, recipient, block_height, block_hash,
                    raw_tx_hex, state, discovered_at, ready_at, failure_reason, submitted_signature
             FROM deposit_candidates WHERE id = ?1",
        )?;
        let row = stmt
            .query_map(params![deposit_id], row_to_deposit)?
            .next()
            .transpose()?;
        Ok(row)
    }

    /// Sum of `amount_atomic` for every deposit that reached
    /// `ReadyForSignature` (or later) at or after `since` (unix seconds) —
    /// the rolling-window value cap's live total.
    pub fn ready_amount_sum_since(&self, since: i64) -> Result<u64, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT amount_atomic FROM deposit_candidates
             WHERE ready_at IS NOT NULL AND ready_at >= ?1",
        )?;
        let rows: Vec<Vec<u8>> = stmt
            .query_map(params![since], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        Ok(rows
            .into_iter()
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .sum())
    }

    pub fn schema_version(&self) -> Result<i64, DbError> {
        Ok(self
            .conn
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| {
                r.get(0)
            })?)
    }

    /// Direct access for tests that need to assert on raw schema objects
    /// (indexes, constraints) or fabricate edge-case rows.
    #[cfg(test)]
    pub(crate) fn raw(&self) -> &Connection {
        &self.conn
    }
}

fn to_array32(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(v);
    out
}

fn row_to_deposit(r: &rusqlite::Row) -> rusqlite::Result<DepositRow> {
    let txid: Vec<u8> = r.get(1)?;
    let recipient: Vec<u8> = r.get(5)?;
    let block_hash: Vec<u8> = r.get(7)?;
    let amount_bytes: Vec<u8> = r.get(4)?;
    let state_str: String = r.get(9)?;
    Ok(DepositRow {
        id: r.get(0)?,
        txid: to_array32(&txid),
        txid_hex: r.get(2)?,
        vout: r.get(3)?,
        amount_atomic: u64::from_le_bytes(amount_bytes.try_into().unwrap()),
        recipient: to_array32(&recipient),
        block_height: r.get(6)?,
        block_hash: to_array32(&block_hash),
        raw_tx_hex: r.get(8)?,
        state: DepositState::parse(&state_str).unwrap_or(DepositState::Failed),
        discovered_at: r.get(10)?,
        ready_at: r.get(11)?,
        failure_reason: r.get(12)?,
        submitted_signature: r.get(13)?,
    })
}

fn apply_v1_schema(tx: &rusqlite::Transaction) -> Result<(), DbError> {
    tx.execute_batch(
        "
        CREATE TABLE indexed_blocks (
            height     INTEGER PRIMARY KEY,
            hash       BLOB NOT NULL UNIQUE,
            prev_hash  BLOB NOT NULL,
            block_time INTEGER NOT NULL,
            indexed_at INTEGER NOT NULL
        );

        CREATE TABLE chain_state (
            id         INTEGER PRIMARY KEY CHECK (id = 0),
            tip_height INTEGER NOT NULL,
            tip_hash   BLOB NOT NULL
        );

        -- txid (BLOB, canonical protocol bytes) and txid_hex (TEXT, lowercase
        -- 64-char RPC/display form) must always agree: enforced at the
        -- schema level via SQLite's built-in hex()/lower(), not just in
        -- application code (owner decision U2).
        CREATE TABLE deposit_candidates (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            txid           BLOB NOT NULL,
            txid_hex       TEXT NOT NULL,
            vout           INTEGER NOT NULL,
            amount_atomic  BLOB NOT NULL,
            recipient      BLOB NOT NULL,
            block_height   INTEGER NOT NULL,
            block_hash     BLOB NOT NULL,
            raw_tx_hex     TEXT NOT NULL,
            state          TEXT NOT NULL,
            discovered_at  INTEGER NOT NULL,
            ready_at       INTEGER,
            failure_reason TEXT,
            UNIQUE (txid, vout, block_hash),
            CHECK (length(txid) = 32),
            CHECK (length(txid_hex) = 64),
            CHECK (txid_hex = lower(hex(txid)))
        );

        CREATE INDEX idx_deposit_candidates_state ON deposit_candidates(state);
        CREATE INDEX idx_deposit_candidates_block_height ON deposit_candidates(block_height);
        CREATE INDEX idx_deposit_candidates_txid_hex ON deposit_candidates(txid_hex);
        CREATE INDEX idx_deposit_candidates_block_hash ON deposit_candidates(block_hash);

        CREATE TABLE deposit_state_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            deposit_id  INTEGER NOT NULL REFERENCES deposit_candidates(id),
            from_state  TEXT,
            to_state    TEXT NOT NULL,
            at          INTEGER NOT NULL,
            reason      TEXT,
            block_hash  BLOB
        );

        CREATE INDEX idx_deposit_state_log_deposit_id ON deposit_state_log(deposit_id);

        CREATE TABLE reorg_events (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at       INTEGER NOT NULL,
            fork_height       INTEGER NOT NULL,
            old_tip_height    INTEGER NOT NULL,
            old_tip_hash      BLOB NOT NULL,
            new_tip_height    INTEGER NOT NULL,
            new_tip_hash      BLOB NOT NULL,
            orphaned_count    INTEGER NOT NULL
        );

        -- Exactly the Phase 3 canonical message (glc_bridge_shared::claim);
        -- never signed or submitted in Phase 4.
        CREATE TABLE claim_artifacts (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            deposit_id        INTEGER NOT NULL REFERENCES deposit_candidates(id),
            canonical_message BLOB NOT NULL,
            message_hash      BLOB NOT NULL,
            protocol_version  INTEGER NOT NULL,
            validator_epoch   BLOB NOT NULL,
            program_id        BLOB NOT NULL,
            wrapped_mint      BLOB NOT NULL,
            created_at        INTEGER NOT NULL,
            UNIQUE (deposit_id),
            CHECK (length(canonical_message) = 166),
            CHECK (length(message_hash) = 32),
            CHECK (length(program_id) = 32),
            CHECK (length(wrapped_mint) = 32)
        );
        ",
    )?;
    Ok(())
}

/// v2 (Phase 5, ADR-0012): records the transaction signature a deposit was
/// last submitted under, for restart reconciliation and audit — the
/// authoritative "is it minted yet" signal remains the on-chain claim PDA's
/// existence, never this column alone.
fn apply_v2_schema(tx: &rusqlite::Transaction) -> Result<(), DbError> {
    tx.execute_batch("ALTER TABLE deposit_candidates ADD COLUMN submitted_signature TEXT;")?;
    Ok(())
}

/// v3 (Phase 5, ADR-0012): forensic detail for an `IntegrityHalted`
/// transition. A coarse `reason` string alone is not enough to investigate
/// suspected corruption or tampering — an operator needs to see exactly
/// which commitment was expected, what was actually recomputed, and which
/// field(s) drifted. Null for every ordinary (non-anomalous) transition.
fn apply_v3_schema(tx: &rusqlite::Transaction) -> Result<(), DbError> {
    tx.execute_batch(
        "
        ALTER TABLE deposit_state_log ADD COLUMN expected_message_hash BLOB;
        ALTER TABLE deposit_state_log ADD COLUMN recomputed_message_hash BLOB;
        ALTER TABLE deposit_state_log ADD COLUMN differing_fields TEXT;
        ",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mem_db() -> Db {
        Db::open(&PathBuf::from(":memory:")).unwrap()
    }

    fn sample_block(height: i64, hash_byte: u8, prev_byte: u8) -> NewBlock {
        NewBlock {
            height,
            hash: [hash_byte; 32],
            prev_hash: [prev_byte; 32],
            block_time: 1_000 + height,
            indexed_at: 2_000 + height,
        }
    }

    fn sample_candidate(
        txid_byte: u8,
        vout: i64,
        block_height: i64,
        block_hash_byte: u8,
    ) -> NewCandidate {
        NewCandidate {
            txid: [txid_byte; 32],
            vout,
            amount_atomic: 50_000,
            recipient: [0xAB; 32],
            block_height,
            block_hash: [block_hash_byte; 32],
            raw_tx_hex: "deadbeef".to_string(),
            discovered_at: 3_000,
            initial_state: DepositState::Candidate,
            failure_reason: None,
        }
    }

    /// Frozen fields a claim artifact is built under, for the
    /// reload-and-recompute tests below.
    struct ArtifactFields {
        protocol_version: u8,
        validator_epoch: u64,
        program_id: [u8; 32],
        wrapped_mint: [u8; 32],
    }

    fn sample_artifact_fields() -> ArtifactFields {
        ArtifactFields {
            protocol_version: 1,
            validator_epoch: 7,
            program_id: [0x11; 32],
            wrapped_mint: [0x22; 32],
        }
    }

    /// Ingests one deposit and promotes it all the way to `ReadyForSignature`
    /// with a genuinely self-consistent, correctly-derived claim artifact —
    /// the fixture every reload-and-recompute test starts from.
    fn ready_deposit_with_artifact(db: &mut Db) -> (i64, ArtifactFields) {
        let txid = [0xAA; 32];
        let ids = db
            .ingest_block(
                &sample_block(1, 0x11, 0x00),
                &[sample_candidate(0xAA, 0, 1, 0x11)],
            )
            .unwrap();
        let id = ids[0];
        let fields = sample_artifact_fields();
        let message = super::super::deposit::build_claim_message(
            fields.protocol_version,
            &fields.program_id,
            fields.validator_epoch,
            &txid,
            0,
            50_000,
            &[0xAB; 32],
            &fields.wrapped_mint,
        );
        let message_hash: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(message).into()
        };
        let artifact = NewClaimArtifact {
            deposit_id: id,
            canonical_message: message,
            message_hash,
            protocol_version: fields.protocol_version,
            validator_epoch: fields.validator_epoch,
            program_id: fields.program_id,
            wrapped_mint: fields.wrapped_mint,
            created_at: 500,
        };
        db.transition_state(id, DepositState::Confirming, 100, None, None)
            .unwrap();
        db.transition_state(
            id,
            DepositState::ReadyForSignature,
            500,
            None,
            Some(&artifact),
        )
        .unwrap();
        (id, fields)
    }

    #[test]
    fn migrates_v1_database_to_v2_adding_submitted_signature_column() {
        let conn = Connection::open(":memory:").unwrap();
        {
            let tx_conn = conn.unchecked_transaction().unwrap();
            tx_conn
                .execute_batch("CREATE TABLE schema_version (version INTEGER NOT NULL)")
                .unwrap();
            apply_v1_schema(&tx_conn).unwrap();
            tx_conn
                .execute("INSERT INTO schema_version (version) VALUES (1)", [])
                .unwrap();
            tx_conn.commit().unwrap();
        }
        // Confirm the column genuinely does not exist yet at v1.
        let has_column_v1: bool = conn
            .prepare("SELECT submitted_signature FROM deposit_candidates LIMIT 1")
            .is_ok();
        assert!(
            !has_column_v1,
            "v1 schema must not yet have submitted_signature"
        );

        let mut db = Db { conn };
        db.run_migrations().unwrap();
        assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
        db.raw()
            .prepare("SELECT submitted_signature FROM deposit_candidates LIMIT 1")
            .expect("v2 migration must add submitted_signature");
    }

    #[test]
    fn mark_submitted_then_mark_minted_transitions_correctly() {
        let mut db = mem_db();
        let (id, _fields) = ready_deposit_with_artifact(&mut db);

        db.mark_submitted(id, "5x1gnatur3", 600).unwrap();
        let row = db.get_by_id(id).unwrap().unwrap();
        assert_eq!(row.state, DepositState::Submitted);
        assert_eq!(row.submitted_signature.as_deref(), Some("5x1gnatur3"));

        db.mark_minted(id, 700).unwrap();
        let row = db.get_by_id(id).unwrap().unwrap();
        assert_eq!(row.state, DepositState::Minted);
        // The audit trail of how it got there is preserved.
        let log_count: i64 = db
            .raw()
            .query_row(
                "SELECT COUNT(*) FROM deposit_state_log WHERE deposit_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            log_count >= 4,
            "candidate/confirming/ready/submitted/minted all logged"
        );
    }

    #[test]
    fn verify_and_load_signable_message_succeeds_on_untouched_row() {
        let mut db = mem_db();
        let (id, fields) = ready_deposit_with_artifact(&mut db);
        let claim = db.verify_and_load_signable_message(id, 900).unwrap();
        assert_eq!(claim.deposit_id, id);
        assert_eq!(claim.txid, [0xAA; 32]);
        assert_eq!(claim.vout, 0);
        assert_eq!(claim.amount_atomic, 50_000);
        assert_eq!(claim.recipient, [0xAB; 32]);
        let expected = super::super::deposit::build_claim_message(
            fields.protocol_version,
            &fields.program_id,
            fields.validator_epoch,
            &[0xAA; 32],
            0,
            50_000,
            &[0xAB; 32],
            &fields.wrapped_mint,
        );
        assert_eq!(claim.message, expected);
        // Untouched: still ReadyForSignature, not halted.
        assert_eq!(
            db.get_by_id(id).unwrap().unwrap().state,
            DepositState::ReadyForSignature
        );
    }

    /// Every one of the ten fields the owner asked to be covered: mutating
    /// ANY of them after `ReadyForSignature` must be caught by the
    /// reload-and-recompute safeguard, transition the deposit to the
    /// dedicated `IntegrityHalted` anomaly state (never `Failed`), and
    /// leave no signature/message returned to the caller.
    mod mismatch_detection {
        use super::*;

        fn assert_halts(db: &mut Db, id: i64) {
            let err = db.verify_and_load_signable_message(id, 900).unwrap_err();
            assert!(
                matches!(err, DbError::MessageIntegrityMismatch { deposit_id, .. } if deposit_id == id)
            );
            let row = db.get_by_id(id).unwrap().unwrap();
            assert_eq!(
                row.state,
                DepositState::IntegrityHalted,
                "must halt to the dedicated anomaly state, never Failed"
            );
            assert!(
                row.failure_reason.is_some(),
                "the anomaly must be audited with a reason"
            );
            let logged: i64 = db
                .raw()
                .query_row(
                    "SELECT COUNT(*) FROM deposit_state_log WHERE deposit_id = ?1 AND to_state = 'IntegrityHalted'",
                    params![id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                logged, 1,
                "the transition must be recorded in the audit trail"
            );
        }

        #[test]
        fn txid_mutated() {
            let mut db = mem_db();
            let (id, _) = ready_deposit_with_artifact(&mut db);
            db.raw()
                .execute(
                    "UPDATE deposit_candidates SET txid = ?1, txid_hex = ?2 WHERE id = ?3",
                    params![[0xFFu8; 32].as_slice(), hex::encode(&[0xFFu8; 32]), id],
                )
                .unwrap();
            assert_halts(&mut db, id);
        }

        #[test]
        fn vout_mutated() {
            let mut db = mem_db();
            let (id, _) = ready_deposit_with_artifact(&mut db);
            db.raw()
                .execute(
                    "UPDATE deposit_candidates SET vout = 99 WHERE id = ?1",
                    params![id],
                )
                .unwrap();
            assert_halts(&mut db, id);
        }

        #[test]
        fn amount_atomic_mutated() {
            let mut db = mem_db();
            let (id, _) = ready_deposit_with_artifact(&mut db);
            db.raw()
                .execute(
                    "UPDATE deposit_candidates SET amount_atomic = ?1 WHERE id = ?2",
                    params![999_999u64.to_le_bytes().as_slice(), id],
                )
                .unwrap();
            assert_halts(&mut db, id);
        }

        #[test]
        fn recipient_mutated() {
            let mut db = mem_db();
            let (id, _) = ready_deposit_with_artifact(&mut db);
            db.raw()
                .execute(
                    "UPDATE deposit_candidates SET recipient = ?1 WHERE id = ?2",
                    params![[0x99u8; 32].as_slice(), id],
                )
                .unwrap();
            assert_halts(&mut db, id);
        }

        #[test]
        fn protocol_version_mutated() {
            let mut db = mem_db();
            let (id, _) = ready_deposit_with_artifact(&mut db);
            db.raw()
                .execute(
                    "UPDATE claim_artifacts SET protocol_version = 9 WHERE deposit_id = ?1",
                    params![id],
                )
                .unwrap();
            assert_halts(&mut db, id);
        }

        #[test]
        fn validator_epoch_mutated() {
            let mut db = mem_db();
            let (id, _) = ready_deposit_with_artifact(&mut db);
            db.raw()
                .execute(
                    "UPDATE claim_artifacts SET validator_epoch = ?1 WHERE deposit_id = ?2",
                    params![999u64.to_le_bytes().as_slice(), id],
                )
                .unwrap();
            assert_halts(&mut db, id);
        }

        #[test]
        fn program_id_mutated() {
            let mut db = mem_db();
            let (id, _) = ready_deposit_with_artifact(&mut db);
            db.raw()
                .execute(
                    "UPDATE claim_artifacts SET program_id = ?1 WHERE deposit_id = ?2",
                    params![[0x77u8; 32].as_slice(), id],
                )
                .unwrap();
            assert_halts(&mut db, id);
        }

        #[test]
        fn wrapped_mint_mutated() {
            let mut db = mem_db();
            let (id, _) = ready_deposit_with_artifact(&mut db);
            db.raw()
                .execute(
                    "UPDATE claim_artifacts SET wrapped_mint = ?1 WHERE deposit_id = ?2",
                    params![[0x66u8; 32].as_slice(), id],
                )
                .unwrap();
            assert_halts(&mut db, id);
        }

        #[test]
        fn stored_canonical_message_mutated() {
            let mut db = mem_db();
            let (id, _) = ready_deposit_with_artifact(&mut db);
            // Corrupt the stored message directly; message_hash still
            // reflects the ORIGINAL (now-absent) message, so the artifact
            // itself becomes internally inconsistent.
            db.raw()
                .execute(
                    "UPDATE claim_artifacts SET canonical_message = ?1 WHERE deposit_id = ?2",
                    params![[0x00u8; 166].as_slice(), id],
                )
                .unwrap();
            assert_halts(&mut db, id);
        }

        #[test]
        fn stored_message_hash_mutated() {
            let mut db = mem_db();
            let (id, _) = ready_deposit_with_artifact(&mut db);
            db.raw()
                .execute(
                    "UPDATE claim_artifacts SET message_hash = ?1 WHERE deposit_id = ?2",
                    params![[0xEEu8; 32].as_slice(), id],
                )
                .unwrap();
            assert_halts(&mut db, id);
        }
    }

    #[test]
    fn fresh_database_is_at_current_schema_version() {
        let db = mem_db();
        assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn reopening_is_idempotent_noop() {
        let mut db = mem_db();
        // Re-run migrations explicitly (simulates a process restart against
        // an already-migrated file-backed DB).
        db.run_migrations().unwrap();
        db.run_migrations().unwrap();
        assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn refuses_to_start_against_future_schema_version() {
        let db = mem_db();
        db.raw()
            .execute(
                "UPDATE schema_version SET version = ?1",
                params![CURRENT_SCHEMA_VERSION + 1],
            )
            .unwrap();
        drop(db);
        // A fresh Db::open against the same (in this test, a fresh
        // in-memory db can't be reopened, so validate the guard directly).
        let db2 = mem_db();
        db2.raw()
            .execute("UPDATE schema_version SET version = 999", [])
            .unwrap();
        let mut db2 = db2;
        let err = db2.run_migrations().unwrap_err();
        assert!(matches!(
            err,
            DbError::UnsupportedSchemaVersion {
                found: 999,
                supported: CURRENT_SCHEMA_VERSION
            }
        ));
    }

    #[test]
    fn txid_txid_hex_mismatch_is_rejected_by_schema_constraint() {
        let db = mem_db();
        let result = db.raw().execute(
            "INSERT INTO deposit_candidates
                (txid, txid_hex, vout, amount_atomic, recipient, block_height, block_hash,
                 raw_tx_hex, state, discovered_at, failure_reason)
             VALUES (?1, ?2, 0, ?3, ?4, 1, ?5, 'aa', 'Candidate', 0, NULL)",
            params![
                [0xAAu8; 32].as_slice(),
                "wrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwron", // 65 chars, deliberately wrong
                50_000u64.to_le_bytes().as_slice(),
                [0xBBu8; 32].as_slice(),
                [0xCCu8; 32].as_slice(),
            ],
        );
        assert!(
            result.is_err(),
            "mismatched/wrong-length txid_hex must violate the CHECK constraint"
        );
    }

    #[test]
    fn matching_txid_and_txid_hex_is_accepted() {
        let db = mem_db();
        let txid = [0xAAu8; 32];
        let txid_hex = hex::encode(&txid);
        db.raw()
            .execute(
                "INSERT INTO deposit_candidates
                    (txid, txid_hex, vout, amount_atomic, recipient, block_height, block_hash,
                     raw_tx_hex, state, discovered_at, failure_reason)
                 VALUES (?1, ?2, 0, ?3, ?4, 1, ?5, 'aa', 'Candidate', 0, NULL)",
                params![
                    txid.as_slice(),
                    txid_hex,
                    50_000u64.to_le_bytes().as_slice(),
                    [0xBBu8; 32].as_slice(),
                    [0xCCu8; 32].as_slice(),
                ],
            )
            .expect("matching txid/txid_hex must be accepted");
    }

    #[test]
    fn required_indexes_exist() {
        let db = mem_db();
        let mut stmt = db
            .raw()
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index'")
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for expected in [
            "idx_deposit_candidates_state",
            "idx_deposit_candidates_block_height",
            "idx_deposit_candidates_txid_hex",
            "idx_deposit_candidates_block_hash",
            "idx_deposit_state_log_deposit_id",
        ] {
            assert!(
                names.contains(&expected.to_string()),
                "missing index {expected}"
            );
        }
    }

    #[test]
    fn ingest_block_is_transactional_and_idempotent() {
        let mut db = mem_db();
        let block = sample_block(1, 0x11, 0x00);
        let candidates = vec![sample_candidate(0xAA, 0, 1, 0x11)];
        let ids1 = db.ingest_block(&block, &candidates).unwrap();
        assert_eq!(ids1.len(), 1);

        // Re-ingesting the identical block/candidate must be a no-op
        // (idempotent rescanning, e.g. after a resumed-from-stale-tip
        // restart) — same row, not a duplicate.
        let ids2 = db.ingest_block(&block, &candidates).unwrap();
        assert_eq!(ids2, ids1);

        let rows = db.candidates_by_state(DepositState::Candidate).unwrap();
        assert_eq!(rows.len(), 1);

        let (tip_h, tip_hash) = db.chain_tip().unwrap().unwrap();
        assert_eq!(tip_h, 1);
        assert_eq!(tip_hash, [0x11; 32]);
    }

    #[test]
    fn duplicate_candidate_same_block_does_not_duplicate() {
        let mut db = mem_db();
        let block = sample_block(1, 0x11, 0x00);
        let dup = sample_candidate(0xAA, 0, 1, 0x11);
        let dup2 = sample_candidate(0xAA, 0, 1, 0x11);
        db.ingest_block(&block, &[dup]).unwrap();
        db.ingest_block(&block, &[dup2]).unwrap();
        let rows = db.history_for(&[0xAA; 32], 0).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn same_deposit_reappearing_after_reorg_creates_fresh_row() {
        let mut db = mem_db();
        let block1 = sample_block(1, 0x11, 0x00);
        db.ingest_block(&block1, &[sample_candidate(0xAA, 0, 1, 0x11)])
            .unwrap();

        // Simulate reorg: block 1 rolled back.
        db.rollback_reorg(0, 0, [0x00; 32], 1, [0x11; 32], 9_999)
            .unwrap();
        let history = db.history_for(&[0xAA; 32], 0).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].state, DepositState::Orphaned);

        // Same (txid, vout) reappears at a NEW block_hash: independent row,
        // old Orphaned row untouched (UNIQUE is (txid, vout, block_hash)).
        let block1b = sample_block(1, 0x22, 0x00);
        db.ingest_block(&block1b, &[sample_candidate(0xAA, 0, 1, 0x22)])
            .unwrap();
        let history = db.history_for(&[0xAA; 32], 0).unwrap();
        assert_eq!(history.len(), 2);
        assert!(history.iter().any(|r| r.state == DepositState::Orphaned));
        assert!(history.iter().any(|r| r.state == DepositState::Candidate));
    }

    #[test]
    fn rollback_reorg_only_orphans_rows_above_fork_point() {
        let mut db = mem_db();
        db.ingest_block(
            &sample_block(1, 0x11, 0x00),
            &[sample_candidate(0xAA, 0, 1, 0x11)],
        )
        .unwrap();
        db.ingest_block(
            &sample_block(2, 0x22, 0x11),
            &[sample_candidate(0xBB, 0, 2, 0x22)],
        )
        .unwrap();
        db.ingest_block(
            &sample_block(3, 0x33, 0x22),
            &[sample_candidate(0xCC, 0, 3, 0x33)],
        )
        .unwrap();

        let orphaned = db
            .rollback_reorg(1, 1, [0x11; 32], 3, [0x33; 32], 5_000)
            .unwrap();
        assert_eq!(orphaned, 2, "only heights 2 and 3 should roll back");

        assert_eq!(
            db.history_for(&[0xAA; 32], 0).unwrap()[0].state,
            DepositState::Candidate,
            "height-1 deposit must be untouched"
        );
        assert_eq!(
            db.history_for(&[0xBB; 32], 0).unwrap()[0].state,
            DepositState::Orphaned
        );
        assert_eq!(
            db.history_for(&[0xCC; 32], 0).unwrap()[0].state,
            DepositState::Orphaned
        );
        assert_eq!(
            db.block_hash_at_height(2).unwrap(),
            None,
            "orphaned block rows are removed"
        );
        assert_eq!(db.block_hash_at_height(1).unwrap(), Some([0x11; 32]));
    }

    #[test]
    fn transition_state_logs_history_and_never_deletes_rows() {
        let mut db = mem_db();
        let ids = db
            .ingest_block(
                &sample_block(1, 0x11, 0x00),
                &[sample_candidate(0xAA, 0, 1, 0x11)],
            )
            .unwrap();
        let id = ids[0];

        db.transition_state(id, DepositState::Confirming, 100, None, None)
            .unwrap();
        db.transition_state(id, DepositState::ReadyForSignature, 200, None, None)
            .unwrap();

        let row = &db
            .candidates_by_state(DepositState::ReadyForSignature)
            .unwrap()[0];
        assert_eq!(row.id, id);
        assert_eq!(row.ready_at, Some(200));

        let log_count: i64 = db
            .raw()
            .query_row(
                "SELECT COUNT(*) FROM deposit_state_log WHERE deposit_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        // Initial Candidate insert + Confirming + ReadyForSignature.
        assert_eq!(log_count, 3);
    }

    #[test]
    fn transition_to_failed_records_reason() {
        let mut db = mem_db();
        let ids = db
            .ingest_block(
                &sample_block(1, 0x11, 0x00),
                &[sample_candidate(0xAA, 0, 1, 0x11)],
            )
            .unwrap();
        db.transition_state(
            ids[0],
            DepositState::Failed,
            100,
            Some("vault_output_spent"),
            None,
        )
        .unwrap();
        let row = &db.candidates_by_state(DepositState::Failed).unwrap()[0];
        assert_eq!(row.failure_reason.as_deref(), Some("vault_output_spent"));
    }

    #[test]
    fn below_minimum_deposit_recorded_as_failed_with_reason_not_dropped() {
        let mut db = mem_db();
        let mut candidate = sample_candidate(0xAA, 0, 1, 0x11);
        candidate.amount_atomic = 1;
        candidate.initial_state = DepositState::Failed;
        candidate.failure_reason = Some("below_min_deposit".to_string());
        db.ingest_block(&sample_block(1, 0x11, 0x00), &[candidate])
            .unwrap();
        let rows = db.candidates_by_state(DepositState::Failed).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].failure_reason.as_deref(), Some("below_min_deposit"));
        assert_eq!(
            rows[0].amount_atomic, 1,
            "the deposit is still recorded, not silently ignored"
        );
    }

    #[test]
    fn claim_artifact_is_created_atomically_with_ready_for_signature_transition() {
        let mut db = mem_db();
        let ids = db
            .ingest_block(
                &sample_block(1, 0x11, 0x00),
                &[sample_candidate(0xAA, 0, 1, 0x11)],
            )
            .unwrap();
        let id = ids[0];
        let artifact = NewClaimArtifact {
            deposit_id: id,
            canonical_message: [0x42; 166],
            message_hash: [0x99; 32],
            protocol_version: 1,
            validator_epoch: 7,
            program_id: [0x01; 32],
            wrapped_mint: [0x02; 32],
            created_at: 500,
        };
        db.transition_state(
            id,
            DepositState::ReadyForSignature,
            500,
            None,
            Some(&artifact),
        )
        .unwrap();

        let (msg, epoch_bytes): (Vec<u8>, Vec<u8>) = db
            .raw()
            .query_row(
                "SELECT canonical_message, validator_epoch FROM claim_artifacts WHERE deposit_id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(msg, vec![0x42u8; 166]);
        assert_eq!(u64::from_le_bytes(epoch_bytes.try_into().unwrap()), 7);
    }

    #[test]
    fn claim_artifact_unique_per_deposit() {
        let mut db = mem_db();
        let ids = db
            .ingest_block(
                &sample_block(1, 0x11, 0x00),
                &[sample_candidate(0xAA, 0, 1, 0x11)],
            )
            .unwrap();
        let id = ids[0];
        let artifact = |byte: u8| NewClaimArtifact {
            deposit_id: id,
            canonical_message: [byte; 166],
            message_hash: [byte; 32],
            protocol_version: 1,
            validator_epoch: 0,
            program_id: [0x01; 32],
            wrapped_mint: [0x02; 32],
            created_at: 500,
        };
        db.transition_state(
            id,
            DepositState::ReadyForSignature,
            500,
            None,
            Some(&artifact(1)),
        )
        .unwrap();
        let second_insert = db.raw().execute(
            "INSERT INTO claim_artifacts
                (deposit_id, canonical_message, message_hash, protocol_version,
                 validator_epoch, program_id, wrapped_mint, created_at)
             VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, 500)",
            params![
                id,
                [2u8; 166].as_slice(),
                [2u8; 32].as_slice(),
                0u64.to_le_bytes().as_slice(),
                [0x01u8; 32].as_slice(),
                [0x02u8; 32].as_slice(),
            ],
        );
        assert!(
            second_insert.is_err(),
            "UNIQUE(deposit_id) must reject a second artifact"
        );
    }

    #[test]
    fn wrong_length_canonical_message_rejected_by_check_constraint() {
        let db = mem_db();
        let result = db.raw().execute(
            "INSERT INTO claim_artifacts
                (deposit_id, canonical_message, message_hash, protocol_version,
                 validator_epoch, program_id, wrapped_mint, created_at)
             VALUES (1, ?1, ?2, 1, ?3, ?4, ?5, 0)",
            params![
                [0u8; 165].as_slice(), // one byte short of 166
                [0u8; 32].as_slice(),
                0u64.to_le_bytes().as_slice(),
                [0u8; 32].as_slice(),
                [0u8; 32].as_slice(),
            ],
        );
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------
    // IntegrityHalted forensics and operator recovery (ADR-0012)
    // -----------------------------------------------------------------

    /// Reads the single `IntegrityHalted` audit row for `deposit_id`.
    #[allow(clippy::type_complexity)]
    fn halt_audit_row(
        db: &Db,
        deposit_id: i64,
    ) -> (
        i64,
        i64,
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<String>,
    ) {
        db.raw()
            .query_row(
                "SELECT deposit_id, at, reason, expected_message_hash, recomputed_message_hash,
                        differing_fields
                 FROM deposit_state_log
                 WHERE deposit_id = ?1 AND to_state = 'IntegrityHalted'",
                params![deposit_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .unwrap()
    }

    #[test]
    fn diff_claim_fields_names_exactly_the_field_that_drifted() {
        let base = super::super::deposit::build_claim_message(
            1,
            &[0x11; 32],
            7,
            &[0xAA; 32],
            0,
            50_000,
            &[0xAB; 32],
            &[0x22; 32],
        );
        // One field at a time, across every field the message embeds.
        let amount_changed = super::super::deposit::build_claim_message(
            1,
            &[0x11; 32],
            7,
            &[0xAA; 32],
            0,
            50_001,
            &[0xAB; 32],
            &[0x22; 32],
        );
        assert_eq!(
            diff_claim_fields(&amount_changed, &base).as_deref(),
            Some("amount_atomic")
        );

        let epoch_changed = super::super::deposit::build_claim_message(
            1,
            &[0x11; 32],
            8,
            &[0xAA; 32],
            0,
            50_000,
            &[0xAB; 32],
            &[0x22; 32],
        );
        assert_eq!(
            diff_claim_fields(&epoch_changed, &base).as_deref(),
            Some("validator_epoch")
        );

        // Two fields at once are both named, in layout order.
        let two_changed = super::super::deposit::build_claim_message(
            1,
            &[0x11; 32],
            7,
            &[0xAA; 32],
            3,
            50_000,
            &[0xCD; 32],
            &[0x22; 32],
        );
        assert_eq!(
            diff_claim_fields(&two_changed, &base).as_deref(),
            Some("vout,recipient")
        );

        // Identical messages: nothing to report.
        assert_eq!(diff_claim_fields(&base, &base), None);
        // Not attributable: a truncated stored blob has no meaningful offsets.
        assert_eq!(diff_claim_fields(&base, &base[..100]), None);
    }

    #[test]
    fn halt_audit_records_deposit_id_timestamp_both_hashes_and_differing_field() {
        let mut db = mem_db();
        let (id, _) = ready_deposit_with_artifact(&mut db);
        let stored_hash: Vec<u8> = db
            .raw()
            .query_row(
                "SELECT message_hash FROM claim_artifacts WHERE deposit_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();

        // Drift exactly one field, out from under the artifact.
        db.raw()
            .execute(
                "UPDATE deposit_candidates SET amount_atomic = ?1 WHERE id = ?2",
                params![60_000u64.to_le_bytes().as_slice(), id],
            )
            .unwrap();
        db.verify_and_load_signable_message(id, 4_242).unwrap_err();

        let (logged_id, at, reason, expected, recomputed, differing) = halt_audit_row(&db, id);
        assert_eq!(logged_id, id, "audit records the deposit id");
        assert_eq!(at, 4_242, "audit records the timestamp it was detected at");
        assert_eq!(reason.as_deref(), Some("claim_message_recomputed_mismatch"));
        assert_eq!(
            expected.as_deref(),
            Some(stored_hash.as_slice()),
            "audit records the expected (stored commitment) message hash"
        );
        let recomputed = recomputed.expect("audit records the recomputed message hash");
        assert_eq!(recomputed.len(), 32);
        assert_ne!(
            recomputed, stored_hash,
            "the recomputed hash must genuinely differ from the expected one"
        );
        assert_eq!(
            differing.as_deref(),
            Some("amount_atomic"),
            "audit names the field that differed"
        );
    }

    #[test]
    fn self_inconsistent_artifact_records_hashes_even_though_no_field_is_attributable() {
        let mut db = mem_db();
        let (id, _) = ready_deposit_with_artifact(&mut db);
        // Corrupt the stored hash alone: the message still recomputes
        // correctly, so no FIELD drifted — only the commitment is broken.
        db.raw()
            .execute(
                "UPDATE claim_artifacts SET message_hash = ?1 WHERE deposit_id = ?2",
                params![[0x99u8; 32].as_slice(), id],
            )
            .unwrap();
        db.verify_and_load_signable_message(id, 77).unwrap_err();

        let (_, at, reason, expected, recomputed, differing) = halt_audit_row(&db, id);
        assert_eq!(at, 77);
        assert_eq!(reason.as_deref(), Some("claim_artifact_self_inconsistent"));
        assert_eq!(expected.as_deref(), Some([0x99u8; 32].as_slice()));
        assert!(recomputed.is_some(), "both hashes are always recorded");
        assert_eq!(
            differing, None,
            "no field drifted — the stored hash itself was corrupted, so attribution is absent"
        );
    }

    #[test]
    fn integrity_halted_deposit_is_never_returned_by_any_workable_state_query() {
        let mut db = mem_db();
        let (id, _) = ready_deposit_with_artifact(&mut db);
        db.raw()
            .execute(
                "UPDATE deposit_candidates SET vout = 42 WHERE id = ?1",
                params![id],
            )
            .unwrap();
        db.verify_and_load_signable_message(id, 100).unwrap_err();

        // The orchestrator only ever pulls these two states; a halted
        // deposit must appear in neither, on this or any later tick.
        assert!(db
            .candidates_by_state(DepositState::ReadyForSignature)
            .unwrap()
            .is_empty());
        assert!(db
            .candidates_by_state(DepositState::Submitted)
            .unwrap()
            .is_empty());
        assert_eq!(
            db.candidates_by_state(DepositState::IntegrityHalted)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn operator_recovery_is_the_only_exit_and_is_fully_audited() {
        let mut db = mem_db();
        let (id, _) = ready_deposit_with_artifact(&mut db);
        db.raw()
            .execute(
                "UPDATE deposit_candidates SET vout = 42 WHERE id = ?1",
                params![id],
            )
            .unwrap();
        db.verify_and_load_signable_message(id, 100).unwrap_err();
        assert_eq!(
            db.get_by_id(id).unwrap().unwrap().state,
            DepositState::IntegrityHalted
        );

        // An anonymous edit is refused.
        assert!(matches!(
            db.operator_clear_integrity_halt(id, DepositState::Failed, "   ", 200)
                .unwrap_err(),
            DbError::OperatorNoteRequired(d) if d == id
        ));
        // Jumping straight to a value-moving state is refused.
        assert!(matches!(
            db.operator_clear_integrity_halt(id, DepositState::Minted, "force it", 200)
                .unwrap_err(),
            DbError::InvalidIntegrityRecoveryTarget { deposit_id, .. } if deposit_id == id
        ));
        assert!(matches!(
            db.operator_clear_integrity_halt(id, DepositState::Submitted, "force it", 200)
                .unwrap_err(),
            DbError::InvalidIntegrityRecoveryTarget { deposit_id, .. } if deposit_id == id
        ));
        // Still halted after every refused attempt.
        assert_eq!(
            db.get_by_id(id).unwrap().unwrap().state,
            DepositState::IntegrityHalted
        );

        // The sanctioned path.
        db.operator_clear_integrity_halt(
            id,
            DepositState::Failed,
            "investigated: corrupted by disk fault, retiring deposit",
            300,
        )
        .unwrap();
        assert_eq!(
            db.get_by_id(id).unwrap().unwrap().state,
            DepositState::Failed
        );

        // The original halt record is still there — append-only audit.
        let halt_rows: i64 = db
            .raw()
            .query_row(
                "SELECT COUNT(*) FROM deposit_state_log
                 WHERE deposit_id = ?1 AND to_state = 'IntegrityHalted'",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(halt_rows, 1, "the anomaly record is never deleted");
        // ...and the recovery is itself recorded, attributed, and timestamped.
        let (from_state, at, reason): (String, i64, String) = db
            .raw()
            .query_row(
                "SELECT from_state, at, reason FROM deposit_state_log
                 WHERE deposit_id = ?1 AND from_state = 'IntegrityHalted'",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(from_state, "IntegrityHalted");
        assert_eq!(at, 300);
        assert!(reason.starts_with("operator_recovery: "));
        assert!(reason.contains("disk fault"));
    }

    #[test]
    fn operator_recovery_does_not_apply_to_a_deposit_that_is_not_halted() {
        let mut db = mem_db();
        let (id, _) = ready_deposit_with_artifact(&mut db);
        assert!(matches!(
            db.operator_clear_integrity_halt(id, DepositState::Failed, "note", 100)
                .unwrap_err(),
            DbError::NotIntegrityHalted { deposit_id, .. } if deposit_id == id
        ));
    }

    #[test]
    fn recovered_deposit_halts_again_if_the_underlying_anomaly_persists() {
        let mut db = mem_db();
        let (id, _) = ready_deposit_with_artifact(&mut db);
        db.raw()
            .execute(
                "UPDATE deposit_candidates SET vout = 42 WHERE id = ?1",
                params![id],
            )
            .unwrap();
        db.verify_and_load_signable_message(id, 100).unwrap_err();

        // Operator sends it back to ReadyForSignature WITHOUT fixing the
        // underlying drift — the safeguard must catch it all over again
        // rather than letting a signature through.
        db.operator_clear_integrity_halt(
            id,
            DepositState::ReadyForSignature,
            "believed spurious, retrying",
            200,
        )
        .unwrap();
        db.verify_and_load_signable_message(id, 300).unwrap_err();
        assert_eq!(
            db.get_by_id(id).unwrap().unwrap().state,
            DepositState::IntegrityHalted,
            "an unfixed anomaly must halt again, never sign"
        );
    }

    #[test]
    fn migrates_v2_database_to_v3_adding_the_forensic_audit_columns() {
        let conn = Connection::open(":memory:").unwrap();
        {
            let tx_conn = conn.unchecked_transaction().unwrap();
            tx_conn
                .execute_batch("CREATE TABLE schema_version (version INTEGER NOT NULL)")
                .unwrap();
            apply_v1_schema(&tx_conn).unwrap();
            apply_v2_schema(&tx_conn).unwrap();
            tx_conn
                .execute("INSERT INTO schema_version (version) VALUES (2)", [])
                .unwrap();
            tx_conn.commit().unwrap();
        }
        assert!(
            conn.prepare("SELECT differing_fields FROM deposit_state_log LIMIT 1")
                .is_err(),
            "v2 schema must not yet have the forensic columns"
        );

        let mut db = Db { conn };
        db.run_migrations().unwrap();
        assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
        for col in [
            "expected_message_hash",
            "recomputed_message_hash",
            "differing_fields",
        ] {
            db.raw()
                .prepare(&format!("SELECT {col} FROM deposit_state_log LIMIT 1"))
                .unwrap_or_else(|e| panic!("v3 must add {col}: {e}"));
        }
    }

    #[test]
    fn migrates_v1_database_all_the_way_to_v3_in_one_run() {
        let conn = Connection::open(":memory:").unwrap();
        {
            let tx_conn = conn.unchecked_transaction().unwrap();
            tx_conn
                .execute_batch("CREATE TABLE schema_version (version INTEGER NOT NULL)")
                .unwrap();
            apply_v1_schema(&tx_conn).unwrap();
            tx_conn
                .execute("INSERT INTO schema_version (version) VALUES (1)", [])
                .unwrap();
            tx_conn.commit().unwrap();
        }
        let mut db = Db { conn };
        db.run_migrations().unwrap();
        assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
        // Both the v2 and the v3 additions must be present.
        db.raw()
            .prepare("SELECT submitted_signature FROM deposit_candidates LIMIT 1")
            .unwrap();
        db.raw()
            .prepare("SELECT differing_fields FROM deposit_state_log LIMIT 1")
            .unwrap();
    }
}
