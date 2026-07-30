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
}

/// Current schema version this build understands. Bumping this must be
/// paired with a migration in [`MIGRATIONS`].
const CURRENT_SCHEMA_VERSION: i64 = 1;

/// The seven states named in the Phase 4 design (docs/reviews/phase4-design.md).
/// `Submitted`/`Minted` are written only from Phase 5 onward — Phase 4's own
/// indexer code never produces them (no Solana RPC exists yet, see
/// config.rs's module docs on owner decision U4) but the schema and
/// transition machinery support them now so Phase 5 needs no migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositState {
    Candidate,
    Confirming,
    ReadyForSignature,
    Orphaned,
    Submitted,
    Minted,
    Failed,
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
            other => Err(DbError::UnknownState(other.to_string())),
        }
    }

    /// States that are neither terminal history (`Orphaned`, `Failed`) nor
    /// fully complete (`Minted`) — i.e. still subject to reorg rollback and
    /// further progression. Reserved for Phase 5's reconciliation pass
    /// (topic 49); Phase 4's own tick loop queries by exact state instead.
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

pub struct Db {
    conn: Connection,
}

impl Db {
    /// Opens (creating if absent) the database at `path` and applies any
    /// pending migrations. `":memory:"` opens a private in-memory database
    /// (used by unit tests).
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
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

        match current {
            None => {
                apply_v1_schema(&tx)?;
                tx.execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    params![CURRENT_SCHEMA_VERSION],
                )?;
            }
            Some(v) if v == CURRENT_SCHEMA_VERSION => {
                // Nothing to do — idempotent no-op re-migration.
            }
            Some(v) if v < CURRENT_SCHEMA_VERSION => {
                // Future migrations would branch on `v` here, applying each
                // step in order up to CURRENT_SCHEMA_VERSION.
                unreachable!("no migrations defined above v1 yet");
            }
            Some(v) => {
                return Err(DbError::UnsupportedSchemaVersion {
                    found: v,
                    supported: CURRENT_SCHEMA_VERSION,
                });
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
                    raw_tx_hex, state, discovered_at, ready_at, failure_reason
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
                    raw_tx_hex, state, discovered_at, ready_at, failure_reason
             FROM deposit_candidates WHERE txid = ?1 AND vout = ?2",
        )?;
        let rows = stmt
            .query_map(params![txid.as_slice(), vout], row_to_deposit)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
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
}
