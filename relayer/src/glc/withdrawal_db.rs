//! Withdrawal-side persistence (Phase 6, ADR-0013).
//!
//! Lives beside [`super::db`] as a second `impl Db` block rather than inside
//! it: the deposit side is already ~1800 lines, and the two sides share only
//! the connection and the migration ladder.
//!
//! # The never-double-pay guarantees are structural, not procedural
//!
//! Two schema constraints do the heavy lifting, so no amount of application
//! bugs, restarts, or concurrent ticks can produce a second payment:
//!
//! - `withdrawal_payouts` is keyed by `withdrawal_index` — at most one payout
//!   row can ever exist per withdrawal;
//! - `withdrawal_payout_inputs` carries `UNIQUE (txid, vout)` — an outpoint
//!   can be committed to at most one payout, ever.
//!
//! Everything else (reservations, reconciliation) is an optimisation that
//! avoids wasted work; these two constraints are the actual boundary.

use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};

use super::db::{Db, DbError};
use super::hex;

/// v5 (Phase 7b, ADR-0015): the designated signing quorum and the vault the
/// payout is bound to.
///
/// `quorum_attempt` makes an explicit reassignment produce a different
/// commitment; `superseded_at` records that a previous attempt existed
/// rather than overwriting it, so reassignment is auditable.
pub(super) fn apply_v5_schema(tx: &rusqlite::Transaction) -> Result<(), DbError> {
    tx.execute_batch(
        "
        ALTER TABLE withdrawal_payouts ADD COLUMN vault_script_hash BLOB;
        ALTER TABLE withdrawal_payouts ADD COLUMN quorum_attempt INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE withdrawal_payouts ADD COLUMN quorum_indices BLOB;

        -- Append-only record of superseded quorum designations.
        CREATE TABLE withdrawal_quorum_history (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            withdrawal_index INTEGER NOT NULL
                             REFERENCES withdrawal_requests(withdrawal_index),
            quorum_attempt   INTEGER NOT NULL,
            quorum_indices   BLOB NOT NULL,
            commitment_hash  BLOB NOT NULL,
            superseded_at    INTEGER NOT NULL,
            reason           TEXT NOT NULL,
            UNIQUE (withdrawal_index, quorum_attempt)
        );
        CREATE INDEX idx_withdrawal_quorum_history_index
            ON withdrawal_quorum_history(withdrawal_index);
        ",
    )?;
    Ok(())
}

/// v4 (Phase 6, ADR-0013): the withdrawal executor's persistent state.
pub(super) fn apply_v4_schema(tx: &rusqlite::Transaction) -> Result<(), DbError> {
    tx.execute_batch(
        "
        CREATE TABLE withdrawal_requests (
            withdrawal_index    INTEGER PRIMARY KEY,
            pda                 BLOB NOT NULL,
            amount_atomic       BLOB NOT NULL,
            requester           BLOB NOT NULL,
            glc_address         TEXT NOT NULL,
            glc_address_hash160 BLOB NOT NULL,
            requested_at_slot   INTEGER NOT NULL,
            protocol_version    INTEGER NOT NULL,
            observed_at         INTEGER NOT NULL,
            observed_at_slot    INTEGER NOT NULL,
            state               TEXT NOT NULL,
            failure_reason      TEXT,
            UNIQUE (pda),
            CHECK (length(pda) = 32),
            CHECK (length(amount_atomic) = 8),
            CHECK (length(requester) = 32),
            CHECK (length(glc_address_hash160) = 20)
        );
        CREATE INDEX idx_withdrawal_requests_state ON withdrawal_requests(state);

        -- Primary key on withdrawal_index: at most ONE payout per withdrawal,
        -- enforced by the database rather than by application logic.
        CREATE TABLE withdrawal_payouts (
            withdrawal_index  INTEGER PRIMARY KEY
                              REFERENCES withdrawal_requests(withdrawal_index),
            commitment_hash   BLOB NOT NULL,
            intent_bytes      BLOB NOT NULL,
            fee_atomic        BLOB NOT NULL,
            payout_atomic     BLOB NOT NULL,
            change_atomic     BLOB NOT NULL,
            change_address    TEXT,
            unsigned_tx_hex   TEXT NOT NULL,
            signed_tx_hex     TEXT,
            txid              BLOB,
            txid_hex          TEXT,
            built_at          INTEGER NOT NULL,
            signed_at         INTEGER,
            broadcast_at      INTEGER,
            mined_block_hash  BLOB,
            mined_height      INTEGER,
            confirmations     INTEGER NOT NULL DEFAULT 0,
            completed_at      INTEGER,
            CHECK (length(commitment_hash) = 32),
            CHECK (txid IS NULL OR length(txid) = 32),
            CHECK (txid_hex IS NULL OR txid_hex = lower(hex(txid))),
            -- signed bytes and their txid are inseparable: it must be
            -- impossible to have broadcastable bytes without a durable txid
            -- to reconcile them by.
            CHECK ((signed_tx_hex IS NULL) = (txid IS NULL))
        );
        CREATE INDEX idx_withdrawal_payouts_txid_hex ON withdrawal_payouts(txid_hex);

        -- Reservation state lives here, NOT in the node: goldcoind's
        -- lockunspent locks are in-memory only and are lost on node restart
        -- (verified empirically, docs/goldcoin-rpc-notes.md).
        CREATE TABLE vault_utxos (
            txid              BLOB NOT NULL,
            vout              INTEGER NOT NULL,
            txid_hex          TEXT NOT NULL,
            amount_atomic     BLOB NOT NULL,
            script_pubkey_hex TEXT NOT NULL,
            confirmations     INTEGER NOT NULL,
            first_seen_at     INTEGER NOT NULL,
            state             TEXT NOT NULL,
            reserved_by       INTEGER REFERENCES withdrawal_requests(withdrawal_index),
            reserved_at       INTEGER,
            spent_by_txid_hex TEXT,
            PRIMARY KEY (txid, vout),
            CHECK (length(txid) = 32),
            CHECK (txid_hex = lower(hex(txid))),
            CHECK (state IN ('Available','Reserved','Spent','Unconfirmed')),
            CHECK ((state = 'Reserved') = (reserved_by IS NOT NULL))
        );
        CREATE INDEX idx_vault_utxos_state ON vault_utxos(state);
        CREATE INDEX idx_vault_utxos_reserved_by ON vault_utxos(reserved_by);

        -- UNIQUE(txid, vout): an outpoint may fund at most one payout, ever.
        CREATE TABLE withdrawal_payout_inputs (
            withdrawal_index INTEGER NOT NULL
                             REFERENCES withdrawal_payouts(withdrawal_index),
            input_order      INTEGER NOT NULL,
            txid             BLOB NOT NULL,
            vout             INTEGER NOT NULL,
            amount_atomic    BLOB NOT NULL,
            PRIMARY KEY (withdrawal_index, input_order),
            UNIQUE (txid, vout)
        );

        CREATE TABLE withdrawal_state_log (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            withdrawal_index      INTEGER NOT NULL
                                  REFERENCES withdrawal_requests(withdrawal_index),
            from_state            TEXT,
            to_state              TEXT NOT NULL,
            at                    INTEGER NOT NULL,
            reason                TEXT,
            expected_commitment   BLOB,
            recomputed_commitment BLOB,
            differing_fields      TEXT
        );
        CREATE INDEX idx_withdrawal_state_log_index
            ON withdrawal_state_log(withdrawal_index);
        ",
    )?;
    Ok(())
}

/// The withdrawal lifecycle (ADR-0013).
///
/// `Completed` is terminal *for Phase 6*, which tracks completion off-chain
/// only (owner decision D1). The transition table below is deliberately
/// data-driven so a future threshold-authorized on-chain completion
/// instruction can append states after `Completed` (e.g. a
/// `CompletionSubmitted`/`CompletionAcknowledged` pair) without any change
/// to the executor's control flow — only this table and the tick's match arm
/// would grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawalState {
    Observed,
    Validated,
    AwaitingFunds,
    Building,
    Signing,
    Broadcast,
    Confirming,
    Completed,
    /// Terminal anomaly state, reached only when a safeguard detects that
    /// persisted state no longer matches what was committed to, or that the
    /// vault inputs were spent by something other than our own payout.
    /// Never retried automatically (mirrors the deposit side's
    /// `IntegrityHalted`, ADR-0012).
    IntegrityHalted,
    Failed,
    Orphaned,
}

impl WithdrawalState {
    pub fn as_str(self) -> &'static str {
        match self {
            WithdrawalState::Observed => "Observed",
            WithdrawalState::Validated => "Validated",
            WithdrawalState::AwaitingFunds => "AwaitingFunds",
            WithdrawalState::Building => "Building",
            WithdrawalState::Signing => "Signing",
            WithdrawalState::Broadcast => "Broadcast",
            WithdrawalState::Confirming => "Confirming",
            WithdrawalState::Completed => "Completed",
            WithdrawalState::IntegrityHalted => "IntegrityHalted",
            WithdrawalState::Failed => "Failed",
            WithdrawalState::Orphaned => "Orphaned",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DbError> {
        Ok(match s {
            "Observed" => WithdrawalState::Observed,
            "Validated" => WithdrawalState::Validated,
            "AwaitingFunds" => WithdrawalState::AwaitingFunds,
            "Building" => WithdrawalState::Building,
            "Signing" => WithdrawalState::Signing,
            "Broadcast" => WithdrawalState::Broadcast,
            "Confirming" => WithdrawalState::Confirming,
            "Completed" => WithdrawalState::Completed,
            "IntegrityHalted" => WithdrawalState::IntegrityHalted,
            "Failed" => WithdrawalState::Failed,
            "Orphaned" => WithdrawalState::Orphaned,
            other => return Err(DbError::UnknownWithdrawalState(other.to_string())),
        })
    }

    /// Terminal for Phase 6. See the type's doc comment: extending past
    /// `Completed` later is an append to [`Self::may_transition_to`], not a
    /// redesign.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            WithdrawalState::Completed | WithdrawalState::Failed | WithdrawalState::IntegrityHalted
        )
    }

    /// The full legal-transition table (ADR-0013). Kept as data so illegal
    /// transitions are rejected uniformly instead of relying on each call
    /// site to be careful.
    pub fn may_transition_to(self, to: WithdrawalState) -> bool {
        use WithdrawalState::*;
        // Any non-terminal state may halt: an integrity anomaly can be
        // detected at any point in the pipeline.
        if to == IntegrityHalted {
            return !self.is_terminal();
        }
        matches!(
            (self, to),
            (Observed, Validated)
                | (Observed, Failed)
                | (Validated, AwaitingFunds)
                | (Validated, Building)
                | (Validated, Failed)
                | (AwaitingFunds, Validated)
                | (AwaitingFunds, Failed)
                | (Building, Signing)
                | (Building, AwaitingFunds)
                | (Building, Failed)
                | (Signing, Broadcast)
                | (Broadcast, Broadcast)
                | (Broadcast, Confirming)
                | (Broadcast, Orphaned)
                | (Confirming, Completed)
                | (Confirming, Confirming)
                | (Confirming, Orphaned)
                | (Confirming, Broadcast)
                | (Orphaned, Broadcast)
                // Operator recovery out of the halt state.
                | (IntegrityHalted, Validated)
                | (IntegrityHalted, Failed)
        )
    }
}

/// A newly observed on-chain `WithdrawalRequest`.
#[derive(Debug, Clone)]
pub struct NewWithdrawalRequest {
    pub withdrawal_index: i64,
    pub pda: [u8; 32],
    pub amount_atomic: u64,
    pub requester: [u8; 32],
    pub glc_address: String,
    pub glc_address_hash160: [u8; 20],
    pub requested_at_slot: i64,
    pub protocol_version: u8,
    pub observed_at: i64,
    pub observed_at_slot: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalRow {
    pub withdrawal_index: i64,
    pub pda: [u8; 32],
    pub amount_atomic: u64,
    pub requester: [u8; 32],
    pub glc_address: String,
    pub glc_address_hash160: [u8; 20],
    pub requested_at_slot: i64,
    pub protocol_version: u8,
    pub state: WithdrawalState,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultUtxo {
    pub txid: [u8; 32],
    pub txid_hex: String,
    pub vout: i64,
    pub amount_atomic: u64,
    pub script_pubkey_hex: String,
    pub confirmations: i64,
}

/// A vault output as reported by the node, before it is reconciled into
/// `vault_utxos`.
#[derive(Debug, Clone)]
pub struct ObservedUtxo {
    pub txid: [u8; 32],
    pub vout: i64,
    pub amount_atomic: u64,
    pub script_pubkey_hex: String,
    pub confirmations: i64,
}

/// The immutable payout intent, written once at `Building`.
#[derive(Debug, Clone)]
pub struct NewPayout {
    pub withdrawal_index: i64,
    /// The vault this payout spends from; binds the intent to one exact
    /// redeem script (ADR-0015).
    pub vault_script_hash: [u8; 20],
    /// Designated signers, as ascending indices into the vault's ordered
    /// signer list. Fixed before any signature is collected so the txid is
    /// deterministic in advance.
    pub quorum_indices: Vec<u8>,
    /// Increments on every explicit reassignment.
    pub quorum_attempt: u32,
    pub commitment_hash: [u8; 32],
    /// The canonical intent preimage the commitment covers. Stored so a
    /// mismatch can be attributed to specific field(s) and so the stored
    /// commitment can be checked for self-consistency — exactly what
    /// `claim_artifacts` does with `canonical_message`/`message_hash`.
    pub intent_bytes: Vec<u8>,
    pub fee_atomic: u64,
    pub payout_atomic: u64,
    pub change_atomic: u64,
    pub change_address: Option<String>,
    pub unsigned_tx_hex: String,
    pub inputs: Vec<VaultUtxo>,
    pub built_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutRow {
    pub withdrawal_index: i64,
    /// Designated signers and the reassignment counter (ADR-0015).
    pub quorum_indices: Vec<u8>,
    pub quorum_attempt: u32,
    pub commitment_hash: [u8; 32],
    pub fee_atomic: u64,
    pub payout_atomic: u64,
    pub change_atomic: u64,
    pub change_address: Option<String>,
    pub unsigned_tx_hex: String,
    pub signed_tx_hex: Option<String>,
    pub txid_hex: Option<String>,
    pub mined_block_hash: Option<[u8; 32]>,
    pub mined_height: Option<i64>,
    pub confirmations: i64,
    pub completed_at: Option<i64>,
}

/// Everything needed to sign, returned by
/// [`Db::verify_and_load_signable_payout`] — the output of the pre-signing
/// guard sequence. Constructed only from freshly reloaded rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignablePayout {
    pub withdrawal_index: i64,
    pub unsigned_tx_hex: String,
    pub payout_atomic: u64,
    pub fee_atomic: u64,
    pub change_atomic: u64,
    pub change_address: Option<String>,
    pub glc_address_hash160: [u8; 20],
    /// The vault this payout spends from.
    pub vault_script_hash: [u8; 20],
    /// The designated signers, ascending. Only these may contribute.
    pub quorum_indices: Vec<u8>,
    pub quorum_attempt: u32,
    pub inputs: Vec<VaultUtxo>,
    /// The freshly recomputed commitment — equal to the stored one, else
    /// this value would never have been returned.
    pub commitment_hash: [u8; 32],
    /// The freshly **recomputed** canonical intent, not the stored blob.
    ///
    /// These are the bytes a validator attests to when a peer asks it to
    /// authorize this payout (Phase 7d): handing back the recomputed
    /// preimage rather than the persisted one is what keeps the signer's
    /// answer derived from its own state.
    pub intent_bytes: Vec<u8>,
}

/// The canonical payout intent (ADR-0013, extended to v2 by ADR-0015).
///
/// Domain-separated and deterministic; this is the byte string the
/// commitment hashes.
///
/// Layout (all integers little-endian):
/// `b"GLC_BRIDGE_PAYOUT"`(17) ‖ protocol_version(1) ‖ withdrawal_index(8)
/// ‖ vault_script_hash(20) ‖ dest_hash160(20)
/// ‖ payout(8) ‖ fee(8) ‖ change(8) ‖ change_hash160(20)
/// ‖ quorum_attempt(4) ‖ quorum_count(1) ‖ quorum_indices(1 each)
/// ‖ input_count(4) ‖ [ txid(32) ‖ vout(4) ‖ amount(8) ]*
///
/// # Why the quorum is inside the commitment (ADR-0015 §2)
///
/// Verified on a real node: with M-of-N multisig, the same inputs and
/// outputs signed by *different quorums* produce *different txids* (signing
/// order is irrelevant; signing set is not). ADR-0013's recovery model
/// persists the txid **before** broadcasting, so the quorum must be fixed
/// before any signature is collected — otherwise the txid is unknowable in
/// advance and two overlapping quorums could each produce a valid, distinct
/// transaction spending the same inputs.
///
/// `vault_script_hash` pins the exact redeem script, which fixes the signer
/// list and its order, so a one-byte index per designated signer is
/// unambiguous. `quorum_attempt` makes an explicit reassignment produce a
/// different commitment, so signatures gathered for a superseded quorum can
/// never be replayed into its replacement.
pub const PAYOUT_DOMAIN_TAG: &[u8; 17] = b"GLC_BRIDGE_PAYOUT";

#[allow(clippy::too_many_arguments)]
pub fn canonical_payout_intent(
    protocol_version: u8,
    withdrawal_index: i64,
    vault_script_hash: &[u8; 20],
    dest_hash160: &[u8; 20],
    payout_atomic: u64,
    fee_atomic: u64,
    change_atomic: u64,
    change_hash160: &[u8; 20],
    quorum_attempt: u32,
    quorum_indices: &[u8],
    inputs: &[VaultUtxo],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        17 + 1 + 8 + 40 + 24 + 20 + 9 + quorum_indices.len() + inputs.len() * 44,
    );
    m.extend_from_slice(PAYOUT_DOMAIN_TAG);
    m.push(protocol_version);
    m.extend_from_slice(&withdrawal_index.to_le_bytes());
    m.extend_from_slice(vault_script_hash);
    m.extend_from_slice(dest_hash160);
    m.extend_from_slice(&payout_atomic.to_le_bytes());
    m.extend_from_slice(&fee_atomic.to_le_bytes());
    m.extend_from_slice(&change_atomic.to_le_bytes());
    m.extend_from_slice(change_hash160);
    m.extend_from_slice(&quorum_attempt.to_le_bytes());
    m.push(quorum_indices.len() as u8);
    m.extend_from_slice(quorum_indices);
    m.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
    for i in inputs {
        m.extend_from_slice(&i.txid);
        m.extend_from_slice(&(i.vout as u32).to_le_bytes());
        m.extend_from_slice(&i.amount_atomic.to_le_bytes());
    }
    m
}

pub fn payout_commitment(intent: &[u8]) -> [u8; 32] {
    Sha256::digest(intent).into()
}

/// Field layout of the canonical payout intent, used ONLY to attribute a
/// mismatch to specific field(s) in the audit record. Purely diagnostic —
/// nothing here can influence which bytes get signed.
const PAYOUT_FIELD_LAYOUT: &[(&str, usize, usize)] = &[
    ("domain_tag", 0, 17),
    ("protocol_version", 17, 18),
    ("withdrawal_index", 18, 26),
    ("vault_script_hash", 26, 46),
    ("dest_hash160", 46, 66),
    ("payout_atomic", 66, 74),
    ("fee_atomic", 74, 82),
    ("change_atomic", 82, 90),
    ("change_hash160", 90, 110),
    ("quorum_attempt", 110, 114),
];

/// Length of the fixed-size prefix of a canonical payout intent. Everything
/// after it (quorum indices, then inputs) is variable-length.
pub const PAYOUT_INTENT_FIXED_LEN: usize = 114;

/// Names the intent field(s) in which `recomputed` and `stored` differ.
/// Returns `Some("inputs")` when only the variable-length input list
/// differs, and `None` when attribution is impossible.
pub fn diff_payout_fields(recomputed: &[u8], stored: &[u8]) -> Option<String> {
    const FIXED: usize = PAYOUT_INTENT_FIXED_LEN;
    if recomputed.len() < FIXED || stored.len() < FIXED {
        return None;
    }
    let mut differing: Vec<&str> = PAYOUT_FIELD_LAYOUT
        .iter()
        .filter(|(_, a, b)| recomputed[*a..*b] != stored[*a..*b])
        .map(|(n, _, _)| *n)
        .collect();
    if recomputed[FIXED..] != stored[FIXED..] {
        // The tail carries the designated quorum then the input set; a
        // change in either is a different payout.
        differing.push("quorum_or_inputs");
    }
    if differing.is_empty() {
        None
    } else {
        Some(differing.join(","))
    }
}

fn to_array32(v: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(v);
    o
}

fn to_array20(v: &[u8]) -> [u8; 20] {
    let mut o = [0u8; 20];
    o.copy_from_slice(v);
    o
}

fn u64_from(v: &[u8]) -> u64 {
    let mut o = [0u8; 8];
    o.copy_from_slice(v);
    u64::from_le_bytes(o)
}

impl Db {
    /// Records a newly observed withdrawal. Idempotent: re-observing the
    /// same `withdrawal_index` is a no-op, so a restart that rescans the
    /// whole program-account set cannot duplicate or reset anything.
    pub fn observe_withdrawal(&mut self, w: &NewWithdrawalRequest) -> Result<bool, DbError> {
        let tx = self.conn.transaction()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO withdrawal_requests
                (withdrawal_index, pda, amount_atomic, requester, glc_address,
                 glc_address_hash160, requested_at_slot, protocol_version,
                 observed_at, observed_at_slot, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                w.withdrawal_index,
                w.pda.as_slice(),
                w.amount_atomic.to_le_bytes().as_slice(),
                w.requester.as_slice(),
                w.glc_address,
                w.glc_address_hash160.as_slice(),
                w.requested_at_slot,
                w.protocol_version,
                w.observed_at,
                w.observed_at_slot,
                WithdrawalState::Observed.as_str(),
            ],
        )? == 1;
        if inserted {
            tx.execute(
                "INSERT INTO withdrawal_state_log
                    (withdrawal_index, from_state, to_state, at, reason)
                 VALUES (?1, NULL, ?2, ?3, 'observed at finalized commitment')",
                params![
                    w.withdrawal_index,
                    WithdrawalState::Observed.as_str(),
                    w.observed_at
                ],
            )?;
        }
        tx.commit()?;
        Ok(inserted)
    }

    pub fn withdrawals_by_state(
        &self,
        state: WithdrawalState,
    ) -> Result<Vec<WithdrawalRow>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT withdrawal_index, pda, amount_atomic, requester, glc_address,
                    glc_address_hash160, requested_at_slot, protocol_version, state,
                    failure_reason
             FROM withdrawal_requests WHERE state = ?1 ORDER BY withdrawal_index",
        )?;
        let rows = stmt
            .query_map(params![state.as_str()], row_to_withdrawal)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_withdrawal(&self, index: i64) -> Result<Option<WithdrawalRow>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT withdrawal_index, pda, amount_atomic, requester, glc_address,
                    glc_address_hash160, requested_at_slot, protocol_version, state,
                    failure_reason
             FROM withdrawal_requests WHERE withdrawal_index = ?1",
        )?;
        let row = stmt
            .query_row(params![index], row_to_withdrawal)
            .optional()?;
        Ok(row)
    }

    /// Transitions a withdrawal, rejecting any transition the state machine
    /// does not define. Every transition is logged.
    pub fn transition_withdrawal(
        &mut self,
        index: i64,
        to: WithdrawalState,
        at: i64,
        reason: Option<&str>,
    ) -> Result<(), DbError> {
        let tx = self.conn.transaction()?;
        let from_str: String = tx
            .query_row(
                "SELECT state FROM withdrawal_requests WHERE withdrawal_index = ?1",
                params![index],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(DbError::WithdrawalNotFound(index))?;
        let from = WithdrawalState::parse(&from_str)?;
        if from != to && !from.may_transition_to(to) {
            return Err(DbError::UnknownWithdrawalState(format!(
                "illegal transition {} -> {}",
                from.as_str(),
                to.as_str()
            )));
        }
        tx.execute(
            "UPDATE withdrawal_requests
                SET state = ?1, failure_reason = COALESCE(?2, failure_reason)
              WHERE withdrawal_index = ?3",
            params![to.as_str(), reason, index],
        )?;
        tx.execute(
            "INSERT INTO withdrawal_state_log (withdrawal_index, from_state, to_state, at, reason)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![index, from_str, to.as_str(), at, reason],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Reconciles the node's reported vault UTXO set into `vault_utxos`.
    ///
    /// Never disturbs a `Reserved` row: once an outpoint is reserved it stays
    /// reserved until the reservation is explicitly released or the payout
    /// consumes it. Outpoints that vanish from the node's view are marked
    /// `Spent` so dependent withdrawals can detect it.
    pub fn sync_vault_utxos(
        &mut self,
        observed: &[ObservedUtxo],
        min_confirmations: i64,
        at: i64,
    ) -> Result<(), DbError> {
        let tx = self.conn.transaction()?;
        for u in observed {
            let txid_hex = hex::encode(&u.txid);
            let state = if u.confirmations >= min_confirmations {
                "Available"
            } else {
                "Unconfirmed"
            };
            // Only ever promote an untracked/unconfirmed outpoint. A
            // Reserved or Spent row is left exactly as it is.
            tx.execute(
                "INSERT INTO vault_utxos
                    (txid, vout, txid_hex, amount_atomic, script_pubkey_hex,
                     confirmations, first_seen_at, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(txid, vout) DO UPDATE SET
                    confirmations = excluded.confirmations,
                    state = CASE
                        WHEN vault_utxos.state IN ('Reserved','Spent') THEN vault_utxos.state
                        ELSE excluded.state
                    END",
                params![
                    u.txid.as_slice(),
                    u.vout,
                    txid_hex,
                    u.amount_atomic.to_le_bytes().as_slice(),
                    u.script_pubkey_hex,
                    u.confirmations,
                    at,
                    state
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Marks every tracked outpoint the node no longer reports as spendable
    /// as `Spent`, EXCEPT those already committed to a payout (whose inputs
    /// are legitimately absent from `listunspent` once broadcast).
    pub fn mark_missing_utxos_spent(&mut self, present: &[[u8; 32]]) -> Result<usize, DbError> {
        let tx = self.conn.transaction()?;
        let present_hex: Vec<String> = present.iter().map(|t| hex::encode(t)).collect();
        let mut stmt = tx.prepare(
            "SELECT txid_hex, vout FROM vault_utxos
             WHERE state IN ('Available','Unconfirmed')",
        )?;
        let tracked: Vec<(String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        let mut n = 0;
        for (txid_hex, vout) in tracked {
            if !present_hex.contains(&txid_hex) {
                tx.execute(
                    "UPDATE vault_utxos SET state = 'Spent' WHERE txid_hex = ?1 AND vout = ?2",
                    params![txid_hex, vout],
                )?;
                n += 1;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    /// Atomically reserves `outpoints` for `index`.
    ///
    /// Uses an immediate (write-locking) transaction plus a guarded update
    /// per row, so two concurrent reservers can never both succeed: the
    /// loser's `WHERE state='Available'` matches zero rows and the whole
    /// reservation rolls back.
    pub fn reserve_utxos(
        &mut self,
        index: i64,
        outpoints: &[VaultUtxo],
        at: i64,
    ) -> Result<(), DbError> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for u in outpoints {
            let n = tx.execute(
                "UPDATE vault_utxos
                    SET state = 'Reserved', reserved_by = ?1, reserved_at = ?2
                  WHERE txid = ?3 AND vout = ?4 AND state = 'Available'",
                params![index, at, u.txid.as_slice(), u.vout],
            )?;
            if n != 1 {
                return Err(DbError::ReservationInvalid {
                    withdrawal_index: index,
                    reason: "outpoint no longer Available at reservation time",
                });
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Releases a withdrawal's reservations. Refuses once a payout row
    /// exists: those inputs are committed to a specific txid forever.
    pub fn release_reservation(&mut self, index: i64) -> Result<usize, DbError> {
        let tx = self.conn.transaction()?;
        let has_payout: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM withdrawal_payouts WHERE withdrawal_index = ?1)",
            params![index],
            |r| r.get(0),
        )?;
        if has_payout {
            return Err(DbError::ReservationInvalid {
                withdrawal_index: index,
                reason: "a payout already commits these inputs; they are never released",
            });
        }
        let n = tx.execute(
            "UPDATE vault_utxos
                SET state = 'Available', reserved_by = NULL, reserved_at = NULL
              WHERE reserved_by = ?1 AND state = 'Reserved'",
            params![index],
        )?;
        tx.commit()?;
        Ok(n)
    }

    /// True when this withdrawal's oldest reservation predates `cutoff`.
    /// Used only to reclaim reservations that never reached a payout (D10).
    pub fn reservation_is_stale(&self, index: i64, cutoff: i64) -> Result<bool, DbError> {
        let stale: bool = self.conn.query_row(
            "SELECT COALESCE(MIN(reserved_at), 0) < ?1
             FROM vault_utxos WHERE reserved_by = ?2",
            params![cutoff, index],
            |r| r.get(0),
        )?;
        Ok(stale)
    }

    pub fn reserved_utxos(&self, index: i64) -> Result<Vec<VaultUtxo>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT txid, txid_hex, vout, amount_atomic, script_pubkey_hex, confirmations
             FROM vault_utxos WHERE reserved_by = ?1 AND state = 'Reserved'
             ORDER BY txid_hex, vout",
        )?;
        let rows = stmt
            .query_map(params![index], row_to_utxo)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Spendable outpoints, in deterministic coin-selection order.
    pub fn available_utxos(&self, min_confirmations: i64) -> Result<Vec<VaultUtxo>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT txid, txid_hex, vout, amount_atomic, script_pubkey_hex, confirmations
             FROM vault_utxos
             WHERE state = 'Available' AND confirmations >= ?1
             ORDER BY amount_atomic DESC, txid_hex ASC, vout ASC",
        )?;
        let rows = stmt
            .query_map(params![min_confirmations], row_to_utxo)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Writes the immutable payout intent and its inputs in one transaction.
    /// Both schema constraints (payout PK, input UNIQUE) fire here if
    /// anything would create a second payout or reuse an outpoint.
    pub fn create_payout(&mut self, p: &NewPayout) -> Result<(), DbError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO withdrawal_payouts
                (withdrawal_index, commitment_hash, intent_bytes, fee_atomic, payout_atomic,
                 change_atomic, change_address, unsigned_tx_hex, built_at,
                 vault_script_hash, quorum_attempt, quorum_indices)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                p.withdrawal_index,
                p.commitment_hash.as_slice(),
                p.intent_bytes.as_slice(),
                p.fee_atomic.to_le_bytes().as_slice(),
                p.payout_atomic.to_le_bytes().as_slice(),
                p.change_atomic.to_le_bytes().as_slice(),
                p.change_address,
                p.unsigned_tx_hex,
                p.built_at,
                p.vault_script_hash.as_slice(),
                p.quorum_attempt,
                p.quorum_indices.as_slice(),
            ],
        )?;
        for (i, u) in p.inputs.iter().enumerate() {
            tx.execute(
                "INSERT INTO withdrawal_payout_inputs
                    (withdrawal_index, input_order, txid, vout, amount_atomic)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    p.withdrawal_index,
                    i as i64,
                    u.txid.as_slice(),
                    u.vout,
                    u.amount_atomic.to_le_bytes().as_slice()
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_payout(&self, index: i64) -> Result<Option<PayoutRow>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT withdrawal_index, commitment_hash, fee_atomic, payout_atomic, change_atomic,
                    change_address, unsigned_tx_hex, signed_tx_hex, txid_hex, mined_block_hash,
                    mined_height, confirmations, completed_at, quorum_indices, quorum_attempt
             FROM withdrawal_payouts WHERE withdrawal_index = ?1",
        )?;
        let row = stmt.query_row(params![index], row_to_payout).optional()?;
        Ok(row)
    }

    pub fn payout_inputs(&self, index: i64) -> Result<Vec<VaultUtxo>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT i.txid, i.txid AS t2, i.vout, i.amount_atomic, COALESCE(v.script_pubkey_hex,''),
                    COALESCE(v.confirmations, 0)
             FROM withdrawal_payout_inputs i
             LEFT JOIN vault_utxos v ON v.txid = i.txid AND v.vout = i.vout
             WHERE i.withdrawal_index = ?1
             ORDER BY i.input_order",
        )?;
        let rows = stmt
            .query_map(params![index], |r| {
                let txid: Vec<u8> = r.get(0)?;
                let amount: Vec<u8> = r.get(3)?;
                Ok(VaultUtxo {
                    txid: to_array32(&txid),
                    txid_hex: hex::encode(&txid),
                    vout: r.get(2)?,
                    amount_atomic: u64_from(&amount),
                    script_pubkey_hex: r.get(4)?,
                    confirmations: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// **The pre-signing guard sequence (owner requirement, ADR-0013).**
    ///
    /// Run inside ONE transaction, immediately before signing, never earlier
    /// and never against cached state. In order, this:
    ///
    /// 1. reloads the live withdrawal row;
    /// 2. reloads the live payout row and its committed inputs;
    /// 3. verifies no completed payout already exists;
    /// 4. verifies no payout transaction has already been confirmed;
    /// 5. verifies every committed input still exists in `vault_utxos`;
    /// 6. verifies each of those inputs is still `Reserved` **by this
    ///    withdrawal** (not released, not stolen by another withdrawal, not
    ///    spent);
    /// 7. recomputes the canonical payout intent from the reloaded fields
    ///    and requires its hash to equal the stored commitment.
    ///
    /// On any failure the withdrawal transitions to `IntegrityHalted` with
    /// the expected/recomputed commitments and differing field(s) recorded,
    /// and NO signable material is returned.
    pub fn verify_and_load_signable_payout(
        &mut self,
        index: i64,
        at: i64,
    ) -> Result<SignablePayout, DbError> {
        let tx = self.conn.transaction()?;

        // (1) live withdrawal row
        let (state_str, amount_atomic, dest_hash160, protocol_version): (
            String,
            Vec<u8>,
            Vec<u8>,
            u8,
        ) = tx
            .query_row(
                "SELECT state, amount_atomic, glc_address_hash160, protocol_version
                 FROM withdrawal_requests WHERE withdrawal_index = ?1",
                params![index],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .ok_or(DbError::WithdrawalNotFound(index))?;
        let amount_atomic = u64_from(&amount_atomic);
        let dest_hash160 = to_array20(&dest_hash160);

        // (2) live payout row
        #[allow(clippy::type_complexity)]
        let (
            stored_commitment,
            fee_atomic,
            payout_atomic,
            change_atomic,
            change_address,
            unsigned_tx_hex,
            signed_tx_hex,
            confirmations,
            completed_at,
            stored_intent,
            stored_vault_hash,
            stored_quorum_attempt,
            stored_quorum,
        ): (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Option<String>,
            String,
            Option<String>,
            i64,
            Option<i64>,
            Vec<u8>,
            Vec<u8>,
            u32,
            Vec<u8>,
        ) = tx
            .query_row(
                "SELECT commitment_hash, fee_atomic, payout_atomic, change_atomic,
                        change_address, unsigned_tx_hex, signed_tx_hex, confirmations,
                        completed_at, intent_bytes, vault_script_hash, quorum_attempt,
                        quorum_indices
                 FROM withdrawal_payouts WHERE withdrawal_index = ?1",
                params![index],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                        r.get(10)?,
                        r.get(11)?,
                        r.get(12)?,
                    ))
                },
            )
            .optional()?
            .ok_or(DbError::MissingPayout(index))?;

        let halt = |tx: rusqlite::Transaction,
                    reason: &'static str,
                    expected: Option<&[u8]>,
                    recomputed: Option<&[u8]>,
                    diff: Option<String>|
         -> Result<(), DbError> {
            tx.execute(
                "UPDATE withdrawal_requests SET state = ?1, failure_reason = ?2
                  WHERE withdrawal_index = ?3",
                params![WithdrawalState::IntegrityHalted.as_str(), reason, index],
            )?;
            tx.execute(
                "INSERT INTO withdrawal_state_log
                    (withdrawal_index, from_state, to_state, at, reason,
                     expected_commitment, recomputed_commitment, differing_fields)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    index,
                    state_str,
                    WithdrawalState::IntegrityHalted.as_str(),
                    at,
                    reason,
                    expected,
                    recomputed,
                    diff
                ],
            )?;
            tx.commit()?;
            Ok(())
        };

        // (3) no completed payout already exists
        if completed_at.is_some() {
            halt(tx, "payout_already_completed", None, None, None)?;
            return Err(DbError::PayoutAlreadyCompleted(index));
        }

        // (4) no payout transaction already confirmed
        if confirmations > 0 {
            halt(tx, "payout_already_confirmed", None, None, None)?;
            return Err(DbError::PayoutAlreadyConfirmed(index));
        }

        // Signing twice over an already-signed payout is never correct: the
        // signed bytes and their txid are already durable.
        if signed_tx_hex.is_some() {
            halt(tx, "payout_already_signed", None, None, None)?;
            return Err(DbError::PayoutAlreadyConfirmed(index));
        }

        // (2b) committed inputs, in their committed order
        let mut stmt = tx.prepare(
            "SELECT txid, vout, amount_atomic FROM withdrawal_payout_inputs
             WHERE withdrawal_index = ?1 ORDER BY input_order",
        )?;
        let committed: Vec<([u8; 32], i64, u64)> = stmt
            .query_map(params![index], |r| {
                let t: Vec<u8> = r.get(0)?;
                let a: Vec<u8> = r.get(2)?;
                Ok((to_array32(&t), r.get(1)?, u64_from(&a)))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        if committed.is_empty() {
            halt(tx, "payout_has_no_committed_inputs", None, None, None)?;
            return Err(DbError::ReservationInvalid {
                withdrawal_index: index,
                reason: "payout has no committed inputs",
            });
        }

        // (5)+(6) every committed input must still exist AND still be
        // reserved by THIS withdrawal.
        let mut inputs = Vec::with_capacity(committed.len());
        for (txid, vout, amount) in &committed {
            #[allow(clippy::type_complexity)]
            let found: Option<(String, Option<i64>, Vec<u8>, String, i64)> = tx
                .query_row(
                    "SELECT state, reserved_by, amount_atomic, script_pubkey_hex, confirmations
                     FROM vault_utxos WHERE txid = ?1 AND vout = ?2",
                    params![txid.as_slice(), vout],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;

            let Some((u_state, reserved_by, u_amount, script, confs)) = found else {
                halt(tx, "reserved_utxo_no_longer_exists", None, None, None)?;
                return Err(DbError::ReservationInvalid {
                    withdrawal_index: index,
                    reason: "a committed input is no longer present in vault_utxos",
                });
            };
            if u_state != "Reserved" {
                halt(tx, "reserved_utxo_not_reserved", None, None, None)?;
                return Err(DbError::ReservationInvalid {
                    withdrawal_index: index,
                    reason: "a committed input is no longer in the Reserved state",
                });
            }
            if reserved_by != Some(index) {
                halt(
                    tx,
                    "reservation_belongs_to_another_withdrawal",
                    None,
                    None,
                    None,
                )?;
                return Err(DbError::ReservationInvalid {
                    withdrawal_index: index,
                    reason: "a committed input is reserved by a different withdrawal",
                });
            }
            if u64_from(&u_amount) != *amount {
                halt(tx, "reserved_utxo_amount_changed", None, None, None)?;
                return Err(DbError::ReservationInvalid {
                    withdrawal_index: index,
                    reason: "a committed input's amount changed after commitment",
                });
            }
            inputs.push(VaultUtxo {
                txid: *txid,
                txid_hex: hex::encode(txid),
                vout: *vout,
                amount_atomic: *amount,
                script_pubkey_hex: script,
                confirmations: confs,
            });
        }

        // (7) recompute the canonical intent from the reloaded fields and
        // compare against the stored commitment. The stored blob is never
        // signed as-is; only these recomputed bytes are trusted.
        let fee_atomic = u64_from(&fee_atomic);
        let payout_atomic = u64_from(&payout_atomic);
        let change_atomic = u64_from(&change_atomic);
        let change_hash160 = change_hash160_of(&tx, index)?;

        let recomputed_intent = canonical_payout_intent(
            protocol_version,
            index,
            &to_array20(&stored_vault_hash),
            &dest_hash160,
            payout_atomic,
            fee_atomic,
            change_atomic,
            &change_hash160,
            stored_quorum_attempt,
            &stored_quorum,
            &inputs,
        );
        let recomputed_hash = payout_commitment(&recomputed_intent);

        // (7a) the frozen commitment must be internally self-consistent:
        // sha256(stored intent) == stored commitment. Catches independent
        // corruption of either stored field.
        if payout_commitment(&stored_intent).as_slice() != stored_commitment.as_slice() {
            halt(
                tx,
                "payout_commitment_self_inconsistent",
                Some(&stored_commitment),
                Some(payout_commitment(&stored_intent).as_slice()),
                None,
            )?;
            return Err(DbError::PayoutIntegrityMismatch {
                withdrawal_index: index,
                field: "payout_commitment_self_inconsistent",
            });
        }

        // (7b) the intent recomputed from live state must be byte-identical
        // to the frozen one. Comparing against the stored PREIMAGE (not just
        // its hash) is what makes exact field attribution possible.
        if recomputed_intent != stored_intent {
            let diff = diff_payout_fields(&recomputed_intent, &stored_intent);
            halt(
                tx,
                "payout_commitment_mismatch",
                Some(&stored_commitment),
                Some(recomputed_hash.as_slice()),
                diff,
            )?;
            return Err(DbError::PayoutIntegrityMismatch {
                withdrawal_index: index,
                field: "payout_commitment_mismatch",
            });
        }

        // D3: the user receives exactly the burned amount; the vault absorbs
        // the fee. A payout that does not equal the on-chain amount is an
        // integrity failure, not a rounding detail.
        if payout_atomic != amount_atomic {
            halt(
                tx,
                "payout_amount_not_equal_to_burned_amount",
                None,
                None,
                None,
            )?;
            return Err(DbError::PayoutIntegrityMismatch {
                withdrawal_index: index,
                field: "payout_atomic",
            });
        }

        tx.commit()?;
        Ok(SignablePayout {
            withdrawal_index: index,
            unsigned_tx_hex,
            payout_atomic,
            fee_atomic,
            change_atomic,
            change_address,
            glc_address_hash160: dest_hash160,
            vault_script_hash: to_array20(&stored_vault_hash),
            quorum_indices: stored_quorum,
            quorum_attempt: stored_quorum_attempt,
            inputs,
            commitment_hash: to_array32(&stored_commitment),
            intent_bytes: recomputed_intent,
        })
    }

    /// Persists the signed bytes and their txid together, atomically, and
    /// advances to `Broadcast` — all BEFORE anything is sent to the network,
    /// so a lost broadcast response is always reconcilable by txid.
    pub fn record_signed_payout(
        &mut self,
        index: i64,
        signed_tx_hex: &str,
        txid: &[u8; 32],
        at: i64,
    ) -> Result<(), DbError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE withdrawal_payouts
                SET signed_tx_hex = ?1, txid = ?2, txid_hex = ?3, signed_at = ?4
              WHERE withdrawal_index = ?5 AND signed_tx_hex IS NULL",
            params![signed_tx_hex, txid.as_slice(), hex::encode(txid), at, index],
        )?;
        tx.execute(
            "UPDATE withdrawal_requests SET state = ?1 WHERE withdrawal_index = ?2",
            params![WithdrawalState::Broadcast.as_str(), index],
        )?;
        tx.execute(
            "INSERT INTO withdrawal_state_log (withdrawal_index, from_state, to_state, at, reason)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                index,
                WithdrawalState::Signing.as_str(),
                WithdrawalState::Broadcast.as_str(),
                at,
                format!("signed; txid {}", hex::encode(txid))
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_broadcast(&mut self, index: i64, at: i64) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE withdrawal_payouts SET broadcast_at = COALESCE(broadcast_at, ?1)
              WHERE withdrawal_index = ?2",
            params![at, index],
        )?;
        Ok(())
    }

    pub fn record_confirmations(
        &mut self,
        index: i64,
        confirmations: i64,
        mined_block_hash: Option<&[u8; 32]>,
        mined_height: Option<i64>,
    ) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE withdrawal_payouts
                SET confirmations = ?1,
                    mined_block_hash = COALESCE(?2, mined_block_hash),
                    mined_height = COALESCE(?3, mined_height)
              WHERE withdrawal_index = ?4",
            params![
                confirmations,
                mined_block_hash.map(|h| h.as_slice()),
                mined_height,
                index
            ],
        )?;
        Ok(())
    }

    /// Marks the payout complete and its inputs finally `Spent`.
    pub fn complete_payout(&mut self, index: i64, at: i64) -> Result<(), DbError> {
        let tx = self.conn.transaction()?;
        let txid_hex: Option<String> = tx.query_row(
            "SELECT txid_hex FROM withdrawal_payouts WHERE withdrawal_index = ?1",
            params![index],
            |r| r.get(0),
        )?;
        tx.execute(
            "UPDATE withdrawal_payouts SET completed_at = ?1 WHERE withdrawal_index = ?2",
            params![at, index],
        )?;
        tx.execute(
            "UPDATE vault_utxos
                SET state = 'Spent', spent_by_txid_hex = ?1, reserved_by = NULL, reserved_at = NULL
              WHERE reserved_by = ?2",
            params![txid_hex, index],
        )?;
        tx.execute(
            "UPDATE withdrawal_requests SET state = ?1 WHERE withdrawal_index = ?2",
            params![WithdrawalState::Completed.as_str(), index],
        )?;
        tx.execute(
            "INSERT INTO withdrawal_state_log (withdrawal_index, from_state, to_state, at, reason)
             VALUES (?1, ?2, ?3, ?4, 'payout confirmed at required depth')",
            params![
                index,
                WithdrawalState::Confirming.as_str(),
                WithdrawalState::Completed.as_str(),
                at
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Reassigns a payout's designated signing quorum (ADR-0015 §3).
    ///
    /// Explicit and auditable by construction: the superseded designation is
    /// appended to `withdrawal_quorum_history` rather than overwritten, and
    /// `quorum_attempt` increments so the new intent commits to different
    /// bytes. Signatures gathered for the old quorum therefore cannot be
    /// replayed into the new one.
    ///
    /// Refuses once the payout has been signed: at that point the txid is
    /// durable and reconciliation depends on it, so the correct response to
    /// a stuck signed payout is rebroadcast, never re-designation.
    #[allow(clippy::too_many_arguments)]
    pub fn reassign_payout_quorum(
        &mut self,
        index: i64,
        new_quorum: &[u8],
        new_commitment: &[u8; 32],
        new_intent: &[u8],
        new_unsigned_tx_hex: &str,
        reason: &str,
        at: i64,
    ) -> Result<u32, DbError> {
        if reason.trim().is_empty() {
            return Err(DbError::WithdrawalOperatorNoteRequired(index));
        }
        let tx = self.conn.transaction()?;
        let (signed, attempt, old_quorum, old_commitment): (Option<String>, u32, Vec<u8>, Vec<u8>) =
            tx.query_row(
                "SELECT signed_tx_hex, quorum_attempt, quorum_indices, commitment_hash
                 FROM withdrawal_payouts WHERE withdrawal_index = ?1",
                params![index],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .ok_or(DbError::MissingPayout(index))?;
        if signed.is_some() {
            return Err(DbError::ReservationInvalid {
                withdrawal_index: index,
                reason: "payout is already signed; its txid is durable and must be rebroadcast, not re-designated",
            });
        }
        let next = attempt.checked_add(1).ok_or(DbError::ReservationInvalid {
            withdrawal_index: index,
            reason: "quorum attempt counter overflow",
        })?;

        tx.execute(
            "INSERT INTO withdrawal_quorum_history
                (withdrawal_index, quorum_attempt, quorum_indices, commitment_hash,
                 superseded_at, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![index, attempt, old_quorum, old_commitment, at, reason],
        )?;
        tx.execute(
            "UPDATE withdrawal_payouts
                SET quorum_indices = ?1, quorum_attempt = ?2, commitment_hash = ?3,
                    intent_bytes = ?4, unsigned_tx_hex = ?5
              WHERE withdrawal_index = ?6",
            params![
                new_quorum,
                next,
                new_commitment.as_slice(),
                new_intent,
                new_unsigned_tx_hex,
                index
            ],
        )?;
        tx.execute(
            "INSERT INTO withdrawal_state_log (withdrawal_index, from_state, to_state, at, reason)
             VALUES (?1, ?2, ?2, ?3, ?4)",
            params![
                index,
                WithdrawalState::Signing.as_str(),
                at,
                format!("quorum reassigned to attempt {next}: {reason}")
            ],
        )?;
        tx.commit()?;
        Ok(next)
    }

    /// Every superseded quorum designation, oldest first.
    pub fn quorum_history(&self, index: i64) -> Result<Vec<(u32, Vec<u8>, String)>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT quorum_attempt, quorum_indices, reason FROM withdrawal_quorum_history
             WHERE withdrawal_index = ?1 ORDER BY quorum_attempt",
        )?;
        let rows = stmt
            .query_map(params![index], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// **The only sanctioned exit from a withdrawal `IntegrityHalted`.**
    ///
    /// Called from no automatic path. Requires a non-empty operator note,
    /// applies only to a genuinely halted withdrawal, and restricts targets
    /// to `Validated`/`Failed` — never directly to a state that implies a
    /// payment happened. The halt record is never deleted; the recovery is
    /// appended alongside it.
    pub fn operator_clear_withdrawal_halt(
        &mut self,
        index: i64,
        to: WithdrawalState,
        operator_note: &str,
        at: i64,
    ) -> Result<(), DbError> {
        if operator_note.trim().is_empty() {
            return Err(DbError::WithdrawalOperatorNoteRequired(index));
        }
        if !matches!(to, WithdrawalState::Validated | WithdrawalState::Failed) {
            return Err(DbError::InvalidWithdrawalRecoveryTarget {
                withdrawal_index: index,
                to_state: to.as_str(),
            });
        }
        let tx = self.conn.transaction()?;
        let from_str: String = tx
            .query_row(
                "SELECT state FROM withdrawal_requests WHERE withdrawal_index = ?1",
                params![index],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(DbError::WithdrawalNotFound(index))?;
        if from_str != WithdrawalState::IntegrityHalted.as_str() {
            return Err(DbError::NotWithdrawalIntegrityHalted {
                withdrawal_index: index,
                found: from_str,
            });
        }
        tx.execute(
            "UPDATE withdrawal_requests SET state = ?1, failure_reason = ?2
              WHERE withdrawal_index = ?3",
            params![to.as_str(), operator_note, index],
        )?;
        tx.execute(
            "INSERT INTO withdrawal_state_log (withdrawal_index, from_state, to_state, at, reason)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                index,
                from_str,
                to.as_str(),
                at,
                format!("operator_recovery: {operator_note}")
            ],
        )?;
        tx.commit()?;
        Ok(())
    }
}

/// The change address's hash160, or all-zeroes when there is no change
/// output. Reads from the payout row so the recomputation in
/// `verify_and_load_signable_payout` uses persisted state only.
///
/// Version-agnostic: change returns to the vault, which is P2SH from Phase
/// 7b (ADR-0015), so decoding it as P2PKH would fail. An undecodable stored
/// address is an integrity failure and is surfaced as one — an earlier
/// version silently substituted zeroes here, which turned a real
/// misconfiguration into an unexplained commitment mismatch.
fn change_hash160_of(tx: &rusqlite::Transaction, index: i64) -> Result<[u8; 20], DbError> {
    let addr: Option<String> = tx.query_row(
        "SELECT change_address FROM withdrawal_payouts WHERE withdrawal_index = ?1",
        params![index],
        |r| r.get(0),
    )?;
    match addr {
        None => Ok([0u8; 20]),
        Some(a) => crate::withdrawal::address::base58check_decode(&a)
            .map(|(_version, h)| h)
            .map_err(|_| DbError::PayoutIntegrityMismatch {
                withdrawal_index: index,
                field: "change_address_undecodable",
            }),
    }
}

fn row_to_withdrawal(r: &rusqlite::Row) -> rusqlite::Result<WithdrawalRow> {
    let pda: Vec<u8> = r.get(1)?;
    let amount: Vec<u8> = r.get(2)?;
    let requester: Vec<u8> = r.get(3)?;
    let h160: Vec<u8> = r.get(5)?;
    let state: String = r.get(8)?;
    Ok(WithdrawalRow {
        withdrawal_index: r.get(0)?,
        pda: to_array32(&pda),
        amount_atomic: u64_from(&amount),
        requester: to_array32(&requester),
        glc_address: r.get(4)?,
        glc_address_hash160: to_array20(&h160),
        requested_at_slot: r.get(6)?,
        protocol_version: r.get(7)?,
        state: WithdrawalState::parse(&state).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                8,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(format!("bad state {state}"))),
            )
        })?,
        failure_reason: r.get(9)?,
    })
}

fn row_to_utxo(r: &rusqlite::Row) -> rusqlite::Result<VaultUtxo> {
    let txid: Vec<u8> = r.get(0)?;
    let amount: Vec<u8> = r.get(3)?;
    Ok(VaultUtxo {
        txid: to_array32(&txid),
        txid_hex: r.get(1)?,
        vout: r.get(2)?,
        amount_atomic: u64_from(&amount),
        script_pubkey_hex: r.get(4)?,
        confirmations: r.get(5)?,
    })
}

fn row_to_payout(r: &rusqlite::Row) -> rusqlite::Result<PayoutRow> {
    let commitment: Vec<u8> = r.get(1)?;
    let fee: Vec<u8> = r.get(2)?;
    let payout: Vec<u8> = r.get(3)?;
    let change: Vec<u8> = r.get(4)?;
    let mined: Option<Vec<u8>> = r.get(9)?;
    Ok(PayoutRow {
        withdrawal_index: r.get(0)?,
        quorum_indices: r.get::<_, Option<Vec<u8>>>(13)?.unwrap_or_default(),
        quorum_attempt: r.get(14)?,
        commitment_hash: to_array32(&commitment),
        fee_atomic: u64_from(&fee),
        payout_atomic: u64_from(&payout),
        change_atomic: u64_from(&change),
        change_address: r.get(5)?,
        unsigned_tx_hex: r.get(6)?,
        signed_tx_hex: r.get(7)?,
        txid_hex: r.get(8)?,
        mined_block_hash: mined.map(|h| to_array32(&h)),
        mined_height: r.get(10)?,
        confirmations: r.get(11)?,
        completed_at: r.get(12)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::withdrawal::address::encode_p2pkh;

    const DEST: [u8; 20] = [0xAA; 20];
    const CHANGE: [u8; 20] = [0xBB; 20];
    const VAULT_HASH: [u8; 20] = [0xCC; 20];
    /// A 2-of-3 vault's designated quorum, ascending (ADR-0015).
    const QUORUM: &[u8] = &[0, 2];

    fn mem_db() -> Db {
        Db::open(std::path::Path::new(":memory:")).unwrap()
    }

    fn utxo(seed: u8, vout: i64, amount: u64) -> VaultUtxo {
        let txid = [seed; 32];
        VaultUtxo {
            txid,
            txid_hex: hex::encode(&txid),
            vout,
            amount_atomic: amount,
            script_pubkey_hex: crate::withdrawal::address::p2pkh_script_hex(&CHANGE),
            confirmations: 10,
        }
    }

    fn observed(u: &VaultUtxo) -> ObservedUtxo {
        ObservedUtxo {
            txid: u.txid,
            vout: u.vout,
            amount_atomic: u.amount_atomic,
            script_pubkey_hex: u.script_pubkey_hex.clone(),
            confirmations: u.confirmations,
        }
    }

    fn new_withdrawal(index: i64, amount: u64) -> NewWithdrawalRequest {
        NewWithdrawalRequest {
            withdrawal_index: index,
            pda: [index as u8; 32],
            amount_atomic: amount,
            requester: [0x11; 32],
            glc_address: encode_p2pkh(&DEST),
            glc_address_hash160: DEST,
            requested_at_slot: 100,
            protocol_version: 1,
            observed_at: 1_000,
            observed_at_slot: 100,
        }
    }

    /// A withdrawal advanced to `Signing` with a genuine, self-consistent
    /// payout: the fixture every guard test starts from.
    fn ready_to_sign(db: &mut Db, index: i64, amount: u64) -> (Vec<VaultUtxo>, [u8; 32]) {
        db.observe_withdrawal(&new_withdrawal(index, amount))
            .unwrap();
        let inputs = vec![utxo(index as u8 + 50, 0, amount + 100_000)];
        let obs: Vec<ObservedUtxo> = inputs.iter().map(observed).collect();
        db.sync_vault_utxos(&obs, 1, 1_000).unwrap();
        db.reserve_utxos(index, &inputs, 1_000).unwrap();

        let fee = 20_000u64;
        let change = inputs[0].amount_atomic - amount - fee;
        let intent = canonical_payout_intent(
            1,
            index,
            &VAULT_HASH,
            &DEST,
            amount,
            fee,
            change,
            &CHANGE,
            0,
            QUORUM,
            &inputs,
        );
        let commitment = payout_commitment(&intent);
        db.create_payout(&NewPayout {
            withdrawal_index: index,
            vault_script_hash: VAULT_HASH,
            quorum_indices: QUORUM.to_vec(),
            quorum_attempt: 0,
            commitment_hash: commitment,
            intent_bytes: intent.clone(),
            fee_atomic: fee,
            payout_atomic: amount,
            change_atomic: change,
            change_address: Some(encode_p2pkh(&CHANGE)),
            unsigned_tx_hex: "0100000001deadbeef".to_string(),
            inputs: inputs.clone(),
            built_at: 1_100,
        })
        .unwrap();
        db.transition_withdrawal(index, WithdrawalState::Validated, 1_010, None)
            .unwrap();
        db.transition_withdrawal(index, WithdrawalState::Building, 1_020, None)
            .unwrap();
        db.transition_withdrawal(index, WithdrawalState::Signing, 1_030, None)
            .unwrap();
        (inputs, commitment)
    }

    fn assert_halted(db: &Db, index: i64, expect_reason_contains: &str) {
        let w = db.get_withdrawal(index).unwrap().unwrap();
        assert_eq!(
            w.state,
            WithdrawalState::IntegrityHalted,
            "must halt to the dedicated anomaly state, never proceed"
        );
        let reason = w.failure_reason.unwrap_or_default();
        assert!(
            reason.contains(expect_reason_contains),
            "reason {reason:?} should mention {expect_reason_contains:?}"
        );
        let logged: i64 = db
            .raw()
            .query_row(
                "SELECT COUNT(*) FROM withdrawal_state_log
                 WHERE withdrawal_index = ?1 AND to_state = 'IntegrityHalted'",
                params![index],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(logged, 1, "the anomaly must be audited exactly once");
    }

    #[test]
    fn schema_is_at_v5_and_withdrawal_tables_exist() {
        let db = mem_db();
        assert_eq!(db.schema_version().unwrap(), 5);
        for t in [
            "withdrawal_requests",
            "withdrawal_payouts",
            "vault_utxos",
            "withdrawal_payout_inputs",
            "withdrawal_state_log",
            "withdrawal_quorum_history",
        ] {
            db.raw()
                .prepare(&format!("SELECT * FROM {t} LIMIT 1"))
                .unwrap_or_else(|e| panic!("table {t} missing: {e}"));
        }
    }

    #[test]
    fn observing_the_same_withdrawal_twice_is_idempotent() {
        let mut db = mem_db();
        assert!(db.observe_withdrawal(&new_withdrawal(1, 500)).unwrap());
        assert!(!db.observe_withdrawal(&new_withdrawal(1, 500)).unwrap());
        assert_eq!(
            db.withdrawals_by_state(WithdrawalState::Observed)
                .unwrap()
                .len(),
            1
        );
        let logs: i64 = db
            .raw()
            .query_row("SELECT COUNT(*) FROM withdrawal_state_log", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            logs, 1,
            "a re-observation must not append a duplicate log row"
        );
    }

    #[test]
    fn illegal_state_transitions_are_rejected() {
        let mut db = mem_db();
        db.observe_withdrawal(&new_withdrawal(1, 500)).unwrap();
        // Observed -> Broadcast skips the entire pipeline.
        assert!(db
            .transition_withdrawal(1, WithdrawalState::Broadcast, 10, None)
            .is_err());
        // Observed -> Completed would claim a payment that never happened.
        assert!(db
            .transition_withdrawal(1, WithdrawalState::Completed, 10, None)
            .is_err());
        assert_eq!(
            db.get_withdrawal(1).unwrap().unwrap().state,
            WithdrawalState::Observed
        );
    }

    #[test]
    fn terminal_states_are_terminal() {
        use WithdrawalState::*;
        for t in [Completed, Failed, IntegrityHalted] {
            assert!(t.is_terminal());
            for to in [Validated, Building, Signing, Broadcast, Confirming] {
                if t == IntegrityHalted && to == Validated {
                    continue; // operator recovery
                }
                assert!(!t.may_transition_to(to), "{t:?} -> {to:?} must be illegal");
            }
        }
        assert!(!Completed.may_transition_to(IntegrityHalted));
    }

    #[test]
    fn a_second_payout_for_one_withdrawal_is_structurally_impossible() {
        let mut db = mem_db();
        let (inputs, commitment) = ready_to_sign(&mut db, 1, 500_000);
        let dup = NewPayout {
            withdrawal_index: 1,
            vault_script_hash: VAULT_HASH,
            quorum_indices: QUORUM.to_vec(),
            quorum_attempt: 0,
            commitment_hash: commitment,
            intent_bytes: vec![0u8; 114],
            fee_atomic: 1,
            payout_atomic: 1,
            change_atomic: 0,
            change_address: None,
            unsigned_tx_hex: "ff".into(),
            inputs,
            built_at: 2_000,
        };
        assert!(
            db.create_payout(&dup).is_err(),
            "payout PK must reject a second payout"
        );
    }

    #[test]
    fn an_outpoint_can_fund_at_most_one_payout_ever() {
        let mut db = mem_db();
        let (inputs, _) = ready_to_sign(&mut db, 1, 500_000);
        // A different withdrawal trying to commit the SAME outpoint.
        db.observe_withdrawal(&new_withdrawal(2, 100)).unwrap();
        let p = NewPayout {
            withdrawal_index: 2,
            vault_script_hash: VAULT_HASH,
            quorum_indices: QUORUM.to_vec(),
            quorum_attempt: 0,
            commitment_hash: [7u8; 32],
            intent_bytes: vec![0u8; 114],
            fee_atomic: 1,
            payout_atomic: 100,
            change_atomic: 0,
            change_address: None,
            unsigned_tx_hex: "ff".into(),
            inputs,
            built_at: 2_000,
        };
        assert!(
            db.create_payout(&p).is_err(),
            "UNIQUE(txid,vout) must reject reusing a committed outpoint"
        );
    }

    #[test]
    fn reservation_is_exclusive_and_a_loser_cannot_steal_it() {
        let mut db = mem_db();
        db.observe_withdrawal(&new_withdrawal(1, 100)).unwrap();
        db.observe_withdrawal(&new_withdrawal(2, 100)).unwrap();
        let u = vec![utxo(9, 0, 1_000_000)];
        db.sync_vault_utxos(&u.iter().map(observed).collect::<Vec<_>>(), 1, 10)
            .unwrap();
        db.reserve_utxos(1, &u, 100).unwrap();
        assert!(db.reserve_utxos(2, &u, 100).is_err(), "already reserved");
        assert_eq!(db.reserved_utxos(1).unwrap().len(), 1);
        assert_eq!(db.reserved_utxos(2).unwrap().len(), 0);
        assert!(
            db.available_utxos(1).unwrap().is_empty(),
            "reserved is not available"
        );
    }

    #[test]
    fn reservations_are_never_released_once_a_payout_commits_them() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        assert!(
            db.release_reservation(1).is_err(),
            "inputs committed to a payout are frozen forever"
        );
        assert_eq!(db.reserved_utxos(1).unwrap().len(), 1);
    }

    #[test]
    fn sync_never_disturbs_a_reserved_utxo() {
        let mut db = mem_db();
        db.observe_withdrawal(&new_withdrawal(1, 100)).unwrap();
        let u = vec![utxo(9, 0, 1_000_000)];
        let obs: Vec<ObservedUtxo> = u.iter().map(observed).collect();
        db.sync_vault_utxos(&obs, 1, 10).unwrap();
        db.reserve_utxos(1, &u, 100).unwrap();
        db.sync_vault_utxos(&obs, 1, 20).unwrap(); // a later tick re-syncs
        assert_eq!(db.reserved_utxos(1).unwrap().len(), 1, "still reserved");
    }

    // ---------------------------------------------------------------
    // The pre-signing guard sequence (owner requirement)
    // ---------------------------------------------------------------

    #[test]
    fn guards_pass_on_a_genuinely_untouched_payout() {
        let mut db = mem_db();
        let (inputs, commitment) = ready_to_sign(&mut db, 1, 500_000);
        let s = db.verify_and_load_signable_payout(1, 2_000).unwrap();
        assert_eq!(s.withdrawal_index, 1);
        assert_eq!(
            s.payout_atomic, 500_000,
            "user receives exactly the burned amount (D3)"
        );
        assert_eq!(s.commitment_hash, commitment);
        assert_eq!(s.inputs, inputs);
        assert_eq!(
            db.get_withdrawal(1).unwrap().unwrap().state,
            WithdrawalState::Signing,
            "a passing guard run must not change state"
        );
    }

    #[test]
    fn guard_refuses_when_a_completed_payout_already_exists() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw()
            .execute(
                "UPDATE withdrawal_payouts SET completed_at = 999 WHERE withdrawal_index = 1",
                [],
            )
            .unwrap();
        assert!(matches!(
            db.verify_and_load_signable_payout(1, 2_000).unwrap_err(),
            DbError::PayoutAlreadyCompleted(1)
        ));
        assert_halted(&db, 1, "already_completed");
    }

    #[test]
    fn guard_refuses_when_a_payout_transaction_is_already_confirmed() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw()
            .execute(
                "UPDATE withdrawal_payouts SET confirmations = 3 WHERE withdrawal_index = 1",
                [],
            )
            .unwrap();
        assert!(matches!(
            db.verify_and_load_signable_payout(1, 2_000).unwrap_err(),
            DbError::PayoutAlreadyConfirmed(1)
        ));
        assert_halted(&db, 1, "already_confirmed");
    }

    #[test]
    fn guard_refuses_to_sign_an_already_signed_payout() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.record_signed_payout(1, "0100signed", &[0xEE; 32], 1_500)
            .unwrap();
        assert!(db.verify_and_load_signable_payout(1, 2_000).is_err());
        assert_halted(&db, 1, "already_signed");
    }

    #[test]
    fn guard_refuses_when_a_reserved_utxo_no_longer_exists() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw().execute("DELETE FROM vault_utxos", []).unwrap();
        assert!(matches!(
            db.verify_and_load_signable_payout(1, 2_000).unwrap_err(),
            DbError::ReservationInvalid { .. }
        ));
        assert_halted(&db, 1, "no_longer_exists");
    }

    #[test]
    fn guard_refuses_when_a_reserved_utxo_is_no_longer_reserved() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw()
            .execute(
                "UPDATE vault_utxos SET state='Spent', reserved_by=NULL WHERE reserved_by=1",
                [],
            )
            .unwrap();
        assert!(matches!(
            db.verify_and_load_signable_payout(1, 2_000).unwrap_err(),
            DbError::ReservationInvalid { .. }
        ));
        assert_halted(&db, 1, "not_reserved");
    }

    #[test]
    fn guard_refuses_when_the_reservation_belongs_to_another_withdrawal() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.observe_withdrawal(&new_withdrawal(2, 100)).unwrap();
        db.raw()
            .execute(
                "UPDATE vault_utxos SET reserved_by = 2 WHERE reserved_by = 1",
                [],
            )
            .unwrap();
        assert!(matches!(
            db.verify_and_load_signable_payout(1, 2_000).unwrap_err(),
            DbError::ReservationInvalid { .. }
        ));
        assert_halted(&db, 1, "another_withdrawal");
    }

    #[test]
    fn guard_refuses_when_a_reserved_utxo_amount_changed_under_us() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw()
            .execute(
                "UPDATE vault_utxos SET amount_atomic = ?1 WHERE reserved_by = 1",
                params![7_777_777u64.to_le_bytes().as_slice()],
            )
            .unwrap();
        assert!(matches!(
            db.verify_and_load_signable_payout(1, 2_000).unwrap_err(),
            DbError::ReservationInvalid { .. }
        ));
        assert_halted(&db, 1, "amount_changed");
    }

    /// Mutating ANY field the canonical intent commits to must be caught by
    /// the recomputation, with the offending field named in the audit trail.
    #[test]
    fn guard_detects_mutation_of_every_committed_field() {
        struct Case {
            name: &'static str,
            sql: &'static str,
            expect_field: &'static str,
        }
        let cases = [
            Case {
                name: "amount",
                sql: "UPDATE withdrawal_requests SET amount_atomic = x'0100000000000000' WHERE withdrawal_index = 1",
                expect_field: "payout_atomic",
            },
            Case {
                name: "destination",
                sql: "UPDATE withdrawal_requests SET glc_address_hash160 = x'00000000000000000000000000000000000000FF' WHERE withdrawal_index = 1",
                expect_field: "dest_hash160",
            },
            Case {
                name: "protocol_version",
                sql: "UPDATE withdrawal_requests SET protocol_version = 9 WHERE withdrawal_index = 1",
                expect_field: "protocol_version",
            },
            Case {
                name: "fee",
                sql: "UPDATE withdrawal_payouts SET fee_atomic = x'FF00000000000000' WHERE withdrawal_index = 1",
                expect_field: "fee_atomic",
            },
            Case {
                name: "change",
                sql: "UPDATE withdrawal_payouts SET change_atomic = x'FF00000000000000' WHERE withdrawal_index = 1",
                expect_field: "change_atomic",
            },
        ];
        for c in cases {
            let mut db = mem_db();
            ready_to_sign(&mut db, 1, 500_000);
            db.raw().execute(c.sql, []).unwrap();
            let err = db.verify_and_load_signable_payout(1, 2_000).unwrap_err();
            assert!(
                matches!(err, DbError::PayoutIntegrityMismatch { .. }),
                "{}: expected integrity mismatch, got {err:?}",
                c.name
            );
            let w = db.get_withdrawal(1).unwrap().unwrap();
            assert_eq!(w.state, WithdrawalState::IntegrityHalted, "{}", c.name);

            let (expected, recomputed, diff): (Option<Vec<u8>>, Option<Vec<u8>>, Option<String>) =
                db.raw()
                    .query_row(
                        "SELECT expected_commitment, recomputed_commitment, differing_fields
                     FROM withdrawal_state_log
                     WHERE withdrawal_index = 1 AND to_state = 'IntegrityHalted'",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .unwrap();
            // The amount case is caught by the D3 equality check, which
            // records no commitments; every other case records both.
            if c.name != "amount" {
                assert!(
                    expected.is_some(),
                    "{}: expected commitment recorded",
                    c.name
                );
                assert!(
                    recomputed.is_some(),
                    "{}: recomputed commitment recorded",
                    c.name
                );
                assert_ne!(expected, recomputed, "{}", c.name);
                let d = diff.unwrap_or_default();
                assert!(
                    d.contains(c.expect_field),
                    "{}: differing_fields {d:?} should name {}",
                    c.name,
                    c.expect_field
                );
            }
        }
    }

    #[test]
    fn guard_detects_a_self_inconsistent_stored_commitment() {
        // Corrupt the stored hash alone: the intent preimage still
        // recomputes correctly, so ONLY the commitment is broken.
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw()
            .execute(
                "UPDATE withdrawal_payouts SET commitment_hash = ?1 WHERE withdrawal_index = 1",
                params![[0x99u8; 32].as_slice()],
            )
            .unwrap();
        assert!(matches!(
            db.verify_and_load_signable_payout(1, 2_000).unwrap_err(),
            DbError::PayoutIntegrityMismatch { .. }
        ));
        assert_halted(&db, 1, "self_inconsistent");
    }

    #[test]
    fn guard_detects_a_tampered_intent_preimage() {
        // Corrupt the preimage alone: its hash no longer matches the stored
        // commitment, which the self-consistency check catches first.
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw()
            .execute(
                "UPDATE withdrawal_payouts SET intent_bytes = ?1 WHERE withdrawal_index = 1",
                params![vec![0u8; 138].as_slice()],
            )
            .unwrap();
        assert!(db.verify_and_load_signable_payout(1, 2_000).is_err());
        assert_halted(&db, 1, "self_inconsistent");
    }

    #[test]
    fn guard_detects_mutation_of_the_committed_input_set() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw()
            .execute(
                "UPDATE withdrawal_payout_inputs SET amount_atomic = ?1 WHERE withdrawal_index = 1",
                params![1u64.to_le_bytes().as_slice()],
            )
            .unwrap();
        // The committed amount no longer matches the live UTXO amount.
        assert!(db.verify_and_load_signable_payout(1, 2_000).is_err());
        assert_halted(&db, 1, "amount_changed");
    }

    #[test]
    fn guard_refuses_a_payout_with_no_committed_inputs() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw()
            .execute("DELETE FROM withdrawal_payout_inputs", [])
            .unwrap();
        assert!(db.verify_and_load_signable_payout(1, 2_000).is_err());
        assert_halted(&db, 1, "no_committed_inputs");
    }

    #[test]
    fn signed_bytes_and_txid_are_durable_before_broadcast_and_advance_state() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.verify_and_load_signable_payout(1, 2_000).unwrap();
        db.record_signed_payout(1, "0100abcd", &[0x5A; 32], 2_100)
            .unwrap();
        let p = db.get_payout(1).unwrap().unwrap();
        assert_eq!(p.signed_tx_hex.as_deref(), Some("0100abcd"));
        assert_eq!(
            p.txid_hex.as_deref(),
            Some(hex::encode(&[0x5A; 32]).as_str())
        );
        assert_eq!(
            db.get_withdrawal(1).unwrap().unwrap().state,
            WithdrawalState::Broadcast,
            "state advances in the same transaction that persists the txid"
        );
    }

    #[test]
    fn completing_a_payout_marks_its_inputs_spent() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.verify_and_load_signable_payout(1, 2_000).unwrap();
        db.record_signed_payout(1, "0100abcd", &[0x5A; 32], 2_100)
            .unwrap();
        db.transition_withdrawal(1, WithdrawalState::Confirming, 2_200, None)
            .unwrap();
        db.complete_payout(1, 2_300).unwrap();
        assert_eq!(
            db.get_withdrawal(1).unwrap().unwrap().state,
            WithdrawalState::Completed
        );
        let spent: i64 = db
            .raw()
            .query_row(
                "SELECT COUNT(*) FROM vault_utxos WHERE state='Spent'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(spent, 1);
    }

    #[test]
    fn operator_recovery_is_the_only_exit_and_cannot_claim_a_payment() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw().execute("DELETE FROM vault_utxos", []).unwrap();
        db.verify_and_load_signable_payout(1, 2_000).unwrap_err();
        assert_halted(&db, 1, "no_longer_exists");

        // Anonymous recovery refused.
        assert!(matches!(
            db.operator_clear_withdrawal_halt(1, WithdrawalState::Failed, "  ", 3_000),
            Err(DbError::WithdrawalOperatorNoteRequired(1))
        ));
        // Cannot jump to a state implying a payment occurred.
        for bad in [
            WithdrawalState::Completed,
            WithdrawalState::Broadcast,
            WithdrawalState::Confirming,
        ] {
            assert!(matches!(
                db.operator_clear_withdrawal_halt(1, bad, "force", 3_000),
                Err(DbError::InvalidWithdrawalRecoveryTarget { .. })
            ));
        }
        assert_eq!(
            db.get_withdrawal(1).unwrap().unwrap().state,
            WithdrawalState::IntegrityHalted
        );

        // The sanctioned path, fully audited.
        db.operator_clear_withdrawal_halt(
            1,
            WithdrawalState::Failed,
            "investigated: node wallet rescan lost the utxo",
            3_100,
        )
        .unwrap();
        assert_eq!(
            db.get_withdrawal(1).unwrap().unwrap().state,
            WithdrawalState::Failed
        );
        let halts: i64 = db
            .raw()
            .query_row(
                "SELECT COUNT(*) FROM withdrawal_state_log WHERE withdrawal_index=1 AND to_state='IntegrityHalted'",
                [], |r| r.get(0))
            .unwrap();
        assert_eq!(halts, 1, "the original anomaly record survives");
        let reason: String = db
            .raw()
            .query_row(
                "SELECT reason FROM withdrawal_state_log WHERE withdrawal_index=1 AND from_state='IntegrityHalted'",
                [], |r| r.get(0))
            .unwrap();
        assert!(reason.starts_with("operator_recovery: "));
    }

    #[test]
    fn operator_recovery_does_not_apply_to_a_healthy_withdrawal() {
        let mut db = mem_db();
        db.observe_withdrawal(&new_withdrawal(1, 500)).unwrap();
        assert!(matches!(
            db.operator_clear_withdrawal_halt(1, WithdrawalState::Failed, "note", 10),
            Err(DbError::NotWithdrawalIntegrityHalted { .. })
        ));
    }

    // -----------------------------------------------------------------
    // Designated signing quorum and reassignment (Phase 7b, ADR-0015)
    // -----------------------------------------------------------------

    #[test]
    fn the_signable_payout_carries_the_designated_quorum() {
        // The signer must know exactly who is authorised to contribute,
        // because the txid depends on the signing set.
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        let s = db.verify_and_load_signable_payout(1, 2_000).unwrap();
        assert_eq!(s.quorum_indices, QUORUM);
        assert_eq!(s.quorum_attempt, 0);
        assert_eq!(s.vault_script_hash, VAULT_HASH);
    }

    #[test]
    fn a_mutated_quorum_is_caught_before_signing() {
        // Swapping the designated signers changes which transaction would
        // result, so it must never pass the pre-signing guards.
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw()
            .execute(
                "UPDATE withdrawal_payouts SET quorum_indices = ?1 WHERE withdrawal_index = 1",
                params![vec![1u8, 2u8].as_slice()],
            )
            .unwrap();
        assert!(matches!(
            db.verify_and_load_signable_payout(1, 2_000).unwrap_err(),
            DbError::PayoutIntegrityMismatch { .. }
        ));
        assert_halted(&db, 1, "commitment_mismatch");
    }

    #[test]
    fn a_mutated_vault_binding_is_caught_before_signing() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw()
            .execute(
                "UPDATE withdrawal_payouts SET vault_script_hash = ?1 WHERE withdrawal_index = 1",
                params![[0xEEu8; 20].as_slice()],
            )
            .unwrap();
        assert!(db.verify_and_load_signable_payout(1, 2_000).is_err());
        assert_halted(&db, 1, "commitment_mismatch");
    }

    #[test]
    fn a_bumped_attempt_counter_alone_is_caught_before_signing() {
        // The attempt is inside the commitment, so a silent bump — without
        // a matching intent — must not pass.
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.raw()
            .execute(
                "UPDATE withdrawal_payouts SET quorum_attempt = 1 WHERE withdrawal_index = 1",
                [],
            )
            .unwrap();
        assert!(db.verify_and_load_signable_payout(1, 2_000).is_err());
        assert_halted(&db, 1, "commitment_mismatch");
    }

    /// Rebuilds a coherent intent for a new quorum, as the executor would.
    fn reassign(db: &mut Db, index: i64, new_quorum: &[u8], reason: &str) -> u32 {
        let inputs = db.payout_inputs(index).unwrap();
        let p = db.get_payout(index).unwrap().unwrap();
        let w = db.get_withdrawal(index).unwrap().unwrap();
        let attempt = p.quorum_attempt + 1;
        let intent = canonical_payout_intent(
            w.protocol_version,
            index,
            &VAULT_HASH,
            &w.glc_address_hash160,
            p.payout_atomic,
            p.fee_atomic,
            p.change_atomic,
            &CHANGE,
            attempt,
            new_quorum,
            &inputs,
        );
        db.reassign_payout_quorum(
            index,
            new_quorum,
            &payout_commitment(&intent),
            &intent,
            "0100rebuilt",
            reason,
            5_000,
        )
        .unwrap()
    }

    #[test]
    fn reassignment_produces_a_new_attempt_that_still_verifies() {
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        let next = reassign(&mut db, 1, &[1, 2], "signer 0 unavailable");
        assert_eq!(next, 1);

        let s = db.verify_and_load_signable_payout(1, 6_000).unwrap();
        assert_eq!(s.quorum_indices, vec![1, 2], "the new quorum is in force");
        assert_eq!(s.quorum_attempt, 1);
    }

    #[test]
    fn reassignment_is_recorded_not_overwritten() {
        let mut db = mem_db();
        let (_, commitment) = {
            ready_to_sign(&mut db, 1, 500_000);
            let p = db.get_payout(1).unwrap().unwrap();
            (p.quorum_attempt, p.commitment_hash)
        };
        reassign(&mut db, 1, &[1, 2], "signer 0 offline");
        reassign(&mut db, 1, &[0, 1], "signer 2 offline");

        let history = db.quorum_history(1).unwrap();
        assert_eq!(history.len(), 2, "every superseded designation is kept");
        assert_eq!(history[0].0, 0);
        assert_eq!(history[0].1, QUORUM);
        assert_eq!(history[0].2, "signer 0 offline");
        assert_eq!(history[1].0, 1);
        assert_eq!(history[1].1, vec![1, 2]);
        // The original commitment is preserved in the audit trail.
        assert_eq!(
            db.raw()
                .query_row(
                    "SELECT commitment_hash FROM withdrawal_quorum_history
                     WHERE withdrawal_index = 1 AND quorum_attempt = 0",
                    [],
                    |r| r.get::<_, Vec<u8>>(0)
                )
                .unwrap(),
            commitment.to_vec()
        );
    }

    #[test]
    fn reassignment_requires_a_reason() {
        // A re-designation with no stated cause is not auditable.
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        assert!(matches!(
            db.reassign_payout_quorum(1, &[1, 2], &[0u8; 32], &[0u8; 114], "x", "   ", 5_000),
            Err(DbError::WithdrawalOperatorNoteRequired(1))
        ));
    }

    #[test]
    fn a_signed_payout_can_never_be_re_designated() {
        // Once signed, the txid is durable and reconciliation depends on it:
        // the correct response to a stuck payout is rebroadcast, never a new
        // quorum that would produce a different transaction.
        let mut db = mem_db();
        ready_to_sign(&mut db, 1, 500_000);
        db.verify_and_load_signable_payout(1, 2_000).unwrap();
        db.record_signed_payout(1, "0100signed", &[0xAB; 32], 3_000)
            .unwrap();
        assert!(matches!(
            db.reassign_payout_quorum(
                1,
                &[1, 2],
                &[0u8; 32],
                &[0u8; 114],
                "x",
                "signer went offline",
                5_000
            ),
            Err(DbError::ReservationInvalid { .. })
        ));
        assert_eq!(db.quorum_history(1).unwrap().len(), 0);
    }

    #[test]
    fn canonical_intent_layout_is_pinned() {
        let inputs = vec![utxo(1, 3, 42)];
        let m = canonical_payout_intent(
            1,
            7,
            &VAULT_HASH,
            &DEST,
            500,
            20,
            480,
            &CHANGE,
            0,
            QUORUM,
            &inputs,
        );
        assert_eq!(&m[0..17], PAYOUT_DOMAIN_TAG);
        assert_eq!(m[17], 1);
        assert_eq!(&m[18..26], &7i64.to_le_bytes());
        assert_eq!(&m[26..46], &VAULT_HASH);
        assert_eq!(&m[46..66], &DEST);
        assert_eq!(&m[66..74], &500u64.to_le_bytes());
        assert_eq!(&m[74..82], &20u64.to_le_bytes());
        assert_eq!(&m[82..90], &480u64.to_le_bytes());
        assert_eq!(&m[90..110], &CHANGE);
        assert_eq!(&m[110..114], &0u32.to_le_bytes(), "quorum_attempt");
        assert_eq!(m[114], 2, "quorum_count");
        assert_eq!(&m[115..117], QUORUM, "quorum indices, ascending");
        assert_eq!(&m[117..121], &1u32.to_le_bytes(), "input_count");
        assert_eq!(&m[121..153], &[1u8; 32]);
        assert_eq!(m.len(), PAYOUT_INTENT_FIXED_LEN + 1 + 2 + 4 + 44);
    }

    #[test]
    fn diff_names_the_field_that_drifted() {
        let inputs = vec![utxo(1, 0, 42)];
        let mk = |fee: u64, q: &[u8], ins: &[VaultUtxo], attempt: u32| {
            canonical_payout_intent(
                1,
                7,
                &VAULT_HASH,
                &DEST,
                500,
                fee,
                480,
                &CHANGE,
                attempt,
                q,
                ins,
            )
        };
        let base = mk(20, QUORUM, &inputs, 0);
        assert_eq!(
            diff_payout_fields(&mk(21, QUORUM, &inputs, 0), &base).as_deref(),
            Some("fee_atomic")
        );
        assert_eq!(
            diff_payout_fields(&mk(20, QUORUM, &inputs, 1), &base).as_deref(),
            Some("quorum_attempt"),
            "a reassignment must be visible as its own field"
        );
        let inputs2 = vec![utxo(2, 0, 42)];
        assert_eq!(
            diff_payout_fields(&mk(20, QUORUM, &inputs2, 0), &base).as_deref(),
            Some("quorum_or_inputs")
        );
        assert_eq!(
            diff_payout_fields(&mk(20, &[1, 2], &inputs, 0), &base).as_deref(),
            Some("quorum_or_inputs"),
            "a different designated quorum is a different payout"
        );
        assert_eq!(diff_payout_fields(&base, &base), None);
    }
}
