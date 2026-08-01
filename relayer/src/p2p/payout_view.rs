//! What a signer will and will not sign for a vault payout (Phase 7e,
//! ADR-0017).
//!
//! This is where the payout path's trust boundary lives, and it is the exact
//! analogue of [`super::view::DbLocalView`] on the mint side: the answer is
//! derived from **this** validator's persisted observations, never from
//! anything the requester supplied.
//!
//! # Three independent things must agree
//!
//! 1. the **canonical intent** this validator recomputes (ADR-0015);
//! 2. the **unsigned transaction** this validator's own executor built from
//!    its own UTXO view;
//! 3. the **quorum attempt** this validator has itself designated.
//!
//! Any disagreement is a refusal, and a refusal is an alarm — it means two
//! operators' independent views of the Goldcoin chain have diverged.
//!
//! # Why amounts come only from local state
//!
//! The legacy sighash does **not** commit to input amounts (ADR-0017 §2.5,
//! verified on a real node): signing with falsified amounts produces a
//! byte-identical, network-accepted transaction. A signature is therefore no
//! evidence whatsoever about what an input was worth.
//!
//! So the `prevtxs` this module hands to its own Goldcoin node are built
//! **entirely** from rows in this validator's own `vault_utxos` table. The
//! request contributes the withdrawal index, the quorum attempt, and two
//! blobs that are only ever *compared*. It contributes no amount, no script,
//! and no outpoint that is used as-is.

use thiserror::Error;

use crate::glc::db::Db;
use crate::glc::rpc::PrevTx;
use crate::glc::withdrawal_db::WithdrawalState;
use crate::withdrawal::multisig::{extract_signatures, MultisigError, Transaction};
use crate::withdrawal::vault::MultisigVault;

/// Why a payout signing request was refused.
///
/// Every variant is an **alarm**: this validator's view of the Goldcoin
/// chain disagrees with a peer's, which is a bug, an outage, or an attack.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PayoutRefusal {
    #[error("this validator has no record of withdrawal {0}")]
    UnknownWithdrawal(u64),
    #[error(
        "withdrawal {index} is in state {state} — this validator will not sign a payout outside \
         the building/signing window"
    )]
    NotSignable { index: u64, state: String },
    #[error(
        "requester asked for quorum attempt {requested}, this validator has designated {local} — \
         refusing to sign for a designation it has not made (ADR-0015)"
    )]
    QuorumAttemptMismatch { requested: u32, local: u32 },
    #[error(
        "the requested payout intent is not what this validator independently recomputes for \
         withdrawal {index}"
    )]
    IntentMismatch { index: u64 },
    #[error(
        "the requested unsigned transaction is not the one this validator's own executor built \
         for withdrawal {index}"
    )]
    UnsignedTxMismatch { index: u64 },
    #[error("this validator is not a designated signer for withdrawal {index} attempt {attempt}")]
    NotDesignated { index: u64, attempt: u32 },
    #[error("integrity safeguard halted withdrawal {index}: {reason}")]
    IntegrityHalted { index: u64, reason: String },
    #[error("local Goldcoin node could not produce a partial signature: {0}")]
    SigningFailed(String),
    #[error("local partial signature is unusable: {0}")]
    MalformedPartial(String),
    #[error("withdrawal index {0} is out of range")]
    IndexOutOfRange(u64),
    #[error(
        "operator {proposer} is not the designated builder for withdrawal {index} and its \
         failover window has not elapsed"
    )]
    NotTheDesignatedBuilder { index: u64, proposer: usize },
    #[error(
        "proposed input {outpoint} for withdrawal {index} is not Available in this validator's \
         own UTXO set"
    )]
    InputNotLocallyAvailable { index: u64, outpoint: String },
    #[error(
        "proposed input {outpoint} for withdrawal {index} is worth {proposed} here but {local} \
         locally"
    )]
    InputAmountMismatch {
        index: u64,
        outpoint: String,
        proposed: u64,
        local: u64,
    },
    #[error(
        "proposed payout for withdrawal {index} does not pay this validator's recorded destination"
    )]
    DestinationMismatch { index: u64 },
    #[error("proposed payout for withdrawal {index} pays {proposed}, this validator owes {local}")]
    AmountMismatch {
        index: u64,
        proposed: u64,
        local: u64,
    },
}

/// What this validator will contribute, once it agrees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutPartial {
    /// This signer's vault key (compressed secp256k1) — the one that must
    /// appear in the redeem script. A different key from the ed25519
    /// federation identity, in a different cryptosystem.
    pub vault_pubkey: [u8; 33],
    /// One DER signature per input, in input order.
    pub signatures: Vec<Vec<u8>>,
}

/// The Goldcoin RPC surface a payout signer needs.
///
/// A trait so the decision logic is testable without a node, mirroring
/// `PayoutRpc` and `SolanaRpc`. In production this is backed by **this
/// signer's own** Goldcoin node: sharing the relayer's node would mean
/// inheriting the requester's view, which defeats the entire purpose
/// (ADR-0017 E2).
pub trait PartialSigner {
    /// Signs with **this signer's single vault key only**, returning the
    /// partially-signed transaction hex.
    ///
    /// A partial M-of-N signature legitimately returns `complete: false`
    /// with `Operation not valid with the current stack size` — that is the
    /// expected result, not a failure (ADR-0017 §2.3).
    fn sign_partial(
        &self,
        unsigned_tx_hex: &str,
        prevtxs: &[PrevTx],
    ) -> impl std::future::Future<Output = Result<String, String>> + Send;
}

/// A validator's payout signing view, over its own database and its own node.
pub struct PayoutView<S: PartialSigner> {
    /// The same validated withdrawal configuration the executor uses, so an
    /// adopted proposal is checked against identical policy.
    config: crate::withdrawal::config::WithdrawalConfig,
    vault: MultisigVault,
    /// This signer's position in the vault's ordered signer list.
    vault_signer_index: u8,
    signer: S,
    /// This operator's place in the federation (Phase 7g, ADR-0019).
    /// `None` means a single-operator deployment, where every proposal is
    /// legitimately our own.
    assignment: Option<crate::withdrawal::assignment::OperatorAssignment>,
}

impl<S: PartialSigner> PayoutView<S> {
    /// Constructs the view, **failing closed** if this signer's configured
    /// vault position does not resolve to a key actually in the vault
    /// (ADR-0017 E1).
    pub fn new(
        config: crate::withdrawal::config::WithdrawalConfig,
        vault_signer_index: u8,
        signer: S,
    ) -> Result<Self, String> {
        let vault = config.vault.clone();
        if vault_signer_index as usize >= vault.signer_pubkeys.len() {
            return Err(format!(
                "configured vault signer index {vault_signer_index} is out of range for a vault \
                 with {} signers — refusing to start",
                vault.signer_pubkeys.len()
            ));
        }
        Ok(PayoutView {
            config,
            vault,
            vault_signer_index,
            signer,
            assignment: None,
        })
    }

    /// Declares this operator's place in the federation, enabling the
    /// designated-builder check (ADR-0019 D3 check 1).
    pub fn with_assignment(
        mut self,
        assignment: crate::withdrawal::assignment::OperatorAssignment,
    ) -> Self {
        self.assignment = Some(assignment);
        self
    }

    /// Whether `proposer` may propose a payout for this withdrawal now.
    ///
    /// A passive operator must not adopt a proposal from an operator that
    /// has no business making it yet — otherwise assignment would decide
    /// nothing and every operator could still race to propose.
    fn proposal_is_timely(&self, index: u64, proposer: usize, observed_at: i64, now: i64) -> bool {
        match &self.assignment {
            None => true,
            Some(a) => a.may_propose(proposer, index, observed_at, now),
        }
    }

    pub fn vault_pubkey(&self) -> [u8; 33] {
        self.vault.signer_pubkeys[self.vault_signer_index as usize]
    }

    /// Adopts a designated builder's proposal, after validating **every**
    /// field against this operator's own state (ADR-0019 D3 checks 2-6).
    ///
    /// This is adoption-after-verification, not trust. What it removes is
    /// the *speculative* reservation that made two honest operators build
    /// different transactions (ADR-0019 §2.1) — not the verification that
    /// makes a proposal safe to sign.
    fn adopt_proposal(
        &self,
        db: &mut Db,
        w: &crate::glc::withdrawal_db::WithdrawalRow,
        unsigned_tx_hex: &str,
        now_unix: i64,
    ) -> Result<(), PayoutRefusal> {
        use crate::withdrawal::multisig::Transaction;

        let index = w.withdrawal_index;
        let idx = index as u64;
        let tx = Transaction::parse_hex(unsigned_tx_hex).map_err(|e| {
            PayoutRefusal::MalformedPartial(format!("proposed transaction is unparseable: {e}"))
        })?;

        // (3) every proposed input must be in THIS operator's own UTXO set,
        // Available, at the required depth, with a matching amount.
        let available = db
            .available_utxos(self.config.vault_min_confirmations)
            .map_err(|e| PayoutRefusal::IntegrityHalted {
                index: idx,
                reason: e.to_string(),
            })?;
        let mut inputs = Vec::with_capacity(tx.inputs.len());
        for vin in &tx.inputs {
            // The wire carries internal byte order; local rows store display
            // order.
            let mut display = vin.prev_txid;
            display.reverse();
            let txid_hex = crate::glc::hex::encode(&display);
            let outpoint = format!("{txid_hex}:{}", vin.prev_vout);
            let found = available
                .iter()
                .find(|u| u.txid_hex == txid_hex && u.vout == vin.prev_vout as i64)
                .ok_or_else(|| PayoutRefusal::InputNotLocallyAvailable {
                    index: idx,
                    outpoint: outpoint.clone(),
                })?;
            inputs.push(found.clone());
        }

        // (4) the outputs must pay exactly what this operator owes, to the
        // destination IT recorded. A proposal that pays the right amount to
        // the wrong place is the most dangerous single tamper.
        let dest_script = crate::glc::hex::decode_vec(
            &crate::withdrawal::address::p2pkh_script_hex(&w.glc_address_hash160),
        )
        .map_err(|e| PayoutRefusal::MalformedPartial(e.to_string()))?;
        let paid: u64 = tx
            .outputs
            .iter()
            .filter(|o| o.script_pubkey == dest_script)
            .map(|o| o.value)
            .sum();
        if paid == 0 {
            return Err(PayoutRefusal::DestinationMismatch { index: idx });
        }
        if paid != w.amount_atomic {
            return Err(PayoutRefusal::AmountMismatch {
                index: idx,
                proposed: paid,
                local: w.amount_atomic,
            });
        }

        // (5) the fee is whatever the inputs exceed the outputs by. It is
        // checked against this operator's own policy by the shared payout
        // verifier below, which also re-checks the destination and change.
        let total_in: u64 = inputs.iter().map(|u| u.amount_atomic).sum();
        let total_out: u64 = tx.outputs.iter().map(|o| o.value).sum();
        let fee = total_in.saturating_sub(total_out);
        let change = tx
            .outputs
            .iter()
            .filter(|o| o.script_pubkey != dest_script)
            .map(|o| o.value)
            .sum::<u64>();

        // (6) the signing quorum must be the one THIS operator designates.
        let quorum = crate::withdrawal::assignment::designate_quorum(
            index,
            self.vault.signer_count(),
            self.vault.threshold,
        );

        let intent = crate::glc::withdrawal_db::canonical_payout_intent(
            w.protocol_version,
            index,
            &self.vault.script_hash160,
            &w.glc_address_hash160,
            paid,
            fee,
            change,
            &self.config.change_hash160,
            0,
            &quorum,
            &inputs,
        );

        db.reserve_utxos(index, &inputs, now_unix)
            .map_err(|e| PayoutRefusal::IntegrityHalted {
                index: idx,
                reason: format!("could not reserve the proposed inputs: {e}"),
            })?;
        db.create_payout(&crate::glc::withdrawal_db::NewPayout {
            withdrawal_index: index,
            vault_script_hash: self.vault.script_hash160,
            quorum_indices: quorum,
            quorum_attempt: 0,
            commitment_hash: crate::glc::withdrawal_db::payout_commitment(&intent),
            intent_bytes: intent,
            fee_atomic: fee,
            payout_atomic: paid,
            change_atomic: change,
            change_address: Some(crate::withdrawal::address::encode_p2pkh(
                &self.config.change_hash160,
            )),
            unsigned_tx_hex: unsigned_tx_hex.to_string(),
            inputs,
            built_at: now_unix,
        })
        .map_err(|e| PayoutRefusal::IntegrityHalted {
            index: idx,
            reason: format!("could not persist the adopted payout: {e}"),
        })?;

        if w.state == crate::glc::withdrawal_db::WithdrawalState::AwaitingFunds {
            db.transition_withdrawal(
                index,
                crate::glc::withdrawal_db::WithdrawalState::Validated,
                now_unix,
                None,
            )
            .map_err(|e| PayoutRefusal::IntegrityHalted {
                index: idx,
                reason: e.to_string(),
            })?;
        }
        for step in [
            crate::glc::withdrawal_db::WithdrawalState::Building,
            crate::glc::withdrawal_db::WithdrawalState::Signing,
        ] {
            db.transition_withdrawal(index, step, now_unix, None)
                .map_err(|e| PayoutRefusal::IntegrityHalted {
                    index: idx,
                    reason: e.to_string(),
                })?;
        }
        tracing::info!(
            withdrawal_index = index,
            "adopted a designated builder's payout proposal after independent validation"
        );
        Ok(())
    }

    /// Decides whether to sign, and if so produces the partial.
    ///
    /// The order of checks is deliberate: cheap local state first, then the
    /// integrity safeguard, then the two byte-for-byte comparisons, and only
    /// then the node round-trip. An attacker cannot make this validator do
    /// expensive work by sending nonsense.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_payout(
        &self,
        db: &mut Db,
        withdrawal_index: u64,
        quorum_attempt: u32,
        canonical_intent: &[u8],
        unsigned_tx_hex: &str,
        proposer_index: usize,
        now_unix: i64,
    ) -> Result<PayoutPartial, PayoutRefusal> {
        let index = i64::try_from(withdrawal_index)
            .map_err(|_| PayoutRefusal::IndexOutOfRange(withdrawal_index))?;

        let w = db
            .get_withdrawal(index)
            .map_err(|e| PayoutRefusal::IntegrityHalted {
                index: withdrawal_index,
                reason: e.to_string(),
            })?
            .ok_or(PayoutRefusal::UnknownWithdrawal(withdrawal_index))?;

        // ADR-0019 D3 check 1: is this proposal timely at all? Cheapest
        // check, and it needs no database work.
        let eligible_since =
            db.withdrawal_eligible_since(index)
                .map_err(|e| PayoutRefusal::IntegrityHalted {
                    index: withdrawal_index,
                    reason: e.to_string(),
                })?;
        if !self.proposal_is_timely(withdrawal_index, proposer_index, eligible_since, now_unix) {
            return Err(PayoutRefusal::NotTheDesignatedBuilder {
                index: withdrawal_index,
                proposer: proposer_index,
            });
        }

        // A PASSIVE operator has not built this payout — by design, so that
        // it never reserved UTXOs speculatively (ADR-0019 D3). It adopts the
        // proposal here, after validating every field against its own state.
        if matches!(
            w.state,
            WithdrawalState::Validated | WithdrawalState::AwaitingFunds
        ) {
            self.adopt_proposal(db, &w, unsigned_tx_hex, now_unix)?;
        }

        // Only inside the signing window. Signing a Broadcast or Completed
        // payout could only serve a replay or a conflicting spend.
        let w = db
            .get_withdrawal(index)
            .map_err(|e| PayoutRefusal::IntegrityHalted {
                index: withdrawal_index,
                reason: e.to_string(),
            })?
            .ok_or(PayoutRefusal::UnknownWithdrawal(withdrawal_index))?;
        if !matches!(
            w.state,
            WithdrawalState::Building | WithdrawalState::Signing
        ) {
            return Err(PayoutRefusal::NotSignable {
                index: withdrawal_index,
                state: w.state.as_str().to_string(),
            });
        }

        // The reload-and-recompute safeguard. On drift this HALTS the
        // withdrawal as an integrity anomaly rather than returning anything.
        let signable = db
            .verify_and_load_signable_payout(index, now_unix)
            .map_err(|e| PayoutRefusal::IntegrityHalted {
                index: withdrawal_index,
                reason: e.to_string(),
            })?;

        // ADR-0015: a superseded designation is a DIFFERENT thing to sign
        // for, because the txid depends on which quorum signs.
        if signable.quorum_attempt != quorum_attempt {
            return Err(PayoutRefusal::QuorumAttemptMismatch {
                requested: quorum_attempt,
                local: signable.quorum_attempt,
            });
        }

        // This validator must actually be in the designated quorum. Signing
        // when not designated would produce a signature that cannot be used
        // and, worse, could be collected into a quorum nobody designated.
        if !signable.quorum_indices.contains(&self.vault_signer_index) {
            return Err(PayoutRefusal::NotDesignated {
                index: withdrawal_index,
                attempt: quorum_attempt,
            });
        }

        // The two byte-for-byte comparisons. `intent_bytes` is the FRESHLY
        // RECOMPUTED intent, not the stored blob.
        if signable.intent_bytes != canonical_intent {
            return Err(PayoutRefusal::IntentMismatch {
                index: withdrawal_index,
            });
        }
        if signable.unsigned_tx_hex != unsigned_tx_hex {
            return Err(PayoutRefusal::UnsignedTxMismatch {
                index: withdrawal_index,
            });
        }

        // D4: prevtxs are built ENTIRELY from local rows. Nothing about the
        // inputs — outpoint or script — comes from the request.
        //
        // Note `PrevTx` carries no amount at all. That is not an omission:
        // the legacy sighash does not commit to input amounts (ADR-0017
        // §2.5), so an amount here would influence nothing while creating a
        // channel for a requester-supplied value to appear trusted. The
        // amounts that DO matter were already checked against this
        // validator's own `vault_utxos` rows inside
        // `verify_and_load_signable_payout`, which halts on any drift.
        let prevtxs: Vec<PrevTx> = signable
            .inputs
            .iter()
            .map(|u| PrevTx {
                txid: u.txid_hex.clone(),
                vout: u.vout,
                script_pub_key: u.script_pubkey_hex.clone(),
                redeem_script: self.vault.redeem_script_hex(),
            })
            .collect();

        // Sign on THIS signer's own node, with THIS signer's single key.
        let partial_hex = self
            .signer
            .sign_partial(&signable.unsigned_tx_hex, &prevtxs)
            .await
            .map_err(PayoutRefusal::SigningFailed)?;

        let partial = Transaction::parse_hex(&partial_hex)
            .map_err(|e: MultisigError| PayoutRefusal::MalformedPartial(e.to_string()))?;
        let signatures = extract_signatures(&partial, &self.vault.redeem_script)
            .map_err(|e| PayoutRefusal::MalformedPartial(e.to_string()))?;

        Ok(PayoutPartial {
            vault_pubkey: self.vault_pubkey(),
            signatures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::withdrawal::vault::MultisigVault;

    struct NeverCalled;
    impl PartialSigner for NeverCalled {
        async fn sign_partial(&self, _: &str, _: &[PrevTx]) -> Result<String, String> {
            panic!("the node must not be reached for a request refused on local state");
        }
    }

    fn vault_of(n: usize, m: usize) -> MultisigVault {
        let keys: Vec<[u8; 33]> = (0..n)
            .map(|i| {
                let mut k = [0u8; 33];
                k[0] = 0x02;
                k[32] = i as u8 + 1;
                k
            })
            .collect();
        MultisigVault::new(m, keys).unwrap()
    }

    /// A validated configuration around `vault_of(n, m)`.
    fn cfg_of(n: usize, m: usize) -> crate::withdrawal::config::WithdrawalConfig {
        let v = vault_of(n, m);
        crate::withdrawal::config::WithdrawalConfig::validate(
            crate::withdrawal::config::RawWithdrawalConfig {
                vault_redeem_script_hex: v.redeem_script_hex(),
                vault_address: v.address.clone(),
                change_address: v.address.clone(),
                fee_rate_per_kb: 100_000,
                dust_threshold_atomic: 5_400,
                vault_min_confirmations: 1,
                confirmation_depth: 2,
                max_inputs_per_payout: 20,
                reservation_timeout_secs: 900,
                discovery_commitment: "finalized".into(),
                poll_interval_ms: 500,
            },
        )
        .unwrap()
    }

    #[test]
    fn refuses_to_construct_with_a_vault_index_out_of_range() {
        // ADR-0017 E1: fail closed rather than run with a mapping that could
        // route a signing request to the wrong key.
        let err = match PayoutView::new(cfg_of(3, 2), 3, NeverCalled) {
            Err(e) => e,
            Ok(_) => panic!("a vault index outside the signer set must be refused"),
        };
        assert!(err.contains("out of range"), "{err}");
        assert!(PayoutView::new(cfg_of(3, 2), 2, NeverCalled).is_ok());
    }

    #[test]
    fn reports_the_vault_pubkey_at_its_configured_position() {
        let v = vault_of(3, 2);
        for i in 0..3u8 {
            let view = PayoutView::new(cfg_of(3, 2), i, NeverCalled).unwrap();
            assert_eq!(view.vault_pubkey(), v.signer_pubkeys[i as usize]);
        }
    }
}
