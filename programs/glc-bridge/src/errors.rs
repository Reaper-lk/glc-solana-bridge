//! Program error taxonomy. Phase 0 carries a single placeholder variant; the
//! real taxonomy (threshold not met, claim already processed, bridge paused,
//! bad proof, arithmetic overflow, …) lands with the instructions that can
//! raise it.

use anchor_lang::prelude::*;

#[error_code]
pub enum BridgeError {
    #[msg("Not implemented: bridge logic lands in Phase 1+")]
    NotImplemented,
}
