//! Key management & claim signing (Phase 5, ADR-0012).
//!
//! # One key per process (Phase 7c, ADR-0016)
//!
//! Phase 5's bootstrap topology (owner decision R2) is **retired**. One
//! process no longer loads several validators' keys and signs with all of
//! them: `load_validator_keypairs` is deleted, and the only loader here
//! returns exactly one identity.
//!
//! A validator's key now lives solely inside its own signer service
//! (`p2p::service::SignerService`), which runs as a separate process. The
//! mint orchestrator and withdrawal executor hold no key material at all —
//! they request signatures over gRPC and aggregate the responses.
//!
//! Keys are loaded once at startup from operator-configured file paths
//! (standard Solana CLI keypair JSON, the `[u8; 64]` array format —
//! matching what `.gitignore` already anticipates via `keypair*.json`/
//! `id.json`), held in memory only, and never logged or persisted anywhere.
//!
//! Signing NEVER operates on a cached or pre-serialized message: callers
//! must obtain the message to sign from
//! [`crate::glc::db::Db::verify_and_load_signable_message`] (the
//! reload-and-recompute safeguard, ADR-0012) immediately beforehand, and
//! pass those exact bytes here.

use std::path::Path;

use solana_sdk::signature::{Keypair, Signature, Signer};
use thiserror::Error;

pub mod aggregate;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("failed to read validator keypair file {path}: {source}")]
    KeypairFile {
        path: String,
        source: std::io::Error,
    },
    #[error("no validator keypairs configured — at least one is required")]
    NoKeypairs,
}

/// Loads **the** validator keypair for this process.
///
/// Singular by design: there is deliberately no function here that loads a
/// set of validator keys. Holding more than one federation identity in one
/// process is the bootstrap topology Phase 7c retires, and removing the
/// plural loader is what makes that structural rather than advisory.
///
/// Fails closed: an unreadable or malformed file aborts startup rather than
/// letting the process run without the identity it is supposed to have.
pub fn load_validator_keypair(path: impl AsRef<Path>) -> Result<Keypair, SignerError> {
    let path = path.as_ref();
    solana_sdk::signature::read_keypair_file(path).map_err(|e| {
        // read_keypair_file returns a boxed dyn error covering both I/O and
        // malformed-content failures; std::io::Error is the closest faithful
        // wrapper without pulling its dynamic error type into this module's
        // public API.
        SignerError::KeypairFile {
            path: path.display().to_string(),
            source: std::io::Error::other(e.to_string()),
        }
    })
}

/// Signs `message` with this validator's single key.
///
/// `message` MUST be freshly obtained from
/// [`crate::glc::db::Db::verify_and_load_signable_message`], never cached.
/// Pure and I/O-free; aggregating signatures from peers is [`aggregate`].
pub fn sign_one(key: &Keypair, message: &[u8]) -> (solana_sdk::pubkey::Pubkey, Signature) {
    (key.pubkey(), key.sign_message(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_keypair_file(dir: &tempfile::TempDir, name: &str, kp: &Keypair) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let bytes = kp.to_bytes();
        let json = serde_json::to_string(&bytes.to_vec()).unwrap();
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        path
    }

    #[test]
    fn loads_the_single_validator_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let k = Keypair::new();
        let p = write_keypair_file(&dir, "v1.json", &k);
        assert_eq!(load_validator_keypair(p).unwrap().pubkey(), k.pubkey());
    }

    #[test]
    fn rejects_missing_file() {
        let err = load_validator_keypair("/nonexistent/path/does/not/exist.json").unwrap_err();
        assert!(matches!(err, SignerError::KeypairFile { .. }));
    }

    #[test]
    fn sign_one_produces_a_verifying_signature() {
        let key = Keypair::new();
        let message = b"exact bytes to sign, nothing cached";
        let (pubkey, sig) = sign_one(&key, message);
        assert_eq!(pubkey, key.pubkey());
        assert!(sig.verify(pubkey.as_ref(), message));
    }
}
