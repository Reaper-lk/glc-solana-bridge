//! Key management & claim signing (Phase 5, ADR-0012).
//!
//! # ⚠️ Single-process bootstrap topology — NOT the production design
//!
//! Owner decision R2: for Phase 5 only, one relayer process loads and holds
//! MULTIPLE validators' ed25519 keypairs directly, signing claims with all
//! of them itself. This exists to prove the full mint pipeline end-to-end
//! (a single process can reach threshold on its own, so the local-validator
//! e2e test doesn't first require a working multi-process p2p network).
//!
//! **This is test/bootstrap architecture only.** A real federation must
//! never operate this way: each validator's private key must be held by
//! that validator alone, on their own infrastructure. The real design —
//! each relayer holding exactly one key, exchanging signatures with peers
//! over the network (`p2p` module, still a placeholder) — is a later
//! phase's work. Do not deploy this module's multi-key loading path beyond
//! a controlled test/bootstrap environment.
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

/// Loads every configured validator keypair file. Fails closed: any
/// unreadable or malformed file aborts startup rather than silently
/// signing with a partial set (a partial set could still be enough to
/// reach threshold with a WRONG membership, which must never happen
/// silently).
pub fn load_validator_keypairs(paths: &[impl AsRef<Path>]) -> Result<Vec<Keypair>, SignerError> {
    if paths.is_empty() {
        return Err(SignerError::NoKeypairs);
    }
    paths
        .iter()
        .map(|p| {
            let path = p.as_ref();
            solana_sdk::signature::read_keypair_file(path).map_err(|e| {
                // read_keypair_file returns a boxed dyn error covering both
                // I/O and malformed-content failures; std::io::Error is the
                // closest faithful wrapper without pulling its dynamic error
                // type into this module's public API.
                SignerError::KeypairFile {
                    path: path.display().to_string(),
                    source: std::io::Error::other(e.to_string()),
                }
            })
        })
        .collect()
}

/// Signs `message` — which MUST be freshly obtained from
/// [`crate::glc::db::Db::verify_and_load_signable_message`], never cached —
/// with every configured key, returning one `(pubkey, signature)` pair per
/// key. Pure and I/O-free: the actual instruction-building/aggregation step
/// is [`aggregate`].
pub fn sign_with_all(
    keys: &[Keypair],
    message: &[u8],
) -> Vec<(solana_sdk::pubkey::Pubkey, Signature)> {
    keys.iter()
        .map(|k| (k.pubkey(), k.sign_message(message)))
        .collect()
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
    fn loads_multiple_real_keypair_files() {
        let dir = tempfile::tempdir().unwrap();
        let k1 = Keypair::new();
        let k2 = Keypair::new();
        let p1 = write_keypair_file(&dir, "v1.json", &k1);
        let p2 = write_keypair_file(&dir, "v2.json", &k2);
        let loaded = load_validator_keypairs(&[p1, p2]).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].pubkey(), k1.pubkey());
        assert_eq!(loaded[1].pubkey(), k2.pubkey());
    }

    #[test]
    fn rejects_empty_key_list() {
        let empty: Vec<std::path::PathBuf> = vec![];
        let err = load_validator_keypairs(&empty).unwrap_err();
        assert!(matches!(err, SignerError::NoKeypairs));
    }

    #[test]
    fn rejects_missing_file() {
        let err = load_validator_keypairs(&["/nonexistent/path/does/not/exist.json"]).unwrap_err();
        assert!(matches!(err, SignerError::KeypairFile { .. }));
    }

    #[test]
    fn sign_with_all_produces_one_signature_per_key_over_the_same_message() {
        let keys = vec![Keypair::new(), Keypair::new(), Keypair::new()];
        let message = b"exact bytes to sign, nothing cached";
        let sigs = sign_with_all(&keys, message);
        assert_eq!(sigs.len(), 3);
        for (i, (pubkey, sig)) in sigs.iter().enumerate() {
            assert_eq!(*pubkey, keys[i].pubkey());
            assert!(sig.verify(pubkey.as_ref(), message));
        }
    }
}
