//! Peer identity for the federation transport (Phase 7d, ADR-0016 §6.2).
//!
//! # Identity is bound twice, and both must agree
//!
//! 1. **Transport** — mutual TLS with a pinned CA, so only certificates
//!    issued for this federation are accepted at all.
//! 2. **Application** — every response is checked against the *on-chain
//!    ed25519 validator key* the endpoint is registered as, and the
//!    signature must verify over the message actually requested.
//!
//! Neither alone is sufficient, and that is the point. A stolen certificate
//! does not let an attacker impersonate a validator, because they cannot
//! produce that validator's ed25519 signatures. Conversely, certificate
//! rotation cannot silently change *which federation member* a peer believes
//! it is talking to, because the on-chain key is what the application
//! checks. Losing either check would leave a single credential able to
//! impersonate a member.
//!
//! This module holds no key material and performs no I/O beyond reading the
//! operator's configured certificate files at startup.

use std::path::{Path, PathBuf};

use solana_sdk::pubkey::Pubkey;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("failed to read {what} from {path}: {source}")]
    Read {
        what: &'static str,
        path: String,
        source: std::io::Error,
    },
    #[error("peer entry {0:?} must be formatted pubkey@uri")]
    MalformedPeer(String),
    #[error("peer {entry:?} has an invalid validator pubkey: {reason}")]
    BadPeerPubkey { entry: String, reason: String },
    #[error("no federation peers configured — a federation of one is not a federation")]
    NoPeers,
    #[error("duplicate federation peer {0}")]
    DuplicatePeer(Pubkey),
    #[error("this validator's own identity {0} appears in its peer list")]
    SelfInPeerList(Pubkey),
}

/// A federation peer: the on-chain identity it must answer as, and where to
/// reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEndpoint {
    /// The validator identity this endpoint is expected to answer as. A
    /// response claiming any other identity is discarded.
    pub validator_pubkey: Pubkey,
    pub uri: String,
}

/// Parses `pubkey@uri[,pubkey@uri...]`.
///
/// Rejects an empty list, duplicates, and this validator's own identity —
/// each of which would silently distort quorum arithmetic: counting a peer
/// twice, or counting yourself as an independent signer, both inflate
/// apparent agreement.
pub fn parse_peers(
    raw: &str,
    own_identity: Option<&Pubkey>,
) -> Result<Vec<PeerEndpoint>, IdentityError> {
    let mut peers: Vec<PeerEndpoint> = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (pk, uri) = entry
            .split_once('@')
            .ok_or_else(|| IdentityError::MalformedPeer(entry.to_string()))?;
        let validator_pubkey: Pubkey =
            pk.parse()
                .map_err(|e: solana_sdk::pubkey::ParsePubkeyError| {
                    IdentityError::BadPeerPubkey {
                        entry: entry.to_string(),
                        reason: e.to_string(),
                    }
                })?;
        if uri.is_empty() {
            return Err(IdentityError::MalformedPeer(entry.to_string()));
        }
        if peers.iter().any(|p| p.validator_pubkey == validator_pubkey) {
            return Err(IdentityError::DuplicatePeer(validator_pubkey));
        }
        if own_identity == Some(&validator_pubkey) {
            return Err(IdentityError::SelfInPeerList(validator_pubkey));
        }
        peers.push(PeerEndpoint {
            validator_pubkey,
            uri: uri.to_string(),
        });
    }
    if peers.is_empty() {
        return Err(IdentityError::NoPeers);
    }
    Ok(peers)
}

/// The certificate material this validator presents and trusts.
///
/// The CA is **pinned**: only certificates issued by the federation's own CA
/// are accepted. The public web PKI is deliberately not trusted here — any
/// publicly-issued certificate for a matching name would otherwise be
/// accepted at the transport layer.
#[derive(Debug, Clone)]
pub struct TlsMaterial {
    pub ca_pem: Vec<u8>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TlsPaths {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl TlsMaterial {
    /// Loads certificate material, failing closed on any unreadable file.
    ///
    /// Starting without the material needed to authenticate peers would mean
    /// running with no transport authentication at all, so this aborts
    /// startup rather than degrading.
    pub fn load(paths: &TlsPaths) -> Result<Self, IdentityError> {
        fn read(what: &'static str, p: &Path) -> Result<Vec<u8>, IdentityError> {
            std::fs::read(p).map_err(|source| IdentityError::Read {
                what,
                path: p.display().to_string(),
                source,
            })
        }
        Ok(TlsMaterial {
            ca_pem: read("federation CA certificate", &paths.ca)?,
            cert_pem: read("this validator's certificate", &paths.cert)?,
            key_pem: read("this validator's private key", &paths.key)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::{Keypair, Signer};

    fn pk() -> Pubkey {
        Keypair::new().pubkey()
    }

    #[test]
    fn parses_a_well_formed_peer_list() {
        let a = pk();
        let b = pk();
        let raw = format!("{a}@http://10.0.0.1:9000, {b}@http://10.0.0.2:9000");
        let peers = parse_peers(&raw, None).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].validator_pubkey, a);
        assert_eq!(peers[1].uri, "http://10.0.0.2:9000");
    }

    #[test]
    fn rejects_an_empty_list() {
        assert!(matches!(
            parse_peers("", None).unwrap_err(),
            IdentityError::NoPeers
        ));
        assert!(matches!(
            parse_peers("  , ,", None).unwrap_err(),
            IdentityError::NoPeers
        ));
    }

    #[test]
    fn rejects_a_duplicate_peer() {
        // Counting one peer twice would inflate apparent agreement.
        let a = pk();
        let raw = format!("{a}@http://x:1,{a}@http://y:2");
        assert!(matches!(
            parse_peers(&raw, None).unwrap_err(),
            IdentityError::DuplicatePeer(_)
        ));
    }

    #[test]
    fn rejects_this_validators_own_identity_in_the_peer_list() {
        // Counting yourself as an independent signer is the same error in a
        // different disguise.
        let me = pk();
        let raw = format!("{me}@http://self:1");
        assert!(matches!(
            parse_peers(&raw, Some(&me)).unwrap_err(),
            IdentityError::SelfInPeerList(_)
        ));
    }

    #[test]
    fn rejects_malformed_entries() {
        let a = pk();
        for raw in [
            "no-at-sign".to_string(),
            format!("{a}@"),
            "notapubkey@http://x:1".to_string(),
        ] {
            assert!(parse_peers(&raw, None).is_err(), "must reject {raw:?}");
        }
    }

    #[test]
    fn tls_material_fails_closed_on_any_single_missing_file() {
        // Each file is checked on its own, not just the all-missing case: a
        // loader that tolerated one absent file would start the process with
        // partial authentication material, which is worse than not starting.
        for missing in ["ca.pem", "cert.pem", "key.pem"] {
            let dir = tempfile::tempdir().unwrap();
            let paths = TlsPaths {
                ca: dir.path().join("ca.pem"),
                cert: dir.path().join("cert.pem"),
                key: dir.path().join("key.pem"),
            };
            for f in ["ca.pem", "cert.pem", "key.pem"] {
                if f != missing {
                    std::fs::write(dir.path().join(f), b"PEM").unwrap();
                }
            }
            assert!(
                matches!(
                    TlsMaterial::load(&paths).unwrap_err(),
                    IdentityError::Read { .. }
                ),
                "a missing {missing} must abort startup, not degrade to partial material"
            );
        }
    }

    #[test]
    fn tls_material_loads_all_three_files() {
        let dir = tempfile::tempdir().unwrap();
        let paths = TlsPaths {
            ca: dir.path().join("ca.pem"),
            cert: dir.path().join("cert.pem"),
            key: dir.path().join("key.pem"),
        };
        std::fs::write(&paths.ca, b"CA").unwrap();
        std::fs::write(&paths.cert, b"CERT").unwrap();
        std::fs::write(&paths.key, b"KEY").unwrap();
        let m = TlsMaterial::load(&paths).unwrap();
        assert_eq!(m.ca_pem, b"CA");
        assert_eq!(m.cert_pem, b"CERT");
        assert_eq!(m.key_pem, b"KEY");
    }
}
