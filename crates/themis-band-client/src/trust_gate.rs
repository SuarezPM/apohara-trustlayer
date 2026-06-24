//! Trust gate: a per-agent allowlist of DIDs whose signed Band
//! messages the orchestrator will accept.
//!
//! G20 / ASI07 (Inter-Agent): only messages whose DID is in the
//! trust set AND whose Ed25519 signature verifies against that
//! DID's pubkey (within the 60s timestamp skew window) are let
//! through. A test-only flag allows unsigned messages for the
//! existing mock BandClient integration tests.

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use crate::signed_message::{verify, Did, SignedMessage, SignedMessageError};

/// Per-DID allowlist. The orchestrator constructs one of these at
/// startup with the DIDs of every known peer (Extractor, PO
/// Matcher, Fraud Auditor, GAAP Classifier, Provenance Signer,
/// and the cross-framework peers arriving in C-12).
#[derive(Debug)]
pub struct TrustGate {
    /// DID -> verifying key. Every accepted message must come from
    /// one of these identities AND be signed by the matching key.
    pub known_dids: HashMap<Did, VerifyingKey>,
    /// When `true`, the gate accepts messages whose DID is NOT in
    /// `known_dids` (provided the signature still verifies). This
    /// exists only for the existing mock BandClient integration
    /// tests; production code must leave this `false`.
    pub allow_unsigned_for_testing: bool,
}

/// Errors from `TrustGate::check`.
#[derive(Debug, Error)]
pub enum TrustGateError {
    /// The signature, did format, or timestamp was bad.
    #[error(transparent)]
    Signed(#[from] SignedMessageError),
    /// The message's DID is not in the trust set.
    #[error("did not in trust set: {0}")]
    UntrustedDid(String),
}

impl TrustGate {
    /// New gate. `allow_unsigned_for_testing=true` is the test
    /// escape hatch — production callers must pass `false`.
    pub fn new(allow_unsigned_for_testing: bool) -> Self {
        Self {
            known_dids: HashMap::new(),
            allow_unsigned_for_testing,
        }
    }

    /// Add a DID -> verifying-key pair to the trust set.
    pub fn trust(&mut self, did: Did, pubkey: VerifyingKey) {
        self.known_dids.insert(did, pubkey);
    }

    /// Number of trusted DIDs (for tests / telemetry).
    pub fn len(&self) -> usize {
        self.known_dids.len()
    }

    /// `true` iff no DIDs are trusted.
    pub fn is_empty(&self) -> bool {
        self.known_dids.is_empty()
    }

    /// Check a `SignedMessage` against the trust gate. Verifies
    /// the signature + timestamp, then ensures the sender is in
    /// the trust set (or `allow_unsigned_for_testing` is on).
    pub fn check(&self, msg: &SignedMessage, now_ms: i64) -> Result<(), TrustGateError> {
        // 1) Signature + timestamp.
        verify(msg, now_ms)?;
        // 2) DID in trust set (unless test flag is on).
        if !self.known_dids.contains_key(&msg.did) && !self.allow_unsigned_for_testing {
            return Err(TrustGateError::UntrustedDid(msg.did.to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_message::sign;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    fn fresh_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn check_accepts_trusted_signed() {
        let sk = fresh_key();
        let pk = sk.verifying_key();
        let did = Did::from_verifying_key(&pk);
        let mut gate = TrustGate::new(false);
        gate.trust(did.clone(), pk);
        let msg = sign(
            serde_json::json!({"action": "approve"}),
            &sk,
            1_700_000_000_000,
        );
        assert!(gate.check(&msg, 1_700_000_000_000).is_ok());
    }

    #[test]
    fn check_rejects_untrusted_did() {
        let sk = fresh_key();
        let did = Did::from_verifying_key(&sk.verifying_key());
        let gate = TrustGate::new(false); // empty trust set
        let msg = sign(
            serde_json::json!({"action": "approve"}),
            &sk,
            1_700_000_000_000,
        );
        let err = gate.check(&msg, 1_700_000_000_000).unwrap_err();
        assert!(matches!(err, TrustGateError::UntrustedDid(d) if d == did.to_string()));
    }

    #[test]
    fn check_rejects_unsigned_when_disallowed() {
        // The "disallowed" path is the same code path as
        // `check_rejects_untrusted_did` — covered there. This test
        // explicitly asserts the test flag is `false` by default.
        let gate = TrustGate::new(false);
        assert!(!gate.allow_unsigned_for_testing);
    }

    #[test]
    fn check_accepts_unsigned_when_test_flag() {
        let sk = fresh_key();
        let gate = TrustGate::new(true); // test flag on
        let msg = sign(
            serde_json::json!({"action": "approve"}),
            &sk,
            1_700_000_000_000,
        );
        assert!(gate.check(&msg, 1_700_000_000_000).is_ok());
    }
}
