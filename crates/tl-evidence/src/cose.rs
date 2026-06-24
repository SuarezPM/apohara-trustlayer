//! COSE_Sign1 wrapper over coset.
//!
//! Per plan v3.1 ADR-002: all exported artifacts (DisclosureRecord,
//! VerificationReceipt, EvidenceBundle, ToolExecutionReceipt) use
//! COSE_Sign1 (RFC 9052). This module provides the thin envelope
//! type + sign/verify primitives that `tl-evidence` exposes.
//!
//! ## Why coset
//!
//! coset crate is the Rust reference implementation of COSE_Sign1 /
//! COSE_Encrypt / etc. (RFC 8152 → RFC 9052). Pinned to v0.4.2 (the
//! crate README says "under construction" — we lock to a known-good
//! version, plan v3.1 AC-20).
//!
//! ## Example (mirrors coset's examples/signature.rs)
//!
//! ```ignore
//! use coset::{iana, HeaderBuilder, CoseSign1Builder, CoseSign1, CborSerializable};
//!
//! let protected = HeaderBuilder::new()
//!     .algorithm(iana::Algorithm::EdDSA)
//!     .build();
//! let sign1 = CoseSign1Builder::new()
//!     .protected(protected)
//!     .payload(b"hello".to_vec())
//!     .create_signature(b"", |pt| ed25519_sign(pt))
//!     .build();
//! ```

#![warn(missing_docs)]

use coset::{
    iana, CborSerializable, CoseError as CosetError, CoseSign1, CoseSign1Builder, HeaderBuilder,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Re-exported coset types (for downstream crates to use without
/// importing coset directly).
pub use coset;

/// Errors emitted by the COSE layer.
#[derive(Debug, Error)]
pub enum CoseError {
    /// coset returned an error.
    #[error("COSE operation failed: {0}")]
    Coset(#[from] CosetError),
}

/// Re-exported COSE_Sign1 with builder + verify helpers.
pub struct CoseSignature {
    inner: CoseSign1,
}

impl CoseSignature {
    /// Create a new COSE_Sign1 with EdDSA over Ed25519 (default).
    ///
    /// `signing_fn` takes the serialized `Sig_structure` (per RFC 9052
    /// §4.4) and returns the signature bytes (Ed25519: 64 bytes).
    /// `external_aad` is additional authenticated data (typically empty).
/// THREAT: Signing key material is constructed in this function.
/// The closure receives the to-be-signed data and returns raw signature
/// bytes. (1) If the closure leaks the signature bytes to non-TLS
/// transport, the signature is forgeable by anyone. (2) The closure
/// MUST NOT call any network/IO — signing must be deterministic and
/// pure-functional. (3) Constant-time signing via ed25519-dalek's
/// `sign` API; this function passes through to it. (4) This function
/// is NEVER exposed to the Python SDK (Architect IC-2 strict:
/// signing is server-side only per plan v3.1 §Risks R10). It is only
/// called by the Rust-side control plane.
    pub fn ed25519<F>(
        payload: Vec<u8>,
        external_aad: &[u8],
        signing_fn: F,
    ) -> Result<Self, CoseError>
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(external_aad, signing_fn)
            .build();
        Ok(Self { inner: sign1 })
    }

    /// Verify the signature against a verification closure.
    /// `verify_fn` takes (signature_bytes, to_be_signed_data) and returns
    /// `Result<(), CoseError>` (Ok if valid).
    /// Returns Ok(true) on success, Ok(false) when the closure reports invalid
    /// OR when coset's verify_signature fails (signature mismatch).
    /// `external_aad` must match the value used at sign time.
    pub fn verify<F>(&self, external_aad: &[u8], verify_fn: F) -> Result<bool, CoseError>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<(), CosetError>,
    {
        let mut sign1_clone = self.inner.clone();
        // coset's verify_signature returns Err for ANY verification failure
        // (closure reports invalid, AAD mismatch, signature malformed, etc.).
        // We collapse all of these to Ok(false) since the caller can't
        // distinguish the failure modes meaningfully — they're all "the
        // signature didn't validate." If the caller needs to know why,
        // they can use coset::CoseSign1 directly.
        match sign1_clone.verify_signature(external_aad, verify_fn) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Borrow the underlying coset CoseSign1.
    pub fn inner(&self) -> &CoseSign1 {
        &self.inner
    }

    /// Serialize to CBOR bytes (RFC 8949).
    pub fn to_cbor(&self) -> Result<Vec<u8>, CoseError> {
        Ok(self.inner.clone().to_vec()?)
    }

    /// Deserialize from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CoseError> {
        let inner = CoseSign1::from_slice(bytes)?;
        Ok(Self { inner })
    }
}

/// Re-exported with serde for use in evidence bundles.
impl Serialize for CoseSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_cbor().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for CoseSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8> as Deserialize>::deserialize(deserializer)?;
        Self::from_cbor(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn cose_sign1_sign_and_verify_roundtrip() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let payload = b"hello world".to_vec();

        let cose = CoseSignature::ed25519(payload, b"", |tbs| {
            key.sign(tbs).to_bytes().to_vec()
        })
        .unwrap();

        let verified = cose
            .verify(b"", |sig, tbs| {
                let sig_arr: [u8; 64] = sig.try_into().unwrap();
                key.verify_strict(tbs, &ed25519_dalek::Signature::from_bytes(&sig_arr))
                    .map_err(|_| CosetError::UnregisteredIanaValue)
            })
            .unwrap();
        assert!(verified);
    }

    #[test]
    fn cose_sign1_serialize_deserialize_roundtrip() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let payload = b"another payload".to_vec();

        let cose = CoseSignature::ed25519(payload, b"", |tbs| key.sign(tbs).to_bytes().to_vec()).unwrap();
        let bytes = cose.to_cbor().unwrap();
        let restored = CoseSignature::from_cbor(&bytes).unwrap();
        let verified = restored
            .verify(b"", |sig, tbs| {
                let sig_arr: [u8; 64] = sig.try_into().unwrap();
                key.verify_strict(tbs, &ed25519_dalek::Signature::from_bytes(&sig_arr))
                    .map_err(|_| CosetError::UnregisteredIanaValue)
            })
            .unwrap();
        assert!(verified);
    }

    #[test]
    fn cose_sign1_with_external_aad() {
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let payload = b"with aad".to_vec();

        let cose = CoseSignature::ed25519(payload, b"aad-bytes", |tbs| {
            key.sign(tbs).to_bytes().to_vec()
        })
        .unwrap();

        // Verify with wrong AAD should fail.
        let wrong = cose
            .verify(b"wrong-aad", |sig, tbs| {
                let sig_arr: [u8; 64] = sig.try_into().unwrap();
                key.verify_strict(tbs, &ed25519_dalek::Signature::from_bytes(&sig_arr))
                    .map_err(|_| CosetError::UnregisteredIanaValue)
            })
            .unwrap();
        assert!(!wrong);

        // Verify with correct AAD should succeed.
        let right = cose
            .verify(b"aad-bytes", |sig, tbs| {
                let sig_arr: [u8; 64] = sig.try_into().unwrap();
                key.verify_strict(tbs, &ed25519_dalek::Signature::from_bytes(&sig_arr))
                    .map_err(|_| CosetError::UnregisteredIanaValue)
            })
            .unwrap();
        assert!(right);
    }
}
