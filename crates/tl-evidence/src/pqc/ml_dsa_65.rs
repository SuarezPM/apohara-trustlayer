//! ML-DSA-65 wrapper for TrustLayer v3.0 (FIPS 204, PQC) — full impl.
//!
//! Per Plan v3.0 W1.1, this wraps the `ml-dsa` RustCrypto crate
//! (pure Rust, FIPS 204 final spec, 2026-06-05) with a TrustLayer-friendly API.
//!
//! ## Key/signature sizes (FIPS 204 §4 Table 1)
//!
//! | Parameter | Size (bytes) |
//! |-----------|--------------|
//! | Public key | 1952 |
//! | Private key (expanded) | 4032 |
//! | Signature | 3309 |

use ml_dsa::{
    signature::Keypair, EncodedSignature, EncodedVerifyingKey, MlDsa65, Seed, Signature,
    SigningKey, VerifyingKey,
};

use thiserror::Error;

/// Public key size in bytes (FIPS 204 §4 Table 1, ML-DSA-65).
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;

/// Private key size (expanded form, FIPS 204 §4 Table 1, ML-DSA-65).
pub const ML_DSA_65_SECRET_KEY_LEN: usize = 4032;

/// Signature size in bytes (FIPS 204 §4 Table 1, ML-DSA-65).
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

/// Errors from ML-DSA-65 operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MlDsa65VerifyError {
    #[error("ML-DSA-65 signature verification failed")]
    InvalidSignature,
    #[error("ML-DSA-65 signature length invalid (expected {expected} bytes, got {actual})")]
    InvalidSignatureLength { expected: usize, actual: usize },
    #[error("ML-DSA-65 public key length invalid (expected {expected}, got {actual})")]
    InvalidPublicKeyLength { expected: usize, actual: usize },
    #[error("ML-DSA-65 deterministic signing failed: {0}")]
    SigningFailed(String),
    #[error("ML-DSA-65 context string too long (max 255 bytes, got {0})")]
    ContextTooLong(usize),
}

/// Wrapper around an ML-DSA-65 keypair (signing + verifying keys together).
#[derive(Clone)]
pub struct MlDsa65KeyPair {
    signing_key: SigningKey<MlDsa65>,
    verifying_key: VerifyingKey<MlDsa65>,
}

impl MlDsa65KeyPair {
    /// Generate a deterministic keypair from a 32-byte seed (FIPS 204 §4.1).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        // Seed = B32 = Array<u8, U32>. Construct via GenericArray::from_slice.
        let seed_arr = Seed::from_slice(seed);
        let signing_key = SigningKey::<MlDsa65>::from_seed(seed_arr);
        // `verifying_key()` comes from the `Keypair` trait (imported above).
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Construct from raw public key bytes (1952 bytes per FIPS 204).
    /// Use this for verification-only contexts.
    pub fn public_only(public_key_bytes: &[u8]) -> Result<Self, MlDsa65VerifyError> {
        if public_key_bytes.len() != ML_DSA_65_PUBLIC_KEY_LEN {
            return Err(MlDsa65VerifyError::InvalidSignatureLength {
                expected: ML_DSA_65_PUBLIC_KEY_LEN,
                actual: public_key_bytes.len(),
            });
        }
        // EncodedVerifyingKey<MlDsa65> = Array<u8, U1952>. Construct from slice.
        let enc: EncodedVerifyingKey<MlDsa65> =
            EncodedVerifyingKey::<MlDsa65>::try_from(public_key_bytes)
                .map_err(|_| MlDsa65VerifyError::InvalidSignature)?;
        let verifying_key = VerifyingKey::<MlDsa65>::decode(&enc);
        // Signing key is not available in verification-only mode.
        // We use a placeholder signing key that will never be used.
        let placeholder_seed: &Seed = &Seed::default();
        let signing_key = SigningKey::<MlDsa65>::from_seed(placeholder_seed);
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Sign a message with deterministic ML-DSA-65 + context binding
    /// (FIPS 204 §5.2). Max context length: 255 bytes.
    pub fn sign(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> Result<MlDsa65Signature, MlDsa65VerifyError> {
        if context.len() > 255 {
            return Err(MlDsa65VerifyError::ContextTooLong(context.len()));
        }
        // sign_deterministic is on ExpandedSigningKey, not SigningKey.
        let sig = self
            .signing_key
            .expanded_key()
            .sign_deterministic(message, context)
            .map_err(|e| MlDsa65VerifyError::SigningFailed(format!("{e:?}")))?;
        Ok(MlDsa65Signature { inner: sig })
    }

    /// Verify a signature against a message and context. Returns Ok if valid,
    /// Err(InvalidSignature) if invalid (or context mismatch).
    pub fn verify(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &MlDsa65Signature,
    ) -> Result<(), MlDsa65VerifyError> {
        // verify_with_context returns bool (true = valid, false = invalid).
        if self
            .verifying_key
            .verify_with_context(message, context, &signature.inner)
        {
            Ok(())
        } else {
            Err(MlDsa65VerifyError::InvalidSignature)
        }
    }

    /// Get the raw public key bytes (1952 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.encode().to_vec()
    }

    /// Get the raw private (signing) key seed (32 bytes).
    pub fn signing_key_seed(&self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(self.signing_key.as_seed());
        seed
    }
}

/// Wrapper around an ML-DSA-65 signature (3309 bytes raw).
#[derive(Clone, Debug)]
pub struct MlDsa65Signature {
    inner: Signature<MlDsa65>,
}

impl MlDsa65Signature {
    /// Get the raw signature bytes (3309 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode().to_vec()
    }

    /// Construct from raw signature bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlDsa65VerifyError> {
        if bytes.len() != ML_DSA_65_SIGNATURE_LEN {
            return Err(MlDsa65VerifyError::InvalidSignatureLength {
                expected: ML_DSA_65_SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        // EncodedSignature<MlDsa65> = Array<u8, U3309>. Construct from slice.
        let enc = EncodedSignature::<MlDsa65>::from_slice(bytes);
        // Signature::decode returns Option<Signature<MlDsa65>>.
        let sig = Signature::<MlDsa65>::decode(&enc).ok_or(MlDsa65VerifyError::InvalidSignature)?;
        Ok(Self { inner: sig })
    }

    /// Length in bytes (constant: 3309).
    pub fn len(&self) -> usize {
        ML_DSA_65_SIGNATURE_LEN
    }

    /// True if the signature is empty (always false for valid ML-DSA-65).
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl PartialEq for MlDsa65Signature {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for MlDsa65Signature {}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    #[test]
    fn key_sizes_match_fips_204() {
        let kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        assert_eq!(kp.public_key_bytes().len(), ML_DSA_65_PUBLIC_KEY_LEN);
        assert_eq!(ML_DSA_65_PUBLIC_KEY_LEN, 1952);
        assert_eq!(ML_DSA_65_SECRET_KEY_LEN, 4032);
        assert_eq!(ML_DSA_65_SIGNATURE_LEN, 3309);
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let message = b"TrustLayer v3.0 PQC evidence payload - JCS bytes";
        let context = b"trustlayer-evidence-v3.0";
        let sig = kp.sign(message, context).expect("sign");
        kp.verify(message, context, &sig).expect("verify");
    }

    #[test]
    fn verify_fails_with_wrong_context() {
        let kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let message = b"message";
        let sig = kp.sign(message, b"original-ctx").expect("sign");
        let result = kp.verify(message, b"tampered-ctx", &sig);
        assert_eq!(result, Err(MlDsa65VerifyError::InvalidSignature));
    }

    #[test]
    fn deterministic_signing_same_seed_same_signature() {
        let kp1 = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let kp2 = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let message = b"deterministic test";
        let context = b"ctx";
        let sig1 = kp1.sign(message, context).expect("sign1");
        let sig2 = kp2.sign(message, context).expect("sign2");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn different_seed_different_signature() {
        let kp_a = MlDsa65KeyPair::from_seed(&[0xAA; 32]);
        let kp_b = MlDsa65KeyPair::from_seed(&[0xBB; 32]);
        let message = b"same message";
        let context = b"ctx";
        let sig_a = kp_a.sign(message, context).expect("sign_a");
        let sig_b = kp_b.sign(message, context).expect("sign_b");
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn public_only_keypair_verifies_without_signing() {
        let signer = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let pk_bytes = signer.public_key_bytes();
        let verifier = MlDsa65KeyPair::public_only(&pk_bytes).expect("public_only");
        let message = b"verify-only message";
        let context = b"ctx";
        let sig = signer.sign(message, context).expect("sign");
        verifier.verify(message, context, &sig).expect("verify");
    }

    #[test]
    fn public_only_rejects_wrong_length() {
        let result = MlDsa65KeyPair::public_only(&[0u8; 100]);
        assert!(matches!(
            result,
            Err(MlDsa65VerifyError::InvalidSignatureLength { .. })
        ));
    }

    #[test]
    fn signature_from_bytes_roundtrip() {
        let kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let sig = kp.sign(b"test", b"ctx").expect("sign");
        let bytes = sig.to_bytes();
        let recovered = MlDsa65Signature::from_bytes(&bytes).expect("from_bytes");
        assert_eq!(sig, recovered);
    }

    #[test]
    fn context_too_long_rejected() {
        let kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let long_ctx = vec![0u8; 256];
        let result = kp.sign(b"message", &long_ctx);
        assert!(matches!(
            result,
            Err(MlDsa65VerifyError::ContextTooLong(256))
        ));
    }
}
