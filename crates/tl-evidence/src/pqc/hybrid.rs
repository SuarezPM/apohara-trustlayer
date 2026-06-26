//! Hybrid Ed25519 + ML-DSA-65 composite signing (Attestix v0.4.1 pattern).
//!
//! Per Plan v3.0 W1.1, this implements the Attestix v0.4.1 cryptosuite
//! `hybrid-ed25519-mldsa65-jcs-2026`:
//!
//! 1. JCS RFC 8785 canonicalization of the JSON payload
//! 2. Both signatures over identical JCS bytes (Ed25519 + ML-DSA-65)
//! 3. Concatenation with `~` separator (base64url-encoded each side)
//! 4. Weak non-separability: verifier MUST validate BOTH signatures

use crate::pqc::ml_dsa_65::{
    MlDsa65KeyPair, MlDsa65Signature, MlDsa65VerifyError, ML_DSA_65_SIGNATURE_LEN,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, Signer as Ed25519Signer, Verifier as Ed25519Verifier};
use thiserror::Error;

/// Cryptosuite identifier for hybrid Ed25519 + ML-DSA-65 signatures.
pub const SUITE_HYBRID: &str = "hybrid-ed25519-mldsa65-jcs-2026";

/// Cryptosuite identifier for ML-DSA-65 standalone signatures.
pub const SUITE_MLDSA65: &str = "mldsa65-jcs-2026";

/// Separator between the two halves of a hybrid proof value.
pub const HYBRID_SEP: char = '~';

/// Context string for hybrid signatures (FIPS 204 §5.2).
pub const TRUSTLAYER_HYBRID_CONTEXT: &[u8] = b"trustlayer-v3.0-hybrid-ed25519-mldsa65-jcs-2026";

/// Context string for ML-DSA-65 standalone signatures.
pub const TRUSTLAYER_MLDSA65_CONTEXT: &[u8] = b"trustlayer-v3.0-mldsa65-jcs-2026";

/// Errors from hybrid signature operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HybridSignatureError {
    #[error("hybrid signature must contain '{sep}' separator", sep = HYBRID_SEP)]
    MissingSeparator,
    #[error("hybrid signature has empty Ed25519 half")]
    EmptyEd25519Half,
    #[error("hybrid signature has empty ML-DSA-65 half")]
    EmptyMlDsa65Half,
    #[error("Ed25519 signature base64url decode failed: {0}")]
    Ed25519Base64Error(String),
    #[error("ML-DSA-65 signature base64url decode failed: {0}")]
    MlDsa65Base64Error(String),
    #[error("ML-DSA-65 signature wrong length: expected {expected}, got {actual}")]
    MlDsa65WrongLength { expected: usize, actual: usize },
    #[error("Ed25519 signature verification failed")]
    Ed25519VerifyFailed,
    #[error("ML-DSA-65 signature verification failed")]
    MlDsa65VerifyFailed,
}

/// Produce a hybrid Ed25519 + ML-DSA-65 signature over `jcs_bytes`.
pub fn hybrid_sign(
    ed25519_private: &ed25519_dalek::SigningKey,
    mldsa65: &MlDsa65KeyPair,
    jcs_bytes: &[u8],
) -> String {
    let ed_sig = ed25519_private.sign(jcs_bytes);
    let pq_sig = mldsa65.sign(jcs_bytes, TRUSTLAYER_HYBRID_CONTEXT).expect("ML-DSA-65 sign");
    let ed_b64 = URL_SAFE_NO_PAD.encode(ed_sig.to_bytes());
    let pq_b64 = URL_SAFE_NO_PAD.encode(pq_sig.to_bytes());
    format!("{ed_b64}{sep}{pq_b64}", sep = HYBRID_SEP)
}

/// Verify a hybrid signature against `jcs_bytes`. BOTH signatures MUST validate.
pub fn hybrid_verify(
    ed25519_public: &ed25519_dalek::VerifyingKey,
    mldsa65_public: &MlDsa65KeyPair,
    jcs_bytes: &[u8],
    proof_value: &str,
) -> Result<(), HybridSignatureError> {
    let sep_pos = proof_value
        .find(HYBRID_SEP)
        .ok_or(HybridSignatureError::MissingSeparator)?;
    let (ed_b64, pq_b64_with_sep) = proof_value.split_at(sep_pos);
    let pq_b64 = &pq_b64_with_sep[HYBRID_SEP.len_utf8()..];

    if ed_b64.is_empty() {
        return Err(HybridSignatureError::EmptyEd25519Half);
    }
    if pq_b64.is_empty() {
        return Err(HybridSignatureError::EmptyMlDsa65Half);
    }

    let ed_bytes = URL_SAFE_NO_PAD
        .decode(ed_b64)
        .map_err(|e| HybridSignatureError::Ed25519Base64Error(e.to_string()))?;
    let ed_sig_array: [u8; 64] = ed_bytes.as_slice().try_into().map_err(|_| {
        HybridSignatureError::Ed25519Base64Error(format!(
            "expected 64 bytes, got {}",
            ed_bytes.len()
        ))
    })?;
    let ed_sig = Ed25519Signature::from_bytes(&ed_sig_array);

    let pq_bytes = URL_SAFE_NO_PAD
        .decode(pq_b64)
        .map_err(|e| HybridSignatureError::MlDsa65Base64Error(e.to_string()))?;
    if pq_bytes.len() != ML_DSA_65_SIGNATURE_LEN {
        return Err(HybridSignatureError::MlDsa65WrongLength {
            expected: ML_DSA_65_SIGNATURE_LEN,
            actual: pq_bytes.len(),
        });
    }
    let pq_sig = MlDsa65Signature::from_bytes(&pq_bytes)
        .map_err(|e: MlDsa65VerifyError| {
            HybridSignatureError::MlDsa65Base64Error(format!("{e:?}"))
        })?;

    ed25519_public
        .verify(jcs_bytes, &ed_sig)
        .map_err(|_| HybridSignatureError::Ed25519VerifyFailed)?;
    mldsa65_public
        .verify(jcs_bytes, TRUSTLAYER_HYBRID_CONTEXT, &pq_sig)
        .map_err(|_| HybridSignatureError::MlDsa65VerifyFailed)?;

    Ok(())
}

/// Sign a payload with ML-DSA-65 standalone (no Ed25519 fallback).
pub fn mldsa65_sign(mldsa65: &MlDsa65KeyPair, jcs_bytes: &[u8]) -> MlDsa65Signature {
    mldsa65.sign(jcs_bytes, TRUSTLAYER_MLDSA65_CONTEXT).expect("ML-DSA-65 sign")
}

/// Verify an ML-DSA-65 standalone signature.
pub fn mldsa65_verify(
    mldsa65_public: &MlDsa65KeyPair,
    jcs_bytes: &[u8],
    signature: &MlDsa65Signature,
) -> Result<(), MlDsa65VerifyError> {
    mldsa65_public.verify(jcs_bytes, TRUSTLAYER_MLDSA65_CONTEXT, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc::ml_dsa_65::MlDsa65KeyPair;

    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    fn ed25519_keypair(seed_byte: u8) -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        let mut bytes = [0u8; 32];
        bytes[0] = seed_byte;
        let sk = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let (ed_sk, ed_vk) = ed25519_keypair(0xAA);
        let mldsa_kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let jcs = br#"{"bundle_id":"b1","rollup":"Compliant"}"#;

        let proof = hybrid_sign(&ed_sk, &mldsa_kp, jcs);
        assert!(proof.contains(HYBRID_SEP));
        hybrid_verify(&ed_vk, &mldsa_kp, jcs, &proof).expect("verify");
    }

    #[test]
    fn hybrid_is_deterministic() {
        let (ed_sk, _) = ed25519_keypair(0xAA);
        let mldsa_kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let jcs = br#"{"deterministic":true}"#;
        let proof1 = hybrid_sign(&ed_sk, &mldsa_kp, jcs);
        let proof2 = hybrid_sign(&ed_sk, &mldsa_kp, jcs);
        assert_eq!(proof1, proof2);
    }

    #[test]
    fn hybrid_rejects_tampered_message() {
        let (ed_sk, ed_vk) = ed25519_keypair(0xAA);
        let mldsa_kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let jcs = br#"{"original":true}"#;
        let tampered = br#"{"original":false}"#;
        let proof = hybrid_sign(&ed_sk, &mldsa_kp, jcs);
        let result = hybrid_verify(&ed_vk, &mldsa_kp, tampered, &proof);
        assert!(result.is_err());
    }

    #[test]
    fn hybrid_rejects_missing_separator() {
        let (_, ed_vk) = ed25519_keypair(0xAA);
        let mldsa_kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let jcs = br#"{"x":1}"#;
        let fake_proof = format!(
            "{}{}",
            URL_SAFE_NO_PAD.encode([0u8; 64]),
            URL_SAFE_NO_PAD.encode([0u8; ML_DSA_65_SIGNATURE_LEN]),
        );
        assert_eq!(
            hybrid_verify(&ed_vk, &mldsa_kp, jcs, &fake_proof),
            Err(HybridSignatureError::MissingSeparator)
        );
    }

    #[test]
    fn hybrid_rejects_wrong_ed25519_key() {
        let (ed_sk, _) = ed25519_keypair(0xAA);
        let mldsa_kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let jcs = br#"{"x":1}"#;
        let proof = hybrid_sign(&ed_sk, &mldsa_kp, jcs);
        let (_, wrong_ed_vk) = ed25519_keypair(0xBB);
        let result = hybrid_verify(&wrong_ed_vk, &mldsa_kp, jcs, &proof);
        assert_eq!(result, Err(HybridSignatureError::Ed25519VerifyFailed));
    }

    #[test]
    fn hybrid_rejects_wrong_mldsa65_key() {
        let (ed_sk, ed_vk) = ed25519_keypair(0xAA);
        let mldsa_kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let jcs = br#"{"x":1}"#;
        let proof = hybrid_sign(&ed_sk, &mldsa_kp, jcs);
        let wrong_mldsa_kp = MlDsa65KeyPair::from_seed(&[0x99; 32]);
        let result = hybrid_verify(&ed_vk, &wrong_mldsa_kp, jcs, &proof);
        assert_eq!(result, Err(HybridSignatureError::MlDsa65VerifyFailed));
    }

    #[test]
    fn hybrid_proof_value_format_is_correct() {
        let (ed_sk, _) = ed25519_keypair(0xAA);
        let mldsa_kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let jcs = br#"{"format":"check"}"#;
        let proof = hybrid_sign(&ed_sk, &mldsa_kp, jcs);
        let sep_count = proof.matches(HYBRID_SEP).count();
        assert_eq!(sep_count, 1);
        let parts: Vec<&str> = proof.splitn(2, HYBRID_SEP).collect();
        assert_eq!(parts.len(), 2);
        // Ed25519 base64url: 64 raw bytes -> 86 chars (no padding)
        assert_eq!(parts[0].len(), 86);
        // ML-DSA-65 base64url: 3309 raw bytes -> 4412 chars (no padding)
        assert_eq!(parts[1].len(), 4412);
    }

    #[test]
    fn mldsa65_standalone_sign_verify_roundtrip() {
        let kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let jcs = br#"{"standalone":true}"#;
        let sig = mldsa65_sign(&kp, jcs);
        mldsa65_verify(&kp, jcs, &sig).expect("verify");
    }
}
