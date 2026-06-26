//! did:key ML-DSA-65 identifier encoding (multicodec 0x1211 + base58btc).
//!
//! Per Plan v3.0 W1.1, this implements the Attestix v0.4.1 convention
//! for encoding ML-DSA-65 public keys as `did:key` identifiers.

use crate::pqc::ml_dsa_65::{MlDsa65KeyPair, ML_DSA_65_PUBLIC_KEY_LEN};

/// Multicodec prefix for ML-DSA-65 public key.
///
/// LEB128 unsigned varint encoding of `0x1211`:
/// - First byte: `0x11 | 0x80` (low 7 bits + continuation bit) = `0x91`
/// - Second byte: `0x24` (next 7 bits)
///
/// Per [multiformats/multicodec table.csv](https://github.com/multiformats/multicodec/blob/master/table.csv).
pub const ML_DSA_65_MULTICODEC_PREFIX: [u8; 2] = [0x91, 0x24];

/// Errors from did:key ML-DSA-65 encoding/decoding.
#[derive(Debug, PartialEq, Eq)]
pub enum DidKeyError {
    InvalidPublicKeyLength { expected: usize, actual: usize },
    InvalidMethod,
    InvalidMultibase,
    InvalidMulticodec,
    Base58DecodeError(String),
}

/// Encode an ML-DSA-65 public key as a `did:key:z...` identifier.
pub fn mldsa65_public_key_to_did_key(public_key: &[u8]) -> String {
    let mut buf = Vec::with_capacity(ML_DSA_65_MULTICODEC_PREFIX.len() + public_key.len());
    buf.extend_from_slice(&ML_DSA_65_MULTICODEC_PREFIX);
    buf.extend_from_slice(public_key);
    let encoded = bs58::encode(buf).into_string();
    format!("did:key:z{encoded}")
}

/// Convenience: encode from a `MlDsa65KeyPair`.
pub fn ml_dsa_65_keypair_to_did_key(kp: &MlDsa65KeyPair) -> String {
    mldsa65_public_key_to_did_key(&kp.public_key_bytes())
}

/// Decode a `did:key:z...` identifier back to the raw ML-DSA-65 public key.
pub fn did_key_to_mldsa65_public_key(did: &str) -> Result<Vec<u8>, DidKeyError> {
    let without_prefix = did
        .strip_prefix("did:key:")
        .ok_or(DidKeyError::InvalidMethod)?;
    let b58 = without_prefix
        .strip_prefix('z')
        .ok_or(DidKeyError::InvalidMultibase)?;
    let decoded = bs58::decode(b58)
        .into_vec()
        .map_err(|e| DidKeyError::Base58DecodeError(e.to_string()))?;
    if decoded.len() < ML_DSA_65_MULTICODEC_PREFIX.len() {
        return Err(DidKeyError::InvalidMulticodec);
    }
    let (prefix, key) = decoded.split_at(ML_DSA_65_MULTICODEC_PREFIX.len());
    if prefix != ML_DSA_65_MULTICODEC_PREFIX {
        return Err(DidKeyError::InvalidMulticodec);
    }
    if key.len() != ML_DSA_65_PUBLIC_KEY_LEN {
        return Err(DidKeyError::InvalidPublicKeyLength {
            expected: ML_DSA_65_PUBLIC_KEY_LEN,
            actual: key.len(),
        });
    }
    Ok(key.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    #[test]
    fn multicodec_prefix_matches_spec() {
        assert_eq!(ML_DSA_65_MULTICODEC_PREFIX, [0x91, 0x24]);
    }

    #[test]
    fn encode_produces_did_key_z_prefix() {
        let kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let did = ml_dsa_65_keypair_to_did_key(&kp);
        assert!(did.starts_with("did:key:z"));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let kp = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let original = kp.public_key_bytes();
        let did = ml_dsa_65_keypair_to_did_key(&kp);
        let decoded = did_key_to_mldsa65_public_key(&did).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_is_deterministic() {
        let kp1 = MlDsa65KeyPair::from_seed(&TEST_SEED);
        let kp2 = MlDsa65KeyPair::from_seed(&TEST_SEED);
        assert_eq!(ml_dsa_65_keypair_to_did_key(&kp1), ml_dsa_65_keypair_to_did_key(&kp2));
    }

    #[test]
    fn decode_rejects_wrong_method() {
        let result = did_key_to_mldsa65_public_key("did:web:example.com");
        assert_eq!(result, Err(DidKeyError::InvalidMethod));
    }

    #[test]
    fn decode_rejects_wrong_multibase() {
        let result = did_key_to_mldsa65_public_key("did:key:k...");
        assert_eq!(result, Err(DidKeyError::InvalidMultibase));
    }

    #[test]
    fn decode_rejects_wrong_key_length() {
        let fake = bs58::encode(
            [0x91u8, 0x24]
                .iter()
                .chain([0u8; 100].iter())
                .copied()
                .collect::<Vec<u8>>(),
        )
        .into_string();
        let did = format!("did:key:z{fake}");
        let result = did_key_to_mldsa65_public_key(&did);
        assert!(matches!(
            result,
            Err(DidKeyError::InvalidPublicKeyLength { expected: 1952, actual: 100 })
        ));
    }
}
