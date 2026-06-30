//! Post-Quantum Cryptography (PQC) hybrid signing for TrustLayer v3.0.
//!
//! Per Plan v3.0 W1.1, this module implements:
//! - FIPS 204 ML-DSA-65 signing + verification
//! - Hybrid Ed25519 + ML-DSA-65 composite (Attestix v0.4.1 cryptosuite)
//! - `mldsa65-jcs-2026` cryptosuite (ML-DSA-65 standalone over JCS)
//! - did:key ML-DSA-65 identifier encoding (multicodec 0x1211)

pub mod did_key;
pub mod hybrid;
pub mod ml_dsa_65;

pub use did_key::{
    did_key_to_mldsa65_public_key, ml_dsa_65_keypair_to_did_key, mldsa65_public_key_to_did_key,
    DidKeyError, ML_DSA_65_MULTICODEC_PREFIX,
};
pub use hybrid::{
    hybrid_sign, hybrid_verify, mldsa65_sign, mldsa65_verify, HybridSignatureError, HYBRID_SEP,
    SUITE_HYBRID, SUITE_MLDSA65, TRUSTLAYER_HYBRID_CONTEXT, TRUSTLAYER_MLDSA65_CONTEXT,
};
pub use ml_dsa_65::{
    MlDsa65KeyPair, MlDsa65Signature, MlDsa65VerifyError, ML_DSA_65_PUBLIC_KEY_LEN,
    ML_DSA_65_SECRET_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
