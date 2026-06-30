//! Ed25519-signed Band messages with `did:key` sender identity.
//!
//! G20 / ASI07 (Inter-Agent): every Band message that flows
//! between THEMIS agents MUST carry an Ed25519 signature over the
//! canonical (JCS-sorted-keys) JSON of its body, with the sender
//! identified by a `did:key` derived from the signer's public key.
//!
//! Wire format (all hex-encoded for transport):
//!
//! ```text
//! SignedMessage {
//!     did: Did { method: "did:key", id: "z6Mk..." },
//!     body: <arbitrary serde_json::Value>,
//!     signature_hex: <128 hex chars / 64 bytes Ed25519 signature>,
//!     timestamp_ms: <i64 unix epoch ms>,
//! }
//! ```
//!
//! The signature is computed over `canonicalize(body) || timestamp_ms_be`.
//! We append the timestamp AFTER the body to bind it to the message
//! (preventing an attacker from replaying an old body with a fresh
//! timestamp). The receiver checks `|now - timestamp_ms| <= 60s`.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum permitted clock skew between sender and receiver (60s).
/// Messages older than `now - MAX_TIMESTAMP_SKEW_MS` or more than
/// `MAX_TIMESTAMP_SKEW_MS` in the future are rejected.
pub const MAX_TIMESTAMP_SKEW_MS: i64 = 60_000;

/// Multicodec prefix for Ed25519 public keys in `did:key`.
/// 0xED = ed25519-pub, base58btc-encoded (the `z6Mk...` prefix).
const ED25519_PUB_MULTICODEC: [u8; 2] = [0xED, 0x01];

/// A Decentralized Identifier. Currently only `did:key` with the
/// Ed25519 multicodec (`z6Mk...`) is supported. This is the W3C
/// DID-Core compliant representation: a method prefix + a
/// method-specific identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did {
    /// DID method. Must be `"did:key"` for `Did::from_verifying_key`.
    pub method: String,
    /// Method-specific id (e.g. `"z6Mk..."` for `did:key` + Ed25519).
    pub id: String,
}

impl Did {
    /// Construct a `did:key` from an Ed25519 verifying key.
    /// Produces `"did:key:z6Mk<base58btc(0xED01 || pubkey)>"`.
    pub fn from_verifying_key(pk: &VerifyingKey) -> Self {
        let mut prefixed = Vec::with_capacity(2 + 32);
        prefixed.extend_from_slice(&ED25519_PUB_MULTICODEC);
        prefixed.extend_from_slice(pk.to_bytes().as_slice());
        Self {
            method: "did:key".to_string(),
            id: format!("z6Mk{}", bs58_encode(&prefixed)),
        }
    }

    /// Render the full DID string (`"did:key:z6Mk..."`).
    pub fn as_string(&self) -> String {
        format!("{}:{}", self.method, self.id)
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.method, self.id)
    }
}

/// A Band message signed by the sender's Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMessage {
    /// Sender identity (DID).
    pub did: Did,
    /// Arbitrary JSON body. The signature covers the canonical-JCS
    /// bytes of this value concatenated with `timestamp_ms`.
    pub body: serde_json::Value,
    /// Hex-encoded Ed25519 signature (128 hex chars / 64 bytes).
    pub signature_hex: String,
    /// Unix epoch ms when the message was signed.
    pub timestamp_ms: i64,
}

/// Errors from sign/verify.
#[derive(Debug, Error)]
pub enum SignedMessageError {
    /// The `did:key` could not be parsed (wrong method, bad base58,
    /// wrong multicodec prefix, or wrong pubkey length).
    #[error("invalid did:key format")]
    InvalidDid,
    /// The Ed25519 signature did not verify against the body + ts.
    #[error("signature verification failed")]
    InvalidSignature,
    /// The message timestamp is outside the acceptable skew window.
    #[error("message timestamp skew > 60s")]
    TimestampSkew,
    /// The body could not be canonicalized (should never happen
    /// for a `serde_json::Value` we built ourselves; surfaces bugs).
    #[error("canonicalize body: {0}")]
    Canonicalize(String),
    /// Hex decoding of `signature_hex` failed.
    #[error("hex decode: {0}")]
    Hex(String),
}

/// Sign a body. Produces a `SignedMessage` whose signature covers
/// `canonicalize(body) || timestamp_ms_be`.
pub fn sign(body: serde_json::Value, signing_key: &SigningKey, timestamp_ms: i64) -> SignedMessage {
    let pk = signing_key.verifying_key();
    let did = Did::from_verifying_key(&pk);
    let message_bytes = signed_payload(&body, timestamp_ms);
    let sig = signing_key.sign(&message_bytes);
    SignedMessage {
        did,
        body,
        signature_hex: hex::encode(sig.to_bytes()),
        timestamp_ms,
    }
}

/// Verify a `SignedMessage` in isolation (no trust-set check).
/// Rejects messages whose timestamp is outside `MAX_TIMESTAMP_SKEW_MS`
/// of `now_ms`, whose DID does not match the signature's pubkey,
/// or whose signature is invalid.
pub fn verify(msg: &SignedMessage, now_ms: i64) -> Result<(), SignedMessageError> {
    let skew = (msg.timestamp_ms - now_ms).abs();
    if skew > MAX_TIMESTAMP_SKEW_MS {
        return Err(SignedMessageError::TimestampSkew);
    }
    let pk = did_to_verifying_key(&msg.did)?;
    let message_bytes = signed_payload(&msg.body, msg.timestamp_ms);
    let sig_bytes =
        hex::decode(&msg.signature_hex).map_err(|e| SignedMessageError::Hex(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(SignedMessageError::InvalidSignature);
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = ed25519_dalek::Signature::from_bytes(&arr);
    pk.verify_strict(&message_bytes, &sig)
        .map_err(|_| SignedMessageError::InvalidSignature)
}

// --- internals ---

/// Build the bytes that the Ed25519 signature actually covers:
/// `canonicalize(body) || timestamp_ms.to_be_bytes()`.
fn signed_payload(body: &serde_json::Value, timestamp_ms: i64) -> Vec<u8> {
    let mut out = serde_json_canonicalizer::to_vec(body)
        .expect("serde_json::Value canonicalization is infallible");
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    out
}

/// Recover the Ed25519 verifying key from a `did:key`.
fn did_to_verifying_key(did: &Did) -> Result<VerifyingKey, SignedMessageError> {
    if did.method != "did:key" {
        return Err(SignedMessageError::InvalidDid);
    }
    let id = did
        .id
        .strip_prefix("z6Mk")
        .ok_or(SignedMessageError::InvalidDid)?;
    let raw = bs58_decode(id).ok_or(SignedMessageError::InvalidDid)?;
    if raw.len() != 2 + 32 || raw[..2] != ED25519_PUB_MULTICODEC {
        return Err(SignedMessageError::InvalidDid);
    }
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&raw[2..]);
    VerifyingKey::from_bytes(&pk_bytes).map_err(|_| SignedMessageError::InvalidDid)
}

// --- base58btc (Bitcoin alphabet) ---

fn bs58_encode(input: &[u8]) -> String {
    bs58::encode(input).into_string()
}

fn bs58_decode(input: &str) -> Option<Vec<u8>> {
    bs58::decode(input).into_vec().ok()
}

// --- unit tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn fresh_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = fresh_key();
        let body = serde_json::json!({"action": "halt", "invoice_id": "inv-001"});
        let now: i64 = 1_700_000_000_000;
        let msg = sign(body.clone(), &sk, now);
        assert!(verify(&msg, now).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let sk = fresh_key();
        let body = serde_json::json!({"action": "approve"});
        let now: i64 = 1_700_000_000_000;
        let mut msg = sign(body, &sk, now);
        msg.body = serde_json::json!({"action": "halt"});
        let err = verify(&msg, now).unwrap_err();
        assert!(matches!(err, SignedMessageError::InvalidSignature));
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let sk = fresh_key();
        let body = serde_json::json!({"action": "approve"});
        let now: i64 = 1_700_000_000_000;
        let mut msg = sign(body, &sk, now);
        // Flip a hex char in the signature.
        let bad = format!("ff{}", &msg.signature_hex[2..]);
        msg.signature_hex = bad;
        let err = verify(&msg, now).unwrap_err();
        assert!(matches!(err, SignedMessageError::InvalidSignature));
    }

    #[test]
    fn verify_rejects_did_mismatch() {
        let sk1 = fresh_key();
        let sk2 = fresh_key();
        let body = serde_json::json!({"action": "approve"});
        let now: i64 = 1_700_000_000_000;
        // Sign with sk1 but lie about the did (use sk2's pubkey).
        let mut msg = sign(body, &sk1, now);
        msg.did = Did::from_verifying_key(&sk2.verifying_key());
        let err = verify(&msg, now).unwrap_err();
        assert!(matches!(err, SignedMessageError::InvalidSignature));
    }

    #[test]
    fn verify_rejects_old_timestamp() {
        let sk = fresh_key();
        let body = serde_json::json!({"action": "approve"});
        let now: i64 = 1_700_000_000_000;
        // Sign 2 minutes in the past — exceeds the 60s skew window.
        let old = sign(body, &sk, now - 120_000);
        let err = verify(&old, now).unwrap_err();
        assert!(matches!(err, SignedMessageError::TimestampSkew));
    }

    #[test]
    fn did_roundtrip_recovers_verifying_key() {
        let sk = fresh_key();
        let pk = sk.verifying_key();
        let did = Did::from_verifying_key(&pk);
        let recovered = did_to_verifying_key(&did).unwrap();
        assert_eq!(recovered.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn did_display_is_method_colon_id() {
        let sk = fresh_key();
        let did = Did::from_verifying_key(&sk.verifying_key());
        assert!(did.as_string().starts_with("did:key:z6Mk"));
    }

    #[test]
    fn canonicalize_is_key_order_independent() {
        // JCS sorts object keys lexicographically, so semantically
        // equal bodies produce byte-identical signatures.
        let sk = fresh_key();
        let now: i64 = 1_700_000_000_000;
        let a = serde_json::json!({"a": 1, "b": 2, "c": 3});
        let b = serde_json::json!({"c": 3, "a": 1, "b": 2});
        let sa = sign(a, &sk, now).signature_hex;
        let sb = sign(b, &sk, now).signature_hex;
        assert_eq!(sa, sb);
    }

    // Ensure the hashing of types referenced in this module doesn't drift.
    #[allow(dead_code)]
    fn _types_anchor() {}
}
