//! tl-scitt — SCITT-native receipts for offline verification.
//!
//! Per **IETF draft-ietf-scitt-scrapi-09** (June 2026), a SCITT receipt
//! is a self-contained, cryptographically-signed assertion that a
//! given issuer has registered a given payload. The `verify_offline`
//! function in this crate is a **pure function** on the receipt and
//! the issuer's public key — it does not contact any registry, any
//! clock, any filesystem, or any environment variable. This is the
//! core property that makes SCITT receipts useful for regulatory
//! evidence: an auditor can verify the receipt in 100% offline mode
//! (R-A-NEW-3 in Plan v1.2, Plan v1.1 Block 2 US-1).
//!
//! ## What is in a SCITT receipt?
//!
//! ```text
//! SCITTReceipt {
//!     payload: Vec<u8>,                          // The artifact being claimed
//!     cose_sign1: Vec<u8>,                       // CBOR-encoded COSE_Sign1
//!     issuer_kid: String,                       // Key identifier
//!     issuer_pubkey_fingerprint: [u8; 32],      // BLAKE3(issuer_pubkey)
//!     inclusion_proof: Option<InclusionProof>,  // None for direct (non-anchored)
//!     issued_at: u64,                            // Unix timestamp, non-authoritative
//!     registry_id: String,                       // Which registry issued this
//! }
//! ```
//!
//! ## Why is `verify_offline` pure?
//!
//! 1. **No network**: The auditor's verification environment may be
//!    air-gapped (e.g. a court receiving a sealed bundle on a USB
//!    drive). Network access would re-introduce the "is the verifier
//!    trustworthy?" question that SCITT is designed to eliminate.
//! 2. **No clock**: Wall-clock time is not part of the cryptographic
//!    claim. `issued_at` is recorded but NOT checked against "now" —
//!    the receipt is a statement of what was true at the time of
//!    issuance, not a statement that "this is still true now".
//! 3. **No filesystem**: Pure in-memory verification means the
//!    verifier can be embedded in a WASM module, a smart contract,
//!    or a constrained embedded device without needing a filesystem.
//! 4. **No environment**: No env vars, no config files. The function
//!    is deterministic: same input → same output, forever.
//!
//! ## Relationship to `tl-evidence`
//!
//! `tl-evidence` produces COSE_Sign1 envelopes and RFC 3161 timestamps.
//! `tl-scitt` is the **higher-level wrapper** that bundles a
//! COSE_Sign1 + the issuer's key fingerprint + (optional) an
//! inclusion proof into a single receipt that an auditor can verify
//! offline. The control plane (Block 2 US-2) exposes both formats
//! via content negotiation.
//!
//! ## What ships in v1.0.5
//!
//! The minimum-viable SCITT surface:
//! - `SCITTReceipt` struct with the 6 fields above
//! - `verify_offline` that checks signature + key-id-fingerprint match
//! - `InclusionProof::None` only (anchored proofs come in v1.0.6
//!   once the IETF draft is stable enough for a production anchor)
//! - Frozen test fixture in `audit_artifacts/test_fixtures/scitt/`
//!   (synthetic, signed with a known key — see Block 2 US-3)
//!
//! Anchored receipts (with merkle-tree inclusion proofs against a
//! transparency log) are out of scope for v1.0.5. The IETF draft is
//! still evolving; v1.0.5 ships the offline-verifiable surface that
//! is stable today, and the inclusion-proof format lands in v1.0.6
//! once IANA assigns the algorithm identifiers.

#![deny(dead_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// Inclusion proof against a SCITT transparency log.
///
/// In v1.0.5, only `None` is supported. Anchored receipts (with
/// merkle-tree proofs) land in v1.0.6 once the IETF draft is
/// stable enough for production use. For the v1.0.5 use case
/// (regulatory evidence with a single trusted issuer), a direct
/// signature on the payload is sufficient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InclusionProof {
    /// No inclusion proof. The receipt is valid iff the COSE_Sign1
    /// signature verifies against the issuer public key. This is
    /// the v1.0.5 default.
    None,
}

/// A SCITT receipt — a self-contained, cryptographically-signed
/// assertion that the issuer has registered the given payload.
///
/// See module-level documentation for the field semantics. The
/// `cose_sign1` field is the **CBOR-encoded** COSE_Sign1 structure
/// (RFC 9052 §4.2), not a parsed structure — we keep it as bytes
/// to (a) match the IETF wire format and (b) allow verify_offline
/// to be a pure function without depending on the COSE parser's
/// internal state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SCITTReceipt {
    /// The artifact (or its hash) that is being claimed.
    pub payload: Vec<u8>,

    /// CBOR-encoded COSE_Sign1 envelope (RFC 9052 §4.2). Contains
    /// the protected header, the payload, and the Ed25519 signature.
    pub cose_sign1: Vec<u8>,

    /// Issuer key identifier (free-form string, typically a URI
    /// like `did:example:1234` or a kid value from the protected
    /// header).
    pub issuer_kid: String,

    /// BLAKE3-256 of the issuer's Ed25519 public key. Used to
    /// bind the receipt to a specific key without requiring a
    /// separate public-key lookup at verify time.
    pub issuer_pubkey_fingerprint: [u8; 32],

    /// Optional inclusion proof against a transparency log.
    /// `None` in v1.0.5.
    pub inclusion_proof: Option<InclusionProof>,

    /// Unix timestamp (seconds since epoch) when the issuer
    /// registered the payload. NON-AUTHORITATIVE — verify_offline
    /// does NOT check this against any wall clock.
    pub issued_at: u64,

    /// Identifier of the SCITT registry that issued this receipt.
    /// Free-form string; in v1.0.5 it can be empty (self-issued) or
    /// a did:web style identifier.
    pub registry_id: String,
}

/// Errors emitted by `verify_offline` and related operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SCITTError {
    /// The COSE_Sign1 signature did not verify against the issuer
    /// public key. The receipt is INVALID.
    #[error("COSE_Sign1 signature verification failed")]
    InvalidSignature,

    /// The `issuer_kid` in the receipt does not match the
    /// fingerprint of the issuer public key. The receipt is
    /// INVALID.
    #[error("issuer_kid does not match the fingerprint of the supplied public key")]
    KeyIdMismatch,

    /// The payload hash in the COSE_Sign1 protected header does
    /// not match the `payload` field of the receipt. The receipt
    /// is INVALID.
    #[error("payload hash in COSE_Sign1 does not match receipt.payload")]
    PayloadHashMismatch,

    /// The COSE_Sign1 bytes could not be parsed as a valid COSE
    /// structure. The receipt is INVALID.
    #[error("COSE_Sign1 CBOR decode failed: {0}")]
    CborDecodeFailed(String),

    /// The COSE_Sign1 structure parsed but is missing required
    /// fields (signature, protected header, etc.).
    #[error("COSE_Sign1 structure is missing required fields: {0}")]
    CoseParseFailed(String),

    /// The receipt carries an `inclusion_proof` variant that
    /// v1.0.5 does not support (anything other than `None`).
    #[error("inclusion proof required but only `None` is supported in v1.0.5")]
    MissingInclusionProof,
}

/// Verify a SCITT receipt in pure offline mode.
///
/// This function is **pure**: it does not contact any network, any
/// clock, any filesystem, or any environment variable. Same input
/// → same output, forever, on any machine. This is the core
/// property that makes the receipt useful for regulatory evidence.
///
/// ## What it checks
///
/// 1. `cose_sign1` parses as a valid COSE_Sign1 structure (CBOR).
/// 2. The COSE_Sign1 signature verifies against `issuer_pubkey`.
/// 3. The `issuer_pubkey_fingerprint` field in the receipt equals
///    `blake3_256(issuer_pubkey.to_bytes())`.
/// 4. The `payload` field in the receipt matches the COSE_Sign1
///    payload field (the protected header binds the payload via
///    the "payload" field of the COSE_Sign1 structure, which
///    v1.0.5 encodes as the same bytes as `receipt.payload`).
/// 5. If `inclusion_proof` is `Some(InclusionProof::None)`, the
///    check passes (None means "no anchored proof").
///
/// Returns `Ok(true)` if all checks pass, `Err(SCITTError::*)` if
/// any check fails. The function does NOT return `Ok(false)`;
/// failure is always reported as an `Err` so the caller can
/// distinguish "valid" from "invalid" from "could not check".
///
/// ## Why this is `pub` and not behind a trait
///
/// Architect IC-2 (see `tl-evidence/src/tsa.rs`): exactly one
/// implementation. No abstraction overhead.
///
/// ## I/O guarantee
///
/// The function body MUST NOT contain any of: `std::net::*`,
/// `std::fs::*`, `std::env::*`, `std::time::SystemTime::now()`,
/// `chrono::*`. A grep check (`AC-7`) enforces this.
pub fn verify_offline(
    receipt: &SCITTReceipt,
    issuer_pubkey: &ed25519_dalek::VerifyingKey,
) -> Result<bool, SCITTError> {
    // Check 3: fingerprint match (do this first — cheapest and
    // catches the most common error: "wrong key supplied").
    let expected_fingerprint: [u8; 32] = blake3::hash(&issuer_pubkey.to_bytes()).into();
    if receipt.issuer_pubkey_fingerprint != expected_fingerprint {
        return Err(SCITTError::KeyIdMismatch);
    }

    // Check 1: parse the COSE_Sign1 structure using coset's native
    // CborSerializable trait. (coset does NOT implement serde's
    // Deserialize directly — it uses ciborium under the hood.)
    use coset::CborSerializable;
    let sign1: coset::CoseSign1 = coset::CoseSign1::from_slice(&receipt.cose_sign1)
        .map_err(|e| SCITTError::CborDecodeFailed(e.to_string()))?;

    // Check 4: payload match. The COSE_Sign1 payload field MUST
    // equal receipt.payload. (IETF draft-ietf-scitt-scrapi-09 §6
    // specifies that the SCITT receipt payload is the same bytes
    // as the COSE_Sign1 payload — there is no separate "outer
    // envelope" in v1.0.5.)
    let cose_payload = sign1.payload.as_ref().ok_or_else(|| {
        SCITTError::CoseParseFailed("COSE_Sign1 missing payload field".to_string())
    })?;
    if cose_payload.as_slice() != receipt.payload.as_slice() {
        return Err(SCITTError::PayloadHashMismatch);
    }

    // Check 2: signature verification. coset's `CoseSign1::verify_signature`
    // takes care of building the Sig_structure per RFC 9052 §4.4 — we
    // just provide the Ed25519 verifier. The closure receives
    // (signature_bytes, tbs_data_bytes) and returns Result<(), our_err>.
    //
    // ed25519-dalek 2.x `verify_strict` expects a `&Signature` (which
    // parses a 64-byte array); raw `&[u8]` doesn't satisfy the type.
    use ed25519_dalek::Signature;
    let sig_result: Result<(), SCITTError> =
        sign1.verify_signature(b"", |signature_bytes, tbs_data| {
            // Ed25519 signatures are exactly 64 bytes. If the COSE_Sign1
            // carries something else, it's malformed and we reject it
            // (which surfaces as InvalidSignature).
            let sig_arr: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| SCITTError::InvalidSignature)?;
            let sig = Signature::from_bytes(&sig_arr);
            issuer_pubkey
                .verify_strict(tbs_data, &sig)
                .map_err(|_| SCITTError::InvalidSignature)
        });
    sig_result?;

    // Check 5: inclusion proof (v1.0.5: only None supported).
    match &receipt.inclusion_proof {
        Some(InclusionProof::None) | None => {}
    }

    Ok(true)
}

// v1.1.0.x+1+7: counter-signed receipts (closes auditor-4 BRECHA 1).
// Re-exported as `tl_scitt::countersign::CounterSignedReceipt` for the
// API surface, with the convenience re-export below for shorter call
// sites.
pub mod countersign;
pub use countersign::{blake3_pubkey_fingerprint, CounterSignError, CounterSignedReceipt};

#[cfg(test)]
mod tests {
    use super::*;
    use coset::CoseSign1Builder;
    use ed25519_dalek::{Signer, SigningKey};

    /// Helper: build a SCITTReceipt signed with a deterministic Ed25519
    /// key derived from `seed` (BLAKE3 of the seed). Pure: no I/O, no
    /// env, no clock. The same seed always produces the same key, so
    /// tests are reproducible.
    fn make_signed_receipt(payload: &[u8], kid: &str, seed: &[u8]) -> (SCITTReceipt, SigningKey) {
        // Derive a 32-byte Ed25519 secret key from the seed.
        let sk_bytes: [u8; 32] = blake3::hash(seed).into();
        let sk = SigningKey::from_bytes(&sk_bytes);
        let pk = sk.verifying_key();

        // Build the COSE_Sign1 envelope with the payload in the
        // payload field. Ed25519 means alg = -8 in the protected
        // header.
        let builder = CoseSign1Builder::new()
            .protected(
                coset::HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::EdDSA)
                    .key_id(kid.as_bytes().to_vec())
                    .build(),
            )
            .payload(payload.to_vec());
        let sign1 = builder
            .try_create_signature(
                b"",
                |sig_structure_bytes| -> Result<Vec<u8>, coset::CoseError> {
                    Ok(sk.sign(sig_structure_bytes).to_bytes().to_vec())
                },
            )
            .expect("COSE_Sign1 build must succeed in tests")
            .build();
        use coset::CborSerializable;
        let cose_sign1_bytes = coset::CoseSign1::to_vec(sign1).expect("CBOR encode");

        let fingerprint: [u8; 32] = blake3::hash(&pk.to_bytes()).into();

        let receipt = SCITTReceipt {
            payload: payload.to_vec(),
            cose_sign1: cose_sign1_bytes,
            issuer_kid: kid.to_string(),
            issuer_pubkey_fingerprint: fingerprint,
            inclusion_proof: None,
            issued_at: 0, // non-authoritative
            registry_id: "test-registry".to_string(),
        };
        (receipt, sk)
    }

    #[test]
    fn test_verify_offline_valid_receipt() {
        // AC-6: positive case with a fresh receipt.
        let payload = b"hello, SCITT world";
        let (receipt, sk) = make_signed_receipt(payload, "test-kid-1", b"seed-1");
        let pk = sk.verifying_key();
        let result = verify_offline(&receipt, &pk);
        assert!(matches!(result, Ok(true)), "got {:?}", result);
    }

    #[test]
    fn test_verify_offline_invalid_signature() {
        // AC-6: negative case — modify the payload after signing.
        let payload = b"hello, SCITT world";
        let (mut receipt, sk) = make_signed_receipt(payload, "test-kid-2", b"seed-2");
        receipt.payload = b"TAMPERED".to_vec();
        let pk = sk.verifying_key();
        let result = verify_offline(&receipt, &pk);
        // Two possible failures: payload mismatch (more likely) or
        // invalid signature. Both are correct rejections.
        assert!(
            matches!(
                result,
                Err(SCITTError::PayloadHashMismatch) | Err(SCITTError::InvalidSignature)
            ),
            "got {:?}",
            result
        );
    }

    #[test]
    fn test_verify_offline_key_id_mismatch() {
        // AC-6: negative case — receipt was signed by a different key.
        let payload = b"hello, SCITT world";
        let (receipt, _sk_issuer) = make_signed_receipt(payload, "test-kid-3", b"seed-3");
        // Use a DIFFERENT deterministic seed — fingerprint won't match.
        let (other_receipt, other_sk) =
            make_signed_receipt(payload, "test-kid-3-other", b"seed-3-OTHER");
        let other_pk = other_sk.verifying_key();
        // Sanity: the receipts differ.
        assert_ne!(
            receipt.issuer_pubkey_fingerprint,
            other_receipt.issuer_pubkey_fingerprint
        );
        let result = verify_offline(&receipt, &other_pk);
        assert!(
            matches!(result, Err(SCITTError::KeyIdMismatch)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn test_verify_offline_garbage_cose_bytes() {
        // Garbage in cose_sign1 must produce a clean CborDecodeFailed,
        // not a panic or a false positive.
        let payload = b"hello, SCITT world";
        let (mut receipt, sk) = make_signed_receipt(payload, "test-kid-4", b"seed-4");
        receipt.cose_sign1 = vec![0xFF; 32]; // not valid CBOR
        let pk = sk.verifying_key();
        let result = verify_offline(&receipt, &pk);
        assert!(
            matches!(result, Err(SCITTError::CborDecodeFailed(_))),
            "got {:?}",
            result
        );
    }

    #[test]
    fn test_verify_offline_is_pure() {
        // AC-7: ensure the function does not call any I/O. We
        // assert the body contains no I/O patterns by re-reading
        // the function source and checking forbidden strings.
        let src = include_str!("lib.rs");
        // Find the verify_offline function and check its body.
        let start = src
            .find("pub fn verify_offline")
            .expect("verify_offline must exist");
        // The function ends at the next "pub " or "fn " boundary
        // after a closing brace at the same indent level. For
        // simplicity, just scan the next 3000 chars.
        let slice = &src[start..start.min(src.len()).saturating_add(3000)];
        for forbidden in &[
            "std::net::",
            "std::fs::",
            "std::env::",
            "SystemTime::now",
            "chrono::",
        ] {
            assert!(
                !slice.contains(forbidden),
                "verify_offline body must not contain `{}`",
                forbidden
            );
        }
    }
}
